#!/usr/bin/env python3
"""R5: all NIP-041 routes, candidate rejection and crossing/noncrossing reorgs."""
import argparse
import json
from pathlib import Path
import struct
import tempfile
import importlib.util
from review_auth_envelope import Envelope, compact

spec = importlib.util.spec_from_file_location('r5_helpers', Path(__file__).with_name('review-opcode-assets-r3-regtest.py'))
r3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r3)
h, b = r3.h, r3.b


def spend(env, point, script, output, refs=(), amount=90_000_000):
    scriptsig = h.push(b'\x51\x20' + env.program(script)) if env.wrapped else b''
    vin = b'\x01' + h.outpoint(*point) + compact(len(scriptsig)) + scriptsig + b'\xff'*4
    body = vin + b'\x01' + b.output(amount, output) + compact(len(refs)) + b''.join(h.outpoint(*p) for p in refs)
    witness = b'\x02\x01\x00' + compact(len(script)) + script
    return struct.pack('<I', 3) + body + bytes(4), struct.pack('<I', 3) + b'\x00\x01' + body + witness + bytes(4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    directory = args.output or Path(tempfile.mkdtemp(prefix='r5-authdest-events-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    files = list(Path(__file__).parent.glob('review*.py')) + [Path(__file__).with_name('generate_authscript_vectors.py')]
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir/'neuraid'),
              'source_sha256': {p.name:h.digest_file(p) for p in files}}
    nodes = []
    def check(label, ok, observed):
        report['results'].append({'case':label,'passed':bool(ok),'observed':observed})
        print(('PASS ' if ok else 'FAIL ')+label,flush=True)
        if not ok:
            raise RuntimeError(label+': '+str(observed))
    try:
        native = Envelope()
        control = native.output(native.program(b'\x51'))
        # Validate full destination for output/ref; spent-program query cannot
        # embed its own commitment without circularity, so validate size/version.
        routes = {
            'output': b'\x00\xc2' + h.push(b'\x01'+control[2:]) + b'\x87',
            'reference': b'\x00\x54\xd2' + h.push(b'\x01'+control[2:]) + b'\x87',
            'spent': b'\x54\xb6\x82'+h.push(b'\x21')+b'\x9d\x51\xb7\x75\x51\x87'}
        for route, script in routes.items():
            for wrapped in (False, True):
                for late in (False, True):
                    label=f'{route}/p2sh{int(wrapped)}/lateparent{int(late)}'
                    env=Envelope(0,wrapped)
                    node=h.Node(args.bindir,directory/label.replace('/','-'),
                                ['-strictauthscriptheight=120','-bypassdownload=1','-par=1'])
                    nodes.append(node)
                    node.ready()
                    miner=node.rpc('getnewaddress')
                    node.rpc('generatetoaddress',110,miner)
                    # Both candidate heights stay inactive.
                    low=node.rpc('generatetoaddress',1,miner)[0]
                    node.rpc('invalidateblock',low)
                    check(label+'/below_no_cross',node.rpc('getblockcount')==110 and
                          node.rpc('getblocktemplate',{'rules':['segwit']})['height']==111,110)
                    node.rpc('reconsiderblock',low)
                    node.rpc('generatetoaddress',6,miner)
                    def fund(outputs):
                        raw=struct.pack('<I',2)+b'\x00'+compact(len(outputs))+b''.join(b.output(100_000_000,s) for s in outputs)+bytes(4)
                        tx=node.rpc('fundrawtransaction',raw.hex())
                        signed=node.rpc('signrawtransaction',tx['hex'])
                        txid=node.rpc('sendrawtransaction',signed['hex'])
                        node.rpc('generatetoaddress',1,miner)
                        decoded=node.rpc('getrawtransaction',txid,True)
                        check(label+'/funding_locktime',decoded['locktime']==0,decoded['locktime'])
                        points=[]
                        for spk in outputs:
                            i=next(o['n'] for o in decoded['vout'] if o['scriptPubKey']['hex']==spk.hex())
                            points.append((txid,i))
                        node.rpc('lockunspent',False,[{'txid':p[0],'vout':p[1]} for p in points])
                        return points
                    contract=env.output(env.program(script))
                    points=fund([control] if late else [control,contract])
                    ref=points[0]
                    if not late:
                        parent=points[1]
                    refs=[ref] if route=='reference' else []
                    if not late:
                        tx=spend(env,parent,script,control,refs)
                        result=node.rpc('testmempoolaccept',[tx[1].hex()])[0]
                        check(label+'/inactive_reject',result.get('allowed')!=1,result)
                        tip=node.rpc('getbestblockhash')
                        raw,_,_=b.block(node.rpc('getblocktemplate',{'rules':['segwit']}),tx)
                        result=node.rpc('submitblock',raw.hex())
                        check(label+'/invalid_candidate',isinstance(result,str) and
                              ('Opcode' in result or 'OP_TXFIELD' in result or 'OP_REFINPUTFIELD' in result),result)
                        check(label+'/candidate_preserves_tip',node.rpc('getbestblockhash')==tip,tip)
                        again=node.rpc('testmempoolaccept',[tx[1].hex()])[0]
                        check(label+'/candidate_preserves_rules',again.get('allowed')!=1,again)
                    block119=node.rpc('generatetoaddress',1,miner)[0]
                    if late:
                        parent=fund([contract])[0]  # 120: disconnected in crossing
                    tx=spend(env,parent,script,control,refs)
                    result=node.rpc('testmempoolaccept',[tx[1].hex()])[0]
                    if route=='spent' and wrapped:
                        check(label+'/p2sh_spent_destination_not_native',result.get('allowed')!=1 and 'OP_TXFIELD' in str(result),result)
                        node.close()
                        nodes.remove(node)
                        continue
                    check(label+'/first_available_active',result.get('allowed')==1,result)
                    # Move above boundary with empty blocks, then admit the package.
                    upper=node.rpc('generatetoaddress',2,miner)[-1]
                    txid=node.rpc('sendrawtransaction',tx[1].hex())
                    child=spend(native,(txid,0),b'\x51',control,amount=80_000_000)
                    childid=node.rpc('sendrawtransaction',child[1].hex())
                    node.rpc('invalidateblock',upper)
                    pool=node.rpc('getrawmempool')
                    check(label+'/above_no_cross_preserves_package',{txid,childid}.issubset(pool),pool)
                    node.rpc('reconsiderblock',upper)
                    node.rpc('invalidateblock',block119)
                    check(label+'/crossed_height',node.rpc('getblockcount')==118,node.rpc('getblockcount'))
                    pool=node.rpc('getrawmempool')
                    check(label+'/crossing_evicts_descendant',txid not in pool and childid not in pool,pool)
                    check(label+'/parent_available',node.rpc('gettxout',*parent) is not None,parent)
                    result=node.rpc('testmempoolaccept',[tx[1].hex()])[0]
                    check(label+'/inactive_readmission_rejected',result.get('allowed')!=1,result)
                    template=node.rpc('getblocktemplate',{'rules':['segwit']})
                    check(label+'/mining_template',template['height']==119 and
                          not {txid,childid}.intersection(t['txid'] for t in template['transactions']),template['height'])
                    node.rpc('generatetoaddress',1,node.rpc('getnewaddress'))
                    result=node.rpc('testmempoolaccept',[tx[1].hex()])[0]
                    check(label+'/recross_admission',result.get('allowed')==1,result)
                    node.rpc('sendrawtransaction',tx[1].hex())
                    node.rpc('sendrawtransaction',child[1].hex())
                    node.rpc('generatetoaddress',1,miner)
                    check(label+'/recross_mined',all(node.rpc('getrawtransaction',x,True).get('confirmations')==1
                                                    for x in (txid,childid)),[txid,childid])
                    node.close()
                    nodes.remove(node)
    except Exception as error:
        report['error']=str(error)
        print('ERROR:',error,flush=True)
    finally:
        for node in reversed(nodes):
            node.close()
        report['passed']=sum(r['passed'] for r in report['results'])
        report['failed']=sum(not r['passed'] for r in report['results'])+int('error' in report)
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('Report:',directory/'report.json',flush=True)
    return int(report['failed']!=0)


if __name__=='__main__':
    raise SystemExit(main())
