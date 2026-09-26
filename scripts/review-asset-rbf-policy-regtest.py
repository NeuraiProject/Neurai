#!/usr/bin/env python3
"""NIP025-patch1: actual signed asset replacements, ancestor pinning and blocks.
Only disposable loopback regtest nodes; nonzero exit on any failure.
"""
import argparse,importlib.util,json,struct,subprocess,tempfile,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('thread',Path(__file__).with_name('review-contract-thread-regtest.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r);h=r.h

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));args=p.parse_args()
    d=Path(tempfile.mkdtemp(prefix='asset-rbf-policy-'));nodes=[]
    report={'binary_sha256':h.digest_file(args.bindir/'neuraid'),'driver_sha256':h.digest_file(Path(__file__)),'results':[]}
    def check(name,ok,detail=None):
        report['results'].append({'case':name,'passed':bool(ok),'observed':detail});print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise RuntimeError(name+': '+str(detail))
    def new(label,extra=()):
        n=h.Node(args.bindir,d/label,['-bypassdownload=1','-mempoolreplacement=1','-acceptnonstdtxn=0','-assetindex=1',*extra]);nodes.append(n);n.ready();return n
    try:
        n=new('source');addr=n.rpc('getnewaddress','','legacy');pay=bytes.fromhex(n.rpc('validateaddress',addr)['scriptPubKey'])
        n.rpc('generatetoaddress',610,addr)
        def mine():return n.rpc('generatetoaddress',1,addr)[0]
        def fund(amount=10):
            txid=n.rpc('sendtoaddress',addr,amount);mine();tx=n.rpc('getrawtransaction',txid,True)
            return (txid,next(o['n'] for o in tx['vout'] if o['value']==amount and o['scriptPubKey']['hex']==pay.hex()))
        def raw(inputs,outputs,seq=0xfffffffd,signer=None,witness=None):
            # v3 supports witness; sequence belongs to every spending input.
            has_witness=bool(witness and any(witness))
            wire=struct.pack('<I',3)+(b'\x00\x01' if has_witness else b'')+h.compact(len(inputs))
            for i,(txid,index) in enumerate(inputs):wire+=h.outpoint(txid,index)+b'\x00'+struct.pack('<I',seq[i] if isinstance(seq,list) else seq)
            wire+=h.compact(len(outputs))
            for value,script in outputs:wire+=struct.pack('<q',value)+h.compact(len(script))+script
            wire+=b'\x00' # no references
            for w in (witness if has_witness else []):
                wire+=h.compact(len(w))+b''.join(h.compact(len(x))+x for x in w)
            wire+=bytes(4)
            return (signer or n).rpc('signrawtransaction',wire.hex())['hex']
        def accept(label,wire,expected=None):
            result=n.rpc('testmempoolaccept',[wire])[0]
            ok=result.get('allowed') if expected is None else not result.get('allowed') and expected in result.get('reject-reason','')
            check(label,ok,result)
        def transfer(prefix,name,amount=100_000_000):
            payload=b'xnat'+h.compact(len(name))+name.encode()+struct.pack('<q',amount)+b'\x00'
            return prefix+b'\xc0'+h.push(payload)+b'\x75'
        # Ordinary XNA replacement remains functional when explicitly enabled.
        coin=fund();a=raw([coin],[(990_000_000,pay)]);aid=n.rpc('sendrawtransaction',a)
        b=raw([coin],[(970_000_000,pay)]);accept('XNA/replacement_allowed',b)
        bid=n.rpc('sendrawtransaction',b);check('XNA/replaced',aid not in n.rpc('getrawmempool') and bid in n.rpc('getrawmempool'));mine()
        # Asset destination matrix. v1 NoAuth is used only as an explicit public fixture.
        v1addr,v1=r.address(b'\x51')
        pq=new('pq',extra=['-addresstype=pq']);pqaddr=pq.rpc('getnewaddress','','pq');pqspk=bytes.fromhex(pq.rpc('validateaddress',pqaddr)['scriptPubKey'])
        ecdsa=n.rpc('getnewaddress','','ecdsa');esp=bytes.fromhex(n.rpc('validateaddress',ecdsa)['scriptPubKey'])
        for family,dest,spk in [('legacy',addr,pay),('v1',v1addr,v1),('v3',ecdsa,esp),('v2',pqaddr,pqspk)]:
            name='RBF'+family.upper();n.rpc('issue',name,1,dest);mine()
            unspent=n.rpc('listassetbalancesbyaddress',dest) # ensures actual issuance indexed
            check(f'{family}/issued',name in unspent,unspent)
            # Find issue output in the most recent block, independent of wallet ownership.
            block=n.rpc('getblock',n.rpc('getbestblockhash'),2)
            prev=None
            for tx in block['tx']:
                for out in tx['vout']:
                    asset=out.get('scriptPubKey',{}).get('asset',{})
                    if asset.get('name')==name:prev=(tx['txid'],out['n'])
            if prev is None:raise RuntimeError('issue output not found '+name)
            coin=fund();input_spk=n.rpc('gettxout',*prev)['scriptPubKey']['hex']
            if family=='v2':
                for height in range(pq.rpc('getblockcount')+1,n.rpc('getblockcount')+1):
                    result=pq.rpc('submitblock',n.rpc('getblock',n.rpc('getblockhash',height),False))
                    if result is not None:raise RuntimeError(result)
            ws=[[b'\x00',b'\x51'],[]] if family=='v1' else None
            def signed(value):
                wire=raw([prev,coin],[(0,transfer(spk,name)),(value,pay)],witness=ws)
                if family=='v2':wire=pq.rpc('signrawtransaction',wire)['hex']
                return wire
            first=signed(990_000_000);accept(f'{family}/first_admission',first);firstid=n.rpc('sendrawtransaction',first)
            replacement=signed(970_000_000);accept(f'{family}/replacement_rejected',replacement,'replacement-involves-assets')
            check(f'{family}/original_retained',firstid in n.rpc('getrawmempool'))
            if family=='legacy':
                # A block with the otherwise valid conflict must override local policy.
                template=n.rpc('getblocktemplate',{'rules':['segwit']});template['coinbasevalue']-=sum(t['fee'] for t in template['transactions'])
                wire=bytes.fromhex(replacement);full,_,_=r.b.block(template,((r.strip_witness(wire) if wire[4:6]==b'\x00\x01' else wire),wire))
                result=n.rpc('submitblock',full.hex());check('consensus/conflicting_block_valid',result is None,result)
                check('consensus/old_removed',firstid not in n.rpc('getrawmempool'))
                tip=n.rpc('getbestblockhash');n.rpc('invalidateblock',tip)
                rid=n.rpc('decoderawtransaction',replacement)['txid']
                check('reorg/readmitted',rid in n.rpc('getrawmempool'))
                n.rpc('reconsiderblock',tip)
            else:mine()
        # First issuance has only XNA inputs: protection must come from outputs.
        issue_coin=fund(1100)
        burn=bytes.fromhex(n.rpc('validateaddress','tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy')['scriptPubKey'])
        name=b'FIRSTISSUE'
        def wrap(payload):return pay+b'\xc0'+h.push(payload)+b'\x75'
        owner=wrap(b'xnao'+h.compact(len(name)+1)+name+b'!')
        issuance=wrap(b'xnaq'+h.compact(len(name))+name+struct.pack('<q',100_000_000)+bytes([0,1,0]))
        issue_raw=raw([issue_coin],[(100_000_000_000,burn),(9_990_000_000,pay),(0,owner),(0,issuance)])
        accept('issuance/first_admission',issue_raw);issue_id=n.rpc('sendrawtransaction',issue_raw)
        cancel=raw([issue_coin],[(100_000_000_000,burn),(9_950_000_000,pay)])
        accept('issuance/XNA_cannot_remove_outputs',cancel,'replacement-involves-assets')
        check('issuance/retained',issue_id in n.rpc('getrawmempool'));mine()
        # Ancestor replacement cannot evict a protected asset descendant.
        # Fresh issue, then an ordinary parent with a confirmed asset input in its child.
        n.rpc('issue','CHAINRBF',1,addr);mine()
        block=n.rpc('getblock',n.rpc('getbestblockhash'),2)
        prev=next((tx['txid'],o['n']) for tx in block['tx'] for o in tx['vout'] if o['scriptPubKey'].get('asset',{}).get('name')=='CHAINRBF')
        coin=fund();parent=raw([coin],[(990_000_000,pay)]);pid=n.rpc('sendrawtransaction',parent)
        candidate=raw([prev,coin],[(0,transfer(pay,'CHAINRBF')),(940_000_000,pay)])
        accept('candidate_assets/cannot_replace_XNA',candidate,'replacement-involves-assets')
        child=raw([prev,(pid,0)],[(0,transfer(pay,'CHAINRBF')),(980_000_000,pay)])
        cid=n.rpc('sendrawtransaction',child)
        replace=raw([coin],[(940_000_000,pay)])
        accept('ancestor/protected_descendant',replace,'replacement-involves-assets')
        check('ancestor/no_partial_removal',set([pid,cid]).issubset(n.rpc('getrawmempool')))
        # Live lookup survives mempool persistence without cached metadata.
        command=n.proc.args;n.close();n.log=(n.directory/'restart.log').open('w');n.proc=subprocess.Popen(command,stdout=n.log,stderr=subprocess.STDOUT);n.ready()
        for _ in range(100):
            if cid in n.rpc('getrawmempool'):break
            time.sleep(.1)
        check('restart/loaded',set([pid,cid]).issubset(n.rpc('getrawmempool')))
        accept('restart/protection',replace,'replacement-involves-assets');mine()
        # Request-like CSV component: relative delay is on a different input
        # from the asset. This is not the ZK-protected NIP043 request script.
        csv_script=h.push(bytes.fromhex('a005'))+b'\xb2\x75\x51'
        csv_address,csv_spk=r.address(csv_script)
        csv_id=n.rpc('sendtoaddress',csv_address,1);mine();height=n.rpc('getblockcount')
        csv_tx=n.rpc('getrawtransaction',csv_id,True)
        csv_index=next(o['n'] for o in csv_tx['vout'] if o['scriptPubKey']['hex']==csv_spk.hex())
        csv_spend=raw([(cid,0),(csv_id,csv_index)],[(0,transfer(pay,'CHAINRBF')),(90_000_000,pay)],
                      seq=[0xfffffffe,1440],witness=[[],[b'\x00',csv_script]])
        n.rpc('generatetoaddress',1438,addr)
        accept('CSV_other_input/immature',csv_spend,'non-BIP68-final');mine()
        accept('CSV_other_input/mature',csv_spend)
        spend_id=n.rpc('sendrawtransaction',csv_spend);mine()
        check('CSV_other_input/mined',n.rpc('getrawtransaction',spend_id,True).get('confirmations',0)==1)
        # Global off remains off, regardless of the new policy.
        off=new('disabled',extra=['-mempoolreplacement=0']);offaddr=off.rpc('getnewaddress','','legacy');off.rpc('generatetoaddress',110,offaddr)
        utxo=off.rpc('listunspent')[0];out=bytes.fromhex(off.rpc('validateaddress',offaddr)['scriptPubKey']);value=int(round(float(utxo['amount'])*100_000_000))
        one=raw([(utxo['txid'],utxo['vout'])],[(value-1_000_000,out)],signer=off);off.rpc('sendrawtransaction',one)
        two=raw([(utxo['txid'],utxo['vout'])],[(value-3_000_000,out)],signer=off)
        result=off.rpc('testmempoolaccept',[two])[0];check('global_off/no_replacement',not result.get('allowed') and 'txn-mempool-conflict' in str(result),result)
        report['success']=True
    except Exception as error:report['error']=str(error);print('ERROR '+str(error),flush=True)
    finally:
        for node in reversed(nodes):node.close()
        (d/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(d/'report.json'),flush=True)
    return int(not report.get('success'))
if __name__=='__main__':raise SystemExit(main())
