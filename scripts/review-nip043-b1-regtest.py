#!/usr/bin/env python3
"""NIP-043 B1_q0: real MAST/Poseidon, 1440-block CSV and reorg; no ZK.
All nodes are disposable loopback regtest nodes. The other MAST leaves are DEMO.
"""
import argparse,copy,importlib.util,json,struct,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('thread',Path(__file__).with_name('review-contract-thread-regtest.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r);h=r.h

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'))
    p.add_argument('--sponsor',choices=['legacy','ecdsa','pq'],default='legacy');args=p.parse_args()
    fixture=ROOT/'src/test/data/nip043_b1_fixture.json';f=json.loads(fixture.read_text())
    d=Path(tempfile.mkdtemp(prefix='nip043-b1-'));nodes=[]
    report={'sponsor':args.sponsor,'results':[],'binary_sha256':h.digest_file(args.bindir/'neuraid'),
            'fixture_sha256':h.digest_file(fixture),'driver_sha256':h.digest_file(Path(__file__))}
    def check(label,ok,observed=None):
        report['results'].append(dict(case=label,passed=bool(ok),observed=observed))
        print(('PASS ' if ok else 'FAIL ')+label,flush=True)
        if not ok:raise RuntimeError(label+': '+str(observed))
    def node(label,par=1,extra=()):
        n=h.Node(args.bindir,d/label,['-bypassdownload=1','-acceptnonstdtxn=0',f'-par={par}',*extra]);nodes.append(n);n.ready();return n
    try:
        n=node('source');miner=n.rpc('getnewaddress','','legacy');n.rpc('generatetoaddress',610,miner)
        def confirm(txid):
            if isinstance(txid,list):txid=txid[0]
            n.rpc('generatetoaddress',1,miner);return n.rpc('getrawtransaction',txid,True)
        confirm(n.rpc('issue',f['name'],1,miner));confirm(n.rpc('issueunique',f['name'],['POOL'],None,miner))
        c=bytes.fromhex(f['program']);spk=b'\x51\x20'+c
        before=r.transfer(spk,f['unique'],bytes.fromhex(f['old_hash']))
        after=r.transfer(spk,f['unique'],bytes.fromhex(f['new_hash']))
        state_tx=confirm(n.rpc('transfer',f['unique'],1,r.t._ctv.bech32m('tnc',1,c),f['old_hash']))
        state=(state_tx['txid'],next(o['n'] for o in state_tx['vout'] if o['scriptPubKey']['hex']==before.hex()))
        funded_height=n.rpc('getblockcount');first_valid_height=funded_height+f['delay']
        report['funding_height']=funded_height;report['first_valid_height']=first_valid_height
        sponsor=node('sponsor',extra=['-pqwallet=1']) if args.sponsor=='pq' else n
        payout=miner if args.sponsor=='legacy' else sponsor.rpc('getnewaddress','',args.sponsor)
        pay=bytes.fromhex(sponsor.rpc('validateaddress',payout)['scriptPubKey'])
        funding=confirm(n.rpc('sendtoaddress',payout,2))
        coin=(funding['txid'],next(o['n'] for o in funding['vout'] if o['value']==2 and o['scriptPubKey']['hex']==pay.hex()))
        if sponsor is not n:
            for height in range(1,n.rpc('getblockcount')+1):
                result=sponsor.rpc('submitblock',n.rpc('getblock',n.rpc('getblockhash',height),False))
                if result is not None:raise RuntimeError(result)
        inputs=[state,coin];outputs=[(0,after),(190_000_000,pay)]
        witness=[[b'\x10',bytes.fromhex(f['old']),bytes.fromhex(f['new']),bytes.fromhex(f['leaf']),bytes.fromhex(f['control'])],[]]
        def raw(seq=f['delay'],outs=outputs,ws=witness):
            wire=bytearray.fromhex(r.a.raw_transaction(inputs,outs,[],ws))
            # v3 marker/flag, two inputs, first outpoint and empty scriptSig.
            assert wire[6]==2 and wire[43]==0
            wire[44:48]=struct.pack('<I',seq)
            return sponsor.rpc('signrawtransaction',wire.hex())['hex']
        good=raw()
        n.rpc('generatetoaddress',first_valid_height-2-n.rpc('getblockcount'),miner)
        result=n.rpc('testmempoolaccept',[good])[0]
        check('CSV/candidate_one_block_early',not result.get('allowed') and 'non-BIP68-final' in str(result),result)
        # Independently prove the same boundary in full blocks, not only policy.
        template=n.rpc('getblocktemplate',{'rules':['segwit']});wire=bytes.fromhex(good)
        invalid,_,_=r.b.block(template,(r.strip_witness(wire),wire))
        history=[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,n.rpc('getblockcount')+1)]
        boundary=n.rpc('generatetoaddress',1,miner)[0]
        result=n.rpc('testmempoolaccept',[good])[0]
        check('CSV/candidate_exact_boundary',result.get('allowed'),result)
        validators=[]
        for par in (1,2):
            v=node('validator'+str(par),par);validators.append(v)
            for block in history:
                result=v.rpc('submitblock',block)
                if result is not None:raise RuntimeError(result)
            result=v.rpc('submitblock',invalid.hex())
            check(f'CSV/par{par}/early_block_rejected',result is not None and 'nonfinal' in result,result)
            check(f'CSV/par{par}/tip_unchanged',v.rpc('getblockcount')==first_valid_height-2)
        def reject(label,wire):
            result=n.rpc('testmempoolaccept',[wire])[0];check(label,not result.get('allowed'),result)
        reject('CSV/sequence_below_T',raw(seq=f['delay']-1))
        reject('CSV/disabled_sequence',raw(seq=f['delay']|(1<<31)))
        reject('CSV/time_instead_of_height',raw(seq=f['delay']|(1<<22)))
        # These are bad openings; C++ separately recalculates hashes for mode/prefix negatives.
        w=copy.deepcopy(witness);w[0][1]=w[0][1][:-1]+b'\x01';reject('B1/wrong_old_opening',raw(ws=w))
        w=copy.deepcopy(witness);w[0][2]=w[0][2][:-1]+b'\x00';reject('B1/wrong_new_opening',raw(ws=w))
        w=copy.deepcopy(witness);w[0].insert(1,b'extra');reject('B1/extra_argument',raw(ws=w))
        o=outputs.copy();o[0]=(0,before);reject('B1/unchanged_output_state',raw(outs=o))
        o=outputs.copy();o[0]=(1,after);reject('B1/nonzero_state_xna',raw(outs=o))
        o=outputs.copy();o[1]=(190_000_000,b'\x53\x20'+bytes(32));reject('B1/redirect_sponsor',raw(outs=o))
        o=outputs+[(0,b'\x6a')];reject('B1/extra_output',raw(outs=o))
        txid=n.rpc('sendrawtransaction',good);activated=n.rpc('generatetoaddress',1,miner)[0]
        check('B1/mined_at_exact_boundary',n.rpc('getblockcount')==first_valid_height)
        check('B1/new_state_exact',n.rpc('gettxout',txid,0)['scriptPubKey']['hex']==after.hex())
        check('B1/old_state_spent',n.rpc('gettxout',*state) is None)
        for par,v in enumerate(validators,1):
            for blockhash in (boundary,activated):
                result=v.rpc('submitblock',n.rpc('getblock',blockhash,False))
                if result is not None:raise RuntimeError(result)
            check(f'B1/par{par}/valid_block',v.rpc('getbestblockhash')==activated)
        n.rpc('invalidateblock',activated)
        check('reorg/readmitted_while_mature',txid in n.rpc('getrawmempool'))
        n.rpc('invalidateblock',boundary)
        check('reorg/removed_when_immature',txid not in n.rpc('getrawmempool'))
        check('reorg/old_state_restored',n.rpc('gettxout',*state,False)['scriptPubKey']['hex']==before.hex())
        check('reorg/template_available',n.rpc('getblocktemplate',{'rules':['segwit']})['height']==first_valid_height-1)
        n.rpc('reconsiderblock',activated)
        check('reorg/new_state_restored',n.rpc('getbestblockhash')==activated and n.rpc('gettxout',txid,0,False)['scriptPubKey']['hex']==after.hex())
        report['success']=True
    except Exception as error:
        report['error']=str(error);print('ERROR '+str(error),flush=True)
    finally:
        for n in reversed(nodes):n.close()
        (d/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(d/'report.json'),flush=True)
    return int(not report.get('success',False))
if __name__=='__main__':raise SystemExit(main())
