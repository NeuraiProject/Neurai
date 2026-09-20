#!/usr/bin/env python3
"""NIP-046 candidate-height admission, both reorg directions and descendants.
Disposable loopback regtest. No mainnet or public testnet connections.
"""
import argparse
import importlib.util
import json
import tempfile
import subprocess
import time
from pathlib import Path
spec=importlib.util.spec_from_file_location('thread',Path(__file__).with_name('review-contract-thread-regtest.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));p.add_argument('--envelope',choices=('native','p2sh','mast'),default='native');args=p.parse_args()
 d=Path(tempfile.mkdtemp(prefix='nip046-activation-'));nodes=[];report={'envelope':args.envelope,'results':[],'binary_sha256':r.h.digest_file(args.bindir/'neuraid'),'driver_sha256':r.h.digest_file(Path(__file__))}
 def node(label,par=1):
  n=r.h.Node(args.bindir,d/label,['-bypassdownload=1','-acceptnonstdtxn=0','-minrelaytxfee=0.00001','-authscriptbudgetheight=630',f'-par={par}']);nodes.append(n);n.ready();return n
 def check(name,ok,observed=None):
  report['results'].append(dict(case=name,passed=bool(ok),observed=observed));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
  if not ok:raise RuntimeError(name+': '+str(observed))
 try:
  n=node('source');miner=n.rpc('getnewaddress','','legacy');n.rpc('generatetoaddress',610,miner)
  pay=bytes.fromhex(n.rpc('validateaddress',miner)['scriptPubKey'])
  scripts=[b'\x61'*202+b'\x51',b'\xa8\x75'*21+b'\x51'];wargs=[[],[b'\x42'*3072]*20+[b'\x42'*2753]];wires=[]
  for script,wa in zip(scripts,wargs):
   addr,spk=r.address(script);redeem=None;witness=[b'\x00',*wa,script]
   if args.envelope=='mast':
    tag=r.sha(b'NeuraiAuthLeaf');leaf=r.sha(tag+tag+b'\x01'+r.h.compact(len(script))+script)
    tag=r.sha(b'NeuraiAuthScript');commitment=r.sha(tag+tag+b'\x04\x00'+leaf)
    spk=b'\x51\x20'+commitment;addr=r.t._ctv.bech32m('tnc',1,commitment)
    witness=[b'\x10',*wa,script,b'\x01']
   elif args.envelope=='p2sh':
    redeem=spk;addr=n.rpc('decodescript',redeem.hex())['p2sh'];spk=bytes.fromhex(n.rpc('validateaddress',addr)['scriptPubKey'])
   txid=n.rpc('sendtoaddress',addr,2);n.rpc('generatetoaddress',1,miner)
   tx=n.rpc('getrawtransaction',txid,True);idx=next(o['n'] for o in tx['vout'] if o['scriptPubKey']['hex']==spk.hex())
   raw=r.a.raw_transaction([(txid,idx)],[(190000000,pay)],[],[witness])
   if redeem is not None:
    wire=bytes.fromhex(raw);assert wire[6]==1 and wire[43]==0
    script_sig=r.h.push(redeem);raw=(wire[:43]+r.h.compact(len(script_sig))+script_sig+wire[44:]).hex()
   wires.append(raw)
  n.rpc('generatetoaddress',628-n.rpc('getblockcount'),miner)
  res=n.rpc('testmempoolaccept',[wires[0]])[0];check('before/202_rejected',not res.get('allowed') and 'Operation limit exceeded' in str(res),res)
  wire=bytes.fromhex(wires[0]);bad_before,_,_=r.b.block(n.rpc('getblocktemplate',{'rules':['segwit']}),(r.strip_witness(wire),wire))
  result=n.rpc('submitblock',bad_before.hex());check('before/block_202_rejected',result is not None and 'script' in result,result)
  oldid=n.rpc('sendrawtransaction',wires[1]);check('before/hash_admitted',oldid in n.rpc('getrawmempool'))
  oldchild=n.rpc('signrawtransaction',r.a.raw_transaction([(oldid,0)],[(180000000,pay)],[],[[]]))['hex']
  oldchildid=n.rpc('sendrawtransaction',oldchild)
  # Do not mine the pending hash spend: use an empty candidate block.
  emptyminer=node('emptyminer')
  for height in range(1,629):
   result=emptyminer.rpc('submitblock',n.rpc('getblock',n.rpc('getblockhash',height),False))
   if result is not None:raise RuntimeError(result)
  emptyhash=emptyminer.rpc('generatetoaddress',1,miner)[0]
  result=n.rpc('submitblock',emptyminer.rpc('getblock',emptyhash,False));check('connect_629',result is None,result)
  boundary=n.rpc('getbestblockhash');check('up/hash_and_child_evicted',oldid not in n.rpc('getrawmempool') and oldchildid not in n.rpc('getrawmempool'))
  res=n.rpc('testmempoolaccept',[wires[1]])[0];check('up/hash_rejected',not res.get('allowed') and 'AuthScript hash budget exceeded' in str(res),res)
  wire=bytes.fromhex(wires[1]);bad_after,_,_=r.b.block(n.rpc('getblocktemplate',{'rules':['segwit']}),(r.strip_witness(wire),wire))
  result=n.rpc('submitblock',bad_after.hex());check('after/block_hash_rejected',result is not None and 'script' in result,result)
  newid=n.rpc('sendrawtransaction',wires[0]);check('up/202_admitted',newid in n.rpc('getrawmempool'))
  child=n.rpc('signrawtransaction',r.a.raw_transaction([(newid,0)],[(180000000,pay)],[],[[]]))['hex']
  childid=n.rpc('sendrawtransaction',child)
  n.rpc('invalidateblock',boundary)
  pool=n.rpc('getrawmempool');check('down/parent_and_child_evicted',newid not in pool and childid not in pool,pool)
  res=n.rpc('testmempoolaccept',[wires[1]])[0];check('down/hash_valid_again',res.get('allowed'),res)
  n.rpc('reconsiderblock',boundary);n.rpc('sendrawtransaction',wires[0]);n.rpc('sendrawtransaction',child)
  tip=n.rpc('generatetoaddress',1,miner)[0];check('active/mined_parent_child',n.rpc('getrawtransaction',childid,True)['confirmations']==1)
  blocks=[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,n.rpc('getblockcount')+1)]
  for par in (1,2):
   v=node('validator'+str(par),par)
   for height,block in enumerate(blocks,1):
    result=v.rpc('submitblock',block)
    if result is not None:raise RuntimeError(result)
    if height in (628,629):
     debug=v.directory/'regtest/debug.log';offset=debug.stat().st_size
     result=v.rpc('submitblock',(bad_before if height==628 else bad_after).hex())
     rejected=result is not None and ('script' in result if par==1 else result=='block-validation-failed')
     if par==2:
      with debug.open() as log:
       log.seek(offset);rejected=rejected and 'ConnectBlock: CheckQueue failed' in log.read()
     check(f'blocks/par{par}/invalid_at_{height+1}',rejected and v.rpc('getblockcount')==height,result)
   check('blocks/par'+str(par),v.rpc('getbestblockhash')==tip)
  n.close()
  n.log=(n.directory/'restart.log').open('w')
  n.proc=subprocess.Popen(n.proc.args,stdout=n.log,stderr=subprocess.STDOUT);n.ready()
  check('restart/tip_restored',n.rpc('getbestblockhash')==tip)
  check('restart/verifychain',n.rpc('verifychain',4,0))
  n.close()
  n.log=(n.directory/'reindex.log').open('w')
  n.proc=subprocess.Popen(n.proc.args+['-reindex'],stdout=n.log,stderr=subprocess.STDOUT);n.ready()
  deadline=time.monotonic()+120
  while n.rpc('getbestblockhash')!=tip and time.monotonic()<deadline:time.sleep(0.1)
  check('reindex/tip_restored',n.rpc('getbestblockhash')==tip)
  check('reindex/verifychain',n.rpc('verifychain',4,0))
  report['success']=True
 except Exception as e:report['error']=str(e);print('ERROR '+str(e),flush=True)
 finally:
  for n in reversed(nodes):n.close()
  (d/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(d/'report.json'),flush=True)
 return int(not report.get('success',False))
if __name__=='__main__':raise SystemExit(main())
