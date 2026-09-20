#!/usr/bin/env python3
"""Regression: a four-item NoAuth MAST envelope must only spend witness v1.
The same tree commitment is funded under all three versions using test coins.
"""
import argparse
import importlib.util
import json
import tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('thread',Path(__file__).with_name('review-contract-thread-regtest.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));args=p.parse_args()
 d=Path(tempfile.mkdtemp(prefix='nip046-strict-tree-'));report={'results':[],'binary_sha256':r.h.digest_file(args.bindir/'neuraid'),'driver_sha256':r.h.digest_file(Path(__file__))}
 n=None
 try:
  n=r.h.Node(args.bindir,d/'node',['-bypassdownload=1','-acceptnonstdtxn=0']);n.ready()
  miner=n.rpc('getnewaddress','','legacy');pay=bytes.fromhex(n.rpc('validateaddress',miner)['scriptPubKey']);n.rpc('generatetoaddress',610,miner)
  script=b'\x75\x51';tag=r.sha(b'NeuraiAuthLeaf');leaf=r.sha(tag+tag+b'\x01'+r.h.compact(len(script))+script)
  tag=r.sha(b'NeuraiAuthScript');c=r.sha(tag+tag+b'\x04\x00'+leaf)
  for version,hrp in [(1,'tnc'),(2,'tpq'),(3,'tnq')]:
   spk=bytes([0x50+version,32])+c;addr=r.t._ctv.bech32m(hrp,version,c)
   txid=n.rpc('sendtoaddress',addr,2);n.rpc('generatetoaddress',1,miner);tx=n.rpc('getrawtransaction',txid,True)
   index=next(o['n'] for o in tx['vout'] if o['scriptPubKey']['hex']==spk.hex())
   raw=r.a.raw_transaction([(txid,index)],[(190000000,pay)],[],[[b'\x10',b'',script,b'\x01']])
   result=n.rpc('testmempoolaccept',[raw])[0];ok=bool(result.get('allowed'))==(version==1)
   if version!=1:ok=ok and 'Witness program hash mismatch' in str(result)
   report['results'].append(dict(case=f'v{version}',passed=ok,observed=result));print(('PASS ' if ok else 'FAIL ')+f'v{version}',flush=True)
   if not ok:raise RuntimeError(str(result))
  report['success']=True
 except Exception as error:report['error']=str(error);print('ERROR '+str(error),flush=True)
 finally:
  if n:n.close()
  (d/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(d/'report.json'),flush=True)
 return int(not report.get('success',False))
if __name__=='__main__':raise SystemExit(main())
