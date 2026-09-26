#!/usr/bin/env python3
"""NIP-018 executed ZK/ECDSA/PQ/Poseidon mixed blocks on isolated regtests."""
import argparse,importlib.util,json,struct,tempfile,time,subprocess
from pathlib import Path
import authscript_tree as tree
spec=importlib.util.spec_from_file_location('blocks',Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);h=m.h
COST=282 # 280 ZK + two executed CSFS signatures

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--saturate-poseidon',action='store_true');p.add_argument('--signer',type=Path,default=Path('/tmp/authscript-review-signer'));a=p.parse_args()
 directory=Path(tempfile.mkdtemp(prefix='nip018-mixed-'));nodes=[]
 report={'binary_sha256':h.digest_file(a.bindir/'neuraid'),'cost':COST,'results':[], 'workload':{'proofs':283,'distinct_vks':283,'ecdsa':283,'pq':283,'poseidon':84900}, 'driver_sha256':h.digest_file(Path(__file__)), 'signer_sha256':h.digest_file(a.signer)}
 def check(label,ok,observed=None):
  report['results'].append({'case':label,'passed':bool(ok),'observed':observed});print(('PASS ' if ok else 'FAIL ')+label,flush=True)
  if not ok:raise RuntimeError(label+': '+str(observed))
 try:
  source=h.Node(a.bindir,directory/'source',['-bypassdownload=1','-acceptnonstdtxn=0']);nodes.append(source);source.ready()
  miner=source.rpc('getnewaddress');source.rpc('generatetoaddress',110,miner)
  proof=(a.fixtures/'k16.proof.bin').read_bytes();public=(a.fixtures/'k16.public.bin').read_bytes()
  contracts=[];payments={}
  keys={}
  for family in ('ecdsa','pq'):
   pub,secret=subprocess.check_output([str(a.signer),'keygen',family],text=True).splitlines()
   keys[family]=(bytes.fromhex(pub),secret)

  def add(leaf,args,cost):
   commitment=tree.tagged('NeuraiAuthScript',b'\x01\x00'+tree.H(leaf));program=b'\x51\x20'+commitment
   payments[m.bech32m('tnc',1,commitment)]=1
   contracts.append((leaf,args,program,cost));return len(contracts)-1
  def zk(index,padding=0):
   vk=(a.fixtures/f'vk-{index:04}.bin').read_bytes()
   leaf=b'\x76\xa8'+h.push(tree.H(vk))+b'\x88'+b''.join(h.push(public[i:i+32]) for i in range(0,512,32))+b'\x60\x51\xc3'
   if padding:leaf+=b'\x00\x63'+b'\xac'*padding+b'\x68'
   msg=tree.H(b'NIP018/mixed/'+struct.pack('<I',index))
   sigs={family:bytes.fromhex(subprocess.check_output([str(a.signer),'sign',family],input=secret+'\n'+tree.H(msg).hex()+'\n',text=True).strip()) for family,(pub,secret) in keys.items()}
   prefix=b''.join(h.push(msg)+h.push(keys[family][0])+b'\xb4\x69' for family in ('pq','ecdsa'))
   leaf=prefix+b'\x00'+b'\xc9'*300+b'\x75'+leaf
   return add(leaf,[proof,vk,sigs['ecdsa'],sigs['pq']],COST+padding)
  base=[zk(i) for i in range(282)]
  last={cost:zk(282,cost-283*COST) for cost in (80000,80001)}
  fillers=[];overfill=None
  if a.saturate_poseidon:
   for i in range(230):
    fillers.append(add(h.push(struct.pack('<I',i))+b'\x75'+b'\xc9'*500+b'\x75\x51',[b''],0))
   fillers.append(add(b'\xc9'*100+b'\x75\x51',[b''],0))
   overfill=add(b'\xc9'*101+b'\x75\x51',[b''],0)
   report['workload']['poseidon']=200000
  fund=source.rpc('sendmany','',payments);source.rpc('generatetoaddress',1,miner)
  lookup={v['scriptPubKey']['hex']:v['n'] for v in source.rpc('getrawtransaction',fund,True)['vout']}
  def spend(chosen,invalid=None):
   inputs=h.compact(len(chosen));witness=b''
   for offset,index in enumerate(chosen):
    leaf,args,program,cost=contracts[index]
    inputs+=h.outpoint(fund,lookup[program.hex()])+b'\x00'+b'\xff'*4
    args=list(args)
    if invalid and offset==len(chosen)-1:
     pos={'proof':0,'ecdsa':2,'pq':3}[invalid]
     mutated=bytearray(args[pos]);mutated[31 if pos==0 else 10]^=128 if pos==0 else 1;args[pos]=bytes(mutated)
    stack=[b'\x00']+args+[leaf]
    witness+=h.compact(len(stack))+b''.join(h.compact(len(v))+v for v in stack)
   outputs=b'\x01'+m.output(len(chosen)*h.COIN-h.COIN//10,b'\x53\x20'+bytes(range(32)))
   v=struct.pack('<I',2)
   return v+inputs+outputs+bytes(4),v+b'\x00\x01'+inputs+outputs+witness+bytes(4)
  for count in (4,5):
   chosen=base[:count];result=source.rpc('testmempoolaccept',[spend(chosen)[1].hex()])[0]
   check(f'policy zk count {count}',result['allowed'] if count==4 else not result['allowed'] and 'bad-witness-nonstandard' in str(result),result)
  for family in ('proof','ecdsa','pq'):
   result=source.rpc('testmempoolaccept',[spend(base[:1],family)[1].hex()])[0]
   check('reject altered '+family,not result['allowed'] and 'script' in str(result),result)
  template=source.rpc('getblocktemplate',{'rules':['segwit']});history=[source.rpc('getblock',source.rpc('getblockhash',i),False) for i in range(1,112)]
  candidates={}
  for cost in (80000,80001):
   chosen=base+fillers+[last[cost]];check(f'constructed block cost {cost}',sum(contracts[i][3] for i in chosen)==cost)
   raw,blockhash,weight=m.block(template,spend(chosen));check(f'block weight {cost}',weight<template['weightlimit'],weight);candidates[cost]=(raw,blockhash)
  overwork=None
  if a.saturate_poseidon:
   overwork=m.block(template,spend(base+fillers[:-1]+[overfill,last[80000]]))[0]
  for par in (1,2):
   node=h.Node(a.bindir,directory/f'validator{par}',['-disablewallet=1',f'-par={par}']);nodes.append(node);node.ready()
   for raw in history:
    result=node.rpc('submitblock',raw)
    if result is not None:raise RuntimeError(result)
   # Rejected by static cost, so it cannot warm either cache before the valid block.
   result=node.rpc('submitblock',candidates[80001][0].hex());check(f'par{par} 80001 rejects',result=='bad-blk-sigops',result)
   check(f'par{par} rejected tip unchanged',node.rpc('getblockcount')==111)
   start=time.monotonic();result=node.rpc('submitblock',candidates[80000][0].hex());elapsed=time.monotonic()-start
   check(f'par{par} cold 80000 accepts',result is None,{'result':result,'seconds':elapsed,'proofs':283,'unique_vks':283})
   check(f'par{par} accepted tip',node.rpc('getbestblockhash')==candidates[80000][1])
   node.rpc('invalidateblock',candidates[80000][1])
   if overwork is not None:
    result=node.rpc('submitblock',overwork.hex())
    check(f'par{par} 200001 work rejects',result=='bad-blk-poseidon-work',result)
    check(f'par{par} work rejection tip unchanged',node.rpc('getblockcount')==111)
   for family in ('proof','ecdsa','pq'):
    bad,bad_hash,weight=m.block(template,spend(base+fillers+[last[80000]],family))
    start=time.monotonic();result=node.rpc('submitblock',bad.hex());elapsed=time.monotonic()-start
    check(f'par{par} mixed block rejects {family}',result is not None and ('script' in str(result) or (par==2 and result=='block-validation-failed')),{'result':result,'seconds':elapsed,'cache':'warm after valid block'})
    check(f'par{par} invalid tip unchanged {family}',node.rpc('getblockcount')==111)
   node.rpc('reconsiderblock',candidates[80000][1])
   check(f'par{par} valid block restored',node.rpc('getbestblockhash')==candidates[80000][1])
  report['success']=True
 finally:
  for node in nodes:node.close()
  (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(directory/'report.json'),flush=True)

if __name__=='__main__':main()
