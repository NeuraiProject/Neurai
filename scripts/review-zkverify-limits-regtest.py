#!/usr/bin/env python3
"""NIP-018 calibrated-cost boundaries and cold k=16 full blocks, isolated regtest."""
import argparse,importlib.util,json,struct,tempfile,time
from pathlib import Path
import authscript_tree as tree
spec=importlib.util.spec_from_file_location('blocks',Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);h=m.h
COST=280

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));p.add_argument('--fixtures',type=Path,required=True);a=p.parse_args()
 directory=Path(tempfile.mkdtemp(prefix='nip018-limits-'));nodes=[]
 report={'binary_sha256':h.digest_file(a.bindir/'neuraid'),'cost':COST,'results':[]}
 def check(label,ok,observed=None):
  report['results'].append({'case':label,'passed':bool(ok),'observed':observed});print(('PASS ' if ok else 'FAIL ')+label,flush=True)
  if not ok:raise RuntimeError(label+': '+str(observed))
 try:
  source=h.Node(a.bindir,directory/'source',['-bypassdownload=1','-acceptnonstdtxn=0']);nodes.append(source);source.ready()
  miner=source.rpc('getnewaddress');source.rpc('generatetoaddress',110,miner)
  proof=(a.fixtures/'k16.proof.bin').read_bytes();public=(a.fixtures/'k16.public.bin').read_bytes()
  contracts=[];payments={}
  def add(leaf,args,cost):
   commitment=tree.tagged('NeuraiAuthScript',b'\x01\x00'+tree.H(leaf));program=b'\x51\x20'+commitment
   payments[m.bech32m('tnc',1,commitment)]=1
   contracts.append((leaf,args,program,cost));return len(contracts)-1
  def zk(index,padding=0):
   vk=(a.fixtures/f'vk-{index:04}.bin').read_bytes()
   leaf=b'\x76\xa8'+h.push(tree.H(vk))+b'\x88'+b''.join(h.push(public[i:i+32]) for i in range(0,512,32))+b'\x60\x51\xc3'
   if padding:leaf+=b'\x00\x63'+b'\xac'*padding+b'\x68'
   return add(leaf,[proof,vk],COST+padding)
  base=[zk(i) for i in range(284)]
  last={cost:zk(284,cost-284*COST-COST) for cost in (80000,80001)}
  # Static ECDSA work in inactive branches fills exact policy boundaries.
  extra=[]
  for i in range(29):extra.append(add(b'\x00\x63'+h.push(struct.pack('<I',i))+b'\xac'*500+b'\x68\x51',[],500))
  policy_last={cost:add(b'\x00\x63'+b'\xac'*(cost-4*COST-29*500)+b'\x68\x51',[],cost-4*COST-29*500) for cost in (16000,16001)}
  fund=source.rpc('sendmany','',payments);source.rpc('generatetoaddress',1,miner)
  lookup={v['scriptPubKey']['hex']:v['n'] for v in source.rpc('getrawtransaction',fund,True)['vout']}
  def spend(chosen,invalid=False):
   inputs=h.compact(len(chosen));witness=b''
   for offset,index in enumerate(chosen):
    leaf,args,program,cost=contracts[index]
    inputs+=h.outpoint(fund,lookup[program.hex()])+b'\x00'+b'\xff'*4
    args=list(args)
    if invalid and offset==len(chosen)-1:args[0]=args[0][:-1]
    stack=[b'\x00']+args+[leaf]
    witness+=h.compact(len(stack))+b''.join(h.compact(len(v))+v for v in stack)
   outputs=b'\x01'+m.output((len(chosen)-1)*h.COIN,b'\x53\x20'+bytes(range(32)))
   v=struct.pack('<I',2)
   return v+inputs+outputs+bytes(4),v+b'\x00\x01'+inputs+outputs+witness+bytes(4)
  for count in (4,5):
   chosen=base[:count];result=source.rpc('testmempoolaccept',[spend(chosen)[1].hex()])[0]
   check(f'policy zk count {count}',result['allowed'] if count==4 else not result['allowed'] and 'bad-witness-nonstandard' in str(result),result)
  for cost in (16000,16001):
   chosen=base[:4]+extra+[policy_last[cost]]
   check(f'constructed policy cost {cost}',sum(contracts[i][3] for i in chosen)==cost)
   result=source.rpc('testmempoolaccept',[spend(chosen)[1].hex()])[0]
   check(f'policy sigops {cost}',result['allowed'] if cost==16000 else not result['allowed'] and 'bad-txns-too-many-sigops' in str(result),result)
  template=source.rpc('getblocktemplate',{'rules':['segwit']});history=[source.rpc('getblock',source.rpc('getblockhash',i),False) for i in range(1,112)]
  candidates={}
  for cost in (80000,80001):
   chosen=base+[last[cost]];check(f'constructed block cost {cost}',sum(contracts[i][3] for i in chosen)==cost)
   raw,blockhash,weight=m.block(template,spend(chosen));check(f'block weight {cost}',weight<template['weightlimit'],weight);candidates[cost]=(raw,blockhash)
  for par in (1,2):
   node=h.Node(a.bindir,directory/f'validator{par}',['-disablewallet=1',f'-par={par}']);nodes.append(node);node.ready()
   for raw in history:
    result=node.rpc('submitblock',raw)
    if result is not None:raise RuntimeError(result)
   # Rejected by static cost, so it cannot warm either cache before the valid block.
   result=node.rpc('submitblock',candidates[80001][0].hex());check(f'par{par} 80001 rejects',result=='bad-blk-sigops',result)
   check(f'par{par} rejected tip unchanged',node.rpc('getblockcount')==111)
   start=time.monotonic();result=node.rpc('submitblock',candidates[80000][0].hex());elapsed=time.monotonic()-start
   check(f'par{par} cold 80000 accepts',result is None,{'result':result,'seconds':elapsed,'proofs':285,'unique_vks':285})
   check(f'par{par} accepted tip',node.rpc('getbestblockhash')==candidates[80000][1])
  report['success']=True
 finally:
  for node in nodes:node.close()
  (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(directory/'report.json'),flush=True)

if __name__=='__main__':main()
