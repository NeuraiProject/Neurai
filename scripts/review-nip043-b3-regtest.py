#!/usr/bin/env python3
"""Real-node B3 consolidation and non-ZK guards, with real Poseidon and MAST.
No fake verifier. Frozen scripts commit to unexecuted DEMO leaves: test funds only.
"""
import argparse,copy,hashlib,importlib.util,json,struct,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('thread',Path(__file__).with_name('review-contract-thread-regtest.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
h=r.h

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));p.add_argument('--sponsor',choices=['legacy','ecdsa','pq'],default='legacy');p.add_argument('--chain',action='store_true',help='Mine two dependent B3 transitions in one block');args=p.parse_args()
 f=json.loads((ROOT/'src/test/data/nip043_b3_fixture.json').read_text())
 d=Path(tempfile.mkdtemp(prefix='nip043-b3-'));nodes=[];report={'sponsor':args.sponsor,'chain':args.chain,'results':[],'binary_sha256':h.digest_file(args.bindir/'neuraid'),'fixture_sha256':h.digest_file(ROOT/'src/test/data/nip043_b3_fixture.json'),'driver_sha256':h.digest_file(Path(__file__))}
 def check(label,ok,observed=None):
  report['results'].append(dict(case=label,passed=bool(ok),observed=observed));print(('PASS ' if ok else 'FAIL ')+label,flush=True)
  if not ok:raise RuntimeError(label+': '+str(observed))
 def node(name,par=1,extra=()):
  n=h.Node(args.bindir,d/name,['-bypassdownload=1','-acceptnonstdtxn=0',f'-par={par}',*extra]);nodes.append(n);n.ready();return n
 def asset(program,name,amount,msg=None):
  data=b'xnat'+h.compact(len(name))+name.encode()+struct.pack('<q',amount)
  if msg is not None:data+=b'\x54\x20'+msg
  return b'\x51\x20'+program+b'\xc0'+h.push(data)+b'\x75'
 try:
  n=node('source');miner=n.rpc('getnewaddress','','legacy');pay=bytes.fromhex(n.rpc('validateaddress',miner)['scriptPubKey'])
  n.rpc('generatetoaddress',610,miner)
  def confirm(txid):
   if isinstance(txid,list):txid=txid[0]
   n.rpc('generatetoaddress',1,miner);return n.rpc('getrawtransaction',txid,True)
  def fund_asset(name,amount,program,msg=None):
   addr=r.t._ctv.bech32m('tnc',1,program)
   tx=confirm(n.rpc('transfer',name,amount,addr,*([msg.hex()] if msg is not None else [])))
   index=next(o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'].startswith((b'\x51\x20'+program).hex()))
   return (tx['txid'],index)
  confirm(n.rpc('issue',f['name'],50 if args.chain else 40,miner));confirm(n.rpc('issueunique',f['name'],['POOL'],None,miner))
  c=bytes.fromhex(f['program']);cv=bytes.fromhex(f['vault_program']);cd=bytes.fromhex(f['deposit_program']);statehash=bytes.fromhex(f['state_hash'])
  # Exercise each guard end-to-end with an explicitly permissive state fixture.
  # This validates the auxiliary, not custody authorization of that OP_TRUE state.
  free_c=r.address(b'\x51')[1][2:]
  for kind in ('vault','deposit'):
   aux=bytes.fromhex(f[kind]);assert aux.count(c)==1
   aux=aux.replace(c,free_c);aux_c=r.address(aux)[1][2:]
   state_in=fund_asset(f['unique'],1,free_c)
   aux_in=fund_asset(f['name'],10,aux_c,bytes([9])*32 if kind=='deposit' else None)
   funding=confirm(n.rpc('sendtoaddress',miner,2))
   fee_in=(funding['txid'],next(o['n'] for o in funding['vout'] if o['value']==2 and o['scriptPubKey']['hex']==pay.hex()))
   outputs=[(0,pay+asset(bytes(32),f['unique'],h.COIN)[34:]),
            (0,pay+asset(bytes(32),f['name'],10*h.COIN)[34:]),(190_000_000,pay)]
   ws=[[b'\x00',b'\x51'],[b'\x00',aux],[]]
   wire=n.rpc('signrawtransaction',r.a.raw_transaction([state_in,aux_in,fee_in],outputs,[],ws))['hex']
   result=n.rpc('testmempoolaccept',[wire])[0];check(kind+'/guard_valid',result.get('allowed'),result)
   bad=n.rpc('signrawtransaction',r.a.raw_transaction([aux_in,state_in,fee_in],outputs,[],[ws[1],ws[0],ws[2]]))['hex']
   result=n.rpc('testmempoolaccept',[bad])[0];check(kind+'/wrong_input0',not result.get('allowed'),result)
   mined=confirm(n.rpc('sendrawtransaction',wire));check(kind+'/mined',mined['confirmations']==1)
  state=fund_asset(f['unique'],1,c,statehash)
  reserves=[fund_asset(f['name'],10,cv) for _ in range(2)]
  deposit=fund_asset(f['name'],10,cd,bytes([7])*32)
  with_message=fund_asset(f['name'],10,cv,bytes([8])*32)
  third_reserve=fund_asset(f['name'],10,cv) if args.chain else None
  sponsor=node('sponsor',extra=['-addresstype=pq']) if args.sponsor=='pq' else n
  payout=miner if args.sponsor=='legacy' else sponsor.rpc('getnewaddress','',args.sponsor)
  pay=bytes.fromhex(sponsor.rpc('validateaddress',payout)['scriptPubKey'])
  coin_tx=confirm(n.rpc('sendtoaddress',payout,2));coin=(coin_tx['txid'],next(o['n'] for o in coin_tx['vout'] if o['value']==2 and o['scriptPubKey']['hex']==pay.hex()))
  if sponsor is not n:
   for j in range(1,n.rpc('getblockcount')+1):
    response=sponsor.rpc('submitblock',n.rpc('getblock',n.rpc('getblockhash',j),False))
    if response is not None:raise RuntimeError(response)
  ins=[state,*reserves,coin]
  outs=[(0,asset(c,f['unique'],h.COIN,statehash)),(0,asset(cv,f['name'],20*h.COIN)),(190_000_000,pay)]
  witnesses=[[b'\x10',bytes.fromhex(f['old']),bytes.fromhex(f['leaf']),bytes.fromhex(f['control'])],*[ [b'\x00',bytes.fromhex(f['vault'])] for _ in range(2)],[]]
  def raw(inputs=ins,outputs=outs,ws=witnesses):
   return sponsor.rpc('signrawtransaction',r.a.raw_transaction(inputs,outputs,[],ws))['hex']
  good=raw();res=n.rpc('testmempoolaccept',[good])[0];check('B3/valid',res.get('allowed'),res)
  def reject(label,inputs=ins,outputs=outs,ws=witnesses):
   res=n.rpc('testmempoolaccept',[raw(inputs,outputs,ws)])[0];check(label,not res.get('allowed'),res)
  w=copy.deepcopy(witnesses);w[0][1]=w[0][1][:-1]+b'\x00';reject('B3/mode0',ws=w)
  w=copy.deepcopy(witnesses);w[0][1]=b'\x01'+w[0][1][1:];reject('B3/wrong_opening',ws=w)
  w=copy.deepcopy(witnesses);w[0].insert(1,b'extra');reject('B3/extra_argument',ws=w)
  o=copy.deepcopy(outs);o[0]=(0,asset(c,f['unique'],h.COIN,bytes(32)));reject('B3/changed_state',outputs=o)
  o=copy.deepcopy(outs);o[1]=(0,asset(cv,f['name'],20*h.COIN,bytes(32)));reject('B3/reserve_output_message',outputs=o)
  o=copy.deepcopy(outs);o[1]=(1,o[1][1]);reject('B3/reserve_nonzero_xna',outputs=o)
  o=copy.deepcopy(outs);o[2]=(o[2][0],b'\x53\x20'+bytes(32));reject('B3/redirect_sponsor',outputs=o)
  o=copy.deepcopy(outs);o.append((0,b'\x6a'));reject('B3/extra_output',outputs=o)
  i=ins.copy();i[1]=deposit;w=copy.deepcopy(witnesses);w[1]=[b'\x00',bytes.fromhex(f['deposit'])];reject('B3/deposit_in_reserve_slot',inputs=i,ws=w)
  i=ins.copy();i[1]=with_message;reject('B3/reserve_input_message',inputs=i)
  i=ins.copy();i[1],i[0]=i[0],i[1];w=copy.deepcopy(witnesses);w[1],w[0]=w[0],w[1];reject('guards/state_not_input0',inputs=i,ws=w)
  i=ins.copy();i[2]=deposit;w=copy.deepcopy(witnesses);w[2]=[b'\x00',bytes.fromhex(f['deposit'])];reject('B3/deposit_in_second_reserve_slot',inputs=i,ws=w)
  i=ins.copy();i[2]=with_message;reject('B3/second_reserve_input_message',inputs=i)
  o=copy.deepcopy(outs);o[0]=(1,o[0][1]);reject('B3/state_nonzero_xna',outputs=o)
  # Keep asset totals equal: the extra withdrawal must fail the contract shape.
  o=copy.deepcopy(outs);o[1]=(0,asset(cv,f['name'],19*h.COIN));o.append((0,pay+asset(bytes(32),f['name'],h.COIN)[34:]));reject('B3/extra_asset_withdrawal',outputs=o)
  # Asset conservation is checked by the node, not by the isolated Script test.
  for amount in (19,21):
   o=copy.deepcopy(outs);o[1]=(0,asset(cv,f['name'],amount*h.COIN));reject('B3/asset_balance_'+str(amount),outputs=o)
  o=copy.deepcopy(outs);o[0]=(1,o[0][1]);bad_wire=bytes.fromhex(raw(outputs=o))
  bad_block,_,_=r.b.block(n.rpc('getblocktemplate',{'rules':['segwit']}),(r.strip_witness(bad_wire),bad_wire))
  txid=n.rpc('sendrawtransaction',good)
  final_txid=txid;final_outs=outs
  if args.chain:
   child_inputs=[(txid,0),(txid,1),third_reserve,(txid,2)]
   child_outs=[outs[0],(0,asset(cv,f['name'],30*h.COIN)),(180_000_000,pay)]
   # The separate PQ wallet has not received the unconfirmed parent over P2P.
   # Explicit prevouts supply its amounts/scripts; real wallet keys sign it.
   previous=[{'txid':txid,'vout':j,'scriptPubKey':outs[j][1].hex(),'amount':outs[j][0]/h.COIN} for j in range(3)]
   child=sponsor.rpc('signrawtransaction',r.a.raw_transaction(child_inputs,child_outs,[],witnesses),previous)['hex']
   result=n.rpc('testmempoolaccept',[child])[0];check('B3/child_admitted',result.get('allowed'),result)
   final_txid=n.rpc('sendrawtransaction',child);final_outs=child_outs
   # getblocktemplate caches mempool updates for >5 seconds on an unchanged tip.
   for attempt in range(12):
    selected=[t['txid'] for t in n.rpc('getblocktemplate',{'rules':['segwit']})['transactions']]
    if txid in selected and final_txid in selected:break
    time.sleep(1)
   check('B3/parent_before_child_template',txid in selected and final_txid in selected and selected.index(txid)<selected.index(final_txid),selected)
  block=n.rpc('generatetoaddress',1,miner)[0]
  if args.chain:
   selected=n.rpc('getblock',block)['tx']
   check('B3/two_transitions_one_block',txid in selected and final_txid in selected and selected.index(txid)<selected.index(final_txid))
   check('B3/intermediate_state_and_reserve_spent',n.rpc('gettxout',txid,0) is None and n.rpc('gettxout',txid,1) is None)
  check('B3/mined',n.rpc('getrawtransaction',txid,True)['confirmations']==1)
  check('B3/consolidated',n.rpc('gettxout',final_txid,1)['scriptPubKey']['hex']==final_outs[1][1].hex())
  n.rpc('invalidateblock',block);check('B3/disconnect',all(n.rpc('gettxout',*u,False) is not None for u in ins+([third_reserve] if args.chain else [])))
  if args.chain:
   check('B3/reorg_both_readmitted',{txid,final_txid}.issubset(set(n.rpc('getrawmempool'))))
  n.rpc('reconsiderblock',block);check('B3/reconnect',n.rpc('gettxout',final_txid,0,False) is not None)
  if args.chain:
   check('B3/reconnect_final_reserve',n.rpc('gettxout',final_txid,1,False)['scriptPubKey']['hex']==final_outs[1][1].hex())
  blocks=[n.rpc('getblock',n.rpc('getblockhash',j),False) for j in range(1,n.rpc('getblockcount')+1)]
  for par in (1,2):
   v=node('validator'+str(par),par)
   for wire in blocks[:-1]:
    result=v.rpc('submitblock',wire)
    if result is not None:raise RuntimeError(result)
   previous=v.rpc('getbestblockhash')
   response=v.rpc('submitblock',bad_block.hex())
   check(f'B3/nonzero_state_block_par{par}',response is not None and v.rpc('getbestblockhash')==previous,response)
   response=v.rpc('submitblock',blocks[-1])
   check(f'B3/blocks_par{par}',response is None and v.rpc('getbestblockhash')==block,response)
  report['success']=True
 except Exception as e:
  report['error']=str(e);print('ERROR '+str(e),flush=True)
 finally:
  for n in reversed(nodes):n.close()
  (d/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(d/'report.json'),flush=True)
 return int(not report.get('success',False))
if __name__=='__main__':raise SystemExit(main())
