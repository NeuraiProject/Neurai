#!/usr/bin/env python3
"""Real CP1 User+anchor proofs and authenticated reference VK carriers. Test keys only."""
import argparse,contextlib,importlib.util,io,json,struct,subprocess,tempfile
from pathlib import Path
import authscript_tree as tree
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent

def load(name,file):
 spec=importlib.util.spec_from_file_location(name,file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
m=load('blocks',HERE/'review-csfs-block-limit-regtest.py');h=m.h
txhash=load('txhash',HERE/'review-txhash-regtest.py')
with contextlib.redirect_stdout(io.StringIO()):poseidon=load('poseidon',HERE/'generate-poseidon-review-vectors.py')
P=21888242871839275222246405745257275088696311157297823662689037894645226208583

def g1(p):
 x,y=map(int,p[:2]);assert 0<=x<P and 0<=y<P and y*y%P==(x*x*x+3)%P
 return (x|((1<<255) if y>P-y else 0)).to_bytes(32,'little')
def g2(p):
 x=list(map(int,p[0]));y=tuple(map(int,p[1]))
 assert all(0<=a<P for a in [*x,*y]);neg=tuple((-a)%P for a in y)
 return x[0].to_bytes(32,'little')+(x[1]|((1<<255) if (y[1],y[0])>(neg[1],neg[0]) else 0)).to_bytes(32,'little')
def vk_bytes(v):
 return g1(v['vk_alpha_1'])+g2(v['vk_beta_2'])+g2(v['vk_gamma_2'])+g2(v['vk_delta_2'])+struct.pack('<Q',len(v['IC']))+b''.join(g1(q) for q in v['IC'])
def num(n):
 if not n:return b'\x00'
 b=n.to_bytes((n.bit_length()+7)//8,'little');b+=b'\x00' if b[-1]&128 else b''
 return h.push(b)

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));ap.add_argument('--circuit',type=Path,required=True);a=ap.parse_args()
 directory=Path(tempfile.mkdtemp(prefix='nip018-anchor-node-'));node=None;report={'binary_sha256':h.digest_file(a.bindir/'neuraid'),'results':[]}
 def check(label,ok,observed=None):
  report['results'].append({'case':label,'passed':bool(ok),'observed':observed});print(('PASS ' if ok else 'FAIL ')+label,flush=True)
  if not ok:raise RuntimeError(label+': '+str(observed))
 cli=Path('/tmp/nip043-groth16-tools/node_modules/snarkjs/build/cli.cjs')
 basecmd=['node','--require',str(ROOT/'NIP/bench/cp1-circuits/limit_workers.cjs'),str(cli)]
 def snark(name,args):
  with (directory/(name+'.log')).open('w') as log:subprocess.run(basecmd+list(map(str,args)),stdout=log,stderr=log,check=True,timeout=600)
 try:
  vk=vk_bytes(json.loads((a.circuit/'vk.json').read_text()));check('VK has six public inputs',len(vk)==456)
  data=json.loads((ROOT/'doc/review-results/nip043/cp1-user/compiled/user_main/family_3.json').read_text())
  owner=b'\x51';carrier=h.push(vk)+b'\x75'+owner;fake=bytearray(vk);fake[31]^=128;fakecarrier=h.push(bytes(fake))+b'\x75'+owner
  # Exact carrier grammar and length, then explicit VK authorization by hash.
  leaf=b'\x6b'+b'\x00\xcc'+num(int(data['amount']))+b'\x9d'
  leaf+=b'\x00\x53\xd2'+b'\x82'+num(len(carrier))+b'\x9d'+b'\x53\xb7\x7c'+h.push(carrier[:3])+b'\x88'
  leaf+=num(len(vk))+b'\xb7'+h.push(b'\x75'+owner)+b'\x88'+b'\x76\xa8'+h.push(tree.H(vk))+b'\x88'
  leaf+=h.push(int(data['cm']).to_bytes(32,'big'))+h.push(int(data['nf']).to_bytes(32,'big'))
  leaf+=b'\x00\xc2\xc9'+h.push(int(data['amount']).to_bytes(32,'big'))
  leaf+=h.push(b'\xff\x01')+b'\xb5\xc9\x6c\x56\x51\xc3'
  flat=tree.tagged('NeuraiAuthScript',b'\x01\x00'+tree.H(leaf));mast=tree.commitment(tree.leaf(leaf));programs=[b'\x51\x20'+flat,b'\x51\x20'+mast]
  node=h.Node(a.bindir,directory/'node',['-bypassdownload=1','-acceptnonstdtxn=0']);node.ready();miner=node.rpc('getnewaddress','','legacy');node.rpc('generatetoaddress',110,miner)
  scripts=[carrier,fakecarrier,b'\x51',*programs]
  outputs=b''.join(m.output(2*h.COIN,s) for s in scripts)
  raw=struct.pack('<I',2)+b'\x00'+h.compact(len(scripts))+outputs+bytes(4)
  funded=node.rpc('fundrawtransaction',raw.hex(),{'changePosition':len(scripts)})
  signed=node.rpc('signrawtransaction',funded['hex']);check('carrier funding signed',signed['complete'])
  funding=bytes.fromhex(signed['hex']);decoded=node.rpc('decoderawtransaction',funding.hex());check('funding uses legacy serialization',decoded['txid']==decoded['hash'])
  result=node.rpc('testmempoolaccept',[funding.hex()])[0];check('carrier creation nonstandard',not result['allowed'] and 'scriptpubkey' in str(result),result)
  template=node.rpc('getblocktemplate',{'rules':['segwit']});block,bhash,weight=m.block(template,(funding,funding));result=node.rpc('submitblock',block.hex());check('carrier creation valid in block',result is None,result)
  txid=decoded['txid'];out=b'\x53\x20'+bytes(range(32))
  def transaction(index,proof,response,destination=out,amount=h.COIN,refs=(0,2),sequence=0xffffffff):
   vin=b'\x01'+h.outpoint(txid,index)+b'\x00'+struct.pack('<I',sequence)
   vout=b'\x01'+m.output(amount,destination);refbytes=h.compact(len(refs))+b''.join(h.outpoint(txid,i) for i in refs)
   stack=[b'\x10' if index==4 else b'\x00',proof,response,leaf]
   if index==4:stack.append(b'\x01')
   witness=h.compact(len(stack))+b''.join(h.compact(len(s))+s for s in stack)
   v=struct.pack('<I',3);return v+b'\x00\x01'+vin+vout+refbytes+witness+bytes(4)
  for index,label in [(3,'flat'),(4,'mast')]:
   digest=txhash.field_hash(511,3,0,[h.outpoint(txid,index)],[0xffffffff],[(h.COIN,out)],0,[h.outpoint(txid,i) for i in (0,2)])
   anchor=int(poseidon.sponge(digest),16)
   response=poseidon.permute([18043254*256+data['sk'][31],int.from_bytes(bytes(data['sk'][:31]),'little'),anchor])[0]
   inputs={**data,'anchor':str(anchor),'response':str(response)};path=directory/(label+'.json');path.write_text(json.dumps(inputs))
   witness=directory/(label+'.wtns');subprocess.run(['node',str(a.circuit/'anchor_main_js/generate_witness.js'),str(a.circuit/'anchor_main_js/anchor_main.wasm'),str(path),str(witness)],check=True,capture_output=True,timeout=120)
   snark(label+'_witness',['wtns','check',a.circuit/'anchor_main.r1cs',witness])
   proofpath=directory/(label+'_proof.json');pubpath=directory/(label+'_public.json')
   snark(label+'_prove',['groth16','prove',a.circuit/'anchor.zkey',witness,proofpath,pubpath]);snark(label+'_verify',['groth16','verify',a.circuit/'vk.json',pubpath,proofpath])
   public=json.loads(pubpath.read_text());check(label+' public ordering',list(map(int,public))==[int(inputs[k]) for k in ('cm','nf','destHash','amount','anchor','response')])
   p=json.loads(proofpath.read_text());proof=g1(p['pi_a'])+g2(p['pi_b'])+g1(p['pi_c']);response=response.to_bytes(32,'big')
   baseline=transaction(index,proof,response)
   result=node.rpc('testmempoolaccept',[baseline.hex()])[0];check(label+' real anchor accepted',result['allowed'],result)
   variants={'destination':{'destination':out[:-1]+bytes([out[-1]^1])},'amount':{'amount':h.COIN+1},'reference_order':{'refs':(2,0)},'reference_removed':{'refs':(0,)},'forged_VK_same_owner':{'refs':(1,2)},'sequence':{'sequence':0xfffffffe}}
   for name,kw in variants.items():
    result=node.rpc('testmempoolaccept',[transaction(index,proof,response,**kw).hex()])[0]
    check(label+' rejects '+name,not result['allowed'] and 'script' in str(result) and (name!='forged_VK_same_owner' or 'OP_EQUALVERIFY' in str(result)),result)
   # Independent verifier: no public input may be silently ignored by R1CS.
   for position in (range(6) if label=='flat' else [4]):
    mutated=public[:];mutated[position]=str((int(mutated[position])+1)%poseidon.R)
    mp=directory/(label+'_wrong_public_'+str(position)+'.json');mp.write_text(json.dumps(mutated))
    run=subprocess.run(basecmd+['groth16','verify',str(a.circuit/'vk.json'),str(mp),str(proofpath)],capture_output=True,text=True,timeout=120)
    (directory/(label+'_wrong_public_'+str(position)+'.log')).write_text(run.stdout+run.stderr)
    check(label+' independent changed public '+str(position)+' rejected','Invalid proof' in run.stdout+run.stderr,(run.stdout+run.stderr).strip())
   if label=='flat':
    for name,field,position in [('domain','note',1),('asset_identity','note',33),('note_nonce','note',137),('spend_secret','sk',0)]:
     negative=json.loads(json.dumps(inputs));negative[field][position]^=1
     ip=directory/(name+'_invalid.json');ip.write_text(json.dumps(negative))
     run=subprocess.run(['node',str(a.circuit/'anchor_main_js/generate_witness.js'),str(a.circuit/'anchor_main_js/anchor_main.wasm'),str(ip),str(directory/(name+'_invalid.wtns'))],capture_output=True,text=True,timeout=120)
     (directory/(name+'_invalid.log')).write_text(run.stdout+run.stderr)
     check('circuit rejects altered '+name,run.returncode!=0 and 'Assert Failed' in run.stdout+run.stderr)
   accepted=node.rpc('sendrawtransaction',baseline.hex());node.rpc('generatetoaddress',1,miner)
   check(label+' real spend confirmed',node.rpc('getrawtransaction',accepted,True).get('confirmations',0)>0)
  # A carrier is a real spendable UTXO; OP_TRUE owner chosen solely for this test.
  wire=struct.pack('<I',2)+b'\x01'+h.outpoint(txid,0)+b'\x00'+b'\xff'*4+b'\x01'+m.output(h.COIN,out)+bytes(4)
  result=node.rpc('testmempoolaccept',[wire.hex()])[0];check('carrier spend nonstandard input',not result['allowed'],result)
  template=node.rpc('getblocktemplate',{'rules':['segwit']});raw,bh,w=m.block(template,(wire,wire));result=node.rpc('submitblock',raw.hex());check('carrier spend valid in block',result is None,result)
  report['success']=True
 finally:
  if node:node.close()
  (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(directory/'report.json'),flush=True)

if __name__=='__main__':main()
