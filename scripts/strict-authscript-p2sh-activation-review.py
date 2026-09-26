#!/usr/bin/env python3
"""Regression: a pending P2SH-v3 spend and its child must be evicted below activation.

Run inside the build container:
  python3 /src/scripts/strict-authscript-p2sh-activation-review.py
Uses isolated temporary regtest wallets and dynamic RPC ports. Nonzero on failure.
"""
import importlib.util, pathlib, tempfile, subprocess, hashlib
spec=importlib.util.spec_from_file_location('helpers','/src/scripts/strict-authscript-recovery-review.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
class Node(h.Node):
 def __init__(self,base,name,height):
  self.path=base/name; self.path.mkdir(); self.rpcport,self.p2pport=h.free_port(),h.free_port()
  self.log=(self.path/'process.log').open('w')
  args=['/root/Neurai/src/neuraid','-regtest','-server','-txindex=1','-listen=0','-connect=0','-dnsseed=0','-keypool=3','-fallbackfee=0.01','-rpcuser=review','-rpcpassword=local-test-only','-datadir='+str(self.path),'-rpcport='+str(self.rpcport),'-strictauthscriptheight='+str(height)]
  self.proc=subprocess.Popen(args,stdout=self.log,stderr=subprocess.STDOUT)
base=pathlib.Path(tempfile.mkdtemp(prefix='strict-mempool-review-')); nodes=[]
print('Artifacts:',base,flush=True)
try:
 a=Node(base,'target',120); nodes.append(a); a.ready()
 f=Node(base,'factory',0); nodes.append(f); f.ready()
 strict=f.rpc('getnewaddress','','ecdsa'); secret=f.rpc('dumpprivkey',strict)
 strictscript=f.rpc('validateaddress',strict)['scriptPubKey']
 redeemscript=strictscript
 strictscript='a914'+hashlib.new('ripemd160',hashlib.sha256(bytes.fromhex(redeemscript)).digest()).hexdigest()+'87'
 legacy=a.rpc('getnewaddress'); legacyscript=a.rpc('validateaddress',legacy)['scriptPubKey']
 a.rpc('generatetoaddress',117,legacy)
 raw=a.rpc('createrawtransaction',[],{legacy:5})
 funded=a.rpc('fundrawtransaction',raw,{'feeRate':0.02})['hex']
 needle=bytes([len(bytes.fromhex(legacyscript))]).hex()+legacyscript
 replacement=bytes([len(bytes.fromhex(strictscript))]).hex()+strictscript
 assert funded.count(needle)==1
 changed=funded.replace(needle,replacement)
 signed=a.rpc('signrawtransaction',changed); assert signed['complete']
 txid=a.rpc('sendrawtransaction',signed['hex'])
 a.rpc('generatetoaddress',1,legacy) # funding at 118, before activation
 block119=a.rpc('generatetoaddress',1,legacy)[0]
 a.rpc('importprivkey',secret,'',False); del secret
 funding=a.rpc('getrawtransaction',txid,True)
 vout=next(o['n'] for o in funding['vout'] if o['scriptPubKey']['hex']==strictscript)
 raw=a.rpc('createrawtransaction',[{'txid':txid,'vout':vout}],{legacy:4.95})
 signed=f.rpc('signrawtransaction',raw,[{'txid':txid,'vout':vout,'scriptPubKey':redeemscript,'amount':5}]); assert signed['complete']
 wire=bytes.fromhex(signed['hex'])
 assert wire[4:7]==bytes.fromhex('000101') and wire[43]==0
 push=bytes([len(bytes.fromhex(redeemscript))])+bytes.fromhex(redeemscript)
 signed['hex']=(wire[:43]+bytes([len(push)])+push+wire[44:]).hex()
 spend=a.rpc('sendrawtransaction',signed['hex'])
 assert spend in a.rpc('getrawmempool')
 # This child spends an ordinary Legacy output: only recursive eviction removes it.
 childraw=a.rpc('createrawtransaction',[{'txid':spend,'vout':0}],{legacy:4.90})
 childsigned=a.rpc('signrawtransaction',childraw); assert childsigned['complete']
 child=a.rpc('sendrawtransaction',childsigned['hex'])
 assert child in a.rpc('getrawmempool')
 a.rpc('invalidateblock',block119)
 assert a.rpc('getblockcount')==118
 remains=spend in a.rpc('getrawmempool')
 print('FAIL: unconfirmed P2SH strict spend remains in mempool below activation' if remains else 'PASS: P2SH strict spend evicted below activation',flush=True)
 childremains=child in a.rpc('getrawmempool')
 print('FAIL: descendant remains in mempool' if childremains else 'PASS: Legacy descendant evicted with P2SH parent',flush=True)
 raise SystemExit(1 if remains or childremains else 0)
finally:
 for n in reversed(nodes): n.close()
