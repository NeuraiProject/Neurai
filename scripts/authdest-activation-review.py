#!/usr/bin/env python3
"""NIP-041 activation/reorg regression with a real script-only v1 covenant.
Run inside the build container with /root/Neurai/src/neuraid available.
Isolated temporary regtest wallets, no secrets printed. Returns nonzero on failure.
"""
import importlib.util, pathlib, tempfile, subprocess, hashlib
spec=importlib.util.spec_from_file_location('helpers','/src/scripts/strict-authscript-recovery-review.py')
h=importlib.util.module_from_spec(spec)
helper=pathlib.Path('/src/scripts/strict-authscript-recovery-review.py').read_text()
helper=helper.replace('raise RuntimeError("RPC %s failed (code %s)" % (method, result["error"]["code"]))','raise RuntimeError(str(result["error"]))')
exec(compile(helper, 'helpers', 'exec'), h.__dict__)
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
 covenant=bytes.fromhex('54b67551') # OP_TXFIELD(0x04), DROP, TRUE
 tag=hashlib.sha256(b'NeuraiAuthScript').digest()
 commitment=hashlib.sha256(tag+tag+b'\x01\x00'+hashlib.sha256(covenant).digest()).digest()
 strictscript='5120'+commitment.hex()
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
 funding=a.rpc('getrawtransaction',txid,True)
 vout=next(o['n'] for o in funding['vout'] if o['scriptPubKey']['hex']==strictscript)
 raw=a.rpc('createrawtransaction',[{'txid':txid,'vout':vout}],{legacy:4.95})
 wire=bytes.fromhex(raw)
 witness=bytes([2,1,0,len(covenant)])+covenant
 signedhex=(wire[:4]+bytes.fromhex('0001')+wire[4:-4]+witness+wire[-4:]).hex()
 boundary_ok=True
 try:
  spend=a.rpc('sendrawtransaction',signedhex)
  print('PASS: admission at tip 119',flush=True)
 except RuntimeError as e:
  boundary_ok=False
  print('FAIL: admission at tip 119:',str(e),flush=True)
  a.rpc('generatetoaddress',1,legacy) # tip120: both standard and tip flags active
  spend=a.rpc('sendrawtransaction',signedhex)
 assert spend in a.rpc('getrawmempool')
 a.rpc('invalidateblock',block119)
 assert a.rpc('getblockcount')==118
 remains=spend in a.rpc('getrawmempool')
 print('FAIL: unconfirmed v1 AUTHDEST covenant spend remains in mempool below activation' if remains else 'PASS: v1 AUTHDEST covenant spend evicted below activation',flush=True)
 mining_ok=True
 try:
  # A new coinbase destination prevents recreating the invalidated block 119.
  a.rpc('generatetoaddress',1,a.rpc('getnewaddress'))
  assert a.rpc('getblockcount')==119
  print('PASS: mining after reorg',flush=True)
 except RuntimeError as e:
  mining_ok=False
  print('FAIL: mining after reorg:',str(e),flush=True)
 raise SystemExit(1 if remains or not boundary_ok or not mining_ok else 0)
finally:
 for n in reversed(nodes): n.close()
