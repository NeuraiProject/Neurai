from pathlib import Path
import struct,hashlib,json
u=lambda x,n:x.to_bytes(n,'little',signed=False)
b=lambda x:u(len(x),4)+x
s=lambda x:b(x.encode('ascii'))
h=lambda x:bytes.fromhex(x)
sha=lambda x:hashlib.sha256(x).digest()
pub='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
identity=hashlib.new('ripemd160',sha(h(pub))).digest();raw=bytes([127])+identity;raw+=sha(sha(raw))[:4]
n=int.from_bytes(raw,'big');address=''
while n: n,k=divmod(n,58);address='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[k]+address
base={'protocol':3,'network':'01'*32,'pool_pubkey':pub,'pool_root':'&TEST','instance_id':'02'*32,'request_id':'03'*32,'timestamp_ms':1800000000123,'token':'&TEST','address':address,'challenge':'04'*32,'args':{},'signature':''}
rows=[]
def add(name,method,kind,args,encoded,overrides=None):
 req={**base,'args':args,**(overrides or {})}
 data=(s('Neurai/DePIN/RPC/request')+u(3,2)+s(method)+u(kind,1)+h(req['network'])+b(h(req['pool_pubkey']))+s(req['pool_root'])+h(req['instance_id'])+h(req['request_id'])+u(req['timestamp_ms'],8)+s(req['token'])+s(req['address'])+b(h(req['challenge']))+b(encoded))
 rows.append({'name':name,'method':method,'request':req,'bytes':data.hex(),'hash':sha(data).hex(),'preimage':'DEPIN-RPC-REQUEST-v3|'+sha(data).hex()})
add('challenge-default','depinchallenge',1,{},b'\x00',{'challenge':''})
add('read-default','depinreceivemsg',2,{},u(0,8)+b(b'')+u(0,8))
add('read-filter','depinreceivemsg',2,{'timestamp':100,'after_hash':'05'*32,'limit':7},u(100,8)+b(h('05'*32))+u(7,8))
add('sequence-first','depinreceiveseq',2,{},b'\0'+bytes(32)+u(0,8)+u(100,8)+u(0,8))
cursor={'version':1,'stream_id':'06'*32,'after_seq':9007199254740993,'scope':'&TEST','address':address,'from_timestamp':17}
add('sequence-continuation','depinreceiveseq',2,{'cursor':cursor,'limit':7,'from_timestamp':17},b'\x01'+h('06'*32)+u(cursor['after_seq'],8)+u(7,8)+u(17,8))
for mode,n in [('expired',0),('all',1),('hours',2)]:
 args={'mode':mode};args.update({'hours':0} if mode=='hours' else {})
 add('clear-'+mode,'depinclearmsg',3,args,u(n,1)+u(0,8))
add('public-directory','depingetancestorrecipients',0,{},u(1000,8)+s('&TEST'),{'address':'','challenge':''})
add('public-sections','depinlistsections',0,{},b'',{'address':'','challenge':''})
add('personal-sections','depinlistsections',2,{},b'')
add('submit-dummy-envelope','depinsubmitmsg',1,{'encrypted':'00'*64},b(bytes(64)),{'token':'','challenge':''})
method='depingetmsginfo';req={k:base[k] for k in ['protocol','request_id','timestamp_ms']}
data=s('Neurai/DePIN/RPC/request')+u(3,2)+s(method)+u(0,1)+bytes(32)+b(b'')+s('')+bytes(32)+h(req['request_id'])+u(req['timestamp_ms'],8)+s('')+s('')+b(b'')+b(b'')
rows.append({'name':'bootstrap','method':method,'request':req,'bytes':data.hex(),'hash':sha(data).hex(),'preimage':'DEPIN-RPC-REQUEST-v3|'+sha(data).hex()})
Path('src/test/data/depin_rpc_v3.json').write_text(json.dumps({'source':'Independent Python struct/hashlib encoder, see contrib/devtools/depin-v3-vectors.py','cases':rows},indent=2)+'\n')
print('Frozen',len(rows),'independent request vectors')
