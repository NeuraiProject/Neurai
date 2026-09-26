#!/usr/bin/env python3
"""NIP-044: real ECDSA/PQ spends, activation/reorg, block validation and restart.
Uses isolated regtest directories; never touches an existing node or wallet.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import socket
from review_tree_compact import relay as relay_compact

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
r=module('contract_thread_helpers',ROOT/'scripts/review-contract-thread-regtest.py')
v=module('tree_bytes',ROOT/'scripts/authscript_tree.py')
h=r.h

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'))
    parser.add_argument('--signer',type=Path,default=Path('/tmp/authscript-review-signer'))
    args=parser.parse_args()
    directory=Path(tempfile.mkdtemp(prefix='nip044-regtest-'))
    report={'binary_sha256':h.digest_file(args.bindir/'neuraid'),
            'source_sha256':{p.name:h.digest_file(p) for p in (Path(__file__),ROOT/'scripts/authscript_tree.py')},
            'results':[]}
    nodes=[]
    def check(label,condition,observed=None):
        report['results'].append({'case':label,'passed':bool(condition),'observed':observed})
        print(('PASS ' if condition else 'FAIL ')+label,flush=True)
        if not condition:raise RuntimeError(label+': '+str(observed))
    def start(label,par=1,extra=()):
        n=h.Node(args.bindir,directory/label,['-authscripttreeheight=120','-bypassdownload=1','-pubkeyindex=1','-addressindex=1','-acceptnonstdtxn=0',f'-par={par}',*extra])
        nodes.append(n);n.ready();return n
    def sign(algorithm,secret,digest):
        return bytes.fromhex(subprocess.check_output([str(args.signer),'sign',algorithm],input=secret+'\n'+digest.hex()+'\n',text=True).strip())
    try:
        n=start('source');miner=n.rpc('getnewaddress','','legacy')
        target=bytes.fromhex(n.rpc('validateaddress',miner)['scriptPubKey'])
        n.rpc('generatetoaddress',110,miner)
        cases=[]
        signing_keys={}
        for algorithm in ('ecdsa','pq'):
            pub,secret=subprocess.check_output([str(args.signer),'keygen',algorithm],text=True).splitlines()
            pub=bytes.fromhex(pub)
            signing_keys[algorithm]=(pub,secret)
            for auth in (0x10,0x11 if algorithm=='pq' else 0x12):
                script=h.push(pub)+b'\xac'
                root,controls=v.tree({'spend':script,'unused':b'\x00'})
                desc=b'\x00' if auth==0x10 else bytes([auth&15])+hashlib.new('ripemd160',v.H(pub)).digest()
                program=v.commitment(root,desc);spk=b'\x51\x20'+program
                address=r.t._ctv.bech32m('tnc',1,program)
                txid=n.rpc('sendtoaddress',address,1)
                n.rpc('generatetoaddress',1,miner)
                funding=n.rpc('getrawtransaction',txid,True)
                index=next(x['n'] for x in funding['vout'] if x['scriptPubKey']['hex']==spk.hex())
                prev=h.outpoint(txid,index);sequence=b'\xff'*4
                output=struct.pack('<Q',90000000)+h.compact(len(target))+target
                pre=struct.pack('<I',3)+v.D(prev)+v.D(sequence)+prev+h.compact(len(script))+script
                pre+=struct.pack('<Q',h.COIN)+sequence+v.D(output)+v.D(b'')+bytes(4)+bytes([auth])+struct.pack('<I',1)
                base=v.D(pre)
                signature=sign(algorithm,secret,v.signature_hash(base,1,auth,program,v.leaf(script)))
                witness=[bytes([auth])]
                if auth!=0x10:
                    witness += [sign(algorithm,secret,v.signature_hash(base,0,auth,program,v.leaf(script))),pub]
                witness += [signature,script,controls['spend']]
                raw=r.a.raw_transaction([(txid,index)],[(90000000,target)],[],[witness])
                cases.append((algorithm+'/'+hex(auth),raw,program,witness,(txid,index)))
        n.rpc('generatetoaddress',118-n.rpc('getblockcount'),miner)
        for label,raw,*_ in cases:
            result=n.rpc('testmempoolaccept',[raw])[0]
            check(label+'/inactive',not result['allowed'],result)
        block119=n.rpc('generatetoaddress',1,miner)[0]
        ids=[]
        for label,raw,program,witness,utxo in cases:
            result=n.rpc('testmempoolaccept',[raw])[0]
            check(label+'/candidate_active',result['allowed'],result)
            bad=[*witness];bad[-1]=bad[-1][:-1]+bytes([bad[-1][-1]^1])
            invalid=r.a.raw_transaction([utxo],[(90000000,target)],[],[bad])
            check(label+'/wrong_path',not n.rpc('testmempoolaccept',[invalid])[0]['allowed'])
            ids.append(n.rpc('sendrawtransaction',raw))
        child=r.a.raw_transaction([(ids[0],0)],[(80000000,target)],[],[[]])
        child=n.rpc('signrawtransaction',child)['hex']
        child_id=n.rpc('sendrawtransaction',child)
        n.rpc('invalidateblock',block119)
        check('reorg/height118',n.rpc('getblockcount')==118)
        check('reorg/pending_removed',not any(i in n.rpc('getrawmempool') for i in ids))
        check('reorg/descendant_removed',child_id not in n.rpc('getrawmempool'))
        check('reorg/template_available',n.rpc('getblocktemplate',{'rules':['segwit']})['height']==119)
        n.rpc('reconsiderblock',block119)
        for label,raw,*_ in cases:n.rpc('sendrawtransaction',raw)
        block120=n.rpc('generatetoaddress',1,miner)[0]
        for txid in ids:check('mined/'+txid,n.rpc('getrawtransaction',txid,True)['confirmations']==1)
        def check_indexes(prefix):
            for label,_,program,witness,_ in cases:
                indexed=n.rpc('getpubkey',r.t._ctv.bech32m('tnc',1,program))
                expected=witness[0]!=b'\x10'
                check(prefix+'/'+label,indexed['revealed']==expected and
                    (not expected or indexed['pubkey']==witness[2].hex()),indexed)
        check_indexes('pubkey_index')
        # Disconnect the funding parents as well as their confirmed tree spends.
        funding_block=n.rpc('getblockhash',111)
        n.rpc('invalidateblock',funding_block)
        check('deep_reorg/height110',n.rpc('getblockcount')==110)
        check('deep_reorg/spends_removed',not any(txid in n.rpc('getrawmempool') for txid in ids))
        check('deep_reorg/template_available',n.rpc('getblocktemplate',{'rules':['segwit']})['height']==111)
        n.rpc('reconsiderblock',funding_block)
        check('deep_reorg/restored',n.rpc('getbestblockhash')==block120)
        # Real BIP152 v2 reconstruction, with and without transactions already in mempool.
        history=[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,120)]
        for par in (1,2):
            for known in (False,True):
                label=f'compact/par{par}/known{int(known)}'
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                validator=start(f'compact-{par}-{int(known)}',par,
                    ['-listen=1',f'-port={port}',f'-bind=127.0.0.1:{port}','-debug=net'])
                for wire in history:
                    response=validator.rpc('submitblock',wire)
                    if response is not None:raise RuntimeError(response)
                relay_compact(n,validator,port,block120,known,check,label)
                validator.close()
        # P2SH wrapping and real asset suffix use the same validated tree path.
        program=v.commitment(v.leaf(b'\x51'))
        redeem=b'\x51\x20'+program
        p2sh=n.rpc('decodescript',redeem.hex())['p2sh']
        wrapped_script=b'\xa9\x14'+hashlib.new('ripemd160',v.H(redeem)).digest()+b'\x87'
        def confirm(txid):
            if isinstance(txid,list):txid=txid[0]
            n.rpc('generatetoaddress',1,miner)
            return n.rpc('getrawtransaction',txid,True)
        funded=confirm(n.rpc('sendtoaddress',p2sh,1))
        index=next(x['n'] for x in funded['vout'] if x['scriptPubKey']['hex']==wrapped_script.hex())
        wire=bytes.fromhex(r.a.raw_transaction([(funded['txid'],index)],[(90000000,target)],[],[[b'\x10',b'\x51',b'\x01']]))
        # Single input: version/marker/flag/count (7 B), then 36-byte outpoint.
        script_sig=h.push(redeem)
        wire=wire[:43]+h.compact(len(script_sig))+script_sig+wire[44:]
        result=n.rpc('testmempoolaccept',[wire.hex()])[0]
        check('wrapped/accepted',result['allowed'],result)
        confirm(n.rpc('sendrawtransaction',wire.hex()))
        # The documented three-route vault, using real keys and independent sighashes.
        vault_keys={}
        for label,algorithm in (('hot','ecdsa'),('cold','pq'),('recover','ecdsa')):
            pub,secret=subprocess.check_output([str(args.signer),'keygen',algorithm],text=True).splitlines()
            vault_keys[label]=(algorithm,bytes.fromhex(pub),secret)
        pubcold=vault_keys['cold'][1]
        leaves={'hot':h.push(vault_keys['hot'][1])+b'\xac',
                'cold':b'\x76\xa9'+h.push(hashlib.new('ripemd160',v.H(pubcold)).digest())+b'\x88\xac',
                'recover':h.push(b'\x90\x00')+b'\xb2\x75'+h.push(vault_keys['recover'][1])+b'\xac'}
        root,controls=v.tree(leaves);program=v.commitment(root)
        vault_addr=r.t._ctv.bech32m('tnc',1,program);vault_spk=b'\x51\x20'+program
        funding={}
        for label in leaves:
            funded=confirm(n.rpc('sendtoaddress',vault_addr,1))
            index=next(o['n'] for o in funded['vout'] if o['scriptPubKey']['hex']==vault_spk.hex())
            funding[label]=(funded['txid'],index)
        vault_raw={}
        for label,script in leaves.items():
            seq=struct.pack('<I',144 if label=='recover' else 0xffffffff)
            prev=h.outpoint(*funding[label]);output=struct.pack('<Q',90000000)+h.compact(len(target))+target
            pre=struct.pack('<I',2)+v.D(prev)+v.D(seq)+prev+h.compact(len(script))+script
            pre+=struct.pack('<Q',h.COIN)+seq+v.D(output)+bytes(4)+b'\x10'+struct.pack('<I',1)
            algorithm,pub,secret=vault_keys[label]
            sig=sign(algorithm,secret,v.signature_hash(v.D(pre),1,0x10,program,v.leaf(script)))
            stack=[b'\x10',sig]+([pub] if label=='cold' else [])+[script,controls[label]]
            witness=h.compact(len(stack))+b''.join(h.compact(len(x))+x for x in stack)
            raw=struct.pack('<I',2)+b'\x00\x01\x01'+prev+b'\x00'+seq+b'\x01'+output+witness+bytes(4)
            vault_raw[label]=raw.hex()
            result=n.rpc('testmempoolaccept',[raw.hex()])[0]
            check('vault/'+label+'/initial',result['allowed']==(label!='recover'),result)
            if label!='recover':confirm(n.rpc('sendrawtransaction',raw.hex()))
        n.rpc('generatetoaddress',144,miner)
        result=n.rpc('testmempoolaccept',[vault_raw['recover']])[0]
        check('vault/recover/mature',result['allowed'],result)
        recovered=confirm(n.rpc('sendrawtransaction',vault_raw['recover']))
        check('vault/recover/mined',recovered['confirmations']==1)
        n.rpc('generatetoaddress',610-n.rpc('getblockcount'),miner)
        confirm(n.rpc('issue','TREE044',1,miner))
        addr=r.t._ctv.bech32m('tnc',1,redeem[2:])
        funded=confirm(n.rpc('transfer','TREE044',1,addr))
        index=next(x['n'] for x in funded['vout'] if x['scriptPubKey']['hex'].startswith(redeem.hex()))
        sponsor=confirm(n.rpc('sendtoaddress',miner,1))
        sponsor_index=next(x['n'] for x in sponsor['vout'] if x['scriptPubKey']['hex']==target.hex() and x['value']==1)
        payload=b'xnat'+h.compact(7)+b'TREE044'+struct.pack('<Q',h.COIN)
        output_asset=target+b'\xc0'+h.push(payload)+b'\x75'
        raw=r.a.raw_transaction([(funded['txid'],index),(sponsor['txid'],sponsor_index)],
            [(0,output_asset),(90000000,target)],[],[[b'\x10',b'\x51',b'\x01'],[]])
        signed=n.rpc('signrawtransaction',raw)
        result=n.rpc('testmempoolaccept',[signed['hex']])[0]
        check('asset/accepted',result['allowed'],result)
        moved=confirm(n.rpc('sendrawtransaction',signed['hex']))
        check('asset/preserved',moved['vout'][0]['scriptPubKey']['hex']==output_asset.hex())
        # Same asset through all four signed tree envelopes (NoAuth/global, EC/PQ).
        for label,_,program,old_witness,_ in cases:
            algorithm=label.split('/')[0];pub,secret=signing_keys[algorithm]
            marker=old_witness[0][0];script=old_witness[-2];control=old_witness[-1]
            funded=confirm(n.rpc('transfer','TREE044',1,r.t._ctv.bech32m('tnc',1,program)))
            asset_output=next(o for o in funded['vout'] if o['scriptPubKey']['hex'].startswith((b'\x51\x20'+program).hex()))
            sponsor=confirm(n.rpc('sendtoaddress',miner,1))
            sponsor_index=next(o['n'] for o in sponsor['vout'] if o['scriptPubKey']['hex']==target.hex() and o['value']==1)
            utxos=[(funded['txid'],asset_output['n']),(sponsor['txid'],sponsor_index)]
            prevs=b''.join(h.outpoint(*u) for u in utxos);seq=b'\xff'*4
            outs=struct.pack('<Q',0)+h.compact(len(output_asset))+output_asset
            outs+=struct.pack('<Q',90000000)+h.compact(len(target))+target
            value=round(asset_output['value']*h.COIN)
            pre=struct.pack('<I',3)+v.D(prevs)+v.D(seq*2)+h.outpoint(*utxos[0])+h.compact(len(script))+script
            pre+=struct.pack('<Q',value)+seq+v.D(outs)+v.D(b'')+bytes(4)+bytes([marker])+struct.pack('<I',1)
            witness=[bytes([marker])]
            if marker!=0x10:
                witness += [sign(algorithm,secret,v.signature_hash(v.D(pre),0,marker,program,v.leaf(script))),pub]
            witness += [sign(algorithm,secret,v.signature_hash(v.D(pre),1,marker,program,v.leaf(script))),script,control]
            raw=r.a.raw_transaction(utxos,[(0,output_asset),(90000000,target)],[],[witness,[]])
            signed=n.rpc('signrawtransaction',raw)
            result=n.rpc('testmempoolaccept',[signed['hex']])[0]
            check('asset/'+label+'/accepted',result['allowed'],result)
            moved=confirm(n.rpc('sendrawtransaction',signed['hex']))
            check('asset/'+label+'/preserved',moved['vout'][0]['scriptPubKey']['hex']==output_asset.hex())
        block120=n.rpc('getbestblockhash')
        blocks=[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,n.rpc('getblockcount')+1)]
        for par in (1,2):
            validator=start('validator'+str(par),par)
            for wire in blocks:
                response=validator.rpc('submitblock',wire)
                if response is not None:raise RuntimeError(response)
            check('full_blocks/par'+str(par),validator.rpc('getbestblockhash')==block120)
        command=n.proc.args;n.close();n.log=(n.directory/'process.log').open('a')
        n.proc=subprocess.Popen(command,stdout=n.log,stderr=subprocess.STDOUT);n.ready()
        check('restart/tip',n.rpc('getbestblockhash')==block120)
        check('restart/verifychain',n.rpc('verifychain',4,0))
        n.close();n.log=(n.directory/'process.log').open('a')
        n.proc=subprocess.Popen(command+['-reindex'],stdout=n.log,stderr=subprocess.STDOUT);n.ready()
        deadline=time.monotonic()+90
        while n.rpc('getbestblockhash')!=block120 and time.monotonic()<deadline:time.sleep(0.2)
        check('reindex/tip',n.rpc('getbestblockhash')==block120)
        check('reindex/verifychain',n.rpc('verifychain',4,0))
        check_indexes('reindex/pubkey_index')
        option_dir=directory/'invalid-option';option_dir.mkdir()
        for value in ('-1','2147483648','1.5'):
            proc=subprocess.run([str(args.bindir/'neuraid'),'-regtest',f'-authscripttreeheight={value}',
                f'-datadir={option_dir}'],text=True,capture_output=True,timeout=30)
            check('option/'+value,proc.returncode!=0 and 'Invalid -authscripttreeheight' in proc.stderr)
        proc=subprocess.run([str(args.bindir/'neuraid'),'-authscripttreeheight=1',f'-datadir={option_dir}'],
            text=True,capture_output=True,timeout=30)
        check('option/mainnet',proc.returncode!=0 and 'only be overridden on regtest' in proc.stderr)
        report['success']=True
    finally:
        for n in nodes:n.close()
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('REPORT '+str(directory/'report.json'),flush=True)
    return 0
if __name__=='__main__':raise SystemExit(main())
