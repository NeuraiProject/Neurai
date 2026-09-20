#!/usr/bin/env python3
"""NIP-043 primitives and a real UNIQUE state thread. Temporary, isolated regtest.
No DEMO ZK/MAST: deliverable 1 uses a genuine ECDSA or ML-DSA CSFS oracle.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


t = module('txhash', 'review-txhash-regtest.py')
h = t.h
a = module('assets', 'review-asset-fields-regtest.py')
b = module('blocks', 'review-csfs-block-limit-regtest.py')
sha = t._ctv.sha
push = h.push
ROOT12 = bytes.fromhex('115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a')


def address(script):
    tag = sha(b'NeuraiAuthScript')
    c = sha(tag + tag + b'\x01\x00' + sha(script))
    return t._ctv.bech32m('tnc', 1, c), b'\x51\x20' + c


def transfer(prefix, name, state, expiration=b'', message_tag=0x54):
    payload = b'xnat' + h.compact(len(name)) + name.encode() + struct.pack('<q', h.COIN) + bytes([message_tag,32]) + state + expiration
    return prefix + b'\xc0' + push(payload) + b'\x75'


def strip_witness(wire):
    """Parse lengths explicitly; support the v2/v3 transactions used here."""
    pos=6
    def compact():
        nonlocal pos
        first=wire[pos];pos+=1
        if first<253:return first
        width={253:2,254:4,255:8}[first]
        value=int.from_bytes(wire[pos:pos+width],'little');pos+=width;return value
    for _ in range(compact()):
        pos+=36
        length=compact();pos+=length+4
    for _ in range(compact()):
        pos+=8
        length=compact();pos+=length
    if int.from_bytes(wire[:4],'little')==3:
        count=compact();pos+=36*count
    return wire[:4]+wire[6:pos]+wire[-4:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--oracle', choices=('ecdsa','pq'), default='ecdsa')
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    parser.add_argument('--sponsor', choices=('legacy','ecdsa','pq'), default='legacy')
    parser.add_argument('--strict-height', type=int, default=0)
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='nip043-regtest-'))
    report = dict(results=[], oracle=args.oracle, sponsor=args.sponsor, strict_height=args.strict_height, binary_sha256=h.digest_file(args.bindir/'neuraid'),
                  signer_sha256=h.digest_file(args.signer),
                  source_sha256={p.name:h.digest_file(p) for p in (Path(__file__),
                    Path(__file__).with_name('review-txhash-regtest.py'),
                    Path(__file__).with_name('review-introspection-regtest.py'),
                    Path(__file__).with_name('review-asset-fields-regtest.py'),
                    Path(__file__).with_name('review-csfs-block-limit-regtest.py'))})
    nodes=[]
    def check(label, ok, observed=None):
        report['results'].append(dict(case=label,passed=bool(ok),observed=observed))
        print(('PASS ' if ok else 'FAIL ')+label,flush=True)
        if not ok: raise RuntimeError(f'{label}: {observed}')
    def node(label, par=1, extra=()):
        n=h.Node(args.bindir,directory/label,['-assetmessageheight=620','-inputfieldheight=620',
            '-merkleposeidonheight=620',f'-strictauthscriptheight={args.strict_height}','-bypassdownload=1','-acceptnonstdtxn=0',f'-par={par}',*extra])
        nodes.append(n);n.ready();return n
    def replay(n, blocks):
        for block in blocks:
            result=n.rpc('submitblock',block)
            if result is not None: raise RuntimeError('replay: '+result)
    try:
        n=node('source');miner=n.rpc('getnewaddress','','legacy')
        wallet_script=bytes.fromhex(n.rpc('validateaddress',miner)['scriptPubKey'])
        n.rpc('generatetoaddress',610,miner)
        def confirm(txid):
            if isinstance(txid,list):txid=txid[0]
            n.rpc('generatetoaddress',1,miner)
            return n.rpc('getrawtransaction',txid,True)
        def locate(tx,spk,asset=False):
            for out in tx['vout']:
                wire=bytes.fromhex(out['scriptPubKey']['hex'])
                if (wire.startswith(spk) and len(wire)>len(spk)) if asset else wire==spk:
                    return tx['txid'],out['n']
            raise RuntimeError('funding output missing')
        def fund(script):
            addr,spk=address(script)
            return locate(confirm(n.rpc('sendtoaddress',addr,1)),spk)
        confirm(n.rpc('issue','THREAD043',1,miner))
        issuance=confirm(n.rpc('issueunique','THREAD043',['state'],None,miner))
        name='THREAD043#state'
        issuance_vout=next(o['n'] for o in issuance['vout'] if
            (b'xnaq'+h.compact(len(name))+name.encode()).hex() in o['scriptPubKey']['hex'])
        network_genesis=n.rpc('getblockhash',0)
        domain=sha(b'NIP043/instance/v3'+bytes.fromhex(network_genesis)[::-1]+
                   h.outpoint(issuance['txid'],issuance_vout)+h.compact(len(name))+name.encode())
        pub,secret=subprocess.check_output([str(args.signer),'keygen',args.oracle],text=True).splitlines()
        pub=bytes.fromhex(pub)
        # Keep UNIQUE and commitment, require 32-byte old/new states. Oracle
        # signs DOMAIN || old_state || new_state, as specified in NIP-043 §8.
        # The state carrier has no protected XNA (§4.1): enforce zero on both sides.
        state_script=b'\x00\xd6\x00\x88\x00\xcc\x00\x88'
        for op in (0xcf,0xce):
            for selector,expected in ((1,name.encode()),(2,a.number(h.COIN))):
                state_script+=b'\x00'+push(bytes([selector]))+bytes([op])+push(expected)+b'\x88'
            state_script+=b'\x00'+push(b'\x08')+bytes([op])+b'\x82'+push(a.number(32))+b'\x88\x75'
        # Exact transfer template also excludes expiration and alternate pushes.
        # Derive C at runtime to avoid a circular commitment to this script.
        tail=transfer(b'',name,bytes(32))[:-33]
        for query in (0xcf,0xce):
            state_script+=push(b'\x51\x20')+push(b'\x02')+b'\xb6\x7e'+push(tail)+b'\x7e'
            state_script+=b'\x00'+push(b'\x08')+bytes([query])+b'\x7e'+push(b'\x75')+b'\x7e'
            state_script+=(b'\x00'+push(b'\x03')+b'\xc4' if query==0xcf else b'\x00\xcd')+b'\x88'
        state_script+=b'\x00\xd5'+push(b'\x02')+b'\xb6\x88'
        state_script+=push(domain)+b'\x00'+push(b'\x08')+b'\xcf\x7e'
        state_script+=b'\x00'+push(b'\x08')+b'\xce\x7e'+push(pub)+b'\xb4'
        state_addr,state_spk=address(state_script)
        initial=bytes(range(32))
        state_utxo=locate(confirm(n.rpc('transfer',name,1,state_addr,initial.hex())),state_spk,True)
        check('thread/initial_state_bytes',n.rpc('gettxout',*state_utxo)['scriptPubKey']['hex']==transfer(state_spk,name,initial).hex())
        # Sponsor is wallet-owned, kept out of automatic coin selection.
        sponsor_node=node('sponsor-wallet',extra=['-strictauthscriptheight=0']+(['-pqwallet=1'] if args.sponsor=='pq' else [])) if args.sponsor!='legacy' else n
        sponsor_address=miner if args.sponsor=='legacy' else sponsor_node.rpc('getnewaddress','',args.sponsor)
        sponsor_spk=sponsor_node.rpc('validateaddress',sponsor_address)['scriptPubKey']
        # Raw native outputs can be funded before their spend rules activate.
        # Decode/generate the strict destination only in the helper wallet.
        funding_coin=next(u for u in n.rpc('listunspent') if u['amount']>2)
        funding_value=round(funding_coin['amount']*h.COIN)
        funding_raw=a.raw_transaction([(funding_coin['txid'],funding_coin['vout'])],
            [(h.COIN,bytes.fromhex(sponsor_spk)),(funding_value-h.COIN-1_000_000,wallet_script)],[],[[]])
        funding_signed=n.rpc('signrawtransaction',funding_raw)['hex']
        coin_tx=confirm(n.rpc('sendrawtransaction',funding_signed))
        coin=next((coin_tx['txid'],o['n']) for o in coin_tx['vout'] if o['value']==1 and o['scriptPubKey']['hex']==sponsor_spk)
        check('sponsor/family',sponsor_spk.startswith({'legacy':'76a914','ecdsa':'5320','pq':'5220'}[args.sponsor]),sponsor_spk)
        n.rpc('lockunspent',False,[dict(txid=coin[0],vout=coin[1])])
        input_script=b'\x00'+push(b'\x01')+b'\xc4'+push(struct.pack('<q',h.COIN))+b'\x87'
        input_utxo=fund(input_script)
        leaf=(1).to_bytes(32,'big');proof=b'\x01'+(2).to_bytes(32,'big')+b'\x00'
        merkle_script=push(leaf)+push(b'\x05')+push(proof)+push(ROOT12)+b'\xc1'
        merkle_utxo=fund(merkle_script)
        # Exercise the reference message path against a real confirmed UNIQUE.
        refscript=b'\x00'+push(b'\x08')+b'\xd3\x82'+push(a.number(32))+b'\x88\x75\x51'
        ref_utxo=fund(refscript)
        inverted_script=merkle_script+b'\x91'
        inverted_utxo=fund(inverted_script)
        inverted_raw=h.transaction(inverted_utxo,inverted_script,wallet_script)
        next_state=bytes(range(32,64))
        inputs=[state_utxo,coin]
        if sponsor_node is not n:
            replay(sponsor_node,[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,n.rpc('getblockcount')+1)])
        def state_raw(state=next_state, target=state_spk, signature=None, signed_state=None, expiration=b'', signing_domain=None, state_value=0, old_state=initial, spent_inputs=None, change=90_000_000, message_tag=0x54):
            outputs=[(state_value,transfer(target,name,state,expiration,message_tag)),(change,wallet_script)]
            message=(domain if signing_domain is None else signing_domain)+old_state+(state if signed_state is None else signed_state)
            if signature is None:
                signature=bytes.fromhex(subprocess.check_output([str(args.signer),'sign',args.oracle],
                    input=secret+'\n'+sha(message).hex()+'\n',text=True).strip())
            wire=a.raw_transaction(inputs if spent_inputs is None else spent_inputs,outputs,[],[[b'\x00',signature,state_script],[]])
            if spent_inputs is None and sponsor_node is not n:
                return sponsor_node.rpc('signrawtransaction',wire)['hex']
            return n.rpc('signrawtransaction',wire)['hex']
        good=state_raw()
        sponsor_only=a.raw_transaction([coin],[(90_000_000,wallet_script)],[],[[]])
        sponsor_only=sponsor_node.rpc('signrawtransaction',sponsor_only)['hex']
        report['oracle_vector']=dict(network_genesis=network_genesis,issuance_txid=issuance['txid'],
            issuance_vout=issuance_vout,unique=name,domain=domain.hex(),old=initial.hex(),new=next_state.hex(),
            pubkey=pub.hex(),message=(domain+initial+next_state).hex(),
            signed_hash=sha(domain+initial+next_state).hex(),
            signature=n.rpc('decoderawtransaction',good)['vin'][0]['txinwitness'][1])
        cases={'message':good,'inputfield':h.transaction(input_utxo,input_script,wallet_script),
               'merkle':h.transaction(merkle_utxo,merkle_script,wallet_script),
               'reference_message':h.transaction(ref_utxo,refscript,wallet_script,[state_utxo])}
        n.rpc('generatetoaddress',618-n.rpc('getblockcount'),miner)
        r=n.rpc('testmempoolaccept',[sponsor_only])[0]
        check('sponsor/below_height',r.get('allowed')==(args.sponsor=='legacy' or args.strict_height<=619),r)
        for label,raw in cases.items():
            r=n.rpc('testmempoolaccept',[raw])[0];check(label+'/below_height',not r.get('allowed'),r)
        history=[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,619)]
        producer=node('producer')
        replay(producer,history)
        block619=producer.rpc('generatetoaddress',1,miner)[0]
        wire619=producer.rpc('getblock',block619,False)
        inverted_txid=n.rpc('sendrawtransaction',inverted_raw)
        child=n.rpc('createrawtransaction',[dict(txid=inverted_txid,vout=0)],[{miner:0.98}])
        child=n.rpc('signrawtransaction',child)['hex']
        child_txid=n.rpc('sendrawtransaction',child)
        check('ascending/inverse_and_child_pending',all(x in n.rpc('getrawmempool') for x in (inverted_txid,child_txid)))
        replay(n,[wire619])
        check('ascending/inverse_and_child_evicted',all(x not in n.rpc('getrawmempool') for x in (inverted_txid,child_txid)))
        r=n.rpc('testmempoolaccept',[inverted_raw])[0]
        check('ascending/inverse_rejected',not r.get('allowed'),r)
        r=n.rpc('testmempoolaccept',[sponsor_only])[0]
        check('sponsor/candidate620',r.get('allowed')==(args.sponsor=='legacy' or args.strict_height<=620),r)
        for label,raw in cases.items():
            r=n.rpc('testmempoolaccept',[raw])[0];check(label+'/candidate620',r.get('allowed')==1,r)
        for label,raw in [('changed_state_without_oracle',state_raw(bytes([9])*32,signed_state=next_state)),
                          ('bad_signature',state_raw(signature=b'')),
                          ('ipfs_not_32_byte_state',state_raw(message_tag=0x12,signed_state=b'\x12\x20'+next_state)),
                          ('expiry_with_valid_oracle',state_raw(expiration=bytes(8))),
                          ('wrong_instance_domain',state_raw(signing_domain=bytes(32))),
                          ('nonzero_state_value',state_raw(state_value=1)),
                          ('escaped_unique',state_raw(target=wallet_script))]:
            r=n.rpc('testmempoolaccept',[raw])[0];check(label+'/rejected',not r.get('allowed'),r)
        # Reference transaction must precede the state transition consuming its reference.
        pending={label:n.rpc('sendrawtransaction',cases[label]) for label in ('inputfield','merkle','reference_message')}
        n.rpc('invalidateblock',block619)
        check('reorg/tip618',n.rpc('getblockcount')==618)
        r=n.rpc('testmempoolaccept',[sponsor_only])[0]
        check('sponsor/descending_height',r.get('allowed')==(args.sponsor=='legacy' or args.strict_height<=619),r)
        r=n.rpc('testmempoolaccept',[inverted_raw])[0]
        check('descending/inverse_valid_again',r.get('allowed')==1,r)
        for label,txid in pending.items():check(label+'/evicted_on_crossing',txid not in n.rpc('getrawmempool'))
        n.rpc('getblocktemplate',{'rules':['segwit']});check('reorg/mining_template_valid',True)
        n.rpc('reconsiderblock',block619)
        for label in pending:
            if pending[label] not in n.rpc('getrawmempool'):n.rpc('sendrawtransaction',cases[label])
        block620=n.rpc('generatetoaddress',1,miner)[0];wire620=n.rpc('getblock',block620,False)
        for label,txid in pending.items():check(label+'/mined',n.rpc('getrawtransaction',txid,True)['confirmations']==1)
        txid=n.rpc('sendrawtransaction',good);block621=n.rpc('generatetoaddress',1,miner)[0]
        check('thread/transition_mined',n.rpc('getrawtransaction',txid,True)['confirmations']==1)
        check('thread/unique_preserved',n.rpc('gettxout',txid,0)['scriptPubKey']['hex']==transfer(state_spk,name,next_state).hex())
        check('thread/old_state_consumed',n.rpc('gettxout',*state_utxo) is None)
        n.rpc('invalidateblock',block621)
        check('thread/disconnect_restores_old_state',n.rpc('gettxout',*state_utxo,False) is not None)
        n.rpc('reconsiderblock',block621)
        check('thread/reconnect_restores_new_state',n.rpc('gettxout',txid,0) is not None)
        # Complete-block script execution, independent empty mempools, both thread modes.
        for par in (1,2):
            v=node(f'validator{par}',par)
            replay(v,history)
            # Every new primitive must fail in a full block before its height.
            for label,raw in cases.items():
                template=n.rpc('getblocktemplate',{'rules':['segwit']})
                template.update(height=619,previousblockhash=n.rpc('getblockhash',618))
                wire=bytes.fromhex(raw)
                invalid,_,_=b.block(template,(strip_witness(wire),wire))
                result=v.rpc('submitblock',invalid.hex())
                expected={'inputfield':'opcode','merkle':'false','message':'ASSETFIELD','reference_message':'ASSETFIELD'}[label]
                check(f'par{par}/{label}/inactive_block', result is not None and
                      (expected.lower() in result.lower() if par==1 else result=='block-validation-failed'), result)
                check(f'par{par}/{label}/tip_unchanged',v.rpc('getblockcount')==618)
            replay(v,[wire619,wire620,n.rpc('getblock',block621,False)])
            check(f'par{par}/same_final_tip',v.rpc('getbestblockhash')==block621)
        # Restart source to check that activation comes from height, not process state.
        command=n.proc.args;n.close();n.log=(n.directory/'process.log').open('a')
        n.proc=subprocess.Popen(command,stdout=n.log,stderr=subprocess.STDOUT);n.ready()
        check('restart/state_persisted',n.rpc('gettxout',txid,0) is not None)
        # Deliverable 1 can chain two genuine oracle transitions in the same block.
        # This does not assert the ZK custody transition rules of deliverable 2.
        state2=bytes([0xa2])*32;state3=bytes([0xa3])*32
        raw2=state_raw(state=state2,old_state=next_state,spent_inputs=[(txid,0),(txid,1)],change=80_000_000)
        id2=n.rpc('sendrawtransaction',raw2)
        raw3=state_raw(state=state3,old_state=state2,spent_inputs=[(id2,0),(id2,1)],change=70_000_000)
        id3=n.rpc('sendrawtransaction',raw3)
        both=n.rpc('generatetoaddress',1,miner)[0]
        ordered=n.rpc('getblock',both)['tx']
        check('thread/two_transitions_same_block',id2 in ordered and id3 in ordered and ordered.index(id2)<ordered.index(id3))
        final=n.rpc('gettxout',id3,0)
        check('thread/final_state_and_zero_value',final['value']==0 and final['scriptPubKey']['hex']==transfer(state_spk,name,state3).hex())
        check('thread/intermediate_consumed',n.rpc('gettxout',id2,0) is None)
        n.rpc('invalidateblock',both)
        old=n.rpc('gettxout',txid,0,False)
        check('thread/two_disconnect_restore',old is not None and old['value']==0 and old['scriptPubKey']['hex']==transfer(state_spk,name,next_state).hex())
        check('thread/two_readmitted',all(i in n.rpc('getrawmempool') for i in (id2,id3)))
        n.rpc('reconsiderblock',both)
        check('thread/two_reconnect_restore',n.rpc('gettxout',id3,0,False)['scriptPubKey']['hex']==transfer(state_spk,name,state3).hex())
        wire=n.rpc('getblock',both,False)
        for validator in [v for v in nodes if v.directory.name in ('validator1','validator2')]:
            replay(validator,[wire])
            check(validator.directory.name+'/two_transitions_block',validator.rpc('getbestblockhash')==both)
        invalid_dir=directory/'invalid-option';invalid_dir.mkdir()
        for option in ('assetmessageheight','inputfieldheight','merkleposeidonheight'):
            for value in ('-1','2147483648','1.5'):
                proc=subprocess.run([str(args.bindir/'neuraid'),'-regtest',f'-{option}={value}',
                    f'-datadir={invalid_dir}'],text=True,capture_output=True,timeout=30)
                check(f'option/{option}/{value}',proc.returncode!=0 and 'Invalid -'+option in proc.stderr,proc.stderr.strip())
            proc=subprocess.run([str(args.bindir/'neuraid'),f'-{option}=1',f'-datadir={invalid_dir}'],
                text=True,capture_output=True,timeout=30)
            check(f'option/{option}/mainnet',proc.returncode!=0 and 'only be overridden on regtest' in proc.stderr,proc.stderr.strip())
    except Exception as error:
        report['error']=str(error);print('ERROR:',error,flush=True)
    finally:
        for n in reversed(nodes):n.close()
        report['passed']=sum(r['passed'] for r in report['results'])
        report['failed']=sum(not r['passed'] for r in report['results'])+int('error' in report)
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('Report:',directory/'report.json',flush=True)
    return int(report['failed']!=0)

if __name__=='__main__':raise SystemExit(main())
