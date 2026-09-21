#!/usr/bin/env python3
"""NIP-018 real Groth16 spends, height/reorg and block verification. Isolated regtest only."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import tempfile
import time
import authscript_tree as tree

spec = importlib.util.spec_from_file_location('blocks', Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
h = m.h


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='nip018-opcode-'))
    fixture = (Path(__file__).resolve().parents[1]/'src/test/data/groth16_vectors.h').read_text()
    data = {key: bytes.fromhex(value) for key, value in re.findall(r'char\* (\w+) = "([0-9a-f]+)"', fixture)}
    nodes = []
    report = {'binary_sha256': h.digest_file(args.bindir/'neuraid'), 'results': []}
    def check(label, ok, observed=None):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ')+label, flush=True)
        if not ok:
            raise RuntimeError(label+': '+str(observed))
    try:
        source = h.Node(args.bindir, directory/'source', ['-zkverifyheight=113', '-bypassdownload=1'])
        nodes.append(source); source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        # VK and every public input fixed by the contract, never supplied unchecked.
        leaf = b'\x76\xa8'+h.push(tree.H(data['VK']))+b'\x88'
        leaf += b''.join(h.push(data['INPUTS'][i:i+32]) for i in range(0, len(data['INPUTS']), 32))
        leaf += bytes([0x50+len(data['INPUTS'])//32])+b'\x51\xc3'
        variants=[]; payments={}
        for mast in (False, True):
            commitment = tree.commitment(tree.leaf(leaf)) if mast else tree.tagged('NeuraiAuthScript', b'\x01\x00'+tree.H(leaf))
            program = b'\x51\x20'+commitment
            for wrapped in (False, True):
                address = source.rpc('decodescript', program.hex())['p2sh'] if wrapped else m.bech32m('tnc',1,commitment)
                output = bytes.fromhex(source.rpc('validateaddress',address)['scriptPubKey'])
                variants.append((mast,wrapped,program,output))
                payments[address]=1
        funded = source.rpc('sendmany','',payments)
        source.rpc('generatetoaddress',1,miner)
        lookup = {v['scriptPubKey']['hex']:v['n'] for v in source.rpc('getrawtransaction',funded,True)['vout']}
        def spend(invalid=False):
            inputs=h.compact(4); witness=b''
            for index,(mast,wrapped,program,output) in enumerate(variants):
                scriptSig=h.push(program) if wrapped else b''
                inputs += h.outpoint(funded,lookup[output.hex()])+h.compact(len(scriptSig))+scriptSig+b'\xff'*4
                proof=data['RERANDOMIZED'] if index%2 else data['PROOF']
                if invalid and index==3: proof=proof[:-1]  # malformed nonempty proof
                stack=[b'\x10' if mast else b'\x00',proof,data['VK'],leaf]
                if mast: stack.append(b'\x01')
                witness += h.compact(len(stack))+b''.join(h.compact(len(x))+x for x in stack)
            outputs=b'\x01'+m.output(3*h.COIN,b'\x53\x20'+bytes(range(32)))
            version=struct.pack('<I',2)
            return version+inputs+outputs+bytes(4), version+b'\x00\x01'+inputs+outputs+witness+bytes(4)
        stripped,wire=spend()
        result=source.rpc('testmempoolaccept',[wire.hex()])[0]
        check('before activation rejects',not result['allowed'],result)
        source.rpc('generatetoaddress',1,miner)
        result=source.rpc('testmempoolaccept',[wire.hex()])[0]
        check('candidate height 113 accepts four real proofs',result['allowed'],result)
        # Fresh validators exercise the actual block path, including worker queue.
        template=source.rpc('getblocktemplate',{'rules':['segwit']})
        history=[source.rpc('getblock',source.rpc('getblockhash',i),False) for i in range(1,113)]
        for par in (1,2):
            node=h.Node(args.bindir,directory/f'validator{par}',['-disablewallet=1',f'-par={par}','-zkverifyheight=113'])
            nodes.append(node);node.ready()
            for raw in history:
                result=node.rpc('submitblock',raw)
                if result is not None: raise RuntimeError(result)
            for invalid in (True,False):
                raw,blockhash,weight=m.block(template,spend(invalid))
                result=node.rpc('submitblock',raw.hex())
                check(f'block par={par} invalid={invalid}', isinstance(result,str) and ('script' in result or result=='block-validation-failed') if invalid else result is None,result)
                check(f'tip par={par} invalid={invalid}',node.rpc('getblockcount')==(112 if invalid else 113))
        txid=source.rpc('sendrawtransaction',wire.hex())
        # getblocktemplate caches the previous empty template for five seconds.
        deadline=time.monotonic()+15
        entry=None
        while time.monotonic()<deadline:
            template=source.rpc('getblocktemplate',{'rules':['segwit']})
            entry=next((tx for tx in template['transactions'] if tx['txid']==txid),None)
            if entry is not None: break
            time.sleep(0.25)
        check('transaction enters refreshed template',entry is not None)
        check('template charges four proofs',entry['sigops']==560,entry['sigops'])
        block=source.rpc('generatetoaddress',1,miner)[0]
        source.rpc('invalidateblock',block)
        check('reorg still active readmits proof',txid in source.rpc('getrawmempool'))
        source.rpc('invalidateblock',source.rpc('getblockhash',112))
        check('cross activation removes proof',txid not in source.rpc('getrawmempool'))
        check('inactive candidate rejects after reorg',not source.rpc('testmempoolaccept',[wire.hex()])[0]['allowed'])
        source.rpc('reconsiderblock',block)
        check('reconsider restores active chain',source.rpc('getblockcount')==113)
        report['success']=True
    finally:
        for node in nodes: node.close()
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('REPORT '+str(directory/'report.json'),flush=True)

if __name__=='__main__':
    main()
