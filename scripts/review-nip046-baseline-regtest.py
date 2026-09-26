#!/usr/bin/env python3
"""NIP-046 before/after boundary checks on disposable regtest, no network peers.
Admission only; activation/reorg are exercised by the separate activation driver.
"""
import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('thread', Path(__file__).with_name('review-contract-thread-regtest.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--envelope', choices=('native', 'p2sh', 'mast'), default='native')
    p.add_argument('--rules', choices=('before', 'after'), default='before', help='before disables NIP-046; after enables it at height zero')
    p.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = p.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='nip046-baseline-'))
    fixture = ROOT/'src/test/data/nip046_budget_vectors.json'
    report = dict(scope='NIP-046 '+args.rules, envelope=args.envelope, results=[],
                  binary_sha256=r.h.digest_file(args.bindir/'neuraid'),
                  driver_sha256=r.h.digest_file(Path(__file__)),
                  fixture_sha256=r.h.digest_file(fixture))
    node = None
    try:
        node = r.h.Node(args.bindir, directory/'node', ['-bypassdownload=1', '-acceptnonstdtxn=0', '-minrelaytxfee=0.00001', '-authscriptbudgetheight='+('-1' if args.rules=='before' else '0')])
        node.ready()
        miner = node.rpc('getnewaddress', '', 'legacy')
        payout = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        node.rpc('generatetoaddress', 610, miner)
        for case in json.loads(fixture.read_text())['cases']:
            script = bytes.fromhex(case['script_hex'])
            address, spk = r.address(script)
            control = None
            redeem = None
            if args.envelope == 'mast':
                tag = r.sha(b'NeuraiAuthLeaf')
                leaf = r.sha(tag+tag+b'\x01'+r.h.compact(len(script))+script)
                tag = r.sha(b'NeuraiAuthScript')
                commitment = r.sha(tag+tag+b'\x04\x00'+leaf)
                spk = b'\x51\x20'+commitment
                address = r.t._ctv.bech32m('tnc',1,commitment)
                control = b'\x01'
            elif args.envelope == 'p2sh':
                redeem = spk
                address = node.rpc('decodescript',redeem.hex())['p2sh']
                spk = bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            txid = node.rpc('sendtoaddress', address, 2)
            node.rpc('generatetoaddress', 1, miner)
            funding = node.rpc('getrawtransaction', txid, True)
            index = next(o['n'] for o in funding['vout'] if o['scriptPubKey']['hex'] == spk.hex())
            witness = [b'\x00']+[b'\x42'*size for size in case['witness_sizes']]+[script]
            if control is not None:
                witness[0] = b'\x10'
                witness.append(control)
            raw = r.a.raw_transaction([(txid, index)], [(190000000, payout)], [], [witness])
            if redeem is not None:
                wire = bytes.fromhex(raw)
                assert wire[6] == 1 and wire[43] == 0
                script_sig = r.h.push(redeem)
                raw = (wire[:43]+r.h.compact(len(script_sig))+script_sig+wire[44:]).hex()
            result = node.rpc('testmempoolaccept', [raw])[0]
            passed = result.get('allowed', False) == case[args.rules]
            # Count failures must be script failures, not an unrelated funding error.
            if not case[args.rules]:
                expected_error = ('Operation limit exceeded' if case['name'].startswith('ops_') else 'AuthScript hash budget exceeded' if case['name'].startswith('sha256_') else 'Stack size limit exceeded')
                passed = passed and expected_error in str(result)
            report['results'].append(dict(case=case['name'], passed=passed, observed=result))
            print(('PASS ' if passed else 'FAIL ')+case['name'], flush=True)
            if not passed:
                raise RuntimeError(str(result))
        report['success'] = True
    except Exception as error:
        report['error'] = str(error)
        print('ERROR '+str(error), flush=True)
    finally:
        if node:
            node.close()
        (directory/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print('REPORT '+str(directory/'report.json'), flush=True)
    return int(not report.get('success', False))


if __name__ == '__main__':
    raise SystemExit(main())
