#!/usr/bin/env python3
"""NIP-046 PRE-IMPLEMENTATION baseline on disposable regtest, no network peers.
Never reports activation/reorg or the proposed rules as tested.
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
    p.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = p.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='nip046-baseline-'))
    fixture = ROOT/'src/test/data/nip046_budget_vectors.json'
    report = dict(scope='pre-implementation only', results=[],
                  binary_sha256=r.h.digest_file(args.bindir/'neuraid'),
                  driver_sha256=r.h.digest_file(Path(__file__)),
                  fixture_sha256=r.h.digest_file(fixture))
    node = None
    try:
        node = r.h.Node(args.bindir, directory/'node', ['-bypassdownload=1', '-acceptnonstdtxn=0', '-minrelaytxfee=0.00001'])
        node.ready()
        miner = node.rpc('getnewaddress', '', 'legacy')
        payout = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        node.rpc('generatetoaddress', 610, miner)
        for case in json.loads(fixture.read_text())['cases']:
            script = bytes.fromhex(case['script_hex'])
            address, spk = r.address(script)
            txid = node.rpc('sendtoaddress', address, 2)
            node.rpc('generatetoaddress', 1, miner)
            funding = node.rpc('getrawtransaction', txid, True)
            index = next(o['n'] for o in funding['vout'] if o['scriptPubKey']['hex'] == spk.hex())
            witness = [b'\x00']+[b'\x42'*size for size in case['witness_sizes']]+[script]
            raw = r.a.raw_transaction([(txid, index)], [(190000000, payout)], [], [witness])
            result = node.rpc('testmempoolaccept', [raw])[0]
            passed = result.get('allowed', False) == case['before']
            # Count failures must be script failures, not an unrelated funding error.
            if not case['before']:
                passed = passed and 'Operation limit exceeded' in str(result)
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
