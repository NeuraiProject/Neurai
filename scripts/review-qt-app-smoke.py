#!/usr/bin/env python3
"""Start the newly linked GUI itself on isolated regtest and exercise its wallet RPC."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('helper', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
root = Path(tempfile.mkdtemp(prefix='qt-app-smoke-'))
binary = Path(sys.argv[1]).resolve()
(root / 'neuraid').symlink_to(binary)
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
report = {'binary_sha256': h.digest_file(binary), 'results': []}
node = h.Node(root, root / 'node', ['-pqwallet=1', '-bypassdownload=1',
    '-mnemonic=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'])
try:
    # A fresh GUI wallet can spend more than the helper's 20 seconds in keygen.
    deadline = time.monotonic() + 120
    while True:
        try:
            node.rpc('getblockcount')
            break
        except (OSError, RuntimeError):
            if node.proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('GUI startup did not reach RPC readiness')
            time.sleep(0.2)
    miner = node.rpc('getnewaddress')
    node.rpc('generatetoaddress', 110, miner)
    for family in ('pq', 'ecdsa'):
        address = node.rpc('getnewaddress', '', family)
        signature = node.rpc('signmessage', address, 'GUI application review')
        verified = node.rpc('verifymessage', address, signature, 'GUI application review')
        txid = node.rpc('sendtoaddress', address, 1)
        node.rpc('generatetoaddress', 1, miner)
        ok = verified and node.rpc('gettransaction', txid)['confirmations'] == 1
        report['results'].append({'case': family, 'passed': bool(ok)})
        if not ok:
            raise RuntimeError(family)
except Exception as error:
    report['error'] = str(error)
finally:
    node.close()
    report['exit_code'] = node.proc.returncode
    report['passed'] = len(report['results']) == 2 and all(r['passed'] for r in report['results']) and 'error' not in report and node.proc.returncode == 0
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Report:', root / 'report.json', 'PASS' if report['passed'] else 'FAIL', flush=True)
sys.exit(0 if report['passed'] else 1)
