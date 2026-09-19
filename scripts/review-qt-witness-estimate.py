#!/usr/bin/env python3
"""Compare the shared Qt estimator with independently serialized transactions.

Compiles the production header in the Docker build environment. This is a
calculation regression, not an end-to-end Qt GUI test. Signatures/pubkeys here
are size fixtures; validity of their cryptography is irrelevant to serialization.
"""
import argparse
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--regtest', action='store_true')
args = parser.parse_args()

root = Path(__file__).resolve().parent.parent
out = Path(tempfile.mkdtemp(prefix='qt-witness-estimate-'))
files = ['src/qt/witnessestimate.h', 'src/qt/coincontroldialog.cpp', 'src/qt/assetcontroldialog.cpp']
code = '#include "qt/witnessestimate.h"\n#include <iostream>\nint main() {\n'
scenarios = [[v] for v in (0, 1, 2, 3)] + [[1, 2, 3], [-1, 1, 2, 3], [-1], [-1, -1], [2] * 253, [-1] * 253]

def compact(n):
    return bytes([n]) if n < 253 else b'\xfd' + struct.pack('<H', n)

def stack(v):
    if v == -1:
        return []
    if v == 0:
        return [bytes(73), bytes(33)]
    return [bytes([2 if v == 3 else 1]), bytes(73 if v == 3 else 2421), bytes(33 if v == 3 else 1313), b'\x51']

def actual_size(versions, outputs):
    vin = compact(len(versions))
    for v in versions:
        script = bytes(107) if v == -1 else b''
        vin += bytes(36) + compact(len(script)) + script + b'\xff' * 4
    vout = compact(outputs) + (bytes(8) + b'\x19' + bytes(25)) * outputs
    stripped = bytes(4) + vin + vout + bytes(4)
    witness = b''
    if any(v >= 0 for v in versions):
        for v in versions:
            items = stack(v)
            witness += compact(len(items)) + b''.join(compact(len(x)) + x for x in items)
        wire = bytes(4) + b'\x00\x01' + vin + vout + witness + bytes(4)
    else:
        wire = stripped
    return (3 * len(stripped) + len(wire) + 3) // 4

cases = []
for versions in scenarios:
    for outputs in (1, 2, 253):
        weight = ' + '.join('592' if v == -1 else f'GUIUtil::EstimateWitnessInputWeight({v}, std::vector<unsigned char>({20 if v == 0 else 32}, 1))' for v in versions)
        code += f'std::cout << GUIUtil::EstimateControlVBytes({weight}, {len(versions)}, {sum(v >= 0 for v in versions)}, {outputs}) << "\\n";\n'
        cases.append((versions, outputs, actual_size(versions, outputs)))
code += '}\n'
(out / 'probe.cpp').write_text(code)
subprocess.run(['g++', '-std=c++11', '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                '-DHAVE_CONFIG_H', '-I' + str(root / 'src'), '-I/root/Neurai/src',
                str(out / 'probe.cpp'), '-o', str(out / 'probe')], check=True)
values = subprocess.check_output([str(out / 'probe')], text=True).splitlines()
assert len(values) == len(cases)
rows = []
for (versions, outputs, expected), value in zip(cases, values):
    rows.append(dict(versions=versions, outputs=outputs, estimated_vbytes=int(value),
                     serialized_vbytes=expected, passed=int(value) == expected))
for name in files[1:]:
    text = (root / name).read_text()
    rows.append(dict(file=name, passed='GUIUtil::EstimateWitnessInputWeight(' in text and
                     'GUIUtil::EstimateControlVBytes(' in text and 'nBytes += nQuantity' not in text and
                     'static unsigned int EstimateWitnessInputVBytes' not in text))
if args.regtest:
    spec = importlib.util.spec_from_file_location('helpers', root / 'scripts/review-introspection-regtest.py')
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    nodes = []
    try:
        bindir = Path('/root/Neurai/src')
        source = h.Node(bindir, out / 'source', ['-pqwallet=1', '-bypassdownload=1'])
        nodes.append(source)
        legacy = h.Node(bindir, out / 'legacy', [])
        nodes.append(legacy)
        for node in nodes:
            node.ready()
        target = legacy.rpc('getnewaddress')
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        addresses = [source.rpc('getnewaddress'), source.rpc('getnewaddress', '', 'pq'), source.rpc('getnewaddress', '', 'ecdsa')]
        funding = source.rpc('sendmany', '', {a: 5 for a in addresses})
        source.rpc('generatetoaddress', 1, miner)
        coins = source.rpc('getrawtransaction', funding, True)['vout']
        for v, address in enumerate(addresses, 1):
            spk = source.rpc('validateaddress', address)['scriptPubKey']
            coin = next(o for o in coins if o['scriptPubKey']['hex'] == spk)
            raw = source.rpc('createrawtransaction', [{'txid': funding, 'vout': coin['n']}], {target: 4.9})
            signed = source.rpc('signrawtransaction', raw)
            assert signed['complete']
            tx = source.rpc('decoderawtransaction', signed['hex'])
            estimate = int(values[v * 3]) # single-input, one legacy output case above
            rows.append(dict(version=v, real_wallet_vsize=tx['vsize'], estimated_vbytes=estimate,
                             passed=estimate == tx['vsize'] if v < 3 else 0 <= estimate - tx['vsize'] <= 1))
            txid = source.rpc('sendrawtransaction', signed['hex'])
            source.rpc('generatetoaddress', 1, miner)
            rows.append(dict(version=v, mined=txid, passed=source.rpc('getrawtransaction', txid, True)['confirmations'] == 1))
    finally:
        for node in reversed(nodes):
            node.close()

report = {'results': rows, 'passed': sum(r['passed'] for r in rows), 'failed': sum(not r['passed'] for r in rows),
          'source_sha256': {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in files}}
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS:', report['passed'], 'FAIL:', report['failed'])
print('Report:', out / 'report.json')
raise SystemExit(int(report['failed'] != 0))
