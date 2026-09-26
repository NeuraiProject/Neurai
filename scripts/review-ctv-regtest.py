#!/usr/bin/env python3
"""Independent CTV vectors and isolated regtest contracts for address families.
Use --vectors to print fixed vectors without starting a node.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

_spec = importlib.util.spec_from_file_location('review_helpers', Path(__file__).with_name('review-introspection-regtest.py'))
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
from generate_authscript_vectors import bech32m


def sha(data):
    return hashlib.sha256(data).digest()


def size(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)


def ctv(version, locktime, sequences, outputs, index, refs=(), script_sigs=None):
    """Explicit LE serialization, independent of the node's hash and serializers."""
    scripts = script_sigs or [b''] * len(sequences)
    preimage = struct.pack('<II', version, locktime)
    if any(scripts):
        preimage += sha(b''.join(size(len(s)) + s for s in scripts))
    preimage += struct.pack('<I', len(sequences))
    preimage += sha(b''.join(struct.pack('<I', n) for n in sequences))
    preimage += struct.pack('<I', len(outputs))
    preimage += sha(b''.join(struct.pack('<q', n) + size(len(s)) + s for n, s in outputs))
    if version == 3:
        preimage += struct.pack('<I', len(refs))
        if refs:
            preimage += sha(b''.join(bytes.fromhex(txid)[::-1] + struct.pack('<I', n) for txid, n in refs))
    preimage += struct.pack('<I', index)
    return sha(preimage)


def vectors():
    rows = []
    for family in range(4):
        prefix = bytes.fromhex('76a914') + bytes(range(20)) + bytes.fromhex('88ac') if family == 0 else bytes([0x50 + family, 32]) + bytes(range(32))
        for asset in (False, True):
            script = prefix
            if asset:
                payload = b'xnat\x08CTVASSET' + struct.pack('<q', 500_000_000)
                script += b'\xc0' + size(len(payload)) + payload + b'\x75'
            refs = [(bytes(range(32)).hex(), 7), (bytes(range(32, 64)).hex(), 9)]
            digest = ctv(3, 123, [0xfffffffe, 0xfffffffd], [(100000, script), (200000, b'\x51')], 1, refs)
            rows.append({'family': family, 'asset': asset, 'script': script.hex(), 'hash': digest.hex()})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vectors', action='store_true')
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    if args.vectors:
        print(json.dumps(vectors(), indent=2))
        return 0
    directory = Path(tempfile.mkdtemp(prefix='opcode-ctv-review-'))
    report = {'results': [], 'binary_sha256': _helpers.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: _helpers.digest_file(p) for p in
                  (Path(__file__), Path(__file__).with_name('review-introspection-regtest.py'),
                   Path(__file__).with_name('generate_authscript_vectors.py'))}}
    node = None
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        node = _helpers.Node(args.bindir, directory / 'node')
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 110, miner)
        legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        program = bytes(range(32))
        destinations = [legacy] + [bytes([0x50 + v, 32]) + program for v in (1, 2, 3)]
        def mine():
            node.rpc('generatetoaddress', 1, miner)
        def fund(address, script):
            txid = node.rpc('sendtoaddress', address, 1)
            mine()
            decoded = node.rpc('getrawtransaction', txid, True)
            index = next(o['n'] for o in decoded['vout'] if o['scriptPubKey']['hex'] == script.hex())
            node.rpc('lockunspent', False, [{'txid': txid, 'vout': index}])
            return txid, index
        refs = [fund(miner, legacy), fund(miner, legacy)]
        contracts = []
        for version in (2, 3):
            actual_refs = refs if version == 3 else []
            for family, destination in enumerate(destinations):
                label = f'txv{version}/family{family}'
                digest = ctv(version, 0, [0xffffffff], [(99_000_000, destination)], 0, actual_refs)
                contract = _helpers.push(digest) + bytes.fromhex('b37551')
                tag = sha(b'NeuraiAuthScript')
                commitment = sha(tag + tag + b'\x01\x00' + sha(contract))
                utxo = fund(bech32m('tnq', 1, commitment), b'\x51\x20' + commitment)
                variants = [('wrong_destination', destinations[(family + 1) % 4], actual_refs)]
                if version == 3:
                    variants.append(('reordered_references', destination, refs[::-1]))
                for suffix, output, references in variants:
                    raw = _helpers.transaction(utxo, contract, output, references)
                    try:
                        node.rpc('sendrawtransaction', raw)
                        check(label + '/' + suffix, False, 'accepted')
                    except _helpers.RPCError as error:
                        check(label + '/' + suffix, error.code == -26 and 'CHECKTEMPLATEVERIFY' in str(error), str(error))
                raw = _helpers.transaction(utxo, contract, destination, actual_refs)
                txid = node.rpc('sendrawtransaction', raw)
                pending = txid in node.rpc('getrawmempool')
                mine()
                confirmations = node.rpc('getrawtransaction', txid, True).get('confirmations', 0)
                check(label + '/accept_and_mine', pending and confirmations > 0, txid)
                contracts.append(txid)
        report['height'] = node.rpc('getblockcount')
        blocks = [node.rpc('getblock', node.rpc('getblockhash', h), False) for h in range(1, report['height'] + 1)]
        for par in (1, 2):
            validator = _helpers.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}'])
            try:
                validator.ready()
                for block in blocks:
                    result = validator.rpc('submitblock', block)
                    if result is not None:
                        raise RuntimeError('submitblock: ' + str(result))
                check(f'validator{par}/same_tip', validator.rpc('getbestblockhash') == node.rpc('getbestblockhash'), report['height'])
                for i, txid in enumerate(contracts):
                    check(f'validator{par}/contract{i}', validator.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
            finally:
                validator.close()
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        if node:
            node.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
