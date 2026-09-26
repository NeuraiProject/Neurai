#!/usr/bin/env python3
"""Independent TXHASH mask vectors; isolated regtest with --regtest."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

_spec = importlib.util.spec_from_file_location('ctv_review', Path(__file__).with_name('review-ctv-regtest.py'))
_ctv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ctv)
h = _ctv._helpers


def double_sha(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def field_hash(mask, version, locktime, prevouts, sequences, outputs, index, refs=()):
    fields = [struct.pack('<I', version), struct.pack('<I', locktime),
              double_sha(b''.join(prevouts)),
              double_sha(b''.join(struct.pack('<I', n) for n in sequences)),
              double_sha(b''.join(struct.pack('<q', n) + _ctv.size(len(s)) + s for n, s in outputs)),
              prevouts[index], struct.pack('<I', sequences[index]), struct.pack('<I', index),
              double_sha(b''.join(refs) if version == 3 else b'')]
    tag = hashlib.sha256(b'NeuraiTxHash').digest()
    return hashlib.sha256(tag + tag + struct.pack('<H', mask) +
                          b''.join(field for bit, field in enumerate(fields) if mask & (1 << bit))).digest()


def vectors(include_digests=False):
    rows = []
    prevouts = [bytes(range(32)) + struct.pack('<I', 7), bytes(range(32, 64)) + struct.pack('<I', 9)]
    for row in _ctv.vectors():
        script = bytes.fromhex(row['script'])
        hashes = [field_hash(mask, 3, 123, prevouts, [0xfffffffe, 0xfffffffd],
                             [(100000, script), (200000, b'\x51')], 1,
                             [bytes.fromhex('aa' + '00'*31) + struct.pack('<I', 7),
                              bytes.fromhex('bb' + '00'*31) + struct.pack('<I', 9)]) for mask in range(1, 512)]
        rows.append({'family': row['family'], 'asset': row['asset'], 'script': row['script'],
                     'all_masks_sha256': hashlib.sha256(b''.join(hashes)).hexdigest()})
        if include_digests:
            rows[-1]['digests'] = {struct.pack('<H', mask).hex(): digest.hex() for mask, digest in enumerate(hashes, 1)}
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--regtest', action='store_true')
    parser.add_argument('--all-masks', action='store_true', help='emit every independent digest, not just fingerprints')
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    if not args.regtest:
        print(json.dumps(vectors(args.all_masks), indent=2))
        return 0
    directory = Path(tempfile.mkdtemp(prefix='opcode-txhash-review-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in
                  (Path(__file__), Path(__file__).with_name('review-ctv-regtest.py'),
                   Path(__file__).with_name('review-introspection-regtest.py'),
                   Path(__file__).with_name('generate_authscript_vectors.py'))}}
    node = None
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        node = h.Node(args.bindir, directory / 'node')
        node.ready()
        miner = node.rpc('getnewaddress', '', 'legacy')
        node.rpc('generatetoaddress', 110, miner)
        legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        destinations = [legacy] + [bytes([0x50 + v, 32]) + bytes(range(32)) for v in (1, 2, 3)]
        def mine():
            node.rpc('generatetoaddress', 1, miner)
        def fund(address, script):
            txid = node.rpc('sendtoaddress', address, 1)
            mine()
            tx = node.rpc('getrawtransaction', txid, True)
            index = next(o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'] == script.hex())
            node.rpc('lockunspent', False, [{'txid': txid, 'vout': index}])
            return txid, index
        refs = [fund(miner, legacy), fund(miner, legacy)]
        replacement = fund(miner, legacy)
        contracts = []
        for family, output in enumerate(destinations):
            for mask in (1, 16, 17, 0x100, 0x110, 0x111):
                label = f'family{family}/mask{mask:02x}'
                # These masks do not select the ordinary input prevout, avoiding
                # a circular commitment to the transaction that funds the contract.
                digest = field_hash(mask, 3, 0, [bytes(36)], [0xffffffff], [(99000000, output)], 0, [h.outpoint(*ref) for ref in refs])
                script = h.push(struct.pack('<H', mask)) + b'\xb5' + h.push(digest) + b'\x87'
                tag = _ctv.sha(b'NeuraiAuthScript')
                commitment = _ctv.sha(tag + tag + b'\x01\x00' + _ctv.sha(script))
                utxo = fund(_ctv.bech32m('tnc', 1, commitment), b'\x51\x20' + commitment)
                alternate = h.transaction(utxo, script, destinations[(family + 1) % 4], refs)
                result = node.rpc('testmempoolaccept', [alternate])[0]
                if mask & 16:
                    check(label + '/changed_output_rejected', result.get('allowed') != 1 and 'false' in str(result).lower(), result)
                else:
                    check(label + '/unselected_output_allowed', result.get('allowed') == 1, result)
                reordered = h.transaction(utxo, script, output, refs[::-1])
                result = node.rpc('testmempoolaccept', [reordered])[0]
                check(label + '/reference_order', (result.get('allowed') == 1) == (not (mask & 0x100)), result)
                substituted = h.transaction(utxo, script, output, refs[:1])
                result = node.rpc('testmempoolaccept', [substituted])[0]
                check(label + '/reference_removed', (result.get('allowed') == 1) == (not (mask & 0x100)), result)
                txid = node.rpc('sendrawtransaction', h.transaction(utxo, script, output, refs))
                pending = txid in node.rpc('getrawmempool')
                mine()
                check(label + '/accept_and_mine', pending and node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
                contracts.append(txid)
        # Standalone signer: it signs a Python-computed SHA256(digest), never
        # asks the node for a sighash, and uses only disposable test keys.
        for algorithm in ('ecdsa', 'pq'):
            pubhex, secret = subprocess.check_output([str(args.signer), 'keygen', algorithm], text=True).split()
            pub = bytes.fromhex(pubhex)
            for app in (b'', b'Neurai/NIP042/testnet/oracle-demo/v1'):
                label = f'oracle/{algorithm}/app{bool(app)}'
                output = destinations[3]
                script = (h.push(app) if app else b'') + h.push(b'\x10\x01') + b'\xb5'
                if app:
                    script += b'\x7e'  # OP_CAT: app_tag || digest
                script += h.push(pub) + b'\xb4'
                tag = _ctv.sha(b'NeuraiAuthScript')
                commitment = _ctv.sha(tag + tag + b'\x01\x00' + _ctv.sha(script))
                utxo = fund(_ctv.bech32m('tnc', 1, commitment), b'\x51\x20' + commitment)
                digest = field_hash(0x110, 3, 0, [h.outpoint(*utxo)], [0xffffffff],
                                    [(90000000, output)], 0, [h.outpoint(*ref) for ref in refs])
                def sign(message):
                    value = hashlib.sha256(message).hexdigest()
                    return bytes.fromhex(subprocess.check_output([str(args.signer), 'sign', algorithm],
                        input=secret + '\n' + value + '\n', text=True).strip())
                signature = sign(app + digest)
                def oracle_tx(sig, targets=refs, target=output):
                    raw = bytes.fromhex(h.transaction(utxo, script, target, targets))
                    raw = raw[:49] + struct.pack('<q', 90000000) + raw[57:]
                    old = b'\x02\x01\x00' + h.compact(len(script)) + script + bytes(4)
                    assert raw.endswith(old)
                    return (raw[:-len(old)] + b'\x03\x01\x00' + h.compact(len(sig)) + sig +
                            h.compact(len(script)) + script + bytes(4)).hex()
                other_mask = field_hash(0x100, 3, 0, [h.outpoint(*utxo)], [0xffffffff],
                                        [(90000000, output)], 0, [h.outpoint(*ref) for ref in refs])
                cases = [('same_script_different_reference', oracle_tx(signature, [refs[0], replacement])),
                         ('reordered_references', oracle_tx(signature, refs[::-1])),
                         ('other_mask_signature', oracle_tx(sign(app + other_mask))),
                         ('changed_output', oracle_tx(signature, target=destinations[2]))]
                if app:
                    cases.append(('missing_app_tag', oracle_tx(sign(digest))))
                for name, raw in cases:
                    result = node.rpc('testmempoolaccept', [raw])[0]
                    check(label + '/' + name, not result.get('allowed') and 'Signature' in str(result), result)
                txid = node.rpc('sendrawtransaction', oracle_tx(signature))
                mine()
                check(label + '/mine', node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
                contracts.append(txid)
        report['height'] = node.rpc('getblockcount')
        blocks = [node.rpc('getblock', node.rpc('getblockhash', i), False) for i in range(1, report['height'] + 1)]
        for par in (1, 2):
            validator = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}'])
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
