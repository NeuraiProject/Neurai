#!/usr/bin/env python3
"""CSFS signatures in real v1 contracts; verify sigop accounting.
Fixtures contain only public keys, messages and signatures, exported by csfs_tests.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

_spec = importlib.util.spec_from_file_location('review_helpers', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)
from generate_authscript_vectors import bech32m, sha256


def transaction(utxo, script, signature, message, output):
    raw = struct.pack('<I', 2) + b'\x00\x01\x01'
    raw += h.outpoint(*utxo) + b'\x00' + b'\xff' * 4
    raw += b'\x01' + struct.pack('<q', 90_000_000) + h.compact(len(output)) + output
    witness = [b'\x00', signature, message, script]
    raw += h.compact(len(witness))
    for item in witness:
        raw += h.compact(len(item)) + item
    return (raw + bytes(4)).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='opcode-csfs-review-'))
    fixtures = json.loads(args.fixtures.read_text())
    if [f['algorithm'] for f in fixtures] != ['ecdsa', 'pq']:
        raise ValueError('expected ECDSA and PQ fixtures')
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'fixture_sha256': h.digest_file(args.fixtures),
              'source_sha256': {p.name: h.digest_file(p) for p in
                  (Path(__file__), Path(__file__).with_name('review-introspection-regtest.py'),
                   Path(__file__).with_name('generate_authscript_vectors.py'))}}
    node = None
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        node = h.Node(args.bindir, directory / 'node', ['-bypassdownload=1'])
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 110, miner)
        legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        destinations = [legacy] + [bytes([0x50 + v, 32]) + bytes(range(32)) for v in (1, 2, 3)]
        contracts = []
        for fixture in fixtures:
            pubkey, message, signature = (bytes.fromhex(fixture[k]) for k in ('pubkey', 'message', 'signature'))
            for family, output in enumerate(destinations):
                label = fixture['algorithm'] + f'/family{family}'
                script = h.push(pubkey) + b'\xb4\x69\x00\xcd' + h.push(output) + b'\x87'
                tag = sha256(b'NeuraiAuthScript')
                commitment = sha256(tag + tag + b'\x01\x00' + sha256(script))
                spk = b'\x51\x20' + commitment
                funding = node.rpc('sendtoaddress', bech32m('tnq', 1, commitment), 1)
                node.rpc('generatetoaddress', 1, miner)
                decoded = node.rpc('getrawtransaction', funding, True)
                index = next(o['n'] for o in decoded['vout'] if o['scriptPubKey']['hex'] == spk.hex())
                utxo = funding, index
                wrong_message = bytes([message[0] ^ 1]) + message[1:]
                wrong_sig = bytearray(signature); wrong_sig[10] ^= 1
                for name, sig, msg, target, reason in (
                    ('wrong_message', signature, wrong_message, output, 'Signature must be zero'),
                    ('wrong_signature', bytes(wrong_sig), message, output, 'Signature must be zero'),
                    ('wrong_output', signature, message, destinations[(family + 1) % 4], 'false')):
                    try:
                        node.rpc('sendrawtransaction', transaction(utxo, script, sig, msg, target))
                        check(label + '/' + name, False, 'accepted')
                    except h.RPCError as error:
                        check(label + '/' + name, error.code == -26 and reason.lower() in str(error).lower(), str(error))
                # Recognized hashtype changes do not change the CSFS message hash.
                result = node.rpc('testmempoolaccept', [transaction(utxo, script, signature[:-1] + b'\x02', message, output)])[0]
                check(label + '/recognized_hashtype', result.get('allowed') == 1, result)
                txid = node.rpc('sendrawtransaction', transaction(utxo, script, signature, message, output))
                template = node.rpc('getblocktemplate', {'rules': ['segwit']})
                entry = next(tx for tx in template['transactions'] if tx['txid'] == txid)
                # CSFS contributes one witness sigop; a Legacy output adds four.
                expected = 5 if family == 0 else 1
                check(label + '/sigop_cost', entry.get('sigops') == expected, entry.get('sigops'))
                node.rpc('generatetoaddress', 1, miner)
                check(label + '/confirmed', node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
                contracts.append(txid)
        # Exercise the actual mempool boundary with cheap, unexecuted CSFS
        # branches. Static sigops must still count; no costly signature loop.
        boundary_scripts = []
        payments = {}
        for i in range(82):
            count = 199 if i < 80 else (80 if i == 80 else 81)
            script = b'\x00\x63' + h.push(struct.pack('<I', i)) + b'\xb4' * count + b'\x68\x51'
            tag = sha256(b'NeuraiAuthScript')
            commitment = sha256(tag + tag + b'\x01\x00' + sha256(script))
            address = bech32m('tnq', 1, commitment)
            payments[address] = 1
            boundary_scripts.append((script, b'\x51\x20' + commitment))
        funding = node.rpc('sendmany', '', payments)
        node.rpc('generatetoaddress', 1, miner)
        funded = node.rpc('getrawtransaction', funding, True)
        indices = {out['scriptPubKey']['hex']: out['n'] for out in funded['vout']}
        def boundary_raw(last):
            chosen = list(range(80)) + [last]
            raw = struct.pack('<I', 2) + b'\x00\x01' + h.compact(len(chosen))
            for i in chosen:
                raw += h.outpoint(funding, indices[boundary_scripts[i][1].hex()]) + b'\x00' + b'\xff' * 4
            # 81 input coins, 79 output coins: enough fee even with virtual
            # size inflated by 16000 sigops. A witness output adds no sigop.
            output = destinations[3]
            raw += b'\x01' + struct.pack('<q', 79 * 100_000_000) + h.compact(len(output)) + output
            for i in chosen:
                script = boundary_scripts[i][0]
                raw += b'\x02\x01\x00' + h.compact(len(script)) + script
            return (raw + bytes(4)).hex()
        exact = boundary_raw(80)
        result = node.rpc('testmempoolaccept', [exact])[0]
        check('limit/16000_allowed', result.get('allowed') == 1, result)
        result = node.rpc('testmempoolaccept', [boundary_raw(81)])[0]
        check('limit/16001_rejected', result.get('allowed') != 1 and 'bad-txns-too-many-sigops' in str(result), result)
        txid = node.rpc('sendrawtransaction', exact)
        template = node.rpc('getblocktemplate', {'rules': ['segwit']})
        cost = next(tx['sigops'] for tx in template['transactions'] if tx['txid'] == txid)
        check('limit/template_cost', cost == 16000, cost)
        node.rpc('generatetoaddress', 1, miner)
        check('limit/confirmed', node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
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
                for index, txid in enumerate(contracts):
                    check(f'validator{par}/contract{index}', validator.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
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
