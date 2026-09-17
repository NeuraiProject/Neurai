#!/usr/bin/env python3
"""Real strict-asset spends and covenant field queries in an isolated regtest node.

Run inside the build Docker: python3 /src/scripts/review-asset-fields-regtest.py
Owns only its temporary node. Reports are regenerated, never overwrite a run.
"""
import argparse
import json
from pathlib import Path
import struct
import tempfile

import importlib.util
_spec = importlib.util.spec_from_file_location('introspection_review', Path(__file__).with_name('review-introspection-regtest.py'))
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
Node, RPCError, compact, push, outpoint, digest_file = (
    getattr(_helpers, name) for name in ('Node', 'RPCError', 'compact', 'push', 'outpoint', 'digest_file'))
from generate_authscript_vectors import bech32m, sha256

COIN = 100_000_000


def number(n):
    out = bytearray()
    while n:
        out.append(n & 255)
        n >>= 8
    if out and out[-1] & 128:
        out.append(0)
    return bytes(out)


def raw_transaction(inputs, outputs, refs, witnesses):
    raw = struct.pack('<I', 3) + b'\x00\x01' + compact(len(inputs))
    for txid, index in inputs:
        raw += outpoint(txid, index) + b'\x00' + b'\xff' * 4
    raw += compact(len(outputs))
    for value, script in outputs:
        raw += struct.pack('<Q', value) + compact(len(script)) + script
    raw += compact(len(refs)) + b''.join(outpoint(*ref) for ref in refs)
    for witness in witnesses:
        raw += compact(len(witness))
        for item in witness:
            raw += compact(len(item)) + item
    return (raw + b'\x00' * 4).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    directory = args.output or Path(tempfile.mkdtemp(prefix='opcode-assets-review-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    report = {'results': [], 'binary_sha256': digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: digest_file(p) for p in
                  (Path(__file__), Path(__file__).with_name('review-introspection-regtest.py'))}}
    node = None

    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))

    try:
        node = Node(args.bindir, directory / 'node', ['-pqwallet=1'])
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 500, miner)
        addresses = {v: node.rpc('getnewaddress', '', kind) for v, kind in ((2, 'pq'), (3, 'ecdsa'))}
        scripts = {v: bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
                   for v, address in addresses.items()}
        miner_script = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])

        def mine():
            node.rpc('generatetoaddress', 1, miner)

        def confirmed(label, result):
            txid = result[0] if isinstance(result, list) else result
            pending = txid in node.rpc('getrawmempool')
            mine()
            tx = node.rpc('getrawtransaction', txid, True)
            check(label, pending and tx.get('confirmations', 0) >= 1, txid)
            return tx

        def asset_output(tx, prefix):
            matches = [out for out in tx['vout'] if out['scriptPubKey']['hex'].startswith(prefix.hex())
                       and len(out['scriptPubKey']['hex']) > len(prefix.hex())]
            if len(matches) != 1:
                raise RuntimeError('asset output not unique: ' + tx['txid'])
            out = matches[0]
            return (tx['txid'], out['n']), bytes.fromhex(out['scriptPubKey']['hex'])

        # A distinct asset/amount in the reference catches accidental source mixing.
        ref_address = node.rpc('getnewaddress', '', 'ecdsa')
        ref_script = bytes.fromhex(node.rpc('validateaddress', ref_address)['scriptPubKey'])
        confirmed('reference/issue', node.rpc('issue', 'FIELDREF', 7, miner))
        ref_tx = confirmed('reference/transfer_to_v3', node.rpc('transfer', 'FIELDREF', 7, ref_address))
        ref, _ = asset_output(ref_tx, ref_script)
        node.rpc('lockunspent', False, [{'txid': ref[0], 'vout': ref[1]}])

        wrong_address = node.rpc('getnewaddress', '', 'pq')
        wrong_script = bytes.fromhex(node.rpc('validateaddress', wrong_address)['scriptPubKey'])
        confirmed('wrong_reference/issue', node.rpc('issue', 'FIELDOTHER', 9, miner))
        wrong_tx = confirmed('wrong_reference/transfer_to_v2', node.rpc('transfer', 'FIELDOTHER', 9, wrong_address))
        wrong_ref, _ = asset_output(wrong_tx, wrong_script)
        node.rpc('lockunspent', False, [{'txid': wrong_ref[0], 'vout': wrong_ref[1]}])

        contract_txids = []
        for version in (2, 3):
            name = 'FIELDV' + str(version)
            confirmed(f'v{version}/issue', node.rpc('issue', name, 5, miner))
            transferred = confirmed(f'v{version}/receive_asset', node.rpc('transfer', name, 5, addresses[version]))
            asset_input, asset_spk = asset_output(transferred, scripts[version])
            check(f'v{version}/real_prefix', asset_spk[:34] == scripts[version], asset_spk.hex())
            target = 3 if version == 2 else 2
            # Split five units into three + two: every query has a distinct
            # amount (spent=5, output=3, reference=7), so source mixing fails.
            def transfer_script(prefix, amount):
                payload = b'xnat' + compact(len(name)) + name.encode() + struct.pack('<q', amount * COIN)
                return prefix + b'\xc0' + push(payload) + b'\x75'

            output_spk = transfer_script(scripts[target], 3)
            contract = b''
            for index, opcode, asset_name, amount in ((1, 0xcf, name, 5),
                                                       (0, 0xce, name, 3),
                                                       (0, 0xd3, 'FIELDREF', 7)):
                for selector, expected in ((1, asset_name.encode()), (2, number(amount * COIN)), (7, b'\x00')):
                    contract += push(number(index)) + push(bytes([selector])) + bytes([opcode]) + push(expected) + b'\x88'
            contract += b'\x00\xc2' + push(bytes([target]) + scripts[target][2:]) + b'\x87'
            tag = sha256(b'NeuraiAuthScript')
            commitment = sha256(tag + tag + b'\x01\x00' + sha256(contract))
            contract_spk = b'\x51\x20' + commitment
            funding = confirmed(f'v{version}/fund_contract', node.rpc('sendtoaddress', bech32m('tnq', 1, commitment), 1))
            index = next(out['n'] for out in funding['vout'] if out['scriptPubKey']['hex'] == contract_spk.hex())
            inputs = [(funding['txid'], index), asset_input]

            def signed(output, references, change=2):
                raw = raw_transaction(inputs, [(0, output), (0, transfer_script(miner_script, change)),
                                               (COIN - 10_000_000, miner_script)],
                                      references, [[b'\x00', contract], []])
                return node.rpc('signrawtransaction', raw)['hex']

            good = signed(output_spk, [ref])
            decoded = node.rpc('decoderawtransaction', good)
            check(f'v{version}/strict_signature_present', len(decoded['vin'][1].get('txinwitness', [])) == 4,
                  [len(bytes.fromhex(x)) for x in decoded['vin'][1].get('txinwitness', [])])
            for label, output, references, change, reason in (
                ('wrong_destination', transfer_script(scripts[version], 3), [ref], 2, 'false'),
                ('wrong_amount', transfer_script(scripts[target], 2), [ref], 3, 'EQUALVERIFY'),
                ('wrong_reference', output_spk, [wrong_ref], 2, 'EQUALVERIFY')):
                bad = signed(output, references, change)
                try:
                    node.rpc('sendrawtransaction', bad)
                    check(f'v{version}/{label}', False, 'accepted')
                except RPCError as error:
                    check(f'v{version}/{label}', error.code == -26 and reason.lower() in str(error).lower(), str(error))
            tx = confirmed(f'v{version}/contract_spend_to_v{target}', node.rpc('sendrawtransaction', good))
            contract_txids.append(tx['txid'])
            check(f'v{version}/source_consumed', node.rpc('gettxout', *asset_input) is None, asset_input)
            check(f'v{version}/reference_unspent', node.rpc('gettxout', *ref) is not None, ref)
            # The receiving wallet must also be able to spend the resulting strict asset.
            returned = confirmed(f'v{version}/wallet_spend_back',
                                 node.rpc('transferfromaddress', name, addresses[target], 3, miner))
            check(f'v{version}/strict_output_consumed', node.rpc('gettxout', tx['txid'], 0) is None, returned['txid'])
        report['height'] = node.rpc('getblockcount')
        # Independent validators receive blocks only, never the mempool transactions.
        # This prevents the source node's script cache from hiding worker failures.
        blocks = [node.rpc('getblock', node.rpc('getblockhash', height), False)
                  for height in range(1, report['height'] + 1)]
        for parallelism in (1, 2):
            validator = Node(args.bindir, directory / ('validator-par' + str(parallelism)),
                             ['-disablewallet=1', '-par=' + str(parallelism)])
            try:
                validator.ready()
                for height, block in enumerate(blocks, 1):
                    result = validator.rpc('submitblock', block)
                    if result is not None:
                        raise RuntimeError(f'validator par={parallelism} block={height}: {result}')
                check(f'validator/par{parallelism}/same_tip',
                      validator.rpc('getbestblockhash') == node.rpc('getbestblockhash'),
                      validator.rpc('getblockcount'))
                for index, txid in enumerate(contract_txids, 2):
                    confirmations = validator.rpc('getrawtransaction', txid, True).get('confirmations', 0)
                    check(f'validator/par{parallelism}/contract_v{index}', confirmations > 0, txid)
            finally:
                validator.close()
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        if node:
            node.close()
        report['passed'] = sum(row['passed'] for row in report['results'])
        report['failed'] = sum(not row['passed'] for row in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
