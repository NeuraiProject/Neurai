#!/usr/bin/env python3
"""Verify OP_CHECKSIG_P256 (NIP-060) spends and sigop accounting in v1 contracts.

One contract per output family (Legacy, witness v1/v2/v3): the NIP-060 §11
vector 1 signature must verify and the contract pays a fixed output. Each
check contributes P256_SIGOP_COST (5) witness sigops; a Legacy output adds
four. Two fresh validators (-par=1 and -par=2) replay the history.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

_spec = importlib.util.spec_from_file_location('csfs_review', Path(__file__).with_name('review-csfs-regtest.py'))
c = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c)
h = c.h
from generate_authscript_vectors import bech32m, sha256

# NIP-060 §11 vector 1.
PK = bytes.fromhex('0301cfb7f8207152900493007ff3a86d1f83be039b6f17418ac3ad52c2debc35a9')
MSG = bytes.fromhex('4e6575726169503235362f76312f7465737400010203')
SIG = bytes.fromhex('03284da89332dae4ca1f4853777269f1c6659893c0830fdb2eaea3ecca4aee35'
                    '5ccf79bc073f56306cd3069d7ffe5b1447e7e6d6e4b52ca89d10c192d01bc1e3')
P256_SIGOP_COST = 5


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='opcode-p256-review-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__),
                  Path(__file__).with_name('review-csfs-regtest.py'),
                  Path(__file__).with_name('generate_authscript_vectors.py'))}}
    nodes = []
    def check(case, passed, observed):
        report['results'].append({'case': case, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + case, flush=True)
        if not passed:
            raise RuntimeError(f'{case}: {observed}')
    try:
        node = h.Node(args.bindir, directory / 'node', ['-bypassdownload=1'])
        nodes.append(node)
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 110, miner)
        info = node.rpc('getblockchaininfo')['signature_opcodes']
        check('rpc/signature_opcodes', info['active_for_next_block'] and info['opcodes']['checksig_p256'], info)
        legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        destinations = [legacy] + [bytes([0x50 + v, 32]) + bytes(range(32)) for v in (1, 2, 3)]
        contracts = []
        for family, output in enumerate(destinations):
            # <pk> OP_CHECKSIG_P256 OP_VERIFY 0 OP_OUTPUTSCRIPT <output> OP_EQUAL
            script = h.push(PK) + b'\xe0\x69\x00\xcd' + h.push(output) + b'\x87'
            tag = sha256(b'NeuraiAuthScript')
            program = sha256(tag + tag + b'\x01\x00' + sha256(script))
            funding = node.rpc('sendtoaddress', bech32m('tnc', 1, program), 1)
            node.rpc('generatetoaddress', 1, miner)
            funded = node.rpc('getrawtransaction', funding, True)
            index = next(o['n'] for o in funded['vout'] if o['scriptPubKey']['hex'] == (b'\x51\x20' + program).hex())
            utxo = funding, index
            for name, message, target, expected in (
                    ('wrong_message', MSG[:-1] + b'\x02', output, 'OP_CHECKSIG_P256 signature does not verify'),
                    ('wrong_output', MSG, destinations[(family + 1) % 4], 'false')):
                try:
                    node.rpc('sendrawtransaction', c.transaction(utxo, script, SIG, message, target))
                    check(f'family{family}/{name}', False, 'accepted')
                except h.RPCError as error:
                    check(f'family{family}/{name}', error.code == -26 and expected in str(error), str(error))
            txid = node.rpc('sendrawtransaction', c.transaction(utxo, script, SIG, MSG, output))
            template = node.rpc('getblocktemplate', {'rules': ['segwit']})
            cost = next(t['sigops'] for t in template['transactions'] if t['txid'] == txid)
            expected_cost = P256_SIGOP_COST + (4 if family == 0 else 0)
            check(f'family{family}/p256_cost', cost == expected_cost, cost)
            node.rpc('generatetoaddress', 1, miner)
            check(f'family{family}/confirmed', node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
            contracts.append(txid)
        height = node.rpc('getblockcount')
        history = [node.rpc('getblock', node.rpc('getblockhash', i), False) for i in range(1, height + 1)]
        for par in (1, 2):
            validator = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}'])
            nodes.append(validator)
            validator.ready()
            for block in history:
                result = validator.rpc('submitblock', block)
                if result is not None:
                    raise RuntimeError(f'submitblock: {result}')
            check(f'par{par}/tip', validator.rpc('getbestblockhash') == node.rpc('getbestblockhash'), height)
            for i, txid in enumerate(contracts):
                check(f'par{par}/contract{i}', validator.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
        report['height'] = height
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        for node in reversed(nodes):
            node.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
