#!/usr/bin/env python3
"""Verify Ed25519 sigop accounting with RFC8032 test 1 in v1 contracts.
Each executed signature opcode contributes one witness sigop.
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

PK = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
SIG = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb'
                    '8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='opcode-ed25519-review-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__),
                  Path(__file__).with_name('review-csfs-regtest.py'),
                  Path(__file__).with_name('review-introspection-regtest.py'),
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
        legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        destinations = [legacy] + [bytes([0x50 + v, 32]) + bytes(range(32)) for v in (1, 2, 3)]
        contracts = []
        for family, output in enumerate(destinations):
            script = h.push(PK) + b'\xdd\x69\x00\xcd' + h.push(output) + b'\x87'
            tag = sha256(b'NeuraiAuthScript')
            program = sha256(tag + tag + b'\x01\x00' + sha256(script))
            funding = node.rpc('sendtoaddress', bech32m('tnq', 1, program), 1)
            node.rpc('generatetoaddress', 1, miner)
            funded = node.rpc('getrawtransaction', funding, True)
            index = next(o['n'] for o in funded['vout'] if o['scriptPubKey']['hex'] == (b'\x51\x20' + program).hex())
            utxo = funding, index
            for name, message, target in (('wrong_message', b'\xff', output),
                                           ('wrong_output', b'', destinations[(family + 1) % 4])):
                try:
                    node.rpc('sendrawtransaction', c.transaction(utxo, script, SIG, message, target))
                    check(f'family{family}/{name}', False, 'accepted')
                except h.RPCError as error:
                    check(f'family{family}/{name}', error.code == -26 and ('OP_VERIFY' if name == 'wrong_message' else 'false') in str(error), str(error))
            txid = node.rpc('sendrawtransaction', c.transaction(utxo, script, SIG, b'', output))
            template = node.rpc('getblocktemplate', {'rules': ['segwit']})
            cost = next(t['sigops'] for t in template['transactions'] if t['txid'] == txid)
            # Ed25519 contributes one witness sigop; a Legacy output adds four.
            check(f'family{family}/ed25519_cost', cost == (5 if family == 0 else 1), cost)
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
