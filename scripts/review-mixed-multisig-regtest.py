#!/usr/bin/env python3
"""Mixed ECDSA/PQ v1 multisig: height gating, native/P2SH, blocks and reorg.
Uses disposable keys and independent transaction/commitment/sighash serialization.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('auth_helpers', Path(__file__).with_name('review-authenticated-contracts-regtest.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
h, b, a = c.h, c.b, c.a


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='mixed-multisig-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'script_sha256': h.digest_file(Path(__file__)), 'activation_height': 120,
              'signer_sha256': h.digest_file(args.signer)}
    nodes = []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    def rejected(node, label, wire, reason):
        try:
            node.rpc('sendrawtransaction', wire.hex())
        except h.RPCError as error:
            check(label, error.code == -26 and reason in str(error), str(error))
        else:
            check(label, False, 'accepted')

    try:
        source = h.Node(args.bindir, directory / 'source',
                        ['-bypassdownload=1', '-acceptnonstdtxn=0', '-par=1', '-strictauthscriptheight=120'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        output = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        keys = {}
        for family in ('ecdsa', 'pq'):
            pub, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            keys[family] = bytes.fromhex(pub), secret
        contracts, outputs = [], []
        for first, second in (('ecdsa', 'pq'), ('pq', 'ecdsa')):
            for verify in (False, True):
                script = b'\x51' + h.push(keys[first][0]) + h.push(keys[second][0]) + b'\x52'
                script += b'\xaf\x51' if verify else b'\xae'
                tag = a.sha256(b'NeuraiAuthScript')
                commitment = a.sha256(tag + tag + b'\x01\x00' + a.sha256(script))
                native = b'\x51\x20' + commitment
                for wrapped in (False, True):
                    spk = b'\xa9\x14' + c.hash160(native) + b'\x87' if wrapped else native
                    outputs.append(b.output(1_000_000_000, spk))
                    contracts.append((f'{first}-first/verify{int(verify)}/p2sh{int(wrapped)}', first,
                                      script, h.push(native) if wrapped else b''))
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(len(outputs)) + b''.join(outputs) + bytes(4)
        funded = source.rpc('fundrawtransaction', raw.hex())
        signed = source.rpc('signrawtransaction', funded['hex'])
        check('funding_signed', signed['complete'], signed['complete'])
        funding = source.rpc('sendrawtransaction', signed['hex'])
        source.rpc('generatetoaddress', 1, miner)
        coins = source.rpc('getrawtransaction', funding, True)['vout']
        # fundrawtransaction may insert change, so locate the original outputs.
        spends = []
        for label, family, script, sigscript in contracts:
            tag = a.sha256(b'NeuraiAuthScript')
            native = b'\x51\x20' + a.sha256(tag + tag + b'\x01\x00' + a.sha256(script))
            spk = b'\xa9\x14' + c.hash160(native) + b'\x87' if sigscript else native
            utxo = funding, next(o['n'] for o in coins if o['scriptPubKey']['hex'] == spk.hex())
            digest = c.sighash(utxo, script, output, 0)
            sig = bytes.fromhex(subprocess.check_output([str(args.signer), 'sign', family],
                                input=keys[family][1] + '\n' + digest.hex() + '\n', text=True).strip())
            stack = [b'\x00', b'', sig, script]
            spends.append((label, utxo, c.transaction(utxo, sigscript, stack, output),
                           c.transaction(utxo, sigscript, stack, b'\x6a')))
        validators = []
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}',
                          ['-disablewallet=1', f'-par={par}', '-assumevalid=0', '-strictauthscriptheight=120'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))
            for height in range(1, 112):
                result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError(f'funding block {height}: {result}')
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        for label, utxo, good, bad in spends:
            rejected(source, label + '/before/mempool', good[1], 'Non-canonical DER signature')
            raw_block, _, _ = b.block(source.rpc('getblocktemplate', {'rules': ['segwit']}), good)
            for par, node in validators:
                tip = node.rpc('getbestblockhash')
                result = node.rpc('submitblock', raw_block.hex())
                check(label + f'/before/par{par}/block', result is not None and
                      ('Non-canonical DER signature' in result if par == 1 else result == 'block-validation-failed'), result)
                check(label + f'/before/par{par}/state', node.rpc('getbestblockhash') == tip and
                      node.rpc('gettxout', *utxo) is not None, tip)
        source.rpc('generatetoaddress', 8, miner)
        for _, node in validators:
            for height in range(112, 120):
                result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                check(f'preactivation/{node.port}/{height}', result is None, result)
        for label, utxo, good, bad in spends:
            rejected(source, label + '/after/invalid_signature', bad[1], 'Signature must be zero')
            raw_block, _, _ = b.block(source.rpc('getblocktemplate', {'rules': ['segwit']}), bad)
            for par, node in validators:
                tip = node.rpc('getbestblockhash')
                result = node.rpc('submitblock', raw_block.hex())
                check(label + f'/after/par{par}/invalid_block', result is not None and
                      node.rpc('getbestblockhash') == tip and node.rpc('gettxout', *utxo) is not None, result)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            check(label + '/mined', source.rpc('getrawtransaction', txid, True)['confirmations'] == 1, txid)
            raw_block = source.rpc('getblock', blockhash, False)
            for par, node in validators:
                result = node.rpc('submitblock', raw_block)
                check(label + f'/after/par{par}/block', result is None and node.rpc('getbestblockhash') == blockhash, result)
                check(label + f'/after/par{par}/utxo', node.rpc('gettxout', *utxo) is None and
                      node.rpc('gettxout', txid, 0) is not None, txid)
        fork = source.rpc('getblockhash', 119)
        source.rpc('invalidateblock', fork)
        check('reorg/height', source.rpc('getblockcount') == 118, source.rpc('getblockcount'))
        check('reorg/mempool', source.rpc('getrawmempool') == [], source.rpc('getrawmempool'))
        rejected(source, 'reorg/reject_before_height', spends[0][2][1], 'Non-canonical DER signature')
        source.rpc('reconsiderblock', fork)
        check('reorg/restored', source.rpc('getblockcount') == 127, source.rpc('getblockcount'))
        report['contracts'] = len(spends)
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
