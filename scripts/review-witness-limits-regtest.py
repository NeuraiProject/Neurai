#!/usr/bin/env python3
"""Compare standard mempool policy and block consensus at v0/v1 witness limits."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

spec = importlib.util.spec_from_file_location('limits_helpers', Path(__file__).with_name('review-arithmetic-regtest.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
h, b = a.h, a.b


def script_size(size):
    # Skipped pushes remain within 520 bytes each; total script length is exact.
    result = b'\x00\x63'
    remaining = size - 4
    while remaining > 523:
        result += h.push(b'B' * 520)
        remaining -= 523
    for length in range(521):
        tail = h.push(b'B' * length)
        if len(tail) == remaining:
            return result + tail + b'\x68\x51'
    raise ValueError('unrepresentable requested size')


def cases():
    for size in (3600, 3601, 10000, 10001):
        yield f'script{size}', script_size(size), [], ('Script is too big' if size > 10000 else None), size > 3600
    for count in (201, 202):
        yield f'ops{count}', b'\x61' * count + b'\x51', [], ('Operation limit exceeded' if count > 201 else None), False
    for size in (3072, 3073):
        yield f'item{size}', b'\x75\x51', [b'B' * size], ('Push value size limit exceeded' if size > 3072 else None), size > 3072
    for excess in (0, 1):
        yield f'bytes{262144 + excess}', b'\x61' + b'\x6d' * 43 + b'\x51', [b'B' * 3072] * 85 + [b'B' * (1024 + excess)], ('Stack size limit exceeded' if excess else None), False
    for count in (100, 101):
        script = b'\x6d' * (count // 2) + (b'\x75' if count % 2 else b'') + b'\x51'
        yield f'items{count}', script, [b'B'] * count, None, count > 100
    yield 'truncated', b'\x4e\xff\xff\xff\xff', [], 'Opcode missing or not understood', False


def transaction(utxo, version, script, arguments, output):
    inputs = b'\x01' + h.outpoint(*utxo) + b'\x00' + b'\xff' * 4
    # One XNA fee covers the default relay rate even for the 256 KiB witness.
    outputs = b'\x01' + b.output(900_000_000, output)
    stack = ([b'\x00'] if version == 1 else []) + arguments + [script]
    witness = h.compact(len(stack)) + b''.join(h.compact(len(x)) + x for x in stack)
    prefix, lock = struct.pack('<I', 2), bytes(4)
    return prefix + inputs + outputs + lock, prefix + b'\x00\x01' + inputs + outputs + witness + lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='witness-limits-regtest-'))
    files = [Path(__file__), *[Path(__file__).with_name(f) for f in (
        'review-arithmetic-regtest.py', 'review-introspection-regtest.py',
        'review-csfs-block-limit-regtest.py', 'generate_authscript_vectors.py')]]
    report = {'results': [], 'matrix': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes, validators = [], []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1', '-acceptnonstdtxn=0', '-par=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        output = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        contracts, outputs = [], []
        for version in (0, 1):
            for name, script, arguments, error, policy in cases():
                tag = a.sha256(b'NeuraiAuthScript')
                program = a.sha256(script) if version == 0 else a.sha256(tag + tag + b'\x01\x00' + a.sha256(script))
                spk = bytes([0 if version == 0 else 0x51, 32]) + program
                outputs.append(b.output(1_000_000_000, spk))
                contracts.append((f'v{version}/{name}', version, script, arguments, error, policy and version == 0, spk))
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(len(outputs)) + b''.join(outputs) + bytes(4)
        funded = source.rpc('fundrawtransaction', raw.hex())
        signed = source.rpc('signrawtransaction', funded['hex'])
        check('funding_signed', signed['complete'], signed['complete'])
        funding = source.rpc('sendrawtransaction', signed['hex'])
        source.rpc('generatetoaddress', 1, miner)
        funded_tx = source.rpc('getrawtransaction', funding, True)
        unused = list(funded_tx['vout'])
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))
            for height in range(1, 112):
                result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError('validator rejected funding: ' + str(result))
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        for label, version, script, arguments, error, policy, spk in contracts:
            coin = next(o for o in unused if o['scriptPubKey']['hex'] == spk.hex())
            unused.remove(coin)
            utxo = funding, coin['n']
            tx = transaction(utxo, version, script, arguments, output)
            accepted = error is None and not policy
            try:
                txid = source.rpc('sendrawtransaction', tx[1].hex())
                check(label + '/mempool', accepted, txid)
            except h.RPCError as failure:
                expected = 'bad-witness-nonstandard' if policy else error
                check(label + '/mempool', not accepted and failure.code == -26 and expected is not None and expected in str(failure), str(failure))
            template = source.rpc('getblocktemplate', {'rules': ['segwit']})
            # Templates may cache an empty transaction list for a few seconds after admission.
            # The block builder below supplies this transaction explicitly and may leave its fee unclaimed.
            pool = source.rpc('getrawmempool')
            check(label + '/mempool_contents', len(pool) == int(accepted), pool)
            check(label + '/template_tip', template['previousblockhash'] == source.rpc('getbestblockhash') and
                  all(entry['txid'] in pool for entry in template['transactions']), template['previousblockhash'])
            raw_block, blockhash, weight = b.block(template, tx)
            (directory / (label.replace('/', '-') + '.hex')).write_text(raw_block.hex())
            for par, validator in validators:
                tip = validator.rpc('getbestblockhash')
                check(label + f'/par{par}/empty_mempool', validator.rpc('getrawmempool') == [], [])
                result = validator.rpc('submitblock', raw_block.hex())
                if error:
                    expected = f'non-mandatory-script-verify-flag ({error})' if par == 1 else 'block-validation-failed'
                    check(label + f'/par{par}/invalid_block', result == expected, result)
                    check(label + f'/par{par}/unchanged', validator.rpc('getbestblockhash') == tip and validator.rpc('gettxout', *utxo) is not None, tip)
                else:
                    txid = b.hash256(tx[0])[::-1].hex()
                    created = validator.rpc('gettxout', txid, 0)
                    check(label + f'/par{par}/valid_block', result is None and validator.rpc('getbestblockhash') == blockhash, result)
                    check(label + f'/par{par}/utxo', validator.rpc('gettxout', *utxo) is None and created is not None and
                          created['scriptPubKey']['hex'] == output.hex() and created['value'] == 9, txid)
            if error is None:
                result = source.rpc('submitblock', raw_block.hex())
                check(label + '/source_block', result is None and source.rpc('getbestblockhash') == blockhash, result)
            report['matrix'].append({'case': label, 'mempool_expected': accepted, 'consensus_expected': error is None,
                                     'script_bytes': len(script), 'argument_bytes': sum(map(len, arguments)), 'block_weight': weight})
        report['height'] = source.rpc('getblockcount')
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
