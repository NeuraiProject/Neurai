#!/usr/bin/env python3
"""R3: byte/hash/arithmetic/timelock contracts with real root assets and reorgs.
Isolated regtest only. Stops at the first failed assertion; never edits consensus.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from review_auth_envelope import Envelope, compact, hash160


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hm = load('r3_hash', 'review-hash-merkle-regtest.py')
a = load('r3_arithmetic', 'review-arithmetic-regtest.py')
sig = load('r3_signature_helpers', 'review-signatures-assets-refs-regtest.py')
h, b = hm.h, hm.b
COIN = 100_000_000


def transaction(env, inputs, script, arguments, outputs, locktime=0, sequence=0xffffffff):
    prev = b''.join(h.outpoint(*p) for p in inputs)
    seq, lock = struct.pack('<I', sequence), struct.pack('<I', locktime)
    out = b''.join(struct.pack('<Q', value) + compact(len(spk)) + spk for value, spk in outputs)
    scriptsig = h.push(b'\x51\x20' + env.program(script)) if env.wrapped else b''
    stack = [bytes([env.auth])]
    if env.auth:
        preimage = (struct.pack('<I', 3) + b.hash256(prev) + b.hash256(seq * len(inputs)) +
                    h.outpoint(*inputs[0]) + compact(len(script)) + script + struct.pack('<Q', COIN) +
                    seq + b.hash256(out) + b.hash256(b'') + lock + bytes([env.auth]) + struct.pack('<I', 1))
        stack += [env.sign(b.hash256(preimage)), env.pub]
    stack += list(arguments) + [script]
    vin = b''
    for i, p in enumerate(inputs):
        script_sig = scriptsig if i == 0 else b''
        vin += h.outpoint(*p) + compact(len(script_sig)) + script_sig + seq
    witness = compact(len(stack)) + b''.join(compact(len(x)) + x for x in stack)
    witness += b'\x00' * (len(inputs) - 1)
    return (struct.pack('<I', 3) + b'\x00\x01' + compact(len(inputs)) + vin +
            compact(len(outputs)) + out + b'\x00' + witness + lock).hex()


def cases(group, vectors):
    data = bytes(range(33))
    rows = []
    if group == 'bytes':
        rows = [
            ('CAT', b'\x7e' + h.push(data) + b'\x88', [data[:17], data[17:]]),
            ('SPLIT', h.push(b'\x11') + b'\xb7' + h.push(data[17:]) + b'\x88' +
             h.push(data[:17]) + b'\x88', [data]),
            ('REVERSEBYTES', b'\xbc' + h.push(data[::-1]) + b'\x88', [data])]
    elif group == 'hashes':
        for name, opcode, digest in [
                ('RIPEMD160', 0xa6, hashlib.new('ripemd160', data).digest()),
                ('SHA1', 0xa7, hashlib.sha1(data).digest()),
                ('SHA256', 0xa8, hashlib.sha256(data).digest()),
                ('HASH160', 0xa9, hash160(data)),
                ('HASH256', 0xaa, b.hash256(data))]:
            rows.append((name, bytes([opcode]) + h.push(digest) + b'\x88', [data]))
        rows += hm.cases(vectors)
    elif group == 'arithmetic':
        for name, script, args, bad, error in a.cases():
            # Real fee is input 0 minus coin output 2; asset outputs 0/1 carry no XNA.
            yield name, script.replace(b'\x00\xcc', b'\x52\xcc'), args, bad, error
        return
    elif group == 'timelocks':
        for kind in ('CLTV_HEIGHT', 'CSV_HEIGHT', 'CLTV_TIME', 'CSV_TIME'):
            yield kind, b'', [], [], ''
        return
    for name, script, args in rows:
        bad = list(args)
        bad[-1] = bytes([bad[-1][0] ^ 1]) + bad[-1][1:]
        yield name, script, args, bad, 'OP_VERIFY' if name.startswith('MERKLE') else 'OP_EQUALVERIFY'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=['bytes', 'hashes', 'arithmetic', 'timelocks'], required=True)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    vectors = Path(__file__).resolve().parents[1] / 'src/test/reversebytes_tests.cpp'
    directory = args.output or Path(tempfile.mkdtemp(prefix='r3-' + args.group + '-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    # Record all local Python helpers to include transitive imports, not just direct ones.
    files = list(Path(__file__).parent.glob('review*.py')) + [vectors, Path(__file__).with_name('generate_authscript_vectors.py')]
    report = {'group': args.group, 'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes = []
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        node = h.Node(args.bindir, directory / 'node', ['-pqwallet=1', '-par=1', '-assumevalid=0', '-bypassdownload=1'])
        nodes.append(node)
        node.ready()
        node.rpc('setmocktime', 1800000000)
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 500, miner)
        legacy = Envelope(2, False, args.signer)
        legacy_spk = b'\x76\xa9\x14' + hash160(legacy.pub) + b'\x88\xac'
        addresses = [node.rpc('decodescript', legacy_spk.hex())['addresses'][0], miner]
        addresses += [node.rpc('getnewaddress', '', kind) for kind in ('pq', 'ecdsa')]
        destinations = [bytes.fromhex(node.rpc('validateaddress', x)['scriptPubKey']) for x in addresses]
        def mine(count=1):
            return node.rpc('generatetoaddress', count, miner)
        def confirm(result):
            txid = result[0] if isinstance(result, list) else result
            mine()
            return node.rpc('getrawtransaction', txid, True)
        def locate(tx, prefix, asset=False):
            out = next(o for o in tx['vout'] if o['scriptPubKey']['hex'].startswith(prefix.hex()) and
                       (len(o['scriptPubKey']['hex']) > len(prefix.hex())) == asset)
            point = tx['txid'], out['n']
            node.rpc('lockunspent', False, [{'txid': point[0], 'vout': point[1]}])
            return point
        name = 'R3' + args.group.upper()
        confirm(node.rpc('issue', name, 100000, miner))
        validators = []
        for par in (1, 2):
            worker = h.Node(args.bindir, directory / f'validator{par}',
                            ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(worker)
            worker.ready()
            worker.rpc('setmocktime', 1801000000)
            validators.append((par, worker))
            log = (worker.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        def sync():
            for par, worker in validators:
                for height in range(worker.rpc('getblockcount') + 1, node.rpc('getblockcount') + 1):
                    result = worker.rpc('submitblock', node.rpc('getblock', node.rpc('getblockhash', height), False))
                    if result is not None:
                        raise RuntimeError(f'par{par}/history: {result}')
        def asset_script(prefix, amount):
            payload = b'xnat' + compact(len(name)) + name.encode() + struct.pack('<q', amount * COIN)
            return prefix + b'\xc0' + h.push(payload) + b'\x75'
        for auth in (0, 1, 2):
            for wrapped in (False, True):
                env = Envelope(auth, wrapped, args.signer)
                for opname, verification, operands, bad_operands, error in cases(args.group, vectors):
                    for family in range(4):
                        label = f'{opname}/auth{auth}/p2sh{int(wrapped)}/family{family}'
                        asset = locate(confirm(node.rpc('transfer', name, 5, addresses[2 + family % 2])),
                                       destinations[2 + family % 2], True)
                        locktime, sequence, maturity = 0, 0xffffffff, []
                        timed = args.group == 'timelocks'
                        if timed:
                            absolute, temporal = opname.startswith('CLTV'), opname.endswith('TIME')
                            funding_height = node.rpc('getblockcount') + 1
                            mtp = node.rpc('getblockchaininfo')['mediantime']
                            target = mtp + 512 if temporal else funding_height + 2
                            operand = target if absolute else 0x400001 if temporal else 3
                            locktime, sequence = (target, 0xfffffffe) if absolute else (0, operand)
                            verification = h.push(a.number(operand)) + bytes([0xb1 if absolute else 0xb2, 0x75])
                        output = asset_script(destinations[family], 3)
                        script = verification + b'\x00\xcd' + h.push(output) + b'\x87'
                        program = env.program(script)
                        funding = locate(confirm(node.rpc('sendtoaddress', env.address(node, program), 1)), env.output(program))
                        inputs = [funding, asset]
                        outputs = [(0, output), (0, asset_script(destinations[1], 2)), (90_000_000, destinations[1])]
                        def signed(arguments=operands, outs=outputs):
                            wire = bytes.fromhex(node.rpc('signrawtransaction',
                                transaction(env, inputs, script, arguments, outs, locktime, sequence))['hex'])
                            stripped = sig.strip(wire)
                            check(label + '/txid', b.hash256(stripped)[::-1].hex() ==
                                  node.rpc('decoderawtransaction', wire.hex())['txid'], len(wire))
                            return stripped, wire
                        good = signed()
                        if timed:
                            result = node.rpc('testmempoolaccept', [good[1].hex()])[0]
                            reason = 'non-final' if absolute else 'non-BIP68-final'
                            check(label + '/immature', result.get('allowed') != 1 and reason in str(result), result)
                            if temporal:
                                node.rpc('setmocktime', target + int(absolute))
                                maturity = mine(6)
                                check(label + '/maturity_mtp', node.rpc('getblockchaininfo')['mediantime'] ==
                                      target + int(absolute), target)
                            else:
                                maturity = mine(2)
                        else:
                            bad = signed(bad_operands)
                            result = node.rpc('testmempoolaccept', [bad[1].hex()])[0]
                            check(label + '/bad_operand', result.get('allowed') != 1 and error.lower() in str(result).lower(), result)
                        alternate = list(outputs)
                        alternate[0] = (0, asset_script(destinations[(family + 1) % 4], 3))
                        wrong = signed(outs=alternate)
                        result = node.rpc('testmempoolaccept', [wrong[1].hex()])[0]
                        check(label + '/wrong_destination', result.get('allowed') != 1 and 'false' in str(result).lower(), result)
                        sync()
                        template = node.rpc('getblocktemplate', {'rules': ['segwit']})
                        check(label + '/empty_template', not template['transactions'], len(template['transactions']))
                        invalid = wrong if timed else bad
                        raw, _, _ = b.block(template, invalid)
                        for par, worker in validators:
                            tip = worker.rpc('getbestblockhash')
                            result = worker.rpc('submitblock', raw.hex())
                            expected = 'false' if timed else error.lower()
                            check(label + f'/par{par}/invalid_block', isinstance(result, str) and
                                  (expected in result.lower() if par == 1 else result == 'block-validation-failed'), result)
                            check(label + f'/par{par}/unchanged', worker.rpc('getbestblockhash') == tip and
                                  worker.rpc('gettxout', *asset) is not None, tip)
                        txid = node.rpc('sendrawtransaction', good[1].hex())
                        block = mine()[0]
                        check(label + '/mined', node.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
                        node.rpc('invalidateblock', maturity[0] if timed else block)
                        pending = node.rpc('getrawmempool')
                        check(label + '/reorg_mempool', (txid in pending) == (not timed), pending)
                        check(label + '/asset_restored', node.rpc('gettxout', *asset, False) is not None, asset)
                        if timed:
                            result = node.rpc('testmempoolaccept', [good[1].hex()])[0]
                            check(label + '/immature_again', result.get('allowed') != 1 and reason in str(result), result)
                            check(label + '/reorg_template', not node.rpc('getblocktemplate', {'rules': ['segwit']})['transactions'], pending)
                        node.rpc('reconsiderblock', maturity[0] if timed else block)
                        check(label + '/reconfirmed', node.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
                        sync()
                        for par, worker in validators:
                            check(label + f'/par{par}/confirmed', worker.rpc('getbestblockhash') == block and
                                  worker.rpc('getrawtransaction', txid, True).get('confirmations') == 1 and
                                  worker.rpc('gettxout', *asset) is None, txid)
        report['height'] = node.rpc('getblockcount')
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
