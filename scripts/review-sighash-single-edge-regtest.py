#!/usr/bin/env python3
"""SIGHASH_SINGLE at input 1 with only output 0: real AuthScript signatures."""
import argparse
from collections import defaultdict, deque
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('auth', Path(__file__).with_name('review-authenticated-contracts-regtest.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
h, b, a = c.h, c.b, c.a


def signhash(utxo, outputs, refs, ht, version, auth):
    txversion = 3 if refs else 2
    prev = h.outpoint(*utxo[1])
    allprev = b''.join(h.outpoint(*p) for p in utxo)
    sequence = b'\xff' * 4
    mode = ht & 31
    preimage = struct.pack('<I', txversion)
    preimage += bytes(32) if ht & 128 else b.hash256(allprev)
    preimage += bytes(32) if ht & 128 or mode in (2, 3) else b.hash256(sequence)
    preimage += prev + b'\x01\x51' + struct.pack('<Q', 1_000_000_000) + sequence
    preimage += bytes(32) if mode == 2 or (mode == 3 and len(outputs) <= 1) else b.hash256(outputs[1] if mode == 3 else b''.join(outputs))
    if refs:
        preimage += b.hash256(b''.join(h.outpoint(*ref) for ref in refs))
    preimage += bytes(4) + (bytes([version]) if version != 1 else b'') + bytes([auth]) + struct.pack('<I', ht)
    return b.hash256(preimage)


def transaction(utxo, sigscript, stack, outputs, refs, sequence=0xffffffff):
    inputs = b'\x02' + h.outpoint(*utxo[0]) + b'\x00' + b'\xff' * 4
    inputs += h.outpoint(*utxo[1]) + h.compact(len(sigscript)) + sigscript + struct.pack('<I', sequence)
    outs = h.compact(len(outputs)) + b''.join(outputs)
    refdata = h.compact(len(refs)) + b''.join(h.outpoint(*ref) for ref in refs) if refs else b''
    witness = b'\x02\x01\x00\x01\x51' + h.compact(len(stack)) + b''.join(h.compact(len(x)) + x for x in stack)
    prefix = struct.pack('<I', 3 if refs else 2)
    return prefix + inputs + outs + refdata + bytes(4), prefix + b'\x00\x01' + inputs + outs + refdata + witness + bytes(4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='sighash-single-edge-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': h.digest_file(Path(__file__)), 'signer_sha256': h.digest_file(args.signer)}
    nodes = []

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
        destination = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        outputs = [b.output(1_800_000_000, destination)]
        keys = {}
        for family in ('pq', 'ecdsa'):
            pub, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            keys[family] = bytes.fromhex(pub), secret
        contracts, funding_outputs = [], []
        tag = a.sha256(b'NeuraiAuthScript')
        for version, auth, family in ((1, 1, 'pq'), (1, 2, 'ecdsa'), (2, 1, 'pq'), (3, 2, 'ecdsa')):
            commitment = a.sha256(tag + tag + bytes([version, auth]) + c.hash160(keys[family][0]) + a.sha256(b'\x51'))
            native = bytes([0x50 + version, 32]) + commitment
            for ht in (3, 0x83):
                for withrefs in (False, True):
                    for wrapped in (False, True):
                        spk = b'\xa9\x14' + c.hash160(native) + b'\x87' if wrapped else native
                        funding_outputs.append(b.output(1_000_000_000, spk))
                        contracts.append((f'v{version}/{family}/ht{ht}/refs{int(withrefs)}/p2sh{int(wrapped)}',
                                          version, auth, family, ht, withrefs, spk, h.push(native) if wrapped else b''))
        refspk = b'\x51\x20' + a.sha256(tag + tag + b'\x01\x00' + a.sha256(b'\x51'))
        funding_outputs += [b.output(1_000_000_000, refspk)] * len(contracts)
        funding_outputs += [b.output(1_000_000, refspk)] * 2
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(len(funding_outputs)) + b''.join(funding_outputs) + bytes(4)
        funded = source.rpc('fundrawtransaction', raw.hex())
        signed = source.rpc('signrawtransaction', funded['hex'])
        check('funding/signed', signed['complete'], signed['complete'])
        funding = source.rpc('sendrawtransaction', signed['hex'])
        source.rpc('generatetoaddress', 1, miner)
        coins = source.rpc('getrawtransaction', funding, True)['vout']
        available = defaultdict(deque)
        for coin in coins:
            available[coin['scriptPubKey']['hex']].append(coin['n'])
        refouts = [(funding, n) for n in list(available[refspk.hex()])[-2:]]
        validators = []
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))
            for height in range(1, 112):
                result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError(f'funding block {height}: {result}')
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in
                  (node.directory / 'regtest/debug.log').read_text(), par)
        for label, version, auth, family, ht, withrefs, spk, sigscript in contracts:
            utxo = ((funding, available[refspk.hex()].popleft()), (funding, available[spk.hex()].popleft()))
            refs = refouts if withrefs else []
            digest = signhash(utxo, outputs, refs, ht, version, auth)
            signature = bytes.fromhex(subprocess.check_output([str(args.signer), 'sign', family],
                         input=keys[family][1] + '\n' + digest.hex() + '\n', text=True).strip())[:-1] + bytes([ht])
            stack = [bytes([auth]), signature, keys[family][0], b'\x51']
            original = transaction(utxo, sigscript, stack, outputs, refs)
            accepted = source.rpc('testmempoolaccept', [original[1].hex()])[0]
            check(label + '/original', accepted.get('allowed') == 1, accepted)
            negatives = [('sequence', transaction(utxo, sigscript, stack, outputs, refs, 0xfffffffe))]
            if refs:
                negatives.append(('references_reordered', transaction(utxo, sigscript, stack, outputs, refs[::-1])))
            # At input 1 there is no corresponding output. The zero output
            # hash is part of the normal preimage, not the legacy uint256(1).
            legacy_one = bytes.fromhex(subprocess.check_output([str(args.signer), 'sign', family],
                         input=keys[family][1] + '\n' + (b'\x01' + bytes(31)).hex() + '\n', text=True).strip())[:-1] + bytes([ht])
            negatives.append(('legacy_one_hash', transaction(utxo, sigscript, [bytes([auth]), legacy_one, keys[family][0], b'\x51'], outputs, refs)))
            negatives.append(('corresponding_output_added', transaction(utxo, sigscript, stack, outputs + [b.output(1_000_000, destination)], refs)))
            changed_outputs = [b.output(1_800_000_001, destination)]
            good = transaction(utxo, sigscript, stack, changed_outputs, refs)
            accepted = source.rpc('testmempoolaccept', [good[1].hex()])[0]
            check(label + '/uncommitted_output', accepted.get('allowed') == 1, accepted)
            for name, tx in negatives:
                accepted = source.rpc('testmempoolaccept', [tx[1].hex()])[0]
                check(label + '/' + name + '/mempool', not accepted.get('allowed') and
                      'Witness program hash mismatch' in accepted.get('reject-reason', ''), accepted)
                raw_block, _, _ = b.block(source.rpc('getblocktemplate', {'rules': ['segwit']}), tx)
                for par, node in validators:
                    tip = node.rpc('getbestblockhash')
                    result = node.rpc('submitblock', raw_block.hex())
                    expected = 'non-mandatory-script-verify-flag (Witness program hash mismatch)' if par == 1 else 'block-validation-failed'
                    check(label + '/' + name + f'/par{par}/block', result == expected, result)
                    check(label + '/' + name + f'/par{par}/state', node.rpc('getbestblockhash') == tip and
                          node.rpc('gettxout', *utxo[1]) is not None, tip)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            check(label + '/mined', source.rpc('getrawtransaction', txid, True)['confirmations'] == 1, txid)
            for par, node in validators:
                result = node.rpc('submitblock', source.rpc('getblock', blockhash, False))
                check(label + f'/par{par}/block', result is None and node.rpc('getbestblockhash') == blockhash, result)
                check(label + f'/par{par}/state', node.rpc('gettxout', *utxo[1]) is None and node.rpc('gettxout', txid, 0) is not None, txid)
            if refs:
                check(label + '/references_unspent', all(source.rpc('gettxout', *ref) is not None for ref in refs), refs)
        report['contracts'] = len(contracts)
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
