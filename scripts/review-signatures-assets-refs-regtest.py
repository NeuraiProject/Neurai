#!/usr/bin/env python3
"""Signature contracts moving a real asset in v3 transactions with references, then reorganised.

Families from phases 29-32: CODESEPARATOR shapes with five internal signature opcodes,
mixed ECDSA/PQ multisig and the six sighash modes for v1 (external auth) and strict v2/v3,
each native and under P2SH. Every spend is a v3 transaction with two reference inputs, the
contract input and a wallet-owned asset input; the contract signatures cover the asset
outputs and the references. The wallet signs only its own asset input. Each mined spend is
disconnected and reconnected on the source and on both validators.
Commitment/sighash/serialisation are independent Python; keys come from the pinned signer.
"""
import argparse
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

COIN = 100_000_000
FEE = 10_000_000
ASSET = 'SIGASSET'
UNITS = 300
NULLFAIL = 'Signature must be zero for failed CHECK(MULTI)SIG operation'
MISMATCH = 'Witness program hash mismatch'
FALSE_TOP = 'Script evaluated without error but finished with a false/empty top stack element'
UNBALANCED = 'bad-tx-inputs-outputs-mismatch'
VERIFY_ERRORS = {'CHECKSIGVERIFY': 'Script failed an OP_CHECKSIGVERIFY operation',
                 'CHECKMULTISIGVERIFY': 'Script failed an OP_CHECKMULTISIGVERIFY operation'}


def transfer_script(prefix, amount):
    payload = b'xnat' + h.compact(len(ASSET)) + ASSET.encode() + struct.pack('<q', amount * COIN)
    return prefix + b'\xc0' + h.push(payload) + b'\x75'


def serialize(inputs, sigscripts, outputs, refs, witnesses):
    version, lock = struct.pack('<I', 3), bytes(4)
    vin = h.compact(len(inputs)) + b''.join(h.outpoint(*p) + h.compact(len(s)) + s + b'\xff' * 4
                                            for p, s in zip(inputs, sigscripts))
    vout = h.compact(len(outputs)) + b''.join(b.output(v, s) for v, s in outputs)
    vref = h.compact(len(refs)) + b''.join(h.outpoint(*r) for r in refs)
    wit = b''.join(h.compact(len(w)) + b''.join(h.compact(len(x)) + x for x in w) for w in witnesses)
    return version + vin + vout + vref + lock, version + b'\x00\x01' + vin + vout + vref + wit + lock


def sighash(inputs, index, code, amount, outputs, refs, hashtype, auth, witversion=1):
    mode, anyone = hashtype & 31, hashtype & 0x80
    seq = b'\xff' * 4
    pre = struct.pack('<I', 3)
    pre += bytes(32) if anyone else b.hash256(b''.join(h.outpoint(*p) for p in inputs))
    pre += bytes(32) if anyone or mode in (2, 3) else b.hash256(seq * len(inputs))
    pre += h.outpoint(*inputs[index]) + h.compact(len(code)) + code + struct.pack('<Q', amount) + seq
    ser = [b.output(v, s) for v, s in outputs]
    pre += bytes(32) if mode == 2 else b.hash256(ser[index] if mode == 3 else b''.join(ser))
    # v3 always commits to the reference list, whatever the sighash mode.
    pre += b.hash256(b''.join(h.outpoint(*r) for r in refs)) + bytes(4)
    pre += (bytes([witversion]) if witversion != 1 else b'') + bytes([auth]) + struct.pack('<I', hashtype)
    return b.hash256(pre)


def strip(wire):
    """Drop the witness of a signed v3 transaction serialised with marker and flag."""
    pos = 6

    def compact():
        nonlocal pos
        first = wire[pos]
        pos += 1
        if first < 253:
            return first
        width = {253: 2, 254: 4, 255: 8}[first]
        value = int.from_bytes(wire[pos:pos + width], 'little')
        pos += width
        return value
    # Read each length before advancing: compact() itself moves pos.
    for _ in range(compact()):
        pos += 36
        length = compact()
        pos += length + 4
    for _ in range(compact()):
        pos += 8
        length = compact()
        pos += length
    count = compact()
    pos += 36 * count
    return wire[:4] + wire[6:pos] + wire[-4:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='signatures-assets-refs-'))
    files = [Path(__file__), *[Path(__file__).with_name(f) for f in (
        'authscript-review-signer.cpp', 'review-authenticated-contracts-regtest.py', 'review-arithmetic-regtest.py',
        'review-introspection-regtest.py', 'review-csfs-block-limit-regtest.py', 'generate_authscript_vectors.py')]]
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'signer_sha256': h.digest_file(args.signer),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes, validators = [], []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    def rejected(label, wire, reason):
        try:
            source.rpc('sendrawtransaction', wire.hex())
            check(label, False, 'accepted')
        except h.RPCError as error:
            check(label, error.code == -26 and reason in str(error), str(error))

    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1', '-acceptnonstdtxn=0', '-par=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)

        def spk(address):
            return bytes.fromhex(source.rpc('validateaddress', address)['scriptPubKey'])
        miner_script = spk(miner)
        holder, sink, other = (source.rpc('getnewaddress') for _ in range(3))
        holder_script, sink_script, other_script = spk(holder), spk(sink), spk(other)
        keys = {}
        for family in ('pq', 'ecdsa'):
            pubhex, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            keys[family] = bytes.fromhex(pubhex), secret

        def sign(family, digest, hashtype=1):
            raw = subprocess.check_output([str(args.signer), 'sign', family],
                                          input=keys[family][1] + '\n' + digest.hex() + '\n', text=True)
            return bytes.fromhex(raw.strip())[:-1] + bytes([hashtype])

        def confirmed(label, result):
            txid = result[0] if isinstance(result, list) else result
            pending = txid in source.rpc('getrawmempool')
            source.rpc('generatetoaddress', 1, miner)
            tx = source.rpc('getrawtransaction', txid, True)
            check(label, pending and tx.get('confirmations', 0) >= 1, txid)
            return tx

        def asset_output(tx, prefix):
            matches = [out for out in tx['vout'] if out['scriptPubKey']['hex'].startswith(prefix.hex())
                       and len(out['scriptPubKey']['hex']) > len(prefix.hex())]
            if len(matches) != 1:
                raise RuntimeError('asset output not unique: ' + tx['txid'])
            return tx['txid'], matches[0]['n']

        confirmed('asset/issue', source.rpc('issue', ASSET, UNITS, miner))
        asset_in = asset_output(confirmed('asset/transfer_to_holder', source.rpc('transfer', ASSET, UNITS, holder)), holder_script)
        units = UNITS

        tag = a.sha256(b'NeuraiAuthScript')
        contracts, funding_outputs = [], []

        def add(label, script, auth, ofamily, witversion, hashtype, ifamily=None, code=None, opcode=None, args_of=None):
            if witversion == 1:
                descriptor = bytes([auth]) + (c.hash160(keys[ofamily][0]) if auth else b'')
                commitment = a.sha256(tag + tag + b'\x01' + descriptor + a.sha256(script))
            else:
                commitment = a.sha256(tag + tag + bytes([witversion, auth]) + c.hash160(keys[ofamily][0]) + a.sha256(script))
            native = bytes([0x50 + witversion, 32]) + commitment
            for wrapped in (False, True):
                spk_ = b'\xa9\x14' + c.hash160(native) + b'\x87' if wrapped else native
                funding_outputs.append(b.output(COIN, spk_))
                contracts.append({'label': f'{label}/p2sh{int(wrapped)}', 'script': script, 'spk': spk_,
                                  'sigscript': h.push(native) if wrapped else b'', 'auth': auth, 'ofamily': ofamily,
                                  'opub': keys[ofamily][0] if auth else b'', 'witversion': witversion,
                                  'hashtype': hashtype, 'ifamily': ifamily, 'code': code, 'opcode': opcode,
                                  'args_of': args_of})

        # CODESEPARATOR shapes and five internal signature opcodes (phase 30).
        for family in ('pq', 'ecdsa'):
            pub = keys[family][0]
            tails = {
                'CHECKSIG': h.push(pub) + b'\xac',
                'CHECKSIGVERIFY': h.push(pub) + b'\xad\x51',
                'CHECKSIGADD': b'\x00' + h.push(pub) + b'\xde\x51\x9c',
                'CHECKMULTISIG': b'\x00\x7c\x51' + h.push(pub) + b'\x51\xae',
                'CHECKMULTISIGVERIFY': b'\x00\x7c\x51' + h.push(pub) + b'\x51\xaf\x51',
            }
            for opcode, tail in tails.items():
                for shape, script, script_code in [
                        ('executed', b'\x51\x75\xab' + tail, tail),
                        ('skipped', b'\x00\x63\xab\x68' + tail, b'\x00\x63\xab\x68' + tail),
                        ('executed_and_later', b'\x51\x63\xab\x68' + tail + b'\xab', b'\x68' + tail + b'\xab')]:
                    for auth in (0, 1, 2):
                        add(f'codesep/{family}/{opcode}/{shape}/auth{auth}', script, auth, 'pq' if auth == 1 else 'ecdsa',
                            1, 1, family, script_code, opcode, lambda sig: [sig])
        # Mixed ECDSA/PQ 1-of-2 multisig, signed by the first key (phase 29).
        for first, second in (('ecdsa', 'pq'), ('pq', 'ecdsa')):
            for verify in (False, True):
                script = b'\x51' + h.push(keys[first][0]) + h.push(keys[second][0]) + b'\x52' + (b'\xaf\x51' if verify else b'\xae')
                add(f'multisig/{first}-first/verify{int(verify)}', script, 0, 'ecdsa', 1, 1, first, script,
                    'CHECKMULTISIGVERIFY' if verify else 'CHECKMULTISIG', lambda sig: [b'', sig])
        # Six sighash modes for v1 external auth and the strict v2/v3 families (phases 31-32).
        for witversion, auth, family in ((1, 1, 'pq'), (1, 2, 'ecdsa'), (2, 1, 'pq'), (3, 2, 'ecdsa')):
            for hashtype in (1, 2, 3, 0x81, 0x82, 0x83):
                add(f'sighash/v{witversion}/{family}/ht{hashtype:02x}', b'\x51', auth, family, witversion, hashtype)

        refspk = b'\x51\x20' + a.sha256(tag + tag + b'\x01\x00' + a.sha256(b'\x51'))
        funding_outputs += [b.output(1_000_000, refspk)] * 2
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(len(funding_outputs)) + b''.join(funding_outputs) + bytes(4)
        signed = source.rpc('signrawtransaction', source.rpc('fundrawtransaction', raw.hex())['hex'])
        check('funding/signed', signed['complete'], signed['complete'])
        funding = source.rpc('sendrawtransaction', signed['hex'])
        source.rpc('generatetoaddress', 1, miner)
        coins = source.rpc('getrawtransaction', funding, True)['vout']
        available = {}
        for coin in coins:
            available.setdefault(coin['scriptPubKey']['hex'], []).append(coin['n'])
        refs = [(funding, n) for n in available.pop(refspk.hex())]
        check('funding/references', len(refs) == 2, refs)
        height = source.rpc('getblockcount')
        history = [source.rpc('getblock', source.rpc('getblockhash', i), False) for i in range(1, height + 1)]
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))
            for raw_block in history:
                if node.rpc('submitblock', raw_block) is not None:
                    raise RuntimeError('validator rejected funding history')
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
            check(f'par{par}/funded_tip', node.rpc('getbestblockhash') == source.rpc('getbestblockhash'), height)

        def build(ct, utxo, outputs, refs_, signed_outputs=None, signed_refs=None, internal_code=None, outer_code=None):
            inputs = [utxo, asset_in]
            so = outputs if signed_outputs is None else signed_outputs
            sr = refs_ if signed_refs is None else signed_refs
            stack = [bytes([ct['auth']])]
            if ct['auth']:
                code = ct['script'] if outer_code is None else outer_code
                digest = sighash(inputs, 0, code, COIN, so, sr, ct['hashtype'], ct['auth'], ct['witversion'])
                stack += [sign(ct['ofamily'], digest, ct['hashtype']), ct['opub']]
            if ct['ifamily']:
                code = ct['code'] if internal_code is None else internal_code
                stack += ct['args_of'](sign(ct['ifamily'], sighash(inputs, 0, code, COIN, so, sr, 1, 0)))
            stack.append(ct['script'])
            _, wire = serialize(inputs, [ct['sigscript'], b''], outputs, refs_, [stack, []])
            wallet = bytes.fromhex(source.rpc('signrawtransaction', wire.hex())['hex'])
            return strip(wallet), wallet

        def reject_block(label, tx, block_error, exact=False):
            template = source.rpc('getblocktemplate', {'rules': ['segwit']})
            check(label + '/empty_template', not template['transactions'], len(template['transactions']))
            raw_block, _, _ = b.block(template, tx)
            for par, node in validators:
                tip = node.rpc('getbestblockhash')
                result = node.rpc('submitblock', raw_block.hex())
                if exact:
                    passed = isinstance(result, str) and result.startswith(block_error)
                else:
                    passed = result == (f'non-mandatory-script-verify-flag ({block_error})' if par == 1 else 'block-validation-failed')
                check(label + f'/par{par}/block', passed, result)
                check(label + f'/par{par}/unchanged', node.rpc('getbestblockhash') == tip and
                      node.rpc('gettxout', *utxo) is not None and node.rpc('gettxout', *asset_in) is not None, tip)

        for ct in contracts:
            label = ct['label']
            utxo = funding, available[ct['spk'].hex()].pop(0)
            outputs = [(0, transfer_script(sink_script, 1)), (0, transfer_script(holder_script, units - 1)), (COIN - FEE, miner_script)]
            good = build(ct, utxo, outputs, refs)
            accepted = source.rpc('testmempoolaccept', [good[1].hex()])[0]
            check(label + '/original_accepted', accepted.get('allowed') == 1, accepted)
            # Signature-wide mutations: the outer signature fails first when present.
            if ct['auth']:
                sig_error, block_error = MISMATCH, MISMATCH
            else:
                sig_error, block_error = NULLFAIL, VERIFY_ERRORS.get(ct['opcode'], FALSE_TOP)
            negatives = [('references_reordered', build(ct, utxo, outputs, refs[::-1], signed_refs=refs), sig_error, block_error, False)]
            redirected = [(0, transfer_script(other_script, 1))] + outputs[1:]
            redirect = build(ct, utxo, redirected, refs, signed_outputs=outputs)
            if ct['hashtype'] & 31 == 2:
                # The contract NONE signature does not commit to outputs. build() signs
                # the asset input again with the owner wallet for the modified outputs.
                # This does NOT redirect an asset while preserving all original signatures;
                # asset conservation still rejects creation of extra units.
                accepted = source.rpc('testmempoolaccept', [redirect[1].hex()])[0]
                check(label + '/redirect_allowed_under_none', accepted.get('allowed') == 1, accepted)
                unbalanced = [(0, transfer_script(sink_script, 2))] + outputs[1:]
                negatives.append(('asset_unbalanced', build(ct, utxo, unbalanced, refs, signed_outputs=outputs), UNBALANCED, UNBALANCED, True))
            else:
                negatives.append(('asset_redirected', redirect, sig_error, block_error, False))
            if ct['ifamily'] and ct['label'].startswith('codesep'):
                wrong = ct['script'] if ct['code'] != ct['script'] else ct['script'][4:]
                negatives.append(('wrong_internal_scriptcode', build(ct, utxo, outputs, refs, internal_code=wrong),
                                  NULLFAIL, VERIFY_ERRORS.get(ct['opcode'], FALSE_TOP), False))
            for name, tx, mempool_error, block_error_, exact in negatives:
                rejected(label + '/' + name + '/mempool', tx[1], mempool_error)
                reject_block(label + '/' + name, tx, block_error_, exact)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            previous = source.rpc('getbestblockhash')
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            raw_block = source.rpc('getblock', blockhash, False)
            check(label + '/mined', source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
            for par, node in validators:
                check(label + f'/par{par}/empty_mempool', node.rpc('getrawmempool') == [], [])
                result = node.rpc('submitblock', raw_block)
                created = node.rpc('gettxout', txid, 0)
                change = node.rpc('gettxout', txid, 1)
                check(label + f'/par{par}/block', result is None and node.rpc('getbestblockhash') == blockhash, result)
                check(label + f'/par{par}/asset_moved', node.rpc('gettxout', *utxo) is None and node.rpc('gettxout', *asset_in) is None and
                      created is not None and created['scriptPubKey']['hex'] == outputs[0][1].hex() and
                      change is not None and change['scriptPubKey']['hex'] == outputs[1][1].hex(), txid)
                check(label + f'/par{par}/references_unspent', all(node.rpc('gettxout', *ref) is not None for ref in refs), refs)
                # Reorganisation: disconnect the spend, then reconnect it.
                node.rpc('invalidateblock', blockhash)
                check(label + f'/par{par}/reorg/rolled_back', node.rpc('getbestblockhash') == previous and
                      node.rpc('gettxout', *utxo, False) is not None and node.rpc('gettxout', *asset_in, False) is not None and
                      node.rpc('gettxout', txid, 0, False) is None, previous)
                node.rpc('reconsiderblock', blockhash)
                check(label + f'/par{par}/reorg/restored', node.rpc('getbestblockhash') == blockhash and
                      node.rpc('gettxout', *utxo) is None and node.rpc('gettxout', txid, 0) is not None and
                      node.rpc('getrawmempool') == [], blockhash)
            source.rpc('invalidateblock', blockhash)
            check(label + '/reorg/source_rolled_back', source.rpc('getbestblockhash') == previous and
                  txid in source.rpc('getrawmempool') and source.rpc('gettxout', *utxo, False) is not None and
                  source.rpc('gettxout', *asset_in, False) is not None, previous)
            source.rpc('reconsiderblock', blockhash)
            check(label + '/reorg/source_restored', source.rpc('getbestblockhash') == blockhash and
                  source.rpc('getrawmempool') == [] and
                  source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, blockhash)
            asset_in = txid, 1
            units -= 1
        report['contracts'] = len(contracts)
        report['asset_units_moved'] = UNITS - units
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
