#!/usr/bin/env python3
"""Signature opcode activation by height for CODESEPARATOR contracts moving an asset with references.

CHECKSIGADD tails (three separator shapes, PQ/ECDSA keys, auth 0/1/2, native/P2SH) are spent
in v3 transactions with two reference inputs and a wallet-owned asset input. Before the
activation height they are rejected by mempool and by blocks on fresh validators; a block at
the last inactive height is rejected too. From the activation height they are admitted, cost
the same sigops as a CHECKSIG control contract (plus one per authenticated input), and are
mined. Disconnecting the chain below the activation height evicts them from the mempool and
readmission fails; reconnecting restores every confirmation. Isolated regtest nodes only.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('sigassets', Path(__file__).with_name('review-signatures-assets-refs-regtest.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
c, h, b, a = s.c, s.h, s.b, s.a

COIN = s.COIN
FEE = s.FEE
HEIGHT = 520
BAD_OPCODE = 'Opcode missing or not understood'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='signatures-activation-'))
    files = [Path(__file__), *[Path(__file__).with_name(f) for f in (
        'review-signatures-assets-refs-regtest.py', 'authscript-review-signer.cpp',
        'review-authenticated-contracts-regtest.py', 'review-arithmetic-regtest.py',
        'review-introspection-regtest.py', 'review-csfs-block-limit-regtest.py', 'generate_authscript_vectors.py')]]
    report = {'results': [], 'activation_height': HEIGHT, 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'signer_sha256': h.digest_file(args.signer),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes, validators = [], []
    flags = [f'-signatureopcodesheight={HEIGHT}', '-bypassdownload=1']

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
        source = h.Node(args.bindir, directory / 'source', flags + ['-acceptnonstdtxn=0', '-par=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)

        def spk(address):
            return bytes.fromhex(source.rpc('validateaddress', address)['scriptPubKey'])
        miner_script = spk(miner)
        holder, sink = source.rpc('getnewaddress'), source.rpc('getnewaddress')
        holder_script, sink_script = spk(holder), spk(sink)
        keys = {}
        for family in ('pq', 'ecdsa'):
            pubhex, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            keys[family] = bytes.fromhex(pubhex), secret

        def sign(family, digest):
            raw = subprocess.check_output([str(args.signer), 'sign', family],
                                          input=keys[family][1] + '\n' + digest.hex() + '\n', text=True)
            return bytes.fromhex(raw.strip())

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

        confirmed('asset/issue', source.rpc('issue', s.ASSET, s.UNITS, miner))
        asset_in = asset_output(confirmed('asset/transfer_to_holder', source.rpc('transfer', s.ASSET, s.UNITS, holder)), holder_script)
        units = s.UNITS
        tag = a.sha256(b'NeuraiAuthScript')
        contracts, funding_outputs = [], []

        def add(label, script, code, family, auth, gated):
            ofamily = 'pq' if auth == 1 else 'ecdsa'
            descriptor = bytes([auth]) + (c.hash160(keys[ofamily][0]) if auth else b'')
            native = b'\x51\x20' + a.sha256(tag + tag + b'\x01' + descriptor + a.sha256(script))
            for wrapped in (False, True):
                spk_ = b'\xa9\x14' + c.hash160(native) + b'\x87' if wrapped else native
                funding_outputs.append(b.output(COIN, spk_))
                contracts.append({'label': f'{label}/p2sh{int(wrapped)}', 'script': script, 'code': code, 'family': family,
                                  'auth': auth, 'ofamily': ofamily, 'spk': spk_, 'gated': gated,
                                  'sigscript': h.push(native) if wrapped else b''})

        for family in ('pq', 'ecdsa'):
            pub = keys[family][0]
            # Control: CHECKSIG is never gated; it fixes the expected sigop cost.
            add(f'control/{family}/CHECKSIG', b'\x51\x75\xab' + h.push(pub) + b'\xac', h.push(pub) + b'\xac', family, 0, False)
            tail = b'\x00' + h.push(pub) + b'\xde\x51\x9c'
            for shape, script, code in [('executed', b'\x51\x75\xab' + tail, tail),
                                        ('skipped', b'\x00\x63\xab\x68' + tail, b'\x00\x63\xab\x68' + tail),
                                        ('executed_and_later', b'\x51\x63\xab\x68' + tail + b'\xab', b'\x68' + tail + b'\xab')]:
                for auth in (0, 1, 2):
                    add(f'checksigadd/{family}/{shape}/auth{auth}', script, code, family, auth, True)

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
        for ct in contracts:
            ct['utxo'] = funding, available[ct['spk'].hex()].pop(0)
        check('funding/before_activation', source.rpc('getblockcount') < HEIGHT - 10, source.rpc('getblockcount'))

        def replay(upto=None):
            upto = source.rpc('getblockcount') if upto is None else upto
            for par, node in validators:
                start = node.rpc('getblockcount') + 1
                for height in range(start, upto + 1):
                    result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                    if result is not None:
                        raise RuntimeError(f'validator par{par} rejected block {height}: {result}')
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', flags + ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))
        replay()
        for par, node in validators:
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)

        def build(ct, current_asset, current_units):
            inputs = [ct['utxo'], current_asset]
            outputs = [(0, s.transfer_script(sink_script, 1)), (0, s.transfer_script(holder_script, current_units - 1)),
                       (COIN - FEE, miner_script)]
            stack = [bytes([ct['auth']])]
            if ct['auth']:
                stack += [sign(ct['ofamily'], s.sighash(inputs, 0, ct['script'], COIN, outputs, refs, 1, ct['auth'])), keys[ct['ofamily']][0]]
            stack += [sign(ct['family'], s.sighash(inputs, 0, ct['code'], COIN, outputs, refs, 1, 0)), ct['script']]
            _, wire = s.serialize(inputs, [ct['sigscript'], b''], outputs, refs, [stack, []])
            wallet = bytes.fromhex(source.rpc('signrawtransaction', wire.hex())['hex'])
            return s.strip(wallet), wallet, outputs

        def reject_block(label, tx, template=None):
            template = template or source.rpc('getblocktemplate', {'rules': ['segwit']})
            raw_block, _, _ = b.block(template, tx[:2])
            for par, node in validators:
                tip = node.rpc('getbestblockhash')
                result = node.rpc('submitblock', raw_block.hex())
                expected = f'non-mandatory-script-verify-flag ({BAD_OPCODE})' if par == 1 else 'block-validation-failed'
                check(label + f'/par{par}/block', result == expected, result)
                check(label + f'/par{par}/unchanged', node.rpc('getbestblockhash') == tip, tip)

        def mine_spend(ct, tx, label, expected_cost=None):
            txid = source.rpc('sendrawtransaction', tx[1].hex())
            check(label + '/admitted', txid in source.rpc('getrawmempool'), txid)
            template = source.rpc('getblocktemplate', {'rules': ['segwit']})
            cost = next((t['sigops'] for t in template['transactions'] if t['txid'] == txid), None)
            if expected_cost is not None:
                check(label + '/sigops', cost == expected_cost, cost)
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            check(label + '/mined', source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
            replay()
            for par, node in validators:
                created = node.rpc('gettxout', txid, 0)
                check(label + f'/par{par}/asset_moved', node.rpc('getbestblockhash') == blockhash and node.rpc('gettxout', *ct['utxo']) is None and
                      created is not None and created['scriptPubKey']['hex'] == tx[2][0][1].hex(), txid)
            return txid, blockhash, cost

        # Before activation: controls are spendable, gated contracts are rejected everywhere.
        control_costs = {}
        gated = [ct for ct in contracts if ct['gated']]
        for ct in contracts:
            if ct['gated']:
                continue
            tx = build(ct, asset_in, units)
            txid, _, cost = mine_spend(ct, tx, ct['label'] + '/before')
            control_costs[ct['auth']] = cost
            asset_in, units = (txid, 1), units - 1
        check('control/sigops_measured', control_costs.get(0) is not None, control_costs)
        for ct in gated:
            tx = build(ct, asset_in, units)
            rejected(ct['label'] + '/before/mempool', tx[1], BAD_OPCODE)
            reject_block(ct['label'] + '/before', tx)
        # Advance to the last inactive tip: candidate height HEIGHT-1 is still inactive.
        source.rpc('generatetoaddress', HEIGHT - 2 - source.rpc('getblockcount'), miner)
        replay()
        check('tip/last_inactive_candidate', source.rpc('getblockcount') == HEIGHT - 2, source.rpc('getblockcount'))
        first = build(gated[0], asset_in, units)
        rejected(gated[0]['label'] + '/candidate_inactive/mempool', first[1], BAD_OPCODE)
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('tip/empty_template', not template['transactions'] and template['height'] == HEIGHT - 1, template['height'])
        reject_block(gated[0]['label'] + '/candidate_inactive', first, template)
        # The first active candidate is HEIGHT: from tip HEIGHT-1 the mempool admits the spends.
        last_inactive = source.rpc('generatetoaddress', 1, miner)[0]
        replay()
        check('tip/first_active_candidate', source.rpc('getblockcount') == HEIGHT - 1, source.rpc('getblockcount'))
        mined = []
        for ct in gated:
            tx = build(ct, asset_in, units)
            txid, blockhash, _ = mine_spend(ct, tx, ct['label'] + '/after', control_costs[0] + (1 if ct['auth'] else 0))
            mined.append((ct, tx, txid, blockhash))
            asset_in, units = (txid, 1), units - 1
        check('after/all_confirmed', source.rpc('getblockcount') == HEIGHT - 1 + len(gated), source.rpc('getblockcount'))
        # Reorganise below the activation height: the spends become invalid again.
        source.rpc('invalidateblock', last_inactive)
        check('reorg/source_tip', source.rpc('getblockcount') == HEIGHT - 2, source.rpc('getblockcount'))
        check('reorg/source_evicted', not set(m[2] for m in mined) & set(source.rpc('getrawmempool')), source.rpc('getrawmempool'))
        first_ct, first_tx, first_txid, _ = mined[0]
        check('reorg/source_utxos_restored', source.rpc('gettxout', *first_ct['utxo'], False) is not None and
              source.rpc('gettxout', first_txid, 0, False) is None, first_txid)
        rejected('reorg/readmission_rejected', first_tx[1], BAD_OPCODE)
        for par, node in validators:
            node.rpc('invalidateblock', last_inactive)
            check(f'reorg/par{par}/rolled_back', node.rpc('getblockcount') == HEIGHT - 2 and node.rpc('getrawmempool') == [] and
                  node.rpc('gettxout', *first_ct['utxo'], False) is not None, node.rpc('getblockcount'))
            node.rpc('reconsiderblock', last_inactive)
            check(f'reorg/par{par}/restored', node.rpc('getbestblockhash') == mined[-1][3] and
                  all(node.rpc('gettxout', txid, 0) is not None for _, _, txid, _ in mined), node.rpc('getblockcount'))
        source.rpc('reconsiderblock', last_inactive)
        check('reorg/source_restored', source.rpc('getbestblockhash') == mined[-1][3] and source.rpc('getrawmempool') == [] and
              all(source.rpc('getrawtransaction', txid, True).get('confirmations') == len(mined) - i
                  for i, (_, _, txid, _) in enumerate(mined)), source.rpc('getblockcount'))
        report['contracts'] = len(contracts)
        report['control_costs'] = control_costs
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
