#!/usr/bin/env python3
"""Covenants inspecting real issuance, owner and reissue outputs to v2/v3."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('asset_helpers', 'review-asset-fields-regtest.py')
b = load('block_helpers', 'review-csfs-block-limit-regtest.py')
COIN = 100_000_000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='asset-output-metadata-'))
    report = {'results': [], 'binary_sha256': m.digest_file(args.bindir / 'neuraid'),
              'source_sha256': m.digest_file(Path(__file__))}
    nodes, validators = [], []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = m.Node(args.bindir, directory / 'source', ['-pqwallet=1', '-acceptnonstdtxn=0', '-par=1', '-bypassdownload=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)
        miner_spk = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        burn_spk = bytes.fromhex(source.rpc('validateaddress', 'tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy')['scriptPubKey'])
        for par in (1, 2):
            node = m.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))

        def sync():
            for par, node in validators:
                for height in range(node.rpc('getblockcount') + 1, source.rpc('getblockcount') + 1):
                    result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                    if result is not None:
                        raise RuntimeError(f'par{par}/sync/{height}: {result}')

        sync()
        for par, node in validators:
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in
                  (node.directory / 'regtest/debug.log').read_text(), par)
        for version in (2, 3):
            address = source.rpc('getnewaddress', '', 'pq' if version == 2 else 'ecdsa')
            prefix = bytes.fromhex(source.rpc('validateaddress', address)['scriptPubKey'])
            name = f'OUTPUTV{version}'
            owner = None
            for kind in ('issue', 'reissue_hash', 'reissue_plain'):
                label = f'v{version}/{kind}'
                quantity = 5 if kind == 'issue' else 2
                datahash = bytes(range(32)) if kind == 'issue' else bytes(range(32, 64))
                name_bytes = name.encode()
                owner_name = (name + '!').encode()
                def asset_script(payload):
                    return prefix + b'\xc0' + m.push(payload) + b'\x75'
                owner_payload = (b'xnao' + m.compact(len(owner_name)) + owner_name if kind == 'issue' else
                                 b'xnat' + m.compact(len(owner_name)) + owner_name + struct.pack('<q', COIN))
                owner_spk = asset_script(owner_payload)
                fields = {1: name_bytes, 2: m.number(quantity * COIN)}
                if kind == 'issue':
                    payload = b'xnaq' + m.compact(len(name_bytes)) + name_bytes + struct.pack('<q', quantity * COIN)
                    payload += b'\x02\x01\x01\x12\x20' + datahash
                    fields.update({3: b'\x02', 4: b'\x01', 5: b'\x01', 6: b'\x12\x20' + datahash, 7: b'\x00'})
                else:
                    payload = b'xnar' + m.compact(len(name_bytes)) + name_bytes + struct.pack('<q', quantity * COIN)
                    payload += b'\xff\x01'
                    fields.update({3: b'\xff', 4: b'\x01', 7: b'\x08'})
                    if kind == 'reissue_hash':
                        payload += b'\x54\x20' + datahash
                        fields[6] = datahash
                asset_spk = asset_script(payload)
                burn = 1000 if kind == 'issue' else 200
                outputs = [(burn * COIN, burn_spk), (COIN, miner_spk), (0, owner_spk), (0, asset_spk)]
                contract = b''
                for selector, value in fields.items():
                    contract += b'\x53' + m.push(bytes([selector])) + b'\xce' + m.push(value) + b'\x88'
                for selector, value in {1: owner_name, 2: m.number(COIN), 7: b'\x09'}.items():
                    contract += b'\x52' + m.push(bytes([selector])) + b'\xce' + m.push(value) + b'\x88'
                for index in (2, 3):
                    contract += m.push(m.number(index)) + b'\xc2' + m.push(bytes([version]) + prefix[2:]) + b'\x88'
                contract += b'\x51'
                tag = m.sha256(b'NeuraiAuthScript')
                commitment = m.sha256(tag + tag + b'\x01\x00' + m.sha256(contract))
                funding = source.rpc('sendtoaddress', m.bech32m('tnq', 1, commitment), burn + 2)
                source.rpc('generatetoaddress', 1, miner)
                coin = source.rpc('getrawtransaction', funding, True)
                prev = (funding, next(o['n'] for o in coin['vout'] if o['scriptPubKey']['hex'] == (b'\x51\x20' + commitment).hex()))
                inputs = [prev] + ([owner] if owner else [])
                witnesses = [[b'\x00', contract]] + ([[]] if owner else [])
                sync()

                def spend(outs):
                    raw = m.raw_transaction(inputs, outs, [], witnesses)
                    signed = source.rpc('signrawtransaction', raw)
                    wire = bytes.fromhex(signed['hex'])
                    decoded = source.rpc('decoderawtransaction', signed['hex'])
                    if decoded['version'] != 3 or decoded['locktime'] != 0 or any(
                            vin['scriptSig']['hex'] or vin['sequence'] != 0xffffffff for vin in decoded['vin']):
                        raise RuntimeError('unexpected signer serialization')
                    stripped = struct.pack('<I', 3) + m.compact(len(inputs))
                    stripped += b''.join(m.outpoint(*i) + b'\x00' + b'\xff' * 4 for i in inputs)
                    stripped += m.compact(len(outs)) + b''.join(b.output(value, script) for value, script in outs)
                    stripped += b'\x00' + bytes(4)  # empty references and locktime
                    check(label + '/txid/' + b.hash256(stripped)[::-1].hex(),
                          b.hash256(stripped)[::-1].hex() == decoded['txid'], decoded['txid'])
                    return stripped, wire

                bad_payload = payload.replace(struct.pack('<q', quantity * COIN), struct.pack('<q', (quantity + 1) * COIN), 1)
                bad_outputs = list(outputs)
                bad_outputs[3] = (0, asset_script(bad_payload))
                bad = spend(bad_outputs)
                accepted = source.rpc('testmempoolaccept', [bad[1].hex()])[0]
                check(label + '/wrong_quantity/mempool', not accepted.get('allowed') and
                      'EQUALVERIFY' in accepted.get('reject-reason', ''), accepted)
                raw_block, _, _ = b.block(source.rpc('getblocktemplate', {'rules': ['segwit']}), bad)
                for par, node in validators:
                    tip = node.rpc('getbestblockhash')
                    result = node.rpc('submitblock', raw_block.hex())
                    expected = 'non-mandatory-script-verify-flag (Script failed an OP_EQUALVERIFY operation)' if par == 1 else 'block-validation-failed'
                    check(label + f'/wrong_quantity/par{par}', result == expected and
                          node.rpc('getbestblockhash') == tip and node.rpc('gettxout', *prev) is not None, result)
                good = spend(outputs)
                txid = source.rpc('sendrawtransaction', good[1].hex())
                blockhash = source.rpc('generatetoaddress', 1, miner)[0]
                check(label + '/mined', source.rpc('getrawtransaction', txid, True)['confirmations'] == 1, txid)
                for par, node in validators:
                    result = node.rpc('submitblock', source.rpc('getblock', blockhash, False))
                    check(label + f'/par{par}/block', result is None and node.rpc('getbestblockhash') == blockhash, result)
                    check(label + f'/par{par}/state', node.rpc('gettxout', *prev) is None and
                          node.rpc('gettxout', txid, 3)['scriptPubKey']['hex'] == asset_spk.hex(), txid)
                owner = txid, 2
                source.rpc('lockunspent', False, [{'txid': txid, 'vout': 2}])
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
