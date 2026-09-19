#!/usr/bin/env python3
"""R4: real DePIN blocks, closed/sealed owner escort and open transfers."""
import argparse
import json
from pathlib import Path
import struct
import tempfile
import importlib.util
from review_auth_envelope import Envelope, compact, hash160

spec = importlib.util.spec_from_file_location('r4_depin_contracts', Path(__file__).with_name('review-opcode-assets-r3-regtest.py'))
r3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r3)
h, b = r3.h, r3.b
COIN = 100_000_000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = args.output or Path(tempfile.mkdtemp(prefix='r4-depin-blocks-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    files = list(Path(__file__).parent.glob('review*.py')) + [Path(__file__).with_name('generate_authscript_vectors.py')]
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes = []
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        source = h.Node(args.bindir, directory / 'source',
                        ['-pqwallet=1', '-par=1', '-bypassdownload=1', '-acceptnonstdtxn=0'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)
        legacy = Envelope(2, False, args.signer)
        legacy_spk = b'\x76\xa9\x14' + hash160(legacy.pub) + b'\x88\xac'
        targets = [source.rpc('decodescript', legacy_spk.hex())['addresses'][0], source.rpc('getnewaddress')]
        targets += [source.rpc('getnewaddress', '', kind) for kind in ('pq', 'ecdsa')]
        holders = {v: source.rpc('getnewaddress', '', 'pq' if v == 2 else 'ecdsa') for v in (2, 3)}
        def spk(address):
            return bytes.fromhex(source.rpc('validateaddress', address)['scriptPubKey'])
        def mine():
            return source.rpc('generatetoaddress', 1, miner)[0]
        def confirm(result):
            txid = result[0] if isinstance(result, list) else result
            mine()
            return source.rpc('getrawtransaction', txid, True)
        def lock(point):
            source.rpc('lockunspent', False, [{'txid': point[0], 'vout': point[1]}])
            return point
        validators = []
        for par in (1, 2):
            worker = h.Node(args.bindir, directory / f'validator{par}',
                            ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(worker)
            worker.ready()
            validators.append((par, worker))
            log = (worker.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        def sync():
            for par, worker in validators:
                for height in range(worker.rpc('getblockcount') + 1, source.rpc('getblockcount') + 1):
                    result = worker.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                    if result is not None:
                        raise RuntimeError(f'par{par}/history: {result}')
        def transfer_script(name, amount, address):
            payload = b'xnat' + compact(len(name)) + name.encode() + struct.pack('<q', amount * COIN)
            return spk(address) + b'\xc0' + h.push(payload) + b'\x75'
        env, script = Envelope(), b'\x51'
        reason = 'bad-txns-depin-transfer-not-by-owner'
        for version, holder in holders.items():
            for family, target in enumerate(targets):
                for state in ('closed', 'open', 'sealed'):
                    label = f'v{version}/target{family}/{state}'
                    name = f'&R4D{version}{family}{state.upper()}'
                    confirm(source.rpc('issue', name, 5, miner))
                    delivered = confirm(source.rpc('transfer', name, 5, holder))
                    out = next(o for o in delivered['vout'] if o['scriptPubKey'].get('asset', {}).get('name') == name)
                    asset = lock((delivered['txid'], out['n']))
                    owner_tx = delivered
                    if state != 'closed':
                        owner_tx = confirm(source.rpc('opendepin' if state == 'open' else 'sealdepin', name))
                    owner_out = next(o for o in owner_tx['vout'] if o['scriptPubKey'].get('asset', {}).get('name') == name + '!')
                    owner = lock((owner_tx['txid'], owner_out['n']))
                    check(label + '/state', source.rpc('getassetdata', name)['transfer_state'] == state, state)
                    program = env.program(script)
                    funded = confirm(source.rpc('sendtoaddress', env.address(source, program), 1))
                    out = next(o for o in funded['vout'] if o['scriptPubKey']['hex'] == env.output(program).hex())
                    funding = lock((funded['txid'], out['n']))
                    def signed(escort):
                        inputs = [funding, asset] + ([owner] if escort else [])
                        outputs = [(0, transfer_script(name, 5, target)), (90_000_000, spk(miner))]
                        if escort:
                            outputs.append((0, transfer_script(name + '!', 1, miner)))
                        wire = bytes.fromhex(source.rpc('signrawtransaction',
                            r3.transaction(env, inputs, script, [], outputs))['hex'])
                        stripped = r3.sig.strip(wire)
                        txid = source.rpc('decoderawtransaction', wire.hex())['txid']
                        check(label + f'/escort{int(escort)}/txid', b.hash256(stripped)[::-1].hex() == txid, txid)
                        return stripped, wire, txid
                    without = signed(False)
                    logfile = source.directory / 'regtest/debug.log'
                    offset = logfile.stat().st_size
                    result = source.rpc('testmempoolaccept', [without[1].hex()])[0]
                    check(label + '/without_owner', (result.get('allowed') == 1) == (state == 'open') and
                          (state == 'open' or reason in str(result) or reason in logfile.read_text()[offset:]), result)
                    sync()
                    if state != 'open':
                        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                        check(label + '/empty_template', not template['transactions'], len(template['transactions']))
                        raw, _, _ = b.block(template, without[:2])
                        (directory / (label.replace('/', '-') + '-invalid.hex')).write_text(raw.hex())
                        for par, worker in validators:
                            tip = worker.rpc('getbestblockhash')
                            logfile = worker.directory / 'regtest/debug.log'
                            offset = logfile.stat().st_size
                            result = worker.rpc('submitblock', raw.hex())
                            detail = logfile.read_text()[offset:]
                            check(label + f'/par{par}/rejected', isinstance(result, str) and
                                  (reason in result or (result == 'rejected' and reason in detail)), result)
                            check(label + f'/par{par}/unchanged', worker.rpc('getbestblockhash') == tip and
                                  all(worker.rpc('gettxout', *point) is not None for point in (funding, asset, owner)), tip)
                    with_owner = signed(True)
                    result = source.rpc('testmempoolaccept', [with_owner[1].hex()])[0]
                    check(label + '/owner_allowed', result.get('allowed') == 1, result)
                    good = without if state == 'open' else with_owner
                    source.rpc('sendrawtransaction', good[1].hex())
                    block = mine()
                    sync()
                    for par, worker in validators:
                        check(label + f'/par{par}/valid_control', worker.rpc('getbestblockhash') == block and
                              worker.rpc('getrawtransaction', good[2], True).get('confirmations') == 1 and
                              worker.rpc('gettxout', *asset) is None, good[2])
                        check(label + f'/par{par}/owner_consumed_only_if_used',
                              (worker.rpc('gettxout', *owner) is None) == (state != 'open'), owner)
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
