#!/usr/bin/env python3
"""R4: restricted-asset failures in full blocks, followed by valid controls."""
import argparse
import json
from pathlib import Path
import struct
import tempfile
import importlib.util
from review_auth_envelope import Envelope, compact, hash160

spec = importlib.util.spec_from_file_location('r4_contracts', Path(__file__).with_name('review-opcode-assets-r3-regtest.py'))
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
    directory = args.output or Path(tempfile.mkdtemp(prefix='r4-restricted-blocks-'))
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
                        ['-addresstype=pq', '-par=1', '-bypassdownload=1', '-acceptnonstdtxn=0'])
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
            block = mine()
            return source.rpc('getrawtransaction', txid, True), block
        def locate(tx, prefix, asset=False):
            out = next(o for o in tx['vout'] if o['scriptPubKey']['hex'].startswith(prefix.hex()) and
                       (len(o['scriptPubKey']['hex']) > len(prefix.hex())) == asset)
            point = tx['txid'], out['n']
            source.rpc('lockunspent', False, [{'txid': point[0], 'vout': point[1]}])
            return point
        confirm(source.rpc('issuequalifierasset', '#R4TAG', 1, miner, miner))
        confirm(source.rpc('issuequalifierasset', '#R4BLOCK', 1, miner, miner))
        for address in list(holders.values()) + targets:
            confirm(source.rpc('addtagtoaddress', '#R4TAG', address, miner))
        for address in targets:
            confirm(source.rpc('addtagtoaddress', '#R4BLOCK', address, miner))
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
        reasons = {'tag': 'bad-txns-null-verifier-address-failed-verification',
                   'verifier': 'bad-txns-null-verifier-address-failed-verification',
                   'address': 'bad-txns-restricted-asset-transfer-from-frozen-address',
                   'global': 'bad-txns-transfer-restricted-asset-that-is-globally-restricted'}
        env, script = Envelope(), b'\x51'
        for version, holder in holders.items():
            for family, target in enumerate(targets):
                for event in reasons:
                    label = f'v{version}/target{family}/{event}'
                    root = f'R4R{version}{family}{event.upper()}'
                    name = '$' + root
                    confirm(source.rpc('issue', root, 5, miner, miner))
                    issued, _ = confirm(source.rpc('issuerestrictedasset', name, 5, '#R4TAG', holder, miner))
                    asset = locate(issued, spk(holder), True)
                    program = env.program(script)
                    funded, _ = confirm(source.rpc('sendtoaddress', env.address(source, program), 1))
                    funding = locate(funded, env.output(program))
                    payload = b'xnat' + compact(len(name)) + name.encode() + struct.pack('<q', 5 * COIN)
                    outputs = [(0, spk(target) + b'\xc0' + h.push(payload) + b'\x75'), (90_000_000, spk(miner))]
                    wire = bytes.fromhex(source.rpc('signrawtransaction',
                        r3.transaction(env, [funding, asset], script, [], outputs))['hex'])
                    stripped = r3.sig.strip(wire)
                    txid = source.rpc('decoderawtransaction', wire.hex())['txid']
                    check(label + '/txid', b.hash256(stripped)[::-1].hex() == txid, txid)
                    result = source.rpc('testmempoolaccept', [wire.hex()])[0]
                    check(label + '/before_allowed', result.get('allowed') == 1, result)
                    if event == 'tag':
                        changed = source.rpc('removetagfromaddress', '#R4TAG', target, miner)
                        undo = ('addtagtoaddress', '#R4TAG', target, miner)
                    elif event == 'verifier':
                        changed = source.rpc('reissuerestrictedasset', name, 0, holder, True, '#R4TAG & !#R4BLOCK', miner)
                        undo = ('reissuerestrictedasset', name, 0, holder, True, '#R4TAG', miner)
                    elif event == 'address':
                        changed = source.rpc('freezeaddress', name, holder, miner)
                        undo = ('unfreezeaddress', name, holder, miner)
                    else:
                        changed = source.rpc('freezerestrictedasset', name, miner)
                        undo = ('unfreezerestrictedasset', name, miner)
                    _, restriction_block = confirm(changed)
                    sync()
                    logfile = source.directory / 'regtest/debug.log'
                    offset = logfile.stat().st_size
                    result = source.rpc('testmempoolaccept', [wire.hex()])[0]
                    check(label + '/mempool_rejected', result.get('allowed') != 1 and
                          reasons[event] in logfile.read_text()[offset:], result)
                    template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                    check(label + '/empty_template', not template['transactions'], len(template['transactions']))
                    raw, _, _ = b.block(template, (stripped, wire))
                    (directory / (label.replace('/', '-') + '-invalid.hex')).write_text(raw.hex())
                    for par, worker in validators:
                        tip = worker.rpc('getbestblockhash')
                        logfile = worker.directory / 'regtest/debug.log'
                        offset = logfile.stat().st_size
                        result = worker.rpc('submitblock', raw.hex())
                        detail = logfile.read_text()[offset:]
                        check(label + f'/par{par}/rejected', isinstance(result, str) and
                              (reasons[event] in result or (result == 'rejected' and reasons[event] in detail)),
                              {'rpc': result, 'reason_in_new_log': reasons[event] in detail})
                        check(label + f'/par{par}/unchanged', worker.rpc('getbestblockhash') == tip and
                              worker.rpc('gettxout', *asset) is not None and worker.rpc('gettxout', *funding) is not None, tip)
                    source.rpc('invalidateblock', restriction_block)
                    # The disconnected restriction can re-enter mempool; block-context
                    # behavior is tested again after a confirmed inverse transition.
                    check(label + '/restriction_disconnected', source.rpc('getbestblockhash') ==
                          source.rpc('getblockheader', restriction_block)['previousblockhash'], restriction_block)
                    source.rpc('reconsiderblock', restriction_block)
                    check(label + '/restriction_restored', source.rpc('getbestblockhash') == restriction_block, restriction_block)
                    confirm(source.rpc(*undo))
                    result = source.rpc('testmempoolaccept', [wire.hex()])[0]
                    check(label + '/after_allowed', result.get('allowed') == 1, result)
                    source.rpc('sendrawtransaction', wire.hex())
                    block = mine()
                    sync()
                    for par, worker in validators:
                        check(label + f'/par{par}/valid_control', worker.rpc('getbestblockhash') == block and
                              worker.rpc('getrawtransaction', txid, True).get('confirmations') == 1 and
                              worker.rpc('gettxout', *asset) is None, txid)
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
