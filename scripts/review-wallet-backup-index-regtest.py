#!/usr/bin/env python3
"""Disposable regtest: backup/restore native and P2SH AuthScript assets and indexes."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('helpers', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--import-wallet', action='store_true', help='Restore keys and redeem scripts into a fresh wallet instead of backupwallet')
    args = parser.parse_args()
    bindir = Path('/root/Neurai/src')
    root = Path(tempfile.mkdtemp(prefix='wallet-backup-index-'))
    report = {'mode': 'import' if args.import_wallet else 'backup', 'binary_sha256': h.digest_file(bindir / 'neuraid'),
              'script_sha256': h.digest_file(Path(__file__)), 'results': []}
    nodes = []

    def check(label, ok):
        report['results'].append({'case': label, 'passed': bool(ok)})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label)

    def start(name):
        node = h.Node(bindir, root / name, ['-pqwallet=1', '-addressindex=1', '-assetindex=1', '-bypassdownload=1'])
        nodes.append(node)
        node.ready()
        return node

    def sync(node, source):
        for height in range(node.rpc('getblockcount') + 1, source.rpc('getblockcount') + 1):
            result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
            if result is not None:
                raise RuntimeError('block replay: ' + str(result))

    def snapshot(node, address):
        return sorted((u['txid'], u['outputIndex'], u['assetName'], u['satoshis'])
                      for kind in ('XNA', '*')
                      for u in node.rpc('getaddressutxos', {'addresses': [address], 'assetName': kind}))

    try:
        source = start('source')
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)
        destinations = []
        import_data = []
        for version, family in ((1, None), (2, 'pq'), (3, 'ecdsa')):
            address = source.rpc('getnewaddress', *(['', family] if family else []))
            redeem = source.rpc('validateaddress', address)['scriptPubKey']
            wrapped = source.rpc('decodescript', redeem)['p2sh']
            source.rpc('importaddress', redeem, '', False, True)
            import_data.append((address, redeem))
            for form, target in (('native', address), ('p2sh', wrapped)):
                label = f'v{version}/{form}'
                asset = f'BACKUP{version}{form.upper()}'
                funding = source.rpc('sendtoaddress', target, 10)
                funded = source.rpc('getrawtransaction', funding, True)
                output = next(o['n'] for o in funded['vout'] if target in o['scriptPubKey'].get('addresses', []))
                source.rpc('lockunspent', False, [{'txid': funding, 'vout': output}])
                if form == 'native':
                    source.rpc('issue', asset, 5, target, miner)
                source.rpc('generatetoaddress', 1, miner)
                check(label + '/owned', source.rpc('validateaddress', target).get('ismine'))
                records = snapshot(source, target)
                check(label + '/index', (form == 'p2sh' or any(r[2:] == (asset, 500000000) for r in records))
                      and any(r[2:] == ('XNA', 1000000000) for r in records))
                destinations.append((label, target, asset, records))
        if args.import_wallet:
            source.rpc('sendtoaddress', destinations[0][1], 50)
            source.rpc('generatetoaddress', 1, miner)
        destinations = [(label, target, asset, snapshot(source, target))
                        for label, target, asset, _ in destinations]
        backup = root / 'backup.dat'
        source.rpc('backupwallet', str(backup))
        restored = start('restored')
        if args.import_wallet:
            for address, redeem in import_data:
                secret = source.rpc('dumpprivkey', address)
                restored.rpc('importprivkey', secret, '', False)
                del secret
                restored.rpc('importaddress', redeem, '', False, True)
        else:
            restored.close()
            shutil.copyfile(backup, restored.directory / 'regtest/wallet.dat')
            restored.log = (restored.directory / 'process.log').open('a')
            restored.proc = subprocess.Popen(restored.proc.args, stdout=restored.log, stderr=subprocess.STDOUT)
            restored.ready()
        sync(restored, source)
        reserved = {}
        for _, target, _, _ in destinations:
            coins = restored.rpc('listunspent', 1, 999999, [target])
            reserved[target] = next(c for c in coins if c['amount'] == 10)
            restored.rpc('lockunspent', False, [{'txid': c['txid'], 'vout': c['vout']} for c in coins if c['amount'] == 10])
        for label, target, asset, records in destinations:
            check(label + '/restored_owned', restored.rpc('validateaddress', target).get('ismine'))
            check(label + '/replayed_index', snapshot(restored, target) == records)
            coin = reserved[target]
            raw = restored.rpc('createrawtransaction', [{'txid': coin['txid'], 'vout': coin['vout']}], {miner: 9.9})
            signed = restored.rpc('signrawtransaction', raw)
            check(label + '/restored_coin_signature', signed['complete'])
            txid = restored.rpc('sendrawtransaction', signed['hex'])
            restored.rpc('generatetoaddress', 1, miner)
            check(label + '/restored_coin_mined', restored.rpc('getrawtransaction', txid, True)['confirmations'] == 1)
            if label.endswith('p2sh'):
                continue  # Asset suffixes support P2PKH/native AuthScript, not P2SH.
            transferred = restored.rpc('transferfromaddress', asset, target, 1, miner, '', 0, '', target)
            block = restored.rpc('generatetoaddress', 1, miner)[0]
            check(label + '/restored_asset_mined', all(restored.rpc('getrawtransaction', tx, True)['confirmations'] == 1 for tx in transferred))
            after = snapshot(restored, target)
            check(label + '/asset_index_spent', sum(r[3] for r in after if r[2] == asset) == 400000000)
            restored.rpc('invalidateblock', block)
            check(label + '/asset_index_disconnect', sum(r[3] for r in snapshot(restored, target) if r[2] == asset) == 500000000)
            restored.rpc('reconsiderblock', block)
            check(label + '/asset_index_reconnect', snapshot(restored, target) == after)
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        for node in reversed(nodes):
            node.close()
        report['passed'] = sum(x['passed'] for x in report['results'])
        report['failed'] = sum(not x['passed'] for x in report['results']) + int('error' in report)
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', root / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
