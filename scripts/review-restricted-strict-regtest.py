#!/usr/bin/env python3
"""Strict PQ/ECDSA destinations: qualifier tags, restricted transfers and freezes."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('asset_helpers', Path(__file__).with_name('review-asset-fields-regtest.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='restricted-strict-'))
    report = {'results': [], 'binary_sha256': m.digest_file(args.bindir / 'neuraid'),
              'source_sha256': m.digest_file(Path(__file__))}
    nodes = []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = m.Node(args.bindir, directory / 'source', ['-addresstype=pq', '-acceptnonstdtxn=0', '-par=1', '-bypassdownload=1', '-assetindex=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)
        addresses = {v: source.rpc('getnewaddress', '', 'pq' if v == 2 else 'ecdsa') for v in (2, 3)}
        validators = []
        for par in (1, 2):
            node = m.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0', '-assetindex=1'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))

        def sync():
            for par, node in validators:
                for height in range(node.rpc('getblockcount') + 1, source.rpc('getblockcount') + 1):
                    result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                    if result is not None:
                        raise RuntimeError(f'par{par}/sync/{height}: {result}')

        def confirm(label, value):
            txid = value[0] if isinstance(value, list) else value
            source.rpc('generatetoaddress', 1, miner)
            tx = source.rpc('getrawtransaction', txid, True)
            check(label + '/confirmed', tx['confirmations'] == 1, txid)
            sync()
            for par, node in validators:
                check(label + f'/par{par}', node.rpc('getbestblockhash') == source.rpc('getbestblockhash'), txid)
            return tx

        confirm('qualifier', source.rpc('issuequalifierasset', '#STRICTTAG', 1, addresses[2], addresses[2]))
        confirm('root', source.rpc('issue', 'STRICTROOT', 5, addresses[3], addresses[3]))
        for version, address in addresses.items():
            confirm(f'tag/v{version}', source.rpc('addtagtoaddress', '#STRICTTAG', address, addresses[2]))
            tagged = source.rpc('checkaddresstag', address, '#STRICTTAG')
            check(f'tag/v{version}/state', tagged is True, tagged)
        confirm('restricted/issue', source.rpc('issuerestrictedasset', '$STRICTROOT', 5, '#STRICTTAG', addresses[2], addresses[3]))
        confirm('restricted/transfer_v3', source.rpc('transfer', '$STRICTROOT', 5, addresses[3]))
        confirm('freeze/v3', source.rpc('freezeaddress', '$STRICTROOT', addresses[3], addresses[3]))
        try:
            source.rpc('transfer', '$STRICTROOT', 5, addresses[2])
        except m.RPCError as error:
            check('freeze/transfer_rejected', source.rpc('checkaddressrestriction', addresses[3], '$STRICTROOT') is True and str(error) == "Wallet doesn't have asset: $STRICTROOT", str(error))
        else:
            check('freeze/transfer_rejected', False, 'accepted')
        confirm('unfreeze/v3', source.rpc('unfreezeaddress', '$STRICTROOT', addresses[3], addresses[3]))
        confirm('restricted/transfer_v2', source.rpc('transfer', '$STRICTROOT', 5, addresses[2]))
        confirm('untag/v3', source.rpc('removetagfromaddress', '#STRICTTAG', addresses[3], addresses[2]))
        tagged = source.rpc('checkaddresstag', addresses[3], '#STRICTTAG')
        check('untag/v3/state', tagged is False, tagged)
        try:
            source.rpc('transfer', '$STRICTROOT', 5, addresses[3])
        except m.RPCError as error:
            check('untag/transfer_rejected', 'verifier' in str(error).lower() or 'qualifier' in str(error).lower(), str(error))
        else:
            check('untag/transfer_rejected', False, 'accepted')
        confirm('retag/v3', source.rpc('addtagtoaddress', '#STRICTTAG', addresses[3], addresses[2]))
        confirm('restricted/transfer_v3_again', source.rpc('transfer', '$STRICTROOT', 5, addresses[3]))
        for par, node in validators:
            for version, address in addresses.items():
                tagged = node.rpc('checkaddresstag', address, '#STRICTTAG')
                check(f'par{par}/v{version}/tag_state', tagged is True, tagged)
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
