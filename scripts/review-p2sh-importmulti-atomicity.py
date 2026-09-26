#!/usr/bin/env python3
"""Regression check: failed importmulti must not persist an owned P2SH redeem script.
Checks owned imports, watch-only, labels, mixed batches and prevalidation before writes.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('import_review_helpers', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='p2sh-importmulti-'))
    report = {'results': [], 'observations': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__), Path(__file__).with_name('review-introspection-regtest.py'))}}
    node = None
    donor = None

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)

    try:
        node = h.Node(args.bindir, directory / 'node', ['-addresstype=pq'])
        node.ready()
        for family in ('pq', 'ecdsa'):
            native = node.rpc('getnewaddress', '', family)
            redeem = node.rpc('validateaddress', native)['scriptPubKey']
            wrapped = node.rpc('decodescript', redeem)['p2sh']
            before = node.rpc('validateaddress', wrapped)
            check(family + '/initially_unknown', before.get('ismine') is False, before)
            result = node.rpc('importmulti', [{
                'scriptPubKey': {'address': wrapped}, 'redeemscript': redeem,
                'timestamp': 'now', 'label': 'review-multi',
            }], {'rescan': False})
            after = node.rpc('validateaddress', wrapped)
            rpc_error = result[0].get('error')
            report['observations'].append({'family': family, 'address': wrapped,
                'before': before, 'result': result, 'error': rpc_error, 'after': after})
            check(family + '/import_succeeds', result[0].get('success') is True, result)
            check(family + '/owned_and_labelled', after.get('ismine') is True and
                  not after.get('iswatchonly', False) and after.get('account') == 'review-multi', after)
        def request(redeem, address=None, label='batch', **extra):
            address = address or node.rpc('decodescript', redeem)['p2sh']
            return {'scriptPubKey': {'address': address}, 'redeemscript': redeem,
                    'timestamp': 'now', 'label': label, **extra}
        owned = []
        for observation in report['observations']:
            redeem = node.rpc('validateaddress', observation['address'])['hex']
            owned.append(request(redeem, observation['address'], 'retry-label'))
        foreign = '76a914' + '42' * 20 + '88ac'
        foreign_address = node.rpc('decodescript', foreign)['p2sh']
        # Successful entries on both sides of an invalid one must still be processed.
        invalid = request('not-hex', report['observations'][0]['address'])
        batch = node.rpc('importmulti', [owned[0], invalid, owned[1], request(foreign, label='foreign')], {'rescan': False})
        check('mixed/results', [x.get('success') for x in batch] == [True, False, True, True] and
              batch[1].get('error', {}).get('code') == -5, batch)
        for observation in report['observations']:
            check(observation['family'] + '/reimport_label', node.rpc('validateaddress', observation['address']).get('account') == 'retry-label', observation['address'])
        watched = node.rpc('validateaddress', foreign_address)
        check('foreign/watch_only', watched.get('ismine') is False and watched.get('iswatchonly') is True and
              watched.get('account') == 'foreign', watched)
        # Known-key and invalid-key failures must not register previously unknown P2SH outputs.
        fresh = node.rpc('getnewaddress', '', 'ecdsa')
        redeem = node.rpc('validateaddress', fresh)['scriptPubKey']
        wrapped = node.rpc('decodescript', redeem)['p2sh']
        before = node.rpc('validateaddress', wrapped)
        known_key = node.rpc('dumpprivkey', fresh)
        result = node.rpc('importmulti', [request(redeem, keys=[known_key])], {'rescan': False})
        check('known_key/rejected_without_registration', result[0].get('success') is False and
              result[0].get('error', {}).get('code') == -5 and node.rpc('validateaddress', wrapped) == before, result)
        wrong = redeem[:-2] + ('00' if redeem[-2:] != '00' else '01')
        wrong_address = node.rpc('decodescript', wrong)['p2sh']
        wrong_before = node.rpc('validateaddress', wrong_address)
        result = node.rpc('importmulti', [request(wrong, wrapped)], {'rescan': False})
        check('mismatched_hash/no_registration', result[0].get('success') is False and
              result[0].get('error', {}).get('code') == -5 and node.rpc('validateaddress', wrapped) == before and
              node.rpc('validateaddress', wrong_address) == wrong_before, result)
        donor = h.Node(args.bindir, directory / 'donor')
        donor.ready()
        address = donor.rpc('getnewaddress')
        private = donor.rpc('dumpprivkey', address)
        redeem = donor.rpc('validateaddress', address)['scriptPubKey']
        wrapped_new = node.rpc('decodescript', redeem)['p2sh']
        new_before = node.rpc('validateaddress', wrapped_new)
        native_before = node.rpc('validateaddress', address)
        for name, keys in [('invalid_second_key', [private, 'not-a-private-key']), ('duplicate_key', [private, private])]:
            result = node.rpc('importmulti', [request(redeem, keys=keys)], {'rescan': False})
            check(name + '/no_partial_import', result[0].get('success') is False and
                  result[0].get('error', {}).get('code') == -5 and
                  node.rpc('validateaddress', wrapped_new) == new_before and
                  node.rpc('validateaddress', address) == native_before, result)
        result = node.rpc('importmulti', [request(redeem, label='new-key', keys=[private])], {'rescan': False})
        check('new_key/import_succeeds', result[0].get('success') is True and
              node.rpc('validateaddress', wrapped_new).get('ismine') is True, result)
        rejected_persistent = [(wrapped, before), (wrong_address, wrong_before)]
        command = node.proc.args
        node.close()
        node.log = (node.directory / 'process.log').open('a')
        node.proc = subprocess.Popen(command, stdout=node.log, stderr=subprocess.STDOUT)
        node.ready()
        for observation in report['observations']:
            restored = node.rpc('validateaddress', observation['address'])
            observation['after_restart'] = restored
            check(observation['family'] + '/owned_label_persists', restored.get('ismine') is True and
                  not restored.get('iswatchonly', False) and restored.get('account') == 'retry-label', restored)
        watched = node.rpc('validateaddress', foreign_address)
        check('foreign/watch_only_persists', watched.get('ismine') is False and watched.get('iswatchonly') is True and
              watched.get('account') == 'foreign', watched)
        for i, (address, state) in enumerate(rejected_persistent):
            check(f'rejected{i}/no_persisted_registration', node.rpc('validateaddress', address) == state, address)
        restored = node.rpc('validateaddress', wrapped_new)
        check('new_key/persists', restored.get('ismine') is True and restored.get('account') == 'new-key', restored)
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        if donor is not None:
            donor.close()
        if node is not None:
            node.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
