#!/usr/bin/env python3
"""Regression check: failed importaddress must not silently persist a new owned P2SH script.
Checks successful owned imports, watch-only imports, labels, retries and restart persistence.
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
    directory = Path(tempfile.mkdtemp(prefix='p2sh-import-atomicity-'))
    report = {'results': [], 'observations': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__), Path(__file__).with_name('review-introspection-regtest.py'))}}
    node = None

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)

    try:
        node = h.Node(args.bindir, directory / 'node', ['-pqwallet=1'])
        node.ready()
        for family in ('pq', 'ecdsa'):
            native = node.rpc('getnewaddress', '', family)
            redeem = node.rpc('validateaddress', native)['scriptPubKey']
            wrapped = node.rpc('decodescript', redeem)['p2sh']
            before = node.rpc('validateaddress', wrapped)
            check(family + '/initially_unknown', before.get('ismine') is False, before)
            rpc_error = None
            try:
                node.rpc('importaddress', redeem, 'review-atomicity', False, True)
            except h.RPCError as error:
                rpc_error = {'code': error.code, 'message': str(error)}
            after = node.rpc('validateaddress', wrapped)
            report['observations'].append({'family': family, 'address': wrapped, 'before': before, 'error': rpc_error, 'after': after})
            check(family + '/import_succeeds', rpc_error is None, rpc_error)
            check(family + '/owned_not_watch_only', after.get('ismine') is True and
                  not after.get('iswatchonly', False), after)
            check(family + '/label_set', after.get('account') == 'review-atomicity', after.get('account'))
            node.rpc('importaddress', redeem, 'review-retry', False, True)
            check(family + '/idempotent_label_update', node.rpc('validateaddress', wrapped).get('account') == 'review-retry', wrapped)
            native_before = node.rpc('validateaddress', native)
            rejected = None
            try:
                node.rpc('importaddress', native, 'must-not-change', False)
            except h.RPCError as error:
                rejected = error.code
            native_after = node.rpc('validateaddress', native)
            check(family + '/native_owned_still_rejected', rejected == -4 and
                  native_after == native_before, rejected)
        foreign_redeem = '76a914' + '42' * 20 + '88ac'
        foreign_address = node.rpc('decodescript', foreign_redeem)['p2sh']
        node.rpc('importaddress', foreign_redeem, 'foreign-watch', False, True)
        foreign = node.rpc('validateaddress', foreign_address)
        check('foreign/watch_only', foreign.get('ismine') is False and foreign.get('iswatchonly') is True and
              foreign.get('account') == 'foreign-watch', foreign)
        node.rpc('importaddress', foreign_redeem, 'foreign-retry', False, True)
        check('foreign/reimport', node.rpc('validateaddress', foreign_address).get('account') == 'foreign-retry', foreign_address)
        command = node.proc.args
        node.close()
        node.log = (node.directory / 'process.log').open('a')
        node.proc = subprocess.Popen(command, stdout=node.log, stderr=subprocess.STDOUT)
        node.ready()
        for observation in report['observations']:
            restored = node.rpc('validateaddress', observation['address'])
            observation['after_restart'] = restored
            check(observation['family'] + '/owned_persists', restored.get('ismine') is True and
                  not restored.get('iswatchonly', False) and restored.get('account') == 'review-retry', restored)
        foreign = node.rpc('validateaddress', foreign_address)
        check('foreign/watch_only_persists', foreign.get('ismine') is False and foreign.get('iswatchonly') is True and
              foreign.get('account') == 'foreign-retry', foreign)
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        if node is not None:
            node.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
