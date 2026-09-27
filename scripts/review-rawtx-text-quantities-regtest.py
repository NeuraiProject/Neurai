#!/usr/bin/env python3
"""createrawtransaction: asset quantities as JSON text build the same transaction.

Every createrawtransaction operation that takes an asset quantity (issue,
reissue, transfer, transferwithmessage, issue_restricted, reissue_restricted,
issue_qualifier, and change_quantity in sub-qualifiers and tag/untag_addresses)
is built twice, with the quantity as an exact JSON number and as decimal text;
the two raw transactions must be byte-identical. Invalid text and values that
are neither number nor text are still refused.

The request is written by hand and the reply read with Decimal: a JSON number
such as 20999999999.99999999 does not survive a float on either side.

Run inside the build Docker: python3 scripts/review-rawtx-text-quantities-regtest.py
"""
import argparse
import base64
from decimal import Decimal
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location('introspection_review', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

QTY = '@@QTY@@'  # placeholder replaced by the raw JSON token of the quantity


def call(node, method, params_json):
    """JSON-RPC with the params already serialized; the reply keeps exact decimals."""
    payload = '{"jsonrpc":"1.0","id":"text-qty","method":%s,"params":%s}' % (json.dumps(method), params_json)
    auth = base64.b64encode(b'review:disposable-regtest').decode()
    request = urllib.request.Request('http://127.0.0.1:' + str(node.port), payload.encode(),
                                     {'Authorization': 'Basic ' + auth})
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return json.loads(response.read(), parse_float=Decimal)


def build(node, outputs, token):
    """createrawtransaction with the quantity placeholder replaced by token."""
    params = json.dumps([[], [outputs]]).replace(json.dumps(QTY), token)
    return call(node, 'createrawtransaction', params)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='rawtx-text-quantities-'))
    report = {'directory': str(directory), 'binary_sha256': h.digest_file(args.bindir / 'neuraid'), 'results': []}
    node = h.Node(args.bindir, directory / 'node', ['-bypassdownload=1'])

    def check(label, ok, observed=None):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': str(observed)})
        print(('PASS ' if ok else 'FAIL ') + label + ('' if ok else f'  -> {observed}'), flush=True)

    try:
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 200, miner)
        holder = node.rpc('getnewaddress')
        other = node.rpc('getnewaddress')

        def mine():
            node.rpc('generatetoaddress', 1, miner)

        # Existing assets for the operations that refer to one. The reissued
        # ones are integral: the raw reissue operations leave the unit field
        # at 0, which rejects reissuing any asset issued with decimals.
        issued = node.rpc('issue', 'TEXTQTY', 1000, holder, holder, 0, True)[0]
        node.rpc('issue', 'TEXTROOT', 1000, holder, holder, 8, True)
        node.rpc('issuequalifierasset', '#TEXTTAG', 1, holder, holder)
        mine()
        node.rpc('addtagtoaddress', '#TEXTTAG', holder, holder)
        mine()
        node.rpc('issuerestrictedasset', '$TEXTQTY', 1000, '#TEXTTAG', holder, holder, 0, True)
        mine()

        expire = int(time.time()) + 86400
        cases = [
            ('issue/integral', {holder: {'issue': {'asset_name': 'TEXTNEW', 'asset_quantity': QTY, 'units': 0,
                                                   'reissuable': 1, 'has_ipfs': 0}}}, '1000'),
            ('issue/units2', {holder: {'issue': {'asset_name': 'TEXTNEW', 'asset_quantity': QTY, 'units': 2,
                                                 'reissuable': 1, 'has_ipfs': 0}}}, '1000.5'),
            ('issue/max-8-decimals', {holder: {'issue': {'asset_name': 'TEXTNEW', 'asset_quantity': QTY, 'units': 8,
                                                         'reissuable': 1, 'has_ipfs': 0}}}, '20999999999.99999999'),
            ('reissue/integral', {holder: {'reissue': {'asset_name': 'TEXTQTY', 'asset_quantity': QTY}}}, '1000'),
            ('reissue/large', {holder: {'reissue': {'asset_name': 'TEXTQTY', 'asset_quantity': QTY}}}, '20000000000'),
            ('transfer/integral', {other: {'transfer': {'TEXTQTY': QTY}}}, '5'),
            ('transfer/max-8-decimals', {other: {'transfer': {'TEXTQTY': QTY}}}, '20999999999.99999999'),
            ('transferwithmessage', {other: {'transferwithmessage': {'TEXTQTY': QTY, 'message': issued,
                                                                      'expire_time': expire}}}, '0.12345678'),
            ('issue_restricted/integral', {holder: {'issue_restricted': {
                'asset_name': '$TEXTROOT', 'asset_quantity': QTY, 'verifier_string': '#TEXTTAG',
                'units': 0, 'reissuable': 1, 'has_ipfs': 0}}}, '1000'),
            ('issue_restricted/max-8-decimals', {holder: {'issue_restricted': {
                'asset_name': '$TEXTROOT', 'asset_quantity': QTY, 'verifier_string': '#TEXTTAG',
                'units': 8, 'reissuable': 1, 'has_ipfs': 0}}}, '20999999999.99999999'),
            ('reissue_restricted', {holder: {'reissue_restricted': {'asset_name': '$TEXTQTY',
                                                                   'asset_quantity': QTY}}}, '2500'),
            ('issue_qualifier', {holder: {'issue_qualifier': {'asset_name': '#TEXTNEW', 'asset_quantity': QTY,
                                                              'has_ipfs': 0}}}, '5'),
            ('issue_qualifier/sub-change_quantity', {holder: {'issue_qualifier': {
                'asset_name': '#TEXTTAG/#SUB', 'asset_quantity': 1, 'has_ipfs': 0, 'change_quantity': QTY}}}, '1'),
            ('tag_addresses/change_quantity', {holder: {'tag_addresses': {
                'qualifier': '#TEXTTAG', 'addresses': [other], 'change_quantity': QTY}}}, '1'),
            ('untag_addresses/change_quantity', {holder: {'untag_addresses': {
                'qualifier': '#TEXTTAG', 'addresses': [other], 'change_quantity': QTY}}}, '1'),
        ]
        for label, outputs, value in cases:
            as_number = build(node, outputs, value)
            as_text = build(node, outputs, json.dumps(value))
            check(label + '/number accepted', as_number['error'] is None, as_number['error'])
            check(label + '/text builds the same transaction',
                  as_text['error'] is None and as_text['result'] == as_number['result'], as_text['error'])

        # The exact quantity reaches the transaction.
        raw = build(node, cases[2][1], json.dumps('20999999999.99999999'))['result']
        amounts = None
        if raw:
            decoded = call(node, 'decoderawtransaction', json.dumps([raw]))['result']
            amounts = [o['scriptPubKey']['asset']['amount'] for o in decoded['vout']
                       if o['scriptPubKey'].get('asset', {}).get('name') == 'TEXTNEW']
        check('issue/text quantity kept exactly', amounts == [Decimal('20999999999.99999999')], amounts)

        refused = [
            ('issue/abc', cases[0][1], '"abc"', 'Invalid amount'),
            ('issue/9-decimals', cases[2][1], '"1.123456789"', 'Invalid amount'),
            ('issue/boolean', cases[0][1], 'true', 'missing asset data for key: asset_quantity'),
            ('issue/null', cases[0][1], 'null', 'missing asset data for key: asset_quantity'),
            ('transfer/abc', cases[5][1], '"abc"', 'Invalid amount'),
            ('transfer/boolean', cases[5][1], 'true', 'missing or invalid quantity'),
            ('tag_addresses/abc', cases[13][1], '"abc"', 'Invalid amount'),
            ('tag_addresses/boolean', cases[13][1], 'true', 'change_amount must be a positive number'),
        ]
        for label, outputs, token, fragment in refused:
            error = build(node, outputs, token)['error']
            check(label + ' refused', error is not None and fragment in error.get('message', ''), error)
    except Exception as error:
        report['error'] = repr(error)
        print('ERROR', repr(error), flush=True)
    finally:
        node.close()
        passed = sum(r['passed'] for r in report['results'])
        failed = len(report['results']) - passed + int('error' in report)
        report.update(passed=passed, failed=failed)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{passed} passed, {failed} failed; report: {directory}/report.json', flush=True)
    return int(failed != 0)


if __name__ == '__main__':
    raise SystemExit(main())
