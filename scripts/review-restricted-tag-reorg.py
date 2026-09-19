#!/usr/bin/env python3
"""A confirmed qualifier tag is disconnected beneath pending restricted transfers."""
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
    parser.add_argument('--target', choices=['pq', 'ecdsa', 'authscript'], default='ecdsa')
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='restricted-tag-reorg-'))
    report = {'results': [], 'target': args.target, 'binary_sha256': m.digest_file(args.bindir / 'neuraid'),
              'source_sha256': m.digest_file(Path(__file__))}
    nodes = []

    def check(label, passed, observed, stop=True):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed and stop:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = m.Node(args.bindir, directory / 'source', ['-pqwallet=1', '-acceptnonstdtxn=0', '-bypassdownload=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)
        holder = source.rpc('getnewaddress', '', 'pq' if args.target == 'ecdsa' else 'ecdsa')
        target = source.rpc('getnewaddress') if args.target == 'authscript' else source.rpc('getnewaddress', '', args.target)

        def confirm(label, value):
            txid = value[0] if isinstance(value, list) else value
            source.rpc('generatetoaddress', 1, miner)
            tx = source.rpc('getrawtransaction', txid, True)
            check(label, tx['confirmations'] == 1, txid)
            return tx

        confirm('qualifier', source.rpc('issuequalifierasset', '#REORGTAG', 1, holder, holder))
        confirm('root', source.rpc('issue', 'REORGROOT', 5, holder, holder))
        confirm('holder_tag', source.rpc('addtagtoaddress', '#REORGTAG', holder, holder))
        issued = confirm('restricted', source.rpc('issuerestrictedasset', '$REORGROOT', 5, '#REORGTAG', holder, holder))
        prefix = source.rpc('validateaddress', holder)['scriptPubKey']
        asset = next(o for o in issued['vout'] if o['scriptPubKey']['hex'].startswith(prefix) and
                     b'$REORGROOT'.hex() in o['scriptPubKey']['hex'])
        # This final block changes eligibility, not the UTXOs we will spend.
        confirm('target_tag', source.rpc('addtagtoaddress', '#REORGTAG', target, holder))
        tagblock = source.rpc('getbestblockhash')
        tagheight = source.rpc('getblockcount')
        coin = next(o for o in source.rpc('listunspent', 100) if o['spendable'] and o['amount'] > 3)
        raw = source.rpc('createrawtransaction', [{'txid': issued['txid'], 'vout': asset['n']},
                         {'txid': coin['txid'], 'vout': coin['vout']}],
                         [{miner: round(coin['amount'] - 1, 8)}, {target: {'transfer': {'$REORGROOT': 5}}}], 0)
        signed = source.rpc('signrawtransaction', raw)
        check('parent_signed', signed['complete'], signed.get('errors'))
        decoded = source.rpc('decoderawtransaction', signed['hex'])
        check('parent_final', decoded['locktime'] == 0 and all(v['sequence'] == 0xffffffff for v in decoded['vin']), decoded['locktime'])
        parent = source.rpc('sendrawtransaction', signed['hex'])
        change = next(o for o in decoded['vout'] if o['value'] > 0)
        legacy = 'tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy'  # Legacy output; disposable regtest coins.
        rawchild = source.rpc('createrawtransaction', [{'txid': parent, 'vout': change['n']}],
                             {legacy: round(change['value'] - 1, 8)}, 0)
        childsig = source.rpc('signrawtransaction', rawchild)
        check('child_signed', childsig['complete'], childsig.get('errors'))
        child = source.rpc('sendrawtransaction', childsig['hex'])
        check('both_pending', all(t in source.rpc('getrawmempool') for t in (parent, child)), [parent, child])
        source.rpc('invalidateblock', tagblock)
        check('height_rewound', source.rpc('getblockcount') == tagheight - 1, source.rpc('getblockcount'))
        check('tag_disconnected', source.rpc('checkaddresstag', target, '#REORGTAG') is False, target)
        check('funding_still_confirmed', source.rpc('gettxout', issued['txid'], asset['n'], False) is not None and
              source.rpc('gettxout', coin['txid'], coin['vout'], False) is not None, [issued['txid'], coin['txid']])
        pending = source.rpc('getrawmempool')
        check('parent_evicted', parent not in pending, pending, stop=False)
        check('child_evicted', child not in pending, pending, stop=False)
        try:
            template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        except m.RPCError as error:
            check('mining_available', False, {'code': error.code, 'message': str(error)}, stop=False)
        else:
            check('mining_available', True, [t['txid'] for t in template['transactions']])
        # The miner has a fallback that may remove the bad package after failing.
        pending_after_template = source.rpc('getrawmempool')
        check('miner_fallback_removed_package', parent not in pending_after_template and child not in pending_after_template,
              pending_after_template, stop=False)
        try:
            retry_template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        except m.RPCError as error:
            check('second_template_available', False, {'code': error.code, 'message': str(error)}, stop=False)
        else:
            check('second_template_available', True, [t['txid'] for t in retry_template['transactions']])
        # Independent node at the same confirmed tip, with an empty mempool.
        verifier = m.Node(args.bindir, directory / 'verifier', ['-disablewallet=1', '-assumevalid=0', '-bypassdownload=1'])
        nodes.append(verifier)
        verifier.ready()
        for height in range(1, tagheight):
            result = verifier.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
            if result is not None:
                raise RuntimeError(f'verifier/{height}: {result}')
        accepted = verifier.rpc('testmempoolaccept', [signed['hex']])[0]
        log = (verifier.directory / 'regtest/debug.log').read_text()
        check('fresh_node_rejects_parent', not accepted.get('allowed') and
              'bad-txns-null-verifier-address-failed-verification' in log, accepted)
        source.rpc('reconsiderblock', tagblock)
        check('tag_restored', source.rpc('checkaddresstag', target, '#REORGTAG') is True, target)
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('mining_restored', True, [t['txid'] for t in template['transactions']])
        # The miner fallback removed this package; explicitly re-admit after restoring the tag.
        for txid, rawhex in ((parent, signed['hex']), (child, childsig['hex'])):
            if txid not in source.rpc('getrawmempool'):
                check('readmit/' + txid, source.rpc('sendrawtransaction', rawhex) == txid, txid)
        source.rpc('generatetoaddress', 1, miner)
        check('both_mined_after_restore', all(source.rpc('getrawtransaction', txid, True).get('confirmations', 0) == 1
                                            for txid in (parent, child)), [parent, child])
        report['parent'] = parent
        report['child'] = child
        report['tag_block'] = tagblock
        report['parent_hex'] = signed['hex']
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
