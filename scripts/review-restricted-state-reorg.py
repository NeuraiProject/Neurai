#!/usr/bin/env python3
"""Disconnect a verifier relaxation or unfreeze beneath restricted transfers."""
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
    parser.add_argument('--coin-only-child', action='store_true', help='Reproduce the original ordinary-coin descendant')
    parser.add_argument('--event', choices=['global', 'address', 'verifier'], required=True)
    parser.add_argument('--competing', action='store_true')
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='restricted-state-reorg-'))
    report = {'results': [], 'target': args.target, 'event': args.event, 'competing': args.competing, 'coin_only_child': args.coin_only_child,
              'binary_sha256': m.digest_file(args.bindir / 'neuraid'),
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
        if args.event == 'global':
            confirm('freeze', source.rpc('freezerestrictedasset', '$REORGROOT', holder))
            confirm('unfreeze', source.rpc('unfreezerestrictedasset', '$REORGROOT', holder))
        elif args.event == 'address':
            confirm('freeze', source.rpc('freezeaddress', '$REORGROOT', holder, holder))
            confirm('unfreeze', source.rpc('unfreezeaddress', '$REORGROOT', holder, holder))
        else:
            confirm('tighten', source.rpc('reissuerestrictedasset', '$REORGROOT', 0, holder, True, '!#REORGTAG', holder))
            confirm('relax', source.rpc('reissuerestrictedasset', '$REORGROOT', 0, holder, True, '#REORGTAG', holder))
        tagblock = source.rpc('getbestblockhash')
        tagheight = source.rpc('getblockcount')
        # Rewinding this unrelated block must preserve a valid package, including
        # a restricted child whose asset input exists only in the mempool.
        unrelated = source.rpc('generatetoaddress', 1, miner)[0]
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
        asset_change = next(o for o in decoded['vout'] if b'$REORGROOT'.hex() in o['scriptPubKey']['hex'])
        legacy = 'tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy'  # Legacy output; disposable regtest coins.
        child_inputs = [{'txid': parent, 'vout': change['n']}]
        child_outputs = [{legacy: round(change['value'] - 1, 8)}]
        if not args.coin_only_child:
            child_inputs.append({'txid': parent, 'vout': asset_change['n']})
            child_outputs.append({holder: {'transfer': {'$REORGROOT': 5}}})
        rawchild = source.rpc('createrawtransaction', child_inputs, child_outputs, 0)
        childsig = source.rpc('signrawtransaction', rawchild)
        check('child_signed', childsig['complete'], childsig.get('errors'))
        child = source.rpc('sendrawtransaction', childsig['hex'])
        check('both_pending', all(t in source.rpc('getrawmempool') for t in (parent, child)), [parent, child])
        source.rpc('invalidateblock', unrelated)
        check('unrelated_reorg_keeps_tag', source.rpc('checkaddresstag', target, '#REORGTAG') is True, target)
        pending = source.rpc('getrawmempool')
        check('unrelated_reorg_keeps_parent', parent in pending, pending)
        check('unrelated_reorg_keeps_child', child in pending, pending)
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('valid_package_minable', {parent, child}.issubset({t['txid'] for t in template['transactions']}),
              [t['txid'] for t in template['transactions']])
        fork = []
        if args.competing:
            rival = m.Node(args.bindir, directory / 'rival', ['-disablewallet=1', '-assumevalid=0', '-bypassdownload=1'])
            nodes.append(rival)
            rival.ready()
            for height in range(1, tagheight):
                result = rival.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError(f'rival/{height}: {result}')
            fork = rival.rpc('generatetoaddress', 3, legacy)
            for block in fork:
                result = source.rpc('submitblock', rival.rpc('getblock', block, False))
                if result not in (None, 'inconclusive'):
                    raise RuntimeError(f'competing/{block}: {result}')
            check('competing_tip_selected', source.rpc('getbestblockhash') == fork[-1], source.rpc('getbestblockhash'))
        else:
            source.rpc('invalidateblock', tagblock)
            check('height_rewound', source.rpc('getblockcount') == tagheight - 1, source.rpc('getblockcount'))
        check('tag_still_present', source.rpc('checkaddresstag', target, '#REORGTAG') is True, target)
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
        pending_after_template = source.rpc('getrawmempool')
        check('package_stays_absent', parent not in pending_after_template and child not in pending_after_template,
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
        reason = {'global': 'bad-txns-transfer-restricted-asset-that-is-globally-restricted',
                  'address': 'bad-txns-restricted-asset-transfer-from-frozen-address',
                  'verifier': 'bad-txns-null-verifier-address-failed-verification'}[args.event]
        check('fresh_node_rejects_parent', not accepted.get('allowed') and reason in log, accepted)
        if fork:
            source.rpc('invalidateblock', fork[0])
        source.rpc('reconsiderblock', tagblock)
        check('state_block_restored', source.rpc('getblockhash', tagheight) == tagblock, source.rpc('getbestblockhash'))
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('mining_restored', True, [t['txid'] for t in template['transactions']])
        # Explicitly re-admit the evicted package after restoring the tag.
        for txid, rawhex in ((parent, signed['hex']), (child, childsig['hex'])):
            if txid not in source.rpc('getrawmempool'):
                check('readmit/' + txid, source.rpc('sendrawtransaction', rawhex) == txid, txid)
        source.rpc('generatetoaddress', 1, miner)
        check('both_mined_after_restore', all(source.rpc('getrawtransaction', txid, True).get('confirmations', 0) == 1
                                            for txid in (parent, child)), [parent, child])
        report['parent'] = parent
        report['child'] = child
        report['state_block'] = tagblock
        report['competing_blocks'] = fork
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
