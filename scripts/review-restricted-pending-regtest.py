#!/usr/bin/env python3
"""Mine competing pending restricted transfers and state changes."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('helpers', Path(__file__).with_name('review-asset-fields-regtest.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--target', choices=['pq', 'ecdsa', 'authscript'], default='ecdsa')
    parser.add_argument('--checkmempool', type=int, choices=[0, 1], default=0)
    parser.add_argument('--event', choices=['tag', 'global', 'address', 'child-address', 'verifier'], default='tag')
    parser.add_argument('--asset-child', action='store_true')
    parser.add_argument('--confirm-parent', action='store_true')
    args = parser.parse_args()
    if args.event == 'child-address' and not args.asset_child:
        parser.error('--event child-address requires --asset-child')
    directory = Path(tempfile.mkdtemp(prefix='restricted-pending-'))
    report = {'results': [], 'target': args.target, 'checkmempool': args.checkmempool, 'event': args.event, 'asset_child': args.asset_child, 'confirm_parent': args.confirm_parent,
              'binary_sha256': m.digest_file(args.bindir / 'neuraid'),
              'source_sha256': m.digest_file(Path(__file__))}
    nodes = []

    def check(label, passed, observed, stop=True):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed and stop:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = m.Node(args.bindir, directory / 'source', ['-pqwallet=1', '-bypassdownload=1'])
        observer = m.Node(args.bindir, directory / 'observer', ['-disablewallet=1', '-bypassdownload=1', '-assumevalid=0', f'-checkmempool={args.checkmempool}'])
        nodes.extend([source, observer])
        source.ready()
        observer.ready()
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

        def sync():
            for height in range(observer.rpc('getblockcount') + 1, source.rpc('getblockcount') + 1):
                result = observer.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError(f'submit/{height}: {result}')

        confirm('qualifier', source.rpc('issuequalifierasset', '#CONNECTTAG', 1, holder, holder))
        confirm('other_qualifier', source.rpc('issuequalifierasset', '#KEEPTAG', 1, holder, holder))
        confirm('holder_other_tag', source.rpc('addtagtoaddress', '#KEEPTAG', holder, holder))
        confirm('root', source.rpc('issue', 'CONNECTROOT', 5, holder, holder))
        confirm('holder_tag', source.rpc('addtagtoaddress', '#CONNECTTAG', holder, holder))
        issued = confirm('restricted', source.rpc('issuerestrictedasset', '$CONNECTROOT', 5, '#CONNECTTAG', holder, holder))
        confirm('target_tag', source.rpc('addtagtoaddress', '#CONNECTTAG', target, holder))
        sync()
        prefix = source.rpc('validateaddress', holder)['scriptPubKey']
        asset = next(o for o in issued['vout'] if o['scriptPubKey']['hex'].startswith(prefix) and b'$CONNECTROOT'.hex() in o['scriptPubKey']['hex'])
        coin = next(o for o in source.rpc('listunspent', 100) if o['spendable'] and o['amount'] > 3)
        # Keep the funding unavailable to source's wallet so the revocation is
        # independent of the package pending exclusively on observer.
        source.rpc('lockunspent', False, [{'txid': coin['txid'], 'vout': coin['vout']}])
        raw = source.rpc('createrawtransaction', [{'txid': issued['txid'], 'vout': asset['n']}, {'txid': coin['txid'], 'vout': coin['vout']}],
                         [{miner: round(coin['amount'] - 1, 8)}, {target: {'transfer': {'$CONNECTROOT': 5}}}], 0)
        signed = source.rpc('signrawtransaction', raw)
        check('parent_signed', signed['complete'], signed.get('errors'))
        decoded = source.rpc('decoderawtransaction', signed['hex'])
        parent = observer.rpc('sendrawtransaction', signed['hex'])
        change = next(o for o in decoded['vout'] if o['value'] > 0)
        child_inputs = [{'txid': parent, 'vout': change['n']}]
        child_outputs = [{'tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy': round(change['value'] - 1, 8)}]
        prevouts = [change]
        if args.asset_child:
            asset_out = next(o for o in decoded['vout'] if b'$CONNECTROOT'.hex() in o['scriptPubKey']['hex'])
            child_inputs.append({'txid': parent, 'vout': asset_out['n']})
            child_outputs.append({holder: {'transfer': {'$CONNECTROOT': 5}}})
            prevouts.append(asset_out)
        rawchild = source.rpc('createrawtransaction', child_inputs, child_outputs, 0)
        childsig = source.rpc('signrawtransaction', rawchild, [{'txid': parent, 'vout': o['n'],
                            'scriptPubKey': o['scriptPubKey']['hex'], 'amount': o['value']} for o in prevouts])
        check('child_signed', childsig['complete'], childsig.get('errors'))
        child = observer.rpc('sendrawtransaction', childsig['hex'])
        check('both_pending', {parent, child}.issubset(set(observer.rpc('getrawmempool'))), [parent, child])
        source.rpc('generatetoaddress', 1, miner)
        sync()
        check('unrelated_block_preserves_package', {parent, child}.issubset(set(observer.rpc('getrawmempool'))), observer.rpc('getrawmempool'))
        template = observer.rpc('getblocktemplate', {'rules': ['segwit']})
        check('initial_template_contains_package', {parent, child}.issubset({t['txid'] for t in template['transactions']}), [t['txid'] for t in template['transactions']])
        # Exercise contextual revalidation without invalidating the package.
        confirm('unrelated_tag', source.rpc('addtagtoaddress', '#KEEPTAG', target, holder))
        sync()
        check('unrelated_tag_preserves_package', {parent, child}.issubset(set(observer.rpc('getrawmempool'))), observer.rpc('getrawmempool'))
        if args.confirm_parent:
            source.rpc('sendrawtransaction', signed['hex'])
            source.rpc('removetagfromaddress', '#KEEPTAG', target, holder)
            confirm('parent_confirmed', parent)
            sync()
            check('confirmed_parent_absent', parent not in observer.rpc('getrawmempool'), parent)
            check('child_survives_parent_confirmation', child in observer.rpc('getrawmempool'), child)
            template = observer.rpc('getblocktemplate', {'rules': ['segwit']})
            check('child_minable_after_parent_confirmation', child in {t['txid'] for t in template['transactions']}, child)
            observer.rpc('generatetoaddress', 1, miner)
            check('child_confirmed', observer.rpc('getrawtransaction', child, True).get('confirmations') == 1, child)
            return 0
        if args.event == 'tag':
            change_tx = source.rpc('removetagfromaddress', '#CONNECTTAG', target, holder)
        elif args.event == 'global':
            change_tx = source.rpc('freezerestrictedasset', '$CONNECTROOT', holder)
        elif args.event in ('address', 'child-address'):
            change_tx = source.rpc('freezeaddress', '$CONNECTROOT', target if args.event == 'child-address' else holder, holder)
        else:
            change_tx = source.rpc('reissuerestrictedasset', '$CONNECTROOT', 0, holder, True, '#CONNECTTAG & !#KEEPTAG', holder)
        state_tx = change_tx[0] if isinstance(change_tx, list) else change_tx
        state_raw = source.rpc('getrawtransaction', state_tx)
        check('state_change_admitted', observer.rpc('sendrawtransaction', state_raw) == state_tx, state_tx)
        # Fee prioritization is local mining policy, not a consensus rule.
        observer.rpc('prioritisetransaction', state_tx, 0, 100_000_000_000)
        check('all_pending', {parent, child, state_tx}.issubset(set(observer.rpc('getrawmempool'))), observer.rpc('getrawmempool'))
        check('confirmed_tag_unchanged', observer.rpc('checkaddresstag', target, '#CONNECTTAG') is True, target)
        try:
            template = observer.rpc('getblocktemplate', {'rules': ['segwit']})
        except m.RPCError as error:
            check('first_template_available', False, {'code': error.code, 'message': str(error)}, False)
        else:
            order = [t['txid'] for t in template['transactions']]
            check('first_template_available', True, order)
            check('state_change_precedes_package', all(t in order for t in (state_tx, parent, child)) and order.index(state_tx) < order.index(parent) < order.index(child), order)
        report['pending_after_first_template'] = observer.rpc('getrawmempool')
        template = observer.rpc('getblocktemplate', {'rules': ['segwit']})
        check('second_template_available', True, [t['txid'] for t in template['transactions']])
        observer.rpc('generatetoaddress', 1, miner)
        check('state_change_mined', observer.rpc('getrawtransaction', state_tx, True).get('confirmations') == 1, state_tx)
        check('package_mined_with_state_change', all(observer.rpc('getrawtransaction', t, True).get('confirmations') == 1 for t in (parent, child)), [parent, child])
        report.update(parent=parent, child=child, state_tx=state_tx)
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        for node in reversed(nodes):
            node.close()
        report['node_exit_codes'] = {node.directory.name: node.proc.returncode for node in nodes}
        report['process_logs'] = {node.directory.name: (node.directory / 'process.log').read_text() for node in nodes}
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
