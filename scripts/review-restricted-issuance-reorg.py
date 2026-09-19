#!/usr/bin/env python3
"""Disconnect restricted asset issuance and its confirmed spending package."""
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
    parser.add_argument('--target', choices=['pq', 'ecdsa', 'authscript', 'legacy'], default='ecdsa')
    parser.add_argument('--coin-only-child', action='store_true', help='Reproduce the original ordinary-coin descendant')
    parser.add_argument('--disconnect-fee', action='store_true', help='Disconnect the original non-coinbase fee funding too')
    parser.add_argument('--competing', action='store_true')
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='restricted-issuance-reorg-'))
    report = {'results': [], 'disconnect_fee': args.disconnect_fee, 'target': args.target, 'competing': args.competing, 'coin_only_child': args.coin_only_child,
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
        if args.target == 'legacy':
            keynode = m.Node(args.bindir, directory / 'legacykeys', ['-pqwallet=0'])
            nodes.append(keynode)
            keynode.ready()
            target = keynode.rpc('getnewaddress', '', 'legacy')
            source.rpc('importprivkey', keynode.rpc('dumpprivkey', target), '', False)
        else:
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
        confirm('target_tag', source.rpc('addtagtoaddress', '#REORGTAG', target, holder))
        fee_coin = None
        fee_block = None
        if args.disconnect_fee:
            fee_address = source.rpc('getnewaddress')
            fee_tx = confirm('fee_funding', source.rpc('sendtoaddress', fee_address, 20))
            fee_prefix = source.rpc('validateaddress', fee_address)['scriptPubKey']
            fee_out = next(o for o in fee_tx['vout'] if o['scriptPubKey']['hex'] == fee_prefix)
            fee_coin = {'txid': fee_tx['txid'], 'vout': fee_out['n'], 'amount': 20}
            # Keep issuance funding from selecting the coin under test.
            source.rpc('lockunspent', False, [{'txid': fee_coin['txid'], 'vout': fee_coin['vout']}])
            fee_block = source.rpc('getbestblockhash')
        issued = confirm('restricted', source.rpc('issuerestrictedasset', '$REORGROOT', 5, '#REORGTAG', holder, holder))
        prefix = source.rpc('validateaddress', holder)['scriptPubKey']
        asset = next(o for o in issued['vout'] if o['scriptPubKey']['hex'].startswith(prefix) and
                     b'$REORGROOT'.hex() in o['scriptPubKey']['hex'])
        tagblock = fee_block or source.rpc('getbestblockhash')
        tagheight = source.rpc('getblockheader', tagblock)['height']
        # Rewinding this unrelated block must preserve a valid package, including
        # a restricted child whose asset input exists only in the mempool.
        unrelated = source.rpc('generatetoaddress', 1, miner)[0]
        coin = fee_coin or next(o for o in source.rpc('listunspent', 100) if o['spendable'] and o['amount'] > 3)
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
        packageblock = source.rpc('generatetoaddress', 1, miner)[0]
        check('package_confirmed_before_reorg', all(source.rpc('getrawtransaction', t, True).get('confirmations') == 1 for t in (parent, child)), packageblock)
        fork = []
        if args.competing:
            rival = m.Node(args.bindir, directory / 'rival', ['-disablewallet=1', '-assumevalid=0', '-bypassdownload=1'])
            nodes.append(rival)
            rival.ready()
            for height in range(1, tagheight):
                result = rival.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError(f'rival/{height}: {result}')
            fork = rival.rpc('generatetoaddress', source.rpc('getblockcount') - rival.rpc('getblockcount') + 1, legacy)
            for block in fork:
                result = source.rpc('submitblock', rival.rpc('getblock', block, False))
                if result not in (None, 'inconclusive'):
                    raise RuntimeError(f'competing/{block}: {result}')
            check('competing_tip_selected', source.rpc('getbestblockhash') == fork[-1], source.rpc('getbestblockhash'))
        else:
            source.rpc('invalidateblock', tagblock)
            check('height_rewound', source.rpc('getblockcount') == tagheight - 1, source.rpc('getblockcount'))
        if args.disconnect_fee:
            check('fee_funding_disconnected', source.rpc('getrawtransaction', fee_coin['txid'], True).get('confirmations', 0) <= 0, fee_coin['txid'])
            check('fee_coin_absent_from_chain', source.rpc('gettxout', fee_coin['txid'], fee_coin['vout'], False) is None, fee_coin)
            check('fee_funding_readmitted', fee_coin['txid'] in source.rpc('getrawmempool'), source.rpc('getrawmempool'))
        check('tag_still_present', source.rpc('checkaddresstag', target, '#REORGTAG') is True, target)
        check('issuance_unconfirmed', source.rpc('getrawtransaction', issued['txid'], True).get('confirmations', 0) <= 0, issued['txid'])
        report['pending_after_reorg'] = source.rpc('getrawmempool')
        try:
            template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        except m.RPCError as error:
            check('mining_available', False, {'code': error.code, 'message': str(error)}, stop=False)
        else:
            check('mining_available', True, [t['txid'] for t in template['transactions']])
        if fork:
            source.rpc('invalidateblock', fork[0])
        source.rpc('reconsiderblock', tagblock)
        check('state_block_restored', source.rpc('getblockhash', tagheight) == tagblock, source.rpc('getbestblockhash'))
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('mining_restored', True, [t['txid'] for t in template['transactions']])
        # Restoring the original branch may already restore the package block.
        for txid, rawhex in ((parent, signed['hex']), (child, childsig['hex'])):
            if txid not in source.rpc('getrawmempool') and source.rpc('getrawtransaction', txid, True).get('confirmations', 0) <= 0:
                check('readmit/' + txid, source.rpc('sendrawtransaction', rawhex) == txid, txid)
        source.rpc('generatetoaddress', 1, miner)
        check('both_mined_after_restore', all(source.rpc('getrawtransaction', txid, True).get('confirmations', 0) >= 1
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
