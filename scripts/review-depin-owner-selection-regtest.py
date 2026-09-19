#!/usr/bin/env python3
"""DePIN address-filtered transfers preserve owner escort and OPEN permission."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('helpers', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pqwallet', action='store_true')
    args = parser.parse_args()
    flags = ['-bypassdownload=1'] + (['-pqwallet=1'] if args.pqwallet else [])
    directory = Path(tempfile.mkdtemp(prefix='depin-owner-selection-'))
    bindir = Path('/root/Neurai/src')
    report = {'results': [], 'pqwallet': args.pqwallet, 'binary_sha256': h.digest_file(bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__), Path(h.__file__))}}
    nodes = []

    def check(label, condition, value):
        report['results'].append({'case': label, 'passed': bool(condition), 'observed': value})
        print(('PASS ' if condition else 'FAIL ') + label, flush=True)
        if not condition:
            raise RuntimeError(f'{label}: {value}')

    try:
        owner = h.Node(bindir, directory / 'owner', flags)
        nodes.append(owner)
        holder = h.Node(bindir, directory / 'holder', flags)
        nodes.append(holder)
        for node in nodes:
            node.ready()
        miner = owner.rpc('getnewaddress')
        owner.rpc('generatetoaddress', 500, miner)

        def sync():
            for height in range(holder.rpc('getblockcount') + 1, owner.rpc('getblockcount') + 1):
                result = holder.rpc('submitblock', owner.rpc('getblock', owner.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError('holder rejected history: ' + str(result))

        def mine(result):
            txid = result[0] if isinstance(result, list) else result
            owner.rpc('generatetoaddress', 1, miner)
            sync()
            return owner.rpc('getrawtransaction', txid, True)

        def assets(tx):
            return [o['scriptPubKey'] for o in tx['vout'] if 'asset' in o['scriptPubKey']]

        def inputs(tx):
            return [owner.rpc('getrawtransaction', i['txid'], True)['vout'][i['vout']]['scriptPubKey'] for i in tx['vin']]

        def transfer(node, rpc, name, address, target):
            return node.rpc(rpc, name, [address] if rpc == 'transferfromaddresses' else address, 1, target, '', 0, '', address)

        sync()
        holder_fees = holder.rpc('getnewaddress')
        mine(owner.rpc('sendtoaddress', holder_fees, 100))
        for kind in (('pq', 'ecdsa') if args.pqwallet else ('legacy',)):
            name = '&SELECT' + kind.upper()
            address = owner.rpc('getnewaddress', '', kind)
            outsider = holder.rpc('getnewaddress', '', kind)
            sink = owner.rpc('getnewaddress')
            mine(owner.rpc('issue', name, 20, miner))
            # Fund the other wallet first: a later automatic transfer must not
            # consume the source UTXO that the filtered RPC is meant to test.
            mine(owner.rpc('transfer', name, 5, outsider))
            mine(owner.rpc('transfer', name, 10, address))
            # Unselected same-asset coins exist at miner: they must never be used.
            for state, transition in [('closed', None), ('open', 'opendepin'), ('sealed', 'sealdepin')]:
                if state == 'sealed':
                    mine(owner.rpc('closedepin', name))
                if transition:
                    mine(owner.rpc(transition, name))
                check(f'{kind}/{state}/state', owner.rpc('getassetdata', name)['transfer_state'] == state, state)
                for rpc in ('transferfromaddress', 'transferfromaddresses'):
                    label = f'{kind}/{state}/{rpc}'
                    tx = mine(transfer(owner, rpc, name, address, sink))
                    vin = inputs(tx)
                    escorts = [p for p in vin if p.get('asset', {}).get('name') == name + '!']
                    coins = [p for p in vin if p.get('asset', {}).get('name') == name]
                    returned = [p for p in assets(tx) if p['asset']['name'] == name + '!']
                    check(label + '/escort', len(escorts) == len(returned) == 1 and
                          escorts[0]['asset']['amount'] == returned[0]['asset']['amount'] == 1, tx['txid'])
                    check(label + '/source_filter', bool(coins) and all(p['addresses'] == [address] for p in coins), coins)
                    check(label + '/confirmed', tx['confirmations'] == 1, tx['txid'])
                    # A distinct wallet cannot supply the owner token.
                    if state != 'open':
                        try:
                            transfer(holder, rpc, name, outsider, sink)
                            check(label + '/holder_rejected', False, 'accepted')
                        except h.RPCError as error:
                            check(label + '/holder_rejected', 'owner token' in str(error), str(error))
                    else:
                        sent = transfer(holder, rpc, name, outsider, sink)[0]
                        raw = holder.rpc('getrawtransaction', sent)
                        owner.rpc('sendrawtransaction', raw)
                        moved = mine(sent)
                        check(label + '/holder_without_escort', all(p.get('asset', {}).get('name') != name + '!'
                              for p in inputs(moved) + assets(moved)), sent)
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        for node in reversed(nodes):
            node.close()
        report['passed'] = sum(x['passed'] for x in report['results'])
        report['failed'] = sum(not x['passed'] for x in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
