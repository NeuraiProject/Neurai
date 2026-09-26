#!/usr/bin/env python3
"""Mixed Legacy/v2/v3 wallet spends, strict assets and compact blocks at activation.

Generic AuthScript v1 is a contract family the wallet never manages, so it is
not part of the wallet-signed mix."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import time

spec = importlib.util.spec_from_file_location('blocks', Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
h = b.h
HEIGHT = 520


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def base_transaction(tx, locktime=None):
    assert tx['version'] == 2
    raw = struct.pack('<I', 2) + h.compact(len(tx['vin']))
    for vin in tx['vin']:
        script = bytes.fromhex(vin['scriptSig']['hex'])
        raw += h.outpoint(vin['txid'], vin['vout']) + h.compact(len(script)) + script + struct.pack('<I', vin['sequence'])
    raw += h.compact(len(tx['vout']))
    for out in tx['vout']:
        raw += b.output(round(out['value'] * 100000000), bytes.fromhex(out['scriptPubKey']['hex']))
    return raw + struct.pack('<I', tx['locktime'] if locktime is None else locktime)


def main():
    directory = Path(tempfile.mkdtemp(prefix='mixed-activation-'))
    bindir = Path('/root/Neurai/src')
    report = {'results': [], 'binary_sha256': h.digest_file(bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__), Path(b.__file__), Path(h.__file__))}}
    nodes = []

    def check(label, condition, value):
        report['results'].append(dict(case=label, passed=bool(condition), observed=value))
        print(('PASS ' if condition else 'FAIL ') + label, flush=True)
        if not condition:
            raise RuntimeError(f'{label}: {value}')

    def wait(predicate, label):
        for _ in range(400):
            if predicate():
                return
            time.sleep(.1)
        raise RuntimeError('timeout: ' + label)

    try:
        p2p = port()
        source = h.Node(bindir, directory / 'source', ['-addresstype=pq', '-par=1', '-bypassdownload=1',
                    f'-strictauthscriptheight={HEIGHT}', '-listen=1', f'-port={p2p}', '-debug=cmpctblock'])
        nodes.append(source)
        peer = h.Node(bindir, directory / 'peer', ['-par=2', '-bypassdownload=1',
                    f'-strictauthscriptheight={HEIGHT}', f'-connect=127.0.0.1:{p2p}', '-debug=cmpctblock', '-assumevalid=0'])
        nodes.append(peer)
        for node in nodes:
            node.ready()
        wait(lambda: len(source.rpc('getpeerinfo')) == 1, 'P2P handshake')
        # Below HEIGHT nothing can pay to the PQ wallet's strict v2 addresses
        # (and it never manages generic v1): it mines to a Legacy key made by
        # the classic peer and imported into the PQ wallet.
        legacy = peer.rpc('getnewaddress')
        source.rpc('importprivkey', peer.rpc('dumpprivkey', legacy), '', False)
        miner = legacy
        source.rpc('generatetoaddress', HEIGHT - 1, miner)
        wait(lambda: peer.rpc('getbestblockhash') == source.rpc('getbestblockhash'), 'initial sync')
        # Warm up compact-block announcements before the activation block.
        wait(lambda: any(p.get('version', 0) for p in source.rpc('getpeerinfo')), 'version handshake')
        addresses = [legacy, source.rpc('getnewaddress', '', 'pq'), source.rpc('getnewaddress', '', 'ecdsa')]
        prefixes = [source.rpc('validateaddress', a)['scriptPubKey'] for a in addresses]
        # First transaction only spends old confirmed coins. The zero-locktime
        # variant below isolates asset activation from transaction finality.
        issuance = source.rpc('issue', 'MIXEDHEIGHT', 10, addresses[2])[0]
        original = source.rpc('getrawtransaction', issuance, True)
        signed = source.rpc('signrawtransaction', base_transaction(original, 0).hex())
        check('issuance/zero_locktime_signed', signed['complete'], signed.get('errors'))
        decoded = source.rpc('decoderawtransaction', signed['hex'])
        candidate = source.rpc('getblocktemplate', {'rules': ['segwit']})
        candidate['height'] = HEIGHT - 1
        candidate['previousblockhash'] = source.rpc('getblockhash', HEIGHT - 2)
        early, _, _ = b.block(candidate, (base_transaction(decoded), bytes.fromhex(signed['hex'])))
        for label, node in [('sync', source), ('workers', peer)]:
            tip = node.rpc('getbestblockhash')
            result = node.rpc('submitblock', early.hex())
            check(label + '/strict_asset_before_height', result == 'bad-txns-op-xna-asset-not-in-right-script-location' and node.rpc('getbestblockhash') == tip, result)
        funding = source.rpc('sendmany', '', {a: 10 for a in addresses})
        wait(lambda: set(source.rpc('getrawmempool')) == set(peer.rpc('getrawmempool')), 'funding relay')
        active = source.rpc('generatetoaddress', 1, miner)[0]
        wait(lambda: peer.rpc('getbestblockhash') == active, 'activation block')
        check('activation/height', peer.rpc('getblockcount') == HEIGHT, peer.rpc('getblockcount'))
        check('activation/issuance_confirmed', source.rpc('getrawtransaction', issuance, True)['confirmations'] == 1, issuance)
        funded = source.rpc('getrawtransaction', funding, True)
        inputs = [{'txid': funding, 'vout': next(o['n'] for o in funded['vout'] if o['scriptPubKey']['hex'] == spk)} for spk in prefixes]
        tx = source.rpc('createrawtransaction', inputs, {legacy: 29}, 0)
        signed = source.rpc('signrawtransaction', tx)
        check('mixed/signed', signed['complete'], signed.get('errors'))
        decoded = source.rpc('decoderawtransaction', signed['hex'])
        check('mixed/three_families', len(decoded['vin']) == 3 and bool(decoded['vin'][0]['scriptSig']['hex']) and
              [len(v.get('txinwitness', [])) for v in decoded['vin']] == [0, 4, 4], decoded['txid'])
        mixed = source.rpc('sendrawtransaction', signed['hex'])
        wait(lambda: mixed in peer.rpc('getrawmempool'), 'mixed relay')
        mixed_block = source.rpc('generatetoaddress', 1, miner)[0]
        wait(lambda: peer.rpc('getbestblockhash') == mixed_block, 'mixed block')
        for label, node in [('sync', source), ('workers', peer)]:
            check(label + '/mixed_spent', all(node.rpc('gettxout', i['txid'], i['vout']) is None for i in inputs) and node.rpc('gettxout', mixed, 0) is not None, mixed)
        log = (peer.directory / 'regtest/debug.log').read_text()
        for label, blockhash in [('activation', active), ('mixed', mixed_block)]:
            lines = [line for line in log.splitlines() if 'Successfully reconstructed block ' + blockhash in line]
            check(label + '/compact_reconstructed', bool(lines), lines)
            check(label + '/compact_used_mempool', any('0 txn from mempool' not in line and 'txn from mempool' in line for line in lines), lines)
        check('workers/enabled', 'Using 2 threads for script verification' in log, 2)
        # Independently replay full blocks without any mempool/script-cache
        # warming, under both synchronous and worker validation.
        history = [source.rpc('getblock', source.rpc('getblockhash', n), False) for n in range(1, HEIGHT + 2)]
        for par in (1, 2):
            fresh = h.Node(bindir, directory / f'fresh{par}', ['-disablewallet=1', f'-par={par}',
                          f'-strictauthscriptheight={HEIGHT}', '-assumevalid=0'])
            nodes.append(fresh)
            fresh.ready()
            for raw in history:
                result = fresh.rpc('submitblock', raw)
                if result is not None:
                    raise RuntimeError(f'fresh par{par}: {result}')
            check(f'fresh{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in
                  (fresh.directory / 'regtest/debug.log').read_text(), par)
            check(f'fresh{par}/tip', fresh.rpc('getbestblockhash') == mixed_block and fresh.rpc('getrawmempool') == [], mixed_block)
            check(f'fresh{par}/utxos', all(fresh.rpc('gettxout', i['txid'], i['vout']) is None for i in inputs) and
                  fresh.rpc('gettxout', mixed, 0) is not None, mixed)
            result = fresh.rpc('submitblock', early.hex())
            check(f'fresh{par}/historical_inactive_asset', result == 'bad-txns-op-xna-asset-not-in-right-script-location' and
                  fresh.rpc('getbestblockhash') == mixed_block, result)
        # Stop automatic relay while both nodes rewind below the candidate boundary.
        source.rpc('setnetworkactive', False)
        peer.rpc('setnetworkactive', False)
        rollback = source.rpc('getblockhash', HEIGHT - 1)
        for label, node in [('sync', source), ('workers', peer)]:
            node.rpc('invalidateblock', rollback)
            check(label + '/reorg_height', node.rpc('getblockcount') == HEIGHT - 2, node.rpc('getblockcount'))
            pool = node.rpc('getrawmempool')
            check(label + '/reorg_eviction', mixed not in pool and issuance not in pool, pool)
            template = node.rpc('getblocktemplate', {'rules': ['segwit']})
            check(label + '/reorg_mining', template['height'] == HEIGHT - 1, template['height'])
            node.rpc('reconsiderblock', rollback)
            check(label + '/restored', node.rpc('getbestblockhash') == mixed_block and node.rpc('gettxout', mixed, 0) is not None, node.rpc('getblockcount'))
        report['height'] = HEIGHT
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
