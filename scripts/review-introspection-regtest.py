#!/usr/bin/env python3
"""Phase 1 opcode review: focused unit suites plus isolated regtest contracts.

Run in the build Docker: python3 /src/scripts/review-introspection-regtest.py
  --unit-bin /root/Neurai/src/test/test_neurai --output /tmp/opcode-review-REPORT
Never stops other nodes or deletes existing directories. Outputs JSON and XML.
Strict synthetic destinations test introspection/payment, not ownership/signing.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from generate_authscript_vectors import bech32m, sha256

COIN = 100_000_000
SUITES = ['authdest_tests', 'strict_authscript_tests', 'outputauthcommitment_tests',
          'txfield_tests', 'txhash_tests', 'refinputs_tests', 'outputscript_tests', 'inputvalue_tests',
          'mempool_tests', 'tx_validationcache_tests']


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + struct.pack('<H', n)
    raise ValueError('test serializer only supports lengths through 65535')


def push(data):
    if not data:
        return b'\x00'
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if len(data) < 76:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b'\x4c' + bytes([len(data)]) + data
    return b'\x4d' + struct.pack('<H', len(data)) + data


def outpoint(txid, index):
    return bytes.fromhex(txid)[::-1] + struct.pack('<I', index)


def transaction(utxo, contract, output, refs=()):
    version = 3 if refs else 2
    wire = struct.pack('<I', version) + b'\x00\x01\x01'
    wire += outpoint(*utxo) + b'\x00' + b'\xff' * 4
    wire += b'\x01' + struct.pack('<Q', COIN - 1_000_000) + compact(len(output)) + output
    if refs:
        wire += compact(len(refs)) + b''.join(outpoint(*ref) for ref in refs)
    wire += b'\x02\x01\x00' + compact(len(contract)) + contract + b'\x00' * 4
    return wire.hex()


class RPCError(RuntimeError):
    def __init__(self, error):
        self.code = error['code']
        super().__init__(error['message'])


class Node:
    def __init__(self, bindir, directory, extra_args=()):
        self.directory = directory
        directory.mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.log = (directory / 'process.log').open('w')
        self.proc = subprocess.Popen([
            str(bindir / 'neuraid'), '-regtest', '-server', '-listen=0', '-connect=0',
            '-dnsseed=0', '-discover=0', '-txindex=1', '-keypool=3', '-fallbackfee=0.01',
            '-strictauthscriptheight=0', '-rpcuser=review', '-rpcpassword=disposable-regtest',
            '-rpcport=' + str(self.port), '-datadir=' + str(directory), *extra_args],
            stdout=self.log, stderr=subprocess.STDOUT)

    def rpc(self, method, *params):
        payload = json.dumps({'jsonrpc': '1.0', 'id': 'review', 'method': method, 'params': params}).encode()
        auth = base64.b64encode(b'review:disposable-regtest').decode()
        request = urllib.request.Request('http://127.0.0.1:' + str(self.port), payload,
                                         {'Authorization': 'Basic ' + auth})
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            reply = json.load(response)
        if reply.get('error'):
            raise RPCError(reply['error'])
        return reply['result']

    def ready(self):
        for _ in range(200):
            if self.proc.poll() is not None:
                raise RuntimeError('temporary node exited; see process.log')
            try:
                self.rpc('getblockcount')
                return
            except (OSError, RuntimeError):
                time.sleep(0.1)
        raise RuntimeError('temporary node startup timed out')

    def close(self):
        if self.proc.poll() is None:
            try:
                self.rpc('stop')
            except (OSError, RuntimeError):
                self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--unit-bin', type=Path, default=Path('/root/Neurai/src/test/test_neurai'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--reuse-units-from', type=Path, help='reuse XML only when tested binaries and test/production sources still match')
    args = parser.parse_args()
    directory = args.output or Path(tempfile.mkdtemp(prefix='opcode-introspection-review-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    directory = directory.resolve()
    results = []
    report = {'phase': 'introspection-1', 'results': results, 'coverage_limits': [
        'Regtest contracts use v1 authType 0x00; real PQ/ECDSA contract signing not covered here.',
        'Broad asset/family matrix is unit-level; integration adds one issued Legacy asset reference.',
        'Does not certify every opcode, every selector, workers or compact blocks.',
        'Height activation uses separate reproducers; this driver tests reference reorg at activation zero.']}

    def record(name, expected, observed, passed):
        results.append({'case': name, 'expected': expected, 'observed': observed,
                        'status': 'pass' if passed else 'fail'})
        print(('PASS: ' if passed else 'FAIL: ') + name, flush=True)

    node = None
    try:
        report['binary_sha256'] = {str(p): digest_file(p) for p in (args.unit_bin, args.bindir / 'neuraid')}
        root = Path(__file__).resolve().parent.parent
        report['source_sha256'] = {str(p.relative_to(root)): digest_file(p) for p in (
            root / 'src/test/authdest_tests.cpp', root / 'src/script/interpreter.cpp',
            root / 'src/validation.cpp', root / 'src/txmempool.cpp', Path(__file__).resolve())}
        xmlpath = directory / 'unit-report.xml'
        unit_exit_code = 0
        if args.reuse_units_from:
            previous = json.loads((args.reuse_units_from / 'report.json').read_text())
            if previous['binary_sha256'] != report['binary_sha256']:
                raise RuntimeError('cannot reuse unit evidence: binaries differ')
            for source, digest in report['source_sha256'].items():
                if source.startswith('src/') and previous['source_sha256'].get(source) != digest:
                    raise RuntimeError('cannot reuse unit evidence: source differs: ' + source)
            shutil.copyfile(args.reuse_units_from / 'unit-report.xml', xmlpath)
            shutil.copyfile(args.reuse_units_from / 'unit.log', directory / 'unit.log')
            report['unit_evidence_reused_from'] = str(args.reuse_units_from)
        else:
            with (directory / 'unit.log').open('w') as log:
                run = subprocess.run([str(args.unit_bin), '--run_test=' + ','.join(SUITES),
                                      '--report_level=detailed', '--report_format=XML',
                                      '--report_sink=' + str(xmlpath), '--log_level=error'], stdout=log, stderr=subprocess.STDOUT)
                unit_exit_code = run.returncode
        tree = ET.parse(xmlpath)
        cases = [el for el in tree.iter('TestCase') if el.get('result') != 'skipped']
        matrix_present = any(el.get('name') == 'review_asset_sources_and_payload_variants' for el in cases)
        for suite in SUITES:
            elements = [el for el in tree.iter('TestSuite') if el.get('name') == suite]
            passed = len(elements) == 1 and elements[0].get('result') == 'passed'
            record('unit/' + suite, 'suite executed and passed', elements[0].attrib if elements else 'missing', passed)
        record('unit/new_asset_matrix_present', 'new test executed', matrix_present, matrix_present)
        if unit_exit_code or not matrix_present or any(r['status'] == 'fail' for r in results):
            raise RuntimeError('unit suite failed or new matrix absent; see unit.log and unit-report.xml')
        node = Node(args.bindir, directory / 'node')
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 110, miner)
        legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
        program = bytes(range(32))
        destinations = {'legacy': legacy, **{f'v{v}': bytes([0x50 + v, 32]) + program for v in (1, 2, 3)}}

        def mine():
            node.rpc('generatetoaddress', 1, miner)

        def fund(address, spk):
            txid = node.rpc('sendtoaddress', address, 1)
            mine()
            tx = node.rpc('getrawtransaction', txid, True)
            index = next(out['n'] for out in tx['vout'] if out['scriptPubKey']['hex'] == spk.hex())
            return txid, index

        def fund_contract(script):
            tag = sha256(b'NeuraiAuthScript')
            commitment = sha256(tag + tag + b'\x01\x00' + sha256(script))
            return fund(bech32m('tnq', 1, commitment), b'\x51\x20' + commitment)

        def exercise(label, script, good_output, bad_outputs=(), refs=(), bad_refs=()):
            utxo = fund_contract(script)
            for label_suffix, output, error_text in bad_outputs:
                try:
                    node.rpc('sendrawtransaction', transaction(utxo, script, output, refs))
                    record(label + '/' + label_suffix, 'reject: ' + error_text, 'accepted', False)
                    return
                except RPCError as error:
                    record(label + '/' + label_suffix, 'reject -26: ' + error_text,
                           str(error), error.code == -26 and error_text.lower() in str(error).lower())
            for label_suffix, ref, error_text in bad_refs:
                try:
                    node.rpc('sendrawtransaction', transaction(utxo, script, good_output, [ref]))
                    record(label + '/' + label_suffix, 'reject: ' + error_text, 'accepted', False)
                    return
                except RPCError as error:
                    record(label + '/' + label_suffix, 'reject -26: ' + error_text,
                           str(error), error.code == -26 and error_text.lower() in str(error).lower())
            try:
                txid = node.rpc('sendrawtransaction', transaction(utxo, script, good_output, refs))
            except RPCError as error:
                record(label + '/accept_and_mine', 'in mempool then confirmed', str(error), False)
                return
            in_pool = txid in node.rpc('getrawmempool')
            mine()
            confirmations = node.rpc('getrawtransaction', txid, True).get('confirmations', 0)
            record(label + '/accept_and_mine', 'in mempool then confirmed',
                   {'mempool': in_pool, 'confirmations': confirmations}, in_pool and confirmations >= 1)

        for family, spk in destinations.items():
            wrong = destinations['v2'] if family != 'v2' else destinations['v3']
            exercise('OP_OUTPUTSCRIPT/' + family, b'\x00\xcd' + push(spk) + b'\x87', spk,
                     [('wrong_script', wrong, 'false')])
        for version in (1, 2, 3):
            spk = destinations[f'v{version}']
            wrong = destinations['v3'] if version != 3 else destinations['v2']
            exercise('OP_OUTPUTAUTHDEST/v' + str(version), b'\x00\xc2' + push(bytes([version]) + program) + b'\x87', spk,
                     [('wrong_version', wrong, 'false'), ('legacy', legacy, 'OP_OUTPUTAUTHDEST')])
        exercise('OP_OUTPUTAUTHCOMMITMENT/v1', b'\x00\xd5' + push(program) + b'\x87', destinations['v1'],
                 [('v2', destinations['v2'], 'OP_OUTPUTAUTHCOMMITMENT'),
                  ('v3', destinations['v3'], 'OP_OUTPUTAUTHCOMMITMENT')])
        # Inspect our spent v1 destination: size 33, version byte 01. No circular commitment constant.
        exercise('OP_TXFIELD/04/spent_v1', bytes.fromhex('54b68201218851b7755187'), legacy)
        for version in (1, 2, 3):
            spk = destinations[f'v{version}']
            hrp = 'tpq' if version == 2 else 'tnq'
            ref = fund(bech32m(hrp, version, program), spk)
            legacy_ref = fund(miner, legacy)
            node.rpc('lockunspent', False, [{'txid': legacy_ref[0], 'vout': legacy_ref[1]}])
            exercise('OP_REFINPUTFIELD/04/v' + str(version), b'\x00\x54\xd2' + push(bytes([version]) + program) + b'\x87', legacy,
                     refs=[ref], bad_refs=[('legacy_ref', legacy_ref, 'OP_REFINPUTFIELD')])
            # Historical selectors separate a pre-existing admission issue from
            # the new versioned destination semantics.
            exercise('OP_REFINPUTFIELD/03/v' + str(version), b'\x00\x53\xd2' + push(spk) + b'\x87', legacy, refs=[ref])
            if version == 1:
                exercise('OP_REFINPUTFIELD/02/v1', b'\x00\x52\xd2' + push(program) + b'\x87', legacy, refs=[ref])

        # Resolve asset fields through the same second admission check, using
        # an actually issued, confirmed asset (rather than a fabricated suffix).
        node.rpc('generatetoaddress', max(0, 500 - node.rpc('getblockcount')), miner)
        asset_name = 'REFREVIEW'
        issue_result = node.rpc('issue', asset_name, 5, miner)
        issue_txid = issue_result[0] if isinstance(issue_result, list) else issue_result
        mine()
        issued = node.rpc('getrawtransaction', issue_txid, True)
        asset_index = next(out['n'] for out in issued['vout']
                           if any(marker in out['scriptPubKey']['hex'] for marker in ('786e6171', '72766e71')))
        asset_ref = (issue_txid, asset_index)
        node.rpc('lockunspent', False, [{'txid': issue_txid, 'vout': asset_index}])
        asset_contract = (b'\x00\x51\xd3' + push(asset_name.encode()) + b'\x88'
                          + b'\x00\x52\xd3' + push(struct.pack('<I', 5 * COIN)) + b'\x87')
        exercise('OP_REFINPUTASSETFIELD/name_and_amount', asset_contract, legacy, refs=[asset_ref])

        def reject(label, raw, reason):
            try:
                node.rpc('sendrawtransaction', raw)
                record(label, 'reject -26: ' + reason, 'accepted', False)
            except RPCError as error:
                record(label, 'reject -26: ' + reason, str(error),
                       error.code == -26 and reason in str(error))

        # Prime the script cache while the reference is valid, then invalidate
        # that reference. Cache hits must not bypass UTXO eligibility checks.
        ref_script = b'\x00\x53\xd2' + push(legacy) + b'\x87'
        contract_utxo = fund_contract(ref_script)
        conflict_ref = fund(miner, legacy)
        node.rpc('lockunspent', False, [{'txid': conflict_ref[0], 'vout': conflict_ref[1]}])
        conflict_raw = transaction(contract_utxo, ref_script, legacy, [conflict_ref])
        accepted = node.rpc('testmempoolaccept', [conflict_raw])[0]
        record('references/cache_prime', 'allowed', accepted, accepted.get('allowed') == 1)
        spending_raw = node.rpc('createrawtransaction', [{'txid': conflict_ref[0], 'vout': conflict_ref[1]}], {miner: 0.99})
        spending = node.rpc('signrawtransaction', spending_raw)
        if not spending['complete']:
            raise RuntimeError('could not sign reference spend')
        node.rpc('sendrawtransaction', spending['hex'])
        reject('references/spent_in_mempool', conflict_raw, 'refinput-spent-in-mempool')
        mine()
        reject('references/spent_in_chain', conflict_raw, 'refinput-not-confirmed')

        # The contract input stays confirmed; only its reference loses its
        # confirmation. A reference is not an ordinary unconfirmed ancestor.
        reorg_utxo = fund_contract(ref_script)
        reorg_ref = fund(miner, legacy)
        node.rpc('lockunspent', False, [{'txid': reorg_ref[0], 'vout': reorg_ref[1]}])
        ref_block = node.rpc('getbestblockhash')
        reorg_raw = transaction(reorg_utxo, ref_script, legacy, [reorg_ref])
        referencer = node.rpc('sendrawtransaction', reorg_raw)
        child_raw = node.rpc('createrawtransaction', [{'txid': referencer, 'vout': 0}], {miner: 0.98})
        child_signed = node.rpc('signrawtransaction', child_raw)
        if not child_signed['complete']:
            raise RuntimeError('could not sign referencer child')
        child = node.rpc('sendrawtransaction', child_signed['hex'])
        node.rpc('invalidateblock', ref_block)
        pool = node.rpc('getrawmempool')
        record('references/reorg_evict_referencer', 'absent from mempool', referencer in pool, referencer not in pool)
        record('references/reorg_evict_descendant', 'absent from mempool', child in pool, child not in pool)
        # Do not confuse txn-already-in-mempool with the eligibility rejection.
        if referencer not in pool:
            reject('references/unconfirmed_after_reorg', reorg_raw, 'refinput-not-confirmed')
        else:
            record('references/unconfirmed_after_reorg', 'refinput-not-confirmed', 'still pending', False)
        # A different coinbase avoids rebuilding the invalidated block verbatim.
        try:
            node.rpc('generatetoaddress', 1, node.rpc('getnewaddress'))
            record('references/mine_after_reorg', 'block accepted', 'accepted', True)
        except RPCError as error:
            record('references/mine_after_reorg', 'block accepted', str(error), False)

        # Conversely, a shallower reorg that leaves the reference confirmed
        # must retain the pending referencer and its child.
        if node.rpc('gettxout', reorg_ref[0], reorg_ref[1]) is not None:
            shallow_block = node.rpc('generatetoaddress', 1, miner)[0]
            restored = node.rpc('sendrawtransaction', reorg_raw)
            restored_child = node.rpc('sendrawtransaction', child_signed['hex'])
            node.rpc('invalidateblock', shallow_block)
            pool = node.rpc('getrawmempool')
            record('references/retain_when_still_confirmed', 'parent and child remain',
                   {'parent': restored in pool, 'child': restored_child in pool},
                   restored in pool and restored_child in pool)
            node.rpc('generatetoaddress', 1, node.rpc('getnewaddress'))
            confirmations = node.rpc('getrawtransaction', restored, True).get('confirmations', 0)
            record('references/readmit_and_mine_after_reconfirmation', 'confirmed', confirmations, confirmations >= 1)
        else:
            record('references/reconfirmation', 'reference confirmed again', 'missing', False)

        report['final_height'] = node.rpc('getblockcount')
    except Exception as error:
        record('driver', 'all stages complete', str(error), False)
    finally:
        if node:
            node.close()
        report['passed'] = sum(r['status'] == 'pass' for r in results)
        report['failed'] = sum(r['status'] == 'fail' for r in results)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return 1 if report['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
