#!/usr/bin/env python3
"""Public testnet smoke test for NIP-043's non-custodial UNIQUE state thread.

Uses disposable testnet assets and an oracle key. Never funds the DEMO custody
commitments or ZK circuits. Requires a funded, synced testnet wallet and mines
one confirmation block. Pass a fresh --asset-root for each run.
"""
import argparse
import base64
from decimal import Decimal
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location('thread', Path(__file__).with_name('review-contract-thread-regtest.py'))
thread = importlib.util.module_from_spec(spec)
spec.loader.exec_module(thread)

COIN = 100_000_000
GENESIS = '0000008b384aeffecdab182575dc4e86c9f07f90318c65088532660ed9a8a021'


class Rpc:
    def __init__(self, port, user, password):
        self.url = f'http://127.0.0.1:{port}/'
        self.authorization = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()

    def __call__(self, method, *params):
        request = urllib.request.Request(
            self.url,
            json.dumps({'jsonrpc': '1.0', 'id': 'nip043-testnet', 'method': method, 'params': params}).encode(),
            {'Authorization': self.authorization, 'Content-Type': 'application/json'},
        )
        try:
            response = urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result['error']:
            raise RuntimeError(f'{method}: {result["error"]}')
        return result['result']


def script_for_thread(name, domain, pub):
    # Same script constructor as the established regtest review. Only the
    # network genesis and issuance outpoint vary in the instance domain.
    h, a, push = thread.h, thread.a, thread.push
    script = b'\x00\xd6\x00\x88\x00\xcc\x00\x88'
    for op in (0xcf, 0xce):
        for selector, expected in ((1, name.encode()), (2, a.number(COIN))):
            script += b'\x00' + push(bytes([selector])) + bytes([op]) + push(expected) + b'\x88'
        script += b'\x00' + push(b'\x08') + bytes([op]) + b'\x82' + push(a.number(32)) + b'\x88\x75'
    tail = thread.transfer(b'', name, bytes(32))[:-33]
    for query in (0xcf, 0xce):
        script += push(b'\x51\x20') + push(b'\x02') + b'\xb6\x7e' + push(tail) + b'\x7e'
        script += b'\x00' + push(b'\x08') + bytes([query]) + b'\x7e' + push(b'\x75') + b'\x7e'
        script += (b'\x00' + push(b'\x03') + b'\xc4' if query == 0xcf else b'\x00\xcd') + b'\x88'
    script += b'\x00\xd5' + push(b'\x02') + b'\xb6\x88'
    script += push(domain) + b'\x00' + push(b'\x08') + b'\xcf\x7e'
    script += b'\x00' + push(b'\x08') + b'\xce\x7e' + push(pub) + b'\xb4'
    return script


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpcport', type=int, required=True)
    parser.add_argument('--asset-root', required=True)
    parser.add_argument('--oracle', choices=('ecdsa', 'pq'), required=True)
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    rpc = Rpc(args.rpcport, os.environ['REVIEW_RPC_USER'], os.environ['REVIEW_RPC_PASSWORD'])
    info = rpc('getblockchaininfo')
    if info['chain'] != 'test' or info['blocks'] < 10 or rpc('getblockhash', 0) != GENESIS:
        raise RuntimeError('expected reset testnet at or above the H10 activation')
    name = args.asset_root + '#state'
    miner = rpc('getnewaddress', '', 'legacy')
    miner_script = bytes.fromhex(rpc('validateaddress', miner)['scriptPubKey'])
    def confirm(txid):
        txid = txid[0] if isinstance(txid, list) else txid
        # Another miner can win the tip while this node builds a block. Use
        # the transaction's actual confirmation, not one generate() result.
        for _ in range(6):
            tx = rpc('getrawtransaction', txid, True)
            if tx.get('confirmations', 0) >= 1:
                return tx
            rpc('generatetoaddress', 1, miner)
        tx = rpc('getrawtransaction', txid, True)
        if tx.get('confirmations', 0) < 1:
            raise RuntimeError(f'unconfirmed after six blocks: {txid}')
        return tx
    confirm(rpc('issue', args.asset_root, 1, miner))
    issuance = confirm(rpc('issueunique', args.asset_root, ['state'], None, miner))
    payload_prefix = (b'xnaq' + thread.h.compact(len(name)) + name.encode()).hex()
    issuance_vout = next(o['n'] for o in issuance['vout'] if payload_prefix in o['scriptPubKey']['hex'])
    domain = thread.sha(b'NIP043/instance/v3' + bytes.fromhex(GENESIS)[::-1]
                        + thread.h.outpoint(issuance['txid'], issuance_vout)
                        + thread.h.compact(len(name)) + name.encode())
    pub_hex, secret_hex = subprocess.check_output([str(args.signer), 'keygen', args.oracle], text=True).splitlines()
    script = script_for_thread(name, domain, bytes.fromhex(pub_hex))
    address, spk = thread.address(script)
    initial, following = bytes(range(32)), bytes(range(32, 64))
    funding = confirm(rpc('transfer', name, 1, address, initial.hex()))
    state_vout = next(o['n'] for o in funding['vout'] if o['scriptPubKey']['hex'] == thread.transfer(spk, name, initial).hex())
    state_utxo = (funding['txid'], state_vout)
    sponsor = next(u for u in rpc('listunspent') if Decimal(str(u['amount'])) > 2 and u.get('spendable', True))
    sponsor_utxo = (sponsor['txid'], sponsor['vout'])
    sponsor_value = int(Decimal(str(sponsor['amount'])) * COIN)
    fee = 10_000_000  # 0.1 XNA; enough for the larger ML-DSA witness
    def transition(state=following, signed_state=None, signature=None, destination=spk, signing_domain=domain):
        message = signing_domain + initial + (state if signed_state is None else signed_state)
        if signature is None:
            signature = bytes.fromhex(subprocess.check_output(
                [str(args.signer), 'sign', args.oracle],
                input=secret_hex + '\n' + thread.sha(message).hex() + '\n', text=True).strip())
        unsigned = thread.a.raw_transaction(
            [state_utxo, sponsor_utxo],
            [(0, thread.transfer(destination, name, state)), (sponsor_value - fee, miner_script)],
            [], [[b'\x00', signature, script], []])
        return rpc('signrawtransaction', unsigned)['hex']
    good = transition()
    def acceptance(raw):
        return rpc('testmempoolaccept', [raw])[0]
    valid = acceptance(good)
    if not valid.get('allowed'):
        raise RuntimeError(f'valid transition rejected: {valid}')
    negatives = {
        'state_without_oracle_signature': transition(state=bytes([9]) * 32, signed_state=following),
        'invalid_signature': transition(signature=b''),
        'wrong_domain': transition(signing_domain=bytes(32)),
        'escaped_unique': transition(destination=miner_script),
    }
    for label, raw in negatives.items():
        result = acceptance(raw)
        if result.get('allowed'):
            raise RuntimeError(f'negative accepted: {label}')
    transition_txid = rpc('sendrawtransaction', good)
    transition_tx = confirm(transition_txid)
    final_utxo = rpc('gettxout', transition_txid, 0)
    if (not final_utxo or final_utxo['scriptPubKey']['hex'] != thread.transfer(spk, name, following).hex()
            or rpc('gettxout', *state_utxo) is not None):
        raise RuntimeError('thread state/UNIQUE invariant failed')
    print(json.dumps({
        'result': 'PASS', 'network_genesis': GENESIS, 'oracle': args.oracle,
        'asset': name, 'issuance_txid': issuance['txid'], 'funding_txid': funding['txid'],
        'transition_txid': transition_txid, 'confirmation_height': transition_tx['height'],
        'domain': domain.hex(), 'contract_address': address,
        'checks': ['valid_transition', *negatives, 'mined', 'unique_preserved', 'old_state_consumed'],
    }, indent=2))


if __name__ == '__main__':
    main()
