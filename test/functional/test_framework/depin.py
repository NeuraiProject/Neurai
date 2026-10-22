# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Independent protocol-4 test client; no project client libraries or C++ codec."""
import copy
import hashlib
import json
import os
import re
import struct
import time
from test_framework.authproxy import JSONRPCException


def blob(value):
    return struct.pack('<I', len(value)) + value


def text(value):
    return blob(value.encode('ascii'))


def digest(value):
    return hashlib.sha256(value).digest()


def arguments(method, r):
    a = r.get('args', {})
    opt = lambda key, default: default if a.get(key) is None else a[key]
    if method == 'depinchallenge':
        return 1, bytes([opt('type', 'receive') == 'admin'])
    if method == 'depinreceivemsg':
        return 2, (struct.pack('<q', opt('timestamp', 0)) + blob(bytes.fromhex(opt('after_hash', ''))) +
                   struct.pack('<q', opt('limit', 0)))
    if method == 'depinreceiveseq':
        c = a.get('cursor')
        return 2, (bytes([c is not None]) + (bytes.fromhex(c['stream_id']) if c else bytes(32)) +
                   struct.pack('<qqq', c['after_seq'] if c else 0, opt('limit', 100), opt('from_timestamp', 0)))
    if method == 'depinclearmsg':
        mode = opt('mode', 'expired')
        return 3, bytes([{'expired': 0, 'all': 1, 'hours': 2}[mode]]) + struct.pack('<q', a['hours'] if mode == 'hours' else 0)
    if method == 'depinsubmitmsg':
        return 1, blob(bytes.fromhex(a['encrypted']))
    if method == 'depingetancestorrecipients':
        return 0, struct.pack('<q', opt('max_results', 1000)) + text(opt('stop_at', r['pool_root']) or r['pool_root'])
    if method == 'depinlistsections':
        return (2 if r['address'] else 0), b''
    if method in ('depingetmsginfo', 'depinpoolstats', 'depinmcpstatus'):
        return 0, b''
    raise ValueError(method)


def request_bytes(method, request):
    r = copy.deepcopy(request)
    if method == 'depingetmsginfo':
        r.update(network='00'*32, pool_pubkey='', pool_root='', instance_id='00'*32, membership_revision='00'*32,
                 token='', address='', challenge='', args={})
    if method == 'depinclearmsg' and not r['token']:
        r['token'] = r['pool_root']
    kind, args = arguments(method, r)
    return (text('Neurai/DePIN/RPC/request') + struct.pack('<H', 4) + text(method) + bytes([kind]) +
            bytes.fromhex(r['network']) + blob(bytes.fromhex(r['pool_pubkey'])) + text(r['pool_root']) +
            bytes.fromhex(r['instance_id']) + bytes.fromhex(r['membership_revision']) + bytes.fromhex(r['request_id']) + struct.pack('<q', r['timestamp_ms']) +
            text(r['token']) + text(r['address']) + blob(bytes.fromhex(r['challenge'])) + blob(args))


def preimage(method, request):
    return 'DEPIN-RPC-REQUEST-v4|' + digest(request_bytes(method, request)).hex()


def pool_address(pubkey):
    # The functional tests use Neurai regtest/testnet Legacy version 127.
    raw = bytes([127]) + hashlib.new('ripemd160', digest(bytes.fromhex(pubkey))).digest()
    raw += digest(digest(raw))[:4]
    n = int.from_bytes(raw, 'big')
    result = ''
    while n:
        n, digit = divmod(n, 58)
        result = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[digit] + result
    return result


def response_preimage(method, response):
    kind = response['body_kind']
    body = bytes.fromhex(response['encrypted' if kind else 'body'])
    q = (text('Neurai/DePIN/RPC/response') + struct.pack('<H', 4) + text(method) +
         bytes.fromhex(response['network']) + blob(bytes.fromhex(response['pool_pubkey'])) + text(response['pool_root']) +
         bytes.fromhex(response['instance_id']) + bytes.fromhex(response['membership_revision']) +
         struct.pack('<q', response['membership_height']) + bytes.fromhex(response['membership_blockhash']) + bytes.fromhex(response['request_hash']) + bytes([kind]) + blob(body))
    return 'DEPIN-RPC-RESPONSE-v4|' + digest(q).hex()


class DepinClient:
    def __init__(self, node):
        self.node = node

    def verify(self, method, request, response, pinned=None):
        assert response['protocol'] == 4
        assert response['body_kind'] in (0, 1)
        assert set(response) == {'protocol', 'network', 'pool_pubkey', 'pool_root', 'instance_id',
                                 'membership_revision', 'membership_height', 'membership_blockhash',
                                 'request_hash', 'body_kind', 'poolsig',
                                 'encrypted' if response['body_kind'] else 'body'}
        assert response['request_hash'] == digest(request_bytes(method, request)).hex()
        if pinned:
            assert response['pool_pubkey'] == pinned
        assert self.node.verifymessage(pool_address(response['pool_pubkey']), response['poolsig'],
                                       response_preimage(method, response))
        body_hex = response['encrypted' if response['body_kind'] else 'body']
        assert len(body_hex) % 2 == 0 and re.fullmatch('[0-9a-f]+', body_hex)
        if response['body_kind']:
            assert 'body' not in response
            result = self.node.depindecrypt(request['address'], response['encrypted'])
        else:
            assert 'encrypted' not in response
            result = json.loads(bytes.fromhex(response['body']).decode())
        self.context = {key: response[key] for key in ['membership_revision', 'membership_height', 'membership_blockhash']}
        if isinstance(result, dict) and 'error' in result:
            raise JSONRPCException(result['error'])
        if method != 'depingetmsginfo':
            for key in ['network', 'pool_pubkey', 'pool_root', 'instance_id']:
                assert response[key] == request[key]
            assert bool(response['body_kind']) == bool(arguments(method, request)[0])
            if arguments(method, request)[0]:
                assert response['membership_revision'] == request['membership_revision']
        return result

    def bootstrap(self):
        r = {'protocol': 4, 'request_id': os.urandom(32).hex(), 'timestamp_ms': int(time.time()*1000)}
        response = self.node.depingetmsginfo(r)
        info = self.verify('depingetmsginfo', r, response)
        assert info['network'] == response['network'] and info['instance_id'] == response['instance_id']
        assert info['depinpoolpkey'] == response['pool_pubkey']
        return response, info

    def prepare(self, method, token='', address='', nonce='', args=None, identity=None):
        if identity is None:
            identity, info = self.bootstrap()
            timestamp = info["server_time_ms"]
        else:
            timestamp = int(time.time()*1000)
        r = {key: identity[key] for key in ['network', 'pool_pubkey', 'pool_root', 'instance_id', 'membership_revision']}
        r.update(protocol=4, request_id=os.urandom(32).hex(), timestamp_ms=timestamp,
                 token=token, address=address, challenge=nonce, args=args or {}, signature='')
        if arguments(method, r)[0]:
            expected = preimage(method, r)
            signature = self.node.signmessage(address, expected)
            native = self.node.depinsignrpc(method, r)
            assert native['preimage'] == expected
            assert native['request_hash'] == digest(request_bytes(method, r)).hex()
            assert native['request']['signature'] == signature
            r['signature'] = signature
        return r

    def call_request(self, method, request):
        response = getattr(self.node, method)(request)
        return self.verify(method, request, response, request.get('pool_pubkey'))

    def call(self, method, token='', address='', nonce='', args=None):
        return self.call_request(method, self.prepare(method, token, address, nonce, args))
