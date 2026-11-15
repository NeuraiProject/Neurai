# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Independent protocol 6 test client; no project client libraries or C++ codec.

It builds and opens envelopes of format 3 itself: secp256k1 from the test
framework, HKDF and SHA-256 from hashlib, AES-GCM from the system OpenSSL.
"""
import copy
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import re
import struct
import time
from test_framework.authproxy import JSONRPCException
from test_framework.key import ECKey, ECPubKey, SECP256K1

PROTOCOL = 6


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
    return (text('Neurai/DePIN/RPC/request') + struct.pack('<H', PROTOCOL) + text(method) + bytes([kind]) +
            bytes.fromhex(r['network']) + blob(bytes.fromhex(r['pool_pubkey'])) + text(r['pool_root']) +
            bytes.fromhex(r['instance_id']) + bytes.fromhex(r['membership_revision']) + bytes.fromhex(r['request_id']) + struct.pack('<q', r['timestamp_ms']) +
            text(r['token']) + text(r['address']) + blob(bytes.fromhex(r['challenge'])) + blob(args))


def preimage(method, request):
    return 'DEPIN-RPC-REQUEST-v%d|' % PROTOCOL + digest(request_bytes(method, request)).hex()


# --- Envelope format 3 --------------------------------------------------------

MESSAGE_TAG = 'Neurai/DePIN/message/v3'
REPLY_TAG = 'Neurai/DePIN/reply/v3'
SUBMIT_TAG = 'Neurai/DePIN/submit/v3'
WRAP_TAG = 'Neurai/DePIN/wrap/v3'
COMMIT_TAG = 'Neurai/DePIN/commit/v3'


def compact(size):
    if size < 253:
        return bytes([size])
    if size <= 0xffff:
        return b'\xfd' + struct.pack('<H', size)
    return b'\xfe' + struct.pack('<I', size)


def var(data):
    """Bytes with their CompactSize length in front, as the node serializes them."""
    return compact(len(data)) + data


def label(value):
    return var(value.encode('ascii'))


def message_context(network, token, sender, timestamp, kind):
    """What a message envelope is bound to: its signed header on one network."""
    return digest(label(MESSAGE_TAG) + network + var(token.encode()) + var(sender.encode()) +
                  struct.pack('<qB', timestamp, kind))


def transport_context(tag, network):
    return digest(label(tag) + network)


def message_hash(context, envelope):
    return digest(digest(context + var(envelope)))


def aes_gcm(key, nonce, plaintext, aad=b''):
    """nonce || ciphertext || tag, with the system OpenSSL."""
    crypto = ctypes.CDLL(ctypes.util.find_library('crypto'))
    pointer = ctypes.c_void_p
    crypto.EVP_CIPHER_CTX_new.restype = pointer
    crypto.EVP_aes_256_gcm.restype = pointer
    crypto.EVP_CIPHER_CTX_free.argtypes = [pointer]
    crypto.EVP_EncryptInit_ex.argtypes = [pointer, pointer, pointer, pointer, pointer]
    crypto.EVP_EncryptUpdate.argtypes = [pointer, pointer, pointer, pointer, ctypes.c_int]
    crypto.EVP_EncryptFinal_ex.argtypes = [pointer, pointer, pointer]
    crypto.EVP_CIPHER_CTX_ctrl.argtypes = [pointer, ctypes.c_int, ctypes.c_int, pointer]
    context = crypto.EVP_CIPHER_CTX_new()
    assert context
    output = ctypes.create_string_buffer(len(plaintext) + 16)
    count, final = ctypes.c_int(), ctypes.c_int()
    tag = ctypes.create_string_buffer(16)
    try:
        assert crypto.EVP_EncryptInit_ex(context, crypto.EVP_aes_256_gcm(), None, None, None) == 1
        assert crypto.EVP_CIPHER_CTX_ctrl(context, 9, 12, None) == 1  # SET_IVLEN
        assert crypto.EVP_EncryptInit_ex(context, None, None, ctypes.create_string_buffer(key), ctypes.create_string_buffer(nonce)) == 1
        if aad:
            assert crypto.EVP_EncryptUpdate(context, None, ctypes.byref(count), ctypes.create_string_buffer(aad), len(aad)) == 1
        assert crypto.EVP_EncryptUpdate(context, output, ctypes.byref(count), ctypes.create_string_buffer(plaintext), len(plaintext)) == 1
        assert crypto.EVP_EncryptFinal_ex(context, ctypes.byref(output, count.value), ctypes.byref(final)) == 1
        assert crypto.EVP_CIPHER_CTX_ctrl(context, 16, 16, tag) == 1  # GET_TAG
        return nonce + output.raw[:count.value + final.value] + tag.raw
    finally:
        crypto.EVP_CIPHER_CTX_free(context)


def legacy_recipient(pubkey):
    """The recipient id of the Legacy address of a public key."""
    return b'\x00' + hashlib.new('ripemd160', digest(pubkey)).digest()


def seal(plaintext, recipients, context):
    """An envelope of format 3 for [(public key, recipient id)], bound to `context`."""
    ephemeral = ECKey()
    ephemeral.generate()
    ephemeral_public = ephemeral.get_pubkey().get_bytes()
    content_key = os.urandom(32)
    payload = aes_gcm(content_key, os.urandom(12), plaintext, context)
    entries = []
    for raw, recipient in recipients:
        public = ECPubKey()
        public.set(raw)
        point = SECP256K1.affine(SECP256K1.mul([(public.p, ephemeral.secret)]))
        shared = digest(bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big'))
        prk = hmac.new(context, shared, hashlib.sha256).digest()
        wrap_key = hmac.new(prk, label(WRAP_TAG) + var(ephemeral_public) + var(recipient) + b'\x01', hashlib.sha256).digest()
        entries.append((recipient, aes_gcm(wrap_key, os.urandom(12), content_key)))
    commitment = digest(label(COMMIT_TAG) + context + content_key)
    return (b'\x00\x03' + var(ephemeral_public) + commitment + var(payload) + compact(len(entries)) +
            b''.join(recipient + var(wrapped) for recipient, wrapped in sorted(entries)))


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
    q = (text('Neurai/DePIN/RPC/response') + struct.pack('<H', PROTOCOL) + text(method) +
         bytes.fromhex(response['network']) + blob(bytes.fromhex(response['pool_pubkey'])) + text(response['pool_root']) +
         bytes.fromhex(response['instance_id']) + bytes.fromhex(response['membership_revision']) +
         struct.pack('<q', response['membership_height']) + bytes.fromhex(response['membership_blockhash']) + bytes.fromhex(response['request_hash']) + bytes([kind]) + blob(body))
    return 'DEPIN-RPC-RESPONSE-v%d|' % PROTOCOL + digest(q).hex()


class DepinClient:
    def __init__(self, node, wallet=None):
        self.node = node
        self.wallet = wallet or node

    def verify(self, method, request, response, pinned=None):
        assert response['protocol'] == PROTOCOL
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
            result = self.wallet.depindecrypt(request['address'], response['encrypted'])
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
        r = {'protocol': PROTOCOL, 'request_id': os.urandom(32).hex(), 'timestamp_ms': int(time.time()*1000)}
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
        r.update(protocol=PROTOCOL, request_id=os.urandom(32).hex(), timestamp_ms=timestamp,
                 token=token, address=address, challenge=nonce, args=args or {}, signature='')
        if arguments(method, r)[0]:
            expected = preimage(method, r)
            signature = self.wallet.signmessage(address, expected)
            native = self.wallet.depinsignrpc(method, r)
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
