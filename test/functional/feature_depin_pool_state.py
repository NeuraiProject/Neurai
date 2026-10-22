#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""DePIN strict wire parsing, durable moderation, sequence cursors and crashes.

This is a test client, independent of the C++ encoders. It uses the existing
pure-Python secp256k1 test key and the system OpenSSL EVP API for AES-GCM.
It never touches external wallets or the project's client libraries.
"""
import copy
import ctypes
import ctypes.util
import hashlib
import os
import struct

from feature_depin_messaging_permissions import DepinMessagingPermissionsTest, TOKEN
from test_framework.key import ECKey, ECPubKey, SECP256K1
from test_framework.depin import DepinClient
from test_framework.util import assert_equal, assert_raises_rpc_error


def compact(size):
    if size < 253:
        return bytes([size])
    if size <= 65535:
        return b'\xfd' + struct.pack('<H', size)
    return b'\xfe' + struct.pack('<I', size)


def vector(data):
    return compact(len(data)) + data


def sha256(data):
    return hashlib.sha256(data).digest()


def aes_gcm(key, nonce, plaintext):
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
        assert crypto.EVP_EncryptUpdate(context, output, ctypes.byref(count), ctypes.create_string_buffer(plaintext), len(plaintext)) == 1
        assert crypto.EVP_EncryptFinal_ex(context, ctypes.byref(output, count.value), ctypes.byref(final)) == 1
        assert crypto.EVP_CIPHER_CTX_ctrl(context, 16, 16, tag) == 1  # GET_TAG
        return nonce + output.raw[:count.value + final.value] + tag.raw
    finally:
        crypto.EVP_CIPHER_CTX_free(context)


def encrypt(plaintext, pubkeys, identities=None):
    ephemeral = ECKey()
    ephemeral.generate()
    content_key = sha256(ephemeral.get_bytes() + b'\x00\x00\x00\x01')
    payload = aes_gcm(content_key, os.urandom(12), plaintext)
    entries = []
    for index, raw in enumerate(pubkeys):
        public = ECPubKey()
        public.set(raw)
        point = SECP256K1.affine(SECP256K1.mul([(public.p, ephemeral.secret)]))
        compressed = bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')
        wrapping_key = sha256(sha256(compressed) + b'\x00\x00\x00\x01')
        identity = identities[index] if identities is not None else hashlib.new('ripemd160', sha256(raw)).digest()
        entries.append((identity, aes_gcm(wrapping_key, os.urandom(12), content_key)))
    return ((b'\x00\x02' if identities is not None else b'') +
            vector(ephemeral.get_pubkey().get_bytes()) + vector(payload) + compact(len(entries)) +
            b''.join(identity + vector(wrapped) for identity, wrapped in sorted(entries)))


def message_wire(message, key=None):
    payload = bytes.fromhex(message['encrypted_payload_hex'])
    kind = {'private': 1, 'group': 2}[message['message_type']]
    body = (vector(message['token'].encode()) + vector(message['sender'].encode()) +
            struct.pack('<qB', message['timestamp'], kind) + vector(payload))
    signature = key.sign_ecdsa(sha256(sha256(body))) if key else bytes.fromhex(message['signature_hex'])
    return body + vector(signature)


def private_key(wif):
    value = 0
    for char in wif:
        value = value * 58 + '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    assert sha256(sha256(raw[:-4]))[:4] == raw[-4:]
    key = ECKey()
    key.set(raw[1:33], True)
    return key


class DepinPoolStateTest(DepinMessagingPermissionsTest):
    def set_test_params(self):
        super().set_test_params()
        self.depin_args.append('-depinmsgsize=10240')

    def sequence_request(self, address, cursor=None, limit=100, since=0, nonce=None):
        nonce = nonce or self.challenge(address)
        return DepinClient(self.nodes[0]).prepare('depinreceiveseq', TOKEN, address, nonce,
                                                {'cursor': cursor, 'limit': limit, 'from_timestamp': since})

    def sequence_page(self, address, cursor=None, limit=100, since=0, nonce=None):
        return DepinClient(self.nodes[0]).call_request('depinreceiveseq', self.sequence_request(address, cursor, limit, since, nonce))

    def purge(self, owner, mode='all'):
        nonce = self.challenge(owner, 'admin')
        args = {'mode': mode} if isinstance(mode, str) else {'mode': 'hours', 'hours': mode}
        return DepinClient(self.nodes[0]).call('depinclearmsg', TOKEN, owner, nonce, args)

    def submit(self, wrapped):
        return DepinClient(self.nodes[0]).call('depinsubmitmsg', '', wrapped['sender'], args={'encrypted': wrapped['encrypted']})

    def kill_restart(self, args=None):
        node = self.nodes[0]
        node.process.kill()
        node.process.wait(timeout=60)
        node.running = False
        node.rpc_connected = False
        node.rpc = None
        self.start_node(0, args or self.depin_args)

    def wrap(self, message, key=None, extra_recipient=None):
        info = self.plain(self.info_response(self.nodes[0]))
        keys = [bytes.fromhex(info['depinpoolpkey'])]
        if extra_recipient:
            keys.append(extra_recipient)
        return {'sender': message['sender'], 'encrypted': encrypt(message_wire(message, key).hex().encode(), keys).hex()}

    def run_test(self):
        node = self.nodes[0]
        assert_equal(aes_gcm(bytes(32), bytes(12), bytes(16)).hex(),
                     '000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
        self.log.info('Bootstrap disposable Legacy holdings and flush chain setup')
        node.generate(432)
        owner, reader = node.getnewaddress(), node.getnewaddress()
        self.reveal(owner)
        self.reveal(reader)
        node.issue(TOKEN, 100, owner)
        node.generate(1)
        node.transferfromaddress(TOKEN, owner, 10, reader, '', 0, '', owner)
        node.generate(1)
        node.gettxoutsetinfo()  # pin chain setup before killing only message state
        signing_key = private_key(node.dumpprivkey(owner))
        first = node.depinsendmsg(TOKEN, 'first', owner)['hash']
        second = node.depinsendmsg(TOKEN, 'second', owner)['hash']
        page = self.sequence_page(reader, limit=1)
        assert_equal(page['messages'][0]['hash'], first)
        assert page['has_more']
        old_cursor = page['cursor']
        original = page['messages'][0]

        self.log.info('Signed cursor parameters cannot be changed or moved between methods')
        nonce = self.challenge(reader)
        request = self.sequence_request(reader, old_cursor, 1, 0, nonce)
        changed = copy.deepcopy(request)
        changed['args']['limit'] = 2
        client = DepinClient(node)
        assert_raises_rpc_error(-32600, 'Signature does not match', client.call_request, 'depinreceiveseq', changed)
        assert_raises_rpc_error(-8, '', client.call_request, 'depinreceivemsg', request)
        for field, value in [('version', 99), ('address', owner), ('after_seq', -1), ('scope', 123)]:
            malformed = copy.deepcopy(request)
            malformed['args']['cursor'][field] = value
            assert_raises_rpc_error(-8, '', client.call_request, 'depinreceiveseq', malformed)
        changed = copy.deepcopy(request)
        changed['args']['cursor']['from_timestamp'] = 1
        changed['args']['from_timestamp'] = 1
        assert_raises_rpc_error(-32600, 'Signature does not match', client.call_request, 'depinreceiveseq', changed)
        resumed = self.sequence_page(reader, old_cursor, 1, nonce=nonce)
        assert_equal(resumed['messages'][0]['hash'], second)

        self.log.info('A killed process retains acknowledged messages and admission order')
        stream = old_cursor['stream_id']
        self.kill_restart()
        node = self.nodes[0]
        assert_equal(self.plain(self.info_response(node))['stream_id'], stream)
        assert_equal(self.sequence_page(reader, old_cursor)['messages'][0]['hash'], second)

        self.log.info('Moderation survives a kill and a new privacy envelope cannot undo it')
        assert_equal(self.purge(owner)['removed'], 2)
        self.kill_restart()
        node = self.nodes[0]
        assert_equal(self.plain(self.info_response(node))['messages'], 0)
        assert_raises_rpc_error(-1, 'administratively deleted', self.submit, self.wrap(original))
        late = copy.deepcopy(original)
        late['timestamp'] -= 60
        late['encrypted_payload_hex'] = encrypt(b'late timestamp', [bytes.fromhex(node.validateaddress(reader)['pubkey'])]).hex()
        accepted = self.submit(self.wrap(late, signing_key))
        late_hash = accepted['hash']
        resumed = self.sequence_page(reader, old_cursor)
        assert_equal([m['hash'] for m in resumed['messages']], [late_hash])
        assert resumed['messages'][0]['sequence'] > old_cursor['after_seq']

        self.log.info('Independent malformed inner and outer encodings are rejected')
        for timestamp in (-2**63, 2**63 - 1):
            invalid = copy.deepcopy(late)
            invalid['timestamp'] = timestamp
            assert_raises_rpc_error(-1, 'timestamp', self.submit, self.wrap(invalid, signing_key))
        invalid = copy.deepcopy(late)
        invalid['encrypted_payload_hex'] += '00'
        assert_raises_rpc_error(-1, 'Invalid ECIES', self.submit, self.wrap(invalid, signing_key))
        assert_raises_rpc_error(-22, 'recipients', self.submit,
                                self.wrap(late, signing_key, bytes.fromhex(node.validateaddress(reader)['pubkey'])))
        assert_raises_rpc_error(-8, 'budget', self.submit,
                                {'sender': owner, 'encrypted': '00' * 40000})
        damaged = self.wrap(late, signing_key)
        raw = bytearray.fromhex(damaged['encrypted'])
        raw[-1] ^= 1
        damaged['encrypted'] = raw.hex()
        assert_raises_rpc_error(-25, 'decrypt', self.submit, damaged)

        self.log.info('Volatile runs rotate cursors while keeping moderation durable')
        volatile_args = [a for a in self.depin_args if not a.startswith('-depinpoolpersist=')] + ['-depinpoolpersist=0']
        self.restart_node(0, volatile_args)
        node = self.nodes[0]
        assert_equal(self.plain(self.info_response(node))['messages'], 0)
        nonce = self.challenge(reader)
        request = self.sequence_request(reader, old_cursor, 1, nonce=nonce)
        assert_raises_rpc_error(-8, 'stream changed', DepinClient(node).call_request, 'depinreceiveseq', request)
        assert self.sequence_page(reader, nonce=nonce)['cursor']['stream_id'] != stream
        transient_hash = node.depinsendmsg(TOKEN, 'volatile message', owner)['hash']
        transient = self.sequence_page(reader)['messages'][0]
        assert_equal(transient['hash'], transient_hash)
        assert_equal(self.purge(owner)['removed'], 2)  # volatile message plus retained late_hash
        self.kill_restart(volatile_args)
        node = self.nodes[0]
        assert_raises_rpc_error(-1, 'administratively deleted', self.submit, self.wrap(transient))
        assert_raises_rpc_error(-1, 'administratively deleted', self.submit, self.wrap(original))
        self.restart_node(0, self.depin_args)
        node = self.nodes[0]
        assert_equal(self.sequence_page(reader)['messages'], [])

        self.log.info('Reply budget truncates safely and cursors cover all large messages')
        self.purge(owner)
        hashes = set()
        for index in range(250):
            hashes.add(node.depinsendmsg(TOKEN, ('large-%03d-' % index).ljust(10240, 'x'), owner)['hash'])
        current = self.sequence_page(reader, limit=1000)
        assert current['has_more']
        seen = [m['hash'] for m in current['messages']]
        while current['has_more']:
            current = self.sequence_page(reader, current['cursor'], 1000)
            seen.extend(m['hash'] for m in current['messages'])
        assert_equal(len(seen), 250)
        assert_equal(set(seen), hashes)
        legacy = self.receive(reader)
        assert len(legacy) < 250  # the legacy no-limit call also respects the reply budget


if __name__ == '__main__':
    DepinPoolStateTest().main()
