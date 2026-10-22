#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Mixed Legacy/strict ECDSA messaging, exact permissions and durable history."""
import copy
from decimal import Decimal
from feature_depin_pool_state import encrypt, message_wire, private_key
from test_framework.depin import DepinClient, pool_address
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, sync_blocks, sync_mempools, connect_nodes_bi

TOKEN = '&ECDSAMSG'


class DepinECDSATest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.depin_args = ['-assetindex', '-pubkeyindex', '-bip44=1', '-addresstype=legacy',
                     '-wallet=primary', '-depinwallet=primary', '-depinmsg=1',
                     '-depinmsgtoken=' + TOKEN, '-depinpoolpersist=1', '-depinratelimit=0']
        self.extra_args = [self.depin_args, ['-wallet=secondary', '-addresstype=ecdsa', '-bip44=1']]

    def clients(self):
        self.primary = self.nodes[0].get_wallet_rpc('primary')
        self.secondary = self.nodes[1].get_wallet_rpc('secondary')
        self.legacy_client, self.strict_client = DepinClient(self.primary), DepinClient(self.primary, self.secondary)

    def restart_relay(self):
        self.restart_node(0, self.depin_args)
        connect_nodes_bi(self.nodes, 0, 1)
        self.clients()

    def mine(self):
        sync_mempools(self.nodes)
        block = self.primary.generate(1)[0]
        sync_blocks(self.nodes)
        return block

    def reveal(self, address, wallet):
        txid = self.primary.sendtoaddress(address, 10)
        self.mine()
        tx = self.primary.decoderawtransaction(self.primary.gettransaction(txid)['hex'])
        index = next(v['n'] for v in tx['vout'] if address in v['scriptPubKey'].get('addresses', []))
        raw = self.primary.createrawtransaction([{'txid': txid, 'vout': index}],
                                             {self.primary.getnewaddress(): Decimal('9.99')})
        signed = wallet.signrawtransaction(raw)
        assert signed['complete']
        wallet.sendrawtransaction(signed['hex'])
        return self.mine()

    def challenge(self, client, address, kind='receive'):
        return client.call('depinchallenge', TOKEN, address, args={'type': kind})['challenge']

    def receive(self, client, address):
        return client.call('depinreceivemsg', TOKEN, address, self.challenge(client, address))['messages']

    def directory(self):
        return {r['address'] for r in self.legacy_client.call('depingetancestorrecipients', TOKEN)['recipients']}

    def identity(self, address):
        detail = self.primary.validateaddress(address)
        if detail.get('family') == 'ecdsa':
            return b'\x03' + bytes.fromhex(detail['commitment'])[::-1]
        raw = bytes.fromhex(self.primary.getpubkey(address)['pubkey'])
        import hashlib
        return b'\x00' + hashlib.new('ripemd160', hashlib.sha256(raw).digest()).digest()

    def prepare_message(self, source, signer, recipients, content):
        message = copy.deepcopy(source)
        message['sender'] = signer
        message['encrypted_payload_hex'] = encrypt(content.encode(),
            [bytes.fromhex(self.primary.getpubkey(a)['pubkey']) for a in recipients],
            [self.identity(a) for a in recipients]).hex()
        key = private_key(self.secondary.dumpprivkey(signer))
        return message, message_wire(message, key)

    def submit(self, client, address, wire):
        info = client.bootstrap()[1]
        outer = encrypt(wire.hex().encode(), [bytes.fromhex(info['depinpoolpkey'])])
        return client.call('depinsubmitmsg', '', address, args={'encrypted': outer.hex()})

    def run_test(self):
        self.primary = self.nodes[0].get_wallet_rpc('primary')
        self.primary.generate(432)
        sync_blocks(self.nodes)
        alice, bob = self.primary.getnewaddress(), self.primary.getnewaddress()
        for address in (alice, bob): self.reveal(address, self.primary)
        self.primary.issue(TOKEN, 100, alice)
        self.mine()
        self.primary.transfer(TOKEN + '!', 1, alice)
        self.mine()
        self.primary.transferfromaddress(TOKEN, alice, 10, bob, '', 0, '', alice)
        self.mine()
        historical = self.primary.depinsendmsg(TOKEN, 'Legacy before mixed addresses', alice)['hash']

        self.log.info('An independent ECDSA wallet signs and decrypts against the Legacy relay node')
        self.clients()
        info = self.legacy_client.bootstrap()[1]
        assert_equal(info['protocol'], 5)
        assert_equal(info['address_types'], ['legacy', 'ecdsa'])
        assert_equal(info['ecies_formats'], [1, 2])
        assert_equal(self.primary.depindecrypt(bob, self.receive(self.legacy_client, bob)[0]['encrypted_payload_hex']),
                     'Legacy before mixed addresses')
        carlos, marta, hidden, outsider = [self.secondary.getnewaddress() for _ in range(4)]
        assert carlos.startswith('tnq1r')
        assert_raises_rpc_error(-4, '', self.secondary.getnewaddress, '', 'legacy')
        for address in (carlos, marta, outsider): self.reveal(address, self.secondary)
        self.primary.sendtoaddress(carlos, 10)  # Funds for strict owner/revoke fees.
        self.mine()
        for address in (carlos, marta, hidden):
            self.primary.transferfromaddress(TOKEN, alice, 10, address, '', 0, '', alice)
            self.mine()
        assert_equal(self.directory(), {alice, bob, carlos, marta})
        assert_raises_rpc_error(-5, 'public key', self.challenge, self.strict_client, hidden)

        self.log.info('A first strict key revelation invalidates challenges and updates the usable directory')
        pending = self.legacy_client.prepare('depinreceivemsg', TOKEN, bob, self.challenge(self.legacy_client, bob))
        self.reveal(hidden, self.secondary)
        assert_raises_rpc_error(-32600, 'membership changed', self.legacy_client.call_request, 'depinreceivemsg', pending)
        assert hidden in self.directory()
        alias = pool_address(self.primary.getpubkey(carlos)['pubkey'])
        self.reveal(alias, self.secondary)
        assert alias not in self.directory()
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, self.strict_client, alias)
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, self.strict_client, outsider)

        self.log.info('Legacy-to-ECDSA, ECDSA-to-Legacy and ECDSA-to-ECDSA use the same content cipher')
        sent = self.primary.depinsendmsg(TOKEN, 'from Legacy to both families', alice)['hash']
        legacy_source = next(m for m in self.receive(self.strict_client, carlos) if m['hash'] == sent)
        _, strict_wire = self.prepare_message(legacy_source, carlos, sorted(self.directory()), 'from ECDSA to both families')
        strict_sent = self.submit(self.strict_client, carlos, strict_wire)['hash']
        for client, wallet, address in ((self.legacy_client, self.primary, bob),
                                        (self.strict_client, self.secondary, carlos),
                                        (self.strict_client, self.secondary, marta)):
            messages = {m['hash']: m for m in self.receive(client, address)}
            for hash_, text in ((sent, 'from Legacy to both families'), (strict_sent, 'from ECDSA to both families')):
                payload = messages[hash_]['encrypted_payload_hex']
                assert payload.startswith('0002')
                assert_equal(wallet.depindecrypt(address, payload), text)
                assert_raises_rpc_error(-22, 'required recipient missing', self.secondary.depindecrypt, alias, payload)
        source = next(m for m in self.receive(self.strict_client, carlos) if m['hash'] == strict_sent)
        subset, wire = self.prepare_message(source, carlos, [bob, carlos], 'independent mixed subset')
        accepted = self.submit(self.strict_client, carlos, wire)['hash']
        assert accepted in {m['hash'] for m in self.receive(self.legacy_client, bob)}
        assert accepted not in {m['hash'] for m in self.receive(self.strict_client, marta)}
        tampered = copy.deepcopy(subset); tampered['sender'] = alias
        assert_raises_rpc_error(None, 'no active balance', self.submit, self.strict_client, alias,
                               message_wire(tampered, private_key(self.secondary.dumpprivkey(carlos))))

        self.log.info('Mixed sequence cursors and exact recipient checks survive freezes and reorganizations')
        page = self.strict_client.call('depinreceiveseq', TOKEN, carlos, self.challenge(self.strict_client, carlos), {'limit': 1})
        assert page['has_more']
        pending = self.strict_client.prepare('depinreceivemsg', TOKEN, carlos, self.challenge(self.strict_client, carlos))
        blocked_message, blocked_wire = self.prepare_message(source, carlos, [bob, marta], 'prepared before freeze')
        original_marta = next(m for m in self.receive(self.strict_client, marta) if m['hash'] == strict_sent)
        self.primary.freezedepin(TOKEN, marta, alice)
        freeze = self.mine()
        assert_raises_rpc_error(-32600, 'membership changed', self.strict_client.call_request, 'depinreceivemsg', pending)
        assert marta not in self.directory()
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, self.strict_client, marta)
        assert_raises_rpc_error(-26, 'Recipient not authorized', self.submit, self.strict_client, carlos, blocked_wire)
        resumed = self.strict_client.call('depinreceiveseq', TOKEN, carlos, self.challenge(self.strict_client, carlos),
                                         {'cursor': page['cursor']})
        assert resumed['messages']
        _, later_wire = self.prepare_message(source, carlos, sorted(self.directory()), 'after strict freeze')
        later = self.submit(self.strict_client, carlos, later_wire)['hash']
        new_message = next(m for m in self.receive(self.legacy_client, bob) if m['hash'] == later)
        assert_raises_rpc_error(-22, 'required recipient missing', self.secondary.depindecrypt,
                                marta, new_message['encrypted_payload_hex'])
        assert_equal(self.secondary.depindecrypt(marta, original_marta['encrypted_payload_hex']), 'from ECDSA to both families')
        self.primary.invalidateblock(freeze)
        self.challenge(self.strict_client, marta)
        self.primary.reconsiderblock(freeze)
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, self.strict_client, marta)

        self.log.info('An ECDSA wallet can sign for its Legacy alias when that exact Legacy address holds the asset')
        self.primary.transferfromaddress(TOKEN, alice, 1, alias, '', 0, '', alice)
        self.mine()
        self.challenge(self.strict_client, alias)
        _, alias_wire = self.prepare_message(source, alias, [bob, carlos, alias], 'Legacy identity from ECDSA wallet')
        alias_sent = self.submit(self.strict_client, alias, alias_wire)['hash']
        alias_message = next(m for m in self.receive(self.strict_client, alias) if m['hash'] == alias_sent)
        assert_equal(self.secondary.depindecrypt(alias, alias_message['encrypted_payload_hex']), 'Legacy identity from ECDSA wallet')
        assert_equal(self.secondary.depindecrypt(carlos, alias_message['encrypted_payload_hex']), 'Legacy identity from ECDSA wallet')

        self.log.info('Strict owner administration, self-revocation and historical verification survive restart')
        self.primary.transfer(TOKEN + '!', 1, carlos)
        self.mine()
        self.challenge(self.strict_client, carlos, 'admin')
        self.secondary.freezedepin(TOKEN, alice, carlos)
        self.mine()
        stream = self.strict_client.bootstrap()[1]['stream_id']
        self.restart_relay()
        assert_equal(self.strict_client.bootstrap()[1]['stream_id'], stream)
        assert {historical, sent, strict_sent, accepted, later}.issubset({m['hash'] for m in self.receive(self.legacy_client, bob)})
        assert strict_sent in {m['hash'] for m in self.receive(self.strict_client, carlos)}
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, self.legacy_client, alice)
        # The existing self-revoke RPC chooses a wallet holding automatically;
        # leave one active non-owner holding so that choice is unambiguous.
        self.secondary.transferfromaddress(TOKEN, alias, 1, carlos, '', 0, '', carlos)
        self.mine()
        self.secondary.unfreezedepin(TOKEN, marta, carlos)
        self.mine()
        self.secondary.transferfromaddress(TOKEN, marta, 10, carlos, '', 0, '', carlos)
        self.mine()
        nonce = self.challenge(self.legacy_client, bob)
        self.secondary.selfrevokedepin(TOKEN)
        revoked = self.mine()
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, self.strict_client, hidden)
        assert_raises_rpc_error(-32600, 'Challenge not found', self.legacy_client.call, 'depinreceivemsg', TOKEN, bob, nonce)
        self.primary.invalidateblock(revoked)
        self.challenge(self.strict_client, carlos)
        removed = self.strict_client.call('depinclearmsg', TOKEN, carlos,
                                         self.challenge(self.strict_client, carlos, 'admin'), {'mode': 'all'})
        assert removed['removed'] >= 5
        self.restart_relay()
        assert_equal(self.receive(self.legacy_client, bob), [])
        assert_raises_rpc_error(-1, 'administratively deleted', self.submit, self.strict_client, carlos, wire)


if __name__ == '__main__':
    DepinECDSATest().main()
