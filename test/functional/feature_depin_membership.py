#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Pool-wide membership epochs, mandatory refresh and challenges, real chain RPC."""
import copy
from concurrent.futures import ThreadPoolExecutor

from feature_depin_pool_state import DepinPoolStateTest, encrypt, private_key
from feature_depin_messaging_permissions import TOKEN
from test_framework.depin import DepinClient
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


class DepinMembershipTest(DepinPoolStateTest):
    def run_test(self):
        node = self.nodes[0]
        node.generate(432)
        alice, bob, marta, carlos, stranger = [node.getnewaddress() for _ in range(5)]
        for address in (alice, bob, marta, carlos):
            self.reveal(address)
        node.issue(TOKEN, 100, alice)
        node.generate(1)
        for address in (bob, marta):
            node.transferfromaddress(TOKEN, alice, 10, address, '', 0, '', alice)
            node.generate(1)
        node.depinsendmsg(TOKEN, 'history before membership changes', alice)
        client = DepinClient(node)
        initial = client.bootstrap()[0]
        assert_equal(initial['protocol'], 5)
        key = private_key(node.dumpprivkey(alice))
        first_page = self.sequence_page(bob)
        original = first_page['messages'][0]

        def context():
            value = client.bootstrap()[0]
            assert value['membership_height'] >= 0
            assert_equal(node.getblockhash(value['membership_height']), value['membership_blockhash'])
            return value

        def stale(method, request):
            try:
                client.call_request(method, request)
                raise AssertionError('Obsolete membership was accepted')
            except JSONRPCException as error:
                assert_equal(error.error['code'], -32600)
                assert_equal(error.error['data']['depin_error'], 'membership_stale')
                assert error.error['data']['refresh_recipients']
                assert error.error['data']['renew_challenge']
                assert error.error['data']['membership_revision'] != request['membership_revision']

        def prepared_message(text, recipients):
            message = copy.deepcopy(original)
            message['encrypted_payload_hex'] = encrypt(text.encode(), [bytes.fromhex(node.validateaddress(a)['pubkey'])
                                                                       for a in recipients]).hex()
            return self.wrap(message, key)

        self.log.info('Empty blocks, first key reveals outside the group, and other roots preserve the epoch')
        node.generate(2)
        assert_equal(context()['membership_revision'], initial['membership_revision'])
        self.reveal(stranger)
        assert_equal(context()['membership_revision'], initial['membership_revision'])
        node.issue(TOKEN + 'OTHER', 10, stranger)
        node.generate(1)
        assert_equal(context()['membership_revision'], initial['membership_revision'])

        old_read = self.read_request(alice, self.challenge(alice))
        old_bob = self.read_request(bob, self.challenge(bob))
        old_admin = client.prepare('depinclearmsg', TOKEN, alice, self.challenge(alice, 'admin'))
        old_issue = client.prepare('depinchallenge', TOKEN, bob)
        query = client.prepare('depingetancestorrecipients', TOKEN)
        prepared = prepared_message('prepared before freeze', (alice, bob, marta))
        old_submit = client.prepare('depinsubmitmsg', '', alice, args={'encrypted': prepared['encrypted']})
        self.log.info('Mempool changes do not revoke; confirmed freeze invalidates every challenge and prepared send')
        node.freezedepin(TOKEN, marta, alice)
        assert_equal(context()['membership_revision'], initial['membership_revision'])
        freeze_block = node.generate(1)[0]
        frozen = context()
        assert frozen['membership_revision'] != initial['membership_revision']
        assert_equal(frozen['instance_id'], initial['instance_id'])
        assert_equal(frozen['membership_blockhash'], freeze_block)
        for method, request in [('depinreceivemsg', old_read), ('depinreceivemsg', old_bob),
                                ('depinclearmsg', old_admin), ('depinchallenge', old_issue), ('depinsubmitmsg', old_submit)]:
            stale(method, request)
        # Public refresh accepts the previous reference and returns the current one.
        reply = node.depingetancestorrecipients(query)
        directory = client.verify('depingetancestorrecipients', query, reply, initial['pool_pubkey'])
        assert_equal(reply['membership_revision'], frozen['membership_revision'])
        assert marta not in {r['address'] for r in directory['recipients']}
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, marta)
        assert_raises_rpc_error(-32600, 'Challenge not found', client.call_request, 'depinreceivemsg',
                                self.read_request(alice, old_read['challenge']))
        assert self.receive(alice)  # The remaining reader renews successfully.
        # The new operation proof cannot turn old content into an authorized send.
        assert_raises_rpc_error(-26, 'Recipient not authorized', self.submit, prepared)
        accepted = self.submit(prepared_message('rebuilt after freeze', (alice, bob)))
        continuation = self.sequence_page(bob, cursor=first_page['cursor'])
        assert_equal([m['hash'] for m in continuation['messages']], [accepted['hash']])
        assert_equal(continuation['cursor']['stream_id'], first_page['cursor']['stream_id'])

        self.log.info('Disconnect/reconnect never resurrects a previously invalidated nonce or epoch')
        frozen_read = self.read_request(bob, self.challenge(bob))
        node.invalidateblock(freeze_block)
        restored = context()
        assert restored['membership_revision'] not in (initial['membership_revision'], frozen['membership_revision'])
        stale('depinreceivemsg', old_bob)
        stale('depinreceivemsg', frozen_read)
        assert self.receive(marta)
        node.reconsiderblock(freeze_block)
        refrozen = context()
        assert refrozen['membership_revision'] not in (initial['membership_revision'], frozen['membership_revision'],
                                                       restored['membership_revision'])
        stale('depinreceivemsg', frozen_read)
        assert_raises_rpc_error(-32600, 'no active balance', self.challenge, marta)
        node.unfreezedepin(TOKEN, marta, alice)
        node.generate(1)
        assert self.receive(marta)

        self.log.info('An addition also rejects a prepared subset even when all its recipients remain eligible')
        before_join = context()
        subset = prepared_message('prepared before Carlos joins', (alice, bob))
        subset_request = client.prepare('depinsubmitmsg', '', alice, args={'encrypted': subset['encrypted']})
        node.transferfromaddress(TOKEN, alice, 1, carlos, '', 0, '', alice)
        assert_equal(context()['membership_revision'], before_join['membership_revision'])
        node.generate(1)
        stale('depinsubmitmsg', subset_request)
        fresh_hash = node.depinsendmsg(TOKEN, 'includes Carlos after refresh', alice)['hash']
        assert fresh_hash in {m['hash'] for m in self.receive(carlos)}
        # Explicit subsets remain valid after refreshing the context and signing again.
        assert self.submit(subset)['hash']

        self.log.info('First key publication of a holder changes the directory, with dirty and persisted balances')
        for flush in (False, True):
            hidden = node.getnewaddress()
            node.transferfromaddress(TOKEN, alice, 1, hidden, '', 0, '', alice)
            node.generate(1)
            if flush:
                node.gettxoutsetinfo()
            before_reveal = context()
            assert hidden not in {r['address'] for r in client.call('depingetancestorrecipients', TOKEN)['recipients']}
            self.reveal(hidden)
            assert context()['membership_revision'] != before_reveal['membership_revision']
            assert hidden in {r['address'] for r in client.call('depingetancestorrecipients', TOKEN)['recipients']}

        self.log.info('Section changes invalidate root/admin nonces; ancestor freezes invalidate section readers')
        before_section = self.read_request(bob, self.challenge(bob))
        node.issue(TOKEN + '/ROOM', 10, alice)
        node.generate(1)
        stale('depinreceivemsg', before_section)
        # Keep the root owner at a known revealed address after issuance change.
        node.transfer(TOKEN + '!', 1, alice)
        node.generate(1)
        section_nonce = client.call('depinchallenge', TOKEN + '/ROOM', bob)['challenge']
        section_read = client.prepare('depinreceivemsg', TOKEN + '/ROOM', bob, section_nonce)
        node.freezedepin(TOKEN, bob, alice)
        node.generate(1)
        stale('depinreceivemsg', section_read)
        assert_raises_rpc_error(-32600, 'no active balance', client.call, 'depinchallenge', TOKEN + '/ROOM', bob)
        node.unfreezedepin(TOKEN, bob, alice)
        node.generate(1)

        self.log.info('Owner changes invalidate administration and reorgs require fresh authorization')
        admin = client.prepare('depinclearmsg', TOKEN, alice, self.challenge(alice, 'admin'))
        node.transfer(TOKEN + '!', 1, carlos)
        owner_block = node.generate(1)[0]
        stale('depinclearmsg', admin)
        assert_raises_rpc_error(-32600, 'does not hold the owner token', self.challenge, alice, 'admin')
        self.challenge(carlos, 'admin')
        node.invalidateblock(owner_block)
        stale('depinclearmsg', admin)
        assert_equal(client.call('depinclearmsg', TOKEN, alice, self.challenge(alice, 'admin'))['removed'], 0)
        node.reconsiderblock(owner_block)

        self.log.info('Concurrent request preparation and connected changes share one authorization snapshot')
        prior = context()
        def reader():
            rpc = get_rpc_proxy(node.url, 980)
            worker = DepinClient(rpc)
            outcomes = []
            for _ in range(20):
                request = worker.prepare('depinchallenge', TOKEN, alice, identity=prior)
                try:
                    response = rpc.depinchallenge(request)
                    worker.verify('depinchallenge', request, response, prior['pool_pubkey'])
                    assert_equal(response['membership_revision'], prior['membership_revision'])
                    outcomes.append('before')
                except JSONRPCException as error:
                    assert_equal(error.error['data']['depin_error'], 'membership_stale')
                    outcomes.append('stale')
            return outcomes
        with ThreadPoolExecutor(max_workers=1) as executor:
            calls = executor.submit(reader)
            node.freezedepin(TOKEN, marta, carlos)
            node.generate(1)
            assert_equal(len(calls.result(timeout=90)), 20)
        stale('depinchallenge', client.prepare('depinchallenge', TOKEN, alice, identity=prior))
        assert self.receive(alice)

        self.log.info('Restart changes process and membership epochs while preserving the message stream')
        last = context()
        pending = self.read_request(alice, self.challenge(alice))
        stream = client.bootstrap()[1]['stream_id']
        self.restart_node(0, self.depin_args)
        node = self.nodes[0]
        client = DepinClient(node)
        restarted, info = client.bootstrap()
        assert restarted['instance_id'] != last['instance_id']
        assert restarted['membership_revision'] != last['membership_revision']
        assert_equal(info['stream_id'], stream)
        assert_raises_rpc_error(-32600, 'service_mismatch', client.call_request, 'depinreceivemsg', pending)
        assert self.receive(alice)


if __name__ == '__main__':
    DepinMembershipTest().main()
