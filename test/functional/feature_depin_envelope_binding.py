#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
The envelope of a message opens only with the header it was made for.

A member that received a group message publishes the same envelope again,
under its own name and with a valid signature of its own. The pool admits it:
it cannot open envelopes. The recipients do not read it as that member's:

- depinopenmsg refuses it as addressed to the reader and not authentic;
- depingetmsg does not show it, and the node says so in its log;
- the original keeps opening, and every served message carries the public key
  the pool verified it with, which the reader checks against the sender.
"""

import copy
import os

from feature_depin_pool_state import DepinPoolStateTest, TOKEN, private_key
from test_framework.util import assert_equal, assert_raises_rpc_error


class DepinEnvelopeBindingTest(DepinPoolStateTest):
    def log_after(self, call):
        """What the node logs while `call` runs, and what it returns."""
        path = os.path.join(self.nodes[0].datadir, 'regtest', 'debug.log')
        start = os.path.getsize(path)
        result = call()
        with open(path, encoding='utf-8', errors='replace') as log:
            log.seek(start)
            return log.read(), result

    def run_test(self):
        node = self.nodes[0]
        node.generate(432)
        owner, reader, member = node.getnewaddress(), node.getnewaddress(), node.getnewaddress()
        for address in (owner, reader, member):
            self.reveal(address)
        node.issue(TOKEN, 100, owner)
        node.generate(1)
        for address in (reader, member):
            node.transferfromaddress(TOKEN, owner, 10, address, '', 0, '', owner)
            node.generate(1)

        self.log.info("A message opens for its recipient, with the sender's key as served...")
        sent = node.depinsendmsg(TOKEN, 'written by the owner', owner)['hash']
        original = next(m for m in self.sequence_page(reader)['messages'] if m['hash'] == sent)
        assert_equal(original['sender_pubkey_hex'], node.validateaddress(owner)['pubkey'])
        assert original['encrypted_payload_hex'].startswith('0003')
        assert_equal(node.depinopenmsg(reader, original), 'written by the owner')
        unserved = {key: value for key, value in original.items() if key != 'sender_pubkey_hex'}
        assert_equal(node.depinopenmsg(reader, unserved), 'written by the owner')  # looked up on chain
        wrong_key = dict(original, sender_pubkey_hex=node.validateaddress(member)['pubkey'])
        assert_raises_rpc_error(-25, 'does not belong to the sender', node.depinopenmsg, reader, wrong_key)

        self.log.info("...and the same envelope under another member's name is admitted, and does not open")
        copied = copy.deepcopy(original)
        copied['sender'] = member
        copied['timestamp'] += 1
        accepted = self.submit(self.wrap(copied, private_key(node.dumpprivkey(member))))
        republished = next(m for m in self.sequence_page(reader)['messages'] if m['hash'] == accepted['hash'])
        assert_equal(republished['encrypted_payload_hex'], original['encrypted_payload_hex'])
        assert_equal(republished['sender'], member)
        assert_raises_rpc_error(-25, 'not authentic', node.depinopenmsg, reader, republished)
        assert_raises_rpc_error(-25, 'not authentic', node.depinopenmsg, owner, republished)

        self.log.info("The wallet does not show it, and says why")
        log, shown = self.log_after(lambda: node.depingetmsg(TOKEN, reader))
        assert 'message %s is addressed to %s and is not authentic' % (accepted['hash'], reader) in log, log
        assert '1 messages addressed to this wallet are not authentic and are not shown' in log, log
        assert_equal([(m['sender'], m['message']) for m in shown], [(owner, 'written by the owner')])

        self.log.info("The member's own messages open as usual")
        own = node.depinsendmsg(TOKEN, 'written by the member', member)['hash']
        mine = next(m for m in self.sequence_page(reader)['messages'] if m['hash'] == own)
        assert_equal(node.depinopenmsg(reader, mine), 'written by the member')


if __name__ == '__main__':
    DepinEnvelopeBindingTest().main()
