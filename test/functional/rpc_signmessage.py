#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Copyright (c) 2017-2020 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test RPC commands for signing and verifying messages."""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal

class SignMessagesTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        message = 'This is just a test message'

        self.log.info('test signing with priv_key')
        priv_key = 'cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N'
        address = 'tFk4VQ5iWUXDHRHsk1qLGB5fRu5DuWpFSr'
        # Deterministic (RFC6979) compact signature over the "Neurai Signed Message:\n" magic.
        expected_signature = 'INQlEBr0rBWE72X14I8dy6mfPCrNDr4yT7JZtcsGAlnPXldH3xklQhwSy0qlgDZoE5mDgcM3LihcW1bWe75ySfE='
        signature = self.nodes[0].signmessagewithprivkey(priv_key, message)
        assert_equal(expected_signature, signature)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test signing with an address with wallet')
        address = self.nodes[0].getnewaddress()
        signature = self.nodes[0].signmessage(address, message)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test verifying with another address should not work')
        other_address = self.nodes[0].getnewaddress()
        other_signature = self.nodes[0].signmessage(other_address, message)
        assert(not self.nodes[0].verifymessage(other_address, signature, message))
        assert(not self.nodes[0].verifymessage(address, other_signature, message))

if __name__ == '__main__':
    SignMessagesTest().main()
