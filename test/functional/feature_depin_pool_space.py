#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Space in the DePIN message pool: the share of one sender and the rolling pool.

-depinpoolsendersize limits the pool space the messages of one sender may use:
a sender that fills it is refused, and the others keep publishing.
-depinpoolrolling makes a full pool, or a sender's full space, drop its oldest
messages to admit a new one instead of refusing it.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_raises_rpc_error

from feature_depin_messaging_permissions import DepinMessagingPermissionsTest, TOKEN

PADDING = "x" * 9000  # close to the largest message, so that few of them fill a megabyte


class DepinPoolSpaceTest(DepinMessagingPermissionsTest):
    def set_test_params(self):
        super().set_test_params()
        self.space_args = self.depin_args + ["-depinmsgsize=10240", "-depinpoolsize=2"]
        self.extra_args = [self.space_args + ["-depinpoolsendersize=1"]]

    def info(self):
        return self.plain(self.info_response(self.nodes[0]))

    def send(self, sender):
        """Publish the next numbered message from `sender`; returns its number."""
        self.number += 1
        self.nodes[0].depinsendmsg(TOKEN, "%05d%s" % (self.number, PADDING), sender)
        return self.number

    def numbers(self, address):
        """The numbers of the messages the pool holds for `address`."""
        return [int(message["message"][:5]) for message in self.nodes[0].depingetmsg(TOKEN, address)]

    def run_test(self):
        node = self.nodes[0]
        node.generate(432)
        alice, bob = node.getnewaddress(), node.getnewaddress()
        for address in (alice, bob):
            self.reveal(address)
        node.issue(TOKEN, 100, alice)
        node.generate(1)
        node.transferfromaddress(TOKEN, alice, 10, bob, "", 0, "", alice)
        node.generate(1)

        self.log.info("One sender fills its megabyte and is refused; the other one publishes...")
        info = self.info()
        assert_equal((info["maxpoolsizemb"], info["maxsendersizemb"], info["rolling"], info["evicted"]), (2, 1, False, 0))
        self.number = 0
        first = self.send(alice)
        sent = 1
        while True:
            try:
                self.send(alice)
                sent += 1
                assert sent < 500
            except JSONRPCException as e:
                assert "Sender space limit exceeded" in e.error["message"], e.error["message"]
                self.number -= 1
                break
        assert sent > 50
        kept = self.send(bob)
        assert first in self.numbers(alice) and kept in self.numbers(alice)
        assert self.info()["memoryusage"] <= 2 * 1024 * 1024

        self.log.info("With a rolling pool the sender goes on, and loses its own oldest messages...")
        self.restart_node(0, self.space_args + ["-depinpoolsendersize=1", "-depinpoolrolling=1"])
        info = self.info()
        assert_equal((info["rolling"], info["evicted"]), (True, 0))
        assert_equal(len(self.numbers(alice)), sent + 1)  # the messages were kept across the restart
        for _ in range(10):
            last = self.send(alice)
        after = self.numbers(alice)
        assert first not in after
        assert last in after and kept in after
        assert self.info()["evicted"] >= 10

        self.log.info("...and without a share per sender it is the pool that rolls")
        self.restart_node(0, self.space_args + ["-depinpoolsendersize=0", "-depinpoolrolling=1"])
        assert_equal(self.info()["maxsendersizemb"], 0)
        # two megabytes hold fewer than 200 of these messages: every message
        # that was in the pool before goes, also the one from the other sender
        for _ in range(220):
            last = self.send(alice)
        after = self.numbers(alice)
        assert kept not in after and last in after
        assert self.info()["memoryusage"] <= 2 * 1024 * 1024

        self.log.info("Without rolling, a full pool refuses")
        self.restart_node(0, self.space_args + ["-depinpoolsendersize=0"])
        assert_raises_rpc_error(None, "Pool size limit exceeded", node.depinsendmsg, TOKEN, PADDING, alice)


if __name__ == '__main__':
    DepinPoolSpaceTest().main()
