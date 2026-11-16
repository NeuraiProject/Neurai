#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
A DePIN service that cannot start does not keep the node from starting.

The service is optional. When a part of it fails, the node starts without it,
says which part in its warnings and in the answers of the depin commands, and
goes on validating blocks.
"""

import tempfile

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

NOT_RUNNING = "The DePIN service is not running"


class DepinServiceStartTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def starts_without_the_service(self, extra_args, part):
        """The node starts with these options, without the service, and names the part that failed."""
        node = self.nodes[0]
        self.stop_node(0)
        # The node also prints the warning on its console (stderr). Keep it out
        # of this test's own stderr, which the test runner counts as a failure,
        # and check it once the node has stopped.
        with tempfile.TemporaryFile() as node_stderr:
            self.start_node(0, extra_args, stderr=node_stderr)
            warnings = node.getnetworkinfo()['warnings']
            assert NOT_RUNNING in warnings and part in warnings, warnings
            assert "The node runs without it" in warnings, warnings
            # the commands of the service say why they cannot answer
            assert_raises_rpc_error(-1, "is not running: ", node.depinsendmsg, "&TOKEN", "hello", node.getnewaddress())
            # ...and the node is a node: it connects blocks
            height = node.getblockcount()
            node.generate(1)
            assert_equal(node.getblockcount(), height + 1)
            self.stop_node(0)
            node_stderr.seek(0)
            console = node_stderr.read().decode('utf-8')
        assert NOT_RUNNING in console and part in console, console

    def run_test(self):
        node = self.nodes[0]
        node.generate(432)

        self.log.info("Without the asset index...")
        self.starts_without_the_service(['-depinmsg=1', '-depinmsgtoken=&TOKEN'], "-assetindex")

        self.log.info("Without a token...")
        self.starts_without_the_service(['-assetindex', '-depinmsg=1'], "no token specified")

        self.log.info("With a token that is not a DEPIN asset name...")
        self.starts_without_the_service(['-assetindex', '-depinmsg=1', '-depinmsgtoken=PLAIN'], "Invalid -depinmsgtoken")

        self.log.info("With a part that fails after the block index is loaded...")
        self.starts_without_the_service(['-assetindex', '-depinmsg=1', '-depinmsgtoken=&TOKEN', '-depinmaxtipage=0'],
                                        "Invalid DePIN freshness limits")

        self.log.info("Without -depinmsg nothing is reported")
        self.restart_node(0, ['-assetindex'])
        assert NOT_RUNNING not in node.getnetworkinfo()['warnings']
        assert_raises_rpc_error(-1, "is not enabled", node.depinsendmsg, "&TOKEN", "hello", node.getnewaddress())


if __name__ == '__main__':
    DepinServiceStartTest().main()
