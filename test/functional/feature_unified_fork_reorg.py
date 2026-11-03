#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The reorg cap counts minutes, not blocks, across the fork (-forkheight).

The cap is 60 minutes of chain: 60 blocks of 60 s before H and 120 blocks of
30 s from H on. A reorg that starts before H and ends after it counts each
disconnected block at the spacing it was mined under. node0 and node1 split
before H, mine past it, and meet again:

- node0 disconnects 11 blocks before H and 97 after (about 59 minutes): it
  follows node1's longer chain, although that is more than 60 blocks
- node0 disconnects 20 blocks before H and 80 after (60 minutes): it refuses
  node1's longer chain (bad-fork-prior-to-maxreorgdepth)
"""

import os

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, disconnect_nodes, wait_until

H = 500


class UnifiedForkReorgTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # The cap only applies to a node with enough peers (regtest: 4).
        self.extra_args = [["-forkheight=%d" % H, "-minreorgpeers=1"], ["-forkheight=%d" % H]]

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(H - 12)
        self.sync_all()

        self.log.info("11 blocks before H and 97 after: node0 reorgs")
        fork_point = node0.getblockcount()
        self.split()
        node0.generate(108)
        node1.generate(118)
        assert_equal(node0.getblockcount(), H + 96)
        self.join()
        wait_until(lambda: node0.getbestblockhash() == node1.getbestblockhash(), timeout=60,
                   err_msg="node0 did not follow the longer chain")
        assert_equal(node0.getblockhash(fork_point + 1), node1.getblockhash(fork_point + 1))

        self.log.info("20 blocks before H and 80 after: node0 refuses to reorg")
        for node in self.nodes:
            node.invalidateblock(node.getblockhash(H - 20))
            assert_equal(node.getblockcount(), H - 21)
        self.split()
        node0.generate(100)
        node1.generate(110)
        tip0 = node0.getbestblockhash()
        assert_equal(node0.getblockcount(), H + 79)
        self.join()
        wait_until(lambda: self.log_has(node0, "bad-fork-prior-to-maxreorgdepth"), timeout=60,
                   err_msg="node0 did not refuse the deep reorg")
        assert_equal(node0.getbestblockhash(), tip0)

    def split(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)
        wait_until(lambda: not self.nodes[0].getpeerinfo() and not self.nodes[1].getpeerinfo(), timeout=30,
                   err_msg="nodes did not disconnect")

    def join(self):
        connect_nodes_bi(self.nodes, 0, 1)

    def log_has(self, node, text):
        with open(os.path.join(node.datadir, "regtest", "debug.log"), encoding="utf8") as f:
            return text in f.read()


if __name__ == '__main__':
    UnifiedForkReorgTest().main()
