#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Nodes that did not upgrade are left out at the fork height (-forkheight).

Upgraded nodes announce protocol 70031 and, once their tip reaches H, refuse
and drop peers below it. Nodes that did not upgrade are played with the old
rules (-forkheight far away) and an old version (-announceversion): node1 is
1.0.7 (70028) and node2 a 2.0 build without the mainnet fork height (70029).
node0 and node3 are upgraded; node4 and node5 start empty later.

- C-01: before H every version connects, inbound and outbound
- C-02, C-05: when node0's tip reaches H, it drops node1 and node2 on the next
  tick, with a line in its log, and keeps node3
- C-03: after H, node0 refuses the handshake of an old node in both
  directions, without banning it
- C-04: an old node reconnecting in a loop costs one short log entry each
- C-07, C-08: node1 mines the old chain past H with more work. node4 syncs
  from node1 and node0 and ends on node0's chain, without node1. node5 only
  reaches node1: it stays below H, since the header batch that crosses H is
  refused, and drops node1 without a ban; once it reaches an upgraded node,
  it follows the new chain
"""

import os
import time

from test_framework.messages import MsgVersion
from test_framework.mininode import NetworkThread, NodeConn, NodeConnCB
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, p2p_port, sync_blocks, wait_until

H = 200
FAR = 1000000
FORK_VERSION = 70031
OLD_1_0_7 = 70028
OLD_2_0 = 70029


class UnifiedForkPeersTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 6
        new = ["-forkheight=%d" % H]
        self.extra_args = [new,
                           ["-forkheight=%d" % FAR, "-announceversion=%d" % OLD_1_0_7],
                           ["-forkheight=%d" % FAR, "-announceversion=%d" % OLD_2_0],
                           new, new, new]

    def setup_network(self):
        self.setup_nodes()
        for other in (1, 2, 3):
            connect_nodes_bi(self.nodes, 0, other)

    def run_test(self):
        self.test_before_the_fork()
        self.test_fork_height_drops_old_peers()
        self.test_old_handshake_refused()
        self.test_reconnection_loop()
        self.test_new_nodes_sync_past_old_peers()

    # ---------------------------------------------------------------- helpers

    def debug_log(self, node):
        return os.path.join(node.datadir, "regtest", "debug.log")

    def log_count(self, node, text):
        with open(self.debug_log(node), encoding="utf8") as f:
            return f.read().count(text)

    def versions(self, node):
        return sorted(p["version"] for p in node.getpeerinfo())

    def addnode(self, node, other):
        node.addnode("127.0.0.1:%d" % p2p_port(other), "onetry")

    # ------------------------------------------------------------------ tests

    def test_before_the_fork(self):
        node0 = self.nodes[0]
        self.log.info("C-01: before H every version connects, inbound and outbound")
        node0.generate(H - 2)
        sync_blocks(self.nodes[:4])
        assert_equal(node0.getnetworkinfo()["protocolversion"], FORK_VERSION)
        assert_equal(self.nodes[1].getnetworkinfo()["protocolversion"], OLD_1_0_7)
        assert_equal(self.versions(node0), [OLD_1_0_7] * 2 + [OLD_2_0] * 2 + [FORK_VERSION] * 2)

    def test_fork_height_drops_old_peers(self):
        node0 = self.nodes[0]
        self.log.info("C-02, C-05: at tip H node0 drops 70028 and 70029 and keeps 70031")
        node0.generate(2)
        sync_blocks([node0, self.nodes[3]])
        assert_equal(node0.getblockcount(), H)
        wait_until(lambda: self.versions(node0) == [FORK_VERSION] * 2, timeout=30,
                   err_msg="node0 kept an old peer")
        for version in (OLD_1_0_7, OLD_2_0):
            assert self.log_count(node0, "using obsolete version %d; disconnecting post-activation per NIP-028"
                                  % version) >= 1, version
        assert_equal(node0.listbanned(), [])

    def test_old_handshake_refused(self):
        node0, node1, node2 = self.nodes[:3]
        self.log.info("C-03: after H node0 refuses an old node inbound and outbound")
        refused = "disconnecting because peer isn't signalling protocol version for NIP-028"
        before = self.log_count(node0, refused)
        self.addnode(node1, 0)   # inbound to node0
        self.addnode(node0, 2)   # outbound from node0
        wait_until(lambda: self.log_count(node0, refused) >= before + 2, timeout=30,
                   err_msg="node0 did not refuse both handshakes")
        for version in (OLD_1_0_7, OLD_2_0):
            assert self.log_count(node0, "using obsolete version %d; %s" % (version, refused)) >= 1, version
        wait_until(lambda: self.versions(node0) == [FORK_VERSION] * 2, timeout=30,
                   err_msg="an old node stayed connected")
        wait_until(lambda: not node1.getpeerinfo() and not node2.getpeerinfo(), timeout=30,
                   err_msg="the old nodes kept a link to node0")
        assert_equal(node0.listbanned(), [])

    def test_reconnection_loop(self):
        node0 = self.nodes[0]
        self.log.info("C-04: an old node reconnecting in a loop")
        attempts, batch = 120, 30
        size_before = os.path.getsize(self.debug_log(node0))
        start = time.time()
        for _ in range(attempts // batch):
            peers = []
            for _ in range(batch):
                peer = NodeConnCB()
                conn = NodeConn("127.0.0.1", p2p_port(0), node0, peer, send_version=False)
                version = MsgVersion()
                version.nVersion = OLD_1_0_7
                version.addrTo.ip = "127.0.0.1"
                version.addrTo.port = p2p_port(0)
                conn.send_message(version, True)
                peer.add_connection(conn)
                peers.append(peer)
            thread = NetworkThread()
            thread.start()
            for peer in peers:
                peer.wait_for_disconnect(timeout=30)
            thread.join(timeout=30)
        elapsed = time.time() - start
        growth = os.path.getsize(self.debug_log(node0)) - size_before
        self.log.info("%d refused handshakes in %.1f s, debug.log grew %d bytes (%d per attempt)",
                      attempts, elapsed, growth, growth // attempts)
        assert growth // attempts < 1000, growth
        assert_equal(node0.getblockcount(), H)
        assert_equal(self.versions(node0), [FORK_VERSION] * 2)

    def test_new_nodes_sync_past_old_peers(self):
        node0, node1, node2, node3, node4, node5 = self.nodes
        self.log.info("C-07: node1 mines the old chain past H with more work")
        connect_nodes_bi(self.nodes, 1, 2)
        node1.generate(100)
        sync_blocks([node1, node2])
        node0.generate(20)
        sync_blocks([node0, node3])
        assert node1.getblockcount() > node0.getblockcount()
        old_tip = node1.getbestblockhash()

        self.log.info("C-08: an empty node with an old and a new peer ends on the new chain")
        self.addnode(node4, 1)
        self.addnode(node4, 0)
        wait_until(lambda: node4.getbestblockhash() == node0.getbestblockhash(), timeout=60,
                   err_msg="node4 did not follow the new chain")
        wait_until(lambda: OLD_1_0_7 not in self.versions(node4), timeout=30,
                   err_msg="node4 kept the old peer past H")
        assert old_tip not in [t["hash"] for t in node4.getchaintips()]
        assert_equal(node4.listbanned(), [])

        self.log.info("C-08: an empty node that only reaches old peers stops below H and drops them")
        self.addnode(node5, 1)
        wait_until(lambda: self.log_count(node5, "is on the other side of the fork height") >= 1, timeout=60,
                   err_msg="node5 did not refuse the old block H")
        # The header batch that crosses H is refused as a whole, so no block of
        # it comes from that peer: here the batch starts at genesis. The peer is
        # dropped at once, without a ban, to make room for an upgraded one.
        wait_until(lambda: not node5.getpeerinfo(), timeout=30, err_msg="node5 kept the old peer")
        assert node5.getblockcount() < H
        self.log.info("node5 stopped at height %d", node5.getblockcount())
        self.log.info("C-08: once it reaches an upgraded node it follows the new chain")
        self.addnode(node5, 3)
        wait_until(lambda: node5.getbestblockhash() == node0.getbestblockhash(), timeout=60,
                   err_msg="node5 did not follow the new chain")
        assert_equal(self.versions(node5), [FORK_VERSION])
        assert_equal(node5.listbanned(), [])


if __name__ == '__main__':
    UnifiedForkPeersTest().main()
