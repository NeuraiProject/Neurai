#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A reorg across the fork height restores the chain state (-forkheight).

node0 and node1 split at H-4. node0 builds state on both sides of H: a root
asset moved with the 'rvn' marker before H and with 'xna' after it, a DEPIN
asset issued at H, handed to a holder, opened, moved by the holder and
closed. node1 mines a longer branch from H-3 without any of it.

- node0 reorgs to node1's branch, which disconnects H-3 to H+5: its chain
  state, asset database and address index become node1's. The address index
  keeps no empty holder for the change address that received the root asset
  and spent it inside the disconnected blocks (the reward snapshots read it)
- node0 goes back to its own branch: the chain state, the DEPIN transfer
  state and the balances are the ones it had, and verifychain 4 passes
"""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, connect_nodes_bi, disconnect_nodes,
                                 sync_blocks, wait_until)

H = 500
ROOT = "STATECOIN"
DEPIN = "&STATEDEVICE"


class UnifiedForkStateTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-forkheight=%d" % H, "-assetindex"]] * 2

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(450)
        node0.issue(ROOT, 1000)
        node0.generate(1)
        self.sync_all()
        node0.generate(H - 4 - node0.getblockcount())
        self.sync_all()

        self.log.info("node0 builds state across H; node1 mines another branch")
        self.split()
        holder = node0.getnewaddress()
        node0.transfer(ROOT, 10, node0.getnewaddress())
        self.mine(node0, H - 1)
        assert_equal(node0.getblockchaininfo()["asset_marker"], "xna")
        node0.issue(DEPIN, 100)
        node0.transfer(ROOT, 20, node0.getnewaddress())
        self.mine(node0, H)
        node0.transfer(DEPIN, 5, holder)
        self.mine(node0, H + 1)
        node0.opendepin(DEPIN)
        self.mine(node0, H + 2)
        assert_equal(node0.getassetdata(DEPIN)["transfer_state"], "open")
        node0.transfer(DEPIN, 2, node0.getnewaddress())
        self.mine(node0, H + 3)
        node0.closedepin(DEPIN)
        self.mine(node0, H + 5)
        own = self.state(node0)
        assert_equal(own["depin"]["transfer_state"], "closed")
        node1.generate(H + 6 - node1.getblockcount())
        other = self.state(node1)

        self.log.info("node0 reorgs to node1's branch across H")
        own_tip = node0.getbestblockhash()
        self.join()
        sync_blocks(self.nodes)
        assert_equal(self.state(node0), other)
        assert_equal(other["depin"], None)

        self.log.info("node0 goes back to its own branch")
        self.split()
        node0.invalidateblock(node1.getblockhash(H - 3))
        wait_until(lambda: node0.getbestblockhash() == own_tip, timeout=60,
                   err_msg="node0 did not return to its own branch")
        assert_equal(self.state(node0), own)
        assert node0.verifychain(4, 20)

    # ---------------------------------------------------------------- helpers

    def mine(self, node, height):
        node.generate(height - node.getblockcount())
        assert_equal(node.getblockcount(), height)

    def state(self, node):
        utxo = node.gettxoutsetinfo()
        try:
            depin = node.getassetdata(DEPIN)
        except Exception:
            depin = None
        return {
            "utxo": (utxo["hash_serialized_2"], utxo["txouts"], utxo["total_amount"]),
            "assets": node.listassets("*", True),
            "root": node.listaddressesbyasset(ROOT),
            "depin": depin,
            "depin_holders": node.listaddressesbyasset(DEPIN) if depin else None,
            "marker": node.getblockchaininfo()["asset_marker"],
        }

    def split(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)
        wait_until(lambda: not self.nodes[0].getpeerinfo() and not self.nodes[1].getpeerinfo(), timeout=30,
                   err_msg="nodes did not disconnect")

    def join(self):
        connect_nodes_bi(self.nodes, 0, 1)


if __name__ == '__main__':
    UnifiedForkStateTest().main()
