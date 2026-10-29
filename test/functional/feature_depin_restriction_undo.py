#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
DEPIN owner freezes, unfreezes and self-revocations across reorgs, restarts and
a rebuilt chainstate.

Node 0 owns the DEPIN asset, node 1 holds it. Undoing a block restores exactly
the restriction state the address had before it, also after -reindex-chainstate
and a restart. A confirmed freeze evicts the holder transfers it makes invalid,
so block templates stay valid, and pending self-revocations survive state
changes and reorgs.
"""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    disconnect_nodes,
    sync_blocks,
    sync_mempools,
)

ASSET = "&DEVICE"

CLEAN = (False, False)        # (owner frozen, blocked)
OWNER_FROZEN = (True, True)
SELF_REVOKED = (False, True)


class DepinRestrictionUndoTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-assetindex']] * self.num_nodes

    # ----------------------------------------------------------------- helpers
    def restriction(self):
        """(owner frozen, blocked) of the holder address; every node must agree."""
        states = set()
        for node in self.nodes:
            frozen = node.checkaddressrestriction(self.holder_address, ASSET)
            blocked = node.checkdepinvalidity(ASSET, self.holder_address)['blocked']
            states.add((frozen, blocked))
        assert_equal(len(states), 1)
        return states.pop()

    def mine(self, node):
        block = node.generate(1)[0]
        self.sync_all()
        return block

    def undo(self, block):
        for node in self.nodes:
            node.invalidateblock(block)
        sync_blocks(self.nodes)

    def redo(self, block):
        for node in self.nodes:
            node.reconsiderblock(block)
        sync_blocks(self.nodes)
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), self.nodes[0].getbestblockhash())

    def isolate(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)

    def rejoin(self):
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

    # ------------------------------------------------------------------- steps
    def setup_asset(self):
        self.log.info("Activating assets and handing DEPIN units to the holder...")
        n0, n1 = self.nodes
        n0.generate(432)
        self.sync_all()
        n0.sendtoaddress(n1.getnewaddress(), 500)
        self.mine(n0)
        self.owner_address = n0.getnewaddress()
        n0.issue(ASSET, 100, self.owner_address)
        self.mine(n0)
        self.holder_address = n1.getnewaddress()
        n0.transfer(ASSET, 10, self.holder_address)
        self.mine(n0)
        assert_equal(CLEAN, self.restriction())

    def undo_owner_only_unfreeze(self):
        self.log.info("Undoing an unfreeze of an owner freeze restores the freeze only...")
        n0 = self.nodes[0]
        n0.freezedepin(ASSET, self.holder_address)
        freeze_block = self.mine(n0)
        n0.unfreezedepin(ASSET, self.holder_address)
        unfreeze_block = self.mine(n0)
        assert_equal(CLEAN, self.restriction())

        self.undo(unfreeze_block)
        assert_equal(OWNER_FROZEN, self.restriction())
        self.undo(freeze_block)
        assert_equal(CLEAN, self.restriction())

        self.redo(freeze_block)
        assert_equal(CLEAN, self.restriction())

    def undo_self_only_unfreeze(self):
        self.log.info("Undoing an unfreeze of a self-revocation restores the self-revocation only...")
        n0, n1 = self.nodes
        n1.selfrevokedepin(ASSET)
        sync_mempools(self.nodes)
        self.mine(n0)
        assert_equal(SELF_REVOKED, self.restriction())
        n0.unfreezedepin(ASSET, self.holder_address)
        self.unfreeze_block = self.mine(n0)
        assert_equal(CLEAN, self.restriction())

        self.undo(self.unfreeze_block)
        assert_equal(SELF_REVOKED, self.restriction())
        self.redo(self.unfreeze_block)
        assert_equal(CLEAN, self.restriction())

    def rebuilt_chainstate_and_restart(self):
        self.log.info("-reindex-chainstate and a restart keep the undo exact...")
        self.restart_node(0, self.extra_args[0] + ['-reindex-chainstate'])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        self.restart_node(1, self.extra_args[1])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(CLEAN, self.restriction())

        self.undo(self.unfreeze_block)
        assert_equal(SELF_REVOKED, self.restriction())
        self.redo(self.unfreeze_block)
        assert_equal(CLEAN, self.restriction())

    def freeze_evicts_pending_holder_transfer(self):
        self.log.info("A confirmed freeze evicts the holder transfer it invalidates; templates stay valid...")
        n0, n1 = self.nodes
        n0.opendepin(ASSET)
        self.mine(n0)

        # The transfer stays on node 1 while node 0 confirms the freeze
        self.isolate()
        move = n1.transfer(ASSET, 1, n1.getnewaddress(), "", 0, "", self.holder_address)[0]
        assert move in n1.getrawmempool()
        n0.freezedepin(ASSET, self.holder_address)
        n0.generate(1)
        self.rejoin()
        assert_equal(OWNER_FROZEN, self.restriction())
        assert move not in n1.getrawmempool(), "the freeze left a now-invalid holder transfer"
        n1.getblocktemplate()
        self.mine(n1)
        n1.abandontransaction(move)

        n0.unfreezedepin(ASSET, self.holder_address)
        self.mine(n0)
        assert_equal(CLEAN, self.restriction())

    def self_revocation_survives_close_and_reorg(self):
        self.log.info("A pending self-revocation survives a confirmed close and a reorg...")
        n0, n1 = self.nodes
        self.isolate()
        revoke = n1.selfrevokedepin(ASSET)[0]
        n0.closedepin(ASSET)
        n0.generate(1)
        self.rejoin()
        assert_equal("closed", n0.getassetdata(ASSET)['transfer_state'])
        assert revoke in n1.getrawmempool(), "the close evicted a valid self-revocation"

        # Transactions are only announced when accepted, so the self-revocation
        # stays on node 1: sync blocks, not mempools
        tip = n0.generate(1)[0]
        sync_blocks(self.nodes)
        self.undo(tip)
        assert revoke in n1.getrawmempool(), "the reorg evicted a valid self-revocation"

        n1.generate(1)
        sync_blocks(self.nodes)
        assert_equal(SELF_REVOKED, self.restriction())

    def verifychain_reconnects(self):
        self.log.info("verifychain level 4 disconnects every block and reconnects them with their freezes...")
        # Reconnecting the unfreezes needs the freeze state of each block's
        # past, not the state at the tip, where the holder is no longer frozen.
        for node in self.nodes:
            assert node.verifychain(4, 0)

    def run_test(self):
        self.setup_asset()
        self.undo_owner_only_unfreeze()
        self.undo_self_only_unfreeze()
        self.rebuilt_chainstate_and_restart()
        self.freeze_evicts_pending_holder_transfer()
        self.self_revocation_survives_close_and_reorg()
        self.verifychain_reconnects()


if __name__ == '__main__':
    DepinRestrictionUndoTest().main()
