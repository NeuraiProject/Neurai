#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Pending DEPIN owner freezes and unfreezes follow the tip.

Node 0 owns the DEPIN asset, node 1 holds it. An owner operation on an address
is valid against the restriction state of that address at the tip:

- a second pending operation on the same (asset, address) is not accepted;
- when a reorg undoes the freeze an unfreeze was built on, the unfreeze leaves
  the mempool and block templates stay valid;
- when the address is still self-revoked after that reorg, the unfreeze is
  still valid and stays.
"""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    disconnect_nodes,
    sync_blocks,
    sync_mempools,
)

ASSET = "&DEVICE"

CLEAN = (False, False)        # (owner frozen, blocked)
OWNER_FROZEN = (True, True)
SELF_REVOKED = (False, True)


class DepinOwnerOpsMempoolTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-assetindex']] * self.num_nodes

    # ----------------------------------------------------------------- helpers
    def restriction(self):
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

    def assert_templates(self):
        for node in self.nodes:
            node.getblocktemplate()

    def isolate(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)

    def reorg_node0(self):
        """Node 1 builds a longer chain without node 0's last block; node 0 follows it.

        The transactions of the abandoned block return to node 0's mempool. An
        invalidateblock would not do: wallet transactions are locked to the
        height they were created at and would simply stop being final."""
        self.nodes[1].generate(2)
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
        n0.issue(ASSET, 100, n0.getnewaddress())
        self.mine(n0)
        self.holder_address = n1.getnewaddress()
        n0.transfer(ASSET, 10, self.holder_address)
        self.mine(n0)
        assert_equal(CLEAN, self.restriction())

    def second_pending_operation_is_refused(self):
        self.log.info("A second pending owner operation on the same address is refused...")
        n0 = self.nodes[0]
        self.freeze_tx = n0.freezedepin(ASSET, self.holder_address)[0]
        assert_raises_rpc_error(None, "bad-txns-depin-owner-change-already-in-mempool",
                                n0.freezedepin, ASSET, self.holder_address)
        assert_equal(n0.getrawmempool(), [self.freeze_tx])

        # A cleared mempool holds no pending operation: the same one is accepted again
        raw = n0.gettransaction(self.freeze_tx)['hex']
        n0.clearmempool()
        assert_equal(n0.getrawmempool(), [])
        assert_equal(n0.sendrawtransaction(raw), self.freeze_tx)
        self.mine(n0)
        assert_equal(OWNER_FROZEN, self.restriction())
        self.assert_templates()

        n0.unfreezedepin(ASSET, self.holder_address)
        self.mine(n0)
        assert_equal(CLEAN, self.restriction())

    def unfreeze_leaves_when_reorg_undoes_the_freeze(self):
        self.log.info("An unfreeze leaves the mempool when a reorg undoes its freeze...")
        n0 = self.nodes[0]
        self.isolate()
        freeze = n0.freezedepin(ASSET, self.holder_address)[0]
        n0.generate(1)
        assert n0.checkaddressrestriction(self.holder_address, ASSET)
        unfreeze = n0.unfreezedepin(ASSET, self.holder_address)[0]
        assert unfreeze in n0.getrawmempool()

        self.reorg_node0()
        assert_equal(CLEAN, self.restriction())
        pool = n0.getrawmempool()
        assert freeze in pool, "the freeze did not return to the mempool"
        assert unfreeze not in pool, "an unfreeze of an active address stayed in the mempool"
        n0.getblocktemplate()

        block = self.mine(n0)
        assert freeze in n0.getblock(block)['tx']
        assert_equal(OWNER_FROZEN, self.restriction())

        self.log.info("...and is valid again once the freeze is confirmed...")
        n0.sendrawtransaction(n0.gettransaction(unfreeze)['hex'])
        self.mine(n0)
        assert_equal(CLEAN, self.restriction())

    def unfreeze_stays_while_self_revoked(self):
        self.log.info("An unfreeze stays when the address is still self-revoked after the reorg...")
        n0, n1 = self.nodes
        n1.selfrevokedepin(ASSET)
        sync_mempools(self.nodes)
        self.mine(n0)
        assert_equal(SELF_REVOKED, self.restriction())

        self.isolate()
        freeze = n0.freezedepin(ASSET, self.holder_address)[0]
        n0.generate(1)
        unfreeze = n0.unfreezedepin(ASSET, self.holder_address)[0]

        self.reorg_node0()
        assert_equal(SELF_REVOKED, self.restriction())
        pool = n0.getrawmempool()
        assert freeze in pool and unfreeze in pool, "a valid unfreeze left the mempool"
        n0.getblocktemplate()

        block = self.mine(n0)
        confirmed = n0.getblock(block)['tx']
        assert freeze in confirmed and unfreeze in confirmed
        assert_equal(CLEAN, self.restriction())

    def run_test(self):
        self.setup_asset()
        self.second_pending_operation_is_refused()
        self.unfreeze_leaves_when_reorg_undoes_the_freeze()
        self.unfreeze_stays_while_self_revoked()


if __name__ == '__main__':
    DepinOwnerOpsMempoolTest().main()
