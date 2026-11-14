#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
The asset state follows the chain state across interrupted flushes.

The coins and the asset state live in separate databases, written one after
the other. Node 0 is stopped at every point where one of them is on disk and
the next one is not, and must come back with the asset state of its chain tip,
equal to node 1's. Every block of the test changes every kind of asset state:
amounts, units, IPFS, balances, restrictions, tags and verifier strings.

- after the coins and before the asset databases;
- between the two asset databases;
- in the middle of the coins (the restart replays blocks);
- with the asset state left on a branch the node reorganised away from, in
  both asset databases or in the restricted one only;
- while it was recovering;
- and it refuses to start, with an actionable message, when a block it needs
  is not on disk.

When the chain state is removed by hand, the asset state is rebuilt with it.
"""

import os
import shutil

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, disconnect_nodes, sync_blocks

DEPIN = "&RECOVER"
PLAIN = "PLAIN"
TAG = "#QUAL"
VERIFIED = "$VERIFY"    # restricted asset whose verifier string changes
FROZEN = "$FREEZE"      # restricted asset with an address that is frozen and unfrozen
LATE = ["$LATEONE", "$LATETWO"]  # restricted assets issued on a branch that is abandoned
IPFS = ["QmcvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8", "QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"]
RECOVERING = "bringing it to the chain state"


class AssetStateRecoveryTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-assetindex']] * self.num_nodes

    # ----------------------------------------------------------------- helpers
    def verifier_of(self, node, asset):
        try:
            return node.getverifierstring(asset)
        except JSONRPCException:
            return None  # the asset does not exist

    def snapshot(self, node):
        """The asset state of a node, with the block it belongs to."""
        return {
            'tip': node.getbestblockhash(),
            # asset database: asset data (amount, units, IPFS) and balances
            'depin': node.getassetdata(DEPIN),
            'plain': node.getassetdata(PLAIN),
            'holder': node.listassetbalancesbyaddress(self.holder),
            'plain_holders': node.listaddressesbyasset(PLAIN),
            # restricted database: restrictions, tags and verifier strings
            'frozen': node.checkaddressrestriction(self.holder, DEPIN),
            'blocked': node.checkdepinvalidity(DEPIN, self.holder)['blocked'],
            'tagged': node.checkaddresstag(self.tagged, TAG),
            'restricted': node.checkaddressrestriction(self.restricted, FROZEN),
            'verifiers': [self.verifier_of(node, asset) for asset in [VERIFIED, FROZEN] + LATE],
        }

    def assert_matches_node1(self):
        n0, n1 = self.nodes
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(self.snapshot(n0), self.snapshot(n1))
        # ...and the state keeps working: another block of changes on top
        self.change_asset_state()
        n0.generate(1)
        self.sync_all()
        assert_equal(self.snapshot(n0), self.snapshot(n1))

    def change_asset_state(self):
        """Pending changes to both asset databases, of every kind a block undoes differently."""
        n0, n1 = self.nodes
        self.changes += 1
        # Asset database: amount, units and IPFS of a reissue (the last two
        # are undone from the block's asset undo data) and a transfer
        n0.reissue(PLAIN, 100, n0.getnewaddress(), "", True, min(self.changes, 8), IPFS[self.changes % 2])
        n0.transfer(PLAIN, 1, self.plain_receiver)
        # Restricted database: a DEPIN owner freeze, a restricted asset
        # freeze, a tag...
        if n1.checkaddressrestriction(self.holder, DEPIN):
            n0.unfreezedepin(DEPIN, self.holder)
        else:
            n0.freezedepin(DEPIN, self.holder)
        if n1.checkaddressrestriction(self.restricted, FROZEN):
            n0.unfreezeaddress(FROZEN, self.restricted)
        else:
            n0.freezeaddress(FROZEN, self.restricted)
        if n1.checkaddresstag(self.tagged, TAG):
            n0.removetagfromaddress(TAG, self.tagged)
        else:
            n0.addtagtoaddress(TAG, self.tagged)
        # ...and both at once: a reissue that also changes the verifier string
        verifier = TAG if n1.getverifierstring(VERIFIED) == "true" else "true"
        n0.reissuerestrictedasset(VERIFIED, 1, self.target, True, verifier)

    def log_size(self):
        return os.path.getsize(os.path.join(self.nodes[0].datadir, "regtest", "debug.log"))

    def log_since(self, offset):
        with open(os.path.join(self.nodes[0].datadir, "regtest", "debug.log"), errors="replace") as log:
            log.seek(offset)
            return log.read()

    def flush_and_crash(self):
        """Ask node 0 for a full flush, which the armed crash point interrupts."""
        n0 = self.nodes[0]
        try:
            n0.gettxoutsetinfo()
        except Exception:
            pass
        n0.wait_until_stopped()

    def restart_recovering(self, expected):
        """Start node 0 again; it must recover exactly the `expected` databases."""
        offset = self.log_size()
        self.start_node(0, self.extra_args[0])
        log = self.log_since(offset)
        for name in ("assets", "restricted assets"):
            recovered = ("The %s database is at block" % name) in log
            assert_equal(recovered, name in expected)
        assert_equal(RECOVERING in log, bool(expected))

    def arm(self, point, height=None):
        args = self.extra_args[0] + ['-assetflushcrashpoint=%d' % point]
        if height is not None:
            args.append('-assetflushcrashheight=%d' % height)
        return args

    # ------------------------------------------------------------------- steps
    def setup_assets(self):
        self.log.info("Issuing a DEPIN asset with a holder and a plain reissuable asset...")
        n0, n1 = self.nodes
        n0.generate(432)
        self.sync_all()
        n0.issue(DEPIN, 100, n0.getnewaddress())
        n0.issue(PLAIN, 1000, n0.getnewaddress())
        n0.generate(1)
        self.sync_all()
        self.holder = n1.getnewaddress()
        self.plain_receiver = n1.getnewaddress()
        n0.transfer(DEPIN, 10, self.holder)
        # Restricted assets: the address that receives them keeps the tag a
        # verifier string may ask for
        self.target = n0.getnewaddress()
        self.tagged = n1.getnewaddress()
        self.restricted = n1.getnewaddress()
        for restricted in [VERIFIED, FROZEN] + LATE:
            n0.issue(restricted[1:])
        n0.issuequalifierasset(TAG, 10)
        n0.generate(1)
        n0.addtagtoaddress(TAG, self.target)
        n0.generate(1)
        for restricted in [VERIFIED, FROZEN]:
            n0.issuerestrictedasset(restricted, 100, "true", self.target)
        n0.generate(1)
        self.sync_all()
        self.changes = 0
        assert_equal(self.snapshot(n0), self.snapshot(n1))

    def interrupted_flush(self, point, expected):
        n0 = self.nodes[0]
        height = n0.getblockcount() + 1
        self.restart_node(0, self.arm(point, height))
        connect_nodes_bi(self.nodes, 0, 1)
        self.change_asset_state()
        n0.generate(1)
        sync_blocks(self.nodes)
        self.flush_and_crash()
        self.restart_recovering(expected)
        self.assert_matches_node1()

    def interrupted_coins_flush(self):
        self.log.info("Stopped in the middle of the coins: the restart replays blocks...")
        n0 = self.nodes[0]
        self.restart_node(0, self.extra_args[0] + ['-dbcrashratio=1', '-dbbatchsize=1'])
        connect_nodes_bi(self.nodes, 0, 1)
        self.change_asset_state()
        n0.generate(1)
        sync_blocks(self.nodes)
        offset = self.log_size()
        self.flush_and_crash()
        assert "Simulating a crash" in self.log_since(offset)
        offset = self.log_size()
        self.start_node(0, self.extra_args[0])
        log = self.log_since(offset)
        assert "Replaying blocks" in log
        assert RECOVERING in log
        self.assert_matches_node1()

    def state_on_an_abandoned_branch(self, point, late):
        """The abandoned block changes every kind of state and issues the restricted asset `late`.

        At point 1 both asset databases are left on that block. At point 2 the
        asset database is written and only the restricted one is left on it,
        so it is undone on its own, with the asset database at the tip."""
        n0, n1 = self.nodes
        disconnect_nodes(n0, 1)
        disconnect_nodes(n1, 0)
        self.change_asset_state()
        n0.issuerestrictedasset(late, 10, "true", self.target)
        abandoned = n0.generate(1)[0]
        assert_equal(n0.getverifierstring(late), "true")
        n0.gettxoutsetinfo()  # full flush: every database is at the block about to be abandoned

        self.restart_node(0, self.arm(point, n0.getblockcount() + 1))
        n1.generate(2)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert abandoned not in [n0.getblockhash(h) for h in range(n0.getblockcount() - 1, n0.getblockcount() + 1)]
        self.flush_and_crash()

        offset = self.log_size()
        self.start_node(0, self.extra_args[0])
        log = self.log_since(offset)
        assert_equal(("The assets database is at block %s" % abandoned) in log, point == 1)
        assert ("The restricted assets database is at block %s" % abandoned) in log
        assert_equal(self.verifier_of(n0, late), None)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(self.snapshot(n0), self.snapshot(n1))
        # The changes of the abandoned block are pending again; confirm them
        n0.generate(1)
        self.sync_all()
        assert_equal(self.snapshot(n0), self.snapshot(n1))

    def interrupted_recovery(self):
        self.log.info("Stopped while recovering: the next start resumes...")
        n0 = self.nodes[0]
        self.restart_node(0, self.arm(1, n0.getblockcount() + 2))
        connect_nodes_bi(self.nodes, 0, 1)
        for _ in range(2):
            self.change_asset_state()
            n0.generate(1)
            sync_blocks(self.nodes)
        self.flush_and_crash()

        offset = self.log_size()
        n0.start(self.arm(3))
        n0.wait_until_stopped()
        log = self.log_since(offset)
        assert RECOVERING in log and "Simulating a crash at asset flush point 3" in log
        assert "database is at the chain state again" not in log

        self.restart_recovering(["assets", "restricted assets"])
        self.assert_matches_node1()

    def missing_block_data(self):
        self.log.info("A block that is needed is not on disk: the node says how to rebuild...")
        n0 = self.nodes[0]
        self.restart_node(0, self.arm(1, n0.getblockcount() + 1))
        connect_nodes_bi(self.nodes, 0, 1)
        self.change_asset_state()
        n0.generate(1)
        sync_blocks(self.nodes)
        self.flush_and_crash()

        undo = os.path.join(n0.datadir, "regtest", "blocks", "rev00000.dat")
        os.rename(undo, undo + ".away")
        offset = self.log_size()
        n0.start(self.extra_args[0], stderr=open(os.devnull, "w"))
        assert n0.process.wait(timeout=120) != 0
        n0.running = False
        n0.process = None
        log = self.log_since(offset)
        assert "does not match the chain state and cannot be brought to it" in log
        assert "-reindex-chainstate" in log

        os.rename(undo + ".away", undo)
        self.restart_recovering(["assets", "restricted assets"])
        self.assert_matches_node1()

    def chain_state_removed(self):
        self.log.info("Chain state removed by hand: the asset state is rebuilt with it...")
        n0 = self.nodes[0]
        self.stop_node(0)
        regtest = os.path.join(n0.datadir, "regtest")
        shutil.rmtree(os.path.join(regtest, "chainstate"))
        offset = self.log_size()
        self.start_node(0, self.extra_args[0])
        assert "rebuilding the asset state with the chain state" in self.log_since(offset)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(self.snapshot(n0), self.snapshot(self.nodes[1]))

    def run_test(self):
        self.setup_assets()
        self.log.info("Stopped after the coins and before the asset databases...")
        self.interrupted_flush(1, ["assets", "restricted assets"])
        self.log.info("Stopped between the two asset databases...")
        self.interrupted_flush(2, ["restricted assets"])
        self.interrupted_coins_flush()
        self.log.info("Asset state left on a branch the node reorganised away from...")
        self.state_on_an_abandoned_branch(1, LATE[0])
        self.log.info("...and only the restricted asset state left on it...")
        self.state_on_an_abandoned_branch(2, LATE[1])
        self.interrupted_recovery()
        self.missing_block_data()
        self.chain_state_removed()


if __name__ == '__main__':
    AssetStateRecoveryTest().main()
