#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
DEPIN transfer state (closed / open / sealed) on real nodes.

Node 0 issues and owns the DEPIN asset, node 1 is a plain holder. The test
walks the state machine through the wallet RPCs (opendepin / closedepin /
sealdepin), checks holder transfers in every state, the mempool rules (one
pending operation per asset, never inserted when rejected, replacement
allowed, eviction on close), reorgs after every transition with
invalidateblock, and the activation frontier with -depinstateheight.
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
FORK_HEIGHT = 470  # room after asset activation at 432


class DepinTransferStateTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # -walletrbf so the wallet's state operations signal BIP125 and the
        # replacement case below can be exercised
        # -mempoolreplacement is off by default; the replacement case needs it
        self.extra_args = [['-assetindex', '-walletrbf=1', '-mempoolreplacement=1',
                            '-depinstateheight=' + str(FORK_HEIGHT)]] * self.num_nodes

    # ----------------------------------------------------------------- helpers
    def state(self, node):
        return node.getassetdata(ASSET)['transfer_state']

    def mine(self, node, n=1):
        node.generate(n)
        self.sync_all()

    def holder_balance(self, node, address):
        balances = node.listassetbalancesbyaddress(address)
        return balances.get(ASSET, 0)

    def holder_transfer(self, qty, to_address):
        """Node 1 moves qty units; the asset change returns to the holder address
        so its balance stays observable (transfer params: asset, qty, to, message,
        expire_time, xna_change_address, asset_change_address)."""
        return self.nodes[1].transfer(ASSET, qty, to_address, "", 0, "", self.holder_address)[0]

    def undo_tip(self, node):
        """Disconnect the tip on every node the same way (the chain stays in sync)."""
        tip = node.getbestblockhash()
        for n in self.nodes:
            n.invalidateblock(tip)
        sync_blocks(self.nodes)
        return tip

    # ------------------------------------------------------------------- steps
    def activate_assets(self):
        self.log.info("Activating assets...")
        n0, n1 = self.nodes
        n0.generate(1)
        self.sync_all()
        n0.generate(431)
        self.sync_all()
        assert_equal("active", n0.getblockchaininfo()['bip9_softforks']['assets']['status'])
        n0.sendtoaddress(n1.getnewaddress(), 500)
        self.mine(n0)

    def issue_and_distribute(self):
        self.log.info("Issuing the DEPIN asset and handing 5 units to the holder...")
        n0, n1 = self.nodes
        self.owner_address = n0.getnewaddress()
        n0.issue(ASSET, 100, self.owner_address)
        self.mine(n0)
        assert_equal("closed", self.state(n0))
        assert_equal("closed", self.state(n1))

        self.holder_address = n1.getnewaddress()
        n0.transfer(ASSET, 5, self.holder_address)
        self.mine(n0)
        assert_equal(5, self.holder_balance(n1, self.holder_address))

    def before_activation(self):
        self.log.info("Before the activation height every state operation is rejected...")
        n0 = self.nodes[0]
        assert n0.getblockcount() + 1 < FORK_HEIGHT
        assert_raises_rpc_error(-32600, "not active", n0.opendepin, ASSET)
        # A holder cannot move it either (soulbound)
        n1 = self.nodes[1]
        assert_raises_rpc_error(None, "Wallet doesn't have owner token", self.holder_transfer, 1, n0.getnewaddress())

        # Frontier: the operation is valid for the first time when the next block is H
        n0.generate(FORK_HEIGHT - 2 - n0.getblockcount())
        self.sync_all()
        assert_equal(FORK_HEIGHT - 1, n0.getblockcount() + 1)
        assert_raises_rpc_error(-32600, "not active", n0.opendepin, ASSET)
        self.mine(n0)
        assert_equal(FORK_HEIGHT, n0.getblockcount() + 1)

    def open_and_holder_transfer(self):
        self.log.info("opendepin, then a holder transfer with no owner token...")
        n0, n1 = self.nodes

        # Not a transition from closed
        assert_raises_rpc_error(-32600, "bad-txns-depin-state-already-closed", n0.closedepin, ASSET)
        # Only the owner can do it
        assert_raises_rpc_error(None, "Wallet doesn't have asset", n1.opendepin, ASSET)

        txid = n0.opendepin(ASSET)[0]
        assert txid in n0.getrawmempool()
        # Still closed until it confirms
        assert_equal("closed", self.state(n0))
        assert_raises_rpc_error(-26, "already in the mempool", n0.closedepin, ASSET)
        self.mine(n0)
        assert_equal("open", self.state(n0))
        assert_equal("open", self.state(n1))

        # Holder moves 2 units to a fresh address of node 0 without any owner token
        self.receiver_address = n0.getnewaddress()
        holder_txid = self.holder_transfer(2, self.receiver_address)
        sync_mempools(self.nodes)
        assert holder_txid in n0.getrawmempool()
        self.mine(n1)
        assert_equal(3, self.holder_balance(n1, self.holder_address))
        assert_equal(2, self.holder_balance(n0, self.receiver_address))

        # Opening twice is not a transition
        assert_raises_rpc_error(-32600, "bad-txns-depin-state-already-open", n0.opendepin, ASSET)
        # Sealing an open asset is not a transition either
        assert_raises_rpc_error(-32600, "bad-txns-depin-state-seal-requires-closed", n0.sealdepin, ASSET)

    def frozen_holder_cannot_move_while_open(self):
        self.log.info("While open, a frozen address cannot move the asset; the owner can...")
        n0, n1 = self.nodes
        n0.freezedepin(ASSET, self.holder_address)
        self.mine(n0)
        assert_raises_rpc_error(-4, "bad-txns-depin-transfer-from-restricted-address",
                                self.holder_transfer, 1, n0.getnewaddress())
        n0.unfreezedepin(ASSET, self.holder_address)
        self.mine(n0)
        self.holder_transfer(1, self.receiver_address)
        sync_mempools(self.nodes)
        self.mine(n1)
        assert_equal(2, self.holder_balance(n1, self.holder_address))
        assert_equal(3, self.holder_balance(n0, self.receiver_address))

    def close_evicts_pending_holder_transfers(self):
        self.log.info("closedepin evicts pending holder transfers, including a chained one...")
        n0, n1 = self.nodes

        # A close and a holder transfer in the SAME block are both valid (the
        # transfer sees the tip state, still open), so a miner holding both
        # would simply confirm them together. Eviction is about transfers
        # still pending when the close confirms: keep them on node 1 only,
        # mine the close on node 0 and let node 1 receive that block.
        disconnect_nodes(n0, 1)
        disconnect_nodes(n1, 0)

        # Two chained holder transfers in node 1's mempool (the second spends the first)
        fresh = n1.getnewaddress()
        first = self.holder_transfer(2, fresh)
        second = n1.transfer(ASSET, 2, n1.getnewaddress())[0]
        assert first in n1.getrawmempool() and second in n1.getrawmempool()
        assert first not in n0.getrawmempool()

        close_txid = n0.closedepin(ASSET)[0]
        n0.generate(1)
        assert_equal("closed", self.state(n0))
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal("closed", self.state(n1))
        assert close_txid not in n0.getrawmempool()
        pool = n1.getrawmempool()
        assert first not in pool and second not in pool, "holder transfers survived the close"
        # Both holder transfers were dropped, nothing moved
        assert_equal(2, self.holder_balance(n1, self.holder_address))
        # The wallet does not learn about mempool evictions on its own; release
        # the coins those two transactions were spending
        n1.abandontransaction(first)

        # Closed again: a holder transfer is rejected outright
        assert_raises_rpc_error(None, "Wallet doesn't have owner token", self.holder_transfer, 1, n0.getnewaddress())

    def raw_state_operation(self, node, key, owner_txid, owner_vout, fee, sequence=None):
        """Build, sign and send a state operation as a raw transaction: the
        owner token input plus one XNA input for the fee, the owner token and
        the state output at a fresh address, XNA change at another. `sequence`
        lets the transaction signal BIP125 (the wallet never does)."""
        utxo = next(u for u in node.listunspent(1) if u['amount'] >= 10)
        inputs = [{"txid": owner_txid, "vout": owner_vout},
                  {"txid": utxo['txid'], "vout": utxo['vout']}]
        if sequence is not None:
            for txin in inputs:
                txin["sequence"] = sequence
        outputs = {
            node.getnewaddress(): {key: {"asset_name": ASSET}},
            node.getnewaddress(): round(utxo['amount'] - fee, 8),
        }
        signed = node.signrawtransaction(node.createrawtransaction(inputs, outputs))['hex']
        return node.sendrawtransaction(signed)

    def mempool_one_operation_per_asset(self):
        self.log.info("One pending state operation per asset in the mempool...")
        n0 = self.nodes[0]
        assert_equal("closed", self.state(n0))
        assert_equal([], n0.getrawmempool())

        # The pending OPEN is a raw transaction signalling BIP125, so the
        # replacement case below can be exercised (the wallet does not opt in)
        owner_txid, owner_vout = self.owner_outpoint(n0)
        open_txid = self.raw_state_operation(n0, "open_depin", owner_txid, owner_vout, 1, sequence=0xfffffffd)
        assert_equal([open_txid], n0.getrawmempool())

        # A second operation, chained on the pending owner output, is rejected and
        # never enters the pool (the wallet refuses first; the raw path is judged
        # by the mempool itself, including under testmempoolaccept). It has to
        # be a seal: judged against the tip, still closed, a close would fail
        # earlier as a null transition.
        assert_raises_rpc_error(-26, "already in the mempool", n0.closedepin, ASSET)
        raw = n0.createrawtransaction(
            [{"txid": open_txid, "vout": self.owner_vout(n0, open_txid)}],
            {n0.getnewaddress(): {"seal_depin": {"asset_name": ASSET}}})
        funded = n0.fundrawtransaction(raw)['hex']
        signed = n0.signrawtransaction(funded)['hex']
        result = n0.testmempoolaccept([signed])[0]
        assert_equal(False, result['allowed'])
        assert "bad-txns-depin-state-change-already-in-mempool" in result['reject-reason']
        assert_raises_rpc_error(-26, "bad-txns-depin-state-change-already-in-mempool", n0.sendrawtransaction, signed)
        assert_equal([open_txid], n0.getrawmempool())

        # A replacement of the pending operation (same inputs, higher fee) is allowed
        original = n0.decoderawtransaction(n0.getrawtransaction(open_txid))
        inputs = [{"txid": vin['txid'], "vout": vin['vout'], "sequence": 0xfffffffd} for vin in original['vin']]
        xna_change = [vout for vout in original['vout']
                      if vout['value'] > 0 and 'asset' not in vout['scriptPubKey']]
        assert_equal(1, len(xna_change))
        bumped = n0.createrawtransaction(inputs, {
            n0.getnewaddress(): {"open_depin": {"asset_name": ASSET}},
            xna_change[0]['scriptPubKey']['addresses'][0]: round(xna_change[0]['value'] - 1, 8),
        })
        replacement = n0.sendrawtransaction(n0.signrawtransaction(bumped)['hex'])
        assert_equal([replacement], n0.getrawmempool())

        # Once the pending operation is gone (mined), the next one enters
        self.mine(n0)
        assert_equal("open", self.state(n0))
        close_txid = n0.closedepin(ASSET)[0]
        assert close_txid in n0.getrawmempool()
        self.mine(n0)
        assert_equal("closed", self.state(n0))
        assert_equal([], n0.getrawmempool())

    def owner_outpoint(self, node):
        """The (txid, vout) currently holding the owner token in node's wallet."""
        for utxo in node.listmyassets(ASSET + '!', True)[ASSET + '!']['outpoints']:
            return utxo['txid'], utxo['vout']
        raise AssertionError("owner token not found in the wallet")

    def owner_vout(self, node, txid):
        tx = node.decoderawtransaction(node.getrawtransaction(txid))
        for vout in tx['vout']:
            asset = vout['scriptPubKey'].get('asset')
            if asset and asset.get('name') == ASSET + '!':
                return vout['n']
        raise AssertionError("owner token output not found in " + txid)

    def reorg_after_every_transition(self):
        self.log.info("invalidateblock after every transition restores the previous state...")
        n0, n1 = self.nodes
        assert_equal("closed", self.state(n0))

        # OPEN then undo: closed again, the holder is soulbound again, and the
        # operation itself is resurrected into the mempool (still a valid
        # transition from closed) so the next block simply replays it
        open_txid = n0.opendepin(ASSET)[0]
        self.mine(n0)
        assert_equal("open", self.state(n1))
        self.undo_tip(n0)
        assert_equal("closed", self.state(n0))
        assert_equal("closed", self.state(n1))
        assert open_txid in n0.getrawmempool()
        assert_raises_rpc_error(None, "Wallet doesn't have owner token", self.holder_transfer, 1, n0.getnewaddress())
        self.mine(n0)
        assert_equal("open", self.state(n1))

        # CLOSE then undo: open again; a holder transfer validates and is mined
        # next to the resurrected close (same-block snapshot semantics)
        close_txid = n0.closedepin(ASSET)[0]
        self.mine(n0)
        assert_equal("closed", self.state(n1))
        self.undo_tip(n0)
        assert_equal("open", self.state(n0))
        assert_equal("open", self.state(n1))
        assert close_txid in n0.getrawmempool()
        self.holder_transfer(1, self.receiver_address)
        sync_mempools(self.nodes)
        self.mine(n1)
        assert_equal("closed", self.state(n0))
        assert_equal(1, self.holder_balance(n1, self.holder_address))

        # SEAL then undo: closed again, the seal resurrected and still valid
        seal_txid = n0.sealdepin(ASSET)[0]
        self.mine(n0)
        assert_equal("sealed", self.state(n1))
        self.undo_tip(n0)
        assert_equal("closed", self.state(n0))
        assert_equal("closed", self.state(n1))
        assert seal_txid in n0.getrawmempool()

        # Undo the close as well: open, and the pending seal is no longer a
        # valid transition, so the reorg drops it while the close survives
        self.undo_tip(n0)
        assert_equal("open", self.state(n0))
        assert_equal("open", self.state(n1))
        for n in self.nodes:
            pool = n.getrawmempool()
            assert seal_txid not in pool
            assert close_txid in pool
        # The wallet still holds the dropped seal as an unconfirmed spend
        n0.abandontransaction(seal_txid)

        # Mining again replays the close (and the holder transfer)
        self.mine(n0)
        assert_equal("closed", self.state(n1))
        assert_equal(1, self.holder_balance(n1, self.holder_address))

    def seal_is_final(self):
        self.log.info("sealdepin is irreversible...")
        n0, n1 = self.nodes
        assert_equal("closed", self.state(n0))
        n0.sealdepin(ASSET)
        self.mine(n0)
        assert_equal("sealed", self.state(n0))
        assert_equal("sealed", self.state(n1))
        for op in (n0.opendepin, n0.closedepin, n0.sealdepin):
            assert_raises_rpc_error(-32600, "bad-txns-depin-state-sealed", op, ASSET)
        # Soulbound: the holder cannot move it, the owner still can
        assert_raises_rpc_error(None, "Wallet doesn't have owner token", self.holder_transfer, 1, n0.getnewaddress())
        n0.transfer(ASSET, 1, n1.getnewaddress())
        self.mine(n0)

    def restart_keeps_state(self):
        self.log.info("The state survives a restart (database)...")
        self.restart_node(0, self.extra_args[0])
        assert_equal("sealed", self.state(self.nodes[0]))

    def run_test(self):
        self.activate_assets()
        self.issue_and_distribute()
        self.before_activation()
        self.open_and_holder_transfer()
        self.frozen_holder_cannot_move_while_open()
        self.close_evicts_pending_holder_transfers()
        self.mempool_one_operation_per_asset()
        self.reorg_after_every_transition()
        self.seal_is_final()
        self.restart_keeps_state()


if __name__ == '__main__':
    DepinTransferStateTest().main()
