#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""No-RBF sequence rule and the removal of transaction replacement.

From -rbfbanheight (H) a sequence that only signals BIP 125 replaceability makes
a transaction invalid; final sequences, 0xfffffffe and BIP 68 relative locks
stay valid. Transaction replacement no longer exists: a conflict with the
mempool is always rejected.

node0 enforces the rule from H. node1 schedules it far away and plays an
un-upgraded miner.

- startup: -mempoolreplacement=1/fee and -walletrbf=1 are refused, =0 loads
- RPC: bumpfee, bip125-replaceable and the replaceable option are gone; the
  wallet signs with 0xfffffffe
- conflicts are rejected whatever their fee and sequence
- mempool frontier: signals are admitted for H-1, evicted with their
  descendants when H-1 connects, refused afterwards; createrawtransaction
  refuses an explicit signal; relative locks and locktime spends still work
- a block at H with a signal (from node1) is rejected by node0
- a reorg below H admits signals again and reconnecting purges them
- mempool.dat: a saved signal is dropped when the rule applies on restart
- stored blocks: restarting with the rule over a block that was mined before
  it applied refuses to load; -reindex-chainstate and reconsiderblock reject
  the block when they reconnect it, and a full -reindex reaches the same tip
"""

from decimal import Decimal

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    disconnect_nodes,
    sync_blocks,
    sync_mempools,
    wait_until,
)

H = 220
FAR = 1000000
SIGNAL = 0xfffffffd
NON_FINAL = 0xfffffffe
FEE = Decimal("0.01")


class NoRbfTest(NeuraiTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-rbfbanheight=%d" % H], ["-rbfbanheight=%d" % FAR]]

    def run_test(self):
        self.used = set()
        self.test_startup_options()

        node0, node1 = self.nodes
        node0.generate(110)
        sync_blocks(self.nodes)
        for _ in range(5):
            node0.sendtoaddress(node1.getnewaddress(), 100)
        node0.generate(1)
        sync_blocks(self.nodes)

        self.test_wallet_and_rpc_surface()
        self.test_conflicts_before_h()
        self.test_mempool_frontier()
        self.test_block_from_old_miner()
        self.test_reorg_and_mempool_file()
        self.test_stored_blocks()

    # ---------------------------------------------------------------- helpers

    def utxo(self, node):
        for u in node.listunspent(1):
            key = (u["txid"], u["vout"])
            if key not in self.used and u["spendable"] and u["amount"] > 1:
                self.used.add(key)
                return u
        raise AssertionError("no spendable coin left")

    def raw_spend(self, node, u, sequence, fee=FEE, locktime=0):
        inputs = [{"txid": u["txid"], "vout": u["vout"], "sequence": sequence}]
        outputs = {node.getnewaddress(): u["amount"] - fee}
        raw = node.createrawtransaction(inputs, outputs, locktime)
        signed = node.signrawtransaction(raw)
        assert signed["complete"]
        return signed["hex"]

    def accept(self, node, tx_hex):
        return node.testmempoolaccept([tx_hex])[0]

    def assert_refused(self, node, tx_hex, reason):
        result = self.accept(node, tx_hex)
        assert not result["allowed"], result
        assert reason in result["reject-reason"], result
        assert_raises_rpc_error(-26, reason, node.sendrawtransaction, tx_hex)

    def in_mempool(self, node, txid):
        return txid in node.getrawmempool()

    def wait_rejected(self, node, height):
        """The block at `height` is invalid and the chain stops below it."""
        def stopped():
            tips = node.getchaintips()
            return (node.getblockcount() == height - 1 and
                    any(t["status"] == "invalid" and t["height"] >= height for t in tips))
        wait_until(stopped, err_msg="chain did not stop below height %d" % height, timeout=60)

    # ------------------------------------------------------------------ tests

    def test_startup_options(self):
        self.log.info("Retired options refuse to start; =0 is accepted")
        self.stop_node(1)
        replacement = "Transaction replacement (-mempoolreplacement) is no longer supported"
        for args, msg in ((["-mempoolreplacement=1"], replacement),
                          (["-mempoolreplacement"], replacement),
                          (["-mempoolreplacement=fee"], replacement),
                          (["-mempoolreplacement=-optin,fee"], replacement),
                          (["-walletrbf=1"], "-walletrbf is no longer supported"),
                          (["-rbfbanheight=-1"], "Invalid -rbfbanheight"),
                          (["-rbfbanheight=abc"], "Invalid -rbfbanheight")):
            self.assert_start_raises_init_error(1, args, msg)
        self.start_node(1, ["-rbfbanheight=%d" % FAR, "-mempoolreplacement=0", "-nomempoolreplacement", "-walletrbf=0"])
        connect_nodes_bi(self.nodes, 0, 1)

    def test_wallet_and_rpc_surface(self):
        node0 = self.nodes[0]
        self.log.info("The wallet never signals and the RBF RPC surface is gone")
        txid = node0.sendtoaddress(node0.getnewaddress(), 1)
        for vin in node0.getrawtransaction(txid, 1)["vin"]:
            assert_equal(vin["sequence"], NON_FINAL)
        assert "bip125-replaceable" not in node0.gettransaction(txid)
        for entry in node0.listtransactions("*", 50):
            assert "bip125-replaceable" not in entry
        for entry in node0.listsinceblock()["transactions"]:
            assert "bip125-replaceable" not in entry
        assert_raises_rpc_error(-32601, "Method not found", node0.bumpfee, txid)
        assert "bumpfee" not in node0.help()
        assert "replaceable" not in node0.help("sendsilentpayments")
        assert "replaceable" not in node0.help("sendtoaddress")
        assert "replaceable" not in node0.help("fundrawtransaction")
        assert_raises_rpc_error(-1, "sendsilentpayments", node0.sendsilentpayments, [], 1, "UNSET", True)
        node0.generate(1)
        sync_blocks(self.nodes)

    def test_conflicts_before_h(self):
        node0, node1 = self.nodes
        assert node0.getblockcount() + 1 < H - 1
        self.log.info("Before H: a signal is valid, but a conflict is always rejected")
        u = self.utxo(node0)
        first = self.raw_spend(node0, u, SIGNAL)
        first_txid = node0.sendrawtransaction(first)
        sync_mempools(self.nodes)
        assert self.in_mempool(node1, first_txid)
        for seq in (SIGNAL, NON_FINAL, 0xffffffff):
            higher = self.raw_spend(node0, u, seq, fee=Decimal("1"))
            for node in (node0, node1):
                self.assert_refused(node, higher, "txn-mempool-conflict")
        node0.generate(1)
        sync_blocks(self.nodes)
        self.signal_block = node0.getbestblockhash()
        assert first_txid in node0.getblock(self.signal_block)["tx"]

    def test_mempool_frontier(self):
        node0, node1 = self.nodes
        self.log.info("Mempool frontier: admitted for H-1, purged when H-1 connects")
        node0.generate(H - 2 - node0.getblockcount())
        sync_blocks(self.nodes)
        assert_equal(node0.getblockcount(), H - 2)
        assert_equal(node1.getrawmempool(), [])

        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        parent = self.raw_spend(node0, self.utxo(node0), SIGNAL)
        parent_txid = node0.sendrawtransaction(parent)
        out = node0.getrawtransaction(parent_txid, 1)["vout"][0]
        child = self.raw_spend(node0, {"txid": parent_txid, "vout": 0, "amount": out["value"]}, 0xffffffff)
        child_txid = node0.sendrawtransaction(child)
        plain_txid = node0.sendtoaddress(node0.getnewaddress(), 1)
        relative = self.raw_spend(node0, self.utxo(node0), 1)
        relative_txid = node0.sendrawtransaction(relative)

        # node1 mines H-1 without them; node0 receives it.
        node1.generate(1)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(node0.getblockcount(), H - 1)
        assert not self.in_mempool(node0, parent_txid)
        assert not self.in_mempool(node0, child_txid)
        assert self.in_mempool(node0, plain_txid)
        assert self.in_mempool(node0, relative_txid)
        template = node0.getblocktemplate()
        template_txids = [t["txid"] for t in template["transactions"]]
        assert plain_txid in template_txids and relative_txid in template_txids
        assert parent_txid not in template_txids

        self.log.info("From H: signals are refused, relative locks and locktime work")
        self.assert_refused(node0, parent, "bad-txns-rbf-sequence")
        u = self.utxo(node0)
        assert_raises_rpc_error(-8, "only signals replaceability", node0.createrawtransaction,
                                [{"txid": u["txid"], "vout": u["vout"], "sequence": SIGNAL}], {node0.getnewaddress(): 1})
        assert_raises_rpc_error(-8, "only signals replaceability", node0.createrawtransaction,
                                [{"txid": u["txid"], "vout": u["vout"], "sequence": 0x80000000}], {node0.getnewaddress(): 1})
        zero_lock = self.raw_spend(node0, u, 0)
        assert self.accept(node0, zero_lock)["allowed"]
        node0.sendrawtransaction(zero_lock)
        locktime = self.raw_spend(node0, self.utxo(node0), NON_FINAL, locktime=node0.getblockcount())
        assert_equal(node0.decoderawtransaction(locktime)["vin"][0]["sequence"], NON_FINAL)
        node0.sendrawtransaction(locktime)
        default_seq = node0.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}], {node0.getnewaddress(): 1}, 5)
        assert_equal(node0.decoderawtransaction(default_seq)["vin"][0]["sequence"], NON_FINAL)

    def test_block_from_old_miner(self):
        node0, node1 = self.nodes
        self.log.info("A block at H carrying a signal is invalid for node0")
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        signal = self.raw_spend(node1, self.utxo(node1), SIGNAL)
        signal_txid = node1.sendrawtransaction(signal)
        bad_hash = node1.generate(1)[0]
        assert signal_txid in node1.getblock(bad_hash)["tx"]
        assert_equal(node1.getblockcount(), H)
        assert_equal(node0.submitblock(node1.getblock(bad_hash, False)), "bad-txns-rbf-sequence")
        assert_equal(node0.getblockcount(), H - 1)
        # Rejected before it is stored, not only when it would be connected.
        assert_raises_rpc_error(-1, "Block not found on disk", node0.getblock, bad_hash)
        assert {"hash": bad_hash, "status": "invalid"}.items() <= next(t for t in node0.getchaintips() if t["hash"] == bad_hash).items()

        self.log.info("node0 mines H with relative locks and locktime spends")
        good_hash = node0.generate(1)[0]
        assert_equal(len(node0.getrawmempool()), 0)
        assert len(node0.getblock(good_hash)["tx"]) >= 4
        node1.invalidateblock(bad_hash)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(node1.getbestblockhash(), good_hash)
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)

    def test_reorg_and_mempool_file(self):
        node0 = self.nodes[0]
        self.log.info("A reorg below H admits signals again; reconnecting purges them")
        h_minus_1 = node0.getblockhash(H - 1)
        tip = node0.getbestblockhash()
        node0.invalidateblock(h_minus_1)
        assert_equal(node0.getblockcount(), H - 2)
        signal = self.raw_spend(node0, self.utxo(node0), SIGNAL)
        signal_txid = node0.sendrawtransaction(signal)

        self.log.info("mempool.dat: the saved signal is dropped when the rule applies at load")
        self.stop_node(0)
        self.start_node(0, ["-rbfbanheight=%d" % (H - 1)])
        node0 = self.nodes[0]
        assert_equal(node0.getblockcount(), H - 2)
        assert not self.in_mempool(node0, signal_txid)
        self.stop_node(0)
        self.start_node(0, ["-rbfbanheight=%d" % H])
        node0 = self.nodes[0]
        node0.sendrawtransaction(signal)
        assert self.in_mempool(node0, signal_txid)

        node0.reconsiderblock(h_minus_1)
        assert_equal(node0.getbestblockhash(), tip)
        assert not self.in_mempool(node0, signal_txid)
        self.assert_refused(node0, signal, "bad-txns-rbf-sequence")

        self.log.info("The wallet keeps working after H")
        txid = node0.sendtoaddress(node0.getnewaddress(), 1)
        node0.generate(1)
        assert txid in node0.getblock(node0.getbestblockhash())["tx"]

    def test_stored_blocks(self):
        bad_hash = self.signal_block
        bad_height = self.nodes[0].getblock(bad_hash)["height"]
        tip = self.nodes[0].getbestblockhash()

        self.log.info("Startup: stored blocks are checked against a lower height once")
        self.stop_node(0)
        self.start_node(0, ["-rbfbanheight=%d" % (bad_height + 1)])
        assert_equal(self.nodes[0].getbestblockhash(), tip)
        self.stop_node(0)
        self.assert_start_raises_init_error(
            0, ["-rbfbanheight=%d" % bad_height],
            "Block %s at height %d breaks the no-RBF sequence rule" % (bad_hash, bad_height))

        self.log.info("-reindex-chainstate reconnects the stored block and rejects it")
        self.start_node(0, ["-rbfbanheight=%d" % bad_height, "-reindex-chainstate"])
        node0 = self.nodes[0]
        self.wait_rejected(node0, bad_height)

        self.log.info("reconsiderblock reconnects it from disk and rejects it again")
        node0.reconsiderblock(bad_hash)
        self.wait_rejected(node0, bad_height)
        self.stop_node(0)
        self.start_node(0, ["-rbfbanheight=%d" % bad_height])
        self.wait_rejected(self.nodes[0], bad_height)

        self.log.info("A full -reindex, through AcceptBlock, stops at the same block")
        self.stop_node(1)
        self.start_node(1, ["-rbfbanheight=%d" % bad_height, "-reindex"])
        self.wait_rejected(self.nodes[1], bad_height)
        assert_equal(self.nodes[1].getbestblockhash(), self.nodes[0].getbestblockhash())


if __name__ == '__main__':
    NoRbfTest().main()
