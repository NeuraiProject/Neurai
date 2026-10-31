#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Every rule of the unified fork activates at one height (-forkheight).

Mainnet will activate all the rules testnet runs at a single height. Regtest
reproduces it with -forkheight=H. node0 has the fork at H; node1 has it far
away and plays a node that was not upgraded.

- startup: -forkheight validates its value and moves every height; a
  single-rule option given with it still moves that one rule
- tip H-2 (next block below the fork): DEPIN assets, long asset names,
  AuthScript outputs and 512-byte OP_RETURN are refused; a BIP 125 signal
  is accepted; the asset marker is still "rvn"
- tip H-1 (next block is the fork): all of that flips at once, under the
  standard relay policy (-acceptnonstdtxn=0)
- block H: carries the NIP-028 version flag and half the subsidy; the
  node without the fork rejects it, and its own pre-fork block H is
  rejected by the upgraded node (bad-version-nip028)
- reorg below H: the fork transactions leave the mempool, the signalling
  transaction mined at H-1 comes back, and reconsidering restores the same
  UTXO set
"""

from decimal import Decimal

from test_framework.messages import CTransaction, from_hex, to_hex
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    disconnect_nodes,
    sync_blocks,
    wait_until,
)

H = 500
FAR = 1000000
SIGNAL = 0xfffffffd
NIP028_FLAG = 0x40000000
FEE = Decimal("0.01")
DEPIN_NAME = "&DEVICE"
LONG_NAME = "LONGNAME" + "X" * 32  # 40 characters: above the legacy 30, below 120
OP_RETURN_DATA = "ab" * 500        # a 504-byte OP_RETURN script


class UnifiedForkTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # The framework config accepts non-standard transactions; the fork
        # must work under the relay policy of mainnet.
        self.extra_args = [["-assetindex", "-acceptnonstdtxn=0", "-forkheight=%d" % H],
                           ["-assetindex", "-acceptnonstdtxn=0", "-forkheight=%d" % FAR]]

    def run_test(self):
        self.used = set()
        self.test_startup_options()
        self.test_below_the_fork()
        self.test_next_block_is_the_fork()
        self.test_fork_block()
        self.test_reorg_across_the_fork()

    # ---------------------------------------------------------------- helpers

    def utxo(self, node):
        for u in node.listunspent(1):
            key = (u["txid"], u["vout"])
            if key not in self.used and u["spendable"] and u["amount"] > 1:
                self.used.add(key)
                return u
        raise AssertionError("no spendable coin left")

    def signed(self, node, raw):
        result = node.signrawtransaction(raw)
        assert result["complete"]
        return result["hex"]

    def signal_tx(self, node):
        u = self.utxo(node)
        inputs = [{"txid": u["txid"], "vout": u["vout"], "sequence": SIGNAL}]
        return self.signed(node, node.createrawtransaction(inputs, {node.getnewaddress(): u["amount"] - FEE}))

    def op_return_tx(self, node):
        u = self.utxo(node)
        outputs = {"data": OP_RETURN_DATA, node.getnewaddress(): u["amount"] - FEE}
        return self.signed(node, node.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}], outputs))

    def authscript_output_tx(self, node, version):
        """Pays a legacy coin to OP_<version> <32 bytes>."""
        u = self.utxo(node)
        raw = node.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}],
                                        {node.getnewaddress(): u["amount"] - FEE})
        tx = from_hex(CTransaction(), raw)
        tx.vout[0].scriptPubKey = bytes([0x50 + version, 0x20]) + bytes([0x42] * 32)
        return self.signed(node, to_hex(tx))

    def assert_refused(self, node, tx_hex, reason):
        result = node.testmempoolaccept([tx_hex])[0]
        assert not result["allowed"], result
        assert reason in result["reject-reason"], result

    def assert_allowed(self, node, tx_hex):
        result = node.testmempoolaccept([tx_hex])[0]
        assert result["allowed"], result

    def isolate(self):
        for a, b in ((0, 1), (1, 0)):
            disconnect_nodes(self.nodes[a], b)
        wait_until(lambda: not self.nodes[0].getpeerinfo() and not self.nodes[1].getpeerinfo(),
                   err_msg="nodes did not disconnect", timeout=30)

    def coinbase_subsidy(self, node, block_hash, fees):
        block = node.getblock(block_hash, 2)
        coinbase = block["tx"][0]
        return sum(Decimal(str(out["value"])) for out in coinbase["vout"]) - fees

    def mempool_fees(self, node):
        return sum(Decimal(str(entry["fee"])) for entry in node.getrawmempool(True).values())

    # ------------------------------------------------------------------ tests

    def test_startup_options(self):
        self.log.info("-forkheight validates its value and moves every rule")
        self.stop_node(1)
        for value in ("-1", "abc"):
            self.assert_start_raises_init_error(1, ["-forkheight=%s" % value], "Invalid -forkheight")
        self.start_node(1, ["-acceptnonstdtxn=0", "-forkheight=600", "-zkpublictreeheight=7"])
        info = self.nodes[1].getblockchaininfo()
        assert_equal(info["zk_portable_tree"]["activation_height"], 600)
        assert_equal(info["zk_public_tree"]["activation_height"], 7)
        self.restart_node(1, self.extra_args[1])
        connect_nodes_bi(self.nodes, 0, 1)

        info = self.nodes[0].getblockchaininfo()
        assert_equal(info["zk_public_tree"]["activation_height"], H)
        assert_equal(info["zk_portable_tree"]["activation_height"], H)

    def test_below_the_fork(self):
        node0 = self.nodes[0]
        self.log.info("Tip H-2: no fork rule applies to the next block")
        node0.generate(H - 2)
        self.sync_all()
        assert_equal(node0.getblockcount(), H - 2)
        assert_equal(node0.getblockchaininfo()["asset_marker"], "rvn")

        assert_raises_rpc_error(None, "DEPIN assets are not active yet", node0.issue, DEPIN_NAME, 10)
        assert_raises_rpc_error(None, "greater than max length of 31", node0.issue, LONG_NAME, 1)
        self.assert_refused(node0, self.authscript_output_tx(node0, 3), "authscript-output-not-active")
        self.assert_refused(node0, self.op_return_tx(node0), "scriptpubkey")

        self.signal = self.signal_tx(node0)       # mined at H-1
        self.late_signal = self.signal_tx(node0)  # offered when H-1 is the tip
        self.assert_allowed(node0, self.signal)
        self.assert_allowed(node0, self.late_signal)

    def test_next_block_is_the_fork(self):
        node0, node1 = self.nodes
        self.log.info("Tip H-1: every fork rule applies to the next block at once")
        self.signal_txid = node0.sendrawtransaction(self.signal)
        self.fees_before = self.mempool_fees(node0)
        node0.generate(1)
        sync_blocks(self.nodes)
        assert_equal(node0.getblockcount(), H - 1)
        assert self.signal_txid in node0.getblock(node0.getbestblockhash())["tx"]
        assert_equal(node0.getblockchaininfo()["asset_marker"], "xna")
        assert_equal(node1.getblockchaininfo()["asset_marker"], "rvn")

        self.assert_refused(node0, self.late_signal, "bad-txns-rbf-sequence")
        assert_raises_rpc_error(-8, "only signals replaceability", self.signal_tx, node0)

        self.fork_txids = [
            node0.issue(DEPIN_NAME, 10)[0],
            node0.issue(LONG_NAME, 1)[0],
            node0.sendrawtransaction(self.authscript_output_tx(node0, 3)),
        ]
        self.op_return_txid = node0.sendrawtransaction(self.op_return_tx(node0))
        mempool = node0.getrawmempool()
        for txid in self.fork_txids + [self.op_return_txid]:
            assert txid in mempool
        # The node without the fork refuses them.
        assert_raises_rpc_error(None, "DEPIN assets are not active yet", node1.issue, DEPIN_NAME, 10)

    def test_fork_block(self):
        node0, node1 = self.nodes
        self.log.info("Block H: version flag and halved subsidy")
        self.isolate()
        fees = self.mempool_fees(node0)
        fork_hash = node0.generate(1)[0]
        block = node0.getblock(fork_hash)
        assert_equal(block["height"], H)
        assert block["version"] & NIP028_FLAG, hex(block["version"])
        for txid in self.fork_txids + [self.op_return_txid]:
            assert txid in block["tx"]
        pre_fork_hash = node0.getblockhash(H - 1)
        assert not node0.getblock(pre_fork_hash)["version"] & NIP028_FLAG
        subsidy_before = self.coinbase_subsidy(node0, pre_fork_hash, self.fees_before)
        subsidy_after = self.coinbase_subsidy(node0, fork_hash, fees)
        assert_equal(subsidy_after * 2, subsidy_before)
        assert_equal(node0.getassetdata(DEPIN_NAME)["amount"], 10)

        self.log.info("The node without the fork rejects block H")
        reason = node1.submitblock(node0.getblock(fork_hash, False))
        assert reason is not None
        self.log.info("node1 rejected block H: %s", reason)
        assert_equal(node1.getblockcount(), H - 1)

        self.log.info("Its own block H is rejected by the upgraded node")
        old_hash = node1.generate(1)[0]
        assert not node1.getblock(old_hash)["version"] & NIP028_FLAG
        reason = node0.submitblock(node1.getblock(old_hash, False))
        assert reason is not None and reason.startswith("bad-version-nip028"), reason
        assert_equal(node0.getbestblockhash(), fork_hash)

    def test_reorg_across_the_fork(self):
        node0 = self.nodes[0]
        self.log.info("Reorg below H: the fork transactions leave the mempool")
        utxo_before = node0.gettxoutsetinfo()["hash_serialized_2"]
        fork_hash = node0.getblockhash(H)
        pre_fork_hash = node0.getblockhash(H - 1)

        node0.invalidateblock(fork_hash)
        assert_equal(node0.getblockcount(), H - 1)
        mempool = node0.getrawmempool()
        for txid in self.fork_txids:
            assert txid in mempool  # the next block is still H

        node0.invalidateblock(pre_fork_hash)
        assert_equal(node0.getblockcount(), H - 2)
        mempool = node0.getrawmempool()
        for txid in self.fork_txids:
            assert txid not in mempool, txid
        assert self.signal_txid in mempool  # valid again for block H-1

        self.log.info("Reconsidering restores the same chain state")
        node0.reconsiderblock(pre_fork_hash)
        wait_until(lambda: node0.getbestblockhash() == fork_hash,
                   err_msg="reconsiderblock did not restore block H", timeout=60)
        assert_equal(node0.gettxoutsetinfo()["hash_serialized_2"], utxo_before)
        assert_equal(node0.getassetdata(DEPIN_NAME)["amount"], 10)


if __name__ == '__main__':
    UnifiedForkTest().main()
