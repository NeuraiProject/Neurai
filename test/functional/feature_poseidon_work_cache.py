#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The script execution cache cannot hide Poseidon work from a block budget.

A node that admitted a transaction to its mempool stores the result of its
scripts with the Poseidon work they measured, and skips them when a block
brings that transaction, charging the recorded work instead. The block budget
(200,000 permutations) must add up the same either way:

- node0 (miner) and node1 hold every transaction in their mempool (warm);
  node2 and node3 only receive blocks (cold). Each pair has one node with
  four script threads and one with a single thread.
- A block of 200,001 permutations is rejected by all four with
  bad-blk-poseidon-work, and none of them moves its tip.
- A block of 200,000 permutations with the same transactions is accepted.
"""

import hashlib

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.mininode import COutPoint, CTxIn, CTxInWitness
from test_framework.script import CScript, CTransaction, CTxOut, OP_TRUE
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, bytes_to_hex_str, connect_nodes, disconnect_nodes, sync_blocks,
                                 wait_until)

COIN = 100000000
VALUE = 2 * COIN
FEE = COIN // 10
INPUTS_PER_TX = 40   # 40 inputs x 500 calls = 20,000, the standard limit per transaction
HEAVY_TXS = 10       # 10 x 20,000 = 200,000, the block limit


def sha256(data):
    return hashlib.sha256(data).digest()


def authscript(script):
    """Native AuthScript v1 output without an authentication key."""
    tag = sha256(b'NeuraiAuthScript')
    return CScript(b'\x51\x20' + sha256(tag + tag + b'\x01\x00' + sha256(script)))


# OP_POSEIDON (0xc9) n times on the empty element, then OP_DROP OP_TRUE: one
# permutation per call.
HEAVY = bytes([0xc9]) * 500 + bytes([0x75, 0x51])
LIGHT = bytes([0xc9, 0x75, 0x51])


class PoseidonWorkCacheTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [["-par=4"], ["-par=1"], ["-par=1", "-blocksonly=1"], ["-par=4", "-blocksonly=1"]]

    def setup_network(self):
        self.setup_nodes()
        for i in range(1, self.num_nodes):
            connect_nodes(self.nodes[0], i)

    def build_block(self, txs):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        header = node.getblockheader(tip)
        template = node.getblocktemplate({"rules": ["segwit"]})
        coinbase = create_coinbase(header["height"] + 1)
        coinbase.vout[0].nValue = template["coinbasevalue"] - sum(t["fee"] for t in template["transactions"])
        coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, header["time"] + 1)
        block.nVersion = template["version"]
        block.nBits = int(template["bits"], 16)
        block.vtx.extend(txs)
        add_witness_commitment(block)
        block.solve()
        return block

    def spend(self, outpoints, script, pay):
        tx = CTransaction()
        for txid, n in outpoints:
            tx.vin.append(CTxIn(COutPoint(txid, n), b""))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00', b'', script]
        tx.vout.append(CTxOut(len(outpoints) * VALUE - FEE, pay))
        tx.rehash()
        return tx

    def run_test(self):
        node = self.nodes[0]
        node.generate(1)  # leave initial block download

        self.log.info("Fund 400 outputs that cost 500 permutations to spend, and one that costs 1")
        block = self.build_block([])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        coinbase = block.vtx[0]
        node.generate(100)
        heavy_outputs = HEAVY_TXS * INPUTS_PER_TX
        funding = CTransaction()
        funding.vin.append(CTxIn(COutPoint(coinbase.x16r, 0), b""))
        funding.vout = [CTxOut(VALUE, authscript(HEAVY)) for _ in range(heavy_outputs)]
        funding.vout.append(CTxOut(VALUE, authscript(LIGHT)))
        funding.vout.append(CTxOut(coinbase.vout[0].nValue - (heavy_outputs + 1) * VALUE - COIN, CScript([OP_TRUE])))
        funding.rehash()
        block = self.build_block([funding])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        sync_blocks(self.nodes)

        self.log.info("Admit 10 transactions of 20,000 permutations and one of 1 to the mempool")
        pay = CScript(bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"]))
        heavy = [self.spend([(funding.x16r, k * INPUTS_PER_TX + i) for i in range(INPUTS_PER_TX)], HEAVY, pay)
                 for k in range(HEAVY_TXS)]
        light = self.spend([(funding.x16r, heavy_outputs)], LIGHT, pay)
        for tx in heavy + [light]:
            node.sendrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()))
        assert_equal(node.getmempoolentry(heavy[0].hash)["poseidonwork"], 20000)
        assert_equal(node.getmempoolentry(light.hash)["poseidonwork"], 1)
        wait_until(lambda: len(self.nodes[1].getrawmempool()) == HEAVY_TXS + 1, err_msg="relay to node1", timeout=180)
        for cold in self.nodes[2:]:
            assert_equal(cold.getrawmempool(), [])

        # Both blocks are built while node0 still has peers (getblocktemplate
        # needs them); the over-budget one must not reach the others by relay.
        over = self.build_block(heavy + [light])
        exact = self.build_block(heavy)
        tip = node.getbestblockhash()
        # Blocks are announced before their scripts run, so a connected peer
        # would already have seen (and rejected) it.
        for i in range(1, self.num_nodes):
            disconnect_nodes(self.nodes[0], i)
        wait_until(lambda: all(n.getpeerinfo() == [] for n in self.nodes), err_msg="disconnect", timeout=60)

        self.log.info("200,001 permutations: rejected by warm and cold nodes alike")
        raw = bytes_to_hex_str(over.serialize(with_witness=True))
        for i, n in enumerate(self.nodes):
            assert_equal(n.submitblock(raw), "bad-blk-poseidon-work")
            assert_equal(n.getbestblockhash(), tip)
            self.log.info("node%d (%s) rejected it", i, "warm" if i < 2 else "cold")

        self.log.info("200,000 permutations: accepted, and every node follows")
        assert_equal(node.submitblock(bytes_to_hex_str(exact.serialize(with_witness=True))), None)
        for i in range(1, self.num_nodes):
            connect_nodes(self.nodes[0], i)
        sync_blocks(self.nodes, timeout=180)
        for n in self.nodes:
            assert_equal(n.getbestblockhash(), exact.hash)
        assert_equal(node.getrawmempool(), [light.hash])


if __name__ == '__main__':
    PoseidonWorkCacheTest().main()
