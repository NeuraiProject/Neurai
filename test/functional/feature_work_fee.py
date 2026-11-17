#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The script work of a transaction counts in its virtual size (A1).

From the NIP-028 height on, each Poseidon permutation weighs 80 and each
OP_CHECKASSETAUTH unit 36: a block's budget of either weighs as much as a full
block. The virtual size is the largest of the weight, the sigops and the work.
A transaction of 5,000 permutations (10 inputs x 500 OP_POSEIDON) weighs
400,000 for its work: 100,000 vbytes, and a minimum relay fee of 1 XNA.

- Below the height the work does not count.
- Crossing the height, in either direction, evicts the entries sized under the
  other rule.
- From the height a fee below the size with work is refused after the scripts
  ran; exactly the minimum is accepted; prioritisetransaction counts.
- testmempoolaccept reports the virtual size only when it is final, also for
  a short fee, so a client can price it.
- The size with work is what the package sizes and limits use, what block
  assembly orders by, and what a restart (mempool.dat) and a reorganisation
  restore. Block assembly takes the room of a transaction from its weight.
"""

import hashlib
import os

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.mininode import COutPoint, CTxIn, CTxInWitness
from test_framework.script import CScript, CTransaction, CTxOut, OP_TRUE
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, assert_raises_rpc_error, bytes_to_hex_str, connect_nodes, sync_blocks,
                                 wait_until)

FORK_HEIGHT = 200
COIN = 100000000
VALUE = COIN
HEAVY = bytes([0xc9]) * 500 + bytes([0x75, 0x51])   # 500 permutations
LIGHT = bytes([0xc9, 0x75, 0x51])                    # 1 permutation
HEAVY_VSIZE = 100000                                 # 10 inputs: 5,000 x 80 / 4
MIN_FEE = 100000000                                  # 0.01 XNA per kvB


def sha256(data):
    return hashlib.sha256(data).digest()


def authscript(script):
    tag = sha256(b'NeuraiAuthScript')
    return CScript(b'\x51\x20' + sha256(tag + tag + b'\x01\x00' + sha256(bytes(script))))


class WorkFeeTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        fork = "-blocktimereductionheight=%d" % FORK_HEIGHT
        # A package of two transactions with work goes over 150 kvB. node1
        # builds blocks of 150,000 weight units: a transaction with work
        # weighs about 7,000, and 400,000 with its work.
        self.extra_args = [[fork, "-limitancestorsize=150", "-limitdescendantsize=150"],
                           [fork, "-blockmaxweight=150000"]]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

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

    def take(self, script, count):
        coins = [c for c in self.coins if c[1] == script][:count]
        assert_equal(len(coins), count)
        for c in coins:
            self.coins.remove(c)
        return coins

    def spend(self, coins, fee, outputs=()):
        """coins: list of (outpoint, script), each worth VALUE. Pays `outputs`
        (spk, value) and the rest, less the fee, to node0."""
        tx = CTransaction()
        for (txid, n), script in coins:
            tx.vin.append(CTxIn(COutPoint(txid, n), b""))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00', b'', script]
        for spk, value in outputs:
            tx.vout.append(CTxOut(value, spk))
        tx.vout.append(CTxOut(len(coins) * VALUE - fee - sum(value for _, value in outputs), self.pay))
        tx.rehash()
        return tx

    def test(self, tx, node=None):
        node = node or self.nodes[0]
        return node.testmempoolaccept([bytes_to_hex_str(tx.serialize_with_witness())])[0]

    def send(self, tx):
        return self.nodes[0].sendrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()))

    def run_test(self):
        node = self.nodes[0]
        node.generate(1)
        block = self.build_block([])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        coinbase = block.vtx[0]
        node.generate(100)
        funding = CTransaction()
        funding.vin.append(CTxIn(COutPoint(coinbase.x16r, 0), b""))
        funding.vout = [CTxOut(VALUE, authscript(HEAVY)) for _ in range(60)]
        funding.vout += [CTxOut(VALUE, authscript(LIGHT)) for _ in range(10)]
        funding.vout.append(CTxOut(coinbase.vout[0].nValue - len(funding.vout) * VALUE - COIN, CScript([OP_TRUE])))
        funding.rehash()
        block = self.build_block([funding])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        sync_blocks(self.nodes)
        self.coins = [((funding.x16r, n), HEAVY) for n in range(60)]
        self.coins += [((funding.x16r, 60 + n), LIGHT) for n in range(10)]
        self.pay = CScript(bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"]))

        heavy_coins = self.take(HEAVY, 10)
        cheap = self.spend(heavy_coins, COIN // 20)   # 0.05 XNA: enough for the weight alone

        self.log.info("Below the NIP-028 height the work does not count in the size")
        assert node.getblockcount() + 1 < FORK_HEIGHT
        result = self.test(cheap)
        assert_equal(result["allowed"], True)
        weight_vsize = result["vsize"]
        assert weight_vsize < 2500
        # Below the height the size is final before the scripts run.
        result = self.test(self.spend(heavy_coins, 0))
        assert_equal(result["reject-reason"], "66: min relay fee not met")
        assert_equal(result["vsize"], weight_vsize)
        self.log.info("  5,000 permutations: %d vbytes, 0.05 XNA accepted", weight_vsize)

        self.log.info("Crossing the height evicts the entries sized without their work")
        node.generate(FORK_HEIGHT - 2 - node.getblockcount())
        sync_blocks(self.nodes)
        self.send(cheap)
        assert_equal(node.getmempoolentry(cheap.hash)["size"], weight_vsize)
        block = self.build_block([])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        assert_equal(node.getblockcount() + 1, FORK_HEIGHT)
        assert cheap.hash not in node.getrawmempool()
        sync_blocks(self.nodes)
        assert cheap.hash not in self.nodes[1].getrawmempool()

        self.log.info("From the height, the fee must cover the size with work")
        result = self.test(cheap)
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], "66: min relay fee not met")
        assert_equal(result["vsize"], HEAVY_VSIZE)
        # A test of acceptance runs the scripts before it checks the fees: a
        # transaction without fee learns its size with work too.
        result = self.test(self.spend(heavy_coins, 0))
        assert_equal(result["reject-reason"], "66: min relay fee not met")
        assert_equal(result["vsize"], HEAVY_VSIZE)
        assert_equal(self.test(self.spend(heavy_coins, MIN_FEE - 1))["reject-reason"], "66: min relay fee not met")
        exact = self.spend(heavy_coins, MIN_FEE)
        result = self.test(exact)
        assert_equal(result["allowed"], True)
        assert_equal(result["vsize"], HEAVY_VSIZE)
        assert_raises_rpc_error(-26, "min relay fee not met", self.send, cheap)
        # A size that is not final is not reported: the scripts failed.
        broken = self.spend(heavy_coins, MIN_FEE)
        broken.wit.vtxinwit[0].scriptWitness.stack[-1] = LIGHT
        result = self.test(broken)
        assert_equal(result["allowed"], False)
        assert "Witness program hash mismatch" in result["reject-reason"]
        assert "vsize" not in result
        self.log.info("  %d vbytes: 1 XNA accepted, one satoshi less refused", HEAVY_VSIZE)

        self.log.info("prioritisetransaction counts against the size with work")
        node.prioritisetransaction(cheap.hash, 0, MIN_FEE - COIN // 20)
        assert_equal(self.test(cheap)["allowed"], True)
        node.prioritisetransaction(cheap.hash, 0, -(MIN_FEE - COIN // 20))
        assert_equal(self.test(cheap)["allowed"], False)

        self.log.info("Package sizes and limits use the size with work")
        # The parent pays 1 XNA and leaves an output for each kind of child.
        parent = self.spend(heavy_coins, MIN_FEE, [(authscript(LIGHT), VALUE), (authscript(HEAVY), VALUE)])
        self.send(parent)
        entry = node.getmempoolentry(parent.hash)
        assert_equal(entry["size"], HEAVY_VSIZE)
        assert_equal(entry["poseidonwork"], 5000)
        assert_equal(entry["assetauthwork"], 0)
        light_child = self.spend([((parent.x16r, 0), LIGHT)], COIN // 100)
        self.send(light_child)
        child_size = node.getmempoolentry(light_child.hash)["size"]
        assert_equal(node.getmempoolentry(parent.hash)["descendantsize"], HEAVY_VSIZE + child_size)
        assert_equal(node.getmempoolentry(light_child.hash)["ancestorsize"], HEAVY_VSIZE + child_size)
        # A second transaction with work on top: 200 kvB of package, over the
        # 150 kvB limits of node0; node1 (default limits) takes it.
        heavy_child = self.spend([((parent.x16r, 1), HEAVY)] + self.take(HEAVY, 9), MIN_FEE)
        result = self.test(heavy_child)
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], "64: too-long-mempool-chain")
        assert_equal(result["vsize"], HEAVY_VSIZE)
        wait_until(lambda: {parent.hash, light_child.hash} <= set(self.nodes[1].getrawmempool()),
                   err_msg="node1 mempool", timeout=60)
        assert_equal(self.test(heavy_child, self.nodes[1])["allowed"], True)

        self.log.info("Block assembly puts, at the same fee, the transaction without work first")
        light = self.spend(self.take(LIGHT, 2), MIN_FEE)
        heavy = self.spend(self.take(HEAVY, 10), MIN_FEE)   # the minimum rate; the light one pays far more per vbyte
        self.send(heavy)
        self.send(light)
        order = [t["txid"] for t in node.getblocktemplate({"rules": ["segwit"]})["transactions"]]
        assert order.index(light.hash) < order.index(heavy.hash)

        self.log.info("Block assembly takes the room of a transaction from its weight, not its work")
        node1 = self.nodes[1]
        wait_until(lambda: {heavy.hash, light.hash} <= set(node1.getrawmempool()), err_msg="node1 mempool", timeout=60)
        template = node1.getblocktemplate({"rules": ["segwit"]})["transactions"]
        weights = {t["txid"]: t["weight"] for t in template}
        assert parent.hash in weights and heavy.hash in weights
        assert weights[heavy.hash] < 10000
        # With 10,000 weight units, 6,000 after the reserve for the coinbase,
        # a transaction with work does not fit and one without does.
        self.stop_node(1)
        self.start_node(1, self.extra_args[1][:1] + ["-blockmaxweight=10000"])
        node1 = self.nodes[1]
        connect_nodes(self.nodes[0], 1)
        wait_until(lambda: {heavy.hash, light.hash} <= set(node1.getrawmempool()), err_msg="node1 mempool.dat", timeout=60)
        ids = [t["txid"] for t in node1.getblocktemplate({"rules": ["segwit"]})["transactions"]]
        assert light.hash in ids
        assert heavy.hash not in ids and parent.hash not in ids

        self.log.info("A restart restores the size with work from mempool.dat")
        self.stop_node(0)
        self.start_node(0, self.extra_args[0])
        connect_nodes(self.nodes[0], 1)
        node = self.nodes[0]
        assert_equal(node.getmempoolentry(heavy.hash)["size"], HEAVY_VSIZE)
        assert_equal(node.getmempoolentry(parent.hash)["descendantsize"], HEAVY_VSIZE + child_size)

        self.log.info("A reorganisation restores it too")
        block_hash = node.generate(1)[0]
        assert heavy.hash in node.getblock(block_hash)["tx"]
        assert heavy.hash not in node.getrawmempool()
        node.invalidateblock(block_hash)
        assert_equal(node.getmempoolentry(heavy.hash)["size"], HEAVY_VSIZE)
        assert_equal(node.getmempoolentry(heavy.hash)["poseidonwork"], 5000)
        node.reconsiderblock(block_hash)
        assert_equal(node.getbestblockhash(), block_hash)

        self.log.info("Crossing the height back evicts the entries sized with their work")
        late = self.spend(self.take(HEAVY, 10), MIN_FEE)
        self.send(late)
        assert_equal(node.getmempoolentry(late.hash)["size"], HEAVY_VSIZE)
        first = node.getblockhash(FORK_HEIGHT - 1)
        node.invalidateblock(first)
        assert_equal(node.getblockcount() + 1, FORK_HEIGHT - 1)
        assert late.hash not in node.getrawmempool()
        # The transactions of the disconnected blocks come back without it.
        assert_equal(node.getmempoolentry(heavy.hash)["size"], weight_vsize)
        node.reconsiderblock(first)
        assert_equal(node.getbestblockhash(), block_hash)


if __name__ == '__main__':
    WorkFeeTest().main()
