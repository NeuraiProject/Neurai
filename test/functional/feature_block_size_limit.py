#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Block size limits around the NIP-028 height.

From the NIP-028 height on (30 s blocks) a block, witness included, may not
exceed 2,000,000 serialized bytes. Below it the RIP2 limit stands: a weight of
8,000,000, which lets a block made mostly of witness data reach almost 8 MB.
Every valid block must fit in one P2P message.

- The largest valid block before the fork, of weight 8,000,000 and nearly
  8 MB, reaches a second node over P2P.
- Before the fork the miner fills a block past 2 MB, and getblocktemplate
  reports a size limit of 8,000,000.
- At the fork height getblocktemplate reports 2,000,000; a block of 2,000,001
  bytes is rejected although its weight is far below the limit, and one of
  2,000,000 bytes is accepted.
- After the fork the miner stops at 2 MB with a mempool full of witness data,
  and -blockmaxsize limits serialized bytes.
"""

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.mininode import COutPoint, CTxIn, CTxInWitness
from test_framework.script import CScript, CTransaction, CTxOut, OP_0, OP_2DROP, OP_TRUE, sha256
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, bytes_to_hex_str, connect_nodes, sync_blocks, wait_until

FORK_HEIGHT = 120
MAX_BLOCK_WEIGHT = 8000000
MAX_BLOCK_SIZE_RIP2 = 8000000
MAX_BLOCK_SIZE_FORK = 2000000
OLD_MAX_PROTOCOL_MESSAGE_LENGTH = 4000000

# Each input carries 2 * NUM_DROPS witness elements that its script drops,
# about 80 kB. Elements of 253 to 65535 bytes have a 3-byte length, so growing
# one by a byte grows the block, and its weight, by exactly one; they stay
# within the 520-byte element limit.
NUM_DROPS = 100
ELEMENT_SIZE = 400
ELEMENT_GROWTH = 120
PROGRAM = CScript([OP_2DROP] * NUM_DROPS + [OP_TRUE])
P2WSH = CScript([OP_0, sha256(PROGRAM)])
NUM_FUNDING_OUTPUTS = 180
FEE = 100000000  # 1 XNA, well above the minimum relay fee for these sizes


def size(block):
    return len(block.serialize(with_witness=True))


def weight(block):
    return 3 * len(block.serialize()) + size(block)


class BlockSizeLimitTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        fork = "-blocktimereductionheight=%d" % FORK_HEIGHT
        self.base_args = [["-acceptnonstdtxn=1", fork], [fork]]
        self.extra_args = self.base_args

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def run_test(self):
        node = self.nodes[0]
        self.outpoints = self.fund()

        self.log.info("Before the fork the largest valid block crosses the P2P network")
        self.relay_largest_block()

        self.log.info("Before the fork the miner fills a block past 2 MB")
        node.generate(FORK_HEIGHT - 2 - node.getblockcount())
        self.sync_all_blocks()
        assert_equal(self.template()["sizelimit"], MAX_BLOCK_SIZE_RIP2)
        block, _ = self.mine_mempool(26)
        assert block["size"] > MAX_BLOCK_SIZE_FORK, block["size"]
        assert_equal(len(block["tx"]), 27)
        assert_equal(block["height"], FORK_HEIGHT - 1)

        self.log.info("At the fork height a block may not exceed 2,000,000 bytes")
        assert_equal(self.template()["sizelimit"], MAX_BLOCK_SIZE_FORK)
        assert_equal(self.template()["weightlimit"], MAX_BLOCK_WEIGHT)
        inputs = self.take(24)
        oversized = self.build_block([self.spend(inputs)])
        self.grow_witness(oversized, size, MAX_BLOCK_SIZE_FORK + 1)
        assert weight(oversized) < MAX_BLOCK_WEIGHT // 3, weight(oversized)
        assert_equal(node.submitblock(bytes_to_hex_str(oversized.serialize(with_witness=True))), "bad-blk-length")
        assert_equal(node.getblockcount(), FORK_HEIGHT - 1)

        largest = self.build_block([self.spend(inputs)])
        self.grow_witness(largest, size, MAX_BLOCK_SIZE_FORK)
        assert_equal(node.submitblock(bytes_to_hex_str(largest.serialize(with_witness=True))), None)
        assert_equal(node.getbestblockhash(), largest.hash)
        self.sync_all_blocks()

        self.log.info("After the fork the miner stops at 2 MB")
        block, tx_size = self.mine_mempool(27)
        assert block["size"] <= MAX_BLOCK_SIZE_FORK, block["size"]
        assert block["weight"] < MAX_BLOCK_WEIGHT // 3, block["weight"]
        left = node.getrawmempool()
        assert len(left) > 0
        assert_equal(len(block["tx"]) - 1 + len(left), 27)
        # The block is full: one more of the transactions left would not fit.
        assert block["size"] + tx_size > MAX_BLOCK_SIZE_FORK - 2000, block["size"]

        self.log.info("-blockmaxsize limits serialized bytes, witness included")
        self.restart_with(["-blockmaxsize=200000"])
        wait_until(lambda: len(node.getrawmempool()) == len(left), err_msg="mempool not reloaded", timeout=60)
        block = node.getblock(node.generate(1)[0])
        assert block["size"] <= 200000, block["size"]
        assert len(block["tx"]) > 1
        assert len(node.getrawmempool()) > 0
        self.restart_with([])
        wait_until(lambda: len(node.getrawmempool()) > 0, err_msg="mempool not reloaded", timeout=60)
        node.generate(1)
        assert_equal(node.getrawmempool(), [])
        self.sync_all_blocks()

    def fund(self):
        """Mine an anyone-can-spend coinbase and split it into P2WSH outputs."""
        node = self.nodes[0]
        node.generate(1)  # leave initial block download: getblocktemplate needs it
        block = self.build_block([])
        coinbase = block.vtx[0]
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        node.generate(100)

        funding = CTransaction()
        funding.vin.append(CTxIn(COutPoint(coinbase.x16r, 0), b""))
        value = (coinbase.vout[0].nValue - FEE) // NUM_FUNDING_OUTPUTS
        funding.vout = [CTxOut(value, P2WSH) for _ in range(NUM_FUNDING_OUTPUTS)]
        funding.rehash()
        block = self.build_block([funding])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        self.sync_all_blocks()
        return [(funding.x16r, i, value) for i in range(NUM_FUNDING_OUTPUTS)]

    def take(self, count):
        taken, self.outpoints = self.outpoints[:count], self.outpoints[count:]
        assert_equal(len(taken), count)
        return taken

    def spend(self, inputs):
        tx = CTransaction()
        for txid, n, _ in inputs:
            tx.vin.append(CTxIn(COutPoint(txid, n), b""))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x01' * ELEMENT_SIZE] * (2 * NUM_DROPS) + [PROGRAM]
        tx.vout.append(CTxOut(sum(value for _, _, value in inputs) - FEE, P2WSH))
        tx.rehash()
        return tx

    def template(self):
        return self.nodes[0].getblocktemplate({"rules": ["segwit"]})

    def build_block(self, txs):
        """A block on the tip of node0 with these transactions, as its miner would date it."""
        node = self.nodes[0]
        tip = node.getbestblockhash()
        header = node.getblockheader(tip)
        template = self.template()
        assert_equal(template["previousblockhash"], tip)
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

    def grow_witness(self, block, metric, target):
        """Grow the witness of the last transaction until metric(block) == target."""
        tx = block.vtx[-1]
        missing = target - metric(block)
        assert 0 <= missing <= len(tx.wit.vtxinwit) * 2 * NUM_DROPS * ELEMENT_GROWTH, missing
        for wit in tx.wit.vtxinwit:
            stack = wit.scriptWitness.stack
            for i in range(2 * NUM_DROPS):
                step = min(missing, ELEMENT_GROWTH)
                stack[i] = stack[i] + b'\x01' * step
                missing -= step
        assert_equal(missing, 0)
        block.vtx[0].vout.pop()  # the witness commitment
        add_witness_commitment(block)
        block.solve()
        assert_equal(metric(block), target)

    def relay_largest_block(self):
        node = self.nodes[0]
        block = self.build_block([self.spend(self.take(98))])
        self.grow_witness(block, weight, MAX_BLOCK_WEIGHT)
        self.log.info("block of %d bytes, weight %d" % (size(block), weight(block)))
        assert size(block) > OLD_MAX_PROTOCOL_MESSAGE_LENGTH
        assert size(block) > MAX_BLOCK_SIZE_RIP2 - 20000
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        assert_equal(node.getbestblockhash(), block.hash)
        sync_blocks(self.nodes, timeout=120)
        assert_equal(self.nodes[1].getblock(block.hash)["size"], size(block))
        assert_equal(len(self.nodes[1].getpeerinfo()), 1)

    def mine_mempool(self, count):
        """Send count transactions of about 80 kB of witness each and mine one block."""
        node = self.nodes[0]
        for outpoint in self.take(count):
            tx = self.spend([outpoint]).serialize_with_witness()
            node.sendrawtransaction(bytes_to_hex_str(tx))
        assert_equal(len(node.getrawmempool()), count)
        block = node.getblock(node.generate(1)[0])
        self.sync_all_blocks()
        return block, len(tx)

    def sync_all_blocks(self):
        sync_blocks(self.nodes, timeout=120)

    def restart_with(self, extra):
        self.stop_node(0)
        self.start_node(0, self.base_args[0] + extra)
        connect_nodes(self.nodes[0], 1)
        self.sync_all_blocks()


if __name__ == '__main__':
    BlockSizeLimitTest().main()
