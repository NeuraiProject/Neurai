#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""-maxmempoolchaincontext bounds the pending spends that read the chain position.

Every mempool entry whose scripts executed OP_CHAINCONTEXT (NIP-026) runs them
again at each tip change, on one thread and under cs_main. The node keeps the
total weight of those entries under -maxmempoolchaincontext:

- spends up to the limit are accepted, the next one is refused with
  chaincontext-mempool-full;
- spends that do not read the chain position are not affected;
- a confirmed entry frees its share of the limit.

-checkmempool=1 also checks the running total against the entries after every
change.

A result that read the chain position is never served from the script
execution cache: a deadline covenant accepted by the mempool leaves it at the
tip where it expires, and a later block that includes it is invalid.
"""

import hashlib

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut,
                                     hash256, uint256_from_compact, uint256_from_str)
from test_framework.script import CScript, CScriptOp, OP_1, OP_3, OP_DROP, OP_LESSTHAN, OP_TRUE
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

OP_CHAINCONTEXT = CScriptOp(0xd7)
FUND = COIN
FEE = COIN // 100
PENDING = 3  # tagged spends that fit under the limit


def sha256(data):
    return hashlib.sha256(data).digest()


class AuthScript:
    """A generic AuthScript v1 output (authType 0x00) and its spending witness."""

    def __init__(self, script):
        self.script = bytes(script)
        tag = sha256(b"NeuraiAuthScript")
        self.spk = b"\x51\x20" + sha256(tag + tag + b"\x01\x00" + sha256(self.script))
        self.witness = [b"\x00", self.script]


TAGGED = AuthScript(CScript([OP_3, OP_CHAINCONTEXT, OP_DROP, OP_TRUE]))
PLAIN = AuthScript(CScript([OP_TRUE]))


def spend(outpoint, contract, dest_spk):
    tx = CTransaction()
    tx.nVersion = 2
    tx.vin = [CTxIn(COutPoint(int(outpoint[0], 16), outpoint[1]), b"", 0xfffffffe)]
    tx.vout = [CTxOut(FUND - FEE, dest_spk)]
    tx.wit.vtxinwit = [CTxInWitness()]
    tx.wit.vtxinwit[0].scriptWitness.stack = contract.witness
    tx.rehash()
    return tx


def weight(tx):
    return 3 * len(tx.serialize_without_witness()) + len(tx.serialize_with_witness())


# Every tagged spend has the same weight: a P2PKH destination is 25 bytes.
SPEND_WEIGHT = weight(spend(("00" * 32, 0), TAGGED, b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"))
LIMIT = PENDING * SPEND_WEIGHT + SPEND_WEIGHT // 2


class MempoolChainContextLimitTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-maxmempoolchaincontext=%d" % LIMIT, "-checkmempool=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.generate(101)
        dest_spk = bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"])
        assert_equal(len(dest_spk), 25)

        self.log.info("Fund %d tagged contracts and one that does not read the chain", PENDING + 1)
        tagged = self.fund([TAGGED] * (PENDING + 1) + [PLAIN])
        plain = tagged.pop()

        self.log.info("Tagged spends up to the limit (%d of %d WU) enter the mempool", PENDING * SPEND_WEIGHT, LIMIT)
        txids = []
        for outpoint in tagged[:PENDING]:
            tx = spend(outpoint, TAGGED, dest_spk)
            assert_equal(weight(tx), SPEND_WEIGHT)
            txids.append(node.sendrawtransaction(tx.serialize_with_witness().hex()))

        self.log.info("The next tagged spend is refused")
        extra = spend(tagged[PENDING], TAGGED, dest_spk).serialize_with_witness().hex()
        result = node.testmempoolaccept([extra])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], "64: chaincontext-mempool-full")
        assert_raises_rpc_error(-26, "chaincontext-mempool-full", node.sendrawtransaction, extra)

        self.log.info("A spend that does not read the chain position is not affected")
        txids.append(node.sendrawtransaction(spend(plain, PLAIN, dest_spk).serialize_with_witness().hex()))
        assert_equal(sorted(node.getrawmempool()), sorted(txids))

        self.log.info("Once confirmed, the tagged spends free their share")
        block = node.getblock(node.generate(1)[0])
        for txid in txids:
            assert txid in block["tx"]
        assert_equal(node.getrawmempool(), [])
        txid = node.sendrawtransaction(extra)
        assert_equal(node.getrawmempool(), [txid])

        self.log.info("A deadline covenant is not re-served from the script cache once it expires")
        funding_height = node.getblockcount() + 1
        deadline = AuthScript(CScript([OP_1, OP_CHAINCONTEXT, funding_height + 2, OP_LESSTHAN]))
        outpoint = self.fund([deadline])[0]
        assert_equal(node.getblockcount(), funding_height)
        late = spend(outpoint, deadline, dest_spk)
        late_txid = node.sendrawtransaction(late.serialize_with_witness().hex())
        assert late_txid in node.getrawmempool()
        # The next block makes the candidate height reach the deadline.
        assert_equal(self.submit_block([]), None)
        assert late_txid not in node.getrawmempool()
        # Same transaction and flags as when the mempool accepted it.
        tip = node.getbestblockhash()
        assert self.submit_block([late]) is not None
        assert_equal(node.getbestblockhash(), tip)

    def submit_block(self, txs):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        tip_header = node.getblock(tip)
        coinbase = create_coinbase(node.getblockcount() + 1)
        coinbase.vout[0].nValue = 0
        coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, tip_header["time"] + 1)
        block.nVersion = tip_header["version"]
        block.nBits = int(tip_header["bits"], 16)
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        add_witness_commitment(block)
        # Regtest mines double-SHA256 over the 80-byte header.
        target = uint256_from_compact(block.nBits)
        while uint256_from_str(hash256(CBlockHeader.serialize(block))) > target:
            block.nNonce += 1
        return node.submitblock(block.serialize(with_witness=True).hex())

    def fund(self, contracts):
        node = self.nodes[0]
        tx = CTransaction()
        tx.nVersion = 2
        tx.vout = [CTxOut(FUND, c.spk) for c in contracts]
        funded = node.fundrawtransaction(tx.serialize_without_witness().hex())["hex"]
        signed = node.signrawtransaction(funded)
        assert signed["complete"]
        txid = node.sendrawtransaction(signed["hex"])
        node.generate(1)
        outpoints = []
        used = set()
        for c in contracts:
            n = next(out["n"] for out in node.decoderawtransaction(signed["hex"])["vout"]
                     if out["scriptPubKey"]["hex"] == c.spk.hex() and out["n"] not in used)
            used.add(n)
            outpoints.append((txid, n))
        return outpoints


if __name__ == '__main__':
    MempoolChainContextLimitTest().main()
