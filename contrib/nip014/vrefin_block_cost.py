#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""What reference inputs (NIP-014) cost a node when it connects a block.

Builds three blocks on regtest and measures, for each one, how long the node
takes to connect it and how much its peak resident memory grows while it does:

- adversarial: TXS standard transactions of 64 references each, all to the
  same 64 outputs whose scriptPubKey has 10,000 bytes, the largest an unspent
  output can have. A reference costs 36 bytes of block space and copies the
  whole referenced output;
- baseline: TXS transactions of the same shape without references;
- distinct: DISTINCT_TXS transactions of 64 references each, every reference
  to a different small output, to time the lookup of each reference;
- slow checks: POSEIDON_TXS transactions with the 64 references of the
  adversarial block, each spending an AuthScript output whose script runs
  OP_POSEIDON 59 times on 520 bytes (531 permutations, close to the block
  budget in total), so that verifying a transaction takes longer than
  copying its references;
- slow checks baseline: the same without references.

Every block is measured when it is first submitted and then again after
invalidateblock, a restart (cold UTXO cache, fresh peak memory) and
reconsiderblock, with the default script check threads (-par=0), with none
(-par=1) and with one (-par=2, as a two-core node would run).

Run from the repository root, after building neuraid, preferably pinned to one
kind of core (taskset on hybrid CPUs):

    python3 contrib/nip014/vrefin_block_cost.py
"""

import os
import sys
import time
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "test", "functional"))

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase  # noqa: E402
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness,  # noqa: E402
                                     CTxOut, from_hex, hash256, uint256_from_compact, uint256_from_str)
from test_framework.test_framework import NeuraiTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402
from feature_assetauth import AuthScript  # noqa: E402

# OP_DUP OP_POSEIDON OP_DROP 59 times on 520 bytes: 59 x 9 = 531 permutations
# and 30,680 of the 30,720 bytes a script may hash.
POSEIDON_DATA = bytes(range(256)) * 2 + bytes(8)
POSEIDON_SCRIPT = AuthScript(bytes([0x76, 0xc9, 0x75]) * 59 + bytes([0x75, 0x51]))

TXS = 780            # about 2 MB of transactions with 64 references each
DISTINCT_TXS = 300   # 19,200 distinct references
POSEIDON_TXS = 360   # 360 x 531 permutations, under the 200,000 of a block
REFS = 64            # the relay limit per transaction
BIG = 64             # outputs with a 10,000-byte scriptPubKey
FEE = 10000          # satoshis per measured transaction; they go straight into blocks
# Without a persisted mempool, a restart also empties the script caches.
BASE_ARGS = ["-acceptnonstdtxn=1", "-maxmempool=2000", "-persistmempool=0"]


def big_script():
    """10,000 bytes: 38 PUSHDATA1 of 255 bytes, then OP_NOPs. Never spent."""
    chunk = bytes([0x4c, 0xff]) + bytes(255)
    script = chunk * 38
    return script + bytes([0x61]) * (10000 - len(script))


class VrefinBlockCost(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [BASE_ARGS]

    # ------------------------------------------------------------------ helpers

    def proc(self, field):
        with open("/proc/%d/status" % self.nodes[0].process.pid) as status:
            for line in status:
                if line.startswith(field + ":"):
                    return int(line.split()[1])  # kB
        raise AssertionError(field)

    def measure(self, label, action):
        with open("/proc/%d/clear_refs" % self.nodes[0].process.pid, "w") as clear:
            clear.write("5")  # resets VmHWM to the current RSS
        before = self.proc("VmRSS")
        start = time.perf_counter()
        result = action()
        elapsed = time.perf_counter() - start
        peak = self.proc("VmHWM")
        self.log.info("%-44s %8.3f s   peak RSS +%7.1f MB (from %6.1f MB)",
                      label, elapsed, (peak - before) / 1024, before / 1024)
        self.results.append((label, elapsed, (peak - before) / 1024))
        return result

    def sign(self, tx):
        signed = self.node.signrawtransaction(tx.serialize().hex())
        assert signed["complete"], signed
        tx = from_hex(CTransaction(), signed["hex"])
        tx.rehash()
        return tx

    def spk(self):
        return bytes.fromhex(self.node.validateaddress(self.node.getnewaddress("", "legacy"))["scriptPubKey"])

    def fan_out(self, count, value, spk, signed=True):
        """One transaction with `count` outputs of `value` satoshis to `spk`."""
        utxo = max(self.node.listunspent(), key=lambda u: u["amount"])
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), b"", 0xffffffff)]
        tx.vout = [CTxOut(value, spk) for _ in range(count)]
        size = 200 + count * (9 + len(spk) + 3)
        change = int(utxo["amount"] * COIN) - count * value - 2000 * size  # 0.02 XNA per kB
        tx.vout.append(CTxOut(change, self.spk()))
        tx = self.sign(tx)
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        return [COutPoint(int(txid, 16), n) for n in range(count)]

    def spend(self, outpoint, value, spk, refs):
        tx = CTransaction()
        tx.nVersion = 3 if refs else 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(value - FEE, spk)]
        tx.vrefin = list(refs)
        return self.sign(tx)

    def slow_spend(self, outpoint, spk, refs):
        """Spends a POSEIDON_SCRIPT output (NoAuth, no signature)."""
        tx = CTransaction()
        tx.nVersion = 3 if refs else 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(COIN - FEE, spk)]
        tx.vrefin = list(refs)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x00", POSEIDON_DATA, POSEIDON_SCRIPT.script]
        tx.rehash()
        return tx

    def submit(self, txs):
        node = self.node
        tip = node.getbestblockhash()
        header = node.getblock(tip)
        coinbase = create_coinbase(node.getblockcount() + 1)
        coinbase.vout[0].nValue = 0
        coinbase.rehash()
        block = create_block(int(tip, 16), coinbase, header["time"] + 1)
        block.nVersion = header["version"]
        block.nBits = int(header["bits"], 16)
        block.vtx += txs
        add_witness_commitment(block)
        target = uint256_from_compact(block.nBits)
        while uint256_from_str(hash256(CBlockHeader.serialize(block))) > target:
            block.nNonce += 1
        block.rehash()
        data = block.serialize(with_witness=True).hex()
        self.log.info("block of %d transactions, %d bytes", len(block.vtx), len(data) // 2)
        return block.hash, data

    def connect(self, label, txs):
        """Submit the block, then reconnect it cold with and without threads."""
        node = self.node
        block_hash, data = self.submit(txs)
        result = self.measure(label + ", submitted", lambda: node.submitblock(data))
        assert_equal(result, None)
        assert_equal(node.getbestblockhash(), block_hash)
        for par in (0, 1, 2):
            node.invalidateblock(block_hash)
            self.restart_node(0, extra_args=BASE_ARGS + ["-par=%d" % par])
            self.node = self.nodes[0]
            self.measure("%s, cold, -par=%d" % (label, par), lambda: self.node.reconsiderblock(block_hash))
            assert_equal(self.node.getbestblockhash(), block_hash)
        self.restart_node(0, extra_args=BASE_ARGS)
        self.node = self.nodes[0]

    # ------------------------------------------------------------------ run

    def run_test(self):
        self.node = self.nodes[0]
        self.results = []
        self.node.generate(150)

        self.log.info("Setting up: %d outputs of 10,000 bytes, spendable and distinct small outputs", BIG)
        big = []
        for _ in range(BIG // 16):
            big += self.fan_out(16, COIN, big_script())
        spk = self.spk()
        coins = self.fan_out(2 * TXS + DISTINCT_TXS, COIN, spk)
        distinct = []
        for _ in range(DISTINCT_TXS * REFS // 2000 + 1):
            distinct += self.fan_out(2000, 1000, bytes([0x51]))  # OP_TRUE, never spent here
        slow = self.fan_out(2 * POSEIDON_TXS, COIN, POSEIDON_SCRIPT.spk)
        self.node.generate(1)
        assert_equal(len(self.node.getrawmempool()), 0)

        self.log.info("Signing %d + %d + %d transactions", TXS, TXS, DISTINCT_TXS)
        adversarial = [self.spend(coins[i], COIN, spk, big) for i in range(TXS)]
        baseline = [self.spend(coins[TXS + i], COIN, spk, []) for i in range(TXS)]
        lookups = [self.spend(coins[2 * TXS + i], COIN, spk, distinct[i * REFS:(i + 1) * REFS])
                   for i in range(DISTINCT_TXS)]
        slow_refs = [self.slow_spend(slow[i], spk, big) for i in range(POSEIDON_TXS)]
        slow_base = [self.slow_spend(slow[POSEIDON_TXS + i], spk, []) for i in range(POSEIDON_TXS)]

        self.connect("baseline (%d txs, no references)" % TXS, baseline)
        self.connect("adversarial (%d txs x %d refs, 10 KB)" % (TXS, REFS), adversarial)
        self.connect("distinct (%d refs)" % (DISTINCT_TXS * REFS), lookups)
        self.connect("slow checks (%d txs, no references)" % POSEIDON_TXS, slow_base)
        self.connect("slow checks + %d txs x %d refs, 10 KB" % (POSEIDON_TXS, REFS), slow_refs)

        self.log.info("Summary (seconds, peak RSS growth in MB):")
        for label, elapsed, peak in self.results:
            self.log.info("  %-44s %8.3f %8.1f", label, elapsed, peak)


if __name__ == "__main__":
    VrefinBlockCost().main()
