#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A block keeps one copy of each output it references (NIP-014).

When a block connects, a reference resolves to the same output wherever its
transaction sits, so the node resolves each referenced output once and shares
it between all the transactions of the block that reference it. Every
transaction must still read its own references, in its own order:

- the spent outputs below carry scripts that check, with OP_REFINPUTFIELD and
  OP_REFINPUTCOUNT, the value and the scriptPubKey of every reference of
  their transaction, so a transaction that read another one's references, or
  its own in another order, would fail;
- many transactions of one block reference the same two outputs, in both
  orders, through the mempool and in blocks built by hand;
- an output spent in the block is seen by the references before and after the
  spend, whichever comes first;
- an output created in the block is missing even after the block resolved
  other references of the same transaction, and nothing carries over to the
  next block;
- a node with script check threads and one without accept and reject the same
  blocks, also after a reorg, verifychain 4 and a restart with
  -checklevel=4.
"""

from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut,
                                     from_hex, hash256, uint256_from_compact, uint256_from_str)
from test_framework.script import CScript, CScriptOp, OP_EQUAL, OP_EQUALVERIFY
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, disconnect_nodes, sync_blocks, sync_mempools
from feature_assetauth import AuthScript

OP_REFINPUTFIELD = CScriptOp(0xd2)
OP_REFINPUTCOUNT = CScriptOp(0xd4)

FEE = Decimal("0.01")      # transactions of one input and one or two outputs
FAN_OUT_FEE = Decimal("0.1")  # the transactions that create the outputs below
SCRIPT_VALUE = Decimal("1")
X_VALUE = Decimal("1.23")
Y_VALUE = Decimal("4.56")
N = 10  # transactions of each kind in the shared block

# Node 0 runs the script checks on threads, node 1 in its own thread.
ARGS = [["-acceptnonstdtxn=1", "-par=4"], ["-acceptnonstdtxn=1", "-par=1"]]
# A script that fails in a block: node 0 reports the check queue, node 1 the
# script error.
SCRIPT_FAILURE = "a script failure"


def sats(amount):
    return int(Decimal(str(amount)) * COIN)


def checks_references(expected):
    """An AuthScript that leaves true only when its transaction references,
    in this order, outputs of these (value, scriptPubKey) and no other. With
    64-bit integers, selector 1 returns the value as a script number."""
    ops = []
    for k, (value, spk) in enumerate(expected):
        ops += [k, 1, OP_REFINPUTFIELD, sats(value), OP_EQUALVERIFY,
                k, 3, OP_REFINPUTFIELD, spk, OP_EQUALVERIFY]
    ops += [OP_REFINPUTCOUNT, len(expected), OP_EQUAL]
    return AuthScript(CScript(ops))


class VrefinSharedOutputsTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = ARGS

    def run_test(self):
        self.node = self.nodes[0]
        self.extra_nonce = 0
        self.pending = []
        self.node.generate(130)
        self.sync_all()

        self.setup_outputs()
        self.first_block = self.node.getblockcount() + 1
        # Each node validates every block by itself: node 0 would otherwise
        # relay a block to node 1 before validating it.
        disconnect_nodes(self.nodes[0], 1)

        self.test_scripts_check_their_references()
        self.test_shared_in_one_block()
        self.test_shared_through_the_mempool()
        self.test_missing_after_shared()
        self.test_spent_in_the_block()
        self.test_nothing_carries_over()
        self.test_reorg()
        self.test_verifychain_and_restart()

    # ---------------------------------------------------------------- helpers

    def p2pkh(self):
        spk = bytes.fromhex(self.node.validateaddress(self.node.getnewaddress())["scriptPubKey"])
        assert_equal(len(spk), 25)
        return spk

    def fee_input(self):
        """A large wallet output that no pending transaction spends and that is
        not one of the referenced outputs."""
        taken = {(i.prevout.hash, i.prevout.n) for t in self.pending for i in t.vin}
        taken |= {(self.x.hash, self.x.n), (self.y.hash, self.y.n)}
        for u in sorted(self.node.listunspent(1), key=lambda u: -u["amount"]):
            if u["amount"] >= 2 and (int(u["txid"], 16), u["vout"]) not in taken:
                return COutPoint(int(u["txid"], 16), u["vout"]), u["amount"]
        raise AssertionError("no spendable output left")

    def sign(self, tx, prevtxs=None):
        result = self.node.signrawtransaction(tx.serialize().hex(), prevtxs or [])
        assert result["complete"], result
        signed = from_hex(CTransaction(), result["hex"])
        signed.rehash()
        self.pending.append(signed)
        return signed

    def setup_outputs(self):
        self.log.info("Setting up the referenced outputs and the outputs whose scripts read them")
        self.x = self.y = COutPoint(0, 0xffffffff)
        outpoint, amount = self.fee_input()
        self.x_spk, self.y_spk = self.p2pkh(), self.p2pkh()
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(X_VALUE), self.x_spk), CTxOut(sats(Y_VALUE), self.y_spk),
                   CTxOut(sats(amount - X_VALUE - Y_VALUE - FEE), self.p2pkh())]
        tx = self.sign(tx)
        self.node.sendrawtransaction(tx.serialize().hex())
        self.x, self.y = COutPoint(tx.sha256, 0), COutPoint(tx.sha256, 1)

        x, y = (X_VALUE, self.x_spk), (Y_VALUE, self.y_spk)
        self.scripts = {"X": checks_references([x]), "Y": checks_references([y]),
                        "XY": checks_references([x, y]), "YX": checks_references([y, x])}
        self.refs = {"X": [self.x], "Y": [self.y], "XY": [self.x, self.y], "YX": [self.y, self.x]}
        counts = {"X": 3 * N, "Y": N, "XY": 2 * N, "YX": 2 * N}
        self.unspent = {kind: [] for kind in counts}
        for kind, count in counts.items():
            outpoint, amount = self.fee_input()
            tx = CTransaction()
            tx.nVersion = 2
            tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
            tx.vout = [CTxOut(sats(SCRIPT_VALUE), self.scripts[kind].spk) for _ in range(count)]
            tx.vout.append(CTxOut(sats(amount - count * SCRIPT_VALUE - FAN_OUT_FEE), self.p2pkh()))
            tx = self.sign(tx)
            self.node.sendrawtransaction(tx.serialize().hex())
            self.unspent[kind] += [COutPoint(tx.sha256, n) for n in range(count)]
        self.node.generate(1)
        self.sync_all()
        assert_equal(self.node.getrawmempool(), [])
        self.pending = []

    def read(self, kind, refs=None):
        """Spends an output whose script checks references `kind`, with the
        references `refs` (by default, the ones the script expects)."""
        tx = CTransaction()
        tx.nVersion = 3
        tx.vin = [CTxIn(self.unspent[kind].pop(), b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(SCRIPT_VALUE - FEE), self.p2pkh())]
        tx.vrefin = list(self.refs[kind] if refs is None else refs)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x00", self.scripts[kind].script]
        tx.rehash()
        return tx

    def payment(self, references):
        """A version 3 payment back to the wallet with these reference inputs."""
        outpoint, amount = self.fee_input()
        tx = CTransaction()
        tx.nVersion = 3
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(amount - FEE), self.p2pkh())]
        tx.vrefin = list(references)
        return self.sign(tx)

    def spend(self, outpoint, value):
        """Spends a wallet output back to the wallet."""
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(value - FEE), self.p2pkh())]
        return self.sign(tx)

    def create_output(self):
        """A transaction whose output 0 pays to the wallet, and that output."""
        outpoint, amount = self.fee_input()
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(1), self.p2pkh()), CTxOut(sats(amount - 1 - FEE), self.p2pkh())]
        tx = self.sign(tx)
        return tx, COutPoint(tx.sha256, 0)

    def build_block(self, txs):
        # Without a block template: it needs a peer.
        tip = self.node.getblock(self.node.getbestblockhash())
        coinbase = create_coinbase(tip["height"] + 1)
        self.extra_nonce += 1
        coinbase.vin[0].scriptSig += bytes(CScript([self.extra_nonce]))
        coinbase.vout[0].nValue = 0
        coinbase.rehash()
        block = create_block(int(tip["hash"], 16), coinbase, tip["time"] + 1)
        block.nVersion = tip["version"]
        block.nBits = int(tip["bits"], 16)
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        add_witness_commitment(block)
        target = uint256_from_compact(block.nBits)
        while uint256_from_str(hash256(CBlockHeader.serialize(block))) > target:
            block.nNonce += 1
        block.rehash()
        return block

    def submit(self, txs, expected=(None,)):
        """Submits a block with these transactions after the coinbase, in this
        order, to both nodes. Each one must answer one of `expected`: None if
        the block connects, else its reject reason."""
        tip = self.node.getblockcount()
        block = self.build_block(txs).serialize(with_witness=True).hex()
        for node in self.nodes:
            result = node.submitblock(block)
            script_failure = result == "block-validation-failed" or \
                (result or "").startswith("mandatory-script-verify-flag-failed")
            assert result in expected or (SCRIPT_FAILURE in expected and script_failure), \
                "node %d: %s" % (node.index, result)
            assert_equal(node.getblockcount(), tip + (1 if result is None else 0))
        assert_equal(self.nodes[1].getbestblockhash(), self.node.getbestblockhash())

    # ------------------------------------------------------------------ tests

    def test_scripts_check_their_references(self):
        self.log.info("The scripts reject references in another order or to other outputs")
        self.submit([self.read("XY", [self.y, self.x])], (SCRIPT_FAILURE,))
        self.submit([self.read("X", [self.y])], (SCRIPT_FAILURE,))
        self.submit([self.read("X", [self.x, self.y])], (SCRIPT_FAILURE,))
        # Also after transactions of the same block resolved the same outputs.
        self.submit([self.read("X"), self.read("XY"), self.read("YX"), self.read("XY", [self.y, self.x])],
                    (SCRIPT_FAILURE,))

    def test_shared_in_one_block(self):
        self.log.info("Many transactions of one block reference the same outputs, in both orders")
        txs = []
        for _ in range(N):
            txs += [self.read("X"), self.read("XY"), self.read("YX")]
        self.submit(txs)

    def test_shared_through_the_mempool(self):
        self.log.info("The same through the mempool and a mined block")
        connect_nodes_bi(self.nodes, 0, 1)
        txids = []
        for _ in range(N // 2):
            for kind in ("X", "XY", "YX"):
                txids.append(self.node.sendrawtransaction(self.read(kind).serialize_with_witness().hex()))
        sync_mempools(self.nodes)
        assert_equal(sorted(self.nodes[1].getrawmempool()), sorted(txids))
        block = self.node.generate(1)[0]
        sync_blocks(self.nodes)
        assert_equal(self.node.getrawmempool(), [])
        assert_equal(self.nodes[1].getrawmempool(), [])
        assert set(txids) <= set(self.node.getblock(block)["tx"])
        disconnect_nodes(self.nodes[0], 1)

    def test_missing_after_shared(self):
        self.log.info("An output created in the block is missing after other references resolved")
        creation, created = self.create_output()
        self.submit([self.read("X"), creation, self.payment([self.x, created])], ("bad-txns-vrefin-missing",))
        creation, created = self.create_output()
        self.submit([self.read("XY"), creation, self.payment([created, self.y])], ("bad-txns-vrefin-missing",))
        self.pending = []

    def test_spent_in_the_block(self):
        self.log.info("A spend in the block between references, and before the first one")
        # X: first referenced, then spent, then referenced again. Y: spent
        # first, so its first reference comes from the undo data of the block.
        self.submit([self.read("X"), self.spend(self.y, Y_VALUE), self.read("YX"), self.read("Y"),
                     self.spend(self.x, X_VALUE), self.read("XY"), self.read("X"), self.read("Y")])
        self.pending = []

    def test_nothing_carries_over(self):
        self.log.info("The next block does not see outputs that the previous one referenced and spent")
        self.submit([self.read("X")], ("bad-txns-vrefin-missing",))
        self.submit([self.read("YX")], ("bad-txns-vrefin-missing",))

    def test_reorg(self):
        self.log.info("Both nodes disconnect and connect the blocks again")
        tip = self.node.getbestblockhash()
        first = self.node.getblockhash(self.first_block)
        for node in self.nodes:
            node.invalidateblock(first)
            assert_equal(node.getblockcount(), self.first_block - 1)
        for node in self.nodes:
            node.reconsiderblock(first)
            assert_equal(node.getbestblockhash(), tip)

    def test_verifychain_and_restart(self):
        self.log.info("verifychain 4, and a restart with -checklevel=4 and the threads swapped")
        tip = self.node.getbestblockhash()
        for node in self.nodes:
            assert node.verifychain(4, 0)
        for i, node in enumerate(self.nodes):
            self.restart_node(i, extra_args=[ARGS[1 - i][1], "-checklevel=4", "-checkblocks=0"])
            assert_equal(node.getbestblockhash(), tip)
            assert node.verifychain(4, 0)


if __name__ == '__main__':
    VrefinSharedOutputsTest().main()
