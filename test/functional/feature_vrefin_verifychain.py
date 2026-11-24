#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Reference inputs (NIP-014) resolve against the UTXO state at block entry,
also when the chain is verified again.

A block resolves its reference inputs against the UTXO state before it, as
NIP-014 section 7.2 specifies:

- a reference sees an output that another transaction of the same block
  spends, before or after it in the block;
- a reference never sees an output that a transaction of the same block
  creates, whether it comes before or after the reference and whether a
  later transaction spends it or not (bad-txns-vrefin-missing).

verifychain level 4 disconnects the last blocks in memory and connects them
again over a view at their own height. The referenced outputs of those blocks
are spent by then on the chain tip, so the reconnection has to resolve them
against that view, not against the tip: verifychain 4 and a restart with
-checklevel=4 accept the chain.
"""

from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxOut, from_hex,
                                     hash256, uint256_from_compact, uint256_from_str)
from test_framework.script import CScript
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal

FEE = Decimal("0.01")
TARGET_AMOUNT = Decimal("1")


def sats(amount):
    return int(Decimal(str(amount)) * COIN)


class VrefinVerifyChainTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # Node 1 only receives the blocks: block templates need a peer, and it
        # verifies the same chain after connecting it from the network.
        self.num_nodes = 2

    def run_test(self):
        self.node = self.nodes[0]
        self.extra_nonce = 0
        self.pending = []
        self.node.generate(130)

        # Outputs that the blocks below reference, then spend.
        self.targets = [self.send_to_self() for _ in range(3)]
        self.node.generate(1)

        self.test_spent_in_a_later_block()
        self.test_spent_in_the_same_block()
        self.test_outputs_created_in_the_same_block()
        self.test_verifychain()
        self.test_restart_with_checklevel_4()

    # ---------------------------------------------------------------- helpers

    def send_to_self(self):
        txid = self.node.sendtoaddress(self.node.getnewaddress(), TARGET_AMOUNT)
        tx = self.node.decoderawtransaction(self.node.gettransaction(txid)["hex"])
        n = [o["n"] for o in tx["vout"] if o["value"] == TARGET_AMOUNT][0]
        return COutPoint(int(txid, 16), n)

    def p2pkh(self):
        spk = bytes.fromhex(self.node.validateaddress(self.node.getnewaddress())["scriptPubKey"])
        assert_equal(len(spk), 25)
        return spk

    def fee_input(self):
        """A large wallet output that no pending transaction spends and that is
        not one of the referenced outputs."""
        taken = {(i.prevout.hash, i.prevout.n) for t in self.pending for i in t.vin}
        taken |= {(o.hash, o.n) for o in self.targets}
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

    def payment(self, references):
        """A version 3 payment back to the wallet with these reference inputs."""
        outpoint, amount = self.fee_input()
        tx = CTransaction()
        tx.nVersion = 3
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(amount - FEE), self.p2pkh())]
        tx.vrefin = list(references)
        return self.sign(tx)

    def spend(self, outpoint, prevtxs=None):
        """Spends a wallet output of TARGET_AMOUNT back to the wallet."""
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(TARGET_AMOUNT - FEE), self.p2pkh())]
        return self.sign(tx, prevtxs)

    def create_output(self):
        """A transaction whose output 0 pays TARGET_AMOUNT to the wallet.
        Returns it, that output and what signing a spend of it needs."""
        outpoint, amount = self.fee_input()
        spk = self.p2pkh()
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(outpoint, b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(TARGET_AMOUNT), spk), CTxOut(sats(amount - TARGET_AMOUNT - FEE), self.p2pkh())]
        tx = self.sign(tx)
        created = COutPoint(tx.sha256, 0)
        prevtxs = [{"txid": tx.hash, "vout": 0, "scriptPubKey": spk.hex(), "amount": TARGET_AMOUNT}]
        return tx, created, prevtxs

    def build_block(self, txs):
        tmpl = self.node.getblocktemplate({"rules": ["segwit"]})
        coinbase = create_coinbase(tmpl["height"])
        self.extra_nonce += 1
        coinbase.vin[0].scriptSig += bytes(CScript([self.extra_nonce]))
        coinbase.vout[0].nValue = tmpl["coinbasevalue"] - sum(t["fee"] for t in tmpl["transactions"])
        coinbase.rehash()
        block = create_block(int(tmpl["previousblockhash"], 16), coinbase, tmpl["curtime"])
        block.nVersion = tmpl["version"]
        block.nBits = int(tmpl["bits"], 16)
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        add_witness_commitment(block)
        target = uint256_from_compact(block.nBits)
        while uint256_from_str(hash256(CBlockHeader.serialize(block))) > target:
            block.nNonce += 1
        block.rehash()
        return block

    def submit(self, txs):
        """Submits a block with these transactions after the coinbase, in this
        order. Returns None if the block connects, or its reject reason."""
        tip = self.node.getblockcount()
        result = self.node.submitblock(self.build_block(txs).serialize(with_witness=True).hex())
        assert_equal(self.node.getblockcount(), tip + (1 if result is None else 0))
        self.sync_all()
        return result

    # ------------------------------------------------------------------ tests

    def test_spent_in_a_later_block(self):
        self.log.info("A reference to an output that a later block spends")
        target = self.targets[0]
        assert_equal(self.submit([self.payment([target])]), None)
        assert_equal(self.submit([self.spend(target)]), None)

    def test_spent_in_the_same_block(self):
        self.log.info("A reference to an output that the same block spends, before and after it")
        before = self.targets[1]
        assert_equal(self.submit([self.spend(before), self.payment([before])]), None)
        after = self.targets[2]
        assert_equal(self.submit([self.payment([after]), self.spend(after)]), None)

    def test_outputs_created_in_the_same_block(self):
        self.log.info("A reference to an output that the same block creates is missing")
        creation, created, _ = self.create_output()
        assert_equal(self.submit([creation, self.payment([created])]), "bad-txns-vrefin-missing")

        creation, created, _ = self.create_output()
        assert_equal(self.submit([self.payment([created]), creation]), "bad-txns-vrefin-missing")

        # Created and spent before the reference: the block's undo data holds
        # the output, but it was never in the state before the block.
        creation, created, prevtxs = self.create_output()
        spend = self.spend(created, prevtxs)
        assert_equal(self.submit([creation, spend, self.payment([created])]), "bad-txns-vrefin-missing")

        # The same transactions connect without the reference.
        assert_equal(self.submit([creation, spend]), None)

    def test_verifychain(self):
        self.log.info("verifychain 4 reconnects the blocks whose referenced outputs are spent at the tip")
        for node in self.nodes:
            assert node.verifychain(4, 0)

    def test_restart_with_checklevel_4(self):
        self.log.info("A restart with -checklevel=4 accepts the chain")
        tip = self.node.getbestblockhash()
        for i, node in enumerate(self.nodes):
            self.restart_node(i, extra_args=["-checklevel=4", "-checkblocks=0"])
            assert_equal(node.getbestblockhash(), tip)
            assert node.verifychain(4, 0)


if __name__ == '__main__':
    VrefinVerifyChainTest().main()
