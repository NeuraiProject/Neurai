#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Below the unified fork, 2.0 gives a transaction the verdict 1.0.7 gives it.

Each shape below was valid for one of them and invalid for the other, which
splits mainnet while both run. The verdicts expected below the fork are the
ones a running 1.0.7 node gave (B-17). From H the new rules apply, and the
mempool drops at H what it accepted below it and block H cannot hold.

- an asset transfer after a prefix that is not P2PKH (OP_CHECKSIGVERIFY):
  valid below H, as in 1.0.7, but not relayed by 2.0; invalid from H
- an issuance whose burn is an asset data push of 21 bytes, whose first 20
  bytes are the burn address: valid and relayed below H; invalid from H
- OP_XNA_ASSET OP_1 <32 bytes> <push>: an inert output below H; asset data
  from H, and this one does not deserialize
- an asset output in the AuthScript form: invalid below H
- an issuance with an extra AuthScript-form asset output: valid in a block
  below H, where that output is not an asset
- a version 3 transaction without reference inputs (B-16), in the 1.0.7
  format: valid on both sides of H, not relayed below it, as in 1.0.7
- a transaction with reference inputs (NIP-014, flag 2 of the extended
  format): invalid below H, valid from H, and gone from the mempool after a
  reorganization below H

The NIP-040 marker moves to a later height, so that only these rules change
at H and the 'rvn' marker stays valid.
"""

from decimal import Decimal
import struct

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxOut, from_hex,
                                     hash256, ser_string, uint256_from_compact, uint256_from_str)
from test_framework.script import CScript
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, sync_blocks, wait_until

H = 600  # regtest activates assets by version bits around block 432
FEE = Decimal("0.01")
BURN_ADDRESS = "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy"
ASSET = "PARITY"
COMMITMENT = bytes(range(1, 33))


def push(data):
    return bytes(CScript([data]))


def sats(amount):
    return int(Decimal(str(amount)) * COIN)


def asset_script(prefix, message):
    return prefix + b"\xc0" + push(message) + b"\x75"


def transfer_message(name, amount):
    return b"rvnt" + ser_string(name.encode()) + struct.pack("<q", amount)


def new_asset_message(name, amount):
    return b"rvnq" + ser_string(name.encode()) + struct.pack("<qbbb", amount, 0, 1, 0)


def owner_message(name):
    return b"rvno" + ser_string((name + "!").encode())


class LegacyParityTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # node0 relays with the standard policy; node1 plays a miner that takes
        # non-standard transactions, as a 1.0.7 pool may.
        self.num_nodes = 2
        self.extra_args = [["-forkheight=%d" % H, "-nip040height=%d" % (H + 1000)],
                           ["-forkheight=%d" % H, "-nip040height=%d" % (H + 1000), "-acceptnonstdtxn=1"]]

    def run_test(self):
        self.node, self.miner = self.nodes
        self.extra_nonce = 0
        self.node.generate(520)
        self.node.issue(ASSET, 1000)
        # The output reference inputs point at: the miner's, so node0 never spends it.
        ref_txid = self.node.sendtoaddress(self.miner.getnewaddress(), 1)
        self.node.generate(1)
        self.sync_all()
        ref_tx = self.node.decoderawtransaction(self.node.gettransaction(ref_txid)["hex"])
        ref_n = [o["n"] for o in ref_tx["vout"] if o["value"] == 1][0]
        self.reference = COutPoint(int(ref_txid, 16), ref_n)

        self.test_below_the_fork()
        self.test_mempool_at_the_fork()
        self.test_from_the_fork()
        self.test_reorganization_below_the_fork()

    # ---------------------------------------------------------------- helpers

    def p2pkh(self):
        spk = bytes.fromhex(self.node.validateaddress(self.node.getnewaddress())["scriptPubKey"])
        assert_equal(len(spk), 25)
        return spk

    def xna_input(self, minimum):
        spent = {(i.prevout.hash, i.prevout.n) for t in self.pending for i in t.vin}
        for u in sorted(self.node.listunspent(1), key=lambda u: -u["amount"]):
            if u["amount"] >= minimum and (int(u["txid"], 16), u["vout"]) not in spent:
                return u
        raise AssertionError("no spendable output of %s" % minimum)

    def sign(self, tx):
        result = self.node.signrawtransaction(tx.serialize().hex())
        assert result["complete"], result
        signed = from_hex(CTransaction(), result["hex"])
        signed.rehash()
        self.pending.append(signed)
        return signed

    def build(self, inputs, outputs):
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(txid, 16), n), b"", 0xffffffff) for txid, n in inputs]
        tx.vout = [CTxOut(value, spk) for value, spk in outputs]
        return self.sign(tx)

    def odd_prefix_transfer(self):
        """One unit of the asset to an asset script after P2PKH with
        OP_CHECKSIGVERIFY, the rest back to a P2PKH asset script."""
        outpoint = max(self.node.listmyassets(ASSET, True)[ASSET]["outpoints"], key=lambda o: o["amount"])
        xna = self.xna_input(1)
        me = self.p2pkh()
        odd = me[:-1] + b"\xad"
        rest = sats(outpoint["amount"]) - COIN
        return self.build([(outpoint["txid"], outpoint["vout"]), (xna["txid"], xna["vout"])],
                          [(0, asset_script(odd, transfer_message(ASSET, COIN))),
                           (0, asset_script(me, transfer_message(ASSET, rest))),
                           (sats(xna["amount"] - FEE), me)])

    def issuance(self, name, burn=None, extra=None):
        xna = self.xna_input(1001)
        me = self.p2pkh()
        burn_spk = bytes.fromhex(self.node.validateaddress(BURN_ADDRESS)["scriptPubKey"]) if burn is None else burn
        outputs = [(1000 * COIN, burn_spk), (sats(xna["amount"] - 1000 - FEE), me)]
        if extra is not None:
            outputs.append((0, extra))
        outputs += [(0, asset_script(me, owner_message(name))), (0, asset_script(me, new_asset_message(name, 10 * COIN)))]
        return self.build([(xna["txid"], xna["vout"])], outputs)

    def burn_push(self):
        """The burn address as the first 20 bytes of a 21-byte asset data push."""
        burn_hash = bytes.fromhex(self.node.validateaddress(BURN_ADDRESS)["scriptPubKey"])[3:23]
        return b"\xc0" + push(burn_hash + b"\x00")

    def null_authscript_payment(self):
        xna = self.xna_input(1)
        return self.build([(xna["txid"], xna["vout"])],
                          [(0, b"\xc0\x51\x20" + bytes(32) + push(b"\x00")), (sats(xna["amount"] - FEE), self.p2pkh())])

    def authscript_transfer(self):
        outpoint = max(self.node.listmyassets(ASSET, True)[ASSET]["outpoints"], key=lambda o: o["amount"])
        xna = self.xna_input(1)
        me = self.p2pkh()
        rest = sats(outpoint["amount"]) - COIN
        authscript = b"\x51\x20" + COMMITMENT
        return self.build([(outpoint["txid"], outpoint["vout"]), (xna["txid"], xna["vout"])],
                          [(0, asset_script(authscript, transfer_message(ASSET, COIN))),
                           (0, asset_script(me, transfer_message(ASSET, rest))),
                           (sats(xna["amount"] - FEE), me)])

    def version3_payment(self, references=False):
        """A version 3 payment, with one reference input or none."""
        xna = self.xna_input(1)
        tx = CTransaction()
        tx.nVersion = 3
        tx.vin = [CTxIn(COutPoint(int(xna["txid"], 16), xna["vout"]), b"", 0xffffffff)]
        tx.vout = [CTxOut(sats(xna["amount"] - FEE), self.p2pkh())]
        if references:
            tx.vrefin = [self.reference]
        return self.sign(tx)

    def verdict(self, node, tx):
        result = node.testmempoolaccept([tx.serialize().hex()])[0]
        # The reason comes after its reject code ("64: scriptpubkey").
        return "accepted" if result["allowed"] else result["reject-reason"].split(": ", 1)[-1]

    def build_block(self, txs):
        tmpl = self.miner.getblocktemplate({"rules": ["segwit"]})
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
        return self.miner.submitblock(self.build_block(txs).serialize(with_witness=True).hex())

    # ------------------------------------------------------------------ tests

    def test_below_the_fork(self):
        self.log.info("Below H: each shape gets the verdict of 1.0.7")
        self.pending = []
        odd = self.odd_prefix_transfer()
        assert_equal(self.verdict(self.node, odd), "scriptpubkey")  # not relayed by 2.0
        assert_equal(self.verdict(self.miner, odd), "accepted")
        burn = self.issuance("PARITYB", burn=self.burn_push())
        assert_equal(self.verdict(self.node, burn), "accepted")
        null = self.null_authscript_payment()
        assert_equal(self.verdict(self.node, null), "accepted")
        authscript = self.authscript_transfer()
        assert_equal(self.verdict(self.miner, authscript), "bad-txns-op-xna-asset-not-in-right-script-location")
        self.pending.remove(authscript)
        extra = asset_script(b"\x51\x20" + COMMITMENT, transfer_message(ASSET, COIN))
        issue_extra = self.issuance("PARITYC", extra=extra)
        v3 = self.version3_payment()
        assert_equal(self.verdict(self.node, v3), "version-v3-not-active")  # not relayed, as in 1.0.7
        assert_equal(self.verdict(self.miner, v3), "accepted")
        assert_equal(len(v3.serialize_with_witness()), len(v3.serialize_without_witness()))  # no marker
        refs = self.version3_payment(references=True)
        assert_equal(self.verdict(self.miner, refs), "bad-txns-vrefin-not-active")
        self.pending.remove(refs)

        # One block below H holds all of them but the AuthScript transfer and
        # the reference inputs.
        tip = self.node.getblockcount()
        assert_equal(self.submit([odd, burn, null, issue_extra, v3]), None)
        self.sync_all()
        assert_equal(self.node.getblockcount(), tip + 1)
        assets = self.node.listassets()
        assert "PARITYB" in assets and "PARITYC" in assets, assets
        assert_equal(self.node.decoderawtransaction(self.node.gettransaction(v3.hash)["hex"])["version"], 3)
        assert_equal(self.submit([authscript]), "bad-txns-op-xna-asset-not-in-right-script-location")
        assert_equal(self.submit([refs]), "bad-txns-vrefin-not-active")

    def test_mempool_at_the_fork(self):
        self.log.info("Connecting H-1: the mempool drops what block H cannot hold")
        self.pending = []
        odd = self.odd_prefix_transfer()
        self.miner.sendrawtransaction(odd.serialize().hex())
        burn = self.issuance("PARITYD", burn=self.burn_push())
        self.node.sendrawtransaction(burn.serialize().hex())
        null = self.null_authscript_payment()
        self.node.sendrawtransaction(null.serialize().hex())
        v3 = self.version3_payment()
        self.miner.sendrawtransaction(v3.serialize().hex())
        # The odd prefix and the version 3 payment stay in the miner's mempool
        # only: node0 does not relay them.
        expected = sorted(t.hash for t in (odd, burn, null, v3))
        wait_until(lambda: sorted(self.miner.getrawmempool()) == expected, timeout=30,
                   err_msg="miner mempool")
        # Empty blocks up to H-2, so that the three stay in the mempool.
        while self.node.getblockcount() < H - 2:
            assert_equal(self.submit([]), None)
        sync_blocks(self.nodes)
        assert_equal(sorted(self.miner.getrawmempool()), expected)
        assert_equal(self.submit([]), None)  # H-1
        sync_blocks(self.nodes)
        # Only the version 3 payment, valid on both sides, stays.
        assert_equal(self.node.getrawmempool(), [])
        assert_equal(self.miner.getrawmempool(), [v3.hash])
        tmpl = self.miner.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["height"], H)
        assert_equal([t["txid"] for t in tmpl["transactions"]], [v3.hash])

    def test_from_the_fork(self):
        self.log.info("From H: the new rules")
        assert_equal(self.submit([]), None)  # H
        sync_blocks(self.nodes)
        assert_equal(self.node.getblockcount(), H)
        self.pending = []
        assert_equal(self.verdict(self.miner, self.odd_prefix_transfer()),
                     "bad-txns-op-xna-asset-not-in-right-script-location")
        assert_equal(self.verdict(self.miner, self.issuance("PARITYE", burn=self.burn_push())),
                     "bad-txns-issue-burn-not-found")
        assert_equal(self.verdict(self.miner, self.null_authscript_payment()),
                     "bad-txns-null-asset-data-serialization")
        self.pending = []
        assert_equal(self.verdict(self.node, self.version3_payment()), "accepted")
        refs = self.version3_payment(references=True)
        assert_equal(self.verdict(self.node, refs), "accepted")
        self.node.sendrawtransaction(refs.serialize_with_witness().hex())
        decoded = self.node.getrawtransaction(refs.hash, True)
        assert_equal(decoded["vrefin"], [{"txid": "%064x" % self.reference.hash, "vout": self.reference.n}])
        assert_equal(self.submit([refs]), None)  # H+1
        sync_blocks(self.nodes)
        assert refs.hash in self.node.getblock(self.node.getbestblockhash())["tx"]

    def test_reorganization_below_the_fork(self):
        self.log.info("A reorganization below H drops reference inputs from the mempool")
        self.pending = []
        refs = self.version3_payment(references=True)
        self.node.sendrawtransaction(refs.serialize_with_witness().hex())
        mined = self.node.getblock(self.node.getbestblockhash())["tx"][1]
        block_h1 = self.node.getblockhash(H - 1)
        for node in self.nodes:
            node.invalidateblock(block_h1)
            assert_equal(node.getblockcount(), H - 2)
            mempool = node.getrawmempool()
            assert refs.hash not in mempool and mined not in mempool, mempool
        for node in self.nodes:
            node.reconsiderblock(block_h1)
        sync_blocks(self.nodes)
        assert_equal(self.node.getblockcount(), H + 1)


if __name__ == '__main__':
    LegacyParityTest().main()
