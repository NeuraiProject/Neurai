#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The unified fork boundary, block by block (-forkheight).

Every rule of the unified fork activates at one height H. Blocks the miner
would never produce are built by hand from getblocktemplate and submitted.

- below H (B-15): the wallet refuses to pay AuthScript v1, post-quantum (v2)
  and strict ECDSA (v3) addresses, and the mempool refuses those outputs
- block H-1 (B-02, B-03): a block H-1 that spends with OP_CAT, issues a DEPIN
  asset or a long asset name, or sets the NIP-028 version flag is rejected
- connecting H-1 (B-04): the mempool keeps what block H can hold and evicts
  what it cannot (a BIP 125 signal, new outputs with the 'rvn' asset marker)
- templates (B-07): at H-1, H and H+1 getblocktemplate sets the version flag
  and the coinbase value of the next block, and its proposal is valid
- tip H-1 (B-15): the wallet pays the new address types
- script cache (B-13): an OP_CAT spend accepted into the mempool for block H
  and cached there is still rejected in a block H-1 after a reorg, which also
  evicts the payments to the new address types and leaves a valid template
  for block H-1 (B-05)
- block H (B-03): the legacy subsidy is rejected (bad-cb-amount); the fork
  transactions confirm; block H+1 without the version flag is rejected
"""

from decimal import Decimal

from test_framework.address import bech32m_address
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxOut, from_hex,
                                     hash256, uint256_from_compact, uint256_from_str)
from test_framework.script import CScript, OP_CAT, OP_EQUAL, OP_HASH160, hash160
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

H = 500  # regtest activates assets by version bits around block 432
NIP028_FLAG = 0x40000000
FEE = Decimal("0.01")
SEQUENCE = 0xffffffff
RBF_SEQUENCE = 0xfffffffd
BURN_ADDRESS = "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy"
ASSET = "BOUNDARYCOIN"
DEPIN_NAME = "&BOUNDARY"
LONG_NAME = "BOUNDARYLONGNAME" + "X" * 24  # 40 characters: above the legacy 30
# Valid only once OP_CAT is active.
CAT_SCRIPT = CScript([b"ab", b"cd", OP_CAT, b"abcd", OP_EQUAL])
# Family: (witness version, address). Below H the wallet refuses to pay v1
# (relay policy) and does not even decode v2 and v3 addresses.
NEW_ADDRESSES = {
    "AuthScript v1": (1, bech32m_address("tnc", 1, bytes([0x11] * 32))),
    "post-quantum v2": (2, bech32m_address("tpq", 2, bytes([0x22] * 32))),
    "strict ECDSA v3": (3, bech32m_address("tnq", 3, bytes([0x33] * 32))),
}


def p2sh(script):
    return CScript([OP_HASH160, hash160(bytes(script)), OP_EQUAL])


class UnifiedForkBoundaryTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # getblocktemplate needs a peer: node1 follows node0. With -par=1 a
        # rejected block reports its script error instead of a generic one.
        self.num_nodes = 2
        self.extra_args = [["-forkheight=%d" % H, "-par=1"], ["-forkheight=%d" % H]]

    def run_test(self):
        self.node = self.nodes[0]
        self.prepare()
        self.test_new_addresses_below_the_fork()
        self.test_block_h1_refuses_fork_transactions()
        self.test_connecting_h1()
        self.test_new_addresses_at_the_fork()
        self.test_script_cache_across_a_reorg()
        self.test_block_h()

    # ---------------------------------------------------------------- helpers

    def build_block(self, txs=None, version=None, coinbase_value=None):
        """A solved block on the tip from getblocktemplate. By default it holds
        the template transactions and claims exactly the subsidy."""
        tmpl = self.node.getblocktemplate({"rules": ["segwit"]})
        subsidy = tmpl["coinbasevalue"] - sum(t["fee"] for t in tmpl["transactions"])
        if txs is None:
            txs = [from_hex(CTransaction(), t["data"]) for t in tmpl["transactions"]]
        coinbase = create_coinbase(tmpl["height"])
        # An extra nonce after the height keeps every block built here distinct.
        self.extra_nonce += 1
        coinbase.vin[0].scriptSig += bytes(CScript([self.extra_nonce]))
        coinbase.vout[0].nValue = subsidy if coinbase_value is None else coinbase_value
        coinbase.rehash()
        block = create_block(int(tmpl["previousblockhash"], 16), coinbase, tmpl["curtime"])
        block.nVersion = tmpl["version"] if version is None else version
        block.nBits = int(tmpl["bits"], 16)
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        add_witness_commitment(block)
        # Regtest mines double-SHA256 over the 80-byte header.
        target = uint256_from_compact(block.nBits)
        while uint256_from_str(hash256(CBlockHeader.serialize(block))) > target:
            block.nNonce += 1
        block.rehash()
        return block

    def submit(self, block):
        return self.node.submitblock(block.serialize(with_witness=True).hex())

    def assert_block_rejected(self, txs, reason, **kwargs):
        tip = self.node.getbestblockhash()
        result = self.submit(self.build_block(txs, **kwargs))
        assert result is not None and result.startswith(reason), result
        assert_equal(self.node.getbestblockhash(), tip)

    def check_template(self, flag, subsidy):
        """B-07: version flag and coinbase value of the next block, and a valid proposal."""
        tmpl = self.node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(bool(tmpl["version"] & NIP028_FLAG), flag)
        fees = sum(t["fee"] for t in tmpl["transactions"])
        assert_equal(tmpl["coinbasevalue"], subsidy + fees)
        block = self.build_block()
        assert_equal(self.node.getblocktemplate({"mode": "proposal",
                                                 "data": block.serialize(with_witness=True).hex()}), None)
        return tmpl

    def coin(self, minimum=Decimal(2)):
        """A confirmed wallet coin no other transaction of this test uses."""
        for u in self.node.listunspent(1):
            key = (u["txid"], u["vout"])
            if key not in self.used and u["spendable"] and u["amount"] >= minimum:
                self.used.add(key)
                self.node.lockunspent(False, [{"txid": u["txid"], "vout": u["vout"]}])
                return u
        raise AssertionError("no spendable coin left")

    def signed(self, raw):
        result = self.node.signrawtransaction(raw)
        assert result["complete"], result
        return result["hex"]

    def raw_payment(self, outputs, sequence=SEQUENCE):
        """Spends one coin to the given extra outputs, the rest back to the wallet."""
        u = self.coin()
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(u["txid"], 16), u["vout"]), b"", sequence)]
        change = int((u["amount"] - FEE) * COIN) - sum(out.nValue for out in outputs)
        spk = bytes.fromhex(self.node.validateaddress(self.node.getnewaddress())["scriptPubKey"])
        tx.vout = list(outputs) + [CTxOut(change, spk)]
        return self.signed(tx.serialize().hex())

    def raw_issue(self, name, burn):
        """An issuance with nLockTime 0, so it is final in any block."""
        u = self.coin(minimum=burn + 1)
        outputs = {BURN_ADDRESS: burn,
                   self.node.getnewaddress(): u["amount"] - burn - FEE,
                   self.node.getnewaddress(): {"issue": {"asset_name": name, "asset_quantity": 1, "units": 0,
                                                         "reissuable": 0, "has_ipfs": 0}}}
        raw = self.node.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}], outputs)
        return from_hex(CTransaction(), self.signed(raw))

    def subsidy(self, height):
        """Regtest stays in the first halving period: 50,000 XNA, halved from H."""
        return 50000 * COIN // (2 if height >= H else 1)

    # ------------------------------------------------------------------ tests

    def prepare(self):
        node = self.node
        self.used = set()
        self.extra_nonce = 0
        node.generate(450)
        node.issue(ASSET, 1000)
        node.generate(1)
        cat_coin = self.raw_payment([CTxOut(COIN, p2sh(CAT_SCRIPT))])
        cat_txid = node.sendrawtransaction(cat_coin)
        node.generate(H - 2 - node.getblockcount())
        assert_equal(node.getblockcount(), H - 2)
        vout = [out["n"] for out in node.decoderawtransaction(cat_coin)["vout"]
                if out["scriptPubKey"]["hex"] == p2sh(CAT_SCRIPT).hex()][0]
        self.cat_spend = CTransaction()
        self.cat_spend.nVersion = 2
        self.cat_spend.vin = [CTxIn(COutPoint(int(cat_txid, 16), vout), bytes(CScript([bytes(CAT_SCRIPT)])), SEQUENCE)]
        dest = bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"])
        self.cat_spend.vout = [CTxOut(COIN - int(FEE * COIN), dest)]
        self.cat_spend.rehash()

    def test_new_addresses_below_the_fork(self):
        node = self.node
        self.log.info("B-15 below H: no payment to the new address types")
        for family, (version, address) in NEW_ADDRESSES.items():
            if version == 1:
                assert_raises_rpc_error(-4, "authscript-output-not-active", node.sendtoaddress, address, 1)
            else:
                assert_raises_rpc_error(-5, "Invalid address", node.sendtoaddress, address, 1)
            spk = bytes([0x50 + version, 0x20]) + bytes([0x11 * version] * 32)
            result = node.testmempoolaccept([self.raw_payment([CTxOut(COIN, spk)])])[0]
            assert_equal(result["reject-reason"], "64: authscript-output-not-active")
            self.log.info("%s refused: %s", family, address)
        assert_equal(node.getrawmempool(), [])

    def test_block_h1_refuses_fork_transactions(self):
        node = self.node
        self.log.info("B-02: block H-1 rejects a spend that needs OP_CAT")
        self.assert_block_rejected([self.cat_spend], "mandatory-script-verify-flag-failed")
        self.log.info("B-03: block H-1 with the NIP-028 version flag is rejected")
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert not tmpl["version"] & NIP028_FLAG
        self.assert_block_rejected([], "bad-version-nip028-early", version=tmpl["version"] | NIP028_FLAG)

    def test_connecting_h1(self):
        node = self.node
        self.log.info("B-04: at tip H-2 the mempool takes what is valid in block H-1")
        signal = node.sendrawtransaction(self.raw_payment([], sequence=RBF_SEQUENCE))
        rvn_transfer = node.transfer(ASSET, 1, node.getnewaddress())[0]
        payment = node.sendrawtransaction(self.raw_payment([]))
        assert_equal(sorted(node.getrawmempool()), sorted([signal, rvn_transfer, payment]))
        self.check_template(flag=False, subsidy=self.subsidy(H - 1))

        self.log.info("B-04: connecting H-1 evicts what block H cannot hold")
        block_h1 = self.build_block(txs=[])
        assert_equal(self.submit(block_h1), None)
        assert_equal(node.getblockcount(), H - 1)
        assert_equal(node.getblockchaininfo()["asset_marker"], "xna")
        mempool = node.getrawmempool()
        assert_equal(mempool, [payment])
        for txid in (signal, rvn_transfer):
            node.abandontransaction(txid)
        self.block_h1 = block_h1.hash
        self.check_template(flag=True, subsidy=self.subsidy(H))

    def test_new_addresses_at_the_fork(self):
        node = self.node
        self.log.info("B-15 at tip H-1: the wallet pays the new address types")
        self.new_address_txids = [node.sendtoaddress(address, 1) for _, address in NEW_ADDRESSES.values()]
        mempool = node.getrawmempool()
        for txid in self.new_address_txids:
            assert txid in mempool

    def test_script_cache_across_a_reorg(self):
        node = self.node
        self.log.info("B-13: the OP_CAT spend enters the mempool for block H")
        self.depin_issue = self.raw_issue(DEPIN_NAME, Decimal(10))
        self.long_issue = self.raw_issue(LONG_NAME, Decimal(1000))
        fork_txs = [self.cat_spend, self.depin_issue, self.long_issue]
        for tx in fork_txs:
            node.sendrawtransaction(tx.serialize_with_witness().hex())

        self.log.info("B-13: after a reorg below H the cached verdict is not reused")
        node.invalidateblock(self.block_h1)
        assert_equal(node.getblockcount(), H - 2)
        mempool = node.getrawmempool()
        for txid in [tx.hash for tx in fork_txs] + self.new_address_txids:
            assert txid not in mempool, txid
        # B-05: what the miner proposes after the reorg is a valid block H-1.
        self.check_template(flag=False, subsidy=self.subsidy(H - 1))
        self.assert_block_rejected([self.cat_spend], "mandatory-script-verify-flag-failed")
        self.log.info("B-02: block H-1 rejects a DEPIN issuance and a long asset name")
        for tx in (self.depin_issue, self.long_issue):
            tip = node.getbestblockhash()
            result = self.submit(self.build_block([tx]))
            # Before H neither name is valid, so the burn of a valid issuance is not found.
            assert_equal(result, "bad-txns-issue-burn-not-found")
            assert_equal(node.getbestblockhash(), tip)

        node.reconsiderblock(self.block_h1)
        assert_equal(node.getbestblockhash(), self.block_h1)
        for tx in fork_txs:
            node.sendrawtransaction(tx.serialize_with_witness().hex())
        for txid in self.new_address_txids:
            node.sendrawtransaction(node.gettransaction(txid)["hex"])
        self.fork_txids = [tx.hash for tx in fork_txs] + self.new_address_txids

    def test_block_h(self):
        node = self.node
        self.log.info("B-03: block H paying the legacy subsidy is rejected")
        self.assert_block_rejected([], "bad-cb-amount", coinbase_value=self.subsidy(H - 1))

        self.log.info("B-07: the template for block H holds every fork transaction")
        tmpl = self.check_template(flag=True, subsidy=self.subsidy(H))
        in_template = [t["txid"] for t in tmpl["transactions"]]
        for txid in self.fork_txids:
            assert txid in in_template, txid
        block_h = node.generate(1)[0]
        confirmed = node.getblock(block_h)["tx"]
        for txid in self.fork_txids:
            assert txid in confirmed, txid
        assert_equal(node.getassetdata(DEPIN_NAME)["amount"], 1)
        assert_equal(node.getassetdata(LONG_NAME)["amount"], 1)

        self.log.info("B-03: block H+1 without the version flag is rejected")
        tmpl = self.check_template(flag=True, subsidy=self.subsidy(H + 1))
        self.assert_block_rejected([], "bad-version-nip028", version=tmpl["version"] & ~NIP028_FLAG)
        node.generate(1)
        assert_equal(node.getblockcount(), H + 1)


if __name__ == '__main__':
    UnifiedForkBoundaryTest().main()
