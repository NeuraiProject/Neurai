#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Every function of the unified fork relays under the standard policy.

Mainnet requires standard transactions, and the unit tests of the new opcodes
call the interpreter directly, without the mempool. Here both nodes run the
default standard policy with every rule at -forkheight=H. node0 accepts one
minimal spend per function, node1 receives it over P2P and mines it in a
block it assembles itself.

- the funding transaction pays every contract at tip H-1 (next block is H)
- AuthScript v1 (authType 0x00) spends of: OP_CAT, OP_SPLIT, OP_REVERSEBYTES,
  64-bit OP_MUL/OP_DIV/OP_MOD, Keccak-256/BLAKE2b (NIP-030), BLAKE3/SHA3-256/
  SHA-512 (NIP-034a), OP_POSEIDON (NIP-036), OP_CHECKMERKLEINCLUSION (NIP-031),
  Ed25519 (NIP-035), CSFS with ECDSA and ML-DSA-44 keys (NIP-021),
  OP_CHECKSIGADD (NIP-039), CTV, OP_TXHASH (NIP-042), OP_TXFIELD,
  OP_TXLOCKTIME, OP_OUTPUTVALUE/OP_OUTPUTSCRIPT, OP_INPUTCOUNT/OP_OUTPUTCOUNT,
  OP_INPUTVALUE (NIP-024), OP_CHAINCONTEXT (NIP-026), OP_INPUTFIELD (NIP-043),
  OP_OUTPUTAUTHCOMMITMENT/OP_OUTPUTAUTHDEST (NIP-023/041), OP_ZKVERIFY
  profile 1 (NIP-016) and the asset introspection opcodes
- an AuthScript tree leaf (NIP-044), a version 3 transaction with a reference
  input (NIP-014) and an AuthScript wrapped in P2SH

OP_CHECKASSETAUTH (feature_assetauth.py), the strict v2/v3 families
(feature_authscript_activation.py, feature_pq_assets.py) and the DEPIN rules
have their own tests, which also run under the standard policy.
"""

import hashlib
import json
import os
import re
import struct
from decimal import Decimal

from test_framework.messages import (COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, from_hex,
                                     ser_compact_size)
from test_framework.script import (CScript, CScriptOp, OP_0, OP_CHECKSIGFROMSTACK, OP_CHECKTEMPLATEVERIFY,
                                   OP_CAT, OP_DIV, OP_DROP, OP_EQUAL, OP_EQUALVERIFY, OP_GREATERTHAN,
                                   OP_HASH160, OP_MOD, OP_MUL, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_SWAP,
                                   OP_TRUE, OP_TXHASH, hash160)
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, sync_blocks, sync_mempools

H = 500
CHAIN_ID = 2  # regtest
FUND = COIN
FEE = 5000000
OUT = FUND - FEE
SEQUENCE = 0xffffffff
ASSET = "RELAYCHECK"
ASSET_QTY = 100

OP_TXFIELD = CScriptOp(0xb6)
OP_SPLIT = CScriptOp(0xb7)
OP_KECCAK256 = CScriptOp(0xba)
OP_BLAKE2B = CScriptOp(0xbb)
OP_REVERSEBYTES = CScriptOp(0xbc)
OP_CHECKMERKLEINCLUSION = CScriptOp(0xc1)
OP_OUTPUTAUTHDEST = CScriptOp(0xc2)
OP_ZKVERIFY = CScriptOp(0xc3)
OP_INPUTFIELD = CScriptOp(0xc4)
OP_TXLOCKTIME = CScriptOp(0xc5)
OP_BLAKE3 = CScriptOp(0xc8)
OP_POSEIDON = CScriptOp(0xc9)
OP_SHA3_256 = CScriptOp(0xca)
OP_SHA512 = CScriptOp(0xcb)
OP_OUTPUTVALUE = CScriptOp(0xcc)
OP_OUTPUTSCRIPT = CScriptOp(0xcd)
OP_OUTPUTASSETFIELD = CScriptOp(0xce)
OP_INPUTASSETFIELD = CScriptOp(0xcf)
OP_INPUTCOUNT = CScriptOp(0xd0)
OP_OUTPUTCOUNT = CScriptOp(0xd1)
OP_REFINPUTFIELD = CScriptOp(0xd2)
OP_REFINPUTCOUNT = CScriptOp(0xd4)
OP_OUTPUTAUTHCOMMITMENT = CScriptOp(0xd5)
OP_INPUTVALUE = CScriptOp(0xd6)
OP_CHAINCONTEXT = CScriptOp(0xd7)
OP_CHECKSIG_ED25519 = CScriptOp(0xdd)
OP_CHECKSIGADD = CScriptOp(0xde)

# Reference values from the unit tests (keccak256_tests.cpp, blake3_tests.cpp).
KECCAK256_ABC = bytes.fromhex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
BLAKE3_ABC = bytes.fromhex("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")

DATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "src", "test", "data")


def load_json(name):
    with open(os.path.join(DATA_DIR, name), encoding="utf8") as f:
        return json.load(f)


def groth16_vector():
    with open(os.path.join(DATA_DIR, "groth16_vectors.h"), encoding="utf8") as f:
        text = f.read()
    return {name: bytes.fromhex(re.search(r'\b%s = "([0-9a-f]+)"' % name, text).group(1))
            for name in ("VK", "PROOF", "INPUTS")}


def sha256(data):
    return hashlib.sha256(data).digest()


def tagged_hash(tag, msg):
    t = sha256(tag)
    return sha256(t + t + msg)


def transfer_spk(dest_spk, name, amount):
    """Asset transfer script with the NIP-040 'xna' marker."""
    payload = b"xnat" + ser_compact_size(len(name)) + name.encode() + struct.pack("<q", amount)
    return dest_spk + b"\xc0" + bytes(CScript([payload])) + b"\x75"


class AuthScript:
    """A generic AuthScript v1 address (authType 0x00) for a witness script."""

    def __init__(self, script):
        self.script = bytes(script)
        self.commitment = tagged_hash(b"NeuraiAuthScript", b"\x01\x00" + sha256(self.script))
        self.spk = b"\x51\x20" + self.commitment
        self.dest33 = b"\x01" + self.commitment


def set_witness(tx, index, stack):
    while len(tx.wit.vtxinwit) < len(tx.vin):
        tx.wit.vtxinwit.append(CTxInWitness())
    tx.wit.vtxinwit[index].scriptWitness.stack = stack


class Contract:
    """A funded output and the witness that spends it."""

    def __init__(self, name, spk, witness, script_sig=b"", out_spk=None, version=2):
        self.name = name
        self.spk = spk
        self.witness = witness
        self.script_sig = script_sig
        self.out_spk = out_spk
        self.version = version
        self.outpoint = None


class UnifiedForkRelayTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-forkheight=%d" % H]] * 2

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(H - 1)
        self.sync_all()
        self.log.info("Both nodes run the standard policy: a bare OP_TRUE output is refused")
        coin = node0.listunspent()[0]
        raw = node0.createrawtransaction([{"txid": coin["txid"], "vout": coin["vout"]}],
                                         {node0.getnewaddress(): coin["amount"] - Decimal("0.05")})
        tx = from_hex(CTransaction(), node0.signrawtransaction(raw)["hex"])
        tx.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx = from_hex(CTransaction(), node0.signrawtransaction(tx.serialize().hex())["hex"])
        for node in self.nodes:
            result = node.testmempoolaccept([tx.serialize().hex()])[0]
            assert_equal(result["reject-reason"], "64: scriptpubkey")
        self.dest_spk = self.spk(node0.getnewaddress())
        self.ref_spk = self.spk(node0.getnewaddress())
        self.sink = AuthScript(CScript([OP_TRUE]))

        contracts = self.contracts()
        self.log.info("Tip H-1: one transaction pays all %d contracts", len(contracts))
        self.fund(contracts)

        self.log.info("Asset introspection needs an asset held by a contract")
        asset_contract = self.fund_asset_contract()

        self.log.info("node0 accepts every spend and relays it to node1")
        spends = [(c.name, self.spend(c)) for c in contracts]
        spends.append(("OP_INPUTASSETFIELD / OP_OUTPUTASSETFIELD", self.spend_asset(asset_contract)))
        txids = {}
        for name, tx_hex in spends:
            result = node0.testmempoolaccept([tx_hex])[0]
            assert result["allowed"], "%s: %s" % (name, result)
            txids[name] = node0.sendrawtransaction(tx_hex)
        sync_mempools(self.nodes)
        assert_equal(set(node1.getrawmempool()), set(txids.values()))

        self.log.info("node1 assembles the block that confirms them")
        block = node1.getblock(node1.generate(1)[0])
        sync_blocks(self.nodes)
        for name, txid in txids.items():
            assert txid in block["tx"], name
        assert_equal(node0.getrawmempool(), [])
        assert_equal(node0.getbestblockhash(), block["hash"])

    # ---------------------------------------------------------------- helpers

    def spk(self, address):
        return bytes.fromhex(self.nodes[0].validateaddress(address)["scriptPubKey"])

    def fund(self, contracts):
        """Pays FUND to every contract and to the reference output at tip H-1."""
        node0 = self.nodes[0]
        assert_equal(node0.getblockcount(), H - 1)
        tx = CTransaction()
        tx.nVersion = 2
        tx.vout = [CTxOut(FUND, c.spk) for c in contracts] + [CTxOut(FUND, self.ref_spk)]
        funded = node0.fundrawtransaction(tx.serialize_without_witness().hex())["hex"]
        signed = node0.signrawtransaction(funded)
        assert signed["complete"]
        txid = node0.sendrawtransaction(signed["hex"])
        sync_mempools(self.nodes)
        self.nodes[1].generate(1)
        sync_blocks(self.nodes)
        outputs = {}
        for out in node0.decoderawtransaction(signed["hex"])["vout"]:
            outputs[out["scriptPubKey"]["hex"]] = out["n"]
        for c in contracts:
            c.outpoint = (txid, outputs[c.spk.hex()])
        self.ref_outpoint = (txid, outputs[self.ref_spk.hex()])

    def spend(self, contract):
        tx = CTransaction()
        tx.nVersion = contract.version
        txid, n = contract.outpoint
        tx.vin = [CTxIn(COutPoint(int(txid, 16), n), contract.script_sig, SEQUENCE)]
        tx.vout = [CTxOut(OUT, contract.out_spk or self.dest_spk)]
        if contract.version == 3:
            tx.vrefin = [COutPoint(int(self.ref_outpoint[0], 16), self.ref_outpoint[1])]
        set_witness(tx, 0, contract.witness)
        return tx.serialize_with_witness().hex()

    def generic(self, name, script, args=(), **kwargs):
        a = AuthScript(script)
        return Contract(name, a.spk, [b"\x00"] + list(args) + [a.script], **kwargs)

    # -------------------------------------------------------------- contracts

    def contracts(self):
        g = self.generic
        csfs = load_json("txhash_csfs_vectors.json")
        ecdsa = next(v for v in csfs if v["algorithm"] == "ecdsa")
        pq = next(v for v in csfs if v["algorithm"] == "pq")
        ecdsa_pub, pq_pub = bytes.fromhex(ecdsa["pubkey"]), bytes.fromhex(pq["pubkey"])
        ed25519 = load_json("ed25519_vectors.json")["rfc8032_pure_ed25519"][0]
        poseidon = next(v for v in load_json("poseidon_vectors.json")["spec_pinned_sponge"]
                        if v["input_hex"] == b"hello".hex())
        zk = groth16_vector()
        abc = b"abc"
        return [
            g("OP_CAT", CScript([b"ab", b"cd", OP_CAT, b"abcd", OP_EQUAL])),
            g("OP_SPLIT", CScript([b"abcd", 2, OP_SPLIT, b"cd", OP_EQUALVERIFY, b"ab", OP_EQUAL])),
            g("OP_REVERSEBYTES", CScript([b"abcd", OP_REVERSEBYTES, b"dcba", OP_EQUAL])),
            g("64-bit OP_MUL / OP_DIV / OP_MOD", CScript([
                3000000000, 3, OP_MUL, 9000000000, OP_NUMEQUALVERIFY,
                9000000000, 3, OP_DIV, 3000000000, OP_NUMEQUALVERIFY,
                9000000000, 7, OP_MOD, 5, OP_NUMEQUAL])),
            g("OP_KECCAK256 / OP_BLAKE2B (NIP-030)", CScript([
                abc, OP_KECCAK256, KECCAK256_ABC, OP_EQUALVERIFY,
                abc, OP_BLAKE2B, hashlib.blake2b(abc, digest_size=32).digest(), OP_EQUAL])),
            g("OP_BLAKE3 / OP_SHA3_256 / OP_SHA512 (NIP-034a)", CScript([
                abc, OP_BLAKE3, BLAKE3_ABC, OP_EQUALVERIFY,
                abc, OP_SHA3_256, hashlib.sha3_256(abc).digest(), OP_EQUALVERIFY,
                abc, OP_SHA512, hashlib.sha512(abc).digest(), OP_EQUAL])),
            g("OP_POSEIDON (NIP-036)", CScript([
                b"hello", OP_POSEIDON, bytes.fromhex(poseidon["output_hex"]), OP_EQUAL])),
            g("OP_CHECKMERKLEINCLUSION (NIP-031)", self.merkle_script()),
            g("OP_CHECKSIG_ED25519 (NIP-035)", CScript([
                bytes.fromhex(ed25519["signature"]), bytes.fromhex(ed25519["message"]),
                bytes.fromhex(ed25519["pubkey"]), OP_CHECKSIG_ED25519])),
            g("OP_CHECKSIGFROMSTACK, ECDSA key (NIP-021)",
              CScript([bytes.fromhex(ecdsa["digest"]), ecdsa_pub, OP_CHECKSIGFROMSTACK]),
              [bytes.fromhex(ecdsa["signature"])]),
            g("OP_CHECKSIGFROMSTACK, ML-DSA-44 key (NIP-021)",
              CScript([bytes.fromhex(pq["digest"]), pq_pub, OP_CHECKSIGFROMSTACK]),
              [bytes.fromhex(pq["signature"])]),
            # Empty signatures add nothing: 0 of {ECDSA, ML-DSA-44}.
            g("OP_CHECKSIGADD (NIP-039)", CScript([
                OP_0, OP_0, ecdsa_pub, OP_CHECKSIGADD,
                OP_0, OP_SWAP, pq_pub, OP_CHECKSIGADD, OP_0, OP_NUMEQUAL])),
            g("OP_CHECKTEMPLATEVERIFY", CScript([self.ctv_hash(), OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_TRUE])),
            g("OP_TXHASH (NIP-042)", CScript([struct.pack("<H", 0x0003), OP_TXHASH, self.txhash_version_locktime(),
                                             OP_EQUAL])),
            g("OP_TXFIELD", CScript([1, OP_TXFIELD, struct.pack("<q", FUND), OP_EQUAL])),
            g("OP_TXLOCKTIME", CScript([OP_TXLOCKTIME, struct.pack("<I", 0), OP_EQUAL])),
            g("OP_OUTPUTVALUE / OP_OUTPUTSCRIPT", CScript([
                0, OP_OUTPUTVALUE, OUT, OP_NUMEQUALVERIFY, 0, OP_OUTPUTSCRIPT, self.dest_spk, OP_EQUAL])),
            g("OP_INPUTCOUNT / OP_OUTPUTCOUNT", CScript([
                OP_INPUTCOUNT, 1, OP_NUMEQUALVERIFY, OP_OUTPUTCOUNT, 1, OP_NUMEQUAL])),
            g("OP_INPUTVALUE (NIP-024)", CScript([0, OP_INPUTVALUE, FUND, OP_NUMEQUAL])),
            g("OP_CHAINCONTEXT (NIP-026)", CScript([
                3, OP_CHAINCONTEXT, CHAIN_ID, OP_NUMEQUALVERIFY, 1, OP_CHAINCONTEXT, H, OP_GREATERTHAN])),
            g("OP_INPUTFIELD (NIP-043)", CScript([0, 1, OP_INPUTFIELD, struct.pack("<q", FUND), OP_EQUAL])),
            g("OP_OUTPUTAUTHCOMMITMENT / OP_OUTPUTAUTHDEST (NIP-023, NIP-041)", CScript([
                0, OP_OUTPUTAUTHCOMMITMENT, self.sink.commitment, OP_EQUALVERIFY,
                0, OP_OUTPUTAUTHDEST, self.sink.dest33, OP_EQUAL]), out_spk=self.sink.spk),
            g("OP_ZKVERIFY profile 1 (NIP-016)", CScript([4, 1, OP_ZKVERIFY]),
              [zk["PROOF"], zk["VK"]] + [zk["INPUTS"][i:i + 32] for i in range(0, len(zk["INPUTS"]), 32)]),
            g("Reference input in a version 3 transaction (NIP-014)", CScript([
                OP_REFINPUTCOUNT, 1, OP_NUMEQUALVERIFY, 0, 1, OP_REFINPUTFIELD, FUND, OP_NUMEQUAL]), version=3),
            self.tree_contract(),
            self.p2sh_contract(),
        ]

    def ctv_hash(self):
        """BIP 119 template of the standard spend: one input, one output to dest."""
        out = CTxOut(OUT, self.dest_spk).serialize()
        return sha256(struct.pack("<iI", 2, 0) + struct.pack("<I", 1) + sha256(struct.pack("<I", SEQUENCE)) +
                      struct.pack("<I", 1) + sha256(out) + struct.pack("<I", 0))

    def txhash_version_locktime(self):
        tag = sha256(b"NeuraiTxHash")
        return sha256(tag + tag + struct.pack("<H", 0x0003) + struct.pack("<iI", 2, 0))

    def merkle_script(self):
        """Leaf 1 of a 4-leaf SHA-256 tree (scheme 0x02), depth 2."""
        leaves = [b"leaf0", b"leaf1", b"leaf2", b"leaf3"]
        h = [sha256(leaf) for leaf in leaves]
        left, right = sha256(h[0] + h[1]), sha256(h[2] + h[3])
        root = sha256(left + right)
        proof = bytes([2]) + h[0] + right + bytes([0b01])  # level 0: running on the right
        return CScript([leaves[1], 2, proof, root, OP_CHECKMERKLEINCLUSION])

    def tree_contract(self):
        """Keyless AuthScript tree (authType 0x10) with two leaves."""
        def leaf_hash(script):
            return tagged_hash(b"NeuraiAuthLeaf", b"\x01" + ser_compact_size(len(script)) + script)
        used = bytes(CScript([b"tree", OP_DROP, OP_TRUE]))
        other = bytes(CScript([b"other", OP_DROP, OP_TRUE]))
        a, b = leaf_hash(used), leaf_hash(other)
        root = tagged_hash(b"NeuraiAuthBranch", min(a, b) + max(a, b))
        commitment = tagged_hash(b"NeuraiAuthScript", b"\x04\x00" + root)
        return Contract("AuthScript tree leaf (NIP-044)", b"\x51\x20" + commitment,
                        [b"\x10", used, b"\x01" + b])

    def p2sh_contract(self):
        native = AuthScript(CScript([b"p2sh", OP_DROP, OP_TRUE]))
        spk = bytes(CScript([OP_HASH160, hash160(native.spk), OP_EQUAL]))
        return Contract("AuthScript wrapped in P2SH", spk, [b"\x00", native.script],
                        script_sig=bytes(CScript([native.spk])))

    # ------------------------------------------------------------------ asset

    def fund_asset_contract(self):
        node0 = self.nodes[0]
        script = CScript([
            0, 1, OP_INPUTASSETFIELD, ASSET.encode(), OP_EQUALVERIFY,
            0, 2, OP_INPUTASSETFIELD, ASSET_QTY * COIN, OP_NUMEQUALVERIFY,
            0, 1, OP_OUTPUTASSETFIELD, ASSET.encode(), OP_EQUALVERIFY,
            0, 2, OP_OUTPUTASSETFIELD, ASSET_QTY * COIN, OP_NUMEQUAL])
        contract = self.generic("OP_INPUTASSETFIELD / OP_OUTPUTASSETFIELD", script)
        node0.issue(ASSET, ASSET_QTY)
        node0.generate(1)
        asset_utxo = node0.listmyassets(ASSET, True)[ASSET]["outpoints"][0]
        fee = next(u for u in node0.listunspent() if u["amount"] >= 1)
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(asset_utxo["txid"], 16), asset_utxo["vout"]), b"", SEQUENCE),
                  CTxIn(COutPoint(int(fee["txid"], 16), fee["vout"]), b"", SEQUENCE)]
        tx.vout = [CTxOut(0, transfer_spk(contract.spk, ASSET, ASSET_QTY * COIN)),
                   CTxOut(int((fee["amount"] - Decimal("0.05")) * COIN), self.spk(node0.getnewaddress()))]
        signed = node0.signrawtransaction(tx.serialize_without_witness().hex())
        assert signed["complete"]
        txid = node0.sendrawtransaction(signed["hex"])
        node0.generate(1)
        self.sync_all()
        contract.outpoint = (txid, 0)
        return contract

    def spend_asset(self, contract):
        """Moves the asset to dest; a wallet coin pays the fee."""
        node0 = self.nodes[0]
        fee = next(u for u in node0.listunspent() if u["amount"] >= 1)
        tx = CTransaction()
        tx.nVersion = 2
        txid, n = contract.outpoint
        tx.vin = [CTxIn(COutPoint(int(txid, 16), n), b"", SEQUENCE),
                  CTxIn(COutPoint(int(fee["txid"], 16), fee["vout"]), b"", SEQUENCE)]
        tx.vout = [CTxOut(0, transfer_spk(self.dest_spk, ASSET, ASSET_QTY * COIN)),
                   CTxOut(int((fee["amount"] - Decimal("0.05")) * COIN), self.spk(node0.getnewaddress()))]
        # The wallet signs its coin; the contract input keeps its witness.
        signed = from_hex(CTransaction(), node0.signrawtransaction(tx.serialize_without_witness().hex())["hex"])
        tx.vin[1].scriptSig = signed.vin[1].scriptSig
        set_witness(tx, 0, contract.witness)
        return tx.serialize_with_witness().hex()


if __name__ == '__main__':
    UnifiedForkRelayTest().main()
