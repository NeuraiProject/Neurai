#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""NIP-060 OP_CHECKSIG_P256 (0xe0) in regtest.

- Activation with -signatureopcodesheight: rejected for blocks below the
  height, accepted from it, evicted from the mempool by a reorganization
  back below it; getblockchaininfo.signature_opcodes follows.
- Spending with a P-256 key and no AuthScript envelope key (NIP §5):
  TXHASH || spent scriptPubKey || amount is signed, so lying about the amount
  breaks the signature.
- The NIP §8 examples: parametric insurance (§8.1), 2 of 3 sensors (§8.2),
  minimal manufacturer certificate (§8.5), mobile wallet with a recovery
  branch after a CSV wait (§8.6) and a NIP-054 role held by a P-256 key that
  votes through the lock (§8.7).
- Mempool rejections with the NIP error codes, and the standard sigop limit
  with P256_SIGOP_COST = 5 per check.

The recovery branch of §8.6 is the one the NIP specifies: a secp256k1 key
checked with OP_CHECKSIG after a CSV wait, signed here with the AuthScript
signature hash (SIGVERSION_AUTHSCRIPT) computed in Python.
"""

import copy
import hashlib
import importlib.util
import os
import struct
from decimal import Decimal

from feature_assetauth import (AuthScript, build_tx, custody_witness, lock_script, num, policy_script,
                               proposal_hash, set_witness, transfer_spk)
from test_framework import key_p256
from test_framework.key import ECKey
from test_framework.messages import COIN, COutPoint, CTransaction, from_hex, ser_compact_size
from test_framework.script import (CScript, CScriptOp, OP_0, OP_1, OP_ADD, OP_CAT, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG,
                                   OP_CHECKSIG_P256, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY,
                                   OP_FROMALTSTACK, OP_GREATERTHANOREQUAL, OP_IF, OP_SWAP, OP_TOALTSTACK,
                                   OP_TXHASH, OP_VERIFY)
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, sync_blocks

ACTIVATION = 260
FEE = Decimal("0.05")
OP_TXFIELD = CScriptOp(0xb6)
OP_OUTPUTAUTHDEST = CScriptOp(0xc2)
OP_OUTPUTVALUE = CScriptOp(0xcc)
OP_OUTPUTCOUNT = CScriptOp(0xd1)
TXHASH_ALL = 0x01ff


def sha256(data):
    return hashlib.sha256(data).digest()


def load_contrib_signer():
    """contrib/p256/p256_sign.py, the reference signer the devices use."""
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "contrib", "p256", "p256_sign.py")
    spec = importlib.util.spec_from_file_location("p256_sign", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def double_sha(data):
    return sha256(sha256(data))


def key(name):
    """Deterministic test key and its compressed public key."""
    priv = int.from_bytes(sha256(b"NIP-060 functional " + name), "big") % key_p256.N
    return priv, key_p256.pubkey_from_privkey(priv)


def txhash(tx, index, mask=TXHASH_ALL):
    """OP_TXHASH (NIP-042) of input `index`, like GetTxFieldHash."""
    prevouts = [txin.prevout.serialize() for txin in tx.vin]
    sequences = [txin.nSequence for txin in tx.vin]
    refs = b"".join(ref.serialize() for ref in tx.vrefin) if tx.nVersion == 3 else b""
    fields = [struct.pack("<I", tx.nVersion), struct.pack("<I", tx.nLockTime),
              double_sha(b"".join(prevouts)),
              double_sha(b"".join(struct.pack("<I", s) for s in sequences)),
              double_sha(b"".join(out.serialize() for out in tx.vout)),
              prevouts[index], struct.pack("<I", sequences[index]), struct.pack("<I", index),
              double_sha(refs)]
    tag = sha256(b"NeuraiTxHash")
    return sha256(tag + tag + struct.pack("<H", mask) +
                  b"".join(field for bit, field in enumerate(fields) if mask & (1 << bit)))


def spend_message(tx, index, spent_spk, value):
    """What the NIP §5 script signs: TXHASH || spent scriptPubKey || amount."""
    return txhash(tx, index) + spent_spk + struct.pack("<q", value)


def txhash_check(pub):
    """NIP §5 body: commit to the transaction, the spent script and amount."""
    return [bytes([0xff, 0x01]), OP_TXHASH, 3, OP_TXFIELD, OP_CAT, 1, OP_TXFIELD, OP_CAT, pub, OP_CHECKSIG_P256]


def wallet_script(pub):
    return CScript(txhash_check(pub))


def recovery_script(phone, cold, wait):
    """NIP §8.6: the phone (P-256), or the cold secp256k1 key after `wait` blocks."""
    return CScript([OP_IF] + txhash_check(phone) +
                   [OP_ELSE, wait, OP_CHECKSEQUENCEVERIFY, OP_DROP, cold, OP_CHECKSIG, OP_ENDIF])


def authscript_sighash(tx, index, script, amount, hashtype=1, auth=0x00):
    """SignatureHash for SIGVERSION_AUTHSCRIPT (BIP 143 layout, then the
    reference inputs of a version 3 transaction, the locktime, the authType of
    the spend and the hash type)."""
    prevouts = b"".join(txin.prevout.serialize() for txin in tx.vin)
    sequences = b"".join(struct.pack("<I", txin.nSequence) for txin in tx.vin)
    pre = struct.pack("<I", tx.nVersion) + double_sha(prevouts) + double_sha(sequences)
    pre += tx.vin[index].prevout.serialize() + ser_compact_size(len(script)) + bytes(script)
    pre += struct.pack("<q", amount) + struct.pack("<I", tx.vin[index].nSequence)
    pre += double_sha(b"".join(out.serialize() for out in tx.vout))
    if tx.nVersion == 3 and tx.vrefin:
        pre += double_sha(b"".join(ref.serialize() for ref in tx.vrefin))
    pre += struct.pack("<I", tx.nLockTime) + bytes([auth]) + struct.pack("<I", hashtype)
    return double_sha(pre)


def insurance_script(threshold, prefix, sensor, insured, amount):
    """NIP §8.1."""
    return CScript([OP_DUP, threshold, OP_GREATERTHANOREQUAL, OP_VERIFY,
                    prefix, OP_SWAP, OP_CAT,
                    sensor, OP_CHECKSIG_P256, OP_VERIFY,
                    OP_OUTPUTCOUNT, 1, OP_EQUALVERIFY,
                    0, OP_OUTPUTAUTHDEST, insured, OP_EQUALVERIFY,
                    0, OP_OUTPUTVALUE, amount, OP_GREATERTHANOREQUAL])


def threshold_script(pk1, pk2, pk3):
    """NIP §8.2: 2 of 3 by adding the results."""
    return CScript([OP_TOALTSTACK,
                    OP_FROMALTSTACK, OP_DUP, OP_TOALTSTACK, pk1, OP_CHECKSIG_P256,
                    OP_SWAP,
                    OP_FROMALTSTACK, OP_DUP, OP_TOALTSTACK, pk2, OP_CHECKSIG_P256,
                    OP_ADD,
                    OP_SWAP,
                    OP_FROMALTSTACK, pk3, OP_CHECKSIG_P256,
                    OP_ADD,
                    2, OP_GREATERTHANOREQUAL])


def certificate_script(manufacturer):
    """NIP §8.5."""
    return CScript([OP_DUP, OP_TOALTSTACK,
                    b"NeuraiP256/v1/alta", OP_SWAP, OP_CAT,
                    manufacturer, OP_CHECKSIG_P256, OP_VERIFY,
                    b"NeuraiP256/v1/dato", OP_SWAP, OP_CAT,
                    OP_FROMALTSTACK, OP_CHECKSIG_P256])


class P256Test(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-signatureopcodesheight=%d" % ACTIVATION]] * 2

    # ---------------------------------------------------------------- helpers

    def legacy_spk(self):
        return bytes.fromhex(self.node.validateaddress(self.node.getnewaddress("", "legacy"))["scriptPubKey"])

    def fund(self, authscript, amount=Decimal("1")):
        """Send `amount` XNA to an AuthScript address; return (txid, n, sats, spk)."""
        txid = self.node.sendtoaddress(authscript.address, amount)
        tx = self.node.getrawtransaction(txid, True)
        for out in tx["vout"]:
            spk = bytes.fromhex(out["scriptPubKey"]["hex"])
            if spk == authscript.spk:
                return txid, out["n"], int(out["value"] * COIN), spk
        raise AssertionError("funding output not found")

    def spend(self, coin, outputs, sequence=0xffffffff):
        tx = build_tx([coin[:2]], outputs)
        tx.vin[0].nSequence = sequence
        return tx

    def sign_txhash(self, tx, index, coin, priv):
        return key_p256.sign(priv, spend_message(tx, index, coin[3], coin[2]))

    def accept(self, tx):
        return self.node.testmempoolaccept([tx.serialize_with_witness().hex()])[0]

    def assert_rejected(self, tx, message):
        assert_raises_rpc_error(-26, message, self.node.sendrawtransaction, tx.serialize_with_witness().hex())

    def send(self, tx):
        return self.node.sendrawtransaction(tx.serialize_with_witness().hex())

    def mine(self, count=1):
        hashes = self.node.generate(count)
        sync_blocks(self.nodes)
        return hashes

    def sign_wallet_inputs(self, tx):
        """Sign the wallet's inputs, keeping the witnesses already set."""
        signed = from_hex(CTransaction(), self.node.signrawtransaction(tx.serialize().hex())["hex"])
        for i, txin in enumerate(signed.vin):
            tx.vin[i].scriptSig = txin.scriptSig
        return tx

    def fee_utxo(self):
        for utxo in sorted(self.node.listunspent(), key=lambda u: u["amount"]):
            if utxo["amount"] >= 1 and (utxo["txid"], utxo["vout"]) not in self.reserved:
                self.reserved.add((utxo["txid"], utxo["vout"]))
                return utxo
        raise AssertionError("no fee utxo")

    # ------------------------------------------------------------------ test

    def run_test(self):
        self.node = self.nodes[0]
        self.reserved = set()
        self.mine(200)
        self.test_activation_and_reorg()
        self.test_txhash_spend()
        self.test_mempool_rejections()
        self.test_insurance()
        self.test_threshold()
        self.test_certificate()
        self.test_recovery_wallet()
        self.test_version3_reference_inputs()
        self.test_assetauth_vote()
        self.test_sigop_limit()

    def test_activation_and_reorg(self):
        self.log.info("Activation at -signatureopcodesheight, and a reorganization back below it")
        node = self.node
        priv, pub = key(b"wallet")
        wallet = AuthScript(wallet_script(pub))
        coin = self.fund(wallet)
        self.mine()
        height = node.getblockcount()
        assert height < ACTIVATION - 2
        info = node.getblockchaininfo()["signature_opcodes"]
        assert_equal(info["activation_height"], ACTIVATION)
        assert_equal(info["active_for_next_block"], False)
        assert_equal(info["opcodes"]["checksig_p256"], True)

        tx = self.spend(coin, [(coin[2] - int(FEE * COIN), self.legacy_spk())])
        set_witness(tx, 0, [b"\x00", self.sign_txhash(tx, 0, coin, priv), wallet.script])
        result = self.accept(tx)
        assert_equal(result["allowed"], False)
        assert "Opcode missing or not understood" in result["reject-reason"]

        self.mine(ACTIVATION - 1 - node.getblockcount())
        assert_equal(node.getblockcount(), ACTIVATION - 1)
        info = node.getblockchaininfo()["signature_opcodes"]
        assert_equal((info["active_at_tip"], info["active_for_next_block"]), (False, True))
        txid = self.send(tx)
        assert txid in node.getrawmempool()

        # A reorganization below the height evicts it: the next block could
        # not include it any more.
        tip = node.getbestblockhash()
        node.invalidateblock(tip)
        assert_equal(node.getblockcount(), ACTIVATION - 2)
        assert txid not in node.getrawmempool()
        node.reconsiderblock(tip)
        assert_equal(node.getbestblockhash(), tip)
        self.send(tx)
        block = self.mine()[0]
        assert txid in node.getblock(block)["tx"]
        assert_equal(self.nodes[1].getblockchaininfo()["signature_opcodes"]["active_at_tip"], True)
        assert_equal(self.nodes[1].getrawtransaction(txid, True)["blockhash"], block)

    def test_txhash_spend(self):
        self.log.info("NIP §5: the signature covers the amount and the spent script")
        priv, pub = key(b"wallet")
        wallet = AuthScript(wallet_script(pub))
        coin = self.fund(wallet, Decimal("2"))
        self.mine()
        tx = self.spend(coin, [(coin[2] - int(FEE * COIN), self.legacy_spk())])
        # A host lying about the amount gets a signature that does not verify.
        lie = (coin[0], coin[1], coin[2] // 2, coin[3])
        set_witness(tx, 0, [b"\x00", self.sign_txhash(tx, 0, lie, priv), wallet.script])
        self.assert_rejected(tx, "OP_CHECKSIG_P256 signature does not verify")
        # And about the spent script.
        other = (coin[0], coin[1], coin[2], AuthScript(wallet_script(key(b"other")[1])).spk)
        set_witness(tx, 0, [b"\x00", self.sign_txhash(tx, 0, other, priv), wallet.script])
        self.assert_rejected(tx, "OP_CHECKSIG_P256 signature does not verify")
        # A signature for different outputs does not verify either.
        changed = self.spend(coin, [(coin[2] - int(2 * FEE * COIN), self.legacy_spk())])
        set_witness(tx, 0, [b"\x00", self.sign_txhash(changed, 0, coin, priv), wallet.script])
        self.assert_rejected(tx, "OP_CHECKSIG_P256 signature does not verify")
        set_witness(tx, 0, [b"\x00", self.sign_txhash(tx, 0, coin, priv), wallet.script])
        txid = self.send(tx)
        self.mine()
        assert self.nodes[1].getrawtransaction(txid, True)["confirmations"] >= 1

    def test_mempool_rejections(self):
        self.log.info("Mempool rejections carry the NIP-060 error codes")
        priv, pub = key(b"wallet")
        wallet = AuthScript(wallet_script(pub))
        coin = self.fund(wallet)
        self.mine()
        tx = self.spend(coin, [(coin[2] - int(FEE * COIN), self.legacy_spk())])
        good = self.sign_txhash(tx, 0, coin, priv)
        high = good[:32] + (key_p256.N - int.from_bytes(good[32:], "big")).to_bytes(32, "big")
        cases = [
            (good[:-1] + bytes([good[-1] ^ 1]), "OP_CHECKSIG_P256 signature does not verify"),
            (high, "OP_CHECKSIG_P256 signature encoding invalid"),
            (good + b"\x01", "OP_CHECKSIG_P256 signature size is neither 0 nor 64 bytes"),
        ]
        for sig, message in cases:
            set_witness(tx, 0, [b"\x00", sig, wallet.script])
            self.assert_rejected(tx, message)
        # The empty signature pushes 0: the script ends false.
        set_witness(tx, 0, [b"\x00", b"", wallet.script])
        self.assert_rejected(tx, "Script evaluated without error but finished with a false/empty top stack element")
        # A key that is not compressed P-256.
        bad_key = AuthScript(wallet_script(b"\x04" + pub[1:] + bytes(32)))
        bad_coin = self.fund(bad_key)
        self.mine()
        bad_tx = self.spend(bad_coin, [(bad_coin[2] - int(FEE * COIN), self.legacy_spk())])
        set_witness(bad_tx, 0, [b"\x00", good, bad_key.script])
        self.assert_rejected(bad_tx, "OP_CHECKSIG_P256 pubkey size != 33 bytes")
        set_witness(tx, 0, [b"\x00", good, wallet.script])
        self.send(tx)
        self.mine()

    def test_insurance(self):
        self.log.info("NIP §8.1: parametric insurance paid on a signed sensor reading")
        sensor_priv, sensor = key(b"sensor")
        insured = AuthScript(CScript([OP_1]))
        amount = 3 * COIN
        prefix = b"NeuraiP256/v1/seguro" + b"POLIZA-0001" + b"2026-11"
        policy = AuthScript(insurance_script(100, prefix, sensor, insured.dest33, amount))
        coin = self.fund(policy, Decimal("3.1"))
        self.mine()

        def claim(level, outputs, signed_prefix=prefix):
            tx = self.spend(coin, outputs)
            reading = num(level)
            sig = key_p256.sign(sensor_priv, signed_prefix + reading)
            set_witness(tx, 0, [b"\x00", sig, reading, policy.script])
            return tx

        pay = [(amount, insured.spk)]
        self.assert_rejected(claim(99, pay), "Script failed an OP_VERIFY operation")
        self.assert_rejected(claim(150, pay, b"NeuraiP256/v1/seguro" + b"POLIZA-0001" + b"2026-10"),
                             "OP_CHECKSIG_P256 signature does not verify")
        # Whoever sees the signed reading cannot keep the excess in a second output.
        self.assert_rejected(claim(150, pay + [(coin[2] - amount - int(FEE * COIN), self.legacy_spk())]),
                             "Script failed an OP_EQUALVERIFY operation")
        # Output 0 must be the insured's AuthScript destination.
        self.assert_rejected(claim(150, [(amount, self.legacy_spk())]), "mandatory-script-verify-flag-failed")
        self.assert_rejected(claim(150, [(amount - 1, insured.spk)]),
                             "Script evaluated without error but finished with a false/empty top stack element")
        txid = self.send(claim(150, pay))
        self.mine()
        assert self.nodes[1].getrawtransaction(txid, True)["confirmations"] >= 1

    def test_threshold(self):
        self.log.info("NIP §8.2: 2 of 3 sensors, absent signatures empty")
        keys = [key(b"sensor-%d" % i) for i in range(3)]
        script = threshold_script(*(pub for _, pub in keys))
        multi = AuthScript(script)
        coin = self.fund(multi)
        self.mine()
        msg = b"NeuraiP256/v1/umbral" + b"lectura-42"
        sigs = [key_p256.sign(priv, msg) for priv, _ in keys]
        tx = self.spend(coin, [(coin[2] - int(FEE * COIN), self.legacy_spk())])
        set_witness(tx, 0, [b"\x00", b"", b"", sigs[0], msg, multi.script])
        self.assert_rejected(tx, "Script evaluated without error but finished with a false/empty top stack element")
        set_witness(tx, 0, [b"\x00", sigs[2], b"", sigs[0], msg, multi.script])
        self.send(tx)
        self.mine()

    def test_certificate(self):
        self.log.info("NIP §8.5: device enrolled by the manufacturer signs a reading")
        fab_priv, fab = key(b"manufacturer")
        dev_priv, dev = key(b"device")
        rogue_priv, rogue = key(b"rogue device")
        cert = AuthScript(certificate_script(fab))
        enrolment = key_p256.sign(fab_priv, b"NeuraiP256/v1/alta" + dev)
        reading = b"altura=1234;lectura=42"
        coin = self.fund(cert)
        self.mine()
        tx = self.spend(coin, [(coin[2] - int(FEE * COIN), self.legacy_spk())])
        rogue_sig = key_p256.sign(rogue_priv, b"NeuraiP256/v1/dato" + reading)
        set_witness(tx, 0, [b"\x00", rogue_sig, reading, enrolment, rogue, cert.script])
        self.assert_rejected(tx, "OP_CHECKSIG_P256 signature does not verify")
        sig = key_p256.sign(dev_priv, b"NeuraiP256/v1/dato" + reading)
        set_witness(tx, 0, [b"\x00", sig, reading, enrolment, dev, cert.script])
        self.send(tx)
        self.mine()

    def test_recovery_wallet(self):
        self.log.info("NIP §8.6: phone key (P-256), or the cold secp256k1 key with OP_CHECKSIG after a CSV wait")
        phone_priv, phone = key(b"phone")
        cold_key = ECKey()
        cold_key.set(sha256(b"NIP-060 functional cold secp256k1"), True)
        cold = cold_key.get_pubkey().get_bytes()
        wait = 10
        wallet = AuthScript(recovery_script(phone, cold, wait))
        coins = [self.fund(wallet) for _ in range(2)]
        self.mine()
        out = [(coins[0][2] - int(FEE * COIN), self.legacy_spk())]
        # Normal use: the phone, branch 1.
        tx = self.spend(coins[0], out)
        set_witness(tx, 0, [b"\x00", self.sign_txhash(tx, 0, coins[0], phone_priv), b"\x01", wallet.script])
        self.send(tx)
        # Recovery: branch 2 needs nSequence >= wait and the coin that old.
        def recover(sequence):
            tx = self.spend(coins[1], out, sequence=sequence)
            digest = authscript_sighash(tx, 0, wallet.script, coins[1][2])
            set_witness(tx, 0, [b"\x00", cold_key.sign_ecdsa(digest) + b"\x01", b"", wallet.script])
            return tx
        # The coin is one block old: BIP68 rejects it before the script runs.
        tx = recover(wait)
        self.assert_rejected(tx, "non-BIP68-final")
        # Old enough for nSequence = wait - 1, but the script asks for `wait`.
        self.mine(wait - 2)
        self.assert_rejected(recover(wait - 1), "Locktime requirement not satisfied")
        self.mine()
        # Now old enough: a recovery signature by another key fails OP_CHECKSIG.
        other = ECKey()
        other.set(sha256(b"NIP-060 functional other secp256k1"), True)
        bad = self.spend(coins[1], out, sequence=wait)
        set_witness(bad, 0, [b"\x00", other.sign_ecdsa(authscript_sighash(bad, 0, wallet.script, coins[1][2])) + b"\x01",
                             b"", wallet.script])
        self.assert_rejected(bad, "mandatory-script-verify-flag-failed")
        txid = self.send(tx)
        self.mine()
        assert self.nodes[1].getrawtransaction(txid, True)["confirmations"] >= 1

    def test_version3_reference_inputs(self):
        self.log.info("NIP §5 in version 3 transactions, with and without reference inputs (contrib signer)")
        signer = load_contrib_signer()
        priv, pub = key(b"v3 wallet")
        script = signer.witness_script(pub)
        assert_equal(script, bytes(wallet_script(pub)))
        wallet = AuthScript(wallet_script(pub))
        coins = [self.fund(wallet) for _ in range(2)]
        reference = self.fund(AuthScript(CScript([OP_1])))
        self.mine()

        def signed(coin, refs, sign_refs=None):
            tx = self.spend(coin, [(coin[2] - int(FEE * COIN), self.legacy_spk())])
            tx.nVersion = 3
            tx.vrefin = refs
            view = tx
            if sign_refs is not None:
                view = copy.deepcopy(tx)
                view.vrefin = sign_refs
            msg = signer.message(view, 0, coin[2], coin[3])
            assert_equal(msg, spend_message(view, 0, coin[3], coin[2]))  # both implementations agree
            set_witness(tx, 0, [b"\x00", key_p256.sign(priv, msg), script])
            return tx

        ref = [COutPoint(int(reference[0], 16), reference[1])]
        # A signer that ignores the reference input signs another transaction.
        self.assert_rejected(signed(coins[1], ref, sign_refs=[]), "OP_CHECKSIG_P256 signature does not verify")
        txids = [self.send(signed(coins[0], [])), self.send(signed(coins[1], ref))]
        block = self.mine()[0]
        for txid in txids:
            assert txid in self.node.getblock(block)["tx"]
        assert_equal(self.node.getrawtransaction(txids[1], True)["vrefin"][0]["vout"], reference[1])

    def test_assetauth_vote(self):
        self.log.info("NIP §8.7: a NIP-054 role held by a P-256 key approves through the vote lock")
        node = self.node
        holder_priv, holder_pub = key(b"board member")
        holder = AuthScript(wallet_script(holder_pub))
        role_addr = {}
        for name in ("PROLEA", "PROLEB", "PROLEP"):
            role_addr[name + "!"] = node.getnewaddress("", "legacy")
            node.issue(name, 1, role_addr[name + "!"])
        self.mine()
        node.transfer("PROLEP!", 1, holder.address)
        custody = AuthScript(policy_script(2, 3, role_addr.keys()))
        node.sendtoaddress(custody.address, 10)
        self.mine()
        custody_coin = None
        token = None
        for txid in node.getblock(node.getbestblockhash())["tx"]:
            for out in node.getrawtransaction(txid, True)["vout"]:
                spk = bytes.fromhex(out["scriptPubKey"]["hex"])
                if spk == custody.spk:
                    custody_coin = (txid, out["n"], int(out["value"] * COIN))
                elif spk.startswith(holder.spk) and len(spk) > len(holder.spk):
                    token = (txid, out["n"], int(out["value"] * COIN), spk)
        assert custody_coin and token

        # Proposal: the custody pays its 10 XNA out. H fixes input 0 and output 0.
        T = node.getblockcount() + 50
        prefix = [(custody_coin[2], self.legacy_spk())]
        skeleton = build_tx([custody_coin[:2]], prefix)
        h = proposal_hash(skeleton, 1, 1, 0, T)
        return_spk = transfer_spk(holder.spk, "PROLEP!", COIN)
        lock = AuthScript(lock_script(T, custody, return_spk))

        # The P-256 holder votes: its token moves to the lock with message H.
        fee = self.fee_utxo()
        vote = build_tx([token[:2], (fee["txid"], fee["vout"])],
                        [(0, transfer_spk(lock.spk, "PROLEP!", COIN, h)),
                         (int((fee["amount"] - FEE) * COIN), self.legacy_spk())])
        set_witness(vote, 0, [b"\x00", self.sign_txhash(vote, 0, token, holder_priv), holder.script])
        vote_txid = self.send(self.sign_wallet_inputs(vote))
        self.mine()

        # PROLEB signs directly; anyone executes. The P-256 role comes back.
        fee = self.fee_utxo()
        bob = node.listmyassets("PROLEB!", True)["PROLEB!"]["outpoints"][0]
        bob_spk = bytes.fromhex(node.validateaddress(role_addr["PROLEB!"])["scriptPubKey"])
        inputs = [custody_coin[:2], (vote_txid, 0), (bob["txid"], bob["vout"]), (fee["txid"], fee["vout"])]
        outputs = prefix + [(0, return_spk), (0, transfer_spk(bob_spk, "PROLEB!", COIN)),
                            (int((fee["amount"] - FEE) * COIN), self.legacy_spk())]
        execution = build_tx(inputs, outputs)
        assert_equal(proposal_hash(execution, 1, 1, 0, T), h)
        set_witness(execution, 0, custody_witness(custody, c=1, a=1, b=0, T=T))
        set_witness(execution, 1, [b"\x00", num(0), num(1), b"\x01", lock.script])
        txid = self.send(self.sign_wallet_inputs(execution))
        self.mine()
        back = node.getrawtransaction(txid, True)["vout"][1]
        assert_equal(bytes.fromhex(back["scriptPubKey"]["hex"]), return_spk)
        assert node.gettxout(txid, 1) is not None

    def test_sigop_limit(self):
        self.log.info("Standard sigop limit: 16,000 sigops, P256_SIGOP_COST = 5 per check")
        # 200 checks in an unexecuted branch: 1,000 sigops per input.
        script = CScript([OP_0, OP_IF] + [OP_CHECKSIG_P256] * 200 + [OP_ENDIF, OP_1])
        heavy = AuthScript(script)
        coins = [self.fund(heavy) for _ in range(17)]
        self.mine()
        pay = CScript([OP_0, sha256(b"p256 sigop sink")])

        def spend(n):
            tx = build_tx([c[:2] for c in coins[:n]], [(n * COIN - 2 * COIN, pay)])
            for i in range(n):
                set_witness(tx, i, [b"\x00", heavy.script])
            return tx

        self.assert_rejected(spend(17), "bad-txns-too-many-sigops")
        assert_equal(self.accept(spend(16))["allowed"], True)


if __name__ == '__main__':
    P256Test().main()
