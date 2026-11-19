#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Block budgets of the CPU review from the NIP-028 height on (B1 and B2-a).

With 30 s blocks a block may cost no more than a tenth of the interval to
validate on the minimum hardware. From the NIP-028 height on:

- B1: an Ed25519 verification costs about three ECDSA ones, so each
  OP_CHECKSIG_ED25519 counts three sigops. A block holds 26,666 checks
  (79,998 sigops), not 26,667; below the height 26,667 checks count 26,667.
  The fee and the standard limit count three per check too: a transaction of
  666 checks (1,998 witness sigops) is standard, one of 667 is not. A
  transaction admitted below the height leaves the mempool at the height.
- NIP-060: each OP_CHECKSIG_P256 counts five sigops at any height, so a block
  holds 16,000 checks (80,000 sigops), not 16,001.
- B2-a: the budgets per block are halved, to keep the work per second: a block
  may run 100,000 Poseidon permutations (200,000 below) and 225,000
  OP_CHECKASSETAUTH units (450,000 below). Block assembly keeps to them.
"""

import hashlib
import json
import os

from feature_assetauth import AuthScript, custody_witness, policy_script, transfer_spk
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import from_hex
from test_framework.mininode import COutPoint, CTxIn, CTxInWitness
from test_framework.script import (CScript, CScriptOp, CTransaction, CTxOut, OP_0, OP_2DROP, OP_3DUP, OP_DROP,
                                   OP_TRUE, OP_VERIFY)
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, bytes_to_hex_str, connect_nodes, sync_blocks

FORK_HEIGHT = 200
COIN = 100000000
VALUE = COIN
CUSTODY_VALUE = COIN // 10
OP_CHECKSIG_ED25519 = CScriptOp(0xdd)
OP_CHECKSIG_P256 = CScriptOp(0xe0)
DATA = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "src", "test", "data")


def sha256(data):
    return hashlib.sha256(data).digest()


def authscript(script):
    """Native AuthScript v1 output without an authentication key."""
    tag = sha256(b'NeuraiAuthScript')
    return CScript(b'\x51\x20' + sha256(tag + tag + b'\x01\x00' + sha256(bytes(script))))


def poseidon(calls):
    """OP_POSEIDON `calls` times on the empty element: one permutation each."""
    return bytes([0xc9]) * calls + bytes([0x75, 0x51])


def ed25519_checks(count):
    """`count` OP_CHECKSIG_ED25519 verifications of the witness arguments."""
    return bytes(CScript([OP_3DUP, OP_CHECKSIG_ED25519, OP_VERIFY] * count + [OP_2DROP, OP_DROP, OP_TRUE]))


def p256_unexecuted(count):
    """`count` OP_CHECKSIG_P256 in a branch that never runs: sigops, no work."""
    return bytes(CScript([OP_0, CScriptOp(0x63)] + [OP_CHECKSIG_P256] * count + [CScriptOp(0x68), OP_TRUE]))


def assetauth_work(n):
    """Units of a spend of n eleven-role custody inputs with two outputs: each
    execution charges 1 + (n + 1) inputs + 2 outputs + 1 + 11 roles + 2 tokens."""
    return n * (n + 18)


class ForkCpuBudgetsTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        fork = "-blocktimereductionheight=%d" % FORK_HEIGHT
        self.extra_args = [[fork], [fork]]

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

    def submit(self, txs):
        block = self.build_block(txs)
        return self.nodes[0].submitblock(bytes_to_hex_str(block.serialize(with_witness=True)))

    def take(self, kind, count):
        coins = self.coins[kind][:count]
        assert_equal(len(coins), count)
        del self.coins[kind][:count]
        return coins

    def spend(self, coins, fee=0):
        """coins: list of (outpoint, script, arguments), each worth VALUE."""
        tx = CTransaction()
        for (txid, n), script, args in coins:
            tx.vin.append(CTxIn(COutPoint(txid, n), b""))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00'] + args + [bytes(script)]
        tx.vout.append(CTxOut(len(coins) * VALUE - fee, self.pay))
        tx.rehash()
        return tx

    def test(self, tx):
        return self.nodes[0].testmempoolaccept([bytes_to_hex_str(tx.serialize_with_witness())])[0]

    def verdict(self, tx):
        result = self.test(tx)
        return "accepted" if result["allowed"] else result["reject-reason"].split(": ", 1)[-1]

    def setup_custodies(self, count):
        """`count` custody outputs of eleven roles, and the roles' tokens."""
        node = self.nodes[0]
        role_addr = {}
        for i in range(11):
            name = "R%02d" % i
            role_addr[name + "!"] = node.getnewaddress("", "legacy")
            node.issue(name, 1, role_addr[name + "!"])
        node.generate(1)
        custody = AuthScript(policy_script(1, 1, role_addr.keys()))
        funding = CTransaction()
        funding.vout = [CTxOut(CUSTODY_VALUE, custody.spk) for _ in range(count)]
        funded = node.fundrawtransaction(bytes_to_hex_str(funding.serialize()), {"changePosition": count})["hex"]
        txid = node.sendrawtransaction(node.signrawtransaction(funded)["hex"])
        node.generate(1)
        self.custody = custody
        self.role_addr = role_addr
        self.custodies = [(int(txid, 16), n) for n in range(count)]

    def assetauth_spends(self, sizes):
        """One spend per size, each approved by a different role, from the
        custodies left; nothing is consumed until a block takes them."""
        node = self.nodes[0]
        custodies = list(self.custodies)
        txs = []
        for i, n in enumerate(sizes):
            role = "R%02d!" % i
            token = node.listmyassets(role, True)[role]["outpoints"][0]
            inputs = [custodies.pop() for _ in range(n)]
            tx = CTransaction()
            tx.nVersion = 2
            for prevout in inputs + [(int(token["txid"], 16), token["vout"])]:
                tx.vin.append(CTxIn(COutPoint(*prevout), b"", 0xffffffff))
            role_spk = bytes.fromhex(node.validateaddress(self.role_addr[role])["scriptPubKey"])
            tx.vout = [CTxOut(n * CUSTODY_VALUE, self.pay), CTxOut(0, transfer_spk(role_spk, role, COIN))]
            signed = from_hex(CTransaction(), node.signrawtransaction(bytes_to_hex_str(tx.serialize()))["hex"])
            tx.vin[-1].scriptSig = signed.vin[-1].scriptSig
            for _ in range(n):
                tx.wit.vtxinwit.append(CTxInWitness())
                tx.wit.vtxinwit[-1].scriptWitness.stack = custody_witness(self.custody)
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.rehash()
            txs.append(tx)
        return txs, custodies

    def run_test(self):
        node = self.nodes[0]
        with open(os.path.join(DATA, "ed25519_vectors.json")) as f:
            vector = json.load(f)["rfc8032_pure_ed25519"][0]
        ed_args = [bytes.fromhex(vector["signature"]), bytes.fromhex(vector["message"]), bytes.fromhex(vector["pubkey"])]
        kinds = {
            "e170": (ed25519_checks(170), ed_args, 326),
            "e156": (ed25519_checks(156), ed_args, 2),
            "e157": (ed25519_checks(157), ed_args, 2),
            "e147": (ed25519_checks(147), ed_args, 2),
            "e146": (ed25519_checks(146), ed_args, 1),
            "p500": (poseidon(500), [b''], 610),
            "p1": (poseidon(1), [b''], 2),
            "q500": (p256_unexecuted(500), [], 32),
            "q1": (p256_unexecuted(1), [], 1),
        }

        node.generate(1)
        block = self.build_block([])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        coinbase = block.vtx[0]
        node.generate(100)
        funding = CTransaction()
        funding.vin.append(CTxIn(COutPoint(coinbase.x16r, 0), b""))
        self.coins = {}
        for name, (script, args, count) in kinds.items():
            self.coins[name] = [((None, len(funding.vout) + i), script, args) for i in range(count)]
            funding.vout += [CTxOut(VALUE, authscript(script)) for _ in range(count)]
        funding.vout.append(CTxOut(coinbase.vout[0].nValue - len(funding.vout) * VALUE - COIN, CScript([OP_TRUE])))
        funding.rehash()
        for name in self.coins:
            self.coins[name] = [((funding.x16r, n), script, args) for (_, n), script, args in self.coins[name]]
        assert_equal(self.submit([funding]), None)
        # Outputs without legacy sigops, so that a transaction's sigops are its checks.
        self.pay = CScript([OP_0, sha256(bytes(CScript([OP_TRUE])))])
        node.generate(50)  # mature coinbases for the issuance fees
        self.setup_custodies(1000)
        sync_blocks(self.nodes)

        self.log.info("Below the NIP-028 height the old budgets apply")
        assert node.getblockcount() + 1 < FORK_HEIGHT - 2
        # 26,667 Ed25519 checks count 26,667 sigops.
        assert_equal(self.submit([self.spend(self.take("e170", 156) + self.take("e147", 1))]), None)
        # 100,001 Poseidon permutations, within 200,000.
        assert_equal(self.submit([self.spend(self.take("p500", 200) + self.take("p1", 1))]), None)
        # 225,001 asset-auth units, within 450,000.
        sizes = [465, 9, 6, 1]
        assert_equal(sum(assetauth_work(n) for n in sizes), 225001)
        txs, self.custodies = self.assetauth_spends(sizes)
        assert_equal(self.submit(txs), None)
        sync_blocks(self.nodes)
        # Each check counts one sigop for the fee: 170 checks, 3,400 sigop
        # bytes, 850 vbytes; there is no witness sigop limit yet.
        assert_equal(self.test(self.spend(self.take("e170", 1), COIN // 10))["vsize"], 850)
        assert_equal(self.verdict(self.spend(self.take("e170", 3) + self.take("e157", 1), COIN // 10)), "accepted")
        self.log.info("  26,667 Ed25519 checks, 100,001 permutations, 225,001 units: accepted")

        self.log.info("Crossing the height evicts the transactions with Ed25519 checks admitted below it")
        node.generate(FORK_HEIGHT - 2 - node.getblockcount())
        sync_blocks(self.nodes)
        pending = self.spend(self.take("e170", 1), COIN // 10)
        node.sendrawtransaction(bytes_to_hex_str(pending.serialize_with_witness()))
        assert_equal(self.submit([]), None)
        assert_equal(node.getblockcount() + 1, FORK_HEIGHT)
        assert pending.hash not in node.getrawmempool()
        sync_blocks(self.nodes)

        self.log.info("From the height each Ed25519 check counts three sigops")
        # In the fee: 510 sigops, 2,550 vbytes.
        assert_equal(self.test(self.spend(self.take("e170", 1), COIN // 10))["vsize"], 2550)
        # In the standard limit of 2,000 witness sigops.
        assert_equal(self.verdict(self.spend(self.take("e170", 3) + self.take("e156", 1), COIN // 10)), "accepted")
        assert_equal(self.verdict(self.spend(self.take("e170", 3) + self.take("e157", 1), COIN // 10)),
                     "bad-txns-too-many-witness-sigops")
        # In the block limit of 80,000 sigops.
        checks = self.take("e170", 156)
        tip = node.getbestblockhash()
        assert_equal(self.submit([self.spend(checks + self.take("e147", 1))]), "bad-blk-sigops")
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(self.submit([self.spend(checks + self.take("e146", 1))]), None)
        self.log.info("  666 checks standard, 667 not; a block of 26,666 accepted, 26,667 refused")

        self.log.info("Each OP_CHECKSIG_P256 counts five sigops: a block holds 16,000")
        checks = self.take("q500", 32)
        tip = node.getbestblockhash()
        assert_equal(self.submit([self.spend(checks + self.take("q1", 1))]), "bad-blk-sigops")
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(self.submit([self.spend(checks)]), None)
        self.log.info("  a block of 16,000 P-256 checks accepted, 16,001 refused")

        self.log.info("From the height a block runs at most 100,000 permutations")
        permutations = self.take("p500", 200)
        tip = node.getbestblockhash()
        assert_equal(self.submit([self.spend(permutations + self.take("p1", 1))]), "bad-blk-poseidon-work")
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(self.submit([self.spend(permutations)]), None)

        self.log.info("From the height a block runs at most 225,000 asset-auth units")
        sizes_over = [465, 9, 6, 1]
        sizes_at = [464, 26, 8]
        assert_equal(sum(assetauth_work(n) for n in sizes_at), 225000)
        txs, _ = self.assetauth_spends(sizes_over)
        tip = node.getbestblockhash()
        assert_equal(self.submit(txs), "bad-blk-assetauth-work")
        assert_equal(node.getbestblockhash(), tip)
        txs, self.custodies = self.assetauth_spends(sizes_at)
        assert_equal(self.submit(txs), None)
        sync_blocks(self.nodes)

        self.log.info("Block assembly keeps to the budget: 20 of 21 transactions of 5,000 permutations")
        txids = [node.sendrawtransaction(bytes_to_hex_str(self.spend(self.take("p500", 10), 2 * COIN).serialize_with_witness()))
                 for _ in range(21)]
        assert_equal(set(txids), set(node.getrawmempool()))
        template = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(len(template["transactions"]), 20)
        block_hash = node.generate(1)[0]
        assert_equal(len(node.getblock(block_hash)["tx"]), 21)  # coinbase + 20
        assert_equal(len(node.getrawmempool()), 1)
        sync_blocks(self.nodes)


if __name__ == '__main__':
    ForkCpuBudgetsTest().main()
