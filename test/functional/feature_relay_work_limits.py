#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Relay limits per transaction from the NIP-028 height on.

Admission runs the scripts of a transaction under cs_main, so the work a
standard transaction may run is bounded. From the NIP-028 height on:

- Poseidon work: 5,000 permutations (20,000 before);
- signature checks in witness scripts: 2,000 witness sigops (no limit of its
  own before; the general sigop limit still applies);
- OP_CHECKASSETAUTH work: 15,000 units (45,000 before).

Below the height a transaction of 5,001 permutations, 2,001 witness sigops or
15,001 asset-auth units is standard; from the height it is not, and it is still
valid in a block.
"""

import hashlib
import json
import os

from feature_assetauth import AuthScript, custody_witness, policy_script, transfer_spk
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import from_hex
from test_framework.mininode import COutPoint, CTxIn, CTxInWitness
from test_framework.script import (CScript, CTransaction, CTxOut, OP_2DROP, OP_3DUP, OP_CHECKSIGFROMSTACK,
                                   OP_DROP, OP_TRUE, OP_VERIFY)
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, bytes_to_hex_str, connect_nodes, sync_blocks

FORK_HEIGHT = 200
COIN = 100000000
VALUE = COIN
FEE = COIN // 2   # 2,000 sigops count as 10,000 vB at 20 bytes per sigop
CUSTODY_VALUE = COIN // 10
CUSTODY_INPUTS = 100
PAYMENTS = 33
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


def checks(count):
    """`count` OP_CHECKSIGFROMSTACK verifications of the witness arguments."""
    return bytes(CScript([OP_3DUP, OP_CHECKSIGFROMSTACK, OP_VERIFY] * count + [OP_2DROP, OP_DROP, OP_TRUE]))


class RelayWorkLimitsTest(NeuraiTestFramework):
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

    def spend(self, coins, pay):
        """coins: list of (outpoint, script, arguments)."""
        tx = CTransaction()
        for (txid, n), script, args in coins:
            tx.vin.append(CTxIn(COutPoint(txid, n), b""))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00'] + args + [bytes(script)]
        tx.vout.append(CTxOut(len(coins) * VALUE - FEE, pay))
        tx.rehash()
        return tx

    def assetauth_cases(self):
        """Two spends of 100 custody inputs, approved by a role token: one of
        15,000 asset-auth units and one of 15,001.

        Each custody input runs OP_CHECKASSETAUTH once, which charges
        1 + inputs + outputs + 1 (message) + the name work: one unit per role
        name of up to 32 bytes and per role token in the inputs and outputs.
        With 101 inputs, 34 outputs and 11 roles that is 150 units per input,
        15,000 for the spend. One input from a custody with a twelfth role
        charges one more unit.
        """
        node = self.nodes[0]
        node.generate(50)  # mature coinbases for the issuance fees
        role_addr = {}
        for i in range(12):
            name = "R%02d" % i
            role_addr[name + "!"] = node.getnewaddress("", "legacy")
            node.issue(name, 1, role_addr[name + "!"])
        node.generate(1)
        eleven = AuthScript(policy_script(1, 1, sorted(role_addr)[:11]))
        twelve = AuthScript(policy_script(1, 1, role_addr.keys()))

        funding = CTransaction()
        funding.vout = [CTxOut(CUSTODY_VALUE, eleven.spk) for _ in range(2 * CUSTODY_INPUTS - 1)]
        funding.vout.append(CTxOut(CUSTODY_VALUE, twelve.spk))
        funded = node.fundrawtransaction(bytes_to_hex_str(funding.serialize()),
                                         {"changePosition": len(funding.vout)})["hex"]
        txid = node.sendrawtransaction(node.signrawtransaction(funded)["hex"])
        node.generate(1)
        sync_blocks(self.nodes)
        outpoints = [(int(txid, 16), n) for n in range(2 * CUSTODY_INPUTS)]
        pay = CScript(bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"]))

        def spend(custodies, role):
            token = node.listmyassets(role, True)[role]["outpoints"][0]
            tx = CTransaction()
            tx.nVersion = 2
            for prevout in [outpoint for outpoint, _ in custodies] + [(int(token["txid"], 16), token["vout"])]:
                tx.vin.append(CTxIn(COutPoint(*prevout), b"", 0xffffffff))
            amount = (len(custodies) * CUSTODY_VALUE - FEE) // PAYMENTS
            tx.vout = [CTxOut(amount, pay) for _ in range(PAYMENTS)]
            role_spk = bytes.fromhex(node.validateaddress(role_addr[role])["scriptPubKey"])
            tx.vout.append(CTxOut(0, transfer_spk(role_spk, role, COIN)))
            signed = from_hex(CTransaction(), node.signrawtransaction(bytes_to_hex_str(tx.serialize()))["hex"])
            tx.vin[-1].scriptSig = signed.vin[-1].scriptSig
            for i, (_, custody) in enumerate(custodies):
                tx.wit.vtxinwit.append(CTxInWitness())
                tx.wit.vtxinwit[i].scriptWitness.stack = custody_witness(custody)
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.rehash()
            return tx

        within = spend([(o, eleven) for o in outpoints[:CUSTODY_INPUTS]], "R00!")
        over = spend([(o, eleven) for o in outpoints[CUSTODY_INPUTS:-1]] + [(outpoints[-1], twelve)], "R01!")
        return within, over

    def verdict(self, tx):
        result = self.nodes[0].testmempoolaccept([bytes_to_hex_str(tx.serialize_with_witness())])[0]
        # testmempoolaccept reports "<code>: <reason>"; compare the reason.
        return "accepted" if result["allowed"] else result["reject-reason"].split(": ", 1)[-1]

    def run_test(self):
        node = self.nodes[0]
        with open(os.path.join(DATA, "txhash_csfs_vectors.json")) as f:
            ecdsa = next(v for v in json.load(f) if v["algorithm"] == "ecdsa")
        sig_args = [bytes.fromhex(ecdsa["signature"]), bytes.fromhex(ecdsa["digest"]), bytes.fromhex(ecdsa["pubkey"])]
        kinds = {
            "p500": (poseidon(500), [b''], 40),
            "p1": (poseidon(1), [b''], 4),
            "c170": (checks(170), sig_args, 44),
            "c130": (checks(130), sig_args, 2),
            "c131": (checks(131), sig_args, 4),
        }

        node.generate(1)
        block = self.build_block([])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        coinbase = block.vtx[0]
        node.generate(100)
        funding = CTransaction()
        funding.vin.append(CTxIn(COutPoint(coinbase.x16r, 0), b""))
        coins = {}
        for name, (script, args, count) in kinds.items():
            coins[name] = [((None, len(funding.vout) + i), script, args) for i in range(count)]
            funding.vout += [CTxOut(VALUE, authscript(script)) for _ in range(count)]
        funding.vout.append(CTxOut(coinbase.vout[0].nValue - len(funding.vout) * VALUE - COIN, CScript([OP_TRUE])))
        funding.rehash()
        for name in coins:
            coins[name] = [((funding.x16r, n), script, args) for (_, n), script, args in coins[name]]
        block = self.build_block([funding])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        sync_blocks(self.nodes)
        pay = CScript(bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"]))
        take = lambda name, n: [coins[name].pop() for _ in range(n)]

        assetauth_within, assetauth_over = self.assetauth_cases()

        def cases():
            return {
                "5,000 permutations": self.spend(take("p500", 10), pay),
                "5,001 permutations": self.spend(take("p500", 10) + take("p1", 1), pay),
                "2,000 witness sigops": self.spend(take("c170", 11) + take("c130", 1), pay),
                "2,001 witness sigops": self.spend(take("c170", 11) + take("c131", 1), pay),
                "15,000 asset-auth units": assetauth_within,
                "15,001 asset-auth units": assetauth_over,
            }

        self.log.info("Below the NIP-028 height the old limits apply")
        assert node.getblockcount() + 1 < FORK_HEIGHT
        for label, tx in cases().items():
            assert_equal(self.verdict(tx), "accepted")
            self.log.info("  %s: accepted", label)

        self.log.info("From the NIP-028 height the lower limits apply")
        node.generate(FORK_HEIGHT - 1 - node.getblockcount())
        sync_blocks(self.nodes)
        assert_equal(node.getblockcount() + 1, FORK_HEIGHT)
        txs = cases()
        expected = {
            "5,000 permutations": "accepted",
            "5,001 permutations": "bad-txns-poseidon-work",
            "2,000 witness sigops": "accepted",
            "2,001 witness sigops": "bad-txns-too-many-witness-sigops",
            "15,000 asset-auth units": "accepted",
            "15,001 asset-auth units": "bad-txns-assetauth-work",
        }
        for label, tx in txs.items():
            assert_equal(self.verdict(tx), expected[label])
            self.log.info("  %s: %s", label, expected[label])

        self.log.info("Transactions over the relay limits are still valid in a block")
        block = self.build_block([txs["5,001 permutations"], txs["2,001 witness sigops"],
                                  txs["15,001 asset-auth units"]])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        assert_equal(node.getbestblockhash(), block.hash)
        sync_blocks(self.nodes)


if __name__ == '__main__':
    RelayWorkLimitsTest().main()
