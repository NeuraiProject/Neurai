#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""NIP-054 v7: policy version 2 of OP_CHECKASSETAUTH (votes by reference) on regtest.

A custody is an AuthScript v1 address whose script is
<2> <M> <G> <role_1> ... <role_n> <n> OP_CHECKASSETAUTH. A member votes by
sending its role token to itself with the proposal hash H2 as its transfer
message. The execution reads that output as a reference input (NIP-014) and
does not spend it, so the token never leaves its holder. The test covers:

- activation: version 2 shares the flag and the height of version 1;
- synchronous mode: direct signatures from P2PKH and strict ECDSA;
- asynchronous mode: votes by reference from P2PKH and strict ECDSA, executed
  by anyone, with the role tokens left where they were;
- voting and executing in one transaction with a direct signature;
- rule 6: the executor may add votes of any list, and nothing else;
- the reference rules of NIP-014: a vote must be confirmed; a retraction in the
  mempool blocks the execution, a confirmed one evicts it, and in the same
  block the vote still counts;
- expiry, and eviction from the mempool when T passes;
- a sale: the vote leaves with the token, and a token received with H2 already
  set votes for its new holder until they move it;
- a reorganization that unconfirms a vote;
- a restart and verifychain 4.
"""

from decimal import Decimal
import struct

from feature_assetauth import AuthScript, num, set_witness, tagged_hash, transfer_spk
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxOut, from_hex, hash256,
                                     ser_compact_size, uint256_from_compact, uint256_from_str)
from test_framework.script import CScript, CScriptOp
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, assert_raises_rpc_error, connect_nodes_bi, disconnect_nodes,
                                 sync_blocks, wait_until)

ACTIVATION = 350
CHAIN_ID = 2  # regtest
OP_CHECKASSETAUTH = CScriptOp(0xdf)
SEQUENCE = 0xffffffff
FEE = Decimal("0.05")
PAYMENT = 1 * COIN

SHAPE = "transaction shape not allowed in asynchronous mode"
THRESHOLD = "not enough roles approve"


def policy_script_v2(M, G, roles):
    roles = sorted(roles)
    return CScript([2, M, G] + [r.encode() for r in roles] + [len(roles), OP_CHECKASSETAUTH])


def proposal_hash_v2(tx, c, a, b, r, T):
    """H2 (NIP-054 v7, section 3.8): m2 commits r and the references 0..r-1."""
    m = bytes([CHAIN_ID]) + struct.pack("<i", tx.nVersion) + struct.pack("<I", tx.nLockTime) + struct.pack("<I", T)
    m += ser_compact_size(c) + ser_compact_size(a) + ser_compact_size(b)
    for i in range(c):
        m += tx.vin[i].prevout.serialize() + struct.pack("<I", tx.vin[i].nSequence)
    for i in range(a):
        m += tx.vout[i].serialize()
    for i in range(len(tx.vout) - b, len(tx.vout)):
        m += tx.vout[i].serialize()
    m += ser_compact_size(r)
    for i in range(r):
        m += tx.vrefin[i].serialize()
    return tagged_hash(b"NeuraiAssetAuthProposalV2", m)


def build_v3(inputs, outputs, refs=()):
    tx = CTransaction()
    tx.nVersion = 3
    tx.nLockTime = 0
    for txid, n in inputs:
        tx.vin.append(CTxIn(COutPoint(int(txid, 16), n), b"", SEQUENCE))
    for value, spk in outputs:
        tx.vout.append(CTxOut(int(value), spk))
    tx.vrefin = [COutPoint(int(txid, 16), n) for txid, n in refs]
    return tx


def custody_witness_v2(custody, c=0, a=0, b=0, r=0, T=0):
    return [b"\x00", num(c), num(a), num(b), num(r), num(T), custody.script]


class AssetAuthV2Test(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-assetauthheight=%d" % ACTIVATION]] * 2

    # ------------------------------------------------------------------ helpers

    def legacy(self, node=None):
        return (node or self.node).getnewaddress("", "legacy")

    def spk(self, address):
        return bytes.fromhex(self.node.validateaddress(address)["scriptPubKey"])

    def asset_outpoint(self, name, node=None):
        outpoint = (node or self.node).listmyassets(name, True)[name]["outpoints"][0]
        return outpoint["txid"], outpoint["vout"]

    def fee_utxo(self, minimum=Decimal("1")):
        for utxo in sorted(self.node.listunspent(), key=lambda u: u["amount"]):
            if utxo["amount"] >= minimum and (utxo["txid"], utxo["vout"]) not in self.reserved:
                self.reserved.add((utxo["txid"], utxo["vout"]))
                return utxo
        raise AssertionError("no fee utxo")

    def sign(self, tx, sighash="ALL", node=None):
        """Sign the wallet inputs; keep the witnesses set by hand."""
        manual = {i: list(w.scriptWitness.stack) for i, w in enumerate(tx.wit.vtxinwit) if w.scriptWitness.stack}
        signed = from_hex(CTransaction(), (node or self.node).signrawtransaction(tx.serialize().hex(), [], None, sighash)["hex"])
        for i, stack in manual.items():
            set_witness(signed, i, stack)
        return signed

    def send(self, tx, node=None):
        return (node or self.node).sendrawtransaction(tx.serialize_with_witness().hex())

    def assert_rejected(self, tx, message):
        assert_raises_rpc_error(-26, message, self.node.sendrawtransaction, tx.serialize_with_witness().hex())

    def mine(self, count=1):
        hashes = self.node.generate(count)
        self.sync_all()
        self.reserved.clear()
        return hashes

    def submit_block(self, txs):
        node = self.node
        tip = node.getbestblockhash()
        coinbase = create_coinbase(node.getblockcount() + 1)
        coinbase.vout[0].nValue = 0
        coinbase.rehash()
        tip_header = node.getblock(tip)
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
        result = node.submitblock(block.serialize(with_witness=True).hex())
        self.sync_all()
        self.reserved.clear()
        return result

    def custody_outputs(self, txid):
        """XNA-only outputs of `txid` at the custody: (txid, n, value)."""
        tx = self.node.getrawtransaction(txid, True)
        return [(txid, out["n"], out["value"]) for out in tx["vout"]
                if bytes.fromhex(out["scriptPubKey"]["hex"]) == self.custody.spk]

    def vote(self, role, h2, node=None, to=None):
        """`role` sent to `to` (its holder by default) with H2 as message."""
        node = node or self.node
        address = to or self.role_addr[role]
        txid = node.transfer(role, 1, address, h2.hex())[0]
        if node is not self.node:
            self.sync_all()  # node0 mines it
        prefix = self.spk(address)
        outs = [out["n"] for out in node.getrawtransaction(txid, True)["vout"]
                if bytes.fromhex(out["scriptPubKey"]["hex"]).startswith(prefix + b"\xc0")]
        assert_equal(len(outs), 1)
        return txid, outs[0]

    def retraction(self, outpoint, role):
        """A signed transfer of `role` from `outpoint` back to its holder, without message."""
        fee = self.fee_utxo()
        tx = build_v3([outpoint, (fee["txid"], fee["vout"])],
                      [(0, transfer_spk(self.spk(self.role_addr[role]), role, COIN)),
                       (int((fee["amount"] - FEE) * COIN), self.spk(self.legacy()))])
        tx.nVersion = 2
        return self.sign(tx)

    def propose(self, T):
        """A payment of PAYMENT out of the custody, the rest back to it: c = 1, a = 2, b = 0, r = 0."""
        utxo = self.custody_utxos.pop(0)
        prefix = [(PAYMENT, self.spk(self.legacy())),
                  (int(Decimal(str(utxo[2])) * COIN) - PAYMENT, self.custody.spk)]
        skeleton = build_v3([utxo[:2]], prefix)
        return {"utxo": utxo, "prefix": prefix, "T": T, "h2": proposal_hash_v2(skeleton, 1, 2, 0, 0, T)}

    def execution(self, p, votes, extra_inputs=(), extra_outputs=(), extra_refs=()):
        """Anyone executes: the custody input, a fee input and the votes as references."""
        fee = self.fee_utxo()
        inputs = [p["utxo"][:2]] + list(extra_inputs) + [(fee["txid"], fee["vout"])]
        outputs = list(p["prefix"]) + list(extra_outputs) + [(int((fee["amount"] - FEE) * COIN), self.spk(self.legacy()))]
        tx = build_v3(inputs, outputs, list(votes) + list(extra_refs))
        # Votes, inputs c.. and intermediate outputs are outside H2.
        assert_equal(proposal_hash_v2(tx, 1, 2, 0, 0, p["T"]), p["h2"])
        set_witness(tx, 0, custody_witness_v2(self.custody, c=1, a=2, b=0, r=0, T=p["T"]))
        return self.sign(tx)

    def executed(self, txid, p):
        """Track the custody output an execution creates."""
        self.custody_utxos.append((txid, 1, Decimal(p["prefix"][1][0]) / COIN))

    def sync_spend(self, roles, sighash="ALL"):
        """XNA from the custody, approved by direct signatures of `roles`."""
        txid, n, value = self.custody_utxos.pop(0)
        inputs = [(txid, n)] + [self.asset_outpoint(r) for r in roles]
        outputs = [(int((Decimal(str(value)) - FEE) * COIN), self.spk(self.legacy()))]
        outputs += [(0, transfer_spk(self.spk(self.role_addr[r]), r, COIN)) for r in roles]
        tx = build_v3(inputs, outputs)
        set_witness(tx, 0, custody_witness_v2(self.custody))
        self.custody_utxos.insert(0, (txid, n, value))  # given back unless the spend is mined
        return self.sign(tx, sighash)

    # ------------------------------------------------------------------ test

    def run_test(self):
        self.node = self.nodes[0]
        self.reserved = set()
        self.mine(300)
        self.setup_roles()
        self.test_activation()
        self.test_sync_mode()
        self.test_async_votes()
        self.test_vote_and_execute()
        self.test_rule_6()
        self.test_unconfirmed_vote()
        self.test_retraction()
        self.test_expiry()
        self.test_reorg()
        self.test_sale_and_received_vote()
        self.test_restart()

    def setup_roles(self):
        self.log.info("Roles ROLEA! and ROLEB! at P2PKH, ROLEC! at strict ECDSA; a 2-of-3 custody, version 2")
        node = self.node
        self.role_addr = {}
        for name, kind in (("ROLEA", "legacy"), ("ROLEB", "legacy"), ("ROLEC", "ecdsa")):
            address = node.getnewaddress("", kind)
            node.issue(name, 1, address)
            self.role_addr[name + "!"] = address
        assert_equal(self.spk(self.role_addr["ROLEC!"])[:2], b"\x53\x20")  # witness v3, strict ECDSA
        self.other_addr = self.legacy()
        node.issue("OTHER", 1, self.other_addr)  # OTHER! is the owner of another list
        node.sendtoaddress(self.legacy(self.nodes[1]), 100)
        self.mine()
        self.custody = AuthScript(policy_script_v2(2, 3, self.role_addr.keys()))
        self.custody_utxos = []
        for _ in range(10):
            self.custody_utxos += self.custody_outputs(node.sendtoaddress(self.custody.address, 10))
        self.mine()

    def test_activation(self):
        self.log.info("Below -assetauthheight 0xdf is a bad opcode for version 2 too")
        node = self.node
        assert node.getblockcount() + 1 < ACTIVATION
        tx = self.sync_spend(["ROLEA!", "ROLEB!"])
        self.assert_rejected(tx, "Opcode missing or not understood")
        self.mine(ACTIVATION - 1 - node.getblockcount())
        self.log.info("From the height of version 1 the same version 2 spend is valid")
        txid = self.send(tx)
        self.custody_utxos.pop(0)
        self.mine()
        assert node.getrawtransaction(txid, True)["confirmations"] >= 1

    def test_sync_mode(self):
        self.log.info("Synchronous mode: one role is not enough, SIGHASH_NONE is refused, strict ECDSA signs")
        self.assert_rejected(self.sync_spend(["ROLEA!"]), THRESHOLD)
        self.reserved.clear()
        self.assert_rejected(self.sync_spend(["ROLEA!", "ROLEB!"], "NONE"), "does not use SIGHASH_ALL")
        self.reserved.clear()
        self.send(self.sync_spend(["ROLEB!", "ROLEC!"]))
        self.custody_utxos.pop(0)
        self.mine()

    def test_async_votes(self):
        self.log.info("Asynchronous mode: ROLEA (P2PKH) and ROLEC (strict ECDSA) vote by reference")
        node = self.node
        p = self.propose(node.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        self.assert_rejected(self.execution(p, [vote_a]), "refinput-not-confirmed")
        self.mine()
        self.log.info("One vote is not enough")
        self.assert_rejected(self.execution(p, [vote_a]), THRESHOLD)
        vote_c = self.vote("ROLEC!", p["h2"])
        self.mine()
        self.log.info("Anyone executes with both votes; the tokens do not move")
        txid = self.send(self.execution(p, [vote_a, vote_c]))
        self.mine()
        self.executed(txid, p)
        assert node.getrawtransaction(txid, True)["confirmations"] >= 1
        for outpoint in (vote_a, vote_c):
            assert node.gettxout(outpoint[0], outpoint[1]) is not None
        assert_equal(self.asset_outpoint("ROLEA!"), vote_a)
        assert_equal(self.asset_outpoint("ROLEC!"), vote_c)

    def test_vote_and_execute(self):
        self.log.info("ROLEA votes by reference, ROLEB signs the execution directly (example 6.3)")
        p = self.propose(self.node.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        self.mine()
        back = (0, transfer_spk(self.spk(self.role_addr["ROLEB!"]), "ROLEB!", COIN))
        txid = self.send(self.execution(p, [vote_a], extra_inputs=[self.asset_outpoint("ROLEB!")],
                                        extra_outputs=[back]))
        self.mine()
        self.executed(txid, p)

    def test_rule_6(self):
        self.log.info("Rule 6: the executor may add a vote of another list, nothing else")
        p = self.propose(self.node.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        other = self.vote("OTHER!", p["h2"], to=self.other_addr)
        self.mine()
        junk = self.fee_utxo()
        self.assert_rejected(self.execution(p, [vote_a, vote_b], extra_refs=[(junk["txid"], junk["vout"])]), SHAPE)
        self.reserved.clear()
        txid = self.send(self.execution(p, [vote_a, vote_b], extra_refs=[other]))
        self.mine()
        self.executed(txid, p)

    def test_unconfirmed_vote(self):
        self.log.info("A vote must be confirmed before an execution references it")
        p = self.propose(self.node.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        self.assert_rejected(self.execution(p, [vote_a, vote_b]), "refinput-not-confirmed")
        self.reserved.clear()
        self.mine()
        txid = self.send(self.execution(p, [vote_a, vote_b]))
        self.mine()
        self.executed(txid, p)

    def test_retraction(self):
        self.log.info("Retraction in the mempool before the execution: refinput-spent-in-mempool")
        node = self.node
        p = self.propose(node.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        self.mine()
        node.transfer("ROLEB!", 1, self.role_addr["ROLEB!"])
        self.assert_rejected(self.execution(p, [vote_a, vote_b]), "refinput-spent-in-mempool")
        self.mine()

        self.log.info("A confirmed retraction evicts the pending execution")
        vote_b = self.vote("ROLEB!", p["h2"])
        self.mine()
        pending = self.send(self.execution(p, [vote_a, vote_b]))
        assert pending in node.getrawmempool()
        assert_equal(self.submit_block([self.retraction(vote_b, "ROLEB!")]), None)
        assert pending not in node.getrawmempool()

        self.log.info("Retraction and execution in the same block: the vote still counts")
        vote_b = self.vote("ROLEB!", p["h2"])
        self.mine()
        execution = self.execution(p, [vote_a, vote_b])
        retraction = self.retraction(vote_b, "ROLEB!")
        assert_equal(self.submit_block([retraction, execution]), None)
        assert node.getrawtransaction(execution.hash, True)["confirmations"] >= 1
        self.executed(execution.hash, p)

    def test_expiry(self):
        self.log.info("Expiry: an execution after T is refused")
        node0, node1 = self.nodes
        p = self.propose(node0.getblockcount() + 2)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        self.mine()
        late = self.execution(p, [vote_a, vote_b])
        self.mine(2)
        assert node0.getblockcount() + 1 > p["T"]
        self.assert_rejected(late, "proposal expired")
        self.reserved.clear()

        self.log.info("A pending execution leaves the mempool when T passes")
        p = self.propose(node0.getblockcount() + 2)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        self.mine()
        pending = self.execution(p, [vote_a, vote_b])
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        txid = self.send(pending)
        assert txid in node0.getrawmempool()
        node1.generate(3)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        wait_until(lambda: txid not in node0.getrawmempool(), timeout=30,
                   err_msg="the expired execution stayed in the mempool")
        self.reserved.clear()

    def test_reorg(self):
        self.log.info("A reorganization that unconfirms a vote evicts the execution")
        node = self.node
        p = self.propose(node.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        block = self.mine()[0]
        execution = self.execution(p, [vote_a, vote_b])
        txid = self.send(execution)
        node.invalidateblock(block)
        assert txid not in node.getrawmempool()
        node.reconsiderblock(block)
        assert_equal(node.getbestblockhash(), self.nodes[1].getbestblockhash())
        assert_equal(self.send(execution), txid)
        self.mine()
        self.executed(txid, p)

    def test_sale_and_received_vote(self):
        self.log.info("A sale: the vote leaves with the token")
        node0, node1 = self.nodes
        p = self.propose(node0.getblockcount() + 50)
        vote_a = self.vote("ROLEA!", p["h2"])
        vote_b = self.vote("ROLEB!", p["h2"])
        self.mine()
        buyer = self.legacy(node1)
        node0.transfer("ROLEA!", 1, buyer)
        self.mine()
        self.assert_rejected(self.execution(p, [vote_a, vote_b]), "refinput-not-confirmed")
        self.reserved.clear()

        self.log.info("The new holder votes with its own transfer")
        vote_a = self.vote("ROLEA!", p["h2"], node=node1, to=buyer)
        self.mine()
        txid = self.send(self.execution(p, [vote_a, vote_b]))
        self.mine()
        self.executed(txid, p)

        self.log.info("A token received with H2 already set votes until its holder moves it (section 3.5)")
        p = self.propose(node0.getblockcount() + 50)
        vote_b = self.vote("ROLEB!", p["h2"])
        received = self.vote("ROLEA!", p["h2"], node=node1, to=self.role_addr["ROLEA!"])
        self.mine()
        assert_equal(self.asset_outpoint("ROLEA!"), received)
        txid = self.send(self.execution(p, [received, vote_b]))
        self.mine()
        self.executed(txid, p)

    def test_restart(self):
        self.log.info("Restart: the chain reloads and verifychain 4 reconnects every execution")
        tip = self.node.getbestblockhash()
        for i in range(self.num_nodes):
            self.restart_node(i, extra_args=["-assetauthheight=%d" % ACTIVATION, "-checklevel=4", "-checkblocks=0"])
            assert_equal(self.nodes[i].getbestblockhash(), tip)
            assert self.nodes[i].verifychain(4, 0)
        self.node = self.nodes[0]


if __name__ == "__main__":
    AssetAuthV2Test().main()
