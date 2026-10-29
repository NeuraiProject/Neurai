#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""NIP-054: OP_CHECKASSETAUTH (P2AH inside AuthScript) on regtest.

A custody is an AuthScript v1 address whose script ends in OP_CHECKASSETAUTH.
Roles are owner tokens held by members. The test covers:

- activation: the byte is a bad opcode below -assetauthheight and works from it;
- synchronous mode: members sign the spend directly (SIGHASH_ALL only);
- the governance threshold G when an owner kept in the custody leaves it;
- asynchronous mode: a member votes by locking its role in a vote lock with
  the proposal hash H as transfer message; anyone executes later;
- expiry, the lock's return branch and mempool eviction when T passes;
- why the lock must identify the custody with OP_INPUTFIELD selector 0x04;
- the work budget: the relay limit per transaction, the consensus limit per
  block and block assembly.
"""

import hashlib
import struct
from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase, serialize_script_num
from test_framework.messages import (COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut,
                                     from_hex, hash256, ser_compact_size, uint256_from_compact, uint256_from_str)
from test_framework.script import (CScript, CScriptOp, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY,
                                   OP_GREATERTHAN, OP_IF, OP_LESSTHANOREQUAL, OP_NIP, OP_SWAP, OP_TRUE, OP_VERIFY)
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, assert_raises_rpc_error, connect_nodes_bi, disconnect_nodes,
                                 sync_blocks, wait_until)

ACTIVATION = 450
CHAIN_ID = 2  # regtest
OP_CHECKASSETAUTH = CScriptOp(0xdf)
OP_INPUTFIELD = CScriptOp(0xc4)
OP_OUTPUTSCRIPT = CScriptOp(0xcd)
OP_CHAINCONTEXT = CScriptOp(0xd7)
SEQUENCE = 0xffffffff
FEE = Decimal("0.05")
CENT_SATS = COIN // 100

BECH32M_CONST = 0x2bc830a3
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def convertbits(data, frombits, tobits):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32m_address(hrp, witver, program):
    data = [witver] + convertbits(program, 8, 5)
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data
    polymod = bech32_polymod(values + [0] * 6) ^ BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def sha256(data):
    return hashlib.sha256(data).digest()


def tagged_hash(tag, msg):
    t = sha256(tag)
    return sha256(t + t + msg)


def num(value):
    return bytes(serialize_script_num(value))


def push(data):
    return bytes(CScript([data]))


def transfer_spk(dest_spk, name, amount, message=b""):
    """Asset transfer script with the NIP-040 'xna' marker."""
    payload = b"xnat" + ser_compact_size(len(name)) + name.encode() + struct.pack("<q", amount)
    if message:
        payload += b"\x54" + ser_compact_size(len(message)) + message
    return dest_spk + b"\xc0" + push(payload) + b"\x75"


class AuthScript:
    """A generic AuthScript v1 address (authType 0x00) for a witness script."""

    def __init__(self, script):
        self.script = bytes(script)
        self.commitment = tagged_hash(b"NeuraiAuthScript", b"\x01\x00" + sha256(self.script))
        self.spk = b"\x51\x20" + self.commitment
        self.dest33 = b"\x01" + self.commitment
        self.address = bech32m_address("tnc", 1, self.commitment)


def policy_script(M, G, roles):
    roles = sorted(roles)
    return CScript([1, M, G] + [r.encode() for r in roles] + [len(roles), OP_CHECKASSETAUTH])


def lock_script(T, custody, return_spk, selector=0x04):
    """Vote lock: execute (custody present before T) or return after T."""
    field = custody.dest33 if selector == 0x04 else custody.commitment
    # Selectors are pushed as small integers (OP_n): AuthScript requires
    # minimal pushes.
    return CScript([OP_IF,
                    1, OP_CHAINCONTEXT, T, OP_LESSTHANOREQUAL, OP_VERIFY,
                    OP_SWAP, selector, OP_INPUTFIELD, field, OP_EQUALVERIFY,
                    OP_OUTPUTSCRIPT, return_spk, OP_EQUAL,
                    OP_ELSE,
                    1, OP_CHAINCONTEXT, T, OP_GREATERTHAN, OP_VERIFY,
                    OP_NIP, OP_OUTPUTSCRIPT, return_spk, OP_EQUAL,
                    OP_ENDIF])


def proposal_hash(tx, c, a, b, T):
    m = bytes([CHAIN_ID]) + struct.pack("<i", tx.nVersion) + struct.pack("<I", tx.nLockTime) + struct.pack("<I", T)
    m += ser_compact_size(c) + ser_compact_size(a) + ser_compact_size(b)
    for i in range(c):
        m += tx.vin[i].prevout.serialize() + struct.pack("<I", tx.vin[i].nSequence)
    for i in range(a):
        m += tx.vout[i].serialize()
    for i in range(len(tx.vout) - b, len(tx.vout)):
        m += tx.vout[i].serialize()
    m += ser_compact_size(0)
    return tagged_hash(b"NeuraiAssetAuthProposal", m)


def build_tx(inputs, outputs):
    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    for txid, n in inputs:
        tx.vin.append(CTxIn(COutPoint(int(txid, 16), n), b"", SEQUENCE))
    for value, spk in outputs:
        tx.vout.append(CTxOut(int(value), spk))
    return tx


def set_witness(tx, index, stack):
    while len(tx.wit.vtxinwit) < len(tx.vin):
        tx.wit.vtxinwit.append(CTxInWitness())
    tx.wit.vtxinwit[index].scriptWitness.stack = stack


def custody_witness(custody, c=0, a=0, b=0, T=0):
    return [b"\x00", num(c), num(a), num(b), num(T), custody.script]


class AssetAuthTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-assetauthheight=%d" % ACTIVATION]] * 2

    # ------------------------------------------------------------------ helpers

    def legacy(self):
        return self.node.getnewaddress("", "legacy")

    def spk(self, address):
        return bytes.fromhex(self.node.validateaddress(address)["scriptPubKey"])

    def asset_outpoint(self, name):
        outpoint = self.node.listmyassets(name, True)[name]["outpoints"][0]
        return outpoint["txid"], outpoint["vout"]

    def fee_utxo(self, minimum=Decimal("1")):
        for utxo in sorted(self.node.listunspent(), key=lambda u: u["amount"]):
            if utxo["amount"] >= minimum and (utxo["txid"], utxo["vout"]) not in self.reserved:
                self.reserved.add((utxo["txid"], utxo["vout"]))
                return utxo
        raise AssertionError("no fee utxo")

    def outputs_to(self, txid, spk_prefix):
        tx = self.node.getrawtransaction(txid, True)
        return [(txid, out["n"], out["value"]) for out in tx["vout"]
                if bytes.fromhex(out["scriptPubKey"]["hex"]).startswith(spk_prefix)]

    def sign(self, tx, sighash="ALL"):
        """Sign the wallet inputs; keep the witnesses already set."""
        signed = from_hex(CTransaction(), self.node.signrawtransaction(tx.serialize().hex(), [], None, sighash)["hex"])
        for i, txin in enumerate(signed.vin):
            tx.vin[i].scriptSig = txin.scriptSig
        return tx

    def send(self, tx):
        return self.node.sendrawtransaction(tx.serialize_with_witness().hex())

    def assert_rejected(self, tx, message):
        assert_raises_rpc_error(-26, message, self.node.sendrawtransaction, tx.serialize_with_witness().hex())

    def mine(self, count=1):
        hashes = self.node.generate(count)
        self.sync_all()
        return hashes

    def submit_block(self, txs):
        node = self.node
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        coinbase = create_coinbase(height)
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
        # Regtest mines double-SHA256 over the 80-byte header, not x16rv2
        # as CBlock.solve() assumes.
        target = uint256_from_compact(block.nBits)
        while uint256_from_str(hash256(CBlockHeader.serialize(block))) > target:
            block.nNonce += 1
        return node.submitblock(block.serialize(with_witness=True).hex())

    # ------------------------------------------------------------------ test

    def run_test(self):
        self.node = self.nodes[0]
        self.reserved = set()
        self.mine(300)
        self.setup_roles()
        self.test_activation()
        self.test_sync_mode()
        self.test_governance_threshold()
        self.test_async_vote()
        self.test_expiry()
        self.test_mempool_eviction()
        self.test_fake_custody()
        self.test_budget()
        self.test_restart()

    def setup_roles(self):
        self.log.info("Roles ROLEA!, ROLEB!, ROLEC! and a 2-of-3 custody with G = 3")
        node = self.node
        self.role_addr = {}
        for name in ("ROLEA", "ROLEB", "ROLEC"):
            address = self.legacy()
            node.issue(name, 1, address)
            self.role_addr[name + "!"] = address
        node.issue("GOLD", 100, self.legacy())
        node.issue("TOKEN", 1, self.legacy())
        self.mine()
        self.custody = AuthScript(policy_script(2, 3, self.role_addr.keys()))
        node.sendtoaddress(self.custody.address, 10)
        node.sendtoaddress(self.custody.address, 10)
        node.transfer("GOLD", 100, self.custody.address)
        self.gold = 100  # GOLD held by the custody
        node.transfer("TOKEN!", 1, self.custody.address)
        self.mine()

    def find_custody(self, asset=None):
        """Latest confirmed custody output carrying XNA only, or `asset`."""
        best = self.node.getbestblockhash()
        while True:
            block = self.node.getblock(best, 2)
            for tx in block["tx"]:
                for out in tx["vout"]:
                    spk = bytes.fromhex(out["scriptPubKey"]["hex"])
                    if not spk.startswith(self.custody.spk):
                        continue
                    if self.node.gettxout(tx["txid"], out["n"]) is None:
                        continue
                    if asset is None and spk == self.custody.spk:
                        return tx["txid"], out["n"], out["value"]
                    if asset is not None and (ser_compact_size(len(asset)) + asset.encode()) in spk[34:]:
                        return tx["txid"], out["n"], out["value"]
            best = block["previousblockhash"]

    def sync_spend(self, roles, sighash="ALL", custody_input=None):
        """XNA from the custody, approved by direct signatures of `roles`."""
        txid, n, value = custody_input or self.find_custody()
        inputs = [(txid, n)] + [self.asset_outpoint(r) for r in roles]
        payout = int((Decimal(str(value)) - FEE) * COIN)
        outputs = [(payout, self.spk(self.legacy()))]
        outputs += [(0, transfer_spk(self.spk(self.role_addr[r]), r, COIN)) for r in roles]
        tx = build_tx(inputs, outputs)
        set_witness(tx, 0, custody_witness(self.custody))
        return self.sign(tx, sighash)

    def test_activation(self):
        self.log.info("Below the activation height 0xdf is a bad opcode")
        node = self.node
        assert node.getblockcount() + 1 < ACTIVATION
        tx = self.sync_spend(["ROLEA!", "ROLEB!"])
        self.assert_rejected(tx, "Opcode missing or not understood")
        self.mine(ACTIVATION - 1 - node.getblockcount())
        self.log.info("From the activation height the same spend is valid")
        txid = self.send(tx)

        self.log.info("A reorg below the activation height evicts it from the mempool")
        last_inactive = node.getblockhash(ACTIVATION - 1)
        node.invalidateblock(last_inactive)
        assert txid not in node.getrawmempool()
        node.reconsiderblock(last_inactive)
        assert_equal(self.send(tx), txid)
        block = self.mine()[0]
        assert_equal(node.getrawtransaction(txid, True)["blockhash"], block)

        self.log.info("Disconnecting the activation block does not bring it back below the height")
        node.invalidateblock(last_inactive)
        assert txid not in node.getrawmempool()
        node.reconsiderblock(last_inactive)
        assert_equal(node.getbestblockhash(), block)
        assert_equal(node.getrawtransaction(txid, True)["blockhash"], block)

    def test_sync_mode(self):
        self.log.info("Synchronous mode: one role is not enough, SIGHASH_NONE is refused")
        self.assert_rejected(self.sync_spend(["ROLEA!"]), "not enough roles approve")
        self.assert_rejected(self.sync_spend(["ROLEA!", "ROLEB!"], "NONE"),
                             "does not use SIGHASH_ALL")
        self.send(self.sync_spend(["ROLEB!", "ROLEC!"]))
        self.mine()

    def test_governance_threshold(self):
        self.log.info("An owner leaving the custody needs G = 3 roles")
        # TOKEN! is not in the wallet: it sits in the custody.
        custody_token = self.find_custody("TOKEN!")

        def leave(roles):
            fee = self.fee_utxo()
            inputs = [(custody_token[0], custody_token[1]), (fee["txid"], fee["vout"])]
            inputs += [self.asset_outpoint(r) for r in roles]
            outputs = [(0, transfer_spk(self.spk(self.legacy()), "TOKEN!", COIN)),
                       (int((fee["amount"] - FEE) * COIN), self.spk(self.legacy()))]
            outputs += [(0, transfer_spk(self.spk(self.role_addr[r]), r, COIN)) for r in roles]
            tx = build_tx(inputs, outputs)
            set_witness(tx, 0, custody_witness(self.custody))
            return self.sign(tx)

        self.assert_rejected(leave(["ROLEA!", "ROLEB!"]), "not enough roles approve")
        self.reserved.clear()
        self.send(leave(["ROLEA!", "ROLEB!", "ROLEC!"]))
        self.mine()
        assert self.node.listmyassets("TOKEN!")["TOKEN!"] == 1

    def vote(self, role, tx, c, a, b, T, selector=0x04):
        """Lock `role` in a vote lock carrying H; return (lock, outpoint)."""
        h = proposal_hash(tx, c, a, b, T)
        return_spk = transfer_spk(self.spk(self.role_addr[role]), role, COIN)
        lock = AuthScript(lock_script(T, self.custody, return_spk, selector))
        txid = self.node.transfer(role, 1, lock.address, h.hex())[0]
        self.mine()
        outpoint = self.outputs_to(txid, lock.spk)[0][:2]
        return lock, outpoint, return_spk

    def propose(self, T):
        """ROLEA proposes sending 10 GOLD out of the custody and votes for it."""
        gold = self.find_custody("GOLD")
        prefix = [(0, transfer_spk(self.spk(self.legacy()), "GOLD", 10 * COIN)),
                  (0, transfer_spk(self.custody.spk, "GOLD", (self.gold - 10) * COIN))]
        # H covers input 0, the prefix, T, version and locktime: the vote can
        # be cast before the execution exists.
        skeleton = build_tx([gold[:2]], prefix)
        lock, vote_outpoint, return_spk = self.vote("ROLEA!", skeleton, 1, 2, 0, T)
        return {"gold": gold, "prefix": prefix, "skeleton": skeleton, "lock": lock,
                "vote": vote_outpoint, "return": return_spk, "T": T}

    def execution(self, p, with_bob=True):
        """Anyone executes: custody input 0, the vote, optionally ROLEB, a fee."""
        fee = self.fee_utxo()
        inputs = [p["gold"][:2], p["vote"]]
        outputs = list(p["prefix"]) + [(0, p["return"])]  # ROLEA return at index 2
        if with_bob:
            inputs.append(self.asset_outpoint("ROLEB!"))
            outputs.append((0, transfer_spk(self.spk(self.role_addr["ROLEB!"]), "ROLEB!", COIN)))
        inputs.append((fee["txid"], fee["vout"]))
        outputs.append((int((fee["amount"] - FEE) * COIN), self.spk(self.legacy())))
        tx = build_tx(inputs, outputs)
        assert_equal(proposal_hash(tx, 1, 2, 0, p["T"]), proposal_hash(p["skeleton"], 1, 2, 0, p["T"]))
        set_witness(tx, 0, custody_witness(self.custody, c=1, a=2, b=0, T=p["T"]))
        set_witness(tx, 1, [b"\x00", num(0), num(2), b"\x01", p["lock"].script])
        return self.sign(tx)

    def return_vote(self, p):
        """After T anyone returns the locked role to its owner (lock branch 2)."""
        fee = self.fee_utxo()
        back = build_tx([p["vote"], (fee["txid"], fee["vout"])],
                        [(0, p["return"]), (int((fee["amount"] - FEE) * COIN), self.spk(self.legacy()))])
        set_witness(back, 0, [b"\x00", num(0), num(0), b"", p["lock"].script])
        self.send(self.sign(back))
        self.mine()
        self.reserved.clear()

    def test_async_vote(self):
        self.log.info("Asynchronous mode: ROLEA votes from a lock, ROLEB signs, anyone executes")
        p = self.propose(self.node.getblockcount() + 50)
        self.assert_rejected(self.execution(p, with_bob=False), "not enough roles approve")
        self.reserved.clear()
        txid = self.send(self.execution(p))
        self.mine()
        self.gold -= 10
        assert self.node.getrawtransaction(txid, True)["confirmations"] >= 1
        assert_equal(self.node.listmyassets("ROLEA!")["ROLEA!"], 1)  # the vote came back
        self.reserved.clear()

    def test_expiry(self):
        self.log.info("Expiry: execution fails after T; the lock returns the role")
        p = self.propose(self.node.getblockcount() + 2)
        tx = self.execution(p)
        self.mine(2)
        assert self.node.getblockcount() + 1 > p["T"]
        self.assert_rejected(tx, "proposal expired")
        self.reserved.clear()
        self.return_vote(p)
        assert_equal(self.node.listmyassets("ROLEA!")["ROLEA!"], 1)

    def test_mempool_eviction(self):
        self.log.info("A pending asynchronous execution leaves the mempool when T passes")
        node0, node1 = self.nodes
        p = self.propose(node0.getblockcount() + 2)
        tx = self.execution(p)
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        txid = self.send(tx)
        assert txid in node0.getrawmempool()
        node1.generate(3)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        wait_until(lambda: txid not in node0.getrawmempool(), timeout=30,
                   err_msg="the expired execution stayed in the mempool")
        self.reserved.clear()
        self.return_vote(p)

    def test_fake_custody(self):
        self.log.info("Vote locks must identify the custody with selector 0x04, not 0x02")
        node = self.node
        # OP_1 <commitment> OP_DROP OP_DROP OP_TRUE: anyone can spend it, and
        # selector 0x02 reads its first 34 bytes as the custody commitment.
        fake_spk = b"\x51\x20" + self.custody.commitment + bytes([OP_DROP, OP_DROP, OP_TRUE])
        fee = self.fee_utxo()
        fund = build_tx([(fee["txid"], fee["vout"])],
                        [(COIN, fake_spk), (int((fee["amount"] - 1 - FEE) * COIN), self.spk(self.legacy()))])
        fake_txid = self.send(self.sign(fund))
        self.mine()
        self.reserved.clear()

        T = node.getblockcount() + 50
        skeleton = build_tx([self.find_custody("GOLD")[:2]],
                            [(0, transfer_spk(self.spk(self.legacy()), "GOLD", COIN))])
        for selector, cancelled in ((0x02, True), (0x04, False)):
            lock, vote_outpoint, return_spk = self.vote("ROLEA!", skeleton, 1, 1, 0, T, selector)
            fee = self.fee_utxo()
            attack = build_tx([(fake_txid, 0), vote_outpoint, (fee["txid"], fee["vout"])],
                              [(0, return_spk), (int((fee["amount"] + 1 - FEE) * COIN), self.spk(self.legacy()))])
            set_witness(attack, 1, [b"\x00", num(0), num(0), b"\x01", lock.script])
            attack = self.sign(attack)
            if cancelled:
                self.send(attack)
                self.mine()
                # The fake custody is spent; fund a new one for the next round.
                fee2 = self.fee_utxo()
                fund = build_tx([(fee2["txid"], fee2["vout"])],
                                [(COIN, fake_spk), (int((fee2["amount"] - 1 - FEE) * COIN), self.spk(self.legacy()))])
                fake_txid = self.send(self.sign(fund))
                self.mine()
            else:
                # The fake custody does not pass selector 0x04: the vote stays
                # locked until it is executed or expires.
                self.assert_rejected(attack, "OP_INPUTFIELD failed")
            self.reserved.clear()

    def test_budget(self):
        self.log.info("Work budget: relay limit per transaction, block limit and block assembly")
        node = self.node
        names = ["R%02d" % i for i in range(11)]
        role_addr = {}
        for name in names:
            address = self.legacy()
            node.issue(name, 1, address)
            role_addr[name + "!"] = address
        self.mine()
        custody = AuthScript(policy_script(1, 1, role_addr.keys()))

        # 3248 small custody outputs, 464 per funding transaction; the cases
        # below use 3035.
        utxos = []
        per_tx = 464
        for _ in range(7):
            fee = self.fee_utxo(Decimal("10"))
            outputs = [(CENT_SATS, custody.spk)] * per_tx
            change = int((fee["amount"] - Decimal(per_tx) * Decimal("0.01") - Decimal("1")) * COIN)
            outputs.append((change, self.spk(self.legacy())))
            txid = self.send(self.sign(build_tx([(fee["txid"], fee["vout"])], outputs)))
            utxos += [(txid, n) for n in range(per_tx)]
        self.mine()
        self.reserved.clear()

        def spend(count, role):
            inputs = [utxos.pop() for _ in range(count)]
            role_outpoint = node.listmyassets(role, True)[role]["outpoints"][0]
            inputs.append((role_outpoint["txid"], role_outpoint["vout"]))
            value = count * CENT_SATS - int(Decimal("0.6") * COIN)
            outputs = [(value, self.spk(self.legacy())),
                       (0, transfer_spk(self.spk(role_addr[role]), role, COIN))]
            tx = build_tx(inputs, outputs)
            for i in range(count):
                set_witness(tx, i, custody_witness(custody))
            return self.sign(tx)

        # An execution with n custody inputs charges 1 + (n + 1) inputs + 2
        # outputs + 1 for m, plus the name work: 11 roles and the two role
        # tokens, one unit each. That is n + 18, so a spend charges n * (n + 18).
        # 210 executions, 47880 units: over the 45000 relay limit, under the
        # 450000 block limit.
        heavy = spend(210, "R00!")
        self.assert_rejected(heavy, "bad-txns-assetauth-work")
        assert_equal(self.submit_block([heavy]), None)
        self.sync_all()

        # 680 executions, 474640 units: over the block limit.
        tip = node.getbestblockhash()
        assert_equal(self.submit_block([spend(680, "R01!")]), "bad-blk-assetauth-work")
        assert_equal(node.getbestblockhash(), tip)

        # Eleven standard transactions of 41535 units each: ten fit in a block
        # (415350), eleven do not (456885).
        txids = [self.send(spend(195, name + "!")) for name in names]
        assert_equal(set(txids), set(node.getrawmempool()))
        template = node.getblocktemplate()
        assert_equal(len(template["transactions"]), 10)
        block_hash = self.mine()[0]
        assert_equal(len(node.getblock(block_hash)["tx"]), 11)  # coinbase + 10
        assert_equal(len(node.getrawmempool()), 1)
        self.mine()
        assert_equal(len(node.getrawmempool()), 0)

    def test_restart(self):
        self.log.info("Restart: the chain reloads and every block with executions reconnects")
        tip = self.node.getbestblockhash()
        self.restart_node(0)
        self.node = self.nodes[0]
        assert_equal(self.node.getbestblockhash(), tip)
        # Level 4 reconnects the blocks, so the asynchronous executions see
        # their chain context again.
        assert self.node.verifychain(4, 0)


if __name__ == "__main__":
    AssetAuthTest().main()
