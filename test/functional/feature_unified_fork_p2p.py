#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Peers are not banned at the fork moment, and are banned away from it.

Every rule of the unified fork activates at one height H (-forkheight). When
block H-1 is found, the nodes that have it accept transactions for block H,
which may use the new opcodes or the new asset rules; a node that receives
block H-1 a few seconds later still validates against the old rules. Within
FORK_ACTIVATION_GRACE_BLOCKS (K) of H a refused transaction never punishes its
peer; outside it, a transaction that breaks the consensus rules of the next
block, witness programs included, bans its peer.

- far before H: a P2SH spend using OP_CAT is invalid and bans its peer
- the fork moment: node0 has block H-1, node1 does not. node1 refuses what
  node0 accepts for block H without banning the peer that sends it: P2SH and
  P2WSH spends using OP_CAT, a payment to an AuthScript output, a DEPIN
  issuance, a long asset name and an asset transfer with the 'xna' marker.
  The same holds when node0 itself relays a new spend to node1, and the other
  way round: node0 refuses without a ban an RBF-signalling transaction that
  is only valid for node1's next block
- once node1 has block H-1 it accepts all of them
- inside the window after H, an invalid AuthScript spend is refused without a
  ban (the price of the window)
- outside the window after H: a policy-only failure (non-minimal push) is not
  punished; an invalid AuthScript spend and an invalid P2SH spend ban their
  peer; the valid AuthScript spend relays and confirms
"""

import os

from test_framework.messages import (COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, MsgWitnessTx,
                                     MY_SUBVERSION, NODE_NETWORK, NODE_WITNESS, from_hex, sha256)
from test_framework.mininode import NetworkThread, NodeConn, NodeConnCB
from test_framework.script import CScript, CScriptOp, OP_0, OP_CAT, OP_EQUAL, OP_HASH160, hash160
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, connect_nodes_bi, disconnect_nodes, p2p_port, sync_blocks,
                                 sync_mempools, wait_until)

H = 500  # regtest activates assets by version bits around block 432
K = 10  # FORK_ACTIVATION_GRACE_BLOCKS
FUND = COIN
FEE = 1000000
SEQUENCE = 0xffffffff
RBF_SEQUENCE = 0xfffffffd
ASSET = "FORKCOIN"
DEPIN_NAME = "&FORKDEVICE"
LONG_NAME = "FORKLONGNAME" + "X" * 28  # 40 characters: above the legacy 30
OP_KECCAK256 = CScriptOp(0xba)
KECCAK256_ABC = bytes.fromhex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

# Valid only once OP_CAT is active.
CAT_SCRIPT = CScript([b"ab", b"cd", OP_CAT, b"abcd", OP_EQUAL])
# Invalid on both sides of the fork.
BAD_CAT_SCRIPT = CScript([b"ab", b"cd", OP_CAT, b"abce", OP_EQUAL])
# Pushes 0x05 with a data push instead of OP_5: only MINIMALDATA (policy) refuses it.
NON_MINIMAL_SCRIPT = bytes([0x01, 0x05, 0x75, 0x51])
# AuthScript v1 (authType 0x00): the witness must carry "abc".
KECCAK_SCRIPT = bytes(CScript([OP_KECCAK256, KECCAK256_ABC, OP_EQUAL]))


def tagged_hash(tag, msg):
    t = sha256(tag)
    return sha256(t + t + msg)


def p2sh(script):
    return bytes(CScript([OP_HASH160, hash160(bytes(script)), OP_EQUAL]))


def p2wsh(script):
    return bytes(CScript([OP_0, sha256(bytes(script))]))


def authscript(script):
    return b"\x51\x20" + tagged_hash(b"NeuraiAuthScript", b"\x01\x00" + sha256(script))


class UnifiedForkP2PTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-forkheight=%d" % H]] * 2

    def run_test(self):
        node0, node1 = self.nodes
        self.peer = None
        self.peer_node = None
        self.thread = None
        self.dest_spk = bytes.fromhex(node0.validateaddress(node0.getnewaddress())["scriptPubKey"])

        node0.generate(H - 16)
        coins = self.fund([p2sh(CAT_SCRIPT), p2sh(CAT_SCRIPT), p2wsh(CAT_SCRIPT),
                           p2sh(BAD_CAT_SCRIPT), p2wsh(NON_MINIMAL_SCRIPT)])
        node0.issue(ASSET, 1000)
        node0.generate(1)
        self.sync_all()
        boundary_p2sh = self.spend(coins[0], script_sig=bytes(CScript([bytes(CAT_SCRIPT)])))
        relay_p2sh = self.spend(coins[1], script_sig=bytes(CScript([bytes(CAT_SCRIPT)])))
        boundary_p2wsh = self.spend(coins[2], witness=[bytes(CAT_SCRIPT)])
        bad_p2sh = self.spend(coins[3], script_sig=bytes(CScript([bytes(BAD_CAT_SCRIPT)])))
        non_minimal = self.spend(coins[4], witness=[NON_MINIMAL_SCRIPT])

        self.log.info("Far before H: a spend that needs OP_CAT bans its peer")
        assert node1.getblockcount() + 1 < H - K
        self.assert_refused(node1, boundary_p2sh, "16: mandatory-script-verify-flag-failed")
        self.send_and_expect_ban(node1, boundary_p2sh)

        node0.generate(H - 2 - node0.getblockcount())
        self.sync_all()
        assert_equal(node1.getblockcount(), H - 2)
        late_signal = self.rbf_signal_tx()

        self.log.info("The fork moment: node0 has block H-1, node1 does not yet")
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        wait_until(lambda: not node0.getpeerinfo() and not node1.getpeerinfo(), timeout=30,
                   err_msg="node0 and node1 did not disconnect")
        block_h1 = node0.generate(1)[0]
        for tx in (boundary_p2sh, boundary_p2wsh):
            node0.sendrawtransaction(tx.serialize_with_witness().hex())
        keccak_txid, keccak_n = self.fund([authscript(KECCAK_SCRIPT)])[0]
        asset_txids = [node0.issue(DEPIN_NAME, 10)[0], node0.issue(LONG_NAME, 1)[0],
                       node0.transfer(ASSET, 10, node0.getnewaddress())[0]]
        # In creation order: a later one may spend the change of an earlier one.
        fork_txs = [boundary_p2sh, boundary_p2wsh] + [from_hex(CTransaction(), node0.getrawtransaction(txid))
                                                      for txid in [keccak_txid] + asset_txids]
        for tx in fork_txs:
            tx.rehash()

        self.log.info("node1 refuses what node0 accepts for block H, without banning the peer that sends it")
        self.send_and_expect_no_ban(node1, fork_txs)
        assert_equal(node1.getrawmempool(), [])
        self.assert_refused(node1, boundary_p2sh, "16: mandatory-script-verify-flag-failed (Attempted to use a disabled opcode)")
        self.assert_refused(node1, boundary_p2wsh, "16: mandatory-script-verify-flag-failed (Attempted to use a disabled opcode)")
        for tx in fork_txs[2:]:
            result = node1.testmempoolaccept([tx.serialize_with_witness().hex()])[0]
            assert not result["allowed"], result
            self.log.info("  node1 refuses %s: %s", tx.hash[:16], result["reject-reason"])

        self.log.info("The other way round: node0 refuses node1's last pre-fork transaction without a ban")
        assert_equal(node1.testmempoolaccept([late_signal.serialize().hex()])[0]["allowed"], True)
        self.assert_refused(node0, late_signal, "16: bad-txns-rbf-sequence")
        self.send_and_expect_no_ban(node0, [late_signal])

        self.log.info("Once block H-1 arrives, node1 accepts all of them")
        assert_equal(node1.submitblock(node0.getblock(block_h1, False)), None)
        self.send_and_expect_no_ban(node1, fork_txs)
        assert_equal(set(node1.getrawmempool()), {tx.hash for tx in fork_txs})

        self.log.info("node0 relays a new spend to node1 while node1 is still before H")
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        node1.invalidateblock(block_h1)
        assert_equal(node1.getblockcount(), H - 2)
        relay_txid = node0.sendrawtransaction(relay_p2sh.serialize_with_witness().hex())
        log1 = os.path.join(node1.datadir, "regtest", "debug.log")
        wait_until(lambda: self.log_has(log1, "%s from peer=" % relay_txid), timeout=60,
                   err_msg="node1 never received the relayed spend")
        assert relay_txid not in node1.getrawmempool()
        self.assert_nodes_not_punished()
        node1.reconsiderblock(block_h1)
        assert_equal(node1.getbestblockhash(), block_h1)

        self.log.info("Block H confirms them on both nodes")
        block_h = node0.generate(1)[0]
        sync_blocks(self.nodes)
        for txid in [tx.hash for tx in fork_txs] + [relay_txid]:
            assert txid in node1.getblock(block_h)["tx"]

        keccak_valid = self.spend((keccak_txid, keccak_n), witness=[b"\x00", b"abc", KECCAK_SCRIPT])
        keccak_invalid = self.spend((keccak_txid, keccak_n), witness=[b"\x00", b"abd", KECCAK_SCRIPT])
        self.log.info("Inside the window after H an invalid AuthScript spend is refused without a ban")
        self.assert_refused(node1, keccak_invalid, "16: mandatory-script-verify-flag-failed")
        self.send_and_expect_no_ban(node1, [keccak_invalid])

        node0.generate(K - 1)
        sync_blocks(self.nodes)
        assert_equal(node1.getblockcount() + 1, H + K)

        self.log.info("Outside the window: a policy-only failure is not punished")
        self.assert_refused(node1, non_minimal, "64: non-mandatory-script-verify-flag (Data push larger than necessary)")
        self.send_and_expect_no_ban(node1, [non_minimal])

        self.log.info("Outside the window: an invalid AuthScript spend bans its peer")
        self.assert_refused(node1, keccak_invalid, "16: mandatory-script-verify-flag-failed")
        self.send_and_expect_ban(node1, keccak_invalid)

        self.log.info("Outside the window: an invalid P2SH spend bans its peer")
        self.assert_refused(node1, bad_p2sh, "16: mandatory-script-verify-flag-failed")
        self.send_and_expect_ban(node1, bad_p2sh)

        self.log.info("The valid AuthScript spend relays and confirms; node0 and node1 never banned each other")
        self.send_and_expect_no_ban(node1, [keccak_valid])
        sync_mempools(self.nodes)
        assert_equal(node0.getrawmempool(), [keccak_valid.hash])
        node1.generate(1)
        sync_blocks(self.nodes)
        self.assert_nodes_not_punished()
        self.close_peer()

    # ---------------------------------------------------------------- helpers

    def fund(self, spks):
        """Pays FUND to each script from node0's wallet; returns the outpoints."""
        node0 = self.nodes[0]
        tx = CTransaction()
        tx.nVersion = 2
        tx.vout = [CTxOut(FUND, spk) for spk in spks]
        funded = node0.fundrawtransaction(tx.serialize_without_witness().hex())["hex"]
        signed = node0.signrawtransaction(funded)
        assert signed["complete"]
        txid = node0.sendrawtransaction(signed["hex"])
        free = {}
        for out in node0.decoderawtransaction(signed["hex"])["vout"]:
            free.setdefault(out["scriptPubKey"]["hex"], []).append(out["n"])
        return [(txid, free[spk.hex()].pop(0)) for spk in spks]

    def spend(self, outpoint, script_sig=b"", witness=None):
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(outpoint[0], 16), outpoint[1]), script_sig, SEQUENCE)]
        tx.vout = [CTxOut(FUND - FEE, self.dest_spk)]
        if witness:
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = witness
        tx.rehash()
        return tx

    def rbf_signal_tx(self):
        """A wallet payment that signals BIP 125: valid only before H. Not broadcast."""
        node0 = self.nodes[0]
        coin = node0.listunspent()[0]
        node0.lockunspent(False, [{"txid": coin["txid"], "vout": coin["vout"]}])
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]), b"", RBF_SEQUENCE)]
        tx.vout = [CTxOut(int(coin["amount"] * COIN) - FEE, self.dest_spk)]
        signed = node0.signrawtransaction(tx.serialize().hex())
        assert signed["complete"]
        tx = from_hex(CTransaction(), signed["hex"])
        tx.rehash()
        return tx

    def assert_refused(self, node, tx, reason):
        result = node.testmempoolaccept([tx.serialize_with_witness().hex()])[0]
        assert not result["allowed"], result
        assert result["reject-reason"].startswith(reason), result

    def log_has(self, path, text):
        with open(path, encoding="utf8") as f:
            return text in f.read()

    def connect_peer(self, node):
        """One test peer at a time: its network thread ends when it disconnects."""
        self.close_peer()
        index = self.nodes.index(node)
        self.peer = NodeConnCB()
        self.peer.add_connection(NodeConn("127.0.0.1", p2p_port(index), node, self.peer,
                                          services=NODE_NETWORK | NODE_WITNESS))
        self.peer_node = node
        self.thread = NetworkThread()
        self.thread.start()
        self.peer.wait_for_verack()

    def close_peer(self):
        if self.peer and self.peer.connected:
            self.peer.connection.disconnect_node()
            self.peer.wait_for_disconnect()
        if self.thread:
            self.thread.join(timeout=30)
        self.peer = None
        self.peer_node = None
        self.thread = None

    def assert_nodes_not_punished(self):
        """node0 and node1 are still connected (both directions) with no ban score."""
        for node in self.nodes:
            links = [p for p in node.getpeerinfo() if p["subver"] != MY_SUBVERSION.decode()]
            assert_equal(len(links), 2)
            for link in links:
                assert_equal(link["banscore"], 0)

    def peer_banscore(self, node):
        peers = [p for p in node.getpeerinfo() if p["subver"] == MY_SUBVERSION.decode()]
        assert_equal(len(peers), 1)
        return peers[0]["banscore"]

    def send_and_expect_no_ban(self, node, txs):
        if not (self.peer and self.peer.connected and self.peer_node is node):
            self.connect_peer(node)
        for tx in txs:
            self.peer.send_message(MsgWitnessTx(tx))
        self.peer.sync_with_ping()
        assert_equal(self.peer_banscore(node), 0)

    def send_and_expect_ban(self, node, tx):
        if not (self.peer and self.peer.connected and self.peer_node is node):
            self.connect_peer(node)
        self.peer.send_message(MsgWitnessTx(tx))
        self.peer.wait_for_disconnect()
        self.close_peer()


if __name__ == '__main__':
    UnifiedForkP2PTest().main()
