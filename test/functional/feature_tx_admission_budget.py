#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Admission CPU of rejected transactions is bounded per address and in total.

A transaction that is admitted, runs its scripts and is then rejected costs
CPU that no fee pays for. node0 receives, from peers with distinct local
addresses, transactions whose 40 AuthScript inputs run 500 OP_POSEIDON each
and whose last input ends in OP_NOP10: they fail only the policy flags, so the
peer is never penalised for them.

- The same witness transaction sent again is recognised by its wtxid and not
  validated again.
- An address that uses up its credit (3 s of CPU) is ignored for 10 minutes:
  even its valid transactions are not processed nor requested when it
  announces them, it is neither banned nor disconnected, and reconnecting does
  not restore the credit.
- Inbound peers share a bucket of 1 s refilled at 9 s per minute: once it is
  empty, their transactions wait in a queue, while an outbound peer keeps its
  reserved bucket.
- As the bucket refills, the waiting transaction of an address that was never
  charged (a wallet) goes ahead of those that arrived earlier from addresses
  that keep sending rejected ones. The ignored address is still dropped, and
  after 10 minutes it is admitted again.
- Orphans wait, when their parent arrives, in the queue of the peer that sent
  them, run on its budget, and once each even if they spend many outputs of
  the same parent.
- A request queued for a peer (two minutes after another peer was asked for
  the same transaction) is not sent if that peer's address is ignored by then,
  and another peer that announces the transaction is asked at once.

The node's clock is mocked and moved forward where the buckets must refill.
Requests are scheduled on the real clock, so the test waits two minutes.
"""

import hashlib
import os
import re
import time

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.mininode import (CInv, COutPoint, CTxIn, CTxInWitness, MsgInv, MsgWitnessTx, NetworkThread,
                                     NodeConn, NodeConnCB, NODE_NETWORK, NODE_WITNESS)
from test_framework.script import CScript, CTransaction, CTxOut, OP_TRUE
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (assert_equal, bytes_to_hex_str, connect_nodes, p2p_port, sync_blocks,
                                 wait_until)

COIN = 100000000
INPUTS = 40
ORPHAN_BATCHES = 5
ORPHANS_PER_BATCH = 6
ORPHAN_INPUT = COIN // 200
LIGHT_COINS = 30


def sha256(data):
    return hashlib.sha256(data).digest()


def authscript(script):
    tag = sha256(b'NeuraiAuthScript')
    return CScript(b'\x51\x20' + sha256(tag + tag + b'\x01\x00' + sha256(script)))


HEAVY = bytes([0xc9]) * 500 + bytes([0x75, 0x51])          # 500 permutations
FAIL = bytes([0xc9]) * 500 + bytes([0x75, 0xb9, 0x51])     # ... OP_DROP OP_NOP10 OP_TRUE
LIGHT = bytes([0xc9, 0x75, 0x51])                          # a valid, cheap spend


class Peer(NodeConnCB):
    def __init__(self):
        super().__init__()
        self.requested = set()

    def on_getdata(self, conn, message):
        self.requested.update(inv.hash for inv in message.inv)

    def announce(self, tx):
        self.send_message(MsgInv([CInv(1, int(tx.hash, 16))]))
        self.sync_with_ping()
        return int(tx.hash, 16) in self.requested


class TxAdmissionBudgetTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # node1 whitelists node0 so that it announces transactions at once,
        # without the random delay of trickling.
        self.extra_args = [["-debug=mempoolrej", "-debug=mempool"], ["-whitelist=127.0.0.1"]]

    def setup_network(self):
        self.setup_nodes()
        # node1 is an outbound peer of node0: it keeps the reserved share.
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

    def log_text(self):
        with open(os.path.join(self.nodes[0].datadir, "regtest", "debug.log"), encoding="utf8") as f:
            return f.read()

    def wait_log(self, pattern, timeout=60):
        wait_until(lambda: re.search(pattern, self.log_text()) is not None, err_msg=pattern, timeout=timeout)

    def connect(self, address):
        peer = Peer()
        conn = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], peer, services=NODE_NETWORK | NODE_WITNESS,
                        srcaddr=address)
        peer.add_connection(conn)
        # The network thread ends when it has no connection left: start one
        # whenever none is running.
        if self.network_thread is None or not self.network_thread.is_alive():
            self.network_thread = NetworkThread()
            self.network_thread.start()
        peer.wait_for_verack()
        return peer

    def failing(self):
        """A new transaction that runs ~20,000 permutations and fails a policy flag."""
        self.serial += 1
        tx = CTransaction()
        for n in range(INPUTS):
            tx.vin.append(CTxIn(COutPoint(self.funding.x16r, n), b""))
            tx.wit.vtxinwit.append(CTxInWitness())
            tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00', b'', FAIL if n == INPUTS - 1 else HEAVY]
        tx.vout.append(CTxOut(INPUTS * COIN - COIN // 10 - self.serial, self.pay))
        tx.rehash()
        return tx

    def valid(self):
        """A new valid, standard transaction spending one cheap output."""
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.funding.x16r, self.light.pop()), b""))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x00', b'', LIGHT]
        tx.vout.append(CTxOut(COIN - COIN // 10, self.pay))
        tx.rehash()
        return tx

    def advance(self, seconds):
        self.mocktime += seconds
        self.nodes[0].setmocktime(self.mocktime)

    def exhaust(self, peer, address, step=0):
        """Send failing transactions until the address is ignored, or until
        the inbound bucket is empty and one waits; returns the last one. With
        `step`, the clock moves that many seconds after each one, so the
        inbound bucket refills and the address credit is what runs out."""
        for _ in range(300):
            tx = self.failing()
            peer.send_message(MsgWitnessTx(tx))
            peer.sync_with_ping(timeout=120)
            if "transactions from %s ignored" % address in self.log_text() or self.waits(tx):
                return tx
            self.advance(step)
        raise AssertionError("%s was never stopped" % address)

    def not_processed(self, tx):
        return re.search(r"%s from peer=\d+ not processed: address ignored by the admission budget" % tx.hash,
                         self.log_text()) is not None

    def waits(self, tx):
        return re.search(r"%s from peer=\d+ waits for the admission budget" % tx.hash, self.log_text()) is not None

    def log_position(self, pattern):
        match = re.search(pattern, self.log_text())
        return match.start() if match else None

    def run_test(self):
        node = self.nodes[0]
        self.network_thread = None
        self.serial = 0
        node.generate(1)
        block = self.build_block([])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        coinbase = block.vtx[0]
        node.generate(100)
        self.funding = CTransaction()
        self.funding.vin.append(CTxIn(COutPoint(coinbase.x16r, 0), b""))
        self.funding.vout = ([CTxOut(COIN, authscript(HEAVY)) for _ in range(INPUTS - 1)] +
                             [CTxOut(COIN, authscript(FAIL))] +
                             [CTxOut(COIN, authscript(LIGHT)) for _ in range(LIGHT_COINS)])
        self.funding.vout.append(CTxOut(coinbase.vout[0].nValue - (INPUTS + LIGHT_COINS + 1) * COIN,
                                        CScript([OP_TRUE])))
        self.funding.rehash()
        self.light = list(range(INPUTS, INPUTS + LIGHT_COINS))
        block = self.build_block([self.funding])
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize(with_witness=True))), None)
        sync_blocks(self.nodes)      # node1 mines on top, or its first coinbase is reorganised away
        self.nodes[1].generate(101)  # node1 gets spendable coins
        sync_blocks(self.nodes)
        self.pay = CScript(bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"]))
        self.mocktime = int(time.time())
        node.setmocktime(self.mocktime)

        # Set up the queued request now, check it at the end: a silent peer is
        # asked for a transaction and never answers; a second peer announces
        # it too, and its request is queued two minutes later.
        silent = self.connect("127.0.0.12")
        queued = self.connect("127.0.0.13")
        pending = self.valid()
        assert silent.announce(pending)
        assert not queued.announce(pending)
        queued_at = time.time()

        self.log.info("The same witness transaction is not validated twice")
        a = self.connect("127.0.0.2")
        tx = self.failing()
        a.send_message(MsgWitnessTx(tx))
        self.wait_log(r"%s from peer=\d+ was not accepted" % tx.hash)
        a.send_message(MsgWitnessTx(tx))
        self.wait_log(r"%s \(wtxid [0-9a-f]+\) from peer=\d+ was already rejected" % tx.hash)
        assert_equal(len(re.findall(r"%s from peer=\d+ was not accepted" % tx.hash, self.log_text())), 1)

        self.log.info("An address that uses up its credit is ignored, not banned")
        self.exhaust(a, "127.0.0.2", step=4)
        assert "transactions from 127.0.0.2 ignored" in self.log_text()
        ignored_at = self.mocktime
        self.exhaust(queued, "127.0.0.13", step=4)
        assert "transactions from 127.0.0.13 ignored" in self.log_text()
        assert time.time() < queued_at + 100, "ignored too late: the queued request may already be due"
        self.advance(10)   # the buckets are full: only the address stops it
        ignored = self.valid()
        a.send_message(MsgWitnessTx(ignored))
        a.sync_with_ping()
        assert self.not_processed(ignored)
        assert ignored.hash not in node.getrawmempool()
        assert any(p["addr"].startswith("127.0.0.2:") for p in node.getpeerinfo())
        assert_equal(node.listbanned(), [])
        assert not a.announce(self.valid())

        self.log.info("Reconnecting from the same address does not restore the credit")
        a.connection.handle_close()
        wait_until(lambda: not any(p["addr"].startswith("127.0.0.2:") for p in node.getpeerinfo()),
                   err_msg="disconnect", timeout=30)
        a = self.connect("127.0.0.2")
        again = self.valid()
        a.send_message(MsgWitnessTx(again))
        a.sync_with_ping()
        assert self.not_processed(again)

        self.log.info("Another inbound address is admitted meanwhile")
        self.advance(10)
        honest = self.connect("127.0.0.9")
        tx = self.valid()
        assert honest.announce(tx)
        start = time.time()
        honest.send_message(MsgWitnessTx(tx))
        wait_until(lambda: tx.hash in node.getrawmempool(), err_msg="honest tx", timeout=30)
        self.log.info("  admitted in %.2f s", time.time() - start)

        self.log.info("Inbound peers share one bucket: once empty, their transactions wait; outbound peers keep their own")
        # Each address gets room for at least one failing transaction, so it
        # is charged, and ends with one waiting.
        waiting = []
        for address in ("127.0.0.3", "127.0.0.4", "127.0.0.5"):
            self.advance(7)
            waiting.append(self.exhaust(self.connect(address), address))
        assert all(self.waits(tx) for tx in waiting)
        wallet = self.connect("127.0.0.10")
        deferred = self.valid()
        assert wallet.announce(deferred)   # only ignored addresses are not asked
        wallet.send_message(MsgWitnessTx(deferred))
        wallet.sync_with_ping()
        assert self.waits(deferred)
        assert deferred.hash not in node.getrawmempool()
        # Failing transactions that arrived earlier and still wait.
        earlier = [tx for tx in waiting if self.log_position(r"%s from peer=\d+ was not accepted" % tx.hash) is None]
        assert earlier
        txid = self.nodes[1].sendtoaddress(node.getnewaddress(), 1)
        start = time.time()
        wait_until(lambda: txid in node.getrawmempool(), err_msg="outbound tx", timeout=60)
        self.log.info("  transaction from the outbound peer admitted in %.2f s", time.time() - start)

        self.log.info("Refills admit the waiting transaction of a clean address first; the ignored one is dropped")
        for _ in range(20):
            self.advance(1)
            if deferred.hash in node.getrawmempool():
                break
            wallet.sync_with_ping()
        wait_until(lambda: deferred.hash in node.getrawmempool(), err_msg="waiting wallet tx", timeout=30)
        accepted_at = self.log_position(r"accepted %s" % deferred.hash)
        for tx in earlier:
            rejected_at = self.log_position(r"%s from peer=\d+ was not accepted" % tx.hash)
            assert rejected_at is None or rejected_at > accepted_at, "an earlier failing transaction went first"
        assert self.mocktime < ignored_at + 600
        still = self.valid()
        a.send_message(MsgWitnessTx(still))
        a.sync_with_ping()
        assert self.not_processed(still)

        self.log.info("After 10 minutes the ignored address is admitted again")
        self.advance(ignored_at + 601 - self.mocktime)
        a.send_message(MsgWitnessTx(still))
        wait_until(lambda: still.hash in node.getrawmempool(), err_msg="recovery", timeout=30)
        assert_equal(node.listbanned(), [])

        self.log.info("Orphans run once each, on the budget of the peer that sent them")
        # Each parent pays the orphans of one batch: 6 orphans of 40 inputs,
        # each input spending one of its outputs. The sender of the orphans,
        # not the honest peer that brings each parent, is charged for them.
        parents, batches = [], []
        for _ in range(ORPHAN_BATCHES):
            parent = CTransaction()
            for _ in range(2):
                parent.vin.append(CTxIn(COutPoint(self.funding.x16r, self.light.pop()), b""))
                parent.wit.vtxinwit.append(CTxInWitness())
                parent.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00', b'', LIGHT]
            for _ in range(ORPHANS_PER_BATCH):
                parent.vout += [CTxOut(ORPHAN_INPUT, authscript(HEAVY)) for _ in range(INPUTS - 1)]
                parent.vout.append(CTxOut(ORPHAN_INPUT, authscript(FAIL)))
            parent.rehash()   # 1.2 XNA out of 2
            batch = []
            for k in range(ORPHANS_PER_BATCH):
                tx = CTransaction()
                for n in range(INPUTS):
                    tx.vin.append(CTxIn(COutPoint(parent.x16r, k * INPUTS + n), b""))
                    tx.wit.vtxinwit.append(CTxInWitness())
                    tx.wit.vtxinwit[-1].scriptWitness.stack = [b'\x00', b'', FAIL if n == INPUTS - 1 else HEAVY]
                tx.vout.append(CTxOut(INPUTS * ORPHAN_INPUT - COIN // 10, self.pay))
                tx.rehash()
                batch.append(tx)
            parents.append(parent)
            batches.append(batch)
        self.advance(10)
        sender = self.connect("127.0.0.11")
        for batch in batches:
            for tx in batch:
                sender.send_message(MsgWitnessTx(tx))
        sender.sync_with_ping()
        for parent in parents:
            self.advance(10)
            honest.send_message(MsgWitnessTx(parent))
            # The orphans run after the parent enters the mempool, in the same
            # message: wait until that message is fully processed.
            honest.sync_with_ping(timeout=120)
            assert parent.hash in node.getrawmempool()
        orphans = [tx for batch in batches for tx in batch]

        def counts():
            log = self.log_text()
            processed = [len(re.findall(r"%s from peer=\d+ was not accepted" % tx.hash, log)) for tx in orphans]
            dropped = [len(re.findall(r"%s from peer=\d+ (not processed: address ignored|dropped by the admission budget)"
                                      % tx.hash, log)) for tx in orphans]
            return processed, dropped

        # Waiting orphans of the sender, once it is ignored, are dropped the
        # next time the queue has room.
        self.advance(10)
        wait_until(lambda: sum(map(sum, counts())) == len(orphans), err_msg="orphans settled", timeout=60)
        processed, dropped = counts()
        log = self.log_text()
        self.log.info("  %d orphans ran and were rejected, %d were dropped", sum(processed), sum(dropped))
        assert_equal(max(processed), 1)
        assert sum(processed) > 0
        assert sum(dropped) > 0
        assert "transactions from 127.0.0.11 ignored" in log
        assert "transactions from 127.0.0.9 ignored" not in log
        assert_equal(node.listbanned(), [])

        self.log.info("A request queued before its peer was ignored is not sent; another peer is asked at once")
        # The request was queued two minutes after the silent peer's.
        wait_until(lambda: time.time() > queued_at + 125, err_msg="queued request due", timeout=180)
        queued.sync_with_ping()
        assert int(pending.hash, 16) not in queued.requested
        assert re.search(r"%s not requested from peer=\d+: address ignored by the admission budget" % pending.hash,
                         self.log_text())
        self.advance(10)
        assert honest.announce(pending)
        honest.send_message(MsgWitnessTx(pending))
        wait_until(lambda: pending.hash in node.getrawmempool(), err_msg="pending tx", timeout=30)


if __name__ == '__main__':
    TxAdmissionBudgetTest().main()
