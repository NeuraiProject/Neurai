#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the NIP-047 silent payment index (-silentpaymentindex).

- node0: wallet that sends silent payments, index, REST.
- node1: index with every other index disabled and no wallet.
- node2: receiving wallet without index; later switched on and off.
- node3: index fed block by block while crashing in the middle of chainstate
  flushes (-dbcrashratio), so restarts go through ReplayBlocks.

Checks the records against getblock verbosity 3 (candidates, all native v3
outputs, all native v3 spends), against the receiving wallet, between nodes
and interfaces (RPC json/hex, REST json/bin/hex), the range contract with
anchors and reorganisations, and the option transitions.
"""

import http.client
import json
import subprocess
import urllib.parse

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
)

COIN = 100000000
INDEX = ["-silentpaymentindex"]
WALLET = ["-addresstype=ecdsa", "-bip44=1", "-fallbackfee=0.01"]
NO_OTHER_INDEXES = ["-txindex=0", "-addressindex=0", "-spentindex=0", "-timestampindex=0", "-pubkeyindex=0"]
CRASHY = INDEX + ["-dbcrashratio=6", "-dbbatchsize=1", "-dbcache=4", "-disablewallet"]


def is_v3(script_hex):
    return len(script_hex) == 68 and script_hex.startswith("5320")


def expected_record(block):
    """Index record of a getblock verbosity 3 result, from the NIP-047 rules."""
    entries, spent = [], []
    for tx in block["tx"][1:]:
        prevouts = [vin["prevout"]["scriptPubKey"]["hex"] for vin in tx["vin"]]
        for vin, script in zip(tx["vin"], prevouts):
            if is_v3(script):
                spent.append({"txid": vin["txid"], "vout": vin["vout"]})
        outputs = [{"vout": out["n"], "commitment": out["scriptPubKey"]["hex"][4:], "value_sat": str(int(out["value"] * COIN))}
                   for out in tx["vout"] if is_v3(out["scriptPubKey"]["hex"])]
        # Consensus already checked that each key opens its prevout, so the
        # witness shape and a native v3 prevout identify an eligible input.
        eligible = tx["version"] == 2 and len(tx["vin"]) > 0 and all(
            len(vin.get("txinwitness", [])) == 4 and vin["txinwitness"][0] == "02" and vin["txinwitness"][3] == "51"
            and len(vin["txinwitness"][2]) == 66 and is_v3(script)
            for vin, script in zip(tx["vin"], prevouts))
        if eligible and outputs:
            entries.append({"txid": tx["txid"], "outputs": outputs})
    return {"height": block["height"], "hash": block["hash"], "prev": block.get("previousblockhash", "0" * 64),
            "entries": entries, "spent": spent}


def without_tweaks(record):
    return {"height": record["height"], "hash": record["hash"], "prev": record["prev"], "spent": record["spent"],
            "entries": [{"txid": e["txid"], "outputs": e["outputs"]} for e in record["entries"]]}


class SilentPaymentIndexTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [INDEX + WALLET + ["-rest"], INDEX + NO_OTHER_INDEXES + ["-disablewallet"], WALLET, CRASHY]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        # node3 gets its blocks one by one with submitblock.

    def rest(self, path):
        url = urllib.parse.urlparse(self.nodes[0].url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()

    def run_test(self):
        node0, node1, node2 = self.nodes[0], self.nodes[1], self.nodes[2]
        node0.generate(120)
        self.sync_main()

        self.log.info("Silent payments: two codes, several payments per code, spends of payments")
        code2 = node2.getsilentpaymentcode()["code"]
        code0 = node0.getsilentpaymentcode()["code"]
        res = node0.sendsilentpayments([{"code": code2, "amount": 5}, {"code": code2, "amount": 2}, {"code": code0, "amount": 1}])
        node0.generate(1)
        node0.sendsilentpayments([{"code": code2, "amount": 3}])
        self.sync_main()
        node0.generate(1)
        self.sync_main()
        # node2 spends one payment (the wallet spends one payment at a time).
        node2.sendtoaddress(node0.getnewaddress(), 4)
        sync_mempools(self.nodes[:3])
        node0.generate(1)
        self.sync_main()
        tip = node0.getblockcount()

        self.log.info("Index state")
        for node in (node0, node1):
            info = node.getsilentpaymentindexinfo()
            assert info["enabled"] is True and info["complete"] is True and info["pruned"] is False
            assert_equal(info["state"], "ready")
            assert_equal(info["start_height"], 1)
            assert_equal(info["synced_height"], tip)
            assert_equal(info["synced_hash"], node.getbestblockhash())
            assert_equal(info["missing"], [])
            assert_equal(info["formats"], [1])
            assert_equal(len(info["context"]), 70)
        assert node2.getsilentpaymentindexinfo()["enabled"] is False
        assert_raises_rpc_error(-1, "disabled", node2.getsilentpaymenttweaks, node2.getbestblockhash())

        self.log.info("Records match getblock verbosity 3 and are identical on both nodes")
        records = {}
        found_entries = 0
        for height in range(1, tip + 1):
            blockhash = node0.getblockhash(height)
            r0 = node0.getsilentpaymenttweaks(blockhash)
            r1 = node1.getsilentpaymenttweaks(blockhash)
            assert_equal(r0, r1)
            assert r0["in_active_chain"] is True
            assert_equal(r0["format"], 1)
            block = r0["block"]
            assert_equal(without_tweaks(block), expected_record(node0.getblock(blockhash, 3)))
            for entry in block["entries"]:
                assert_equal(len(entry["tweak"]), 66)
                assert entry["tweak"][:2] in ("02", "03")
                for output in entry["outputs"]:
                    assert isinstance(output["value_sat"], str)
            assert_equal(node0.getsilentpaymenttweaks(blockhash, "hex"), node1.getsilentpaymenttweaks(blockhash, "hex"))
            records[height] = block
            found_entries += len(block["entries"])
        assert found_entries >= 3

        self.log.info("Every payment found by the receiving wallet is an index entry")
        payments = node2.listsilentpayments(True)
        assert len(payments) >= 3
        txids = {}
        for height, block in records.items():
            for entry in block["entries"]:
                txids[entry["txid"]] = (height, [o["vout"] for o in entry["outputs"]])
        for p in payments:
            assert p["txid"] in txids, p
            assert p["vout"] in txids[p["txid"]][1]
        sent = [p for p in payments if p["txid"] == res["txid"]]
        assert_equal(sorted(p["k"] for p in sent), [0, 1])
        # The spent payment is listed as a spend in its block.
        spent_payments = [p for p in payments if p["status"] == "spent"]
        assert spent_payments
        all_spent = {(s["txid"], s["vout"]) for b in records.values() for s in b["spent"]}
        for p in spent_payments:
            assert (p["txid"], p["vout"]) in all_spent

        self.log.info("Ranges")
        assert_raises_rpc_error(-8, "start_height must be between", node0.getsilentpaymenttweaksrange, 0, 10)
        assert_raises_rpc_error(-8, "start_height must be between", node0.getsilentpaymenttweaksrange, tip + 2, 10)
        assert_raises_rpc_error(-8, "count must be at least 1", node0.getsilentpaymenttweaksrange, 1, 0)
        r = node0.getsilentpaymenttweaksrange(1, 50)
        assert_equal(len(r["blocks"]), 50)
        assert_equal(r["next_height"], 51)
        assert_equal(r["status"], "more")
        assert_equal(r["snapshot"], {"height": tip, "hash": node0.getbestblockhash()})
        assert_equal(r["blocks"], [records[h] for h in range(1, 51)])
        r = node0.getsilentpaymenttweaksrange(51, 1000, node0.getblockhash(50))
        assert_equal(r["blocks"], [records[h] for h in range(51, tip + 1)])
        assert_equal(r["next_height"], tip + 1)
        assert_equal(r["status"], "tip")
        r = node0.getsilentpaymenttweaksrange(tip + 1, 10, node0.getbestblockhash())
        assert_equal((r["blocks"], r["status"], r["next_height"]), ([], "tip", tip + 1))
        assert_raises_rpc_error(-8, "start_height - 1", node0.getsilentpaymenttweaksrange, 10, 5, node0.getblockhash(5))
        assert_raises_rpc_error(-5, "anchor_hash not found", node0.getsilentpaymenttweaksrange, 10, 5, "11" * 32)
        assert_equal(node0.getsilentpaymenttweaksrange(1, 200, "", "hex"), node1.getsilentpaymenttweaksrange(1, 200, "", "hex"))

        self.log.info("REST")
        status, headers, body = self.rest("/rest/spindexinfo.json")
        assert_equal(status, 200)
        assert_equal(json.loads(body), node0.getsilentpaymentindexinfo())
        blockhash = node0.getblockhash(122)
        status, headers, body = self.rest("/rest/sptweaks/v1/%s.json" % blockhash)
        assert_equal(status, 200)
        assert "immutable" in headers["Cache-Control"]
        rpc = node0.getsilentpaymenttweaks(blockhash)
        del rpc["in_active_chain"]
        assert_equal(json.loads(body), rpc)
        status, _, body = self.rest("/rest/sptweaks/v1/%s.bin" % blockhash)
        assert_equal(status, 200)
        assert_equal(body.hex(), node0.getsilentpaymenttweaks(blockhash, "hex"))
        assert_equal(body[:4], b"NSPT")
        assert_equal(body[4:6], bytes([1, 1]))
        assert_equal(body[6:41].hex(), node0.getsilentpaymentindexinfo()["context"])
        status, _, body = self.rest("/rest/sptweaks/v1/%s.hex" % blockhash)
        assert_equal(body.decode().strip(), node0.getsilentpaymenttweaks(blockhash, "hex"))
        status, headers, body = self.rest("/rest/sptweaksrange/v1/100/30.json?anchor=%s" % node0.getblockhash(99))
        assert_equal(status, 200)
        assert_equal(json.loads(body), node0.getsilentpaymenttweaksrange(100, 30, node0.getblockhash(99)))
        assert "immutable" not in headers["Cache-Control"]
        status, _, body = self.rest("/rest/sptweaksrange/v1/1/200.bin")
        assert_equal(body.hex(), node0.getsilentpaymenttweaksrange(1, 200, "", "hex"))
        assert_equal(self.rest("/rest/sptweaks/v1/%s.json" % ("00" * 32))[0], 404)
        assert_equal(self.rest("/rest/sptweaksrange/v1/0/5.json")[0], 400)
        assert_equal(self.rest("/rest/sptweaksrange/v1/x/5.json")[0], 400)

        self.log.info("Reorganisation: anchors on the abandoned branch, records kept by hash")
        old_tip = node0.getbestblockhash()
        old_record = node0.getsilentpaymenttweaks(old_tip)
        for node in (node0, node1, node2):
            node.invalidateblock(old_tip)
        node0.generate(2)
        self.sync_main()
        r = node0.getsilentpaymenttweaksrange(tip + 1, 10, old_tip)
        assert r["reorg"] is True
        assert_equal(r["fork_height"], tip - 1)
        status, _, body = self.rest("/rest/sptweaksrange/v1/%d/10.json?anchor=%s" % (tip + 1, old_tip))
        assert_equal(status, 409)
        assert_equal(json.loads(body)["fork_height"], tip - 1)
        stale = node0.getsilentpaymenttweaks(old_tip)
        assert stale["in_active_chain"] is False
        assert_equal(stale["block"], old_record["block"])
        # The transactions of the abandoned block are indexed again in the new one.
        new_tip_height = node0.getblockcount()
        new_txids = {e["txid"] for h in (tip, tip + 1)
                     for e in node0.getsilentpaymenttweaks(node0.getblockhash(h))["block"]["entries"]}
        assert {e["txid"] for e in old_record["block"]["entries"]} <= new_txids
        r = node0.getsilentpaymenttweaksrange(tip - 1, 10, node0.getblockhash(tip - 2))
        assert_equal(r["next_height"], new_tip_height + 1)
        for node in (node0, node1):
            assert_equal(node.getsilentpaymentindexinfo()["synced_height"], new_tip_height)
        assert_equal(node0.getsilentpaymenttweaksrange(1, 1000, "", "hex"), node1.getsilentpaymenttweaksrange(1, 1000, "", "hex"))

        self.log.info("Turning the index on in a synced node fills it from block and undo data")
        expected_hex = node0.getsilentpaymenttweaksrange(1, 1000, "", "hex")
        self.restart_node(2, WALLET + INDEX)
        connect_nodes_bi(self.nodes, 0, 2)
        info = node2.getsilentpaymentindexinfo()
        assert info["complete"] is True
        assert_equal((info["state"], info["synced_height"]), ("ready", new_tip_height))
        assert_equal(node2.getsilentpaymenttweaksrange(1, 1000, "", "hex"), expected_hex)
        self.restart_node(2, WALLET)
        assert node2.getsilentpaymentindexinfo()["enabled"] is False
        self.restart_node(2, WALLET + INDEX)
        assert_equal(node2.getsilentpaymenttweaksrange(1, 1000, "", "hex"), expected_hex)
        connect_nodes_bi(self.nodes, 0, 2)

        self.log.info("Crashes in the middle of chainstate flushes leave a complete index")
        self.crash_test(new_tip_height, expected_hex)

    def sync_main(self):
        sync_blocks(self.nodes[:3])

    def restart_crashy_node(self):
        """Starts node3 after a simulated crash; the replay at startup
        flushes too and may crash again. Returns the number of crashes."""
        node3 = self.nodes[3]
        for crashes in range(1, 100):
            node3.running = False
            node3.process = None
            try:
                self.start_node(3, CRASHY)
                return crashes
            except AssertionError as e:
                if "exited with status 0 during initialization" not in str(e):
                    raise
        raise AssertionError("node3 kept crashing at startup")

    def crash_test(self, tip, expected_hex):
        node0, node3 = self.nodes[0], self.nodes[3]
        crashes = 0
        height = node3.getblockcount() + 1
        while height <= tip:
            try:
                node3.submitblock(node0.getblock(node0.getblockhash(height), 0))
                node3.gettxoutsetinfo()  # flushes the chainstate
                height += 1
            except Exception:
                # A simulated crash ends the process; anything else is a failure.
                try:
                    node3.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    raise AssertionError("node3 failed without crashing")
                crashes += self.restart_crashy_node()
                height = node3.getblockcount() + 1
        self.stop_node(3)
        self.start_node(3, INDEX + ["-disablewallet"])
        info = node3.getsilentpaymentindexinfo()
        assert info["complete"] is True
        assert_equal(info["synced_height"], tip)
        assert_equal(node3.getsilentpaymenttweaksrange(1, 1000, "", "hex"), expected_hex)
        with open(node3.datadir + "/regtest/debug.log", encoding="utf-8") as f:
            log = f.read()
        replays = log.count("Replaying blocks")
        self.log.info("node3 crashed %d times, %d replays", crashes, replays)
        assert crashes > 0 and replays > 0
        # The records of the blocks rolled forward were on disk before each
        # interrupted flush: no restart had to rebuild or rewrite any.
        # Some crashes happen while replaying, before the index is checked.
        checks = [line for line in log.splitlines() if "blocks verified" in line]
        assert len(checks) > 1
        for line in checks:
            assert ", 0 rebuilt, 0 rewritten," in line, line


if __name__ == '__main__':
    SilentPaymentIndexTest().main()
