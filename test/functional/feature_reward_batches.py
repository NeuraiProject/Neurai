#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test reward plan proofs, batches and their verification (NIP-048 B3-B4).

The node computes a plan; the operator builds each batch with
createdistributionbatch (signed, inputs locked, not broadcast), records it,
broadcasts it, and follows it with verifydistribution:
- every recipient has an inclusion proof that checks against the plan;
- batches split the payments in plan order;
- a batch moves from unknown to pending, confirming and confirmed;
- a new version that spends the same anchor replaces an unsent one;
- a version whose anchor is spent elsewhere is conflicting with -txindex, and
  a node without -txindex says it cannot tell;
- a changed plan cannot be paid with the approved plan hash;
- a second node that captured the same snapshot computes the same plan;
- a snapshot height announced in advance on the owner token makes the plan
  independently verifiable, and replaysnapshot rebuilds a snapshot from the
  blocks (B5).
"""

from decimal import Decimal

from test_framework.nip048 import announcement_hash, verify_plan, verify_proof
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

BATCH = {"max_outputs": 3}


class RewardBatchesTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-assetindex', '-txindex'], ['-assetindex']]

    def verify(self, node, records, plan=None):
        return node.verifydistribution(plan or self.plan, records, BATCH)

    @staticmethod
    def states(result):
        return [batch["state"] for batch in result["batches"]]

    def setup_snapshot(self):
        n0, n1 = self.nodes
        n0.generate(150)
        self.sync_all()

        self.owner = n0.getnewaddress()
        n0.issue(asset_name="SHARES", qty=500, to_address=self.owner, change_address="", units=0, reissuable=True, has_ipfs=False)
        n0.issue(asset_name="DIVIDEND", qty=1000, to_address=self.owner, change_address="", units=2, reissuable=True, has_ipfs=False)
        n0.generate(1)
        # One holder belongs to the paying wallet
        for address in [n1.getnewaddress() for _ in range(3)] + [n0.getnewaddress()]:
            n0.transfer(asset_name="SHARES", qty=100, to_address=address, message="", expire_time=0,
                        change_address="", asset_change_address=self.owner)
        n0.generate(1)
        self.sync_all()

        # Both nodes capture the snapshot independently
        self.height = n0.getblockcount() + 1
        n0.requestsnapshot(asset_name="SHARES", block_height=self.height)
        n1.requestsnapshot(asset_name="SHARES", block_height=self.height)
        n0.generate(61)
        self.sync_all()

    def test_plan_and_proofs(self):
        n0, n1 = self.nodes
        self.log.info("The plan, and a proof per recipient")
        self.plan = {"asset_name": "SHARES", "snapshot_height": self.height, "distribution_asset_name": "DIVIDEND",
                     "amount": 100, "exception_addresses": self.owner}
        self.full_plan = n0.getdistributionplan("SHARES", self.height, "DIVIDEND", 100, self.owner)
        verify_plan(n0, self.full_plan)
        self.plan_hash = self.full_plan["plan_hash"]
        assert_equal(len(self.full_plan["recipients"]), 4)
        assert_equal(n1.getdistributionplan("SHARES", self.height, "DIVIDEND", 100, self.owner)["plan_hash"], self.plan_hash)

        for recipient in self.full_plan["recipients"]:
            verify_proof(n0.getdistributionproof(self.plan, recipient["address"]), self.full_plan)
        assert_raises_rpc_error(-8, "not a recipient", n0.getdistributionproof, self.plan, self.owner)

    def test_batches(self):
        n0 = self.nodes[0]
        self.log.info("Batches split the payments in plan order")
        batches = n0.getdistributionbatches(self.plan, BATCH)
        assert_equal(batches["plan_hash"], self.plan_hash)
        assert_equal([b["recipient_count"] for b in batches["batches"]], [3, 1])
        assert batches["batches"][0]["batch_id"] != batches["batches"][1]["batch_id"]
        outputs = {}
        for batch in batches["batches"]:
            for address, output in batch["outputs"].items():
                outputs[address] = output["transfer"]["DIVIDEND"]
        assert_equal(outputs, {r["address"]: r["amount"] for r in self.full_plan["recipients"]})

        result = self.verify(n0, [])
        assert_equal(self.states(result), ["unknown", "unknown"])
        assert_equal((result["unpaid"], result["complete"]), (100, False))

    def test_versions(self):
        n0 = self.nodes[0]
        self.log.info("Only the approved plan can be paid")
        assert_raises_rpc_error(-8, "plan_hash does not match", n0.createdistributionbatch,
                                "00" * 32, self.plan, 0, BATCH)
        assert_raises_rpc_error(-8, "plan_hash does not match", n0.createdistributionbatch,
                                self.plan_hash, dict(self.plan, remainder="largest"), 0, BATCH)

        self.log.info("A batch is built and signed but not broadcast; its inputs are locked")
        v0 = n0.createdistributionbatch(self.plan_hash, self.plan, 0, BATCH)
        assert v0["txid"] not in n0.getrawmempool()
        locked = n0.listlockunspent()
        for outpoint in v0["inputs"]:
            assert outpoint in locked
        result = self.verify(n0, [{"index": 0, "versions": [v0["hex"]]}])
        assert_equal(self.states(result), ["pending", "unknown"])
        assert_equal(result["reserved"], 75)

        self.log.info("A new version with the same anchor replaces the unsent one")
        n0.lockunspent(True, v0["inputs"])
        v0b = n0.createdistributionbatch(self.plan_hash, self.plan, 0, dict(BATCH, anchor=v0["anchor"]))
        assert v0["anchor"] in v0b["inputs"]
        assert v0b["txid"] != v0["txid"]
        n0.sendrawtransaction(v0b["hex"])
        self.record0 = {"index": 0, "versions": [v0["hex"], v0b["hex"]]}
        batch = self.verify(n0, [self.record0])["batches"][0]
        assert_equal((batch["state"], batch["txid"], batch["issues"]), ("pending", v0b["txid"], []))

        n0.generate(1)
        self.sync_all()
        batch = self.verify(n0, [self.record0])["batches"][0]
        assert_equal((batch["state"], batch["confirmations"]), ("confirming", 1))
        n0.generate(5)
        self.sync_all()
        result = self.verify(n0, [self.record0])
        assert_equal(self.states(result), ["confirmed", "unknown"])
        assert_equal(result["paid"], 75)
        self.v0b = v0b

    def test_conflict_and_rebuild(self):
        n0, n1 = self.nodes
        self.log.info("A version whose anchor is spent elsewhere is conflicting")
        v1 = n0.createdistributionbatch(self.plan_hash, self.plan, 1, BATCH)
        anchor = v1["anchor"]
        n0.lockunspent(True, [anchor])
        value = n0.gettxout(anchor["txid"], anchor["vout"])["value"]
        spend = n0.createrawtransaction([anchor], {n0.getnewaddress(): value - Decimal("0.01")})
        n0.sendrawtransaction(n0.signrawtransaction(spend)["hex"])
        n0.generate(6)
        self.sync_all()
        record1 = {"index": 1, "versions": [v1["hex"]]}
        assert_equal(self.states(self.verify(n0, [self.record0, record1])), ["confirmed", "conflicting"])

        self.log.info("Without -txindex a node says it cannot tell")
        result = self.verify(n1, [self.record0, record1])
        assert_equal(self.states(result), ["confirmed", "unknown"])
        assert "enable -txindex" in result["batches"][1]["issues"][0]

        self.log.info("The batch is rebuilt with a new anchor and paid")
        n0.lockunspent(True, [outpoint for outpoint in v1["inputs"] if outpoint != anchor])
        v1b = n0.createdistributionbatch(self.plan_hash, self.plan, 1, BATCH)
        assert v1b["anchor"] != anchor
        n0.sendrawtransaction(v1b["hex"])
        n0.generate(6)
        self.sync_all()
        record1["versions"].append(v1b["hex"])
        result = self.verify(n0, [self.record0, record1])
        assert_equal(self.states(result), ["confirmed", "confirmed"])
        assert_equal((result["complete"], result["paid"], result["unpaid"]), (True, 100, 0))
        assert_equal(result["batches"][1]["issues"], [])
        # The payer's own holder address was paid too, but what the payer pays
        # itself is its own coin again: a later batch may spend it.
        for recipient in self.full_plan["recipients"]:
            if not n0.validateaddress(recipient["address"])["ismine"]:
                assert_equal(n0.listassetbalancesbyaddress(recipient["address"])["DIVIDEND"], recipient["amount"])

        self.log.info("A transaction that does not pay the batch is reported")
        batch = self.verify(n0, [{"index": 1, "versions": [self.v0b["hex"]]}])["batches"][1]
        assert_equal(batch["state"], "unknown")
        assert "does not pay this batch" in batch["issues"][0]

    def test_xna_batch(self):
        n0, n1 = self.nodes
        self.log.info("An XNA plan is paid the same way")
        plan = {"asset_name": "SHARES", "snapshot_height": self.height, "distribution_asset_name": "XNA",
                "amount": 10, "exception_addresses": self.owner}
        full = n0.getdistributionplan("SHARES", self.height, "XNA", 10, self.owner)
        verify_plan(n0, full)
        assert_raises_rpc_error(-4, "above max_fee", n0.createdistributionbatch,
                                full["plan_hash"], plan, 0, {"max_outputs": 10, "max_fee": Decimal("0.00000001")})

        batch = n0.createdistributionbatch(full["plan_hash"], plan, 0, {"max_outputs": 10, "max_fee": 1})
        n0.sendrawtransaction(batch["hex"])
        n0.generate(6)
        self.sync_all()
        result = n0.verifydistribution(plan, [{"index": 0, "versions": [batch["hex"]]}], {"max_outputs": 10})
        assert_equal((result["complete"], result["paid"]), (True, 10))
        n1_addresses = {a["address"] for a in n1.listreceivedbyaddress(0, True)}
        for recipient in full["recipients"]:
            if recipient["address"] in n1_addresses:
                assert_equal(n1.getreceivedbyaddress(recipient["address"]), recipient["amount"])

    def test_announcement_and_replay(self):
        n0, n1 = self.nodes
        self.log.info("A snapshot height announced on the owner token (NIP-048 B5)")
        owner_token_address = list(n0.listaddressesbyasset("SHARES!").keys())[0]
        height = n0.getblockcount() + 62
        announcement = n0.getsnapshotannouncement("SHARES", height)
        assert_equal(announcement["owner_token"], "SHARES!")
        assert_equal(announcement["message"], announcement_hash(n0.getblockchaininfo()["chain"], "SHARES", height).hex())
        assert_equal(announcement["notice_if_mined_next"], 61)
        txid = n0.transfer(asset_name="SHARES!", qty=1, to_address=owner_token_address, message=announcement["message"])[0]
        n0.requestsnapshot(asset_name="SHARES", block_height=height)
        n1.requestsnapshot(asset_name="SHARES", block_height=height)
        n0.generate(height - n0.getblockcount() + 60)
        self.sync_all()

        options = {"announcement": {"txid": txid}}
        announced = n0.getdistributionplan("SHARES", height, "DIVIDEND", 100, self.owner, options)
        verify_plan(n0, announced)
        assert_equal((announced["version"], announced["verifiability"]), (2, "announced"))
        assert_equal(announced["announcement"]["notice"], 61)
        unannounced = n0.getdistributionplan("SHARES", height, "DIVIDEND", 100, self.owner)
        assert_equal((unannounced["version"], unannounced["verifiability"], unannounced["announcement"]),
                     (1, "unannounced", None))
        assert announced["plan_hash"] != unannounced["plan_hash"]
        # Without -txindex the announcement is found through its unspent owner token output
        assert_equal(n1.getdistributionplan("SHARES", height, "DIVIDEND", 100, self.owner, options)["plan_hash"],
                     announced["plan_hash"])
        assert_raises_rpc_error(-8, "does not carry the expected message", n0.getdistributionplan,
                                "SHARES", self.height, "DIVIDEND", 100, self.owner, options)

        self.log.info("An announcement made too late is flagged")
        late_height = n0.getblockcount() + 11
        message = n0.getsnapshotannouncement("SHARES", late_height)["message"]
        late_txid = n0.transfer(asset_name="SHARES!", qty=1, to_address=owner_token_address, message=message)[0]
        n0.requestsnapshot(asset_name="SHARES", block_height=late_height)
        n0.generate(late_height - n0.getblockcount() + 60)
        self.sync_all()
        late = n0.getdistributionplan("SHARES", late_height, "DIVIDEND", 100, self.owner,
                                      {"announcement": {"txid": late_txid}})
        verify_plan(n0, late)
        assert_equal((late["verifiability"], late["announcement"]["notice"]), ("late_announcement", 10))

        self.log.info("replaysnapshot rebuilds a snapshot from the blocks alone")
        expected = announced["snapshot"]["snapshot_hash"]
        for node in (n0, n1):
            replay = node.replaysnapshot("SHARES", height, expected)
            assert_equal((replay["snapshot_hash"], replay["matches_stored"], replay["matches_expected"], replay["holders"]),
                         (expected, True, True, 5))
        assert_equal(n0.replaysnapshot("SHARES", self.height)["matches_stored"], True)
        assert_equal(n0.replaysnapshot("SHARES", height - 5)["matches_stored"], None)
        assert_equal(n0.replaysnapshot("SHARES", height, "00" * 32)["matches_expected"], False)

    def run_test(self):
        self.setup_snapshot()
        self.test_plan_and_proofs()
        self.test_batches()
        self.test_versions()
        self.test_conflict_and_rebuild()
        self.test_xna_batch()
        self.test_announcement_and_replay()


if __name__ == '__main__':
    RewardBatchesTest().main()
