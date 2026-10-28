#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test reward eligibility from holder state (NIP-048 D3) and bulletin recipients (D5).

- A snapshot records, per holder, freezes, DEPIN self-revocations and the
  qualifier tags it had at the snapshot height, and replaysnapshot rebuilds
  them from the blocks.
- Frozen and self-revoked holders are excluded; a qualifier filter keeps only
  tagged holders; report weights replace holdings, and the plan commits to
  the qualifier and the report (format version 3).
- Equal allocation gives every eligible holder the same share, a minimum
  holding excludes smaller holders, and the plan commits to both (format
  version 4).
- getsnapshotrecipients classifies holders for an encrypted bulletin.
"""

from test_framework.nip048 import report_hash, verify_plan, verify_proof
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class RewardEligibilityTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # The third node only provides a post-quantum address
        self.extra_args = [['-assetindex', '-pubkeyindex'], ['-assetindex', '-pubkeyindex'], ['-addresstype=pq']]

    @staticmethod
    def reasons(plan):
        return {e["address"]: e["reason"] for e in plan["excluded"]}

    @staticmethod
    def amounts(plan):
        return {r["address"]: r["amount"] for r in plan["recipients"]}

    def snapshot_at_next_block(self, asset):
        n0, n1 = self.nodes[:2]
        height = n0.getblockcount() + 1
        n0.requestsnapshot(asset_name=asset, block_height=height)
        n1.requestsnapshot(asset_name=asset, block_height=height)
        n0.generate(1)
        self.sync_all()
        return height

    def test_restricted_asset(self):
        n0, n1 = self.nodes[:2]
        self.log.info("A restricted asset: tags and an address freeze at the snapshot height")
        issuer = n0.getnewaddress()
        n0.issue("STOCK", 1000)
        n0.issuequalifierasset("#KYC", 1)
        n0.issuequalifierasset("#VIP", 1)
        n0.generate(1)
        # The verifier applies to the issuance address too
        n0.addtagtoaddress("#KYC", issuer)
        n0.generate(1)
        n0.issuerestrictedasset("$STOCK", 1000, "#KYC", issuer)
        n0.generate(1)
        holders = [n1.getnewaddress() for _ in range(3)] + [n0.getnewaddress()]
        for address in holders:
            n0.addtagtoaddress("#KYC", address)
        for address in holders[:2]:
            n0.addtagtoaddress("#VIP", address)
        n0.generate(1)
        for address in holders:
            n0.transfer(asset_name="$STOCK", qty=100, to_address=address)
        n0.generate(1)
        n0.freezeaddress("$STOCK", holders[1])
        n0.generate(1)
        self.sync_all()

        height = self.snapshot_at_next_block("$STOCK")
        # A tag removed after the snapshot height does not change the snapshot
        n0.removetagfromaddress("#VIP", holders[0])
        n0.generate(61)
        self.sync_all()

        snapshot = n0.getsnapshot("$STOCK", height)
        owners = {o["address"]: o for o in snapshot["owners"]}
        assert_equal((snapshot["format"], snapshot["global_frozen"]), (2, False))
        assert_equal((owners[holders[0]]["tags"], owners[holders[1]]["frozen"]), (["#KYC", "#VIP"], True))
        assert_equal(owners[holders[2]]["tags"], ["#KYC"])

        plan = n0.getdistributionplan("$STOCK", height, "XNA", 12, issuer)
        verify_plan(n0, plan)
        assert_equal(self.amounts(plan), {holders[0]: 4, holders[2]: 4, holders[3]: 4})
        assert_equal(self.reasons(plan), {issuer: "exception", holders[1]: "frozen"})
        assert_equal((plan["version"], plan["qualifier"]), (1, None))

        vip = n0.getdistributionplan("$STOCK", height, "XNA", 12, issuer, {"qualifier": "#VIP"})
        verify_plan(n0, vip)
        assert_equal(self.amounts(vip), {holders[0]: 12})
        assert_equal(self.reasons(vip)[holders[2]], "missing_qualifier")
        assert_equal((vip["version"], vip["qualifier"]), (3, "#VIP"))
        assert vip["plan_hash"] != plan["plan_hash"]
        assert_raises_rpc_error(-8, "qualifier tag", n0.getdistributionplan,
                                "$STOCK", height, "XNA", 12, issuer, {"qualifier": "VIP"})

        self.log.info("replaysnapshot rebuilds tags and freezes from the blocks")
        for node in (n0, n1):
            replay = node.replaysnapshot("$STOCK", height)
            assert_equal((replay["format"], replay["matches_stored"]), (2, True))

    def test_depin_and_report(self):
        n0, n1 = self.nodes[:2]
        self.log.info("A DEPIN token: self-revocation, owner freeze and report weights")
        owner = n0.getnewaddress()
        n0.issue("&GRID", 100, owner)
        n0.sendtoaddress(n1.getnewaddress(), 10)
        n0.generate(1)
        revoking = n1.getnewaddress()
        paid, frozen, light = n0.getnewaddress(), n0.getnewaddress(), n0.getnewaddress()
        for address in (revoking, paid, frozen, light):
            n0.transferfromaddress("&GRID", owner, 10, address, "", 0, "", owner)
            n0.generate(1)
        self.sync_all()
        n1.selfrevokedepin("&GRID")
        self.sync_all()
        n0.generate(1)
        n0.freezedepin("&GRID", frozen)
        n0.generate(1)
        self.sync_all()

        # The report hash is anchored on the owner token
        weights = {paid: 3, light: 1, revoking: 5}
        owner_token = list(n0.listaddressesbyasset("&GRID!").keys())[0]
        report_txid = n0.transfer(asset_name="&GRID!", qty=1, to_address=owner_token,
                                  message=report_hash(weights).hex())[0]
        n0.generate(1)
        self.sync_all()

        height = self.snapshot_at_next_block("&GRID")
        n0.generate(60)
        self.sync_all()
        owners = {o["address"]: o for o in n0.getsnapshot("&GRID", height)["owners"]}
        assert_equal((owners[revoking]["self_revoked"], owners[frozen]["frozen"]), (True, True))

        by_holding = n0.getdistributionplan("&GRID", height, "XNA", 8, owner)
        verify_plan(n0, by_holding)
        assert_equal(self.amounts(by_holding), {paid: 4, light: 4})
        assert_equal(self.reasons(by_holding), {owner: "exception", revoking: "self_revoked", frozen: "frozen"})

        # Equal shares among devices: the same exclusions, one share each
        equal = n0.getdistributionplan("&GRID", height, "XNA", 8, owner, {"allocation": "equal"})
        verify_plan(n0, equal)
        assert_equal(self.amounts(equal), {paid: 4, light: 4})
        assert_equal(self.reasons(equal), self.reasons(by_holding))
        assert_equal((equal["version"], equal["allocation"]), (4, "equal"))

        options = {"weights": weights, "report": {"txid": report_txid}}
        weighted = n0.getdistributionplan("&GRID", height, "XNA", 8, owner, options)
        verify_plan(n0, weighted, weights)
        assert_equal(self.amounts(weighted), {paid: 6, light: 2})
        assert_equal({r["address"]: r["weight"] for r in weighted["recipients"]}, {paid: 3, light: 1})
        assert_equal((weighted["version"], weighted["report"]["txid"]), (3, report_txid))
        assert_equal(weighted["report"]["hash"], report_hash(weights).hex())
        assert_equal(n1.getdistributionplan("&GRID", height, "XNA", 8, owner, options)["plan_hash"],
                     weighted["plan_hash"])

        partial = n0.getdistributionplan("&GRID", height, "XNA", 8, owner, {"weights": {paid: 3}})
        verify_plan(n0, partial, {paid: 3})
        assert_equal(self.amounts(partial), {paid: 8})
        assert_equal(self.reasons(partial)[light], "no_weight")
        assert_raises_rpc_error(-8, "does not carry the expected message", n0.getdistributionplan,
                                "&GRID", height, "XNA", 8, owner, {"weights": {paid: 3}, "report": {"txid": report_txid}})
        assert_raises_rpc_error(-8, "cannot be combined with report weights", n0.getdistributionplan,
                                "&GRID", height, "XNA", 8, owner, {"weights": weights, "allocation": "equal"})

        for node in (n0, n1):
            assert_equal(node.replaysnapshot("&GRID", height)["matches_stored"], True)

        self.log.info("getsnapshotrecipients classifies holders for a bulletin (D5)")
        recipients = {h["address"]: h for h in n0.getsnapshotrecipients("&GRID", height)["holders"]}
        assert_equal(recipients[owner]["state"], "ready")
        assert_equal(recipients[revoking]["state"], "ready")
        assert_equal(recipients[paid]["state"], "key_not_revealed")
        assert_equal((recipients[revoking]["self_revoked"], recipients[frozen]["frozen"]), (True, True))

    def test_equal_allocation(self):
        n0, n1 = self.nodes[:2]
        self.log.info("Equal allocation and a minimum holding")
        issuer = n0.getnewaddress()
        n0.issue("CLUB", 2000, issuer)
        n0.generate(1)
        alice, bob, carl, dave = n0.getnewaddress(), n0.getnewaddress(), n0.getnewaddress(), n1.getnewaddress()
        for address, qty in ((alice, 1000), (bob, 500), (carl, 100), (dave, 40)):
            n0.transferfromaddress("CLUB", issuer, qty, address, "", 0, "", issuer)
            n0.generate(1)
        self.sync_all()
        height = self.snapshot_at_next_block("CLUB")
        n0.generate(60)
        self.sync_all()

        by_holding = n0.getdistributionplan("CLUB", height, "XNA", 16, issuer)
        assert_equal((by_holding["version"], by_holding["allocation"], by_holding["min_held"]), (1, "holdings", 0))

        # Every eligible holder gets the same share, whatever it holds
        equal = n0.getdistributionplan("CLUB", height, "XNA", 12, issuer, {"allocation": "equal"})
        verify_plan(n0, equal)
        assert_equal(self.amounts(equal), {alice: 3, bob: 3, carl: 3, dave: 3})
        assert_equal({r["address"]: r["held"] for r in equal["recipients"]},
                     {alice: 1000, bob: 500, carl: 100, dave: 40})
        assert_equal((equal["version"], equal["allocation"]), (4, "equal"))

        # A minimum holding excludes smaller holders, with equal shares...
        options = {"allocation": "equal", "min_held": 100}
        club = n0.getdistributionplan("CLUB", height, "XNA", 12, issuer, options)
        verify_plan(n0, club)
        assert_equal(self.amounts(club), {alice: 4, bob: 4, carl: 4})
        assert_equal(self.reasons(club), {issuer: "exception", dave: "below_minimum"})
        assert_equal((club["version"], club["min_held"]), (4, 100))
        assert_equal(n1.getdistributionplan("CLUB", height, "XNA", 12, issuer, options)["plan_hash"], club["plan_hash"])
        assert len({by_holding["plan_hash"], equal["plan_hash"], club["plan_hash"]}) == 3

        # ...and in proportion to the holdings
        proportional = n0.getdistributionplan("CLUB", height, "XNA", 16, issuer, {"min_held": 100})
        verify_plan(n0, proportional)
        assert_equal(self.amounts(proportional), {alice: 10, bob: 5, carl: 1})
        assert_equal((proportional["version"], proportional["allocation"]), (4, "holdings"))

        # The plan object of the proof and batch RPCs takes the same rules
        plan_object = dict(options, asset_name="CLUB", snapshot_height=height, distribution_asset_name="XNA",
                           amount=12, exception_addresses=issuer)
        verify_proof(n0.getdistributionproof(plan_object, carl), club)
        assert_equal(n0.getdistributionbatches(plan_object)["plan_hash"], club["plan_hash"])

        for bad, message in (({"allocation": "weighted"}, "allocation must be"),
                             ({"min_held": "0.5"}, "multiple of the asset's smallest unit"),
                             ({"min_held": -1}, "must not be negative")):
            assert_raises_rpc_error(-8, message, n0.getdistributionplan, "CLUB", height, "XNA", 12, issuer, bad)

    def test_unsupported_recipient(self):
        n0 = self.nodes[0]
        # DePIN-style encryption does not cover post-quantum addresses
        script_address = self.nodes[2].getnewaddress()
        n0.issue("PLAIN", 10)
        n0.generate(1)
        n0.transfer(asset_name="PLAIN", qty=1, to_address=script_address)
        n0.generate(1)
        self.sync_all()
        height = self.snapshot_at_next_block("PLAIN")
        result = n0.getsnapshotrecipients("PLAIN", height)
        states = {h["address"]: h["state"] for h in result["holders"]}
        assert_equal(states[script_address], "unsupported_type")
        assert_equal(result["unsupported_type"], 1)

    def run_test(self):
        self.nodes[0].generate(150)
        self.sync_all()
        self.test_restricted_asset()
        self.test_depin_and_report()
        self.test_equal_allocation()
        self.test_unsupported_recipient()


if __name__ == '__main__':
    RewardEligibilityTest().main()
