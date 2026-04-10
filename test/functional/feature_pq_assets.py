#!/usr/bin/env python3
# Copyright (c) 2017-2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise mixed legacy/PQ XNA and asset flows via wallet RPC."""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


ASSET_NAME = "PQMIXROOT"
ASSET_UNITS = 2
ISSUE_QTY = 1000
REISSUE_QTY_PQ = 500
REISSUE_QTY_LEGACY = 250
TRANSFER_PQ_TO_LEGACY = 125
TRANSFER_PQ_TO_PQ = 50
TRANSFER_LEGACY_TO_PQ = 100


class PQAssetTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ["-assetindex"],
            ["-assetindex", "-pqwallet"],
            ["-assetindex", "-pqwallet"],
        ]

    def mine_and_sync(self, miner=0, blocks=1):
        self.nodes[miner].generate(blocks)
        self.sync_all()

    def assert_script_type(self, node, address, expected):
        info = node.validateaddress(address)
        assert_equal(info["isvalid"], True)
        assert_equal(info["script"], expected)

    def assert_hd_path(self, node, address, expected):
        info = node.validateaddress(address)
        assert_equal(info["hdkeypath"], expected)

    def assert_relayed(self, txid):
        self.sync_all()
        for node in self.nodes:
            assert txid in node.getrawmempool()

    def activate_assets(self):
        self.log.info("Activating assets")
        self.mine_and_sync(0, 432)
        assert_equal("active", self.nodes[0].getblockchaininfo()["bip9_softforks"]["assets"]["status"])

    def setup_wallet_types_and_funding(self):
        self.log.info("Checking legacy/PQ address types and funding PQ wallets")

        n0, n1, n2 = self.nodes

        self.legacy_receive = n0.getnewaddress()
        self.pq1_receive = n1.getnewaddress()
        self.pq2_receive = n2.getnewaddress()

        self.assert_script_type(n0, self.legacy_receive, "pubkeyhash")
        self.assert_script_type(n1, self.pq1_receive, "witness_v1_keyhash")
        self.assert_script_type(n2, self.pq2_receive, "witness_v1_keyhash")
        self.assert_hd_path(n1, self.pq1_receive, "m/100'/1'/0'/0/0")
        self.assert_hd_path(n2, self.pq2_receive, "m/100'/1'/0'/0/0")

        pq_master_info = n1.getmasterkeyinfo()
        assert_equal(pq_master_info["account_derivation_path"], "m/100'/1'/0'")
        assert_equal(pq_master_info["external_derivation_path"], "m/100'/1'/0'/0")
        assert_equal(pq_master_info["internal_derivation_path"], "m/100'/1'/0'/1")

        assert self.pq1_receive in n1.listpqaddresses()
        assert self.pq2_receive in n2.listpqaddresses()

        n0.sendtoaddress(self.pq1_receive, 3000)
        n0.sendtoaddress(self.pq2_receive, 3000)
        self.mine_and_sync(0, 1)

        # Mixed XNA path: PQ -> legacy.
        pq_to_legacy_txid = n1.sendtoaddress(self.legacy_receive, 10)
        self.assert_relayed(pq_to_legacy_txid)
        self.mine_and_sync(1, 1)

        change_address = None
        outs = n1.decoderawtransaction(n1.gettransaction(pq_to_legacy_txid)["hex"])["vout"]
        for out in outs:
            addresses = out["scriptPubKey"].get("addresses", [])
            if out["value"] != 10 and addresses:
                change_address = addresses[0]
                break

        assert change_address is not None
        self.assert_script_type(n1, change_address, "witness_v1_keyhash")
        self.assert_hd_path(n1, change_address, "m/100'/1'/0'/1/0")

    def pq_issue_and_reissue(self):
        self.log.info("Issuing and reissuing an asset from a PQ wallet")

        n1 = self.nodes[1]

        self.pq_issue_address = n1.getnewaddress()
        self.pq_owner_change_after_reissue = n1.getnewaddress()

        issue_txid = n1.issue(
            asset_name=ASSET_NAME,
            qty=ISSUE_QTY,
            to_address=self.pq_issue_address,
            change_address="",
            units=ASSET_UNITS,
            reissuable=True,
            has_ipfs=False,
        )[0]
        self.assert_relayed(issue_txid)
        self.mine_and_sync(0, 1)

        assetdata = n1.getassetdata(ASSET_NAME)
        assert_equal(assetdata["amount"], ISSUE_QTY)
        assert_equal(assetdata["units"], ASSET_UNITS)
        assert_equal(assetdata["reissuable"], 1)

        assert_equal(n1.listassetbalancesbyaddress(self.pq_issue_address)[ASSET_NAME], ISSUE_QTY)
        assert_equal(n1.listassetbalancesbyaddress(self.pq_issue_address)[ASSET_NAME + "!"], 1)

        self.pq_reissue_receive = n1.getnewaddress()
        reissue_txid = n1.reissue(
            ASSET_NAME,
            REISSUE_QTY_PQ,
            self.pq_reissue_receive,
            self.pq_owner_change_after_reissue,
            True,
            -1,
        )[0]
        self.assert_relayed(reissue_txid)
        self.mine_and_sync(0, 1)

        assetdata = n1.getassetdata(ASSET_NAME)
        assert_equal(assetdata["amount"], ISSUE_QTY + REISSUE_QTY_PQ)
        assert_equal(n1.listassetbalancesbyaddress(self.pq_reissue_receive)[ASSET_NAME], REISSUE_QTY_PQ)
        assert_equal(n1.listassetbalancesbyaddress(self.pq_owner_change_after_reissue)[ASSET_NAME + "!"], 1)

    def pq_transfers_and_owner_handoff(self):
        self.log.info("Transferring PQ-issued assets to legacy and PQ wallets, then handing off owner")

        n0, n1, n2 = self.nodes

        self.legacy_asset_receive = n0.getnewaddress()
        self.pq_asset_receive = n2.getnewaddress()
        self.pq_asset_receive_2 = n2.getnewaddress()

        pq_xna_change_1 = n1.getnewaddress()
        self.pq_asset_change_1 = n1.getnewaddress()
        transfer_legacy_txid = n1.transfer(
            ASSET_NAME,
            TRANSFER_PQ_TO_LEGACY,
            self.legacy_asset_receive,
            "",
            0,
            pq_xna_change_1,
            self.pq_asset_change_1,
        )[0]
        self.assert_relayed(transfer_legacy_txid)
        self.mine_and_sync(0, 1)

        assert_equal(n0.listassetbalancesbyaddress(self.legacy_asset_receive)[ASSET_NAME], TRANSFER_PQ_TO_LEGACY)
        assert_equal(n1.listassetbalancesbyaddress(self.pq_asset_change_1)[ASSET_NAME], ISSUE_QTY + REISSUE_QTY_PQ - TRANSFER_PQ_TO_LEGACY)

        pq_xna_change_2 = n1.getnewaddress()
        self.pq_asset_change_2 = n1.getnewaddress()
        transfer_pq_txid = n1.transfer(
            ASSET_NAME,
            TRANSFER_PQ_TO_PQ,
            self.pq_asset_receive,
            "",
            0,
            pq_xna_change_2,
            self.pq_asset_change_2,
        )[0]
        self.assert_relayed(transfer_pq_txid)
        self.mine_and_sync(0, 1)

        assert_equal(n2.listassetbalancesbyaddress(self.pq_asset_receive)[ASSET_NAME], TRANSFER_PQ_TO_PQ)
        assert_equal(n1.listassetbalancesbyaddress(self.pq_asset_change_2)[ASSET_NAME], ISSUE_QTY + REISSUE_QTY_PQ - TRANSFER_PQ_TO_LEGACY - TRANSFER_PQ_TO_PQ)

        self.legacy_owner_receive = n0.getnewaddress()
        owner_handoff_txid = n1.transfer(
            ASSET_NAME + "!",
            1,
            self.legacy_owner_receive,
            "",
            0,
            n1.getnewaddress(),
            "",
        )[0]
        self.assert_relayed(owner_handoff_txid)
        self.mine_and_sync(0, 1)

        assert_equal(n0.listassetbalancesbyaddress(self.legacy_owner_receive)[ASSET_NAME + "!"], 1)
        assert_equal(n0.listmyassets(asset=ASSET_NAME + "!")[ASSET_NAME + "!"], 1)

        assert_raises_rpc_error(
            -32600,
            "Wallet doesn't have asset: {}!".format(ASSET_NAME),
            n1.reissue,
            ASSET_NAME,
            1,
            n1.getnewaddress(),
            "",
            True,
        )

    def legacy_owner_reissue_and_legacy_transfer(self):
        self.log.info("Reissuing with owner in legacy and transferring legacy-held assets back to PQ")

        n0, n2 = self.nodes[0], self.nodes[2]

        self.legacy_owner_change = n0.getnewaddress()
        self.pq_reissue_from_legacy_receive = n2.getnewaddress()

        reissue_legacy_txid = n0.reissue(
            ASSET_NAME,
            REISSUE_QTY_LEGACY,
            self.pq_reissue_from_legacy_receive,
            self.legacy_owner_change,
            True,
            -1,
        )[0]
        self.assert_relayed(reissue_legacy_txid)
        self.mine_and_sync(0, 1)

        assetdata = n0.getassetdata(ASSET_NAME)
        assert_equal(assetdata["amount"], ISSUE_QTY + REISSUE_QTY_PQ + REISSUE_QTY_LEGACY)
        assert_equal(n2.listassetbalancesbyaddress(self.pq_reissue_from_legacy_receive)[ASSET_NAME], REISSUE_QTY_LEGACY)
        assert_equal(n0.listassetbalancesbyaddress(self.legacy_owner_change)[ASSET_NAME + "!"], 1)

        legacy_xna_change = n0.getnewaddress()
        self.legacy_asset_change = n0.getnewaddress()
        transfer_back_txid = n0.transfer(
            ASSET_NAME,
            TRANSFER_LEGACY_TO_PQ,
            self.pq_asset_receive_2,
            "",
            0,
            legacy_xna_change,
            self.legacy_asset_change,
        )[0]
        self.assert_relayed(transfer_back_txid)
        self.mine_and_sync(0, 1)

        assert_equal(n2.listassetbalancesbyaddress(self.pq_asset_receive_2)[ASSET_NAME], TRANSFER_LEGACY_TO_PQ)
        assert_equal(n0.listassetbalancesbyaddress(self.legacy_asset_change)[ASSET_NAME], TRANSFER_PQ_TO_LEGACY - TRANSFER_LEGACY_TO_PQ)

        assert_equal(n0.listmyassets(asset=ASSET_NAME)[ASSET_NAME], TRANSFER_PQ_TO_LEGACY - TRANSFER_LEGACY_TO_PQ)
        assert_equal(n1.listmyassets(asset=ASSET_NAME)[ASSET_NAME], ISSUE_QTY + REISSUE_QTY_PQ - TRANSFER_PQ_TO_LEGACY - TRANSFER_PQ_TO_PQ)
        assert_equal(n2.listmyassets(asset=ASSET_NAME)[ASSET_NAME], TRANSFER_PQ_TO_PQ + REISSUE_QTY_LEGACY + TRANSFER_LEGACY_TO_PQ)

    def run_test(self):
        self.activate_assets()
        self.setup_wallet_types_and_funding()
        self.pq_issue_and_reissue()
        self.pq_transfers_and_owner_handoff()
        self.legacy_owner_reissue_and_legacy_transfer()


if __name__ == "__main__":
    PQAssetTest().main()
