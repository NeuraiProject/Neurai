#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise regtest mining, deployments and recovery without fixed PoW nonces.

Use RPC mining so the same test works with main's X16R and DePIN's SHA256d.
Keep the mock clock after the old 2023 deployment timeouts to catch expiry.
"""
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, wait_until


class RegtestTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-assetindex", "-checkblockindex=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.setmocktime(1791417600)  # October 2026; deterministic across runs.
        genesis = node.getblockhash(0)
        assert_equal(node.getblockchaininfo()["chain"], "regtest")

        self.log.info("Mine across the DGW boundary and activate assets")
        assert_equal(len(node.generate(432)), 432)
        for height in (1, 179, 180, 199, 200, 201, 432):
            block = node.getblock(node.getblockhash(height))
            assert_equal(block["height"], height)
            assert int(block["bits"], 16) > 0
        for name in ("assets", "messaging_restricted", "enforce"):
            assert_equal(node.getblockchaininfo()["bip9_softforks"][name]["status"], "active")

        self.log.info("Activate transfer-script and coinbase rules")
        node.generate(1500 - 432)
        for name in ("transfer_script", "coinbase"):
            assert_equal(node.getblockchaininfo()["bip9_softforks"][name]["status"], "active")

        self.log.info("Spend a mature coinbase and issue/transfer an asset")
        node.settxfee(0.01)
        txid = node.sendtoaddress(node.getnewaddress(), 1)
        owner = node.getnewaddress()
        node.issue("REGTEST_REPAIR", 100, owner)
        node.generate(1)
        assert_equal(node.gettransaction(txid)["confirmations"], 1)
        assert_equal(node.getassetdata("REGTEST_REPAIR")["amount"], 100)
        destination = node.getnewaddress()
        node.transfer("REGTEST_REPAIR", 25, destination)
        node.generate(1)
        assert_equal(node.listassetbalancesbyaddress(destination)["REGTEST_REPAIR"], 25)

        self.log.info("Disconnect/reconnect and recover the same chain after restarts")
        tip = node.getbestblockhash()
        height = node.getblockcount()
        stats = node.gettxoutsetinfo()
        node.invalidateblock(tip)
        assert_equal(node.getblockcount(), height - 1)
        node.reconsiderblock(tip)
        assert_equal(node.getbestblockhash(), tip)
        for extra in ([], ["-reindex"], ["-reindex-chainstate"]):
            self.restart_node(0, self.extra_args[0] + extra)
            wait_until(lambda: node.getblockcount() == height,
                       err_msg="Regtest did not recover its tip", timeout=120)
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(node.getblockhash(0), genesis)
            assert_equal(node.listassetbalancesbyaddress(destination)["REGTEST_REPAIR"], 25)
            recovered = node.gettxoutsetinfo()
            for key in ("height", "bestblock", "total_amount", "hash_serialized_2"):
                assert_equal(recovered[key], stats[key])
            assert node.verifychain(4, 0)


if __name__ == '__main__':
    RegtestTest().main()
