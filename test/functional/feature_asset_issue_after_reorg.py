#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
An asset name issued again after a reorganisation is the new asset on every node.

Node 0 connects blocks that issue an asset and is then reorganised away from
them. Until its asset state is next written to disk it remembers that the
asset was removed. Node 1 never connected those blocks. Both must judge the
blocks that follow in the same way:

- a block that issues the name again and transfers the asset in the same
  block is valid for both, and node 0 can build it from its own mempool;
- when the name is issued again with other properties, node 0 reports and
  enforces the properties of the new asset, not the ones of the asset it
  disconnected, also after a reissue of the disconnected asset.
"""

from decimal import Decimal

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, disconnect_nodes, sync_blocks


class AssetIssueAfterReorgTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-assetindex']] * self.num_nodes

    # ----------------------------------------------------------------- helpers
    def isolate(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)

    def rejoin(self):
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

    def assert_same_chain(self):
        """Both nodes follow the same chain and neither holds a block it refused."""
        sync_blocks(self.nodes, timeout=30)
        for node in self.nodes:
            assert_equal([tip['status'] for tip in node.getchaintips() if tip['status'] == 'invalid'], [])

    def hand_over(self, txids):
        """Give node 1 transactions of node 0's wallet that it does not hold."""
        n0, n1 = self.nodes
        for txid in txids:
            if txid not in n1.getrawmempool():
                n1.sendrawtransaction(n0.gettransaction(txid)['hex'])

    def issued_and_abandoned(self, name):
        """Node 0 issues `name` and transfers it on a branch that loses. Both transactions return to its mempool."""
        n0, n1 = self.nodes
        self.isolate()
        issue = n0.issue(name, 50, n0.getnewaddress())[0]
        n0.generate(1)
        transfer = n0.transfer(name, 1, n0.getnewaddress())[0]
        n0.generate(1)
        n1.generate(3)
        self.rejoin()
        assert_equal(sorted(n0.getrawmempool()), sorted([issue, transfer]))
        return issue, transfer

    # ------------------------------------------------------------------- steps
    def setup_assets(self):
        n0, n1 = self.nodes
        n0.generate(432)
        n0.sendtoaddress(n1.getnewaddress(), 5000)
        n0.issue("ROOT", 100)
        n0.generate(1)
        self.sync_all()

    def block_from_the_other_node(self):
        self.log.info("A block that issues the name again and transfers it, mined by the node that saw nothing...")
        n0, n1 = self.nodes
        issue, transfer = self.issued_and_abandoned("ROOT/ELSEWHERE")
        self.hand_over([issue, transfer])
        block = n1.generate(1)[0]
        assert issue in n1.getblock(block)['tx'] and transfer in n1.getblock(block)['tx']
        self.assert_same_chain()
        assert_equal(n0.getbestblockhash(), block)
        assert_equal(n0.getassetdata("ROOT/ELSEWHERE"), n1.getassetdata("ROOT/ELSEWHERE"))

    def block_from_its_own_mempool(self):
        self.log.info("...and built by the node that disconnected the first issue, from its own mempool...")
        n0, n1 = self.nodes
        issue, transfer = self.issued_and_abandoned("ROOT/OWN")
        block = n0.generate(1)[0]
        assert issue in n0.getblock(block)['tx'] and transfer in n0.getblock(block)['tx']
        assert_equal(n0.getrawmempool(), [])
        self.assert_same_chain()
        assert_equal(n0.getassetdata("ROOT/OWN"), n1.getassetdata("ROOT/OWN"))

    def issued_again_with_other_properties(self):
        self.log.info("The name is issued again with other properties, after a reissue of the first asset...")
        n0, n1 = self.nodes
        name = "TWICE"
        self.isolate()
        # Node 0: no decimals, then a reissue that allows two
        n0.issue(name, 100, n0.getnewaddress(), "", 0)
        n0.generate(1)
        n0.reissue(name, 50, n0.getnewaddress(), "", True, 2)
        n0.generate(1)
        assert_equal(n0.getassetdata(name)['units'], 2)
        # Node 1: the same name with four decimals, on the branch that wins and
        # at another height
        n1.generate(1)
        n1.issue(name, 1000, n1.getnewaddress(), "", 4)
        issued = n1.generate(3)[0]
        self.rejoin()
        assert_equal(n0.getrawmempool(), [])  # the first asset's transactions have no place on this chain
        assert_equal(n0.getassetdata(name), n1.getassetdata(name))
        assert_equal(n0.getassetdata(name)['units'], 4)

        self.log.info("...and an amount that only the new asset allows is accepted by both nodes...")
        n1.transfer(name, Decimal('0.0001'), n1.getnewaddress())
        block = n1.generate(1)[0]
        self.assert_same_chain()
        assert_equal(n0.getbestblockhash(), block)

        self.log.info("...and a reissue of the new asset keeps the block the new asset was issued in...")
        n1.reissue(name, 10, n1.getnewaddress())
        n1.generate(1)
        self.assert_same_chain()
        assert_equal(n0.getassetdata(name), n1.getassetdata(name))

        self.log.info("...also once the node has written its asset state to disk")
        n0.gettxoutsetinfo()
        assert_equal(n0.getassetdata(name), n1.getassetdata(name))
        assert_equal(n0.listassets(name, True), n1.listassets(name, True))
        assert_equal(n0.listassets(name, True)[name]['blockhash'], issued)
        self.restart_node(0)
        connect_nodes_bi(self.nodes, 0, 1)
        assert_equal(n0.getassetdata(name), n1.getassetdata(name))
        assert_equal(n0.listassets(name, True), n1.listassets(name, True))
        n1.transfer(name, Decimal('0.0002'), n1.getnewaddress())
        n1.generate(1)
        self.assert_same_chain()

    def run_test(self):
        self.setup_assets()
        self.block_from_the_other_node()
        self.block_from_its_own_mempool()
        self.issued_again_with_other_properties()


if __name__ == '__main__':
    AssetIssueAfterReorgTest().main()
