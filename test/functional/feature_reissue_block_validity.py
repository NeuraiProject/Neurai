#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
The validity of a block does not depend on the reissues a node has pending.

"One pending reissue per asset" is mempool policy. Node 0 owns the assets and
keeps one reissue of an asset in its mempool while node 1 confirms another
reissue of the same asset. Node 0 must accept that block:

- with the other reissue in its mempool,
- after a restart that did not reload its mempool,
- after being offline while the block was mined.

The policy itself still holds: a second reissue chained on a pending one is
not accepted to the mempool.
"""

from decimal import Decimal

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    disconnect_nodes,
    sync_blocks,
)

BURN_ADDRESS = "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy"
REISSUE_BURN = 200


class ReissueBlockValidityTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    # ----------------------------------------------------------------- helpers
    def isolate(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)

    def rejoin(self):
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

    def owner_outpoint(self, asset):
        owner = asset + "!"
        return self.nodes[0].listmyassets(owner, True)[owner]['outpoints'][0]

    def funding(self):
        for unspent in self.nodes[0].listunspent():
            if unspent['amount'] > REISSUE_BURN + 1:
                return unspent
        raise AssertionError("no output large enough to pay a reissue")

    def signed_reissue(self, asset, quantity, inputs, amount):
        """A signed reissue of `asset` spending `inputs`, the first of which holds `amount` XNA."""
        n0 = self.nodes[0]
        outputs = {
            BURN_ADDRESS: REISSUE_BURN,
            n0.getnewaddress(): Decimal(amount) - REISSUE_BURN - Decimal('0.1'),
            n0.getnewaddress(): {'reissue': {'asset_name': asset, 'asset_quantity': quantity}},
        }
        signed = n0.signrawtransaction(n0.createrawtransaction(inputs, outputs))
        assert signed['complete']
        return signed['hex']

    def conflicting_reissues(self, asset):
        """Two signed reissues of `asset` that spend the same owner token."""
        funding = self.funding()
        inputs = [{k: funding[k] for k in ['txid', 'vout']},
                  {k: self.owner_outpoint(asset)[k] for k in ['txid', 'vout']}]
        return (self.signed_reissue(asset, 1000, inputs, funding['amount']),
                self.signed_reissue(asset, 2000, inputs, funding['amount']))

    def confirm_on_node1(self, tx_hex):
        n1 = self.nodes[1]
        txid = n1.sendrawtransaction(tx_hex)
        block = n1.generate(1)[0]
        assert txid in n1.getblock(block)['tx']
        return block

    def assert_follows(self, block, asset, expected_amount):
        n0, n1 = self.nodes
        assert_equal(n0.getbestblockhash(), block)
        assert_equal(n0.getbestblockhash(), n1.getbestblockhash())
        assert_equal(n0.getrawmempool(), [])
        assert_equal(n0.getassetdata(asset)['amount'], expected_amount)

    # ------------------------------------------------------------------- steps
    def setup_assets(self):
        self.log.info("Activating assets and issuing three reissuable assets...")
        n0 = self.nodes[0]
        n0.generate(432)
        self.sync_all()
        for asset in ("PENDING", "RESTARTED", "OFFLINE"):
            n0.issue(asset, 1000)
        n0.generate(1)
        self.sync_all()

    def other_reissue_pending(self):
        self.log.info("A block is valid while another reissue of the asset is pending...")
        n0 = self.nodes[0]
        asset = "PENDING"
        self.isolate()
        mine, theirs = self.conflicting_reissues(asset)
        pending = n0.sendrawtransaction(mine)
        assert pending in n0.getrawmempool()

        self.log.info("...and a reissue chained on a pending one stays out of the mempool...")
        decoded = n0.decoderawtransaction(mine)
        owner_vout = next(out['n'] for out in decoded['vout']
                          if out['scriptPubKey'].get('asset', {}).get('name') == asset + "!")
        change_vout = next(out for out in decoded['vout']
                           if out['value'] > 0 and 'asset' not in out['scriptPubKey']
                           and BURN_ADDRESS not in out['scriptPubKey'].get('addresses', []))
        chained = self.signed_reissue(asset, 500,
                                      [{'txid': pending, 'vout': change_vout['n']}, {'txid': pending, 'vout': owner_vout}],
                                      change_vout['value'])
        assert_raises_rpc_error(-26, "bad-tx-reissue-chaining-not-allowed", n0.sendrawtransaction, chained)

        self.log.info("...which a cleared mempool no longer holds...")
        n0.clearmempool()
        assert_equal(n0.getrawmempool(), [])
        assert_equal(n0.sendrawtransaction(mine), pending)

        block = self.confirm_on_node1(theirs)
        self.rejoin()
        self.assert_follows(block, asset, 3000)

        self.log.info("...and the asset can be reissued again afterwards...")
        again, _ = self.conflicting_reissues(asset)
        n0.sendrawtransaction(again)
        n0.generate(1)
        self.sync_all()
        assert_equal(n0.getassetdata(asset)['amount'], 4000)

    def restarted_without_mempool(self):
        self.log.info("...after a restart that does not reload the mempool...")
        n0 = self.nodes[0]
        asset = "RESTARTED"
        self.isolate()
        mine, theirs = self.conflicting_reissues(asset)
        n0.sendrawtransaction(mine)
        # The wallet must not resubmit its transaction either
        self.restart_node(0, ['-persistmempool=0', '-walletbroadcast=0'])
        assert_equal(n0.getrawmempool(), [])

        block = self.confirm_on_node1(theirs)
        self.rejoin()
        self.assert_follows(block, asset, 3000)

    def offline_while_confirmed(self):
        self.log.info("...and after being offline while the other reissue was confirmed...")
        n0 = self.nodes[0]
        asset = "OFFLINE"
        self.isolate()
        mine, theirs = self.conflicting_reissues(asset)
        pending = n0.sendrawtransaction(mine)
        self.stop_node(0)
        block = self.confirm_on_node1(theirs)
        self.start_node(0)
        assert pending in n0.getrawmempool()

        self.rejoin()
        self.assert_follows(block, asset, 3000)

    def run_test(self):
        self.setup_assets()
        self.other_reissue_pending()
        self.restarted_without_mempool()
        self.offline_while_confirmed()


if __name__ == '__main__':
    ReissueBlockValidityTest().main()
