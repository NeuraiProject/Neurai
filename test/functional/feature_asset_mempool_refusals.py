#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
A transaction the mempool refuses is not left in it.

One pending change per tag and address, and one pending freeze and one pending
unfreeze per restricted asset, are accepted to the mempool. The transaction
that repeats one is refused, and must not be stored: once the first confirms,
the repeated one is invalid against the chain and no block can carry it.

For each of the four rules: the repeated operation is refused, the mempool
holds the first one only, the next block is mined from it, and the state is
the one the first operation asked for.
"""

from decimal import Decimal

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

TAG = "#REFUSAL"
RESTRICTED = "$REFUSAL"


class AssetMempoolRefusalsTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def mine(self):
        self.nodes[0].generate(1)
        self.sync_all()

    def setup_assets(self):
        n0 = self.nodes[0]
        n0.generate(432)
        self.address = n0.getnewaddress()
        n0.issue(RESTRICTED[1:], 100)
        n0.issuequalifierasset(TAG, 10)
        self.mine()
        n0.issuerestrictedasset(RESTRICTED, 100, "true", self.address)
        self.mine()

    def chained_global_operation(self, first, operation):
        """A second freeze or unfreeze of the asset, which spends the outputs of the pending one.

        The wallet refuses to build it, so it is built by hand."""
        n0 = self.nodes[0]
        decoded = n0.decoderawtransaction(n0.gettransaction(first)['hex'])
        owner = next(out for out in decoded['vout']
                     if out['scriptPubKey'].get('asset', {}).get('name') == RESTRICTED[1:] + "!")
        coins = next(out for out in decoded['vout'] if out['value'] > 1 and 'asset' not in out['scriptPubKey'])
        inputs = [{'txid': first, 'vout': coins['n']}, {'txid': first, 'vout': owner['n']}]
        outputs = {
            n0.getnewaddress(): coins['value'] - Decimal('0.1'),
            n0.getnewaddress(): {operation + '_asset': {'asset_name': RESTRICTED}},
        }
        signed = n0.signrawtransaction(n0.createrawtransaction(inputs, outputs))
        assert signed['complete']
        return signed['hex']

    def repeated(self, operation, arguments, refusal, expected, by_hand=None):
        """The same operation twice before a block: the second is refused and not stored."""
        n0, n1 = self.nodes
        self.log.info("%s twice before a block...", operation)
        first = getattr(n0, operation)(*arguments)
        first = first[0] if isinstance(first, list) else first
        assert_equal(n0.getrawmempool(), [first])
        if by_hand:
            assert_raises_rpc_error(-26, refusal, n0.sendrawtransaction, self.chained_global_operation(first, by_hand))
        else:
            assert_raises_rpc_error(None, refusal, getattr(n0, operation), *arguments)
        assert_equal(n0.getrawmempool(), [first])

        # The block is built from this mempool and the other node accepts it
        block = n0.generate(1)[0]
        self.sync_all()
        assert first in n0.getblock(block)['tx']
        assert_equal(n0.getrawmempool(), [])
        assert_equal(n1.getrawmempool(), [])
        for node in self.nodes:
            expected(node)
        # ...and the node keeps building blocks
        self.mine()

    def run_test(self):
        self.setup_assets()
        address = self.address
        self.repeated('addtagtoaddress', (TAG, address), "bad-txns-adding-tag-already-in-mempool",
                      lambda node: assert_equal(node.checkaddresstag(address, TAG), True))
        self.repeated('removetagfromaddress', (TAG, address), "bad-txns-remove-tag-already-in-mempool",
                      lambda node: assert_equal(node.checkaddresstag(address, TAG), False))
        self.repeated('freezerestrictedasset', (RESTRICTED,), "bad-txns-global-freeze-already-in-mempool",
                      lambda node: assert_equal(node.checkglobalrestriction(RESTRICTED), True), by_hand='freeze')
        self.repeated('unfreezerestrictedasset', (RESTRICTED,), "bad-txns-global-unfreeze-already-in-mempool",
                      lambda node: assert_equal(node.checkglobalrestriction(RESTRICTED), False), by_hand='unfreeze')


if __name__ == '__main__':
    AssetMempoolRefusalsTest().main()
