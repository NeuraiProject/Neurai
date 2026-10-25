#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Cross the AuthScript activation height with a wallet that holds strict outputs.

Regtest moves the generic (v1) and strict (v2/v3) AuthScript activation to
ACTIVATION_HEIGHT, as a network upgrade would:

- Below it, outputs to OP_1/OP_2/OP_3 <32> are not relayed and strict addresses
  are not payable: consensus would leave those outputs spendable by anyone.
- From it, a strict ECDSA wallet receives XNA and an asset.
- A -reindex reloads that wallet while the tip is below the activation height;
  every transaction, coin and asset must survive it.
- A reorg back below the activation height drops the strict transactions from
  the mempool, and reconsidering the blocks confirms them again.
"""

import os
from decimal import Decimal

from test_framework.messages import CTransaction, from_hex, to_hex
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, connect_nodes_bi, wait_until

ASSET_ACTIVATION_BLOCKS = 432
ACTIVATION_HEIGHT = 500
ASSET_NAME = "STRICTBOUNDARY"
STRICT_XNA = Decimal("10")
STRICT_ASSET_QTY = 25


class AuthScriptActivationTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        activation = ["-optinfeaturesheight={}".format(ACTIVATION_HEIGHT),
                      "-strictauthscriptheight={}".format(ACTIVATION_HEIGHT)]
        self.extra_args = [
            ["-assetindex"] + activation,
            ["-assetindex", "-addresstype=ecdsa"] + activation,
        ]

    def witness_output_tx(self, node, version):
        """Raw tx paying a legacy coin to OP_<version> <32 bytes>, signed."""
        utxo = next(u for u in node.listunspent() if u["amount"] > 1)
        raw = node.createrawtransaction([{"txid": utxo["txid"], "vout": utxo["vout"]}],
                                        {node.getnewaddress(): utxo["amount"] - Decimal("0.01")})
        tx = from_hex(CTransaction(), raw)
        tx.vout[0].scriptPubKey = bytes([0x50 + version, 0x20]) + bytes([0x42] * 32)
        return node.signrawtransaction(to_hex(tx))["hex"]

    def wallet_state(self, node):
        return {
            "txcount": node.getwalletinfo()["txcount"],
            "balance": node.getbalance(),
            "assets": node.listmyassets(),
        }

    def assert_clean_wallet_load(self, node):
        with open(os.path.join(node.datadir, "regtest", "debug.log"), encoding="utf-8") as log:
            content = log.read()
        assert "DB failed to Read Key" not in content, "the wallet rejected a stored transaction"
        assert "Error reading wallet" not in content

    def run_test(self):
        miner, holder = self.nodes
        strict_address = holder.getnewaddress()
        assert strict_address.startswith("tnq1r"), strict_address

        self.log.info("Below activation: no relay of AuthScript outputs, strict addresses not payable")
        miner.generate(ASSET_ACTIVATION_BLOCKS + 20)
        self.sync_all()
        assert miner.getblockcount() < ACTIVATION_HEIGHT - 1
        for version in (1, 2, 3):
            assert_raises_rpc_error(-26, "authscript-output-not-active",
                                    miner.sendrawtransaction, self.witness_output_tx(miner, version))
        assert_raises_rpc_error(-5, "Invalid address", miner.sendtoaddress, strict_address, STRICT_XNA)

        self.log.info("At activation: the strict wallet receives XNA and an asset")
        miner.generate(ACTIVATION_HEIGHT - 1 - miner.getblockcount())
        self.sync_all()
        assert_equal(miner.getblockcount(), ACTIVATION_HEIGHT - 1)  # the next block applies the rules
        miner.sendrawtransaction(self.witness_output_tx(miner, 3))
        funding_txid = miner.sendtoaddress(strict_address, STRICT_XNA)
        miner.issue(ASSET_NAME, 100)
        miner.generate(1)
        transfer_txid = miner.transfer(ASSET_NAME, STRICT_ASSET_QTY, strict_address)[0]
        miner.generate(1)
        self.sync_all()
        before = self.wallet_state(holder)
        assert_equal(before["balance"], STRICT_XNA)
        assert_equal(before["assets"], {ASSET_NAME: STRICT_ASSET_QTY})
        height = holder.getblockcount()

        self.log.info("Reindex: the wallet loads while the tip is below the activation height")
        self.restart_node(1, self.extra_args[1] + ["-reindex"])
        wait_until(lambda: holder.getblockcount() == height, err_msg="reindex did not finish", timeout=120)
        self.assert_clean_wallet_load(holder)
        assert_equal(self.wallet_state(holder), before)
        connect_nodes_bi(self.nodes, 0, 1)

        self.log.info("Reorg below activation: strict transactions leave the mempool")
        fork = holder.getblockhash(ACTIVATION_HEIGHT - 1)
        holder.invalidateblock(fork)
        assert_equal(holder.getblockcount(), ACTIVATION_HEIGHT - 2)
        mempool = holder.getrawmempool()
        assert funding_txid not in mempool
        assert transfer_txid not in mempool
        assert_equal(holder.getbalance(), 0)
        assert_equal(holder.listmyassets().get(ASSET_NAME, 0), 0)

        self.log.info("Back above activation: the transactions confirm again")
        holder.reconsiderblock(fork)
        wait_until(lambda: holder.getblockcount() == height, err_msg="reconsiderblock did not restore the tip", timeout=60)
        assert_equal(self.wallet_state(holder), before)
        assert holder.gettransaction(funding_txid)["confirmations"] > 0
        assert holder.gettransaction(transfer_txid)["confirmations"] > 0


if __name__ == '__main__':
    AuthScriptActivationTest().main()
