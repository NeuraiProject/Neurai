#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
NIP-040: rvn -> xna asset marker migration on a real node.

Regtest defaults to xna-native (fork height 1), so this test moves the
frontier with -nip040height to exercise the legacy era, the exact boundary,
consensus rejection on both sides, mempool eviction in both directions and
migration-by-spend of legacy UTXOs.
"""

import math
from io import BytesIO
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes_bi,
    disconnect_nodes,
    sync_blocks,
)
from test_framework.mininode import CTransaction, hex_str_to_bytes, bytes_to_hex_str

RVNQ = '72766e71'  # legacy issue marker
RVNT = '72766e74'  # legacy transfer marker
XNAQ = '786e6171'  # NIP-040 issue marker
XNAT = '786e6174'  # NIP-040 transfer marker

FORK_HEIGHT = 460  # leaves room after asset activation at 432


def truncate(number, digits=8):
    stepper = pow(10.0, digits)
    return math.trunc(stepper * number) / stepper


class Nip040MarkerMigrationTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-nip040height=' + str(FORK_HEIGHT)]] * self.num_nodes

    def activate_assets(self):
        self.log.info("Generating XNA and activating assets...")
        n0 = self.nodes[0]
        n0.generate(1)
        self.sync_all()
        n0.generate(431)
        self.sync_all()
        assert_equal("active", n0.getblockchaininfo()['bip9_softforks']['assets']['status'])

    def marker_in_outputs(self, node, tx_hex, marker):
        decoded = node.decoderawtransaction(tx_hex)
        return any(marker in vout['scriptPubKey']['hex'] for vout in decoded['vout'])

    def build_raw_transfer(self, node, asset_name):
        """Raw transfer of the full first outpoint of asset_name (so no asset
        change output is needed), built by createrawtransaction — which must
        pick the marker from the candidate height on its own."""
        to_address = node.getnewaddress()
        change_address = node.getnewaddress()
        unspent = None
        for u in node.listunspent():
            if float(u['amount']) > 1:
                unspent = u
                break
        assert unspent is not None, "no XNA utxo available"
        outpoint = node.listmyassets(asset_name, True)[asset_name]['outpoints'][0]
        inputs = [
            {'txid': unspent['txid'], 'vout': unspent['vout']},
            {'txid': outpoint['txid'], 'vout': outpoint['vout']},
        ]
        outputs = {
            change_address: truncate(float(unspent['amount']) - 0.01),
            to_address: {'transfer': {asset_name: outpoint['amount']}},
        }
        return node.createrawtransaction(inputs, outputs)

    def tamper_marker(self, node, tx_hex, old_marker, new_marker):
        """Swap the 3-byte marker prefix inside the asset outputs and re-sign."""
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(tx_hex)))
        found = False
        for out in tx.vout:
            spk = bytes_to_hex_str(out.scriptPubKey)
            if old_marker in spk:
                out.scriptPubKey = hex_str_to_bytes(spk.replace(old_marker, new_marker))
                found = True
        assert found, "no output carried marker " + old_marker
        return node.signrawtransaction(bytes_to_hex_str(tx.serialize()))['hex']

    def run_test(self):
        n0, n1 = self.nodes[0], self.nodes[1]
        self.activate_assets()  # height 432

        self.log.info("Pre-fork: wallet and RPC emit legacy rvn markers")
        txid = n0.issue("MIGRATE", 1000)[0]
        issue_hex = n0.getrawtransaction(txid)
        assert self.marker_in_outputs(n0, issue_hex, RVNQ)
        assert not self.marker_in_outputs(n0, issue_hex, XNAQ)
        n0.generate(1)  # 433
        self.sync_all()

        txid = n0.transfer("MIGRATE", 100, n1.getnewaddress())[0]
        transfer_hex = n0.getrawtransaction(txid)
        assert self.marker_in_outputs(n0, transfer_hex, RVNT)
        n0.generate(1)  # 434
        self.sync_all()

        self.log.info("Pre-fork: an xna output is rejected by consensus")
        raw = self.build_raw_transfer(n0, "MIGRATE")
        assert self.marker_in_outputs(n0, raw, RVNT)
        bad = self.tamper_marker(n0, raw, RVNT, XNAT)
        assert_raises_rpc_error(-26, "bad-txns-asset-marker-before-nip040",
                                n0.sendrawtransaction, bad)

        self.log.info("Advance to two blocks before the frontier")
        n0.generate(FORK_HEIGHT - 2 - n0.getblockcount())
        self.sync_all()
        assert_equal(n0.getblockcount(), FORK_HEIGHT - 2)

        self.log.info("Mempool eviction: legacy tx dies when the target height crosses the fork")
        disconnect_nodes(n0, 1)
        legacy_txid = n0.transfer("MIGRATE", 7, n0.getnewaddress())[0]  # candidate H-1: legacy
        assert legacy_txid in n0.getrawmempool()
        assert self.marker_in_outputs(n0, n0.getrawtransaction(legacy_txid), RVNT)
        n1.generate(1)  # n1 mines H-1 without the tx
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(n0.getblockcount(), FORK_HEIGHT - 1)
        # connecting H-1 moved the mempool target height to H: the legacy tx
        # can never be mined again and must be gone
        assert legacy_txid not in n0.getrawmempool()
        n0.abandontransaction(legacy_txid)  # release its wallet inputs

        self.log.info("Cross the frontier: wallet switches to xna, legacy inputs migrate on spend")
        n0.generate(1)  # height H
        self.sync_all()
        migrate_txid = n0.transfer("MIGRATE", 50, n1.getnewaddress())[0]
        migrate_hex = n0.getrawtransaction(migrate_txid)
        assert self.marker_in_outputs(n0, migrate_hex, XNAT)
        assert not self.marker_in_outputs(n0, migrate_hex, RVNT)
        n0.generate(1)
        self.sync_all()
        assert n0.getrawtransaction(migrate_txid, 1)['confirmations'] >= 1

        txid = n0.issue("MIGRATE2", 500)[0]
        issue2_hex = n0.getrawtransaction(txid)
        assert self.marker_in_outputs(n0, issue2_hex, XNAQ)
        assert not self.marker_in_outputs(n0, issue2_hex, RVNQ)
        n0.generate(1)
        self.sync_all()

        self.log.info("Post-fork: a legacy output is rejected by consensus")
        raw = self.build_raw_transfer(n0, "MIGRATE2")
        assert self.marker_in_outputs(n0, raw, XNAT)
        bad = self.tamper_marker(n0, raw, XNAT, RVNT)
        assert_raises_rpc_error(-26, "bad-txns-legacy-asset-marker-after-nip040",
                                n0.sendrawtransaction, bad)

        self.log.info("Reorg below the frontier: xna mempool txs are evicted")
        disconnect_nodes(n0, 1)
        xna_txid = n0.transfer("MIGRATE2", 5, n0.getnewaddress())[0]
        assert xna_txid in n0.getrawmempool()
        fork_block = n0.getblockhash(FORK_HEIGHT - 1)
        n0.invalidateblock(fork_block)  # tip back to H-2, target height H-1: legacy era
        assert_equal(n0.getblockcount(), FORK_HEIGHT - 2)
        assert xna_txid not in n0.getrawmempool()
        # confirmed xna txs from the disconnected blocks must not resurrect
        # into the mempool either — resubmission runs the marker rule
        assert migrate_txid not in n0.getrawmempool()

        self.log.info("Reconsider and resync")
        n0.reconsiderblock(fork_block)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert n0.getrawtransaction(migrate_txid, 1)['confirmations'] >= 1


if __name__ == '__main__':
    Nip040MarkerMigrationTest().main()
