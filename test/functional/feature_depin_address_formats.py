#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
DEPIN restrictions reach the holder on every address format.

Node 0 owns the asset. Nodes 1 to 3 hold it on a legacy, a strict ECDSA
(witness v3) and a strict post-quantum (witness v2) address. On each format an
owner freeze and a self-revocation block the holder's transfers, an owner
unfreeze allows them again, and a restriction on one address leaves the others
alone. Script-hash addresses cannot hold assets and are refused.

Also checks the name limit: the longest DEPIN name leaves room for the owner
tag, so its owner token can be moved.
"""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, sync_mempools

ASSET = "&FORMATS"
FORMATS = ["legacy", "ecdsa", "pq"]

CLEAN = (False, False)        # (owner frozen, blocked)
OWNER_FROZEN = (True, True)
SELF_REVOKED = (False, True)


class DepinAddressFormatsTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [['-assetindex', '-addresstype=legacy']] + \
                          [['-assetindex', '-addresstype=' + fmt] for fmt in FORMATS]

    # ----------------------------------------------------------------- helpers
    def mine(self):
        sync_mempools(self.nodes)
        self.nodes[0].generate(1)
        self.sync_all()

    def restriction(self, address):
        states = set()
        for node in self.nodes:
            states.add((node.checkaddressrestriction(address, ASSET),
                        node.checkdepinvalidity(ASSET, address)['blocked']))
        assert_equal(len(states), 1)
        return states.pop()

    def move(self, holder, address):
        """The holder moves one unit off `address`, keeping the rest there."""
        return holder.transfer(ASSET, 1, holder.getnewaddress(), "", 0, "", address)

    def assert_blocked(self, holder, address):
        assert_raises_rpc_error(None, "bad-txns-depin-transfer-from-restricted-address", self.move, holder, address)

    # ------------------------------------------------------------------- steps
    def setup_asset(self):
        self.log.info("Issuing the asset, opening it and handing units to each holder...")
        owner = self.nodes[0]
        owner.generate(432)
        self.sync_all()
        owner.issue(ASSET, 100, owner.getnewaddress())
        self.mine()
        owner.opendepin(ASSET)
        self.mine()

        self.holders = {}
        for fmt, node in zip(FORMATS, self.nodes[1:]):
            address = node.getnewaddress()
            owner.sendtoaddress(node.getnewaddress(), 50)
            owner.transfer(ASSET, 10, address)
            self.mine()
            assert_equal(node.listmyassets(ASSET)[ASSET], 10)
            assert_equal(self.restriction(address), CLEAN)
            self.holders[fmt] = (node, address)
        assert_equal(len({address for _, address in self.holders.values()}), len(FORMATS))

    def restrictions_reach_every_format(self):
        owner = self.nodes[0]
        for fmt in FORMATS:
            holder, address = self.holders[fmt]
            others = [a for f, (_, a) in self.holders.items() if f != fmt]
            self.log.info("%s address: owner freeze, unfreeze and self-revocation...", fmt)

            owner.freezedepin(ASSET, address)
            self.mine()
            assert_equal(self.restriction(address), OWNER_FROZEN)
            self.assert_blocked(holder, address)
            for other in others:
                assert_equal(self.restriction(other), CLEAN)

            owner.unfreezedepin(ASSET, address)
            self.mine()
            assert_equal(self.restriction(address), CLEAN)

            holder.selfrevokedepin(ASSET)
            self.mine()
            assert_equal(self.restriction(address), SELF_REVOKED)
            self.assert_blocked(holder, address)
            for other in others:
                assert_equal(self.restriction(other), CLEAN)

            owner.unfreezedepin(ASSET, address)
            self.mine()
            assert_equal(self.restriction(address), CLEAN)
            self.move(holder, address)
            self.mine()
            assert_equal(holder.listmyassets(ASSET)[ASSET], 10)

    def script_hash_addresses_are_refused(self):
        self.log.info("A script-hash address cannot hold the asset, be frozen or unfrozen...")
        owner = self.nodes[0]
        refused = "Script-hash addresses cannot hold assets"
        script_hash = owner.addmultisigaddress(1, [owner.getnewaddress()])
        for call in (owner.freezedepin, owner.unfreezedepin):
            assert_raises_rpc_error(-5, refused, call, ASSET, script_hash)

        # ...as the destination of an issue, a reissue or a transfer...
        assert_raises_rpc_error(-5, refused, owner.issue, "&TOSCRIPTHASH", 1, script_hash)
        assert_raises_rpc_error(-5, refused, owner.reissue, ASSET, 1, script_hash)
        assert_raises_rpc_error(-5, refused, owner.transfer, ASSET, 1, script_hash)
        assert_raises_rpc_error(-5, refused, owner.transfer, ASSET + "!", 1, script_hash)
        # ...as the change address of the asset...
        assert_raises_rpc_error(-5, refused, owner.transfer, ASSET, 1, owner.getnewaddress(), "", 0, "", script_hash)
        assert_raises_rpc_error(-5, refused, owner.issue, ASSET + "/SECTION", 1, owner.getnewaddress(), script_hash)
        # ...and in a raw transaction.
        unspent = owner.listunspent()[0]
        assert_raises_rpc_error(-5, refused, owner.createrawtransaction, [{'txid': unspent['txid'], 'vout': unspent['vout']}],
                                {script_hash: {'transfer': {ASSET: 1}}})
        assert_equal(owner.getrawmempool(), [])

        self.log.info("...while coins still go to it, as the change of a new asset too...")
        owner.issue("PLAINASSET", 1, owner.getnewaddress(), script_hash)
        owner.sendtoaddress(script_hash, 1)
        assert_equal(len(owner.getrawmempool()), 2)
        self.mine()

    def longest_name_keeps_room_for_the_owner_tag(self):
        self.log.info("The longest DEPIN name leaves room for the owner tag...")
        owner = self.nodes[0]
        longest = "&" + "D" * 119
        assert_raises_rpc_error(None, "Name is greater than max length", owner.issue, longest + "D", 1)
        owner.issue(longest, 1)
        self.mine()
        owner.transfer(longest + "!", 1, owner.getnewaddress())
        self.mine()
        assert_equal(owner.listmyassets(longest + "!")[longest + "!"], 1)

    def run_test(self):
        self.setup_asset()
        self.restrictions_reach_every_format()
        self.script_hash_addresses_are_refused()
        self.longest_name_keeps_room_for_the_owner_tag()


if __name__ == '__main__':
    DepinAddressFormatsTest().main()
