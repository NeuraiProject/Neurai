#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test the legacy asset modules switches (NIP-048 deliveries A1 and A2).

Legacy asset messaging (-assetmessages, -disablemessaging):
- A fresh node creates no messages store; -assetmessages=1 creates it, and a
  node whose data directory already has it keeps using it.
- A bare -disablemessaging disables messaging like -disablemessaging=1, and
  combining it with -assetmessages=1 is refused at startup.
- The command line overrides the configuration file.
- Disabling never deletes the store.

Legacy asset rewards (-assetrewards):
- Active by default with -assetindex, or when the rewards store exists.
- -assetrewards=0 closes the stores without deleting them.
"""

import os

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

MESSAGING_DISABLED = "Messaging is disabled"
REWARDS_INACTIVE = "Reward stores are not open"


class AssetModulesTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], ['-assetindex']]

    def services(self, i):
        return self.nodes[i].getblockchaininfo()['asset_services']

    def messaging_enabled(self):
        # Enabled: the lists. Disabled: the explanatory string.
        node = self.nodes[0]
        results = [node.viewallmessages(), node.viewallmessagechannels()]
        if all(isinstance(r, list) for r in results):
            assert_equal(self.services(0)['messages']['active'], True)
            return True
        for r in results:
            assert r.startswith(MESSAGING_DISABLED), r
        assert_equal(self.services(0)['messages']['active'], False)
        return False

    def check_messaging(self, extra_args, expected):
        self.restart_node(0, extra_args)
        assert_equal(self.messaging_enabled(), expected)

    def rewards_active(self, i, extra_args):
        self.restart_node(i, extra_args)
        active = self.services(i)['rewards']['active']
        if self.services(i)['rewards']['assetindex']:
            if active:
                assert_equal(self.nodes[i].listsnapshotrequests(), [])
            else:
                assert_raises_rpc_error(-20, REWARDS_INACTIVE, self.nodes[i].listsnapshotrequests)
        return active

    def test_messaging(self):
        node = self.nodes[0]
        conf = os.path.join(node.datadir, "neurai.conf")
        with open(conf, encoding='utf8') as f:
            base_conf = f.read()

        # The messaging RPCs only answer once RIP5 is active (height 1 on regtest).
        node.generate(1)

        self.log.info("Fresh node: no messages store")
        assert_equal(self.messaging_enabled(), False)
        assert_equal(self.services(0)['messages']['store_on_disk'], False)

        self.log.info("-assetmessages creates the store; later starts keep it")
        self.check_messaging(["-assetmessages=1"], True)
        assert_equal(self.services(0)['messages']['store_on_disk'], True)
        self.check_messaging([], True)
        self.check_messaging(["-assetmessages=0"], False)
        self.check_messaging(["-noassetmessages"], False)
        assert_equal(self.services(0)['messages']['store_on_disk'], True)

        self.log.info("-disablemessaging forms")
        self.check_messaging(["-disablemessaging"], False)
        self.check_messaging(["-disablemessaging=1"], False)
        self.check_messaging(["-disablemessaging=0"], True)
        self.check_messaging(["-nodisablemessaging"], True)
        self.check_messaging(["-disablemessaging", "-assetmessages=0"], False)

        self.log.info("-disablemessaging with -assetmessages=1 is refused")
        self.stop_node(0)
        self.assert_start_raises_init_error(0, ["-disablemessaging", "-assetmessages=1"],
                                            "-disablemessaging cannot be combined with -assetmessages=1")
        self.start_node(0)

        self.log.info("Configuration file and command-line precedence")
        with open(conf, 'w', encoding='utf8') as f:
            f.write(base_conf + "disablemessaging=1\n")
        self.check_messaging([], False)
        self.check_messaging(["-disablemessaging=0"], True)
        self.check_messaging(["-nodisablemessaging"], True)

        with open(conf, 'w', encoding='utf8') as f:
            f.write(base_conf + "assetmessages=0\n")
        self.check_messaging([], False)
        self.check_messaging(["-assetmessages=1"], True)

        with open(conf, 'w', encoding='utf8') as f:
            f.write(base_conf)
        self.check_messaging([], True)
        assert_equal(self.services(0)['messages']['store_on_disk'], True)

    def test_rewards(self):
        self.log.info("Rewards without -assetindex: no store unless requested")
        assert_equal(self.rewards_active(0, []), False)
        assert_equal(self.services(0)['rewards']['store_on_disk'], False)
        assert_equal(self.rewards_active(0, ["-assetrewards=1"]), True)
        assert_equal(self.services(0)['rewards']['store_on_disk'], True)
        assert_equal(self.rewards_active(0, []), True)
        assert_equal(self.rewards_active(0, ["-assetrewards=0"]), False)
        assert_equal(self.services(0)['rewards']['store_on_disk'], True)

        self.log.info("Rewards with -assetindex: active by default")
        assert_equal(self.services(1)['rewards']['active'], True)
        assert_equal(self.services(1)['rewards']['store_on_disk'], True)
        assert_equal(self.rewards_active(1, ["-assetindex"]), True)
        assert_equal(self.rewards_active(1, ["-assetindex", "-assetrewards=0"]), False)
        assert_equal(self.services(1)['rewards']['store_on_disk'], True)
        assert_equal(self.rewards_active(1, ["-assetindex"]), True)

    def run_test(self):
        self.test_messaging()
        self.test_rewards()


if __name__ == '__main__':
    AssetModulesTest().main()
