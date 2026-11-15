#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
A purged message stays out when the purge was remembered by date only.

With no room left for a mark per message, a purge is remembered by the date of
the newest message it removed. That date is dropped once it is older than any
message the pool would admit, by a later purge or when the node starts. What it
refused must stay refused afterwards, also if the clock of the node goes back.

Both ways of dropping the date are exercised, through the signed requests.
"""

import time

from feature_depin_pool_state import DepinPoolStateTest, TOKEN
from test_framework.util import assert_equal, assert_raises_rpc_error

DAY = 24 * 3600
# Longer than the longest retention period the pool can be configured with
LATER = 31 * DAY


class DepinPurgeByDateTest(DepinPoolStateTest):
    def set_test_params(self):
        super().set_test_params()
        # One mark: a purge of two messages can only be remembered by date.
        # The clock moves by weeks and the chain does not follow it.
        self.depin_args += ['-depintombstonelimit=1', '-depinmaxtipage=4000000', '-maxtipage=4000000']
        self.extra_args = [self.depin_args]

    def purged_stays_out(self, owner, base, restart):
        node = self.nodes[0]
        node.setmocktime(base)
        node.generate(1)
        node.depinsendmsg(TOKEN, 'first purged message', owner)
        node.depinsendmsg(TOKEN, 'second purged message', owner)
        original = self.sequence_page(owner)['messages'][0]
        assert_equal(self.purge(owner)['removed'], 2)
        info = self.plain(self.info_response(node))
        assert_equal(info['tombstones'], 0)
        assert_raises_rpc_error(None, 'administratively deleted', self.submit, self.wrap(original))

        # The date of the purge is dropped...
        node.setmocktime(base + LATER)
        if restart:
            self.restart_node(0, self.depin_args + ['-mocktime=%d' % (base + LATER)])
        else:
            assert_equal(self.purge(owner)['removed'], 0)

        # ...and the clock goes back to when the message could be published
        node.setmocktime(base)
        assert_raises_rpc_error(None, 'retention floor', self.submit, self.wrap(original))
        assert_equal(self.plain(self.info_response(node))['messages'], 0)

    def run_test(self):
        node = self.nodes[0]
        node.generate(432)
        owner = node.getnewaddress()
        self.reveal(owner)
        node.issue(TOKEN, 100, owner)
        node.generate(1)
        now = int(time.time())

        self.log.info("The date is dropped by a later purge...")
        self.purged_stays_out(owner, now, restart=False)
        self.log.info("...or when the node starts")
        self.purged_stays_out(owner, now + 40 * DAY, restart=True)


if __name__ == '__main__':
    DepinPurgeByDateTest().main()
