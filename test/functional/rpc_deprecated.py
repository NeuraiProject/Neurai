#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Copyright (c) 2017-2020 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test deprecation of RPC calls."""

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal

class DeprecatedRpcTest(NeuraiTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], ["-deprecatedrpc=getmininginfo"]]

    def run_test(self):
        # Neurai removed the estimatefee deprecation gate, so it no longer needs
        # -deprecatedrpc. The getmininginfo "errors" field is the remaining
        # deprecated behaviour behind -deprecatedrpc.
        self.log.info("estimatefee: works without -deprecatedrpc")
        assert_equal(self.nodes[0].estimatefee(1), -1)

        self.log.info("getmininginfo: reports warnings, not the deprecated errors field")
        info = self.nodes[0].getmininginfo()
        assert 'warnings' in info
        assert 'errors' not in info

        self.log.info("Using -deprecatedrpc=getmininginfo restores the errors field")
        info = self.nodes[1].getmininginfo()
        assert 'errors' in info
        assert 'warnings' not in info

if __name__ == '__main__':
    DeprecatedRpcTest().main()
