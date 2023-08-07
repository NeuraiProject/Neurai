// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_WALLET_TEST_FIXTURE_H
#define NEURAI_WALLET_TEST_FIXTURE_H

#include "test/test_neurai.h"

/** Testing setup and teardown for wallet.
 */
struct WalletTestingSetup : public TestingSetup
{
    explicit WalletTestingSetup(const std::string &chainName = CBaseChainParams::MAIN);

    ~WalletTestingSetup();
};

#endif

