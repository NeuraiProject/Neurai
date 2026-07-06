// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP revision 004: the height-based shortcut in AreAssetsDeployed()/
// IsRip5Active() must be gated by nAssetRip5ActivationByHeightEnabled, off on
// mainnet (VersionBits only, like origin/main) and on for fresh test networks.
// AreAssetsDeployed()/IsRip5Active() depend on chainActive and a sticky global,
// so they are not cheaply unit-testable; the per-network contract of the flag
// is the stable thing to assert.

#include "chainparams.h"
#include "consensus/params.h"
#include "test/test_neurai.h"

#include <string>

#include <boost/test/unit_test.hpp>

namespace {

// RAII guard: SelectParams mutates the global CChainParams; restore it so the
// switch does not leak into later test cases.
struct NetworkGuard {
    std::string previous;
    explicit NetworkGuard(const std::string& net) : previous(GetParams().NetworkIDString()) {
        SelectParams(net);
    }
    ~NetworkGuard() {
        if (previous == "main") SelectParams(CBaseChainParams::MAIN);
        else if (previous == "test") SelectParams(CBaseChainParams::TESTNET);
        else SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_activation_gating_tests, BasicTestingSetup)

// Test 0: per-network contract of the flag.
BOOST_AUTO_TEST_CASE(asset_rip5_height_shortcut_flag_per_network)
{
    {
        NetworkGuard g(CBaseChainParams::MAIN);
        // Mainnet must not use the height shortcut → VersionBits only (origin/main).
        BOOST_CHECK(!GetParams().GetConsensus().nAssetRip5ActivationByHeightEnabled);
    }
    {
        NetworkGuard g(CBaseChainParams::TESTNET);
        // Testnet activates assets/RIP5 early by height (1).
        BOOST_CHECK(GetParams().GetConsensus().nAssetRip5ActivationByHeightEnabled);
    }
    {
        NetworkGuard g(CBaseChainParams::REGTEST);
        // Regtest: flag on, but inert because its heights are 0 (the shortcut's
        // `> 0` guard skips it → VersionBits); behaviour unchanged either way.
        BOOST_CHECK(GetParams().GetConsensus().nAssetRip5ActivationByHeightEnabled);
        BOOST_CHECK_EQUAL(GetParams().GetAssetActivationHeight(), 0);
        BOOST_CHECK_EQUAL(GetParams().MessagingActivationBlock(), 0u);
    }
}

// Guard against a future regression that zeroes the mainnet heights: those
// params still feed IsMessagingActive/messages.cpp and must stay at their
// origin/main value of 10 (the fix gates the shortcut, it does not touch them).
BOOST_AUTO_TEST_CASE(mainnet_activation_heights_unchanged)
{
    NetworkGuard g(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(GetParams().GetAssetActivationHeight(), 10);
    BOOST_CHECK_EQUAL(GetParams().MessagingActivationBlock(), 10u);
}

BOOST_AUTO_TEST_SUITE_END()
