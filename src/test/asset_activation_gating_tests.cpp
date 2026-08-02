// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP revision 004: the height-based shortcut in AreAssetsDeployed()/
// IsRip5Active() must be gated by nAssetRip5ActivationByHeightEnabled, off on
// mainnet (VersionBits only, like origin/main) and on for fresh test networks.
// The per-network contract of the flag is asserted below; the lifecycle of the
// sticky globals behind AreAssetsDeployed()/IsRip5Active() (latch on a live
// chain, reset on UnloadBlockIndex) is covered by
// sticky_activation_flags_reset_on_unload, which drives a real chain via
// TestChain100Setup.

#include "chainparams.h"
#include "consensus/params.h"
#include "test/test_neurai.h"
#include "validation.h"
#include "versionbits.h"

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
        // Regtest mirrors testnet: assets/RIP5 activate by height (1).
        BOOST_CHECK(GetParams().GetConsensus().nAssetRip5ActivationByHeightEnabled);
        BOOST_CHECK_EQUAL(GetParams().GetAssetActivationHeight(), 1);
        BOOST_CHECK_EQUAL(GetParams().MessagingActivationBlock(), 1u);
        BOOST_CHECK_EQUAL(GetParams().RestrictedActivationBlock(), 1u);
    }
}

// Regression test for the state leak that broke versionbits_tests (147
// failures): a regtest chain activates assets via the height shortcut, and the
// sticky flag in validation.cpp used to survive UnloadBlockIndex(), so a later
// mainnet fixture saw AreAssetsDeployed() == true and ComputeBlockVersion()
// emitted VERSIONBITS_TOP_BITS_ASSETS (bit 28 set) instead of
// VERSIONBITS_TOP_BITS. The cycle exercised here is regtest-active →
// UnloadBlockIndex() → mainnet.
BOOST_FIXTURE_TEST_CASE(sticky_activation_flags_reset_on_unload, TestChain100Setup)
{
    // The 100-block regtest chain is past nAssetActivationHeight (1), so the
    // height shortcut has latched the sticky flag inside validation.cpp.
    BOOST_CHECK(AreAssetsDeployed());

    UnloadBlockIndex();

    NetworkGuard g(CBaseChainParams::MAIN);
    BOOST_CHECK(!AreAssetsDeployed());
    // The exact symptom seen in versionbits_tests: the assets-only version bit
    // must not leak into mainnet block versions.
    const int32_t assetsOnlyBits = VERSIONBITS_TOP_BITS_ASSETS & ~VERSIONBITS_TOP_BITS;
    BOOST_CHECK_EQUAL(ComputeBlockVersion(nullptr, GetParams().GetConsensus()) & assetsOnlyBits, 0);
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
