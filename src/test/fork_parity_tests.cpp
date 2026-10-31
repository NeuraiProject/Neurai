// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unified fork: mainnet adopts at once every rule that testnet and regtest run.
// Every activation height comes from one constant (MAINNET_FORK_HEIGHT) and,
// past it, mainnet must apply the same rules as testnet. Rules that once
// depended on the network name follow the activation height instead.

#include "assets/assets.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"

#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

// Every activation height of the unified fork. A rule added to testnet must be
// added here, so that mainnet cannot be left without it.
std::vector<std::pair<std::string, int>> ForkHeights(const Consensus::Params& p)
{
    return {
        {"nOptInFeaturesHeight", p.nOptInFeaturesHeight},
        {"nStrictAuthScriptHeight", p.nStrictAuthScriptHeight},
        {"nSignatureOpcodesHeight", p.nSignatureOpcodesHeight},
        {"nTxHashHeight", p.nTxHashHeight},
        {"nZKVerifyHeight", p.nZKVerifyHeight},
        {"nZKPublicTreeHeight", p.nZKPublicTreeHeight},
        {"nZKPortableTreeHeight", p.nZKPortableTreeHeight},
        {"nPoseidonWorkHeight", p.nPoseidonWorkHeight},
        {"nAuthScriptBudgetHeight", p.nAuthScriptBudgetHeight},
        {"nAssetMessageHeight", p.nAssetMessageHeight},
        {"nInputFieldHeight", p.nInputFieldHeight},
        {"nAuthScriptTreeHeight", p.nAuthScriptTreeHeight},
        {"nMerklePoseidonHeight", p.nMerklePoseidonHeight},
        {"nAssetAuthHeight", p.nAssetAuthHeight},
        {"nAssetMarkerNip040Height", p.nAssetMarkerNip040Height},
        {"nDepinTransferStateHeight", p.nDepinTransferStateHeight},
        {"nNoRbfHeight", p.nNoRbfHeight},
        {"nBlockTimeReductionHeight", p.nBlockTimeReductionHeight},
    };
}

// Every switch the unified fork schedules; each applies from
// nOptInFeaturesHeight (and nSignatureOpcodesHeight where noted in params.h).
std::vector<std::pair<std::string, bool>> ForkSwitches(const Consensus::Params& p)
{
    return {
        {"nPQWitnessEnabled", p.nPQWitnessEnabled},
        {"nCATEnabled", p.nCATEnabled},
        {"nCTVEnabled", p.nCTVEnabled},
        {"nCSFSEnabled", p.nCSFSEnabled},
        {"nTXFIELDEnabled", p.nTXFIELDEnabled},
        {"nSPLITEnabled", p.nSPLITEnabled},
        {"nREVERSEBYTESEnabled", p.nREVERSEBYTESEnabled},
        {"nOUTPUTVALUEEnabled", p.nOUTPUTVALUEEnabled},
        {"nOUTPUTSCRIPTEnabled", p.nOUTPUTSCRIPTEnabled},
        {"nOUTPUTASSETFIELDEnabled", p.nOUTPUTASSETFIELDEnabled},
        {"nINPUTASSETFIELDEnabled", p.nINPUTASSETFIELDEnabled},
        {"n64BitIntegersEnabled", p.n64BitIntegersEnabled},
        {"nTXLOCKTIMEEnabled", p.nTXLOCKTIMEEnabled},
        {"nINPUTOUTPUTCOUNTEnabled", p.nINPUTOUTPUTCOUNTEnabled},
        {"nREFINPUTSEnabled", p.nREFINPUTSEnabled},
        {"nOUTPUTAUTHCOMMITMENTEnabled", p.nOUTPUTAUTHCOMMITMENTEnabled},
        {"nINPUTVALUEEnabled", p.nINPUTVALUEEnabled},
        {"nCHAINCONTEXTEnabled", p.nCHAINCONTEXTEnabled},
        {"nXNAAssetStrictEnabled", p.nXNAAssetStrictEnabled},
        {"nKeccakBlake2bEnabled", p.nKeccakBlake2bEnabled},
        {"nMerkleInclusionEnabled", p.nMerkleInclusionEnabled},
        {"nModernHashesEnabled", p.nModernHashesEnabled},
        {"nPoseidonEnabled", p.nPoseidonEnabled},
        {"nEd25519Enabled", p.nEd25519Enabled},
        {"nCheckSigAddEnabled", p.nCheckSigAddEnabled},
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fork_parity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mainnet_schedules_every_rule_at_one_height)
{
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params& main = mainnet->GetConsensus();
    const int nForkHeight = main.nOptInFeaturesHeight;

    for (const auto& height : ForkHeights(main)) {
        BOOST_CHECK_MESSAGE(height.second == nForkHeight,
            height.first << " is " << height.second << " on mainnet, not the fork height " << nForkHeight);
    }
    for (const auto& sw : ForkSwitches(main)) {
        BOOST_CHECK_MESSAGE(sw.second, sw.first << " is not scheduled on mainnet");
    }

    // The fork height is not set yet: no block applies any of these rules and
    // nothing that only checks whether a rule is scheduled sees one. Update
    // this check together with MAINNET_FORK_HEIGHT.
    BOOST_CHECK_EQUAL(nForkHeight, std::numeric_limits<int>::max());
    for (const auto& sw : ForkSwitches(main)) {
        BOOST_CHECK_MESSAGE(!main.IsOptInScheduled(sw.second), sw.first << " counts as scheduled on mainnet");
    }
}

BOOST_AUTO_TEST_CASE(mainnet_past_the_fork_matches_testnet)
{
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const Consensus::Params& main = mainnet->GetConsensus();
    const Consensus::Params& test = testnet->GetConsensus();

    const auto mainSwitches = ForkSwitches(main);
    const auto testSwitches = ForkSwitches(test);
    BOOST_REQUIRE_EQUAL(mainSwitches.size(), testSwitches.size());
    for (size_t i = 0; i < mainSwitches.size(); ++i) {
        BOOST_CHECK_MESSAGE(mainSwitches[i].second == testSwitches[i].second,
            mainSwitches[i].first << " differs between mainnet and testnet");
    }
    // Every height of testnet is a real activation height too.
    for (const auto& height : ForkHeights(test)) {
        BOOST_CHECK_MESSAGE(height.second != std::numeric_limits<int>::max(),
            height.first << " is not scheduled on testnet");
    }

    // NIP-028 values from the block-time reduction on.
    BOOST_CHECK_EQUAL(main.nPowTargetSpacingPost, test.nPowTargetSpacingPost);
    BOOST_CHECK_EQUAL(main.nPowTargetTimespanPost, test.nPowTargetTimespanPost);
    BOOST_CHECK_EQUAL(main.nSubsidyHalvingIntervalPost, test.nSubsidyHalvingIntervalPost);
    const int nPast = std::numeric_limits<int>::max();
    BOOST_CHECK_EQUAL(mainnet->MaxReorganizationDepth(nPast), testnet->MaxReorganizationDepth(nPast));
    // Before the block-time reduction mainnet keeps its legacy values.
    BOOST_CHECK_EQUAL(mainnet->MaxReorganizationDepth(0), 60);
    BOOST_CHECK_EQUAL(main.nPowTargetSpacing, 60);
}

BOOST_AUTO_TEST_CASE(intentional_network_divergences)
{
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const auto regtest = CreateChainParams(CBaseChainParams::REGTEST);
    const Consensus::Params& main = mainnet->GetConsensus();
    const Consensus::Params& test = testnet->GetConsensus();

    // Mainnet keeps VersionBits for assets and RIP5, as origin/main.
    BOOST_CHECK(!main.nAssetRip5ActivationByHeightEnabled);
    BOOST_CHECK(!main.nAssetsActiveFromGenesis);
    BOOST_CHECK(test.nAssetRip5ActivationByHeightEnabled);
    BOOST_CHECK(test.nAssetsActiveFromGenesis);
    BOOST_CHECK(!main.fPowAllowMinDifficultyBlocks);

    // Coinbase maturity is a network parameter, not a fork rule.
    BOOST_CHECK_EQUAL(main.nCoinbaseMaturity, COINBASE_MATURITY);
    BOOST_CHECK_EQUAL(test.nCoinbaseMaturity, COINBASE_MATURITY_TESTNET);
    BOOST_CHECK_EQUAL(regtest->GetConsensus().nCoinbaseMaturity, COINBASE_MATURITY);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), COINBASE_MATURITY); // fixture selects mainnet
}

BOOST_AUTO_TEST_CASE(depin_assets_follow_the_activation_context)
{
    // The fixture selects mainnet. Validation scopes the context to the
    // height of each block; here it is set by hand on both sides of the fork.
    // Root names keep one character of the limit for the owner tag ('!').
    const std::string legacyName(30, 'A');
    const std::string longName(120, 'A');
    {
        CStrictAuthScriptContext beforeFork(false);
        BOOST_CHECK(!AreDepinAssetsActiveInContext());
        BOOST_CHECK_EQUAL(GetMaxAssetNameLength(), 31);
        BOOST_CHECK(!IsAssetNameValid("&DEVICE"));
        BOOST_CHECK(!IsAssetNameValid("&DEVICE/SECTION"));
        BOOST_CHECK(IsAssetNameValid(legacyName));
        BOOST_CHECK(!IsAssetNameValid(legacyName + "A"));
        BOOST_CHECK(!IsAssetNameValid(longName));
    }
    {
        CStrictAuthScriptContext pastFork(true);
        BOOST_CHECK(AreDepinAssetsActiveInContext());
        BOOST_CHECK_EQUAL(GetMaxAssetNameLength(), 121);
        BOOST_CHECK(IsAssetNameValid("&DEVICE"));
        BOOST_CHECK(IsAssetNameValid("&DEVICE/SECTION"));
        BOOST_CHECK(IsAssetNameValid(longName));
        BOOST_CHECK(!IsAssetNameValid(longName + "A"));
    }
    // Without a scope, mainnet sees the block after the tip: before the fork.
    BOOST_CHECK(!AreDepinAssetsActiveInContext());
}

BOOST_AUTO_TEST_CASE(op_return_limit_follows_the_fork_height)
{
    // Mainnet, fork height unset.
    BOOST_CHECK_EQUAL(GetMaxOPReturnRelay(), MAX_OP_RETURN_RELAY);

    SelectParams(CBaseChainParams::REGTEST);
    UpdateOptInFeaturesHeight(50);
    SetSignatureOpcodeCandidateHeight(49);
    BOOST_CHECK_EQUAL(GetMaxOPReturnRelay(), MAX_OP_RETURN_RELAY);
    BOOST_CHECK_EQUAL(GetMaxDatacarrierBytes(), MAX_OP_RETURN_RELAY);
    SetSignatureOpcodeCandidateHeight(50);
    BOOST_CHECK_EQUAL(GetMaxOPReturnRelay(), MAX_OP_RETURN_RELAY_FORK);
    BOOST_CHECK_EQUAL(GetMaxDatacarrierBytes(), MAX_OP_RETURN_RELAY_FORK);

    // -datacarriersize wins on both sides of the fork.
    fMaxDatacarrierBytesSet = true;
    nMaxDatacarrierBytes = 100;
    BOOST_CHECK_EQUAL(GetMaxDatacarrierBytes(), 100U);
    SetSignatureOpcodeCandidateHeight(49);
    BOOST_CHECK_EQUAL(GetMaxDatacarrierBytes(), 100U);

    fMaxDatacarrierBytesSet = false;
    nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
