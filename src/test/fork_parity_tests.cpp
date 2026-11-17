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
#include "policy/policy.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "validation.h"

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
        {"nConsensusCleanupHeight", p.nConsensusCleanupHeight},
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

BOOST_AUTO_TEST_CASE(regtest_forkheight_moves_every_rule)
{
    // -forkheight goes through UpdateUnifiedForkHeight, the list mainnet
    // takes its heights from.
    SelectParams(CBaseChainParams::REGTEST);
    UpdateUnifiedForkHeight(777);
    for (const auto& height : ForkHeights(GetParams().GetConsensus())) {
        BOOST_CHECK_MESSAGE(height.second == 777, height.first << " did not move with -forkheight");
    }
    // The strict context default follows the moved height.
    BOOST_CHECK(!AreDepinAssetsActiveInContext());
    SelectParams(CBaseChainParams::MAIN);
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

        // DEPIN names keep that character too, in roots and in sections: the
        // owner token of the longest name is still a valid name.
        const std::string longDepin = "&" + std::string(119, 'D');
        const std::string longSection = "&DEVICE/" + std::string(112, 'S');
        for (const std::string& depin : {longDepin, longSection}) {
            BOOST_CHECK_EQUAL(depin.size(), 120u);
            BOOST_CHECK(IsAssetNameValid(depin));
            BOOST_CHECK(IsAssetNameValid(depin + "!"));
            BOOST_CHECK(!IsAssetNameValid(depin + "D"));
        }
        // A name over the limit reports an invalid type, not a stale one.
        AssetType type = AssetType::DEPIN;
        BOOST_CHECK(!IsAssetNameValid(longDepin + "DD", type));
        BOOST_CHECK(type == AssetType::INVALID);
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

BOOST_AUTO_TEST_CASE(block_size_limit_follows_the_fork_height)
{
    // Mainnet keeps the RIP2 limit until its fork height is set.
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params& main = mainnet->GetConsensus();
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(0, main), MAX_BLOCK_SERIALIZED_SIZE_RIP2);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(std::numeric_limits<int>::max() - 1, main), MAX_BLOCK_SERIALIZED_SIZE_RIP2);

    // Testnet and mainnet past the fork: 2 MB from the NIP-028 height on.
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const Consensus::Params& test = testnet->GetConsensus();
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(test.nBlockTimeReductionHeight - 1, test), MAX_BLOCK_SERIALIZED_SIZE_RIP2);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(test.nBlockTimeReductionHeight, test), MAX_BLOCK_SERIALIZED_SIZE_NIP028);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE_NIP028, 2000000U);

    // Regtest moves it with -forkheight.
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(1000, GetParams().GetConsensus()), MAX_BLOCK_SERIALIZED_SIZE_RIP2);
    UpdateUnifiedForkHeight(500);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(499, GetParams().GetConsensus()), MAX_BLOCK_SERIALIZED_SIZE_RIP2);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeAtHeight(500, GetParams().GetConsensus()), MAX_BLOCK_SERIALIZED_SIZE_NIP028);
    SelectParams(CBaseChainParams::MAIN);

    // Below 2 MB the weight limit cannot bind: a block of 2 MB weighs at most 8M.
    static_assert(MAX_BLOCK_SERIALIZED_SIZE_NIP028 * WITNESS_SCALE_FACTOR <= MAX_BLOCK_WEIGHT_RIP2,
                  "the size limit must be the one that binds");
}

BOOST_AUTO_TEST_CASE(relay_work_limits_follow_the_fork_height)
{
    // Mainnet keeps the old relay limits until its fork height is set.
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params& main = mainnet->GetConsensus();
    const int never = std::numeric_limits<int>::max() - 1;
    BOOST_CHECK_EQUAL(GetMaxStandardTxPoseidonWork(never, main), MAX_STANDARD_TX_POSEIDON_WORK);
    BOOST_CHECK_EQUAL(GetMaxStandardTxAssetAuthWork(never, main), MAX_STANDARD_TX_ASSETAUTH_WORK);
    BOOST_CHECK_EQUAL(GetMaxStandardTxWitnessSigOps(never, main), std::numeric_limits<int64_t>::max());

    // Testnet: lower from the NIP-028 height on.
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const Consensus::Params& test = testnet->GetConsensus();
    const int h = test.nBlockTimeReductionHeight;
    BOOST_CHECK_EQUAL(GetMaxStandardTxPoseidonWork(h - 1, test), MAX_STANDARD_TX_POSEIDON_WORK);
    BOOST_CHECK_EQUAL(GetMaxStandardTxPoseidonWork(h, test), 5000U);
    BOOST_CHECK_EQUAL(GetMaxStandardTxAssetAuthWork(h - 1, test), MAX_STANDARD_TX_ASSETAUTH_WORK);
    BOOST_CHECK_EQUAL(GetMaxStandardTxAssetAuthWork(h, test), 15000U);
    BOOST_CHECK_EQUAL(GetMaxStandardTxWitnessSigOps(h - 1, test), std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(GetMaxStandardTxWitnessSigOps(h, test), 2000);
}

BOOST_AUTO_TEST_CASE(block_work_budgets_follow_the_fork_height)
{
    // Mainnet keeps the budgets until its fork height is set.
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params& main = mainnet->GetConsensus();
    const int never = std::numeric_limits<int>::max() - 1;
    BOOST_CHECK_EQUAL(GetMaxBlockPoseidonWork(never, main), 200000U);
    BOOST_CHECK_EQUAL(GetMaxBlockAssetAuthWork(never, main), 450000U);

    // From the NIP-028 height on, half: the same work per second with blocks
    // of 30 s (B2-a).
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const Consensus::Params& test = testnet->GetConsensus();
    const int h = test.nBlockTimeReductionHeight;
    BOOST_CHECK_EQUAL(GetMaxBlockPoseidonWork(h - 1, test), MAX_BLOCK_POSEIDON_WORK);
    BOOST_CHECK_EQUAL(GetMaxBlockPoseidonWork(h, test), 100000U);
    BOOST_CHECK_EQUAL(GetMaxBlockAssetAuthWork(h - 1, test), MAX_BLOCK_ASSETAUTH_WORK);
    BOOST_CHECK_EQUAL(GetMaxBlockAssetAuthWork(h, test), 225000U);

    // Regtest moves them with the NIP-028 height.
    SelectParams(CBaseChainParams::REGTEST);
    UpdateBlockTimeReductionHeight(500);
    BOOST_CHECK_EQUAL(GetMaxBlockPoseidonWork(499, GetParams().GetConsensus()), MAX_BLOCK_POSEIDON_WORK);
    BOOST_CHECK_EQUAL(GetMaxBlockPoseidonWork(500, GetParams().GetConsensus()), MAX_BLOCK_POSEIDON_WORK_NIP028);
    BOOST_CHECK_EQUAL(GetMaxBlockAssetAuthWork(499, GetParams().GetConsensus()), MAX_BLOCK_ASSETAUTH_WORK);
    BOOST_CHECK_EQUAL(GetMaxBlockAssetAuthWork(500, GetParams().GetConsensus()), MAX_BLOCK_ASSETAUTH_WORK_NIP028);
    UpdateBlockTimeReductionHeight(std::numeric_limits<int>::max());
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(ed25519_counts_three_sigops_from_the_fork_height)
{
    // The sigops of one OP_CHECKSIG_ED25519 under each set of flags.
    BOOST_CHECK_EQUAL(GetEd25519SigOps(SCRIPT_VERIFY_NONE), 0U);
    BOOST_CHECK_EQUAL(GetEd25519SigOps(SCRIPT_VERIFY_ED25519_COST), 0U);   // opcode not active
    BOOST_CHECK_EQUAL(GetEd25519SigOps(SCRIPT_VERIFY_ED25519), 1U);
    BOOST_CHECK_EQUAL(GetEd25519SigOps(SCRIPT_VERIFY_ED25519 | SCRIPT_VERIFY_ED25519_COST), 3U);
    BOOST_CHECK(CONSENSUS_OPT_IN_FLAGS & SCRIPT_VERIFY_ED25519_COST);

    // The flag follows the NIP-028 height, on its own as well.
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const int never = std::numeric_limits<int>::max() - 1;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, mainnet->GetConsensus(), false, never) & SCRIPT_VERIFY_ED25519_COST));
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const Consensus::Params& test = testnet->GetConsensus();
    const int h = test.nBlockTimeReductionHeight;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, test, true, h - 1) & SCRIPT_VERIFY_ED25519_COST));
    BOOST_CHECK_EQUAL(GetEd25519SigOps(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, test, true, h)), 3U);
    SelectParams(CBaseChainParams::REGTEST);
    UpdateBlockTimeReductionHeight(500);
    BOOST_CHECK_EQUAL(GetEd25519SigOps(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, GetParams().GetConsensus(), true, 499)), 1U);
    BOOST_CHECK_EQUAL(GetEd25519SigOps(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, GetParams().GetConsensus(), true, 500)), 3U);
    UpdateBlockTimeReductionHeight(std::numeric_limits<int>::max());
    SelectParams(CBaseChainParams::MAIN);

    // Counting, in a script and in a witness script.
    const CScript script = CScript() << OP_CHECKSIG_ED25519 << OP_CHECKSIG_ED25519 << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true, false, false, 0), 1U);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true, false, false, 1), 3U);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true, false, false, ED25519_SIGOP_COST), 7U);
    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>(script.begin(), script.end()));
    const CScript p2wsh = GetScriptForWitness(script);
    const script_verify_flags flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_ED25519;
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), p2wsh, &witness, flags), 3U);
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), p2wsh, &witness, flags | SCRIPT_VERIFY_ED25519_COST), 7U);

    // A block holds 26,666 checks, 79,998 sigops; 26,667 are over the limit.
    static_assert(26666 * ED25519_SIGOP_COST <= MAX_BLOCK_SIGOPS_COST, "26,666 checks fit");
    static_assert(26667 * ED25519_SIGOP_COST > MAX_BLOCK_SIGOPS_COST, "26,667 checks do not");
}

BOOST_AUTO_TEST_CASE(work_weight_follows_the_fork_height)
{
    // A block's budget of Poseidon permutations, or of OP_CHECKASSETAUTH
    // units, from the NIP-028 height weighs as much as a full block (8,000,000).
    BOOST_CHECK_EQUAL(WORK_WEIGHT_PER_POSEIDON_PERMUTATION, 80);
    BOOST_CHECK_EQUAL(WORK_WEIGHT_PER_ASSETAUTH_UNIT, 36);

    // Mainnet: no work weight until its fork height is set.
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const int never = std::numeric_limits<int>::max() - 1;
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(5000, 15000, never, mainnet->GetConsensus()), 0);

    // Testnet: from the NIP-028 height on, the larger of the two works.
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const Consensus::Params& test = testnet->GetConsensus();
    const int h = test.nBlockTimeReductionHeight;
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(5000, 15000, h - 1, test), 0);
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(5000, 0, h, test), 400000);
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(0, 15000, h, test), 540000);
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(5000, 15000, h, test), 540000);
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(701, 0, h, test), 56080);   // a C7 operation measured on testnet
    // No overflow.
    BOOST_CHECK_EQUAL(GetTransactionWorkWeight(std::numeric_limits<uint64_t>::max(), 0, h, test),
                      std::numeric_limits<int64_t>::max() / 80 * 80);

    // The virtual size is the largest of the weight, the sigops and the work,
    // rounded up to whole vbytes.
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(4000, 0, 0), 1000);
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(4001, 0, 0), 1001);
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(4000, 0, 200000), 50000);
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(4000, 20000, 200000), 100000);   // 20 bytes per sigop
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(300000, 0, 200000), 75000);
    BOOST_CHECK_EQUAL(GetVirtualTransactionSize(4000, 0), GetVirtualTransactionSize(4000, 0, 0));
}

BOOST_AUTO_TEST_CASE(mandatory_flags_are_consensus_on_every_network)
{
    // A mempool script failure under the mandatory flags bans the peer, so
    // every block on every network must enforce them.
    for (const std::string& network : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST}) {
        const auto chainparams = CreateChainParams(network);
        const Consensus::Params& params = chainparams->GetConsensus();
        BOOST_CHECK_MESSAGE(params.nBIP66Enabled && params.nBIP65Enabled && params.nCSVEnabled && params.nSegwitEnabled,
                            network << " does not enforce every mandatory flag");
    }
    BOOST_CHECK(bool(MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
    BOOST_CHECK((STANDARD_SCRIPT_VERIFY_FLAGS & MANDATORY_SCRIPT_VERIFY_FLAGS) == MANDATORY_SCRIPT_VERIFY_FLAGS);
    BOOST_CHECK(!(MANDATORY_SCRIPT_VERIFY_FLAGS & CONSENSUS_OPT_IN_FLAGS));
}

BOOST_AUTO_TEST_CASE(rejections_near_the_fork_do_not_ban)
{
    const int K = FORK_ACTIVATION_GRACE_BLOCKS;
    SelectParams(CBaseChainParams::REGTEST);
    UpdateUnifiedForkHeight(500);
    const Consensus::Params& regtest = GetParams().GetConsensus();
    // The window covers every next block whose neighbours within K blocks
    // run other rules: [H - K, H + K).
    BOOST_CHECK(!IsNearForkActivation(regtest, 500 - K - 1));
    BOOST_CHECK(IsNearForkActivation(regtest, 500 - K));
    BOOST_CHECK(IsNearForkActivation(regtest, 499));
    BOOST_CHECK(IsNearForkActivation(regtest, 500));
    BOOST_CHECK(IsNearForkActivation(regtest, 500 + K - 1));
    BOOST_CHECK(!IsNearForkActivation(regtest, 500 + K));

    // A rule moved on its own opens its own window.
    UpdateZKPublicTreeHeight(700);
    BOOST_CHECK(IsNearForkActivation(regtest, 700));
    BOOST_CHECK(!IsNearForkActivation(regtest, 700 + K));

    // Mainnet has no fork height yet: no window anywhere.
    SelectParams(CBaseChainParams::MAIN);
    for (const int nHeight : {0, 1, 1000000, 10000000}) {
        BOOST_CHECK(!IsNearForkActivation(GetParams().GetConsensus(), nHeight));
    }
}

BOOST_AUTO_TEST_SUITE_END()
