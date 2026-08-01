// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "pow.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

    /* Test calculation of next difficulty target with no constraints applying */
    BOOST_AUTO_TEST_CASE(get_next_work_test)
    {
        BOOST_TEST_MESSAGE("Running Get Next Work Test");

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        int64_t nLastRetargetTime = 1261130161; // Block #30240
        CBlockIndex pindexLast;
        pindexLast.nHeight = 32255;
        pindexLast.nTime = 1262152739;  // Block #32255
        pindexLast.nBits = 0x1e00ffff;
        BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), (uint64_t)0x1e03fffc);
    }

    /* Test the constraint on the upper bound for next work */
    BOOST_AUTO_TEST_CASE(get_next_work_pow_limit_test)
    {
        BOOST_TEST_MESSAGE("Running Get Next Work POW Limit Test");

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        int64_t nLastRetargetTime = 1231006505; // Block #0
        CBlockIndex pindexLast;
        pindexLast.nHeight = 2015;
        pindexLast.nTime = 1233061996;  // Block #2015
        pindexLast.nBits = 0x1e00ffff;
        BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), (uint64_t)0x1e03fffc);
    }

    /* Test the constraint on the lower bound for actual time taken */
    BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual_test)
    {
        BOOST_TEST_MESSAGE("Running Get Next Work Lower Limit Actual Test");

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        int64_t nLastRetargetTime = 1279008237; // Block #66528
        CBlockIndex pindexLast;
        pindexLast.nHeight = 68543;
        pindexLast.nTime = 1279297671;  // Block #68543
        pindexLast.nBits = 0x1e00ffff;
        BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), (uint64_t)0x1e02648c);
    }

    /* Test the constraint on the upper bound for actual time taken */
    BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual_test)
    {
        BOOST_TEST_MESSAGE("Running Get Next Work Upper Limit Actual  Test");

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
        CBlockIndex pindexLast;
        pindexLast.nHeight = 46367;
        pindexLast.nTime = 1269211443;  // Block #46367
        pindexLast.nBits = 0x1e00ffff;
        BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), (uint64_t)0x1e03fffc);
    }

    BOOST_AUTO_TEST_CASE(get_block_proof_equivalent_time_test)
    {
        BOOST_TEST_MESSAGE("Running Get Block Proof Equivalent Time Test");

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        std::vector<CBlockIndex> blocks(10000);
        for (int i = 0; i < 10000; i++)
        {
            blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
            blocks[i].nHeight = i;
            blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
            blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
            blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
        }

        for (int j = 0; j < 1000; j++)
        {
            CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
            CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
            CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

            int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
            BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
        }
    }

    // bNetwork is a process-wide global that SetNetwork only ever flips to
    // true, and the test harness never calls it (fixtures use
    // SelectParams(chain) without fForceBlockNetwork) -- save and restore
    // all three flags so the switch cannot leak into other suites.
    struct BlockNetworkGuard
    {
        bool prevTestnet;
        bool prevRegtest;
        bool prevSHA256;
        BlockNetworkGuard()
            : prevTestnet(bNetwork.fOnTestnet),
              prevRegtest(bNetwork.fOnRegtest),
              prevSHA256(bNetwork.fSHA256Mining) {}
        ~BlockNetworkGuard()
        {
            bNetwork.fOnTestnet = prevTestnet;
            bNetwork.fOnRegtest = prevRegtest;
            bNetwork.fSHA256Mining = prevSHA256;
        }
    };

    // Regression for the regtest mining algorithm: SetNetwork("regtest")
    // must select double-SHA256 header hashing, the same path testnet uses.
    // Before the fix only "test" set fSHA256Mining, silently leaving the
    // regtest daemon on X16R with real DGW retargeting.
    BOOST_AUTO_TEST_CASE(regtest_header_hash_is_sha256d)
    {
        BlockNetworkGuard guard;
        bNetwork.SetNetwork("regtest");
        BOOST_CHECK(bNetwork.fOnRegtest);
        BOOST_CHECK(bNetwork.fSHA256Mining);

        CBlockHeader header;
        header.nVersion = 2;
        header.hashPrevBlock = uint256S("0x01");
        header.hashMerkleRoot = uint256S("0x02");
        header.nTime = 1700000000; // pre-KAWPOW-activation: must not matter
        header.nBits = 0x207fffff;
        header.nNonce = 7;

        const uint256 expected = Hash(BEGIN(header.nVersion), END(header.nNonce));
        BOOST_CHECK_EQUAL(header.GetHash().ToString(), expected.ToString());

        // GetHashFull must take the same path and report no KAWPOW mix hash.
        uint256 mix_hash = uint256S("0xff");
        BOOST_CHECK_EQUAL(header.GetHashFull(mix_hash).ToString(), expected.ToString());
        BOOST_CHECK(mix_hash.IsNull());

        // And it is genuinely not the X16R-family hash regtest used to compute.
        BOOST_CHECK(header.GetHash() != header.GetX16RHash());
    }

BOOST_AUTO_TEST_SUITE_END()
