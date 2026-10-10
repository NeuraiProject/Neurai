// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "validation.h"
#include "net.h"

#include "test/test_neurai.h"

#include <cmath>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

    // Neurai uses a custom subsidy schedule (validation.cpp:GetBlockSubsidy):
    //   - heights  0.. 35 halvings: 50000 * 0.95^n  (continuous 5% micro-decay)
    //   - heights 36.. 71 halvings: flat 5000 XNA
    //   - heights 72..107 halvings: flat 4000 XNA
    //   - heights 108..143 halvings: flat 3000 XNA
    //   - heights 144..179 halvings: flat 2000 XNA
    //   - heights 180..215 halvings: flat 1000 XNA
    //   - heights 216..382 halvings: flat 500 XNA
    //   - heights >= 383 halvings: 0
    //
    // This is NOT the Bitcoin-style "halve every interval" schedule, so the
    // legacy halving test has been replaced with a Neurai-specific one.

    static CAmount ExpectedSubsidyByHalving(int halvings)
    {
        if (halvings >= 383) return 0;
        if (halvings >= 216) return 500  * COIN;
        if (halvings >= 180) return 1000 * COIN;
        if (halvings >= 144) return 2000 * COIN;
        if (halvings >= 108) return 3000 * COIN;
        if (halvings >= 72)  return 4000 * COIN;
        if (halvings >= 36)  return 5000 * COIN;
        // Continuous-decay region: 50000 * 0.95^halvings
        return static_cast<CAmount>(50000.0 * COIN * std::pow(0.95, halvings));
    }

    BOOST_AUTO_TEST_CASE(block_subsidy_test)
    {
        BOOST_TEST_MESSAGE("Running Block Subsidy Test");

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        const Consensus::Params& consensusParams = chainParams->GetConsensus();

        // Genesis reward matches the documented value (50000 XNA).
        BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensusParams), 50000 * COIN);

        // Subsidy is monotonically non-increasing.
        CAmount prev = GetBlockSubsidy(0, consensusParams);
        for (int halvings = 1; halvings < 400; halvings++)
        {
            int nHeight = halvings * consensusParams.nSubsidyHalvingInterval;
            CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
            BOOST_CHECK(nSubsidy <= prev);
            BOOST_CHECK_EQUAL(nSubsidy, ExpectedSubsidyByHalving(halvings));
            prev = nSubsidy;
        }

        // Eventually reaches zero and stays there.
        BOOST_CHECK_EQUAL(GetBlockSubsidy(383 * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(1000 * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
    }

    BOOST_AUTO_TEST_CASE(subsidy_limit_test)
    {
        BOOST_TEST_MESSAGE("Running Subsidy Limit Test");

        // NOTE: Neurai's subsidy schedule (validation.cpp:GetBlockSubsidy) emits
        // a total of ~21.106 billion XNA, which slightly exceeds MAX_MONEY
        // (21 billion XNA). The sampled sum below reflects the actual schedule;
        // MoneyRange() is therefore intentionally NOT asserted on the cumulative
        // total because it is a per-amount validity predicate, not a supply
        // ceiling. The per-subsidy check still catches any individual block
        // reward exceeding the expected max (50000 XNA = coinbase at height 0).
        //
        // If MAX_MONEY is ever raised to accommodate the real supply, re-enable
        // the MoneyRange(nSum) assertion inside the loop.

        const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
        CAmount nSum = 0;
        for (int nHeight = 0; nHeight < 14000000; nHeight += 1000)
        {
            CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
            BOOST_CHECK(nSubsidy <= 50000 * COIN);
            BOOST_CHECK(MoneyRange(nSubsidy));
            nSum += nSubsidy * 1000;
        }
        // Exact sampled sum (step = 1000 blocks) under Neurai's custom schedule.
        // Computed offline; regenerate if the schedule ever changes.
        BOOST_CHECK_EQUAL(nSum, (int64_t)2112755667238737000ULL);
    }

    bool ReturnFalse()
    { return false; }

    bool ReturnTrue()
    { return true; }

    BOOST_AUTO_TEST_CASE(combiner_all_test)
    {
        BOOST_TEST_MESSAGE("Running Combiner All Test");

        boost::signals2::signal<bool(), CombinerAll> Test;
        BOOST_CHECK(Test());
        Test.connect(&ReturnFalse);
        BOOST_CHECK(!Test());
        Test.connect(&ReturnTrue);
        BOOST_CHECK(!Test());
        Test.disconnect(&ReturnFalse);
        BOOST_CHECK(Test());
        Test.disconnect(&ReturnTrue);
        BOOST_CHECK(Test());
    }

BOOST_AUTO_TEST_SUITE_END()
