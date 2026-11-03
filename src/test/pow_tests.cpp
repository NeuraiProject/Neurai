// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "hash.h"
#include "pow.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <vector>

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

    // NIP-028 on mainnet: Dark Gravity Wave across the unified fork height H,
    // where the target spacing goes from 60 to 30 seconds. Blocks are built in
    // memory with mainnet parameters (KAWPOW, every window block KAWPOW).

    static const int FORK_HEIGHT = 1900000;
    static const uint32_t SIMULATION_START_TIME = 1800000000;
    static const uint32_t EQUILIBRIUM_BITS = 0x1b0404cb;

    static Consensus::Params MainnetWithFork(int nForkHeight)
    {
        Consensus::Params params = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
        params.nBlockTimeReductionHeight = nForkHeight;
        return params;
    }

    // Blocks [nFirstHeight, nFirstHeight + count), linked; the vector never
    // reallocates so pprev stays valid.
    struct SimulatedChain
    {
        std::vector<CBlockIndex> blocks;
        SimulatedChain(int nFirstHeight, size_t capacity) : nFirst(nFirstHeight) { blocks.reserve(capacity); }
        int nFirst;
        CBlockIndex& Tip() { return blocks.back(); }
        void Add(uint32_t nTime, uint32_t nBits)
        {
            BOOST_REQUIRE(blocks.size() < blocks.capacity());
            CBlockIndex index;
            index.pprev = blocks.empty() ? nullptr : &blocks.back();
            index.nHeight = nFirst + blocks.size();
            index.nTime = nTime;
            index.nBits = nBits;
            blocks.push_back(index);
        }
        uint32_t NextBits(const Consensus::Params& params)
        {
            CBlockHeader header;
            header.nTime = Tip().nTime + 1;
            return GetNextWorkRequired(&Tip(), &header, params);
        }
    };

    // Time a block takes at a hashrate `hashrate` times the one that mines a
    // block of EQUILIBRIUM_BITS every 60 seconds.
    static uint32_t ExpectedBlockTime(uint32_t nBits, double hashrate)
    {
        arith_uint256 target, equilibrium;
        target.SetCompact(nBits);
        equilibrium.SetCompact(EQUILIBRIUM_BITS);
        const double seconds = 60.0 * equilibrium.getdouble() / target.getdouble() / hashrate;
        return std::max<uint32_t>(1, (uint32_t)(seconds + 0.5));
    }

    BOOST_AUTO_TEST_CASE(nip028_fork_block_keeps_the_legacy_difficulty)
    {
        // B-09: the window of block H holds only 60-second blocks, so H
        // requires the nBits a node without the fork computes. The rules
        // first differ at H + 1, whose window holds block H.
        const Consensus::Params fork = MainnetWithFork(FORK_HEIGHT);
        const Consensus::Params legacy = MainnetWithFork(std::numeric_limits<int>::max());
        SimulatedChain chain(FORK_HEIGHT - 400, 402);
        uint32_t nTime = SIMULATION_START_TIME;
        uint32_t seed = 12345;
        for (int i = 0; i < 400; i++) {
            // Irregular history: block times of 10..130 s and drifting targets.
            seed = seed * 1103515245 + 12345;
            nTime += 10 + (seed >> 16) % 121;
            chain.Add(nTime, i < 181 ? EQUILIBRIUM_BITS : chain.NextBits(legacy));
        }
        BOOST_REQUIRE_EQUAL(chain.Tip().nHeight, FORK_HEIGHT - 1);
        const uint32_t nBitsAtFork = chain.NextBits(fork);
        BOOST_CHECK_EQUAL(nBitsAtFork, chain.NextBits(legacy));

        chain.Add(chain.Tip().nTime + 30, nBitsAtFork);
        BOOST_CHECK(chain.NextBits(fork) != chain.NextBits(legacy));
    }

    struct ForkRun
    {
        int nBlocksToTwice = -1;          // first block whose 180-block mean is at most 60 s
        int nBlocksToBand = -1;           // first block from which the mean stays within 30 s ± 10%
        int64_t nSecondsToTwice = -1;
        int64_t nSecondsToBand = -1;
        uint32_t nLongestBlock = 0;
        double finalMean = 0;
    };

    // The fork happens at equilibrium; after it the hashrate is `hashrate`
    // times the previous one.
    static ForkRun SimulateFork(double hashrate, int nBlocksAfterFork)
    {
        const Consensus::Params fork = MainnetWithFork(FORK_HEIGHT);
        SimulatedChain chain(FORK_HEIGHT - 400, 400 + nBlocksAfterFork);
        uint32_t nTime = SIMULATION_START_TIME;
        for (int i = 0; i < 400; i++) {
            nTime += 60;
            chain.Add(nTime, i < 181 ? EQUILIBRIUM_BITS : chain.NextBits(fork));
        }
        ForkRun run;
        std::vector<uint32_t> times;
        int64_t elapsed = 0;
        for (int i = 0; i < nBlocksAfterFork; i++) {
            const uint32_t nBits = chain.NextBits(fork);
            const uint32_t seconds = ExpectedBlockTime(nBits, hashrate);
            chain.Add(chain.Tip().nTime + seconds, nBits);
            times.push_back(seconds);
            elapsed += seconds;
            run.nLongestBlock = std::max(run.nLongestBlock, seconds);
            const size_t window = std::min<size_t>(times.size(), 180);
            double mean = 0;
            for (size_t j = times.size() - window; j < times.size(); j++) mean += times[j];
            mean /= window;
            if (run.nBlocksToTwice < 0 && times.size() >= 180 && mean <= 60) {
                run.nBlocksToTwice = i + 1;
                run.nSecondsToTwice = elapsed;
            }
            const bool inBand = times.size() >= 180 && mean >= 27 && mean <= 33;
            if (!inBand) {
                run.nBlocksToBand = -1;
            } else if (run.nBlocksToBand < 0) {
                run.nBlocksToBand = i + 1;
                run.nSecondsToBand = elapsed;
            }
            run.finalMean = mean;
        }
        return run;
    }

    BOOST_AUTO_TEST_CASE(nip028_difficulty_converges_after_the_fork)
    {
        // B-08 with the recovery criterion proposed in D-05: the mean block
        // time is back to at most 60 s within 12 hours and stays in 30 s ±
        // 10% within 48 hours, whatever share of the hashrate stays behind.
        for (const double hashrate : {1.0, 0.5, 0.1, 3.0}) {
            const ForkRun run = SimulateFork(hashrate, 6000);
            BOOST_TEST_MESSAGE("NIP-028 hashrate x" << hashrate << ": mean <= 60 s after " << run.nBlocksToTwice
                               << " blocks (" << run.nSecondsToTwice << " s), 30 s +-10% after " << run.nBlocksToBand
                               << " blocks (" << run.nSecondsToBand << " s), longest block " << run.nLongestBlock
                               << " s, final mean " << run.finalMean << " s");
            BOOST_CHECK_MESSAGE(run.nBlocksToTwice > 0 && run.nSecondsToTwice <= 12 * 60 * 60,
                                "hashrate x" << hashrate << " takes " << run.nSecondsToTwice << " s to a 60 s mean");
            BOOST_CHECK_MESSAGE(run.nBlocksToBand > 0 && run.nSecondsToBand <= 48 * 60 * 60,
                                "hashrate x" << hashrate << " takes " << run.nSecondsToBand << " s to 30 s +-10%");
            BOOST_CHECK(run.finalMean >= 29 && run.finalMean <= 31);
        }
    }

    struct TimestampRun
    {
        double meanInterval = 0;      // real seconds per block over the last 4000 blocks
        double largestTargetRise = 0; // largest target increase from one block to the next
    };

    // From H - 200 on, a miner with a share `alpha` of the (constant) hashrate
    // stamps its blocks as far ahead as the rules allow: real time plus
    // MAX_FUTURE_BLOCK_TIME_DGW. Every block must be later than the median of
    // the previous 11, so honest miners follow the attacker's timestamps when
    // those run ahead of real time.
    static TimestampRun SimulateFutureTimestamps(double alpha)
    {
        const Consensus::Params fork = MainnetWithFork(FORK_HEIGHT);
        const int nBlocks = 6000;
        SimulatedChain chain(FORK_HEIGHT - 400, 400 + nBlocks);
        uint32_t nNow = SIMULATION_START_TIME;
        for (int i = 0; i < 200; i++) {
            nNow += 60;
            chain.Add(nNow, i < 181 ? EQUILIBRIUM_BITS : chain.NextBits(fork));
        }
        TimestampRun run;
        uint32_t seed = 4242;
        int64_t nMeasured = 0, nMeasuredBlocks = 0;
        for (int i = 0; i < 200 + nBlocks; i++) {
            const uint32_t nBits = chain.NextBits(fork);
            arith_uint256 target, previous;
            target.SetCompact(nBits);
            previous.SetCompact(chain.Tip().nBits);
            run.largestTargetRise = std::max(run.largestTargetRise, target.getdouble() / previous.getdouble());
            const uint32_t seconds = ExpectedBlockTime(nBits, 1.0);
            nNow += seconds;
            seed = seed * 1103515245 + 12345;
            const bool fAttacker = ((seed >> 16) % 1000) < alpha * 1000;
            const uint32_t nStamp = fAttacker ? nNow + MAX_FUTURE_BLOCK_TIME_DGW : nNow;
            chain.Add(std::max<uint32_t>(nStamp, chain.Tip().GetMedianTimePast() + 1), nBits);
            if (i >= 200 + nBlocks - 4000) {
                nMeasured += seconds;
                nMeasuredBlocks++;
            }
        }
        run.meanInterval = double(nMeasured) / nMeasuredBlocks;
        return run;
    }

    BOOST_AUTO_TEST_CASE(nip028_future_timestamps_stay_bounded_across_the_fork)
    {
        // B-08, timestamp manipulation. A stamp 12 minutes ahead lowers the
        // difficulty of the next block by the share of the 180-block window
        // that 12 minutes are, twice when such a stamp leaves the window as
        // another enters it: after the fork the window is 1.5 hours, so one
        // block can get about a third more target. It does not accumulate,
        // because stamps ahead of time do not grow, and the mean block time
        // stays the honest one.
        const double honest = SimulateFutureTimestamps(0.0).meanInterval;
        for (const double alpha : {0.0, 0.3, 0.45}) {
            const TimestampRun run = SimulateFutureTimestamps(alpha);
            BOOST_TEST_MESSAGE("NIP-028 future timestamps, share " << alpha << ": mean block "
                               << run.meanInterval << " s, largest target rise x" << run.largestTargetRise);
            BOOST_CHECK(run.meanInterval >= 27 && run.meanInterval <= 33);
            BOOST_CHECK(std::abs(run.meanInterval - honest) < 0.5);
            BOOST_CHECK(run.largestTargetRise <= 1.4);
        }
    }

BOOST_AUTO_TEST_SUITE_END()
