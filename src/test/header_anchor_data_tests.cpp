// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chainparamsanchors.h>
#include <crypto/sha256.h>
#include <header_anchors.h>
#include <test/test_neurai.h>
#include <utilstrencodings.h>

#include <boost/test/unit_test.hpp>

namespace {
struct MainAnchorDataSetup : BasicTestingSetup {
    MainAnchorDataSetup() : BasicTestingSetup(CBaseChainParams::MAIN) {}
};
struct TestnetAnchorDataSetup : BasicTestingSetup {
    TestnetAnchorDataSetup() : BasicTestingSetup(CBaseChainParams::TESTNET) {}
};
struct RegtestAnchorDataSetup : BasicTestingSetup {
    RegtestAnchorDataSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};
}

BOOST_AUTO_TEST_SUITE(header_anchor_data_tests)

BOOST_FIXTURE_TEST_CASE(mainnet_anchors_match_checkpoints, MainAnchorDataSetup)
{
    static_assert(HeaderAnchorData::INTERVAL == HEADER_ANCHOR_INTERVAL, "anchor interval mismatch");
    const auto& anchors = GetParams().HeaderAnchors();
    const auto& checkpoints = GetParams().Checkpoints().mapCheckpoints;
    BOOST_REQUIRE_EQUAL(anchors.size(), HeaderAnchorData::CHECKPOINT_HEIGHT / HEADER_ANCHOR_INTERVAL);
    BOOST_REQUIRE(!anchors.empty());
    BOOST_REQUIRE(!checkpoints.empty());
    BOOST_CHECK_EQUAL(checkpoints.count(HeaderAnchorData::CHECKPOINT_HEIGHT), 1U);
    BOOST_CHECK_LE(anchors.size() * HEADER_ANCHOR_INTERVAL, size_t(checkpoints.rbegin()->first));
    for (const auto& anchor : anchors) BOOST_CHECK(!anchor.IsNull());
    size_t matched = 0;
    for (const auto& checkpoint : checkpoints) {
        if (checkpoint.first > 0 && checkpoint.first % HEADER_ANCHOR_INTERVAL == 0) {
            const size_t index = checkpoint.first / HEADER_ANCHOR_INTERVAL - 1;
            BOOST_REQUIRE_LT(index, anchors.size());
            BOOST_CHECK(anchors[index] == checkpoint.second);
            ++matched;
        }
    }
    BOOST_CHECK_GT(matched, 0U);
}

BOOST_FIXTURE_TEST_CASE(verified_anchor_prefix_never_changes, MainAnchorDataSetup)
{
    // First independently verified set. A later release may append, never edit
    // these 866 entries. Digest is SHA256 of the concatenated lowercase hex,
    // recorded in both generator provenance files (not derived from this array).
    constexpr size_t previous_count = 866;
    const auto& anchors = GetParams().HeaderAnchors();
    BOOST_REQUIRE_GE(anchors.size(), previous_count);
    CSHA256 hash;
    for (size_t i = 0; i < previous_count; ++i) {
        const auto hex = anchors[i].GetHex();
        hash.Write(reinterpret_cast<const unsigned char*>(hex.data()), hex.size());
    }
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hash.Finalize(digest);
    BOOST_CHECK_EQUAL(HexStr(digest, digest + sizeof(digest)), "a81616274f7a23ddf0912a090369faf7c5eef88f2a64bbf80db728154c8b1c66");
}

BOOST_FIXTURE_TEST_CASE(testnet_has_no_anchors, TestnetAnchorDataSetup)
{
    BOOST_CHECK(GetParams().HeaderAnchors().empty());
}

BOOST_FIXTURE_TEST_CASE(regtest_has_no_anchors, RegtestAnchorDataSetup)
{
    BOOST_CHECK(GetParams().HeaderAnchors().empty());
}

BOOST_AUTO_TEST_SUITE_END()
