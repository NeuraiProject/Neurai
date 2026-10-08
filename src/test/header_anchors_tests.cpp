// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <header_anchors.h>
#include <net_processing.h>
#include <pow.h>
#include <test/test_neurai.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <limits>

namespace {
struct AnchorSetup : BasicTestingSetup {
    std::vector<CBlockHeader> chain;
    std::vector<uint256> anchors;
    AnchorSetup() : BasicTestingSetup(CBaseChainParams::REGTEST)
    {
        CBlockHeader header;
        header.nVersion = 4;
        header.nBits = 0x207fffff;
        header.nTime = 1600000000;
        for (int height = 1; height <= 6000; ++height) {
            header.nHeight = height;
            ++header.nNonce;
            ++header.nTime;
            chain.push_back(header);
            header.hashPrevBlock = header.GetHash();
            if (height % HEADER_ANCHOR_INTERVAL == 0) anchors.push_back(header.hashPrevBlock);
        }
    }

    std::vector<CBlockHeader> Batch(int start, int count) const
    {
        return {chain.begin() + start - 1, chain.begin() + start - 1 + count};
    }
};

struct AnchorValidationSetup : TestingSetup {
    AnchorValidationSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
    CBlockHeader Candidate() const
    {
        LOCK(cs_main);
        CBlockHeader header;
        header.nVersion = 4;
        header.nHeight = 1;
        header.nTime = chainActive.Tip()->nTime + 60;
        header.nBits = chainActive.Tip()->nBits;
        header.hashPrevBlock = chainActive.Tip()->GetBlockHash();
        // Intentionally invalid PoW, but valid header context.
        while (CheckProofOfWork(header.GetHash(), header.nBits, GetParams().GetConsensus())) ++header.nNonce;
        return header;
    }
};

struct AnchorPeerSetup : AnchorValidationSetup {
    struct ParamsWithAnchors : CChainParams {
        explicit ParamsWithAnchors(const std::vector<uint256>& anchors) : CChainParams(GetParams())
        {
            headerAnchors = anchors;
        }
    };
    CNode peer{43000, NODE_NETWORK, 0, INVALID_SOCKET, CAddress(), 0, 0, CAddress(), "", true};
    std::vector<CBlockHeader> headers;
    std::vector<uint256> anchors;
    const bool checkpoints{fCheckpointsEnabled};
    AnchorPeerSetup()
    {
        fCheckpointsEnabled = true;
        peer.SetSendVersion(PROTOCOL_VERSION);
        peer.nVersion = PROTOCOL_VERSION;
        peer.fSuccessfullyConnected = true;
        peerLogic->InitializeNode(&peer);
        auto header = Candidate();
        for (int height = 1; height <= 3000; ++height) {
            header.nHeight = height;
            // Every header has deliberately bad PoW. A trusted anchor is the
            // only reason any unknown prefix can be accepted in these tests.
            while (CheckProofOfWork(header.GetHash(), header.nBits, GetParams().GetConsensus())) ++header.nNonce;
            headers.push_back(header);
            header.hashPrevBlock = header.GetHash();
            if (height % HEADER_ANCHOR_INTERVAL == 0) anchors.push_back(header.hashPrevBlock);
            header.nTime += 60;
        }
    }
    ~AnchorPeerSetup()
    {
        bool update = false;
        peerLogic->FinalizeNode(peer.GetId(), update);
        fCheckpointsEnabled = checkpoints;
    }
    void AcceptKnownPrefix(size_t count)
    {
        const std::vector<CBlockHeader> prefix(headers.begin(), headers.begin() + count);
        const std::vector<uint8_t> checked(count, 1);
        CValidationState state;
        BOOST_REQUIRE(ProcessNewBlockHeaders(prefix, state, GetParams(), nullptr, nullptr, &checked));
    }
};
}

BOOST_FIXTURE_TEST_SUITE(header_anchors_tests, AnchorSetup)

BOOST_AUTO_TEST_CASE(aligned_and_unaligned_prefixes)
{
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 1, Batch(1, 2000)), 2000U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 2001, Batch(2001, 2000)), 2000U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 2, Batch(2, 2000)), 1999U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 1900, Batch(1900, 200)), 101U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 6000, Batch(6000, 1)), 1U);
}

BOOST_AUTO_TEST_CASE(absent_anchor_authenticates_nothing)
{
    BOOST_CHECK_EQUAL(CountAnchoredHeaders({}, 1, Batch(1, 2000)), 0U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 1, Batch(1, 1999)), 0U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 1, {}), 0U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 0, Batch(1, 2000)), 0U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, -1, Batch(1, 2000)), 0U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 6001, Batch(1, 2000)), 0U);
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, std::numeric_limits<int>::max(), Batch(1, 2000)), 0U);
}

BOOST_AUTO_TEST_CASE(mismatched_anchor_and_broken_commitment_chain)
{
    auto batch = Batch(1, 2000);
    ++batch.back().nNonce;
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 1, batch), 0U);
    batch = Batch(1, 2000);
    ++batch[42].nNonce; // The final anchor still matches, but its ancestry does not.
    BOOST_CHECK_EQUAL(CountAnchoredHeaders(anchors, 1, batch), 0U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(header_anchor_peer_tests, AnchorPeerSetup)

BOOST_AUTO_TEST_CASE(full_unaligned_batch_requests_after_the_anchor)
{
    AcceptKnownPrefix(1000);
    const ParamsWithAnchors params(anchors);
    std::vector<CBlockHeader> batch(headers.begin() + 1000, headers.end());
    BOOST_REQUIRE_EQUAL(batch.size(), MAX_HEADERS_RESULTS);
    BOOST_CHECK(ProcessHeadersMessage(&peer, connman, std::move(batch), params, false));
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(pindexBestHeader->nHeight, 2000);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(headers[2000].GetHash()), 0U);
    }
    bool requested_after_anchor = false;
    for (const auto& stats : GetHeaderSyncStats().peers) {
        if (stats.node_id == peer.GetId() && stats.request_start_height == 2000) requested_after_anchor = true;
    }
    BOOST_CHECK(requested_after_anchor);
    BOOST_CHECK(!peer.fDisconnect);
}

BOOST_AUTO_TEST_CASE(short_batch_checks_the_unanchored_tail)
{
    AcceptKnownPrefix(1900);
    const ParamsWithAnchors params(anchors);
    std::vector<CBlockHeader> batch(headers.begin() + 1900, headers.begin() + 2100);
    BOOST_CHECK(!ProcessHeadersMessage(&peer, connman, std::move(batch), params, false));
    CNodeStateStats stats;
    BOOST_REQUIRE(GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.nMisbehavior, 50);
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(pindexBestHeader->nHeight, 2000);
    BOOST_CHECK_EQUAL(mapBlockIndex.count(headers[2000].GetHash()), 0U);
}

BOOST_AUTO_TEST_CASE(disabled_checkpoints_disable_anchor_trust)
{
    fCheckpointsEnabled = false;
    const ParamsWithAnchors params(anchors);
    std::vector<CBlockHeader> batch(headers.begin(), headers.begin() + 2000);
    BOOST_CHECK(!ProcessHeadersMessage(&peer, connman, std::move(batch), params, false));
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(pindexBestHeader->nHeight, 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(header_anchor_validation_tests, AnchorValidationSetup)

BOOST_AUTO_TEST_CASE(only_checked_headers_skip_pow)
{
    const auto header = Candidate();
    for (const std::vector<uint8_t> flags : {std::vector<uint8_t>{}, {1, 1}, {0}}) {
        CValidationState state;
        BOOST_CHECK(!ProcessNewBlockHeaders({header}, state, GetParams(), nullptr, nullptr, &flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "high-hash");
        int dos = 0;
        BOOST_CHECK(state.IsInvalid(dos));
        BOOST_CHECK_EQUAL(dos, 50);
    }
    CValidationState without_marks;
    BOOST_CHECK(!ProcessNewBlockHeaders({header}, without_marks, GetParams()));
    BOOST_CHECK_EQUAL(without_marks.GetRejectReason(), "high-hash");
    const std::vector<uint8_t> checked{1};
    CValidationState authenticated;
    const CBlockIndex* last = nullptr;
    BOOST_CHECK(ProcessNewBlockHeaders({header}, authenticated, GetParams(), &last, nullptr, &checked));
    BOOST_REQUIRE(last);
    BOOST_CHECK(last->GetBlockHash() == header.GetHash());
}

BOOST_AUTO_TEST_CASE(checked_pow_keeps_contextual_checks)
{
    const std::vector<uint8_t> checked{1};
    auto header = Candidate();
    header.nBits -= 1;
    CValidationState difficulty;
    BOOST_CHECK(!ProcessNewBlockHeaders({header}, difficulty, GetParams(), nullptr, nullptr, &checked));
    BOOST_CHECK_EQUAL(difficulty.GetRejectReason(), "bad-diffbits");
    header = Candidate();
    header.nTime = chainActive.Tip()->GetMedianTimePast();
    CValidationState time;
    BOOST_CHECK(!ProcessNewBlockHeaders({header}, time, GetParams(), nullptr, nullptr, &checked));
    BOOST_CHECK_EQUAL(time.GetRejectReason(), "time-too-old");
}

BOOST_AUTO_TEST_SUITE_END()
