// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include <amount.h>
#include <assets/assetdb.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <miner.h>
#include <header_verification.h>
#include <net_processing.h>
#include <pow.h>
#include <test/data/mainnet_dgw_history.h>
#include <test/epoch_context_cache_test_access.h>
#include <test/test_neurai.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>
#include <boost/signals2/connection.hpp>
#include <atomic>
#include <algorithm>

namespace {
struct WorkSetup : TestingSetup {
    const BlockNetwork previousNetwork{bNetwork};
    CAssetsDB* previousAssets{passetsdb};
    WorkSetup() : TestingSetup(CBaseChainParams::MAIN)
    {
        bNetwork = BlockNetwork();
        passetsdb = new CAssetsDB(1 << 20, true, true);
    }
    ~WorkSetup()
    {
        GetMainSignals().FlushBackgroundCallbacks();
        delete passetsdb;
        passetsdb = previousAssets;
        bNetwork = previousNetwork;
    }
    CBlock Block()
    {
        auto block = BlockAssembler(GetParams()).CreateNewBlock(CScript() << OP_TRUE)->block;
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.fChecked = false;
        return block;
    }
    void Mine(CBlock& block)
    {
        block.fChecked = false;
        do { ++block.nNonce64; ++block.nNonce; }
        while (!CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
    }
    CValidationState Result(const CBlock& block, bool force)
    {
        auto result = std::make_shared<CValidationState>();
        const auto hash = block.GetHash();
        auto called = std::make_shared<bool>(false);
        boost::signals2::scoped_connection observer(GetMainSignals().ConnectBlockChecked(
            [result, called, hash](const CBlock& checked, const CValidationState& state) {
                if (checked.GetHash() == hash) { *result = state; *called = true; }
            }));
        bool newBlock = true;
        BOOST_CHECK(!ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), force, &newBlock));
        BOOST_CHECK(!newBlock);
        BOOST_REQUIRE(*called);
        return *result;
    }
};

struct NoContext {
    std::atomic<int> calls{0};
    EpochContextCacheTestAccess::FactoryOverride guard{KawpowValidationCache(),
        [this](int) -> EpochContextCache::Context { ++calls; throw std::bad_alloc(); }};
};
}

BOOST_FIXTURE_TEST_SUITE(block_work_tests, WorkSetup)

BOOST_AUTO_TEST_CASE(wrong_difficulty_precedes_pow_and_body_checks)
{
    auto block = Block();
    block.vtx.clear(); // If body validation runs first, its verdict will differ.
    NoContext context;
    for (const uint32_t bits : {0U, 0x2180ffffU, 0x2200ffffU, 0x207fffffU, 0x1f00ffffU}) {
        block.nBits = bits;
        for (bool force : {false, true}) {
            const auto state = Result(block, force);
            int dos = 0;
            BOOST_CHECK(state.IsInvalid(dos));
            BOOST_CHECK_EQUAL(dos, 100);
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-diffbits");
            BOOST_CHECK(!block.fChecked);
        }
        CValidationState headers;
        const CBlockIndex* last = nullptr;
        BOOST_CHECK(!ProcessNewBlockHeaders({block.GetBlockHeader()}, headers, GetParams(), &last));
        BOOST_CHECK_EQUAL(headers.GetRejectReason(), "bad-diffbits");
        BOOST_CHECK(last == nullptr);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(block.GetHash()), 0U);
    }
    BOOST_CHECK_EQUAL(context.calls.load(), 0);
}

BOOST_AUTO_TEST_CASE(cached_body_checks_do_not_bypass_difficulty)
{
    auto block = Block();
    block.nBits = 0x207fffff;
    block.fChecked = true;
    NoContext context;
    BOOST_CHECK_EQUAL(Result(block, true).GetRejectReason(), "bad-diffbits");
    BOOST_CHECK_EQUAL(context.calls.load(), 0);
}

BOOST_AUTO_TEST_CASE(missing_parent_is_temporary_and_same_block_can_be_retried)
{
    auto parent = Block();
    Mine(parent);
    auto child = parent;
    child.hashPrevBlock = parent.GetHash();
    ++child.nHeight;
    ++child.nTime;
    CMutableTransaction coinbase(*child.vtx[0]);
    coinbase.vin[0].scriptSig = CScript() << child.nHeight << OP_0;
    child.vtx[0] = MakeTransactionRef(coinbase);
    child.hashMerkleRoot = BlockMerkleRoot(child);
    Mine(child);
    {
        NoContext context;
        for (bool force : {false, true}) {
            const auto state = Result(child, force);
            BOOST_CHECK(state.IsError());
            BOOST_CHECK(!state.IsInvalid());
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "block-parent-unavailable");
        }
        BOOST_CHECK_EQUAL(context.calls.load(), 0);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(child.GetHash()), 0U);
    }
    BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(parent), true, nullptr));
    BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(child), true, nullptr));
    LOCK(cs_main);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == child.GetHash());
    BOOST_CHECK(!(chainActive.Tip()->nStatus & BLOCK_FAILED_MASK));
}

BOOST_AUTO_TEST_CASE(difficulty_uses_the_parent_branch_and_still_requires_pow)
{
    auto block = Block();
    std::vector<CBlockIndex> fork(180);
    for (size_t i = 0; i < fork.size(); ++i) {
        fork[i].nHeight = i + 1;
        fork[i].nBits = block.nBits;
        fork[i].nTime = nKAWPOWActivationTime + 60 * i;
        fork[i].pprev = i ? &fork[i - 1] : nullptr;
    }
    const auto hash = uint256S("12345");
    struct Restore {
        uint256 hash;
        bool check{fCheckBlockIndex};
        ~Restore() { LOCK(cs_main); mapBlockIndex.erase(hash); fCheckBlockIndex = check; }
    } restore{hash};
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.emplace(hash, &fork.back()).second);
        fCheckBlockIndex = false; // This fixture installs only a synthetic parent.
    }
    block.hashPrevBlock = hash;
    block.nHeight = 181;
    block.nTime = fork.back().nTime + 60;
    const auto expected = GetNextWorkRequired(&fork.back(), &block, GetParams().GetConsensus());
    BOOST_REQUIRE_NE(expected, block.nBits); // The active tip requires the easier genesis target.
    NoContext context;
    BOOST_CHECK_EQUAL(Result(block, true).GetRejectReason(), "bad-diffbits");
    BOOST_CHECK_EQUAL(context.calls.load(), 0);
    block.nBits = expected;
    const auto state = Result(block, true);
    BOOST_CHECK(state.IsError());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "KAWPOW context unavailable");
    BOOST_CHECK_EQUAL(context.calls.load(), 1);
    BOOST_CHECK_EQUAL(fork.back().nStatus & BLOCK_FAILED_MASK, 0U);
}

BOOST_AUTO_TEST_CASE(network_distinguishes_invalid_work_from_missing_parent)
{
    // TestingSetup constructs peer logic without registering its callbacks.
    // Full blocks report misbehavior through BlockChecked, unlike headers.
    RegisterValidationInterface(peerLogic.get());
    struct UnregisterPeerLogic {
        CValidationInterface* logic;
        ~UnregisterPeerLogic() { UnregisterValidationInterface(logic); }
    } subscription{peerLogic.get()};
    auto block = Block();
    NoContext context;
    for (bool missing : {false, true}) {
        CBlock input = block;
        if (missing) input.hashPrevBlock = uint256S("777");
        else input.nBits = 0x207fffff;
        CNode peer(missing ? 47001 : 47000, NODE_NETWORK, 0, INVALID_SOCKET, CAddress(), 0, 0, CAddress(), "", true);
        peer.SetSendVersion(PROTOCOL_VERSION);
        peer.SetRecvVersion(PROTOCOL_VERSION);
        peer.nVersion = PROTOCOL_VERSION;
        peer.fSuccessfullyConnected = true;
        peerLogic->InitializeNode(&peer);
        struct Finalize {
            PeerLogicValidation& logic; CNode& peer;
            ~Finalize() { bool update = false; logic.FinalizeNode(peer.GetId(), update); }
        } finalizer{*peerLogic, peer};
        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        payload << input;
        CNetMessage message(GetParams().MessageStart(), SER_NETWORK, PROTOCOL_VERSION);
        message.hdr = CMessageHeader(GetParams().MessageStart(), NetMsgType::BLOCK, payload.size());
        message.in_data = true;
        message.readData(payload.data(), payload.size());
        const auto hash = message.GetMessageHash();
        std::copy_n(hash.begin(), CMessageHeader::CHECKSUM_SIZE, message.hdr.pchChecksum);
        {
            LOCK(peer.cs_vProcessMsg);
            peer.nProcessQueueSize += payload.size() + CMessageHeader::HEADER_SIZE;
            peer.vProcessMsg.push_back(std::move(message));
        }
        std::atomic<bool> interrupt{false};
        peerLogic->ProcessMessages(&peer, interrupt);
        CNodeStateStats stats;
        BOOST_REQUIRE(GetNodeStateStats(peer.GetId(), stats));
        BOOST_CHECK_EQUAL(stats.nMisbehavior, missing ? 0 : 100);
        if (missing) BOOST_CHECK(!peer.fDisconnect);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(input.GetHash()), 0U);
    }
    BOOST_CHECK_EQUAL(context.calls.load(), 0);
}

BOOST_AUTO_TEST_CASE(historical_mainnet_dgw_targets_are_unchanged)
{
    const auto& headers = mainnet_dgw_history::headers;
    std::vector<CBlockIndex> history(sizeof(headers) / sizeof(headers[0]));
    for (size_t i = 0; i < history.size(); ++i) {
        history[i].nHeight = i;
        history[i].nBits = headers[i].bits;
        history[i].nTime = headers[i].time;
        history[i].pprev = i ? &history[i - 1] : nullptr;
    }
    for (size_t h = 180; h <= 400; ++h) {
        CBlockHeader candidate;
        candidate.nTime = headers[h].time;
        BOOST_CHECK_MESSAGE(GetNextWorkRequired(&history[h - 1], &candidate, GetParams().GetConsensus()) == headers[h].bits,
                            "historical DGW target changed at height " << h);
    }
}

BOOST_AUTO_TEST_CASE(high_target_dgw_keeps_legacy_consensus_arithmetic)
{
    struct Vector { uint32_t bits; uint32_t spacing; uint32_t expected; };
    // Independent arbitrary-precision audit, with legacy 256-bit reductions.
    const Vector vectors[] = {
        {0x1b00ffffU, 60, 0x1b00fe92U},
        {0x1b00ffffU, 180, 0x1b02fbb8U},
        {0x1b00ffffU, 600, 0x1b02fffdU},
        {0x1f00ffffU, 60, 0x1f00fe92U},
        {0x1f00ffffU, 180, 0x1f02fbb8U},
        {0x1f00ffffU, 600, 0x1f02fffdU},
        {0x207fffffU, 60, 0x1f040d7fU},
        {0x207fffffU, 180, 0x1e059967U},
        {0x207fffffU, 600, 0x1f030a03U},
        {0x2100ffffU, 60, 0x1f010cf5U},
        {0x2100ffffU, 180, 0x1f0326e0U},
        {0x2100ffffU, 600, 0x1f031a07U},
    };
    for (const auto& v : vectors) {
        std::vector<CBlockIndex> history(180);
        for (size_t i = 0; i < history.size(); ++i) {
            history[i].nHeight = i + 1;
            history[i].nTime = nKAWPOWActivationTime + i * v.spacing;
            history[i].nBits = v.bits;
            history[i].pprev = i ? &history[i - 1] : nullptr;
        }
        CBlockHeader candidate;
        candidate.nTime = history.back().nTime + v.spacing;
        BOOST_CHECK_EQUAL(GetNextWorkRequired(&history.back(), &candidate, GetParams().GetConsensus()), v.expected);
    }
}

BOOST_AUTO_TEST_CASE(parallel_window_checks_initial_difficulty_before_building_context)
{
    struct RestoreThreads {
        int old{nScriptCheckThreads};
        ~RestoreThreads() { nScriptCheckThreads = old; }
    } restore;
    nScriptCheckThreads = 2;
    auto header = Block().GetBlockHeader();
    header.nBits = 0x207fffff;
    std::vector<CBlockHeader> headers;
    for (int i = 0; i < 16; ++i) {
        headers.push_back(header);
        header.hashPrevBlock = header.GetHash();
        ++header.nHeight;
        ++header.nTime;
    }
    NoContext context;
    CValidationState state;
    const CBlockIndex* last = nullptr;
    CBlockHeader invalid;
    BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, state, GetParams(), &last, &invalid));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-diffbits");
    BOOST_CHECK(invalid.GetHash() == headers.front().GetHash());
    BOOST_CHECK(last == nullptr);
    BOOST_CHECK_EQUAL(context.calls.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
