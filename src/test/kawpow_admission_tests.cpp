// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/ethash/lib/ethash/ethash-internal.hpp>
#include <hash.h>
#include <miner.h>
#include <net_processing.h>
#include <pow.h>
#include <rpc/server.h>
#include <test/test_neurai.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <limits>
#include <stdexcept>

extern UniValue CallRPC(std::string args);

namespace {
struct AllocationFailure {
    bool previous{ethash::testing::set_context_allocation_failure(true)};
    ~AllocationFailure() { ethash::testing::set_context_allocation_failure(previous); }
};

struct AdmissionSetup : TestingSetup {
    AdmissionSetup() : TestingSetup(CBaseChainParams::MAIN) {}
    CBlock Block() {
        auto block = GetParams().GenesisBlock();
        block.nTime = nKAWPOWActivationTime + 60;
        block.hashPrevBlock = chainActive.Tip()->GetBlockHash();
        block.nHeight = chainActive.Height() + 1;
        block.nBits = UintToArith256(GetParams().GetConsensus().powLimit).GetCompact();
        block.fChecked = false;
        return block;
    }
    void Mine(CBlock& block) {
        while (!CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()))
            ++block.nNonce64;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(kawpow_admission_tests, AdmissionSetup)

BOOST_AUTO_TEST_CASE(epoch_bounds_precede_allocation)
{
    AllocationFailure no_large_allocations; // Mutations must not allocate an unbounded DAG.
    const auto before = ethash::testing::context_allocation_count();
    for (const int epoch : {-1, std::numeric_limits<int>::min(), ETHASH_MAX_EPOCH_NUMBER + 1, 32640, std::numeric_limits<int>::max()}) {
        BOOST_CHECK_EQUAL(ethash::calculate_light_cache_num_items(epoch), 0);
        BOOST_CHECK_EQUAL(ethash::calculate_full_dataset_num_items(epoch), 0);
        BOOST_CHECK(!ethash::create_epoch_context(epoch));
        BOOST_CHECK(!ethash::create_epoch_context_full(epoch));
    }
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
    const auto items = ethash::calculate_light_cache_num_items(ETHASH_MAX_EPOCH_NUMBER);
    BOOST_CHECK_GT(items, 0);
    BOOST_CHECK_LE(uint64_t(items) * ETHASH_LIGHT_CACHE_ITEM_SIZE, uint64_t(128) << 20);
    BOOST_CHECK_GT(ethash::calculate_full_dataset_num_items(ETHASH_MAX_EPOCH_NUMBER), 0);
    BOOST_CHECK_EQUAL(ethash::get_epoch_number(uint32_t(0xffffffff)), 572662);
    BOOST_CHECK_EQUAL(ethash::get_epoch_number(-1), -1);
}

BOOST_AUTO_TEST_CASE(external_heights_cannot_build_contexts)
{
    for (const uint32_t height : {0x90000000U, 0xfff00000U, 0xffffffffU, 0x7fffffffU, 0x10000000U, 7502U}) {
        auto block = Block();
        block.nHeight = height;
        const auto before = ethash::testing::context_allocation_count();
        CValidationState headers, body;
        const CBlockIndex* last = nullptr;
        BOOST_CHECK(!ProcessNewBlockHeaders({block.GetBlockHeader()}, headers, GetParams(), &last));
        BOOST_CHECK_EQUAL(headers.GetRejectReason(), "bad-kawpow-height-range");
        int dos = 0;
        BOOST_CHECK(headers.IsInvalid(dos));
        BOOST_CHECK_EQUAL(dos, 100);
        BOOST_CHECK(last == nullptr);
        BOOST_CHECK(!CheckBlock(block, body, GetParams().GetConsensus()));
        BOOST_CHECK_EQUAL(body.GetRejectReason(), "bad-kawpow-height-range");
        BOOST_CHECK(!ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr));
        BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(block.GetHash()), 0U);
    }
}

BOOST_AUTO_TEST_CASE(hash_api_cannot_wrap_unsigned_heights)
{
    auto block = Block();
    const auto before = ethash::testing::context_allocation_count();
    uint256 mix;
    for (const uint32_t height : {0xffffffffU, 0x90000000U, 0x7fffffffU, 0x10000000U}) {
        block.nHeight = height;
        BOOST_CHECK_THROW(KAWPOWHash(block, mix), std::out_of_range);
    }
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
}

BOOST_AUTO_TEST_CASE(contextual_bound_preserves_equality_activation)
{
    auto block = Block();
    auto params = GetParams().GetConsensus();
    block.nHeight = 7501; // Inclusive bound for a child at contextual height 1.
    params.nKAWPOWHeaderHeightCheckActivation = 2;
    CValidationState historical;
    BOOST_CHECK(CheckKAWPOWHeaderAdmission(block, historical, params));
    params.nKAWPOWHeaderHeightCheckActivation = 1;
    CValidationState activated;
    BOOST_CHECK(!CheckKAWPOWHeaderAdmission(block, activated, params));
    BOOST_CHECK_EQUAL(activated.GetRejectReason(), "bad-blk-height");
    block.nHeight = 1;
    CValidationState coherent;
    BOOST_CHECK(CheckKAWPOWHeaderAdmission(block, coherent, params));
}

BOOST_AUTO_TEST_CASE(unknown_parent_admission_is_retryable)
{
    // Below the equality activation an offset of one epoch remains allowed.
    // This makes the child exceed the unknown-parent bound until its parent arrives.
    auto parent_template = BlockAssembler(GetParams()).CreateNewBlock(CScript() << OP_TRUE);
    BOOST_REQUIRE(parent_template);
    auto parent = parent_template->block;
    parent.hashMerkleRoot = BlockMerkleRoot(parent);
    Mine(parent);
    auto child = parent;
    child.hashPrevBlock = parent.GetHash();
    child.nHeight = 7502;
    child.nTime = parent.nTime + 1;
    CMutableTransaction coinbase(*child.vtx[0]);
    coinbase.vin[0].scriptSig = CScript() << 2 << OP_0;
    child.vtx[0] = MakeTransactionRef(coinbase);
    child.hashMerkleRoot = BlockMerkleRoot(child);
    child.fChecked = false;
    Mine(child);
    CValidationState pending;
    const auto before = ethash::testing::context_allocation_count();
    BOOST_CHECK(!CheckBlock(child, pending, GetParams().GetConsensus()));
    BOOST_CHECK(pending.IsError());
    BOOST_CHECK(!pending.IsInvalid());
    BOOST_CHECK_EQUAL(pending.GetRejectReason(), "kawpow-height-unavailable");
    BOOST_CHECK(!ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(child), true, nullptr));
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
    BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(parent), true, nullptr));
    BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(child), true, nullptr));
    LOCK(cs_main);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == child.GetHash());
    BOOST_CHECK(!(chainActive.Tip()->nStatus & BLOCK_FAILED_MASK));
}

BOOST_AUTO_TEST_CASE(allocation_failure_is_local_and_retryable)
{
    auto block = Block();
    block.nHeight = 0;
    uint256 ignored;
    KAWPOWHash(block, ignored); // Make the legacy one-entry cache hold epoch zero.
    CBlockIndex parent;
    parent.nHeight = 307499; // A different, valid epoch not used by the vector tests.
    const uint256 parent_hash = uint256S("1234567890");
    struct RemoveParent {
        uint256 hash;
        ~RemoveParent() { LOCK(cs_main); mapBlockIndex.erase(hash); }
    } remove{parent_hash};
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.emplace(parent_hash, &parent).second);
    }
    block.nHeight = 307500;
    block.hashPrevBlock = parent_hash;
    {
        AllocationFailure fail;
        CValidationState state;
        BOOST_CHECK(!CheckBlock(block, state, GetParams().GetConsensus()));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "KAWPOW context unavailable");
        BOOST_CHECK(!block.fChecked);

        // Exercise the network caller: a local header failure must not fall
        // through to the compact-block path that requires a non-null index.
        CNode peer(43000, NODE_NETWORK, 0, INVALID_SOCKET, CAddress(), 0, 0, CAddress(), "", true);
        peer.SetSendVersion(PROTOCOL_VERSION);
        peer.SetRecvVersion(PROTOCOL_VERSION);
        peer.nVersion = PROTOCOL_VERSION;
        peer.fSuccessfullyConnected = true;
        peerLogic->InitializeNode(&peer);
        struct FinalizePeer {
            PeerLogicValidation& logic;
            CNode& peer;
            ~FinalizePeer() { bool update = false; logic.FinalizeNode(peer.GetId(), update); }
        } finalizer{*peerLogic, peer};
        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        payload << block.GetBlockHeader() << uint64_t(0);
        WriteCompactSize(payload, 0); // No short transaction IDs.
        WriteCompactSize(payload, 0); // No prefilled transactions.
        CNetMessage message(GetParams().MessageStart(), SER_NETWORK, PROTOCOL_VERSION);
        message.hdr = CMessageHeader(GetParams().MessageStart(), NetMsgType::CMPCTBLOCK, payload.size());
        message.in_data = true;
        message.readData(payload.data(), payload.size());
        const auto hash = message.GetMessageHash();
        std::copy_n(hash.begin(), CMessageHeader::CHECKSUM_SIZE, message.hdr.pchChecksum);
        {
            LOCK(peer.cs_vProcessMsg);
            peer.nProcessQueueSize += payload.size() + CMessageHeader::HEADER_SIZE;
            peer.vProcessMsg.push_back(std::move(message));
        }
        const auto before = ethash::testing::context_allocation_count();
        std::atomic<bool> interrupt{false};
        peerLogic->ProcessMessages(&peer, interrupt);
        BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before + 1);
        CNodeStateStats stats;
        BOOST_REQUIRE(GetNodeStateStats(peer.GetId(), stats));
        BOOST_CHECK_EQUAL(stats.nMisbehavior, 0);
        BOOST_CHECK(!peer.fDisconnect);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(block.GetHash()), 0U);
    }
    Mine(block);
    CValidationState retry;
    BOOST_CHECK(CheckBlock(block, retry, GetParams().GetConsensus()));
    BOOST_CHECK(retry.IsValid());
    BOOST_CHECK_EQUAL(parent.nStatus & BLOCK_FAILED_MASK, 0U);
}

BOOST_AUTO_TEST_CASE(rpc_height_bound_precedes_context)
{
    const std::string zero(64, '0');
    const auto before = ethash::testing::context_allocation_count();
    for (const uint32_t height : {11U, 0x90000000U, 0xffffffffU}) {
        BOOST_CHECK_THROW(CallRPC("getkawpowhash " + zero + " " + zero + " 0 " + std::to_string(height)), std::exception);
    }
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
}

BOOST_AUTO_TEST_CASE(legacy_headers_do_not_use_epoch_admission)
{
    auto block = GetParams().GenesisBlock();
    block.nHeight = 0xffffffffU;
    CValidationState state;
    BOOST_REQUIRE(block.nTime < nKAWPOWActivationTime);
    BOOST_CHECK(CheckKAWPOWHeaderAdmission(block, state, GetParams().GetConsensus()));
}

BOOST_AUTO_TEST_SUITE_END()
