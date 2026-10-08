// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <chainparams.h>
#include <crypto/ethash/helpers.hpp>
#include <hash.h>
#include <net_processing.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/epoch_context_cache_test_access.h>
#include <test/test_neurai.h>
#include <validation.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>
#include <atomic>

extern UniValue CallRPC(std::string args);

namespace {
using Context = EpochContextCache::Context;
Context RealContext(int epoch)
{
    return Context(ethash::create_epoch_context(epoch));
}

struct MiningModeGuard {
    const bool sha{bNetwork.fSHA256Mining};
    const uint32_t activation{nKAWPOWActivationTime};
    MiningModeGuard() { bNetwork.fSHA256Mining = false; nKAWPOWActivationTime = 0; }
    ~MiningModeGuard() { bNetwork.fSHA256Mining = sha; nKAWPOWActivationTime = activation; }
};
}

BOOST_FIXTURE_TEST_SUITE(epoch_context_integration_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(candidate_selection_keeps_sha_and_legacy_but_not_checkpoint_siblings)
{
    MiningModeGuard mode;
    LOCK(cs_main);
    nKAWPOWActivationTime = 100;
    CBlockHeader header;
    header.nHeight = 1;
    header.nTime = 99;
    BOOST_CHECK(!NeedsFullKAWPOWCheck(header));
    header.nTime = 100;
    BOOST_CHECK(NeedsFullKAWPOWCheck(header));
    bNetwork.fSHA256Mining = true;
    BOOST_CHECK(!NeedsFullKAWPOWCheck(header));
    bNetwork.fSHA256Mining = false;
    const auto& checkpoint = *GetParams().Checkpoints().mapCheckpoints.rbegin();
    CBlockIndex index;
    index.nHeight = checkpoint.first;
    const auto inserted = mapBlockIndex.emplace(checkpoint.second, &index);
    BOOST_REQUIRE(inserted.second);
    header.nHeight = checkpoint.first;
    // Matching the checkpoint height does not authenticate this different hash.
    BOOST_CHECK(NeedsFullKAWPOWCheck(header));
    ++header.nHeight;
    BOOST_CHECK(NeedsFullKAWPOWCheck(header));
    mapBlockIndex.erase(inserted.first);
}

BOOST_AUTO_TEST_CASE(explicit_context_and_serial_checks_agree)
{
    MiningModeGuard mode;
    auto params = GetParams().GetConsensus();
    params.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CBlockHeader header;
    header.nHeight = 7500;
    header.nTime = 1;
    header.nBits = 0x207fffff;
    const auto context = KawpowValidationCache().Get(1);
    uint256 full;
    do {
        ++header.nNonce64;
        full = header.GetHashFull(header.mix_hash);
    } while (!CheckProofOfWork(full, header.nBits, params));
    uint256 explicit_mix;
    BOOST_CHECK(KAWPOWHash(header, explicit_mix, *context) == full);
    BOOST_CHECK(explicit_mix == header.mix_hash);
    for (int invalid = 0; invalid < 3; ++invalid) {
        CBlockHeader candidate = header;
        if (invalid == 1) candidate.mix_hash.begin()[0] ^= 1;
        if (invalid == 2) candidate.nBits = 0;
        CValidationState serial, retained;
        const bool a = CheckBlockHeaderPoWFull(candidate, serial, params);
        const bool b = CheckBlockHeaderPoWFull(candidate, retained, params, *context);
        BOOST_CHECK_EQUAL(a, b);
        BOOST_CHECK_EQUAL(a, invalid == 0);
        BOOST_CHECK_EQUAL(serial.GetRejectReason(), retained.GetRejectReason());
        int serial_dos = 0, retained_dos = 0;
        BOOST_CHECK_EQUAL(serial.IsInvalid(serial_dos), retained.IsInvalid(retained_dos));
        BOOST_CHECK_EQUAL(serial_dos, retained_dos);
    }
}

BOOST_AUTO_TEST_CASE(construction_failure_is_local_and_retryable)
{
    CBlockHeader header;
    header.nTime = chainActive.Tip()->nTime + 60;
    header.hashPrevBlock = chainActive.Tip()->GetBlockHash();
    header.nBits = chainActive.Tip()->nBits;
    header.nHeight = 1;
    int calls = 0;
    EpochContextCacheTestAccess::FactoryOverride inject(KawpowValidationCache(), [&](int epoch) -> Context {
        if (++calls <= 2) return {};
        return RealContext(epoch);
    });
    const CBlockIndex* last = nullptr;
    CValidationState first;
    BOOST_CHECK(!ProcessNewBlockHeaders({header}, first, GetParams(), &last));
    BOOST_CHECK(first.IsError());
    BOOST_CHECK(!first.IsInvalid());
    BOOST_CHECK(last == nullptr);
    CValidationState after_prefix;
    const auto genesis = GetParams().GenesisBlock().GetBlockHeader();
    BOOST_CHECK(!ProcessNewBlockHeaders({genesis, header}, after_prefix, GetParams(), &last));
    BOOST_CHECK(after_prefix.IsError());
    BOOST_CHECK(last == chainActive.Genesis());
    {
        LOCK(cs_main);
        BOOST_CHECK(mapBlockIndex.count(header.GetHash()) == 0);
        BOOST_CHECK((last->nStatus & BLOCK_FAILED_MASK) == 0);
    }
    CValidationState retried;
    CheckBlockHeaderPoWFull(header, retried, GetParams().GetConsensus());
    BOOST_CHECK(!retried.IsError()); // The next operation gets a usable context.
    BOOST_CHECK_EQUAL(calls, 3);
}

BOOST_AUTO_TEST_CASE(rpc_and_validation_caches_are_independent)
{
    std::atomic<int> validation_builds{0}, rpc_builds{0};
    EpochContextCacheTestAccess::FactoryOverride validation(KawpowValidationCache(), [&](int epoch) {
        ++validation_builds; return RealContext(epoch);
    });
    EpochContextCacheTestAccess::FactoryOverride rpc(KawpowRpcCache(), [&](int epoch) {
        ++rpc_builds; return RealContext(epoch);
    });
    const auto held = KawpowValidationCache().Get(0);
    for (int epoch : {1, 2, 3, 0}) KawpowRpcCache().Get(epoch);
    const std::string zeros(64, '0');
    const UniValue result = CallRPC("getkawpowhash " + zeros + " " + zeros + " 0 0");
    BOOST_CHECK(find_value(result, "digest").isStr());
    BOOST_CHECK(KawpowValidationCache().Get(0) == held);
    BOOST_CHECK_EQUAL(validation_builds.load(), 1);
    BOOST_CHECK_EQUAL(rpc_builds.load(), 4);
}

BOOST_AUTO_TEST_CASE(rpc_reports_allocation_failure_and_can_retry)
{
    int calls = 0;
    EpochContextCacheTestAccess::FactoryOverride inject(KawpowRpcCache(), [&](int epoch) -> Context {
        if (++calls == 1) return {};
        return RealContext(epoch);
    });
    const std::string zeros(64, '0');
    BOOST_CHECK_EXCEPTION(CallRPC("getkawpowhash " + zeros + " " + zeros + " 0 0"), std::runtime_error,
        [](const std::runtime_error& e) { return std::string(e.what()).find("KAWPOW context unavailable") == 0; });
    BOOST_CHECK_EQUAL(EpochContextCacheTestAccess::Pending(KawpowRpcCache()), 0U);
    BOOST_CHECK_NO_THROW(CallRPC("getkawpowhash " + zeros + " " + zeros + " 0 0"));
    BOOST_CHECK_EQUAL(calls, 2);
}

BOOST_AUTO_TEST_CASE(headers_resource_failure_does_not_penalize_peer_or_record_success)
{
    CBlockHeader known;
    known.nVersion = 4;
    known.nTime = chainActive.Tip()->nTime + 60;
    known.hashPrevBlock = chainActive.Tip()->GetBlockHash();
    known.nBits = chainActive.Tip()->nBits;
    known.nHeight = 1;
    // Model an already accepted prefix. Its PoW is not revisited; only the
    // following unknown header requests a context and triggers our local error.
    struct KnownHeader {
        const uint256 hash;
        CBlockIndex index;
        explicit KnownHeader(const CBlockHeader& header) : hash(header.GetHash()), index(header)
        {
            LOCK(cs_main);
            index.pprev = chainActive.Genesis();
            index.nHeight = 1;
            index.nStatus = BLOCK_VALID_TREE;
            index.nChainWork = index.pprev->nChainWork + GetBlockProof(index);
            const auto inserted = mapBlockIndex.emplace(hash, &index);
            assert(inserted.second);
            index.phashBlock = &inserted.first->first;
        }
        ~KnownHeader() { LOCK(cs_main); mapBlockIndex.erase(hash); }
    } prefix(known);

    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride inject(KawpowValidationCache(), [&](int) -> Context {
        ++constructions;
        return {};
    });
    CAddress address;
    CNode peer(42000, NODE_NETWORK, 0, INVALID_SOCKET, address, 0, 0, CAddress(), "", true);
    peer.SetSendVersion(PROTOCOL_VERSION);
    peer.SetRecvVersion(PROTOCOL_VERSION);
    peer.nVersion = PROTOCOL_VERSION;
    peer.fSuccessfullyConnected = true;
    peerLogic->InitializeNode(&peer);
    struct PeerFinalizer {
        PeerLogicValidation& logic;
        CNode& peer;
        ~PeerFinalizer() { bool update = false; logic.FinalizeNode(peer.GetId(), update); }
    } finalizer{*peerLogic, peer};

    for (const bool with_prefix : {false, true}) {
        CBlockHeader candidate = known;
        if (with_prefix) {
            candidate.hashPrevBlock = prefix.hash;
            ++candidate.nHeight;
            candidate.nTime += 60;
        } else {
            ++candidate.nNonce64;
        }
        CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
        WriteCompactSize(payload, with_prefix ? 2 : 1);
        if (with_prefix) { payload << known; WriteCompactSize(payload, 0); }
        payload << candidate;
        WriteCompactSize(payload, 0);
        CNetMessage message(GetParams().MessageStart(), SER_NETWORK, PROTOCOL_VERSION);
        message.hdr = CMessageHeader(GetParams().MessageStart(), NetMsgType::HEADERS, payload.size());
        message.in_data = true;
        message.readData(payload.data(), payload.size());
        const auto hash = message.GetMessageHash();
        std::copy_n(hash.begin(), CMessageHeader::CHECKSUM_SIZE, message.hdr.pchChecksum);
        {
            LOCK(peer.cs_vProcessMsg);
            peer.nProcessQueueSize += payload.size() + CMessageHeader::HEADER_SIZE;
            peer.vProcessMsg.push_back(std::move(message));
        }
        const auto before = GetHeaderSyncStats();
        std::atomic<bool> interrupt{false};
        peerLogic->ProcessMessages(&peer, interrupt);
        CNodeStateStats stats;
        BOOST_REQUIRE(GetNodeStateStats(peer.GetId(), stats));
        BOOST_CHECK_EQUAL(stats.nMisbehavior, 0);
        BOOST_CHECK(!peer.fDisconnect);
        BOOST_CHECK_EQUAL(GetHeaderSyncStats().batches, before.batches);
        BOOST_CHECK_EQUAL(GetHeaderSyncStats().unsolicited_responses, before.unsolicited_responses);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(candidate.GetHash()), 0U);
        BOOST_CHECK_EQUAL(prefix.index.nStatus & BLOCK_FAILED_MASK, 0U);
    }
    BOOST_CHECK_EQUAL(constructions, 2);
}

BOOST_AUTO_TEST_SUITE_END()
