// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <crypto/ethash/helpers.hpp>
#include <header_verification.h>
#include <pow.h>
#include <test/epoch_context_cache_test_access.h>
#include <test/test_neurai.h>
#include <validation.h>
#include <ui_interface.h>

#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <atomic>
#include <future>

namespace {
using Context = EpochContextCache::Context;
Context RealContext(int epoch) { return Context(ethash::create_epoch_context(epoch)); }

struct ParallelSetup : TestingSetup {
    const bool sha;
    const uint32_t activation;
    const int threads;
    const bool checkpoints;
    ParallelSetup() : TestingSetup(CBaseChainParams::REGTEST), sha(bNetwork.fSHA256Mining),
        activation(nKAWPOWActivationTime), threads(nScriptCheckThreads), checkpoints(fCheckpointsEnabled)
    {
        bNetwork.fSHA256Mining = false;
        nKAWPOWActivationTime = 0;
        nScriptCheckThreads = 4;
        fCheckpointsEnabled = true;
    }
    ~ParallelSetup()
    {
        bNetwork.fSHA256Mining = sha;
        nKAWPOWActivationTime = activation;
        nScriptCheckThreads = threads;
        fCheckpointsEnabled = checkpoints;
    }
    std::vector<CBlockHeader> Batch(size_t count, bool mine = true)
    {
        CBlockHeader header;
        header.nVersion = 4;
        header.nHeight = 1;
        header.nTime = chainActive.Tip()->nTime + 60;
        header.nBits = chainActive.Tip()->nBits;
        header.hashPrevBlock = chainActive.Tip()->GetBlockHash();
        std::vector<CBlockHeader> result;
        for (size_t i = 0; i < count; ++i) {
            if (mine) {
                do { ++header.nNonce64; }
                while (!CheckProofOfWork(header.GetHashFull(header.mix_hash), header.nBits, GetParams().GetConsensus()));
            }
            result.push_back(header);
            header.hashPrevBlock = header.GetHash();
            ++header.nHeight;
            header.nTime += 60;
        }
        return result;
    }
    void Relink(std::vector<CBlockHeader>& headers)
    {
        for (size_t i = 1; i < headers.size(); ++i) headers[i].hashPrevBlock = headers[i-1].GetHash();
    }
    void MineSuffix(std::vector<CBlockHeader>& headers)
    {
        for (size_t i = 1; i < headers.size(); ++i) {
            auto& header = headers[i];
            header.hashPrevBlock = headers[i-1].GetHash();
            do { ++header.nNonce64; }
            while (!CheckProofOfWork(header.GetHashFull(header.mix_hash), header.nBits, GetParams().GetConsensus()));
        }
    }
    HeaderWindowStatus Prepare(const std::vector<CBlockHeader>& headers, HeaderVerificationWindow& window,
        CValidationState& state, size_t& offset, const CBlockIndex** last = nullptr, size_t limit = 64)
    {
        LOCK(cs_main);
        return PrepareHeaderWindow(headers, std::vector<uint8_t>(headers.size(), 0), offset, limit,
                                   GetParams(), state, last, nullptr, window);
    }
};

struct TemporaryIndex {
    uint256 hash;
    CBlockIndex index;
    explicit TemporaryIndex(const CBlockHeader& header, int height, uint32_t status = BLOCK_VALID_TREE)
        : hash(header.GetHash()), index(header)
    {
        LOCK(cs_main);
        index.nHeight = height;
        index.nStatus = status;
        index.pprev = chainActive.Genesis();
        index.nChainWork = index.pprev->nChainWork + GetBlockProof(index);
        const auto inserted = mapBlockIndex.emplace(hash, &index);
        assert(inserted.second);
        index.phashBlock = &inserted.first->first;
    }
    ~TemporaryIndex() { LOCK(cs_main); mapBlockIndex.erase(hash); }
};

struct TemporaryCheckpoint {
    MapCheckpoints saved;
    TemporaryIndex index;
    TemporaryCheckpoint(const CBlockHeader& header, int height)
        : saved(GetParams().Checkpoints().mapCheckpoints), index(header, height)
    {
        LOCK(cs_main);
        const_cast<CCheckpointData&>(GetParams().Checkpoints()).mapCheckpoints[height] = index.hash;
    }
    ~TemporaryCheckpoint()
    {
        LOCK(cs_main);
        const_cast<CCheckpointData&>(GetParams().Checkpoints()).mapCheckpoints = saved;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(header_verification_tests, ParallelSetup)

BOOST_AUTO_TEST_CASE(valid_batch_is_verified_outside_main_and_accepted)
{
    const auto headers = Batch(65);
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        AssertLockNotHeld(cs_main);
        ++constructions;
        return RealContext(epoch);
    });
    const auto before = GetFullKawpowCheckCount();
    const CBlockIndex* last = nullptr;
    CValidationState state;
    BOOST_REQUIRE(ProcessHeadersWithParallelPoW(headers, state, GetParams(), &last, nullptr));
    BOOST_REQUIRE(last);
    BOOST_CHECK_EQUAL(last->nHeight, 65);
    BOOST_CHECK(last->GetBlockHash() == headers.back().GetHash());
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, headers.size());
    BOOST_CHECK_EQUAL(constructions, 1);
}

BOOST_AUTO_TEST_CASE(no_concurrency_and_small_batches_use_the_serial_lock)
{
    const auto headers = Batch(17);
    for (const int workers : {0, 1, 4}) {
        nScriptCheckThreads = workers;
        const size_t count = workers == 4 ? 15 : headers.size();
        int constructions = 0;
        EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int) -> Context {
            AssertLockHeld(cs_main);
            ++constructions;
            return {}; // No accepted headers; every variant starts from the same state.
        });
        CValidationState state;
        const CBlockIndex* last = nullptr;
        BOOST_CHECK(!ProcessHeadersWithParallelPoW({headers.begin(), headers.begin() + count}, state, GetParams(), &last, nullptr));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(last == nullptr);
        BOOST_CHECK_EQUAL(constructions, 1);
    }
}

BOOST_AUTO_TEST_CASE(prefix_notifications_run_without_main_lock)
{
    const auto headers = Batch(32);
    CValidationState state;
    BOOST_REQUIRE(ProcessNewBlockHeaders({}, state, GetParams())); // Reset the notification tip.
    int notifications = 0;
    boost::signals2::scoped_connection watch(uiInterface.NotifyHeaderTip.connect(
        [&](bool, const CBlockIndex*) { AssertLockNotHeld(cs_main); ++notifications; }));
    std::vector<uint8_t> authenticated(headers.size(), 0);
    std::fill_n(authenticated.begin(), 16, uint8_t{1});
    const CBlockIndex* last = nullptr;
    BOOST_REQUIRE(ProcessHeadersWithParallelPoW(headers, state, GetParams(), &last, nullptr, &authenticated));
    BOOST_REQUIRE(last);
    BOOST_CHECK_EQUAL(last->nHeight, 32);
    BOOST_CHECK_EQUAL(notifications, 1);
}

BOOST_AUTO_TEST_CASE(height_and_epoch_boundaries_stop_the_window)
{
    auto headers = Batch(80, false);
    headers[20].nHeight = 999999;
    HeaderVerificationWindow window;
    CValidationState state;
    size_t offset = 0;
    BOOST_CHECK(Prepare(headers, window, state, offset) == HeaderWindowStatus::READY);
    BOOST_CHECK_EQUAL(window.headers.size(), 20U);
    BOOST_CHECK(!window.context);

    auto parent = headers.front();
    ++parent.nNonce64;
    TemporaryIndex previous(parent, 7495);
    headers = Batch(80, false);
    headers.front().hashPrevBlock = previous.hash;
    for (size_t i = 0; i < headers.size(); ++i) headers[i].nHeight = 7496 + i;
    Relink(headers);
    HeaderVerificationWindow edge;
    BOOST_CHECK(Prepare(headers, edge, state, offset) == HeaderWindowStatus::READY);
    BOOST_CHECK_EQUAL(edge.headers.size(), 4U);
    BOOST_CHECK_EQUAL(edge.epoch, 0);
    headers.front().nHeight = 7500; // Mismatch is a serial fallback, never a new reject rule.
    HeaderVerificationWindow mismatch;
    BOOST_CHECK(Prepare(headers, mismatch, state, offset) == HeaderWindowStatus::SERIAL);
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(mismatch.headers.empty());
}

BOOST_AUTO_TEST_CASE(known_invalid_prefix_does_no_speculative_work)
{
    const auto headers = Batch(20, false);
    TemporaryIndex failed(headers.front(), 1, BLOCK_FAILED_VALID);
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        ++constructions; return RealContext(epoch);
    });
    const auto before = GetFullKawpowCheckCount();
    CValidationState state;
    BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, state, GetParams(), nullptr, nullptr));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "duplicate");
    BOOST_CHECK_EQUAL(constructions, 0);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount(), before);
}

BOOST_AUTO_TEST_CASE(sha_and_legacy_headers_do_not_request_kawpow_contexts)
{
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        ++constructions; return RealContext(epoch);
    });
    const auto before = GetFullKawpowCheckCount();
    for (const bool use_sha : {true, false}) {
        bNetwork.fSHA256Mining = use_sha;
        nKAWPOWActivationTime = use_sha ? 0 : UINT32_MAX;
        auto headers = Batch(20, false);
        while (CheckProofOfWork(headers.front().GetHash(), headers.front().nBits, GetParams().GetConsensus()))
            ++headers.front().nNonce;
        Relink(headers);
        CValidationState state;
        BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, state, GetParams(), nullptr, nullptr));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "high-hash");
    }
    BOOST_CHECK_EQUAL(constructions, 0);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount(), before);
}

BOOST_AUTO_TEST_CASE(failure_at_epoch_boundary_never_constructs_the_next_epoch)
{
    auto headers = Batch(40, false);
    auto parent = headers.front();
    ++parent.nNonce64;
    TemporaryIndex previous(parent, 7495);
    headers.front().hashPrevBlock = previous.hash;
    for (size_t i = 0; i < headers.size(); ++i) {
        headers[i].nHeight = 7496 + i;
        headers[i].nBits = 0;
    }
    Relink(headers);
    std::vector<int> epochs;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        epochs.push_back(epoch); return RealContext(epoch);
    });
    const auto before = GetFullKawpowCheckCount();
    CValidationState state;
    BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, state, GetParams(), nullptr, nullptr));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "high-hash");
    BOOST_REQUIRE_EQUAL(epochs.size(), 1U);
    BOOST_CHECK_EQUAL(epochs.front(), 0);
    BOOST_CHECK_LE(GetFullKawpowCheckCount() - before, 5U);
}

BOOST_AUTO_TEST_CASE(checkpoint_sibling_requires_full_pow_and_false_height_is_rejected)
{
    auto headers = Batch(1);
    auto checkpoint = headers.front();
    ++checkpoint.nVersion;
    TemporaryCheckpoint anchor(checkpoint, 1);
    // Cheap validity is irrelevant for a distinct, unauthenticated header.
    do { ++headers.front().mix_hash.begin()[0]; }
    while (!CheckProofOfWork(headers.front().GetHash(), headers.front().nBits, GetParams().GetConsensus()));
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        ++constructions; return RealContext(epoch);
    });
    const auto before = GetFullKawpowCheckCount();
    for (const bool false_height : {false, true}) {
        if (false_height) headers.front().hashPrevBlock = anchor.index.hash;
        CValidationState state;
        BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, state, GetParams(), nullptr, nullptr));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), false_height ? "bad-blk-height" : "invalid-mix-hash");
    }
    BOOST_CHECK_EQUAL(constructions, 1);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
}

BOOST_AUTO_TEST_CASE(false_height_stops_parallel_work_before_later_epochs)
{
    auto headers = Batch(40);
    auto& mismatch = headers[20];
    ++mismatch.nHeight;
    do { ++mismatch.nNonce64; }
    while (!CheckProofOfWork(mismatch.GetHashFull(mismatch.mix_hash), mismatch.nBits, GetParams().GetConsensus()));
    for (size_t i = 21; i < headers.size(); ++i) headers[i].nHeight = 7500 * (i + 1);
    Relink(headers);
    std::vector<int> epochs;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        epochs.push_back(epoch); return RealContext(epoch);
    });
    const auto before = GetFullKawpowCheckCount();
    CValidationState parallel;
    CBlockHeader invalid;
    const CBlockIndex* last = nullptr;
    BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, parallel, GetParams(), &last, &invalid));
    BOOST_CHECK_EQUAL(parallel.GetRejectReason(), "bad-blk-height");
    BOOST_CHECK(invalid.GetHash() == mismatch.GetHash());
    BOOST_REQUIRE(last);
    BOOST_CHECK_EQUAL(last->nHeight, 20);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 20U);
    BOOST_REQUIRE_EQUAL(epochs.size(), 1U);
    BOOST_CHECK_EQUAL(epochs.front(), 0);
    CValidationState serial;
    CBlockHeader serial_invalid;
    BOOST_CHECK(!ProcessNewBlockHeaders(headers, serial, GetParams(), nullptr, &serial_invalid));
    BOOST_CHECK(serial_invalid.GetHash() == invalid.GetHash());
    BOOST_CHECK_EQUAL(serial.GetRejectReason(), parallel.GetRejectReason());
    int serial_dos = 0, parallel_dos = 0;
    BOOST_CHECK_EQUAL(serial.IsInvalid(serial_dos), parallel.IsInvalid(parallel_dos));
    BOOST_CHECK_EQUAL(serial_dos, parallel_dos);
}

BOOST_AUTO_TEST_CASE(pow_and_context_failures_bound_all_speculative_work)
{
    auto headers = Batch(80);
    for (const bool bad_pow : {true, false}) {
        auto candidate = headers;
        if (bad_pow) candidate.front().mix_hash.begin()[0] ^= 1;
        else {
            candidate.front().nTime = chainActive.Tip()->nTime;
            do { ++candidate.front().nNonce64; }
            while (!CheckProofOfWork(candidate.front().GetHashFull(candidate.front().mix_hash), candidate.front().nBits, GetParams().GetConsensus()));
        }
        MineSuffix(candidate);
        CValidationState serial;
        CBlockHeader serial_invalid;
        const CBlockIndex* serial_last = nullptr;
        const auto before_serial = GetFullKawpowCheckCount();
        BOOST_CHECK(!ProcessNewBlockHeaders(candidate, serial, GetParams(), &serial_last, &serial_invalid));
        BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before_serial, 1U);
        const auto before = GetFullKawpowCheckCount();
        CValidationState state;
        CBlockHeader invalid;
        const CBlockIndex* last = nullptr;
        BOOST_CHECK(!ProcessHeadersWithParallelPoW(candidate, state, GetParams(), &last, &invalid));
        BOOST_CHECK(invalid.GetHash() == candidate.front().GetHash());
        BOOST_CHECK(last == nullptr);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), bad_pow ? "invalid-mix-hash" : "time-too-old");
        BOOST_CHECK_EQUAL(state.GetRejectReason(), serial.GetRejectReason());
        BOOST_CHECK_EQUAL(state.GetRejectCode(), serial.GetRejectCode());
        BOOST_CHECK(invalid.GetHash() == serial_invalid.GetHash());
        BOOST_CHECK(last == serial_last);
        int parallel_dos = 0, serial_dos = 0;
        BOOST_CHECK_EQUAL(state.IsInvalid(parallel_dos), serial.IsInvalid(serial_dos));
        BOOST_CHECK_EQUAL(parallel_dos, serial_dos);
        BOOST_CHECK_LE(GetFullKawpowCheckCount() - before, bad_pow ? 17U : 16U);
        BOOST_CHECK_GE(GetFullKawpowCheckCount() - before, bad_pow ? 2U : 1U);
        if (!bad_pow) BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 16U);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.count(candidate.back().GetHash()), 0U);
    }
}

BOOST_AUTO_TEST_CASE(pinned_window_survives_eviction_and_serial_rejection)
{
    auto headers = Batch(20);
    headers.front().mix_hash.begin()[0] ^= 1;
    Relink(headers);
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        if (epoch == 0) { ++constructions; return RealContext(epoch); }
        // Other epochs only create eviction pressure; no worker hashes them.
        return std::make_shared<const ethash::epoch_context>(ethash::epoch_context{epoch, 0, nullptr, nullptr, 0});
    });
    HeaderVerificationWindow window;
    CValidationState state;
    size_t offset = 0;
    BOOST_REQUIRE(Prepare(headers, window, state, offset) == HeaderWindowStatus::READY);
    std::promise<void> started;
    std::atomic<bool> stop{false};
    auto pressure = std::async(std::launch::async, [&] {
        started.set_value();
        size_t requests = 0;
        do {
            KawpowValidationCache().Get(1 + requests % 5);
            ++requests;
        } while (!stop.load(std::memory_order_relaxed));
        return requests;
    });
    started.get_future().get();
    const bool verified = VerifyHeaderWindow(window, 8, GetParams().GetConsensus(), state);
    stop.store(true, std::memory_order_relaxed);
    BOOST_CHECK_GT(pressure.get(), 0U); // Join before assertions can unwind the fixture.
    BOOST_REQUIRE(verified);
    BOOST_CHECK(window.pow_failed);
    BOOST_CHECK_EQUAL(window.checked.front(), 0);
    for (int epoch : {1, 2, 3, 1}) {
        KawpowValidationCache().Get(epoch);
        BOOST_CHECK(KawpowValidationCache().Get(0).get() == &*window.context);
    }
    const auto before = GetFullKawpowCheckCount();
    BOOST_CHECK(!AcceptHeaderWindow(window, GetParams(), state, nullptr, nullptr));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-mix-hash");
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    BOOST_CHECK_EQUAL(constructions, 1);
}

BOOST_AUTO_TEST_CASE(checkpoint_race_acceptance_is_authoritative)
{
    auto headers = Batch(20);
    // A false mix that satisfies the cheap check, but fails full KAWPOW.
    do { ++headers.front().mix_hash.begin()[0]; }
    while (!CheckProofOfWork(headers.front().GetHash(), headers.front().nBits, GetParams().GetConsensus()));
    Relink(headers);
    for (const int checkpoint_height : {2, 1}) {
        HeaderVerificationWindow window;
        CValidationState state;
        size_t offset = 0;
        BOOST_REQUIRE(Prepare(headers, window, state, offset) == HeaderWindowStatus::READY);
        // Use a one-header window so the checkpoint can cover precisely the
        // failed candidate. The suffix must still be processed normally.
        window.headers.resize(1); window.checked.resize(1); window.candidates.resize(1);
        BOOST_REQUIRE(VerifyHeaderWindow(window, 4, GetParams().GetConsensus(), state));
        BOOST_REQUIRE(window.pow_failed);
        auto other = headers.front();
        ++other.nNonce64;
        TemporaryCheckpoint checkpoint(other, checkpoint_height);
        const CBlockIndex* last = nullptr;
        const bool accepted = AcceptHeaderWindow(window, GetParams(), state, &last, nullptr);
        // A sibling is not authenticated at either height. Full PoW fails
        // before contextual fork rejection, just as in serial acceptance.
        BOOST_CHECK(!accepted);
        BOOST_CHECK(last == nullptr);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-mix-hash");
    }
}

BOOST_AUTO_TEST_CASE(known_between_steps_costs_one_speculative_context)
{
    const auto headers = Batch(1);
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        ++constructions; return RealContext(epoch);
    });
    HeaderVerificationWindow window;
    CValidationState state;
    size_t offset = 0;
    BOOST_REQUIRE(Prepare(headers, window, state, offset) == HeaderWindowStatus::READY);
    TemporaryIndex known(headers.front(), 1); // Another validator wins the race.
    const auto before = GetFullKawpowCheckCount();
    const CBlockIndex* last = nullptr;
    BOOST_REQUIRE(ProcessNewBlockHeaders(headers, state, GetParams(), &last));
    BOOST_CHECK(last == &known.index);
    BOOST_CHECK_EQUAL(constructions, 0);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount(), before);
    BOOST_REQUIRE(VerifyHeaderWindow(window, 4, GetParams().GetConsensus(), state));
    BOOST_REQUIRE(AcceptHeaderWindow(window, GetParams(), state, &last, nullptr));
    BOOST_CHECK(last == &known.index);
    BOOST_CHECK_EQUAL(constructions, 1);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
}

BOOST_AUTO_TEST_CASE(context_allocation_failure_is_local_before_any_worker)
{
    const auto headers = Batch(20, false);
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int) -> Context {
        AssertLockNotHeld(cs_main);
        ++constructions;
        return {};
    });
    const auto before = GetFullKawpowCheckCount();
    CValidationState state;
    const CBlockIndex* last = nullptr;
    BOOST_CHECK(!ProcessHeadersWithParallelPoW(headers, state, GetParams(), &last, nullptr));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK(last == nullptr);
    BOOST_CHECK_EQUAL(constructions, 1);
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount(), before);
}

BOOST_AUTO_TEST_CASE(coordinator_processes_suffix_after_authenticated_checkpoint_race)
{
    auto headers = Batch(20);
    do { ++headers.front().mix_hash.begin()[0]; }
    while (!CheckProofOfWork(headers.front().GetHash(), headers.front().nBits, GetParams().GetConsensus()));
    MineSuffix(headers);
    std::unique_ptr<TemporaryCheckpoint> checkpoint;
    int constructions = 0;
    EpochContextCacheTestAccess::FactoryOverride factory(KawpowValidationCache(), [&](int epoch) {
        AssertLockNotHeld(cs_main);
        ++constructions;
        // Inject the fixed commitment to this header, not an unrelated sibling.
        // The test supplies trust explicitly; real anchor hashes are compiled in.
        checkpoint.reset(new TemporaryCheckpoint(headers.front(), 1));
        return RealContext(epoch);
    });
    CValidationState state;
    const CBlockIndex* last = nullptr;
    BOOST_REQUIRE(ProcessHeadersWithParallelPoW(headers, state, GetParams(), &last, nullptr));
    BOOST_REQUIRE(last);
    BOOST_CHECK_EQUAL(last->nHeight, 20);
    BOOST_CHECK(last->GetBlockHash() == headers.back().GetHash());
    BOOST_CHECK_EQUAL(constructions, 1);
}

BOOST_AUTO_TEST_SUITE_END()
