// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include <arith_uint256.h>
#include <hash.h>
#include <miner.h>
#include <test/epoch_context_cache_test_access.h>
#include <test/test_neurai.h>

#include <boost/test/unit_test.hpp>
#include <future>
#include <limits>

namespace {
struct NonceSetup : BasicTestingSetup {
    const uint32_t savedActivation{nKAWPOWActivationTime};
    const BlockNetwork savedNetwork{bNetwork};
    NonceSetup() { bNetwork = BlockNetwork(); nKAWPOWActivationTime = 2000000000; }
    ~NonceSetup() { nKAWPOWActivationTime = savedActivation; bNetwork = savedNetwork; }
};

CBlockHeader Header(uint32_t time)
{
    CBlockHeader block;
    block.nVersion = 4;
    block.nTime = time;
    block.nHeight = 1;
    block.nBits = 0x207fffff;
    block.hashPrevBlock.SetHex("1234");
    block.hashMerkleRoot.SetHex("5678");
    return block;
}

void CheckSearch(CBlockHeader block, bool kawpow)
{
    const arith_uint256 target = arith_uint256().SetCompact(block.nBits);
    uint256 mix;
    // Start from a demonstrably unsuccessful nonce. A test starting from a
    // solution would pass even if the miner never advanced its nonce.
    unsigned int skip = 0;
    while (UintToArith256(block.GetHashFull(mix)) <= target && skip < 100) {
        ++block.nNonce; ++block.nNonce64; ++skip;
    }
    BOOST_REQUIRE_LT(skip, 100U);
    const CBlockHeader before = block;
    uint64_t hashes = 0;
    BOOST_REQUIRE(ScanBlockNonces(block, target, 64, hashes) == MiningScanResult::FOUND);
    BOOST_CHECK_GT(hashes, 1U);
    BOOST_CHECK_LE(hashes, 64U);
    BOOST_CHECK(UintToArith256(block.GetHashFull(mix)) <= target);
    BOOST_CHECK(block.mix_hash == mix);
    BOOST_CHECK(block.GetHash() == block.GetHashFull(mix));
    if (kawpow) {
        BOOST_CHECK_EQUAL(block.nNonce, before.nNonce);
        BOOST_CHECK_EQUAL(block.nNonce64, before.nNonce64 + hashes - 1);
        BOOST_CHECK(!block.mix_hash.IsNull());
    } else {
        BOOST_CHECK_EQUAL(block.nNonce64, before.nNonce64);
        BOOST_CHECK_EQUAL(block.nNonce, before.nNonce + hashes - 1);
    }
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(miner_nonce_tests, NonceSetup)

BOOST_AUTO_TEST_CASE(kawpow_search_changes_the_64_bit_nonce_and_saves_the_mix)
{
    CheckSearch(Header(nKAWPOWActivationTime), true);
}

BOOST_AUTO_TEST_CASE(legacy_search_preserves_the_64_bit_nonce)
{
    CheckSearch(Header(1500000000), false); // X16R
    CheckSearch(Header(1600000000), false); // X16Rv2
}

BOOST_AUTO_TEST_CASE(sha256_search_uses_32_bits_even_after_the_kawpow_timestamp)
{
    bNetwork.fSHA256Mining = true;
    CheckSearch(Header(nKAWPOWActivationTime), false);
}

BOOST_AUTO_TEST_CASE(bounded_search_resumes_without_repeating_work)
{
    for (bool kawpow : {false, true}) {
        CBlockHeader block = Header(kawpow ? nKAWPOWActivationTime : 1500000000);
        block.nNonce = 0xfffffffeU;
        block.nNonce64 = 0xfffffffeULL;
        block.mix_hash.SetHex("123");
        const uint256 previousMix = block.mix_hash;
        uint64_t hashes = 99;
        const arith_uint256 impossible(0);
        BOOST_CHECK(ScanBlockNonces(block, impossible, 0, hashes) == MiningScanResult::MORE);
        BOOST_CHECK_EQUAL(hashes, 0U);
        BOOST_CHECK_EQUAL(block.nNonce, 0xfffffffeU);
        BOOST_CHECK_EQUAL(block.nNonce64, 0xfffffffeULL);
        BOOST_CHECK(ScanBlockNonces(block, impossible, 1, hashes) == MiningScanResult::MORE);
        BOOST_CHECK_EQUAL(hashes, 1U);
        BOOST_CHECK_EQUAL(kawpow ? block.nNonce64 : block.nNonce, 0xffffffffULL);
        if (kawpow) {
            BOOST_CHECK(ScanBlockNonces(block, impossible, 2, hashes) == MiningScanResult::MORE);
            BOOST_CHECK_EQUAL(hashes, 2U);
            BOOST_CHECK_EQUAL(block.nNonce64, 0x100000001ULL);
            BOOST_CHECK_EQUAL(block.nNonce, 0xfffffffeU);
        } else {
            BOOST_CHECK(ScanBlockNonces(block, impossible, 2, hashes) == MiningScanResult::EXHAUSTED);
            BOOST_CHECK_EQUAL(hashes, 1U);
            BOOST_CHECK_EQUAL(block.nNonce, 0xffffffffU);
            BOOST_CHECK_EQUAL(block.nNonce64, 0xfffffffeULL);
        }
        BOOST_CHECK(block.mix_hash == previousMix);
    }
}

BOOST_AUTO_TEST_CASE(last_nonce_is_tried_once_without_wrapping)
{
    for (bool kawpow : {false, true}) {
        CBlockHeader block = Header(kawpow ? nKAWPOWActivationTime : 1500000000);
        block.nNonce = std::numeric_limits<uint32_t>::max();
        block.nNonce64 = std::numeric_limits<uint64_t>::max();
        uint64_t hashes = 0;
        BOOST_CHECK(ScanBlockNonces(block, arith_uint256(0), 2, hashes) == MiningScanResult::EXHAUSTED);
        BOOST_CHECK_EQUAL(hashes, 1U);
        BOOST_CHECK_EQUAL(block.nNonce, std::numeric_limits<uint32_t>::max());
        BOOST_CHECK_EQUAL(block.nNonce64, std::numeric_limits<uint64_t>::max());
        // Exhaustion must not discard a solution at the last nonce.
        const arith_uint256 easiest = ~arith_uint256(0);
        BOOST_REQUIRE(ScanBlockNonces(block, easiest, 2, hashes) == MiningScanResult::FOUND);
        BOOST_CHECK_EQUAL(hashes, 1U);
    }
}

BOOST_AUTO_TEST_CASE(interruption_is_checked_before_hashing)
{
    std::promise<void> ready, proceed;
    auto go = proceed.get_future();
    bool interrupted = false;
    uint64_t hashes = 99;
    CBlockHeader block = Header(nKAWPOWActivationTime);
    boost::thread worker([&] {
        ready.set_value();
        go.wait();
        try { ScanBlockNonces(block, arith_uint256(0), 1, hashes); }
        catch (const boost::thread_interrupted&) { interrupted = true; }
    });
    ready.get_future().wait();
    worker.interrupt();
    proceed.set_value();
    worker.join();
    BOOST_CHECK(interrupted);
    BOOST_CHECK_EQUAL(hashes, 0U);
    BOOST_CHECK_EQUAL(block.nNonce64, 0U);
}

BOOST_AUTO_TEST_CASE(local_hashing_errors_do_not_advance_the_nonce)
{
    EpochContextCacheTestAccess::FactoryOverride failure(KawpowValidationCache(), [](int) -> EpochContextCache::Context {
        throw std::bad_alloc();
    });
    CBlockHeader block = Header(nKAWPOWActivationTime);
    uint64_t hashes = 99;
    BOOST_CHECK_THROW(ScanBlockNonces(block, arith_uint256(0), 2, hashes), std::bad_alloc);
    BOOST_CHECK_EQUAL(hashes, 0U);
    BOOST_CHECK_EQUAL(block.nNonce64, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
