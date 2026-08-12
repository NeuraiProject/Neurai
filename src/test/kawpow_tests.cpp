// Copyright (c) 2019 Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <test/test_neurai.h>

#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <uint256.h>
#include <validation.h>

#include <crypto/ethash/lib/ethash/endianness.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>

#include "crypto/ethash/helpers.hpp"
#include "crypto/ethash/progpow_test_vectors.hpp"

#include <array>

namespace {
// Restores the global KAWPOW activation time on scope exit, so a test that changes it
// cannot leak the change into other tests even if an assertion aborts the case.
struct KawpowActivationGuard {
    const uint32_t saved;
    explicit KawpowActivationGuard(uint32_t value) : saved(nKAWPOWActivationTime) { nKAWPOWActivationTime = value; }
    ~KawpowActivationGuard() { nKAWPOWActivationTime = saved; }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(kawpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(kawpow_l1_cache)
{
    auto& context = get_ethash_epoch_context_0();

    constexpr auto test_size = 20;
    std::array<uint32_t, test_size> cache_slice;
    for (size_t i = 0; i < cache_slice.size(); ++i)
    cache_slice[i] = ethash::le::uint32(context.l1_cache[i]);

    const std::array<uint32_t, test_size> expected{
        {2492749011, 430724829, 2029256771, 3095580433, 3583790154, 3025086503,
         805985885, 4121693337, 2320382801, 3763444918, 1006127899, 1480743010,
         2592936015, 2598973744, 3038068233, 2754267228, 2867798800, 2342573634,
         467767296, 246004123}};
    int i = 0;
    for (auto item : cache_slice) {
        BOOST_CHECK(item == expected[i]);
        i++;
    }
}

BOOST_AUTO_TEST_CASE(kawpow_hash_empty)
{
    auto& context = get_ethash_epoch_context_0();

    int count = 1000;
    ethash_result result;
    while (count > 0) {
        result = progpow::hash(context, count, {}, 0);
        --count;
    }

    const auto mix_hex = "6e97b47b134fda0c7888802988e1a373affeb28bcd813b6e9a0fc669c935d03a";
    const auto final_hex = "e601a7257a70dc48fccc97a7330d704d776047623b92883d77111fb36870f3d1";
    BOOST_CHECK_EQUAL(to_hex(result.mix_hash), mix_hex);
    BOOST_CHECK_EQUAL(to_hex(result.final_hash), final_hex);
}

BOOST_AUTO_TEST_CASE(kawpow_hash_30000)
{
    const int block_number = 30000;
    const auto header =
            to_hash256("ffeeddccbbaa9988776655443322110000112233445566778899aabbccddeeff");
    const uint64_t nonce = 0x123456789abcdef0;

    auto context = ethash::create_epoch_context(ethash::get_epoch_number(block_number));

    const auto result = progpow::hash(*context, block_number, header, nonce);
    const auto mix_hex = "177b565752a375501e11b6d9d3679c2df6197b2cab3a1ba2d6b10b8c71a3d459";
    const auto final_hex = "c824bee0418e3cfb7fae56e0d5b3b8b14ba895777feea81c70c0ba947146da69";
    BOOST_CHECK_EQUAL(to_hex(result.mix_hash), mix_hex);
    BOOST_CHECK_EQUAL(to_hex(result.final_hash), final_hex);

}

BOOST_AUTO_TEST_CASE(kawpow_hash_and_verify)
{
    ethash::epoch_context_ptr context{nullptr, nullptr};

    for (auto& t : progpow_hash_test_cases)
    {
        const auto epoch_number = ethash::get_epoch_number(t.block_number);
        if (!context || context->epoch_number != epoch_number)
            context = ethash::create_epoch_context(epoch_number);

        const auto header_hash = to_hash256(t.header_hash_hex);
        const auto nonce = std::stoull(t.nonce_hex, nullptr, 16);
        const auto result = progpow::hash(*context, t.block_number, header_hash, nonce);
        BOOST_CHECK_EQUAL(to_hex(result.mix_hash), t.mix_hash_hex);
        BOOST_CHECK_EQUAL(to_hex(result.final_hash), t.final_hash_hex);

        auto success = progpow::verify(
                *context, t.block_number, header_hash, result.mix_hash, nonce, result.final_hash);
        BOOST_CHECK(success);

        auto lower_boundary = result.final_hash;
        --lower_boundary.bytes[31];
        auto final_failure = progpow::verify(
                *context, t.block_number, header_hash, result.mix_hash, nonce, lower_boundary);
        BOOST_CHECK(!final_failure);

        auto different_mix = result.mix_hash;
        ++different_mix.bytes[7];
        auto mix_failure = progpow::verify(
                *context, t.block_number, header_hash, different_mix, nonce, result.final_hash);
        BOOST_CHECK(!mix_failure);
    }
}

BOOST_AUTO_TEST_CASE(kawpow_search)
{
    auto ctxp = ethash::create_epoch_context_full(0);
    auto& ctx = *ctxp;
    auto& ctxl = reinterpret_cast<const ethash::epoch_context&>(ctx);

    auto boundary = to_hash256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto sr = progpow::search(ctx, 0, {}, boundary, 700, 100);
    auto srl = progpow::search_light(ctxl, 0, {}, boundary, 700, 100);

    BOOST_CHECK(sr.mix_hash == ethash::hash256{});
    BOOST_CHECK(sr.final_hash == ethash::hash256{});
    BOOST_CHECK(sr.nonce == 0x0);
    BOOST_CHECK(sr.mix_hash == srl.mix_hash);
    BOOST_CHECK(sr.final_hash == srl.final_hash);
    BOOST_CHECK(sr.nonce == srl.nonce);

    // Switch it to a different starting nonce and find another solution
    sr = progpow::search(ctx, 0, {}, boundary, 300, 100);
    srl = progpow::search_light(ctxl, 0, {}, boundary, 300, 100);

    BOOST_CHECK(sr.mix_hash != ethash::hash256{});
    BOOST_CHECK(sr.final_hash != ethash::hash256{});
    BOOST_CHECK(sr.nonce == 395);
    BOOST_CHECK(sr.mix_hash == srl.mix_hash);
    BOOST_CHECK(sr.final_hash == srl.final_hash);
    BOOST_CHECK(sr.nonce == srl.nonce);

    auto r = progpow::hash(ctx, 0, {}, 395);
    BOOST_CHECK(sr.final_hash == r.final_hash);
    BOOST_CHECK(sr.mix_hash == r.mix_hash);
}

// Consensus rule: once nKAWPOWHeaderHeightCheckActivation is reached, a KAWPOW
// header's declared nHeight must equal the contextual chain height. This closes the
// checkpoint-shortcut vector where a block above the last checkpoint declares a
// height below it to skip real KAWPOW verification.
BOOST_AUTO_TEST_CASE(kawpow_header_height_rule)
{
    KawpowActivationGuard guard(0); // KAWPOW active for any nTime; restored on scope exit

    Consensus::Params params{};
    params.nKAWPOWHeaderHeightCheckActivation = 1000;

    CBlockHeader header;
    header.nTime = 1;

    // Below the activation height the rule is inert, even on a mismatch.
    header.nHeight = 42;
    BOOST_CHECK(CheckKAWPOWHeaderHeight(header, 999, params));

    // At/after activation, the declared height must equal the contextual height.
    header.nHeight = 1000;
    BOOST_CHECK(CheckKAWPOWHeaderHeight(header, 1000, params));   // honest match -> accepted

    header.nHeight = 500;                                         // the attack shape:
    BOOST_CHECK(!CheckKAWPOWHeaderHeight(header, 1000, params));  // declared < real -> rejected

    header.nHeight = 2000;
    BOOST_CHECK(!CheckKAWPOWHeaderHeight(header, 1000, params));  // declared > real -> rejected

    // Pre-KAWPOW headers (nTime below KAWPOW activation) never trigger the rule,
    // because they do not carry a meaningful serialized nHeight.
    nKAWPOWActivationTime = 100;
    header.nTime = 50;                                            // < activation
    header.nHeight = 500;
    BOOST_CHECK(CheckKAWPOWHeaderHeight(header, 1000, params));   // gated off -> accepted
}

// Demonstrates the vulnerability the fix addresses: the mix-only GetHash() used by
// CheckBlockHeader's checkpoint shortcut trusts the miner-supplied mix_hash and never
// recomputes it, and it depends on the miner-controlled nHeight.
BOOST_AUTO_TEST_CASE(kawpow_shortcut_trusts_supplied_mix_hash)
{
    KawpowActivationGuard guard(0); // force the KAWPOW hashing path; restored on scope exit

    CBlockHeader header;
    header.nVersion      = 0x20000000;
    header.hashPrevBlock = uint256S("0x01");
    header.hashMerkleRoot = uint256S("0x02");
    header.nTime         = 1;            // >= activation -> KAWPOW path
    header.nBits         = 0x1e00ffff;
    header.nHeight       = 1000;
    header.nNonce64      = 0;

    // The canonical, memory-hard result an honest miner must produce.
    uint256 canonicalMix;
    const uint256 fullHash = header.GetHashFull(canonicalMix);

    // Honest case: with the correct mix_hash, the cheap mix-only GetHash() reproduces
    // the full hash (this is why the shortcut is normally sound below a checkpoint).
    header.mix_hash = canonicalMix;
    BOOST_CHECK(header.GetHash() == fullHash);

    // Attack surface: GetHash() never checks that mix_hash is the real ProgPoW output.
    // With a bogus mix_hash it still returns a (different) hash derived from it, so an
    // attacker can search cheap (nNonce64, mix_hash) pairs to meet the target instead
    // of doing real memory-hard KAWPOW. The full path (GetHashFull + mix compare) would
    // reject this; the checkpoint shortcut only tests CheckProofOfWork(GetHash()).
    uint256 bogusMix = canonicalMix;
    bogusMix.begin()[0] ^= 0xff;
    header.mix_hash = bogusMix;
    BOOST_CHECK(header.GetHash() != fullHash);

    // The hash depends on nHeight, which is why the shortcut keyed on the miner's
    // declared block.nHeight is exploitable and why the fix pins declared == real.
    header.mix_hash = canonicalMix;
    const uint256 hashAtH1000 = header.GetHash();
    header.nHeight = 1001;
    BOOST_CHECK(header.GetHash() != hashAtH1000);
}

// Recovery: PruneBrokenBlockIndex must drop a placeholder (a parent that was skipped
// during load because its reconstructed header failed PoW, so it keeps nBits == 0) and
// every descendant, while leaving the healthy chain intact.
BOOST_AUTO_TEST_CASE(prune_broken_block_index_removes_orphaned_subtree)
{
    BlockMap map;

    auto add = [&map](const uint256& hash, uint32_t nBits, int nHeight, CBlockIndex* prev) -> CBlockIndex* {
        CBlockIndex* pindex = new CBlockIndex();
        pindex->nBits   = nBits;
        pindex->nHeight = nHeight;
        pindex->pprev   = prev;
        auto it = map.insert(std::make_pair(hash, pindex)).first;
        pindex->phashBlock = &it->first;
        return pindex;
    };

    // Healthy chain: g -> a -> b (all nBits != 0).
    CBlockIndex* g = add(uint256S("0x10"), 0x1e00ffff, 0, nullptr);
    CBlockIndex* a = add(uint256S("0x11"), 0x1e00ffff, 1, g);
                     add(uint256S("0x12"), 0x1e00ffff, 2, a);

    // Contaminated branch hanging off a placeholder p (nBits == 0): p -> c -> d.
    CBlockIndex* p = add(uint256S("0x20"), 0,          0,   nullptr);
    CBlockIndex* c = add(uint256S("0x21"), 0x1e00ffff, 100, p);
                     add(uint256S("0x22"), 0x1e00ffff, 101, c);

    BOOST_CHECK_EQUAL(map.size(), 6u);

    const size_t pruned = PruneBrokenBlockIndex(map);

    BOOST_CHECK_EQUAL(pruned, 3u);       // p, c, d
    BOOST_CHECK_EQUAL(map.size(), 3u);   // g, a, b survive
    BOOST_CHECK(map.count(uint256S("0x10")) == 1);
    BOOST_CHECK(map.count(uint256S("0x11")) == 1);
    BOOST_CHECK(map.count(uint256S("0x12")) == 1);
    BOOST_CHECK(map.count(uint256S("0x20")) == 0);
    BOOST_CHECK(map.count(uint256S("0x21")) == 0);
    BOOST_CHECK(map.count(uint256S("0x22")) == 0);

    // The helper freed the pruned entries; free the survivors here.
    for (auto& item : map) delete item.second;
}

BOOST_AUTO_TEST_SUITE_END()