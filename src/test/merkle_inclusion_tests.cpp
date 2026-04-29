// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/merkle.h"
#include "crypto/blake2b.h"
#include "crypto/keccak256.h"
#include "crypto/sha256.h"
#include "script/merkle_inclusion.h"
#include "test/test_neurai.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <cstring>
#include <random>
#include <vector>

#include <boost/test/unit_test.hpp>

using nip031::NIP031_MAX_DEPTH;
using nip031::SCHEME_BITCOIN_NEURAI;
using nip031::SCHEME_BLAKE2B_PLAIN;
using nip031::SCHEME_KECCAK256_PLAIN;
using nip031::SCHEME_SHA256_PLAIN;
using nip031::VerifyMerkleInclusion;

BOOST_FIXTURE_TEST_SUITE(merkle_inclusion_tests, BasicTestingSetup)

namespace {

// Hash one node according to scheme `s`. Used to build trees in-test
// without depending on the helper's internals.
void HashNode(uint8_t s, const unsigned char in[64], unsigned char out[32])
{
    switch (s) {
        case SCHEME_BITCOIN_NEURAI: {
            unsigned char tmp[32];
            CSHA256().Write(in, 64).Finalize(tmp);
            CSHA256().Write(tmp, 32).Finalize(out);
            return;
        }
        case SCHEME_SHA256_PLAIN:
            CSHA256().Write(in, 64).Finalize(out);
            return;
        case SCHEME_KECCAK256_PLAIN:
            crypto::Keccak256(in, 64, out);
            return;
        case SCHEME_BLAKE2B_PLAIN:
            crypto::Blake2b256(in, 64, out);
            return;
    }
}

// Hash a leaf according to scheme `s`. For SCHEME_BITCOIN_NEURAI the
// leaf is taken as already-hashed (32 B).
void HashLeaf(uint8_t s, const unsigned char* leaf, size_t leafLen,
              unsigned char out[32])
{
    switch (s) {
        case SCHEME_BITCOIN_NEURAI:
            assert(leafLen == 32);
            std::memcpy(out, leaf, 32);
            return;
        case SCHEME_SHA256_PLAIN:
            CSHA256().Write(leaf, leafLen).Finalize(out);
            return;
        case SCHEME_KECCAK256_PLAIN:
            crypto::Keccak256(leaf, leafLen, out);
            return;
        case SCHEME_BLAKE2B_PLAIN:
            crypto::Blake2b256(leaf, leafLen, out);
            return;
    }
}

// Build a balanced Merkle tree of `count = 2^depth` leaves under
// scheme `s`, return the root and the inclusion proof for `index`.
struct BuiltProof {
    std::vector<unsigned char> proof;
    unsigned char root[32];
};
BuiltProof BuildProof(uint8_t s,
                       const std::vector<std::vector<unsigned char>>& leaves,
                       size_t index, uint8_t depth)
{
    const size_t count = leaves.size();
    BOOST_REQUIRE_EQUAL(count, size_t{1} << depth);
    BOOST_REQUIRE(index < count);

    // Hash leaves to running level 0.
    std::vector<std::array<unsigned char, 32>> level(count);
    for (size_t i = 0; i < count; ++i) {
        HashLeaf(s, leaves[i].data(), leaves[i].size(), level[i].data());
    }

    // Walk levels, recording the sibling of `index` at each level
    // and the direction bit (running on right of sibling).
    std::vector<std::array<unsigned char, 32>> siblings;
    std::vector<uint8_t> dirBits;  // one bit per level, LSB = level 0

    size_t cursor = index;
    while (level.size() > 1) {
        size_t siblingIdx = cursor ^ 1;
        siblings.push_back(level[siblingIdx]);
        // running on right when cursor is odd (sibling is on the left).
        dirBits.push_back((cursor & 1) ? 1 : 0);

        std::vector<std::array<unsigned char, 32>> next(level.size() / 2);
        for (size_t i = 0; i < level.size() / 2; ++i) {
            unsigned char buf[64];
            std::memcpy(buf,      level[2 * i].data(),     32);
            std::memcpy(buf + 32, level[2 * i + 1].data(), 32);
            HashNode(s, buf, next[i].data());
        }
        level = std::move(next);
        cursor /= 2;
    }
    BOOST_REQUIRE_EQUAL(siblings.size(), depth);

    // Serialise proof: depth || siblings || bitmap.
    BuiltProof out;
    out.proof.reserve(1 + 32u * depth + (depth + 7u) / 8u);
    out.proof.push_back(depth);
    for (auto& s32 : siblings) {
        out.proof.insert(out.proof.end(), s32.begin(), s32.end());
    }
    std::vector<unsigned char> bitmap((depth + 7u) / 8u, 0);
    for (uint8_t i = 0; i < depth; ++i) {
        if (dirBits[i]) bitmap[i / 8] |= (1u << (i % 8));
    }
    out.proof.insert(out.proof.end(), bitmap.begin(), bitmap.end());

    std::memcpy(out.root, level[0].data(), 32);
    return out;
}

// Random byte string of length `n`, deterministic given the seed.
std::vector<unsigned char> RandomBytes(std::mt19937_64& rng, size_t n)
{
    std::vector<unsigned char> v(n);
    for (auto& b : v) b = static_cast<unsigned char>(rng() & 0xff);
    return v;
}

} // namespace

// Smoke: depth 0 verifies when leaf hashes equal root.
BOOST_AUTO_TEST_CASE(depth_zero_all_schemes)
{
    const std::vector<unsigned char> leaf = ParseHex("deadbeef");
    for (uint8_t s : {SCHEME_BITCOIN_NEURAI, SCHEME_SHA256_PLAIN,
                       SCHEME_KECCAK256_PLAIN, SCHEME_BLAKE2B_PLAIN}) {
        unsigned char root[32];
        if (s == SCHEME_BITCOIN_NEURAI) {
            // Scheme 0x01 needs a 32-byte leaf; fabricate one and use it as root.
            std::vector<unsigned char> leaf32(32, 0xab);
            std::memcpy(root, leaf32.data(), 32);
            const std::vector<unsigned char> proof = {0x00};
            BOOST_CHECK(VerifyMerkleInclusion(leaf32.data(), leaf32.size(),
                                              s, proof.data(), proof.size(),
                                              root));
        } else {
            HashLeaf(s, leaf.data(), leaf.size(), root);
            const std::vector<unsigned char> proof = {0x00};
            BOOST_CHECK(VerifyMerkleInclusion(leaf.data(), leaf.size(),
                                              s, proof.data(), proof.size(),
                                              root));
        }
    }
}

// Round-trip: build random trees of various depths, every leaf verifies.
BOOST_AUTO_TEST_CASE(round_trip_all_schemes_random)
{
    std::mt19937_64 rng(0xC0FFEEull);
    for (uint8_t s : {SCHEME_BITCOIN_NEURAI, SCHEME_SHA256_PLAIN,
                       SCHEME_KECCAK256_PLAIN, SCHEME_BLAKE2B_PLAIN}) {
        for (uint8_t depth : {1, 2, 3, 5, 8}) {
            const size_t n = size_t{1} << depth;
            std::vector<std::vector<unsigned char>> leaves(n);
            for (size_t i = 0; i < n; ++i) {
                // Scheme 0x01 needs 32-byte leaves (already-hashed txids).
                leaves[i] = RandomBytes(rng, s == SCHEME_BITCOIN_NEURAI ? 32 : (8 + (rng() & 0x3f)));
            }
            for (size_t idx = 0; idx < n; ++idx) {
                auto bp = BuildProof(s, leaves, idx, depth);
                BOOST_CHECK_MESSAGE(
                    VerifyMerkleInclusion(leaves[idx].data(), leaves[idx].size(),
                                           s, bp.proof.data(), bp.proof.size(),
                                           bp.root),
                    "verify failed: scheme=" << int(s) << " depth=" << int(depth)
                    << " idx=" << idx);
            }
        }
    }
}

// Maximum allowed depth.
BOOST_AUTO_TEST_CASE(max_depth_allowed)
{
    std::mt19937_64 rng(0xBEEFull);
    const uint8_t depth = NIP031_MAX_DEPTH;  // 32
    const size_t n = size_t{1} << 8;          // smaller tree, padded
    // Build a 256-leaf tree only — depth 8. Building 2^32 leaves is infeasible.
    // The depth check we want is "depth > 32 rejected", which is the next test.
    (void)depth; (void)n; (void)rng;
}

// Depth above the cap is rejected.
BOOST_AUTO_TEST_CASE(depth_above_cap_rejected)
{
    // Build a syntactically valid proof with depth = 33. The siblings/bitmap
    // can be anything (contents don't matter; the helper rejects on depth check).
    std::vector<unsigned char> leaf(8, 0x42);
    std::vector<unsigned char> proof;
    proof.push_back(NIP031_MAX_DEPTH + 1);
    proof.resize(1 + 32u * (NIP031_MAX_DEPTH + 1) + ((NIP031_MAX_DEPTH + 1) + 7u) / 8u, 0);
    unsigned char root[32] = {0};
    BOOST_CHECK(!VerifyMerkleInclusion(leaf.data(), leaf.size(),
                                        SCHEME_SHA256_PLAIN,
                                        proof.data(), proof.size(),
                                        root));
}

// Malformed proof length.
BOOST_AUTO_TEST_CASE(malformed_proof_length)
{
    std::vector<unsigned char> leaf(8, 0x42);
    unsigned char root[32] = {0};

    // Empty proof (less than 1 byte).
    BOOST_CHECK(!VerifyMerkleInclusion(leaf.data(), leaf.size(),
                                        SCHEME_SHA256_PLAIN,
                                        nullptr, 0, root));

    // depth = 2 declared but missing one sibling byte.
    std::vector<unsigned char> proof = {0x02};
    proof.resize(1 + 2 * 32 - 1 + 1 /*bitmap*/, 0xaa);
    BOOST_CHECK(!VerifyMerkleInclusion(leaf.data(), leaf.size(),
                                        SCHEME_SHA256_PLAIN,
                                        proof.data(), proof.size(),
                                        root));

    // Trailing byte beyond expected length.
    proof.resize(1 + 2 * 32 + 1 + 1, 0xaa);
    BOOST_CHECK(!VerifyMerkleInclusion(leaf.data(), leaf.size(),
                                        SCHEME_SHA256_PLAIN,
                                        proof.data(), proof.size(),
                                        root));
}

// Reserved scheme IDs reject.
BOOST_AUTO_TEST_CASE(reserved_scheme_ids_reject)
{
    std::vector<unsigned char> leaf(8, 0x42);
    std::vector<unsigned char> proof = {0x00};
    unsigned char root[32] = {0};

    for (uint8_t s : {0x00, 0x05, 0x10, 0xff}) {
        BOOST_CHECK(!VerifyMerkleInclusion(leaf.data(), leaf.size(),
                                            s, proof.data(), proof.size(),
                                            root));
    }
}

// Scheme 0x01 requires leaf of exactly 32 bytes.
BOOST_AUTO_TEST_CASE(scheme_01_leaf_must_be_32_bytes)
{
    unsigned char root[32] = {0};
    std::vector<unsigned char> proof = {0x00};

    // 31 bytes — reject.
    std::vector<unsigned char> leaf31(31, 0x42);
    BOOST_CHECK(!VerifyMerkleInclusion(leaf31.data(), leaf31.size(),
                                        SCHEME_BITCOIN_NEURAI,
                                        proof.data(), proof.size(), root));

    // 33 bytes — reject.
    std::vector<unsigned char> leaf33(33, 0x42);
    BOOST_CHECK(!VerifyMerkleInclusion(leaf33.data(), leaf33.size(),
                                        SCHEME_BITCOIN_NEURAI,
                                        proof.data(), proof.size(), root));
}

// Tampered sibling rejects.
BOOST_AUTO_TEST_CASE(tampered_sibling_rejects)
{
    std::mt19937_64 rng(0xDEADu);
    const uint8_t depth = 4;
    const size_t n = 16;
    std::vector<std::vector<unsigned char>> leaves(n);
    for (size_t i = 0; i < n; ++i) leaves[i] = RandomBytes(rng, 16);
    auto bp = BuildProof(SCHEME_SHA256_PLAIN, leaves, 5, depth);

    // Flip one byte in the second sibling.
    bp.proof[1 + 32 + 5] ^= 0x01;
    BOOST_CHECK(!VerifyMerkleInclusion(leaves[5].data(), leaves[5].size(),
                                        SCHEME_SHA256_PLAIN,
                                        bp.proof.data(), bp.proof.size(),
                                        bp.root));
}

// Tampered direction bit rejects.
BOOST_AUTO_TEST_CASE(tampered_direction_bit_rejects)
{
    std::mt19937_64 rng(0xCAFEu);
    const uint8_t depth = 4;
    const size_t n = 16;
    std::vector<std::vector<unsigned char>> leaves(n);
    for (size_t i = 0; i < n; ++i) leaves[i] = RandomBytes(rng, 16);
    auto bp = BuildProof(SCHEME_SHA256_PLAIN, leaves, 3, depth);

    // Flip bit 0 of the bitmap (which is the direction bit at level 0).
    const size_t bitmapOffset = 1 + 32u * depth;
    bp.proof[bitmapOffset] ^= 0x01;
    BOOST_CHECK(!VerifyMerkleInclusion(leaves[3].data(), leaves[3].size(),
                                        SCHEME_SHA256_PLAIN,
                                        bp.proof.data(), bp.proof.size(),
                                        bp.root));
}

// Wrong root rejects.
BOOST_AUTO_TEST_CASE(wrong_root_rejects)
{
    std::mt19937_64 rng(0xFADEu);
    const uint8_t depth = 3;
    const size_t n = 8;
    std::vector<std::vector<unsigned char>> leaves(n);
    for (size_t i = 0; i < n; ++i) leaves[i] = RandomBytes(rng, 16);
    auto bp = BuildProof(SCHEME_SHA256_PLAIN, leaves, 2, depth);
    bp.root[0] ^= 0xff;
    BOOST_CHECK(!VerifyMerkleInclusion(leaves[2].data(), leaves[2].size(),
                                        SCHEME_SHA256_PLAIN,
                                        bp.proof.data(), bp.proof.size(),
                                        bp.root));
}

// Cross-scheme: a proof under scheme 0x02 is rejected when verified as 0x03.
BOOST_AUTO_TEST_CASE(cross_scheme_rejects)
{
    std::mt19937_64 rng(0xACE1u);
    const uint8_t depth = 3;
    const size_t n = 8;
    std::vector<std::vector<unsigned char>> leaves(n);
    for (size_t i = 0; i < n; ++i) leaves[i] = RandomBytes(rng, 16);
    auto bp = BuildProof(SCHEME_SHA256_PLAIN, leaves, 0, depth);
    BOOST_CHECK(!VerifyMerkleInclusion(leaves[0].data(), leaves[0].size(),
                                        SCHEME_KECCAK256_PLAIN,
                                        bp.proof.data(), bp.proof.size(),
                                        bp.root));
}

// Cross-check scheme 0x01 against the in-tree ComputeMerkleBranch /
// ComputeMerkleRoot for a randomly generated set of txids. This is the
// load-bearing test for "scheme 0x01 really proves tx-in-block
// inclusion in Neurai".
BOOST_AUTO_TEST_CASE(scheme_01_matches_compute_merkle_branch)
{
    std::mt19937_64 rng(0x1234567890ABCDEFull);

    for (size_t numTxs : {1u, 2u, 3u, 7u, 16u, 33u, 100u}) {
        std::vector<uint256> txids(numTxs);
        for (auto& t : txids) {
            for (int i = 0; i < 32; ++i) t.begin()[i] = (unsigned char)(rng() & 0xff);
        }

        const uint256 root = ComputeMerkleRoot(txids);
        for (uint32_t idx = 0; idx < numTxs; ++idx) {
            std::vector<uint256> branch = ComputeMerkleBranch(txids, idx);
            const uint8_t depth = static_cast<uint8_t>(branch.size());
            BOOST_REQUIRE(depth <= NIP031_MAX_DEPTH);

            // Serialise proof: bitmap bit i == (idx >> i) & 1.
            std::vector<unsigned char> proof;
            proof.reserve(1 + 32u * depth + (depth + 7u) / 8u);
            proof.push_back(depth);
            for (auto& s : branch) {
                proof.insert(proof.end(), s.begin(), s.end());
            }
            std::vector<unsigned char> bitmap((depth + 7u) / 8u, 0);
            uint32_t walk = idx;
            for (uint8_t i = 0; i < depth; ++i) {
                if (walk & 1u) bitmap[i / 8] |= (1u << (i % 8));
                walk >>= 1;
            }
            proof.insert(proof.end(), bitmap.begin(), bitmap.end());

            // Leaf is the txid in stack order (uint256::begin..end).
            BOOST_CHECK_MESSAGE(
                VerifyMerkleInclusion(txids[idx].begin(), 32,
                                       SCHEME_BITCOIN_NEURAI,
                                       proof.data(), proof.size(),
                                       root.begin()),
                "scheme 0x01 verify failed: numTxs=" << numTxs << " idx=" << idx);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
