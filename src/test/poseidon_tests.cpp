// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-036: tests for crypto/poseidon_bn254.{h,cpp}.
//
// The hex outputs hardcoded below MUST stay byte-exactly in sync with
// src/test/data/poseidon_vectors.json — drift between the two is
// treated as a consensus-affecting change (NIP-036 §3.6 / §10 merge
// gate). The JSON file is the human-readable single source of truth;
// these inline values are the machine-checkable mirror.

#include "crypto/poseidon_bn254.h"
#include "crypto/poseidon_bn254_constants.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <cstring>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

using crypto::poseidon_bn254_detail::Fr;
using crypto::poseidon_bn254_detail::FrAdd;
using crypto::poseidon_bn254_detail::FrSub;
using crypto::poseidon_bn254_detail::FrMul;
using crypto::poseidon_bn254_detail::FrPow5;
using crypto::poseidon_bn254_detail::FrEqual;
using crypto::poseidon_bn254_detail::FrFromCanonical;
using crypto::poseidon_bn254_detail::FrToCanonical;
using crypto::poseidon_bn254_detail::FrFromBytesBE;
using crypto::poseidon_bn254_detail::FrToBytesBE;
using crypto::poseidon_bn254_detail::Permutation;
using crypto::poseidon_bn254_detail::MODULUS_R;

namespace {

std::string PoseidonHex(const std::vector<unsigned char>& v)
{
    unsigned char hash[32];
    crypto::PoseidonBN254(v.data(), v.size(), hash);
    return HexStr(hash, hash + 32);
}

std::string PoseidonHex(const std::string& s)
{
    return PoseidonHex(std::vector<unsigned char>(s.begin(), s.end()));
}

Fr FrFromU64(uint64_t v)
{
    uint64_t can[4] = {v, 0, 0, 0};
    return FrFromCanonical(can);
}

} // namespace

// =====================================================================
// Suite 1: BN254 Fr arithmetic.
// =====================================================================

BOOST_FIXTURE_TEST_SUITE(bn254_fr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fr_add_zero_identities)
{
    Fr zero = FrFromU64(0);
    Fr one  = FrFromU64(1);

    BOOST_CHECK(FrEqual(FrAdd(zero, zero), zero));
    BOOST_CHECK(FrEqual(FrAdd(zero, one),  one));
    BOOST_CHECK(FrEqual(FrAdd(one,  zero), one));
}

BOOST_AUTO_TEST_CASE(fr_add_small)
{
    BOOST_CHECK(FrEqual(FrAdd(FrFromU64(1), FrFromU64(1)), FrFromU64(2)));
    BOOST_CHECK(FrEqual(FrAdd(FrFromU64(7), FrFromU64(35)), FrFromU64(42)));
}

BOOST_AUTO_TEST_CASE(fr_sub_underflow_wraps_to_r_minus_one)
{
    Fr one = FrFromU64(1);
    Fr two = FrFromU64(2);

    uint64_t rm1[4];
    std::memcpy(rm1, MODULUS_R, sizeof(rm1));
    rm1[0] -= 1;
    Fr expected = FrFromCanonical(rm1);

    BOOST_CHECK(FrEqual(FrSub(one, two), expected));
}

BOOST_AUTO_TEST_CASE(fr_add_wraps_at_r)
{
    // (r-1) + 1 == 0 mod r
    uint64_t rm1[4];
    std::memcpy(rm1, MODULUS_R, sizeof(rm1));
    rm1[0] -= 1;

    Fr expected = FrFromU64(0);
    BOOST_CHECK(FrEqual(FrAdd(FrFromCanonical(rm1), FrFromU64(1)), expected));
}

BOOST_AUTO_TEST_CASE(fr_mul_small)
{
    BOOST_CHECK(FrEqual(FrMul(FrFromU64(7),  FrFromU64(9)),  FrFromU64(63)));
    BOOST_CHECK(FrEqual(FrMul(FrFromU64(2),  FrFromU64(3)),  FrFromU64(6)));
    BOOST_CHECK(FrEqual(FrMul(FrFromU64(1),  FrFromU64(99)), FrFromU64(99)));
    BOOST_CHECK(FrEqual(FrMul(FrFromU64(0),  FrFromU64(99)), FrFromU64(0)));
}

BOOST_AUTO_TEST_CASE(fr_mul_minus_one_squared_is_one)
{
    // (r-1)^2 == (-1)^2 == 1 mod r
    uint64_t rm1[4];
    std::memcpy(rm1, MODULUS_R, sizeof(rm1));
    rm1[0] -= 1;
    Fr neg_one = FrFromCanonical(rm1);

    BOOST_CHECK(FrEqual(FrMul(neg_one, neg_one), FrFromU64(1)));
}

BOOST_AUTO_TEST_CASE(fr_pow5_small)
{
    BOOST_CHECK(FrEqual(FrPow5(FrFromU64(0)),  FrFromU64(0)));
    BOOST_CHECK(FrEqual(FrPow5(FrFromU64(1)),  FrFromU64(1)));
    BOOST_CHECK(FrEqual(FrPow5(FrFromU64(2)),  FrFromU64(32)));
    BOOST_CHECK(FrEqual(FrPow5(FrFromU64(3)),  FrFromU64(243)));
}

BOOST_AUTO_TEST_CASE(fr_mul_reference_external)
{
    // Verified independently in Python:
    //   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    //   a = 0x023456789abcdef0_23456789abcdef01_123456789abcdef0_0123456789abcdef
    //   b = 0x0fedcba098765432_edcba09876543210_fedcba0987654320_0fedcba098765432
    //   (a * b) mod r =
    //   0x211bff58a2a86665_767d8305f13bdbab_5b63f9e7b11dba8f_d8a7a2ceac2b10a5
    uint64_t a_can[4] = {
        0x0123456789abcdefULL, 0x123456789abcdef0ULL,
        0x23456789abcdef01ULL, 0x023456789abcdef0ULL,
    };
    uint64_t b_can[4] = {
        0x0fedcba098765432ULL, 0xfedcba0987654320ULL,
        0xedcba09876543210ULL, 0x0fedcba098765432ULL,
    };
    uint64_t expected_can[4] = {
        0xd8a7a2ceac2b10a5ULL, 0x5b63f9e7b11dba8fULL,
        0x767d8305f13bdbabULL, 0x211bff58a2a86665ULL,
    };
    Fr a = FrFromCanonical(a_can);
    Fr b = FrFromCanonical(b_can);
    Fr expected = FrFromCanonical(expected_can);
    BOOST_CHECK(FrEqual(FrMul(a, b), expected));
}

BOOST_AUTO_TEST_CASE(fr_canonical_roundtrip)
{
    uint64_t in[4] = {
        0x0123456789abcdefULL, 0xfedcba9876543210ULL,
        0xdeadbeefcafebabeULL, 0x0123456789abcdefULL,
    };
    Fr x = FrFromCanonical(in);
    uint64_t out[4];
    FrToCanonical(x, out);
    BOOST_CHECK_EQUAL(out[0], in[0]);
    BOOST_CHECK_EQUAL(out[1], in[1]);
    BOOST_CHECK_EQUAL(out[2], in[2]);
    BOOST_CHECK_EQUAL(out[3], in[3]);
}

BOOST_AUTO_TEST_CASE(fr_bytes_be_roundtrip)
{
    unsigned char in[32] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    Fr x = FrFromBytesBE(in);
    unsigned char out[32];
    FrToBytesBE(x, out);
    BOOST_CHECK(std::memcmp(in, out, 32) == 0);
}

BOOST_AUTO_TEST_SUITE_END()

// =====================================================================
// Suite 2: Poseidon permutation (Layer 1).
//
// The single canonical Iden3-ecosystem interop vector for t=3 is
// Poseidon([1, 2]) — defined as Permutation([0, 1, 2]) and reading
// state[0]. arnaucube/poseidon-rs, circomlibjs and go-iden3-crypto
// all agree on the BE 32-byte output 0x115cc0f5...4417189a. If our
// 195 round constants and 9 MDS entries (poseidon_bn254_constants.h)
// are wrong by even one limb, this test catches it.
// =====================================================================

BOOST_FIXTURE_TEST_SUITE(poseidon_permutation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(permutation_iden3_canonical_1_2)
{
    Fr state[3];
    state[0] = FrFromU64(0);
    state[1] = FrFromU64(1);
    state[2] = FrFromU64(2);

    Permutation(state);

    unsigned char out[32];
    FrToBytesBE(state[0], out);
    BOOST_CHECK_EQUAL(
        HexStr(out, out + 32),
        "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
}

BOOST_AUTO_TEST_CASE(permutation_is_deterministic)
{
    Fr s1[3] = { FrFromU64(0), FrFromU64(1), FrFromU64(2) };
    Fr s2[3] = { FrFromU64(0), FrFromU64(1), FrFromU64(2) };

    Permutation(s1);
    Permutation(s2);

    BOOST_CHECK(FrEqual(s1[0], s2[0]));
    BOOST_CHECK(FrEqual(s1[1], s2[1]));
    BOOST_CHECK(FrEqual(s1[2], s2[2]));
}

BOOST_AUTO_TEST_CASE(permutation_diffuses_input)
{
    // Tiny input change should yield wildly different output.
    Fr s1[3] = { FrFromU64(0), FrFromU64(1), FrFromU64(2) };
    Fr s2[3] = { FrFromU64(0), FrFromU64(1), FrFromU64(3) };

    Permutation(s1);
    Permutation(s2);

    BOOST_CHECK(!FrEqual(s1[0], s2[0]));
}

BOOST_AUTO_TEST_SUITE_END()

// =====================================================================
// Suite 3: Byte sponge (Layer 2) — the 11 §3.6 spec-pinned vectors,
// frozen in src/test/data/poseidon_vectors.json. Drift = consensus
// change.
// =====================================================================

BOOST_FIXTURE_TEST_SUITE(poseidon_sponge_tests, BasicTestingSetup)

namespace {
std::vector<unsigned char> Zeros(size_t n)            { return std::vector<unsigned char>(n, 0); }
std::vector<unsigned char> ImodN(size_t n)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = (unsigned char)(i & 0xff);
    return v;
}
} // namespace

BOOST_AUTO_TEST_CASE(sponge_empty)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(std::vector<unsigned char>{}),
        "067761295e881eec953a764e4d72bbccedf07472b57b9a3f754dcb5012441956");
}

BOOST_AUTO_TEST_CASE(sponge_single_byte_a)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(std::string("a")),
        "2dce4f0b4a54641dee666e6a9704e64f49a52acf86b62c37575088b82fa045e2");
}

BOOST_AUTO_TEST_CASE(sponge_hello)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(std::string("hello")),
        "19a31753d0b32445ade8c7fe5158568be0182b5fb7756fd0229ed62257e5df2b");
}

// Padding boundary cases — the §3.5 worked-examples table.
// L=30 -> N=1, L=31 -> N=2; L=61 -> N=2, L=62 -> N=3;
// L=92 -> N=3, L=93 -> N=4. Each pair must produce different outputs
// because the §3.5 padding (append 0x01, then zero-pad) lands them
// in different chunk counts.

BOOST_AUTO_TEST_CASE(sponge_zero30)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(Zeros(30)),
        "0ee069e6aa796ef0e46cbd51d10468393d443a00f5affe72898d9ab62e335e16");
}

BOOST_AUTO_TEST_CASE(sponge_zero31)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(Zeros(31)),
        "2c8200bd43b6b7ba32d55f85bd480739fefa58c50db8b3b45a998e1e3c9a298e");
}

BOOST_AUTO_TEST_CASE(sponge_zero61)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(Zeros(61)),
        "28bb28a2c7566e896a177dc7328d4298d197973bcac177fb8291984a1cc43b7f");
}

BOOST_AUTO_TEST_CASE(sponge_zero62)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(Zeros(62)),
        "041e9272526a9aaa6d439337caf3229e9d9c5224cd7641000926b9f7817378d9");
}

BOOST_AUTO_TEST_CASE(sponge_zero92)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(Zeros(92)),
        "24a5696413bfaeb8b174f647fabbe8da416ad982bb2fa5e50a5132b7bb6d25ec");
}

BOOST_AUTO_TEST_CASE(sponge_zero93)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(Zeros(93)),
        "19ee3fb113e682469722285be2032401d47cd1647ae9ea785e79120e007612bc");
}

// 520-byte and 3072-byte regimes from NIP §3.7 — the worst cases for
// per-call DoS. byte[i] = i mod 256 for reproducibility.

BOOST_AUTO_TEST_CASE(sponge_520_imod256)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(ImodN(520)),
        "18ba739494c866f1049fd9967b77d46dd32178a5bf16f58b28b65f91975f6b9c");
}

BOOST_AUTO_TEST_CASE(sponge_3072_imod256)
{
    BOOST_CHECK_EQUAL(
        PoseidonHex(ImodN(3072)),
        "0566a0fabf609b0e941d5305ac258bef2e7292febedff18ccf9bf8370399a9e7");
}

// Cross-cutting properties.

BOOST_AUTO_TEST_CASE(sponge_padding_boundary_outputs_differ)
{
    // Adjacent boundary pairs MUST land at different chunk counts and
    // therefore at different outputs. This guards against accidentally
    // making the §3.5 padding rule absorb an extra zero somewhere.
    BOOST_CHECK_NE(PoseidonHex(Zeros(30)), PoseidonHex(Zeros(31)));
    BOOST_CHECK_NE(PoseidonHex(Zeros(61)), PoseidonHex(Zeros(62)));
    BOOST_CHECK_NE(PoseidonHex(Zeros(92)), PoseidonHex(Zeros(93)));
}

BOOST_AUTO_TEST_CASE(sponge_is_deterministic)
{
    auto a = PoseidonHex(std::string("hello"));
    auto b = PoseidonHex(std::string("hello"));
    BOOST_CHECK_EQUAL(a, b);
}

BOOST_AUTO_TEST_CASE(sponge_large_input_no_overrun)
{
    // 1 MB input — exercises long absorption loops + many permutations.
    // We don't assert a specific output here; the goal is to confirm
    // the function survives without crashing or corrupting memory.
    std::vector<unsigned char> big(1 << 20);
    for (size_t i = 0; i < big.size(); ++i) big[i] = (unsigned char)(i & 0xff);
    unsigned char hash[32];
    crypto::PoseidonBN254(big.data(), big.size(), hash);
    // Sanity: output isn't all zeros (random Poseidon outputs aren't 0).
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) if (hash[i] != 0) { all_zero = false; break; }
    BOOST_CHECK(!all_zero);
}

BOOST_AUTO_TEST_SUITE_END()
