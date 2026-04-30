// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/poseidon_bn254.h"
#include "crypto/poseidon_bn254_constants.h"

#include <cstring>

// =====================================================================
// NIP-036 — BN254 Fr arithmetic (Montgomery form, CIOS multiplication).
//
// Modular arithmetic on the BN254 scalar-field modulus
// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// (254 bits; see MODULUS_R in poseidon_bn254_constants.h).
//
// Internal representation: 4 little-endian uint64_t limbs in MONTGOMERY
// form. The value X is stored as X*R mod r, where R = 2^256. Conversion
// to and from canonical form happens at the API boundary
// (FrFromCanonical / FrToCanonical / FrFromBytesBE / FrToBytesBE).
//
// Montgomery setup constants (derived from r, computed once and pinned):
//   kInvNeg   = -r^-1 mod 2^64       (used for the Montgomery reduction
//                                     step's "magic multiplier" m)
//   kRSquared = R^2 mod r            (used to convert canonical -> Mont:
//                                     mont_mul(X, R^2) = X*R^2*R^-1 = X*R)
//
// CIOS algorithm reference: Tolga Acar, "High-Speed Algorithms &
// Architectures For Number-Theoretic Cryptosystems", PhD thesis, 1997,
// §2.4. The sketch is:
//
//   t = [0; 6]
//   for i in 0..4:
//     // multiply step
//     C = 0
//     for j in 0..4:
//       (t[j], C) = t[j] + a[j]*b[i] + C
//     (t[4], t[5]) += C
//
//     // reduction step
//     m = t[0] * kInvNeg mod 2^64
//     C = 0
//     (_, C) = t[0] + m*r[0] + C            // low 64 bits == 0 by m's choice
//     for j in 1..4:
//       (t[j-1], C) = t[j] + m*r[j] + C
//     (t[3], t[4]) = (t[4] + C, t[5] + carry)
//     t[5] = 0
//
//   if t >= r: t -= r
//   return t[0..4]
// =====================================================================

namespace crypto {
namespace poseidon_bn254_detail {

namespace {

// -r^-1 mod 2^64. Verified by: (r mod 2^64) * kInvNeg mod 2^64 == 2^64 - 1.
constexpr uint64_t kInvNeg = 0xc2e1f593efffffffULL;

// R^2 mod r where R = 2^256.
constexpr uint64_t kRSquared[4] = {
    0x1bb8e645ae216da7ULL, 0x53fe3ab1e35c59e3ULL,
    0x8c49833d53bb8085ULL, 0x0216d0b17f4e44a5ULL,
};

// Canonical "1" in non-Montgomery form. Used to convert Montgomery ->
// canonical via mont_mul(X*R, 1) = X*R*1*R^-1 = X.
constexpr uint64_t kOneCanonical[4] = {1, 0, 0, 0};

// Word-pair return type for arithmetic helpers: 64-bit low half plus a
// 64-bit high half (carry / borrow / multiplication overflow).
struct WordPair { uint64_t low, high; };

// Returns (a + b*c + carry_in) split into low and high 64-bit halves.
inline WordPair MulAddCarry(uint64_t a, uint64_t b, uint64_t c, uint64_t carry_in)
{
    __uint128_t s = (__uint128_t)a
                  + (__uint128_t)b * (__uint128_t)c
                  + (__uint128_t)carry_in;
    return { (uint64_t)s, (uint64_t)(s >> 64) };
}

// Returns (a + b + carry_in) split into low and (0 or 1) high.
inline WordPair AddCarry(uint64_t a, uint64_t b, uint64_t carry_in)
{
    __uint128_t s = (__uint128_t)a + (__uint128_t)b + (__uint128_t)carry_in;
    return { (uint64_t)s, (uint64_t)(s >> 64) };
}

// Returns (a - b - borrow_in) split into low and (0 or 1) borrow_out.
inline WordPair SubBorrow(uint64_t a, uint64_t b, uint64_t borrow_in)
{
    __uint128_t d = (__uint128_t)a - (__uint128_t)b - (__uint128_t)borrow_in;
    return { (uint64_t)d, (uint64_t)((d >> 64) & 1u) };
}

// Returns true iff the 4-limb LE value `a` is >= the 4-limb LE value `b`.
inline bool GreaterOrEqual(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return true; // equal
}

// out = a + b mod r. Inputs must each be < r.
void AddModR(uint64_t out[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t tmp[4];
    uint64_t carry = 0;
    {
        auto p = AddCarry(a[0], b[0], carry); tmp[0] = p.low; carry = p.high;
    }
    {
        auto p = AddCarry(a[1], b[1], carry); tmp[1] = p.low; carry = p.high;
    }
    {
        auto p = AddCarry(a[2], b[2], carry); tmp[2] = p.low; carry = p.high;
    }
    {
        auto p = AddCarry(a[3], b[3], carry); tmp[3] = p.low; carry = p.high;
    }
    // tmp is at most 2r-2, so subtract r at most once.
    bool ge = (carry != 0) || GreaterOrEqual(tmp, MODULUS_R);
    if (ge) {
        uint64_t borrow = 0;
        auto s0 = SubBorrow(tmp[0], MODULUS_R[0], borrow); tmp[0] = s0.low; borrow = s0.high;
        auto s1 = SubBorrow(tmp[1], MODULUS_R[1], borrow); tmp[1] = s1.low; borrow = s1.high;
        auto s2 = SubBorrow(tmp[2], MODULUS_R[2], borrow); tmp[2] = s2.low; borrow = s2.high;
        auto s3 = SubBorrow(tmp[3], MODULUS_R[3], borrow); tmp[3] = s3.low; borrow = s3.high;
        (void)borrow;
    }
    std::memcpy(out, tmp, sizeof(tmp));
}

// out = a - b mod r. Inputs must each be < r.
void SubModR(uint64_t out[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t tmp[4];
    uint64_t borrow = 0;
    auto p0 = SubBorrow(a[0], b[0], borrow); tmp[0] = p0.low; borrow = p0.high;
    auto p1 = SubBorrow(a[1], b[1], borrow); tmp[1] = p1.low; borrow = p1.high;
    auto p2 = SubBorrow(a[2], b[2], borrow); tmp[2] = p2.low; borrow = p2.high;
    auto p3 = SubBorrow(a[3], b[3], borrow); tmp[3] = p3.low; borrow = p3.high;
    if (borrow) {
        // a < b: add r back.
        uint64_t carry = 0;
        auto a0 = AddCarry(tmp[0], MODULUS_R[0], carry); tmp[0] = a0.low; carry = a0.high;
        auto a1 = AddCarry(tmp[1], MODULUS_R[1], carry); tmp[1] = a1.low; carry = a1.high;
        auto a2 = AddCarry(tmp[2], MODULUS_R[2], carry); tmp[2] = a2.low; carry = a2.high;
        auto a3 = AddCarry(tmp[3], MODULUS_R[3], carry); tmp[3] = a3.low; carry = a3.high;
        (void)carry;
    }
    std::memcpy(out, tmp, sizeof(tmp));
}

// out = a * b * R^-1 mod r (CIOS Montgomery multiplication).
void MontMul(uint64_t out[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t t[6] = {0, 0, 0, 0, 0, 0};

    for (int i = 0; i < 4; ++i) {
        // ----- Multiply step: t += a * b[i] -----
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            auto p = MulAddCarry(t[j], a[j], b[i], carry);
            t[j] = p.low; carry = p.high;
        }
        // Propagate carry into t[4], spill into t[5].
        auto p4 = AddCarry(t[4], carry, 0);
        t[4] = p4.low;
        t[5] += p4.high; // at most 1

        // ----- Reduction step -----
        // m = t[0] * kInvNeg (mod 2^64) chosen so that t[0] + m*r[0]
        // has its low 64 bits equal to zero.
        uint64_t m = t[0] * kInvNeg;
        carry = 0;
        // The low half of t[0] + m*r[0] is implicitly zero by m's
        // construction; we only need the high half as `carry`.
        {
            auto p = MulAddCarry(t[0], m, MODULUS_R[0], carry);
            carry = p.high;
        }
        for (int j = 1; j < 4; ++j) {
            auto p = MulAddCarry(t[j], m, MODULUS_R[j], carry);
            t[j-1] = p.low; carry = p.high;
        }
        // Shift t[4] -> t[3] (with the final reduction carry), t[5] -> t[4].
        auto p3 = AddCarry(t[4], carry, 0);
        t[3] = p3.low;
        auto p4b = AddCarry(t[5], p3.high, 0);
        t[4] = p4b.low;
        t[5] = 0;
    }

    // After 4 iterations, the accumulator may exceed r by at most r
    // (worst case t[4] == 1 and t[0..3] arbitrary). Subtract r if so.
    bool ge = (t[4] != 0) || GreaterOrEqual(t, MODULUS_R);
    if (ge) {
        uint64_t borrow = 0;
        auto s0 = SubBorrow(t[0], MODULUS_R[0], borrow); t[0] = s0.low; borrow = s0.high;
        auto s1 = SubBorrow(t[1], MODULUS_R[1], borrow); t[1] = s1.low; borrow = s1.high;
        auto s2 = SubBorrow(t[2], MODULUS_R[2], borrow); t[2] = s2.low; borrow = s2.high;
        auto s3 = SubBorrow(t[3], MODULUS_R[3], borrow); t[3] = s3.low; borrow = s3.high;
        (void)borrow;
    }

    std::memcpy(out, t, 32);
}

} // anonymous

// =====================================================================
// Detail API — used by the permutation in commit 3 and by tests.
// =====================================================================

Fr FrFromCanonical(const uint64_t canonical_limbs[4])
{
    // canonical X -> Montgomery: mont_mul(X, R^2) = X*R^2*R^-1 = X*R.
    Fr res;
    MontMul(res.limbs, canonical_limbs, kRSquared);
    return res;
}

void FrToCanonical(const Fr& a, uint64_t out_limbs[4])
{
    // Montgomery X*R -> canonical: mont_mul(X*R, 1) = X*R*1*R^-1 = X.
    MontMul(out_limbs, a.limbs, kOneCanonical);
}

Fr FrFromBytesBE(const unsigned char bytes32[32])
{
    uint64_t canonical[4];
    for (int limb_idx = 0; limb_idx < 4; ++limb_idx) {
        // Limb `limb_idx` (LE) corresponds to BE bytes [24-8*limb_idx ..
        // 31-8*limb_idx]. limbs[0] is the least significant 64 bits.
        const unsigned char* base = bytes32 + (24 - 8 * limb_idx);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | base[i];
        }
        canonical[limb_idx] = v;
    }
    return FrFromCanonical(canonical);
}

void FrToBytesBE(const Fr& x, unsigned char bytes32[32])
{
    uint64_t canonical[4];
    FrToCanonical(x, canonical);
    for (int limb_idx = 0; limb_idx < 4; ++limb_idx) {
        unsigned char* base = bytes32 + (24 - 8 * limb_idx);
        uint64_t v = canonical[limb_idx];
        for (int i = 7; i >= 0; --i) {
            base[i] = (unsigned char)(v & 0xffu);
            v >>= 8;
        }
    }
}

Fr FrAdd(const Fr& a, const Fr& b)
{
    Fr res;
    AddModR(res.limbs, a.limbs, b.limbs);
    return res;
}

Fr FrSub(const Fr& a, const Fr& b)
{
    Fr res;
    SubModR(res.limbs, a.limbs, b.limbs);
    return res;
}

Fr FrMul(const Fr& a, const Fr& b)
{
    Fr res;
    MontMul(res.limbs, a.limbs, b.limbs);
    return res;
}

Fr FrPow5(const Fr& x)
{
    Fr x2 = FrMul(x, x);   // x^2
    Fr x4 = FrMul(x2, x2); // x^4
    return FrMul(x4, x);   // x^5
}

bool FrEqual(const Fr& a, const Fr& b)
{
    return a.limbs[0] == b.limbs[0]
        && a.limbs[1] == b.limbs[1]
        && a.limbs[2] == b.limbs[2]
        && a.limbs[3] == b.limbs[3];
}

// =====================================================================
// Poseidon permutation (t = 3, R_F = 8, R_P = 57, x^5 S-box).
//
// Standard Poseidon paper algorithm (unoptimized). For each of the 65
// rounds:
//   1. ARK   — add round constants C[round*t + i] to state[i] for all i.
//   2. S-box — apply x^5; full rounds touch all t elements, partial
//              rounds touch only state[0].
//   3. MDS   — state = M * state.
//
// Round constants and MDS live in poseidon_bn254_constants.h in
// canonical (non-Montgomery) form. We convert them to Montgomery once,
// the first time the permutation runs, and cache the result behind a
// thread-safe magic-static.
// =====================================================================

namespace {

struct MontConstants {
    Fr rc[195];
    Fr mds[3][3];
};

const MontConstants& GetMontConstants()
{
    static const MontConstants cache = []{
        MontConstants out;
        for (int i = 0; i < 195; ++i) {
            out.rc[i] = FrFromCanonical(POSEIDON_BN254_RC[i]);
        }
        for (int i = 0; i < 3; ++i) {
            for (int j = 0; j < 3; ++j) {
                out.mds[i][j] = FrFromCanonical(POSEIDON_BN254_MDS[i][j]);
            }
        }
        return out;
    }();
    return cache;
}

} // anonymous

void Permutation(Fr state[3])
{
    constexpr int T = 3;
    constexpr int R_F_HALF = 4;        // R_F / 2
    constexpr int R_P = 57;
    constexpr int R_TOTAL = 2 * R_F_HALF + R_P;  // 8 + 57 = 65

    const auto& K = GetMontConstants();

    for (int round = 0; round < R_TOTAL; ++round) {
        // ----- 1. Add round constants -----
        for (int i = 0; i < T; ++i) {
            state[i] = FrAdd(state[i], K.rc[round * T + i]);
        }

        // ----- 2. S-box -----
        // Full rounds: rounds [0, R_F/2) (head) and
        //              [R_F/2 + R_P, R_F + R_P) (tail).
        // Partial rounds: rounds [R_F/2, R_F/2 + R_P).
        const bool is_full = (round < R_F_HALF) ||
                             (round >= R_F_HALF + R_P);
        if (is_full) {
            for (int i = 0; i < T; ++i) {
                state[i] = FrPow5(state[i]);
            }
        } else {
            state[0] = FrPow5(state[0]);
        }

        // ----- 3. MDS multiply: new_state = M * state -----
        Fr new_state[T];
        for (int i = 0; i < T; ++i) {
            new_state[i] = FrMul(K.mds[i][0], state[0]);
            for (int j = 1; j < T; ++j) {
                new_state[i] = FrAdd(new_state[i],
                                     FrMul(K.mds[i][j], state[j]));
            }
        }
        for (int i = 0; i < T; ++i) state[i] = new_state[i];
    }
}

} // namespace poseidon_bn254_detail

// =====================================================================
// Public API — NIP-036 §3.5 byte sponge.
//
// CHUNK = 31 bytes per Fr element (so 2^248 < r holds for any chunk).
// rate = 2, capacity = 1, t = 3 (matching the permutation above).
//
// Padding rule:
//   - Append the single byte 0x01 to the input (domain separator, sits
//     strictly after the input — never between chunks).
//   - Zero-pad to a multiple of CHUNK = 31. The padded length is
//     L' = ceil((L+1)/31) * 31, and we always have N = L'/31 >= 1.
//
// Chunk i (0 <= i < N) is the 31-byte slice [i*31, (i+1)*31) of the
// padded buffer, interpreted as a 31-byte big-endian unsigned integer
// (left-padded with one 0x00 byte to get a 32-byte BE encoding) and
// converted to an Fr element via FrFromBytesBE.
//
// Sponge:
//   state = (0, 0, 0)
//   i = 0
//   while i + 1 < N:
//     state[0] += e_i; state[1] += e_{i+1}; state = Permutation(state); i += 2
//   if i < N:
//     state[0] += e_i; state = Permutation(state)
//
// Output = canonical big-endian 32-byte serialisation of state[0].
//
// We process one chunk at a time without materialising the full padded
// buffer, so memory is O(1) regardless of input length.
// =====================================================================

namespace {

// Build chunk `i` of the padded input as an Fr element. `padded[k]`
// (logically) equals `data[k]` for `k < len`, `0x01` for `k == len`,
// and `0x00` for `k > len`. We render that into a 32-byte big-endian
// buffer (one leading 0x00 + 31 bytes of chunk) and convert.
poseidon_bn254_detail::Fr LoadChunk(const unsigned char* data, size_t len,
                                    size_t chunk_idx)
{
    constexpr size_t CHUNK = 31;
    unsigned char buf[32] = {0}; // buf[0] = 0x00 (the left-pad byte)
    const size_t chunk_start = chunk_idx * CHUNK;
    for (size_t j = 0; j < CHUNK; ++j) {
        size_t pos = chunk_start + j;
        unsigned char b;
        if (pos < len)        b = data[pos];
        else if (pos == len)  b = 0x01;
        else                  b = 0x00;
        buf[1 + j] = b;
    }
    return poseidon_bn254_detail::FrFromBytesBE(buf);
}

} // anonymous

void PoseidonBN254(const unsigned char* data, size_t len, unsigned char hash[32])
{
    using poseidon_bn254_detail::Fr;
    using poseidon_bn254_detail::FrAdd;
    using poseidon_bn254_detail::FrToBytesBE;

    constexpr size_t CHUNK = 31;
    // N = ceil((len + 1) / CHUNK), always >= 1.
    const size_t N = (len + 1 + (CHUNK - 1)) / CHUNK;

    // Initial sponge state (0, 0, 0). Montgomery form of zero is zero,
    // so a value-initialised array is the right starting point.
    Fr state[3] = {};

    size_t i = 0;
    while (i + 1 < N) {
        Fr e_i  = LoadChunk(data, len, i);
        Fr e_i1 = LoadChunk(data, len, i + 1);
        state[0] = FrAdd(state[0], e_i);
        state[1] = FrAdd(state[1], e_i1);
        poseidon_bn254_detail::Permutation(state);
        i += 2;
    }
    if (i < N) {
        Fr e_i = LoadChunk(data, len, i);
        state[0] = FrAdd(state[0], e_i);
        poseidon_bn254_detail::Permutation(state);
    }

    FrToBytesBE(state[0], hash);
}

} // namespace crypto
