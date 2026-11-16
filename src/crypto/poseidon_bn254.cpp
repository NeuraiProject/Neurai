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
constexpr uint64_t kZeroCanonical[4] = {0, 0, 0, 0};

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
// Reference Poseidon permutation (t = 3, R_F = 8, R_P = 57, x^5 S-box).
//
// Standard Poseidon paper algorithm (unoptimized), kept as the reference
// that tests compare Permutation() against. For each of the 65 rounds:
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

void PermutationReference(Fr state[3])
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


// =====================================================================
// Optimized Poseidon permutation: same function as PermutationReference.
//
// 1. Field arithmetic: Montgomery multiplication unrolled with the
//    "no-carry" CIOS variant, valid because the top limb of r leaves a
//    spare bit (as in gnark-crypto), and branchless final reductions.
// 2. Round structure (Poseidon paper, appendix B):
//    - In a partial round only state[0] goes through the S-box, so the
//      constants of state[1] and state[2] can be added after it, that is,
//      pushed through the MDS matrix into the next round. Each partial
//      round is left with one constant, on state[0]; the last one pushes
//      its remainder into the first full round after them.
//    - The matrix D of a partial round factors as B * A, with
//      A = diag(1, Ahat). A commutes with that round's S-box and constant
//      (both only touch state[0]), so it moves into the matrix of the
//      round before. B = [[d00, b01, b02], [d10, 1, 0], [d20, 0, 1]] costs
//      5 multiplications instead of 9. What is left after the first
//      partial round goes into the last full round before them.
// The transformed constants are derived from the pinned ones at first use.
// =====================================================================

namespace {

using u128 = unsigned __int128;

constexpr uint64_t Q0 = MODULUS_R[0], Q1 = MODULUS_R[1], Q2 = MODULUS_R[2], Q3 = MODULUS_R[3];
static_assert(Q3 < 0x7fffffffffffffffULL, "no-carry Montgomery multiplication needs a spare top bit");

inline void ReduceOnce(uint64_t& t0, uint64_t& t1, uint64_t& t2, uint64_t& t3)
{
    u128 d;
    uint64_t b, r0, r1, r2, r3;
    d = (u128)t0 - Q0;     r0 = (uint64_t)d; b = (uint64_t)(d >> 64) & 1;
    d = (u128)t1 - Q1 - b; r1 = (uint64_t)d; b = (uint64_t)(d >> 64) & 1;
    d = (u128)t2 - Q2 - b; r2 = (uint64_t)d; b = (uint64_t)(d >> 64) & 1;
    d = (u128)t3 - Q3 - b; r3 = (uint64_t)d; b = (uint64_t)(d >> 64) & 1;
    const uint64_t keep = 0 - b; // all ones when t < r
    t0 = (t0 & keep) | (r0 & ~keep);
    t1 = (t1 & keep) | (r1 & ~keep);
    t2 = (t2 & keep) | (r2 & ~keep);
    t3 = (t3 & keep) | (r3 & ~keep);
}

inline Fr FastMul(const Fr& a, const Fr& b)
{
    const uint64_t* x = a.limbs;
    const uint64_t* y = b.limbs;
    uint64_t t0, t1, t2, t3, c0, c1, c2, m;
    u128 r;
    {
        const uint64_t v = x[0];
        r = (u128)v * y[0];          c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        m = c0 * kInvNeg;
        c2 = (uint64_t)(((u128)m * Q0 + c0) >> 64);
        r = (u128)v * y[1] + c1;     c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        r = (u128)m * Q1 + c2 + c0;  c2 = (uint64_t)(r >> 64); t0 = (uint64_t)r;
        r = (u128)v * y[2] + c1;     c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        r = (u128)m * Q2 + c2 + c0;  c2 = (uint64_t)(r >> 64); t1 = (uint64_t)r;
        r = (u128)v * y[3] + c1;     c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        r = (u128)m * Q3 + c0 + c2;  t3 = (uint64_t)(r >> 64) + c1; t2 = (uint64_t)r;
    }
    for (int i = 1; i < 4; ++i) {
        const uint64_t v = x[i];
        r = (u128)v * y[0] + t0;      c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        m = c0 * kInvNeg;
        c2 = (uint64_t)(((u128)m * Q0 + c0) >> 64);
        r = (u128)v * y[1] + c1 + t1; c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        r = (u128)m * Q1 + c2 + c0;   c2 = (uint64_t)(r >> 64); t0 = (uint64_t)r;
        r = (u128)v * y[2] + c1 + t2; c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        r = (u128)m * Q2 + c2 + c0;   c2 = (uint64_t)(r >> 64); t1 = (uint64_t)r;
        r = (u128)v * y[3] + c1 + t3; c1 = (uint64_t)(r >> 64); c0 = (uint64_t)r;
        r = (u128)m * Q3 + c0 + c2;   t3 = (uint64_t)(r >> 64) + c1; t2 = (uint64_t)r;
    }
    ReduceOnce(t0, t1, t2, t3);
    return Fr{{t0, t1, t2, t3}};
}

inline Fr FastAdd(const Fr& a, const Fr& b)
{
    // Both below r < 2^254: the sum fits in 256 bits.
    u128 s;
    uint64_t t0, t1, t2, t3;
    s = (u128)a.limbs[0] + b.limbs[0];                       t0 = (uint64_t)s;
    s = (u128)a.limbs[1] + b.limbs[1] + (uint64_t)(s >> 64); t1 = (uint64_t)s;
    s = (u128)a.limbs[2] + b.limbs[2] + (uint64_t)(s >> 64); t2 = (uint64_t)s;
    t3 = a.limbs[3] + b.limbs[3] + (uint64_t)(s >> 64);
    ReduceOnce(t0, t1, t2, t3);
    return Fr{{t0, t1, t2, t3}};
}

inline Fr FastPow5(const Fr& x)
{
    const Fr x2 = FastMul(x, x);
    const Fr x4 = FastMul(x2, x2);
    return FastMul(x4, x);
}

// x^(r-2), by Fermat. Only used to derive the constants.
Fr Inverse(const Fr& x)
{
    const uint64_t e[4] = {Q0 - 2, Q1, Q2, Q3};
    Fr result = FrFromCanonical(kOneCanonical), base = x;
    for (int limb = 0; limb < 4; ++limb) {
        for (int bit = 0; bit < 64; ++bit) {
            if ((e[limb] >> bit) & 1) result = FastMul(result, base);
            base = FastMul(base, base);
        }
    }
    return result;
}

constexpr int R_F_HALF = 4, R_P = 57, R_TOTAL = 2 * R_F_HALF + R_P;

struct OptimizedConstants {
    Fr full[2 * R_F_HALF][3]; // full rounds, in order
    Fr partial[R_P];          // one constant per partial round, on state[0]
    Fr mds[3][3];             // matrix of the full rounds
    Fr pre[3][3];             // matrix of the last full round before the partial ones
    Fr s00[R_P], s01[R_P], s02[R_P], s10[R_P], s20[R_P]; // sparse partial-round matrices
};

const OptimizedConstants& GetOptimizedConstants()
{
    static const OptimizedConstants cache = [] {
        OptimizedConstants out;
        const Fr zero = FrFromCanonical(kZeroCanonical);
        const Fr one = FrFromCanonical(kOneCanonical);
        Fr rc[R_TOTAL][3];
        for (int r = 0; r < R_TOTAL; ++r) {
            for (int i = 0; i < 3; ++i) rc[r][i] = FrFromCanonical(POSEIDON_BN254_RC[3 * r + i]);
        }
        for (int i = 0; i < 3; ++i) {
            for (int j = 0; j < 3; ++j) out.mds[i][j] = FrFromCanonical(POSEIDON_BN254_MDS[i][j]);
        }

        // Constants of the partial rounds, pushed forward.
        for (int r = R_F_HALF; r < R_F_HALF + R_P; ++r) {
            for (int i = 0; i < 3; ++i) {
                rc[r + 1][i] = FastAdd(rc[r + 1][i], FastAdd(FastMul(out.mds[i][1], rc[r][1]),
                                                             FastMul(out.mds[i][2], rc[r][2])));
            }
            out.partial[r - R_F_HALF] = rc[r][0];
        }
        for (int r = 0; r < R_F_HALF; ++r) {
            for (int i = 0; i < 3; ++i) {
                out.full[r][i] = rc[r][i];
                out.full[R_F_HALF + r][i] = rc[R_F_HALF + R_P + r][i];
            }
        }

        // Matrices of the partial rounds, factored from the last one back.
        Fr d[3][3];
        for (int i = 0; i < 3; ++i) for (int j = 0; j < 3; ++j) d[i][j] = out.mds[i][j];
        for (int p = R_P - 1; p >= 0; --p) {
            const Fr a11 = d[1][1], a12 = d[1][2], a21 = d[2][1], a22 = d[2][2];
            const Fr det = FrSub(FastMul(a11, a22), FastMul(a12, a21));
            const Fr inv = Inverse(det);
            // Ahat^-1 = det^-1 * [[a22, -a12], [-a21, a11]]
            const Fr i11 = FastMul(inv, a22), i12 = FastMul(inv, FrSub(zero, a12));
            const Fr i21 = FastMul(inv, FrSub(zero, a21)), i22 = FastMul(inv, a11);
            out.s00[p] = d[0][0];
            out.s01[p] = FastAdd(FastMul(d[0][1], i11), FastMul(d[0][2], i21));
            out.s02[p] = FastAdd(FastMul(d[0][1], i12), FastMul(d[0][2], i22));
            out.s10[p] = d[1][0];
            out.s20[p] = d[2][0];
            // The matrix of the round before becomes A * M.
            const Fr a[3][3] = {{one, zero, zero}, {zero, a11, a12}, {zero, a21, a22}};
            for (int i = 0; i < 3; ++i) {
                for (int j = 0; j < 3; ++j) {
                    d[i][j] = FastAdd(FastAdd(FastMul(a[i][0], out.mds[0][j]), FastMul(a[i][1], out.mds[1][j])),
                                      FastMul(a[i][2], out.mds[2][j]));
                }
            }
        }
        for (int i = 0; i < 3; ++i) for (int j = 0; j < 3; ++j) out.pre[i][j] = d[i][j];
        return out;
    }();
    return cache;
}

inline void Dense(const Fr m[3][3], Fr& a, Fr& b, Fr& c)
{
    const Fr na = FastAdd(FastAdd(FastMul(m[0][0], a), FastMul(m[0][1], b)), FastMul(m[0][2], c));
    const Fr nb = FastAdd(FastAdd(FastMul(m[1][0], a), FastMul(m[1][1], b)), FastMul(m[1][2], c));
    const Fr nc = FastAdd(FastAdd(FastMul(m[2][0], a), FastMul(m[2][1], b)), FastMul(m[2][2], c));
    a = na;
    b = nb;
    c = nc;
}

} // anonymous

void Permutation(Fr state[3])
{
    const OptimizedConstants& k = GetOptimizedConstants();
    Fr a = state[0], b = state[1], c = state[2];
    for (int r = 0; r < R_F_HALF; ++r) {
        a = FastPow5(FastAdd(a, k.full[r][0]));
        b = FastPow5(FastAdd(b, k.full[r][1]));
        c = FastPow5(FastAdd(c, k.full[r][2]));
        Dense(r == R_F_HALF - 1 ? k.pre : k.mds, a, b, c);
    }
    for (int p = 0; p < R_P; ++p) {
        a = FastPow5(FastAdd(a, k.partial[p]));
        const Fr na = FastAdd(FastAdd(FastMul(k.s00[p], a), FastMul(k.s01[p], b)), FastMul(k.s02[p], c));
        b = FastAdd(FastMul(k.s10[p], a), b);
        c = FastAdd(FastMul(k.s20[p], a), c);
        a = na;
    }
    for (int r = R_F_HALF; r < 2 * R_F_HALF; ++r) {
        a = FastPow5(FastAdd(a, k.full[r][0]));
        b = FastPow5(FastAdd(b, k.full[r][1]));
        c = FastPow5(FastAdd(c, k.full[r][2]));
        Dense(k.mds, a, b, c);
    }
    state[0] = a;
    state[1] = b;
    state[2] = c;
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

namespace crypto {
bool IsCanonicalPoseidonField(const unsigned char bytes[32])
{
    // BN254 scalar modulus in canonical big-endian order.
    static constexpr unsigned char modulus[32] = {
        0x30,0x64,0x4e,0x72,0xe1,0x31,0xa0,0x29,0xb8,0x50,0x45,0xb6,0x81,0x81,0x58,0x5d,
        0x28,0x33,0xe8,0x48,0x79,0xb9,0x70,0x91,0x43,0xe1,0xf5,0x93,0xf0,0x00,0x00,0x01
    };
    return std::memcmp(bytes, modulus, 32) < 0;
}

bool PoseidonMerkleNode(const unsigned char left[32], const unsigned char right[32], unsigned char out[32])
{
    if (!IsCanonicalPoseidonField(left) || !IsCanonicalPoseidonField(right)) return false;
    using namespace poseidon_bn254_detail;
    const uint64_t zero[4] = {};
    Fr state[3] = {FrFromCanonical(zero), FrFromBytesBE(left), FrFromBytesBE(right)};
    Permutation(state);
    FrToBytesBE(state[0], out);
    return true;
}
} // namespace crypto
