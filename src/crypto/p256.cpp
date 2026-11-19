// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-060 strict-profile ECDSA P-256 verification. See crypto/p256.h for the
// consensus rules. Field and scalar arithmetic: Fiat Cryptography
// (crypto/p256/fiat, Montgomery domain, fully reduced outputs). Point
// arithmetic: Jacobian coordinates with the a = -3 doubling formula
// (dbl-2001-b) and add-2007-bl addition, both with explicit handling of the
// point at infinity and of P == +-Q. Double scalar multiplication:
// interleaved wNAF (width 7 for the generator, from a static affine table;
// width 5 for the public key). Everything here is variable time: it only
// processes public data (keys, signatures, messages).

#include "crypto/p256.h"

#include "crypto/sha256.h"

#include <cstring>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#if defined(__SIZEOF_INT128__) && !defined(NEURAI_P256_FORCE_32BIT)
#include "crypto/p256/fiat/p256_64.h"
#include "crypto/p256/fiat/p256_scalar_64.h"
#define NEURAI_P256_LIMBS 4
typedef uint64_t p256_limb_t;
#else
#include "crypto/p256/fiat/p256_32.h"
#include "crypto/p256/fiat/p256_scalar_32.h"
#define NEURAI_P256_LIMBS 8
typedef uint32_t p256_limb_t;
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

namespace crypto {
namespace p256 {
namespace {

// Curve constants, big-endian (SEC 2, secp256r1).
const uint8_t P_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t N_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
const uint8_t HALF_N_BE[32] = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8};
const uint8_t P_MINUS_N_BE[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x19, 0x05, 0x53, 0x58, 0xe8, 0x61, 0x7b,
    0x0c, 0x46, 0x35, 0x3d, 0x03, 0x9c, 0xda, 0xae};
const uint8_t B_BE[32] = {
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
    0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
    0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b};
const uint8_t GX_BE[32] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
const uint8_t GY_BE[32] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
// (p + 1) / 4: p = 3 mod 4, so a square root of a square r is r^((p+1)/4).
const uint8_t P_SQRT_EXP_BE[32] = {
    0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t P_MINUS_2_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd};
const uint8_t N_MINUS_2_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f};

// wNAF window widths. Digits are odd and |d| < 2^(w-1); a table holds the
// odd multiples 1P, 3P, ..., (2^(w-1) - 1)P.
constexpr int G_WINDOW = 7;
constexpr int Q_WINDOW = 5;
constexpr int G_TABLE_SIZE = 1 << (G_WINDOW - 2);
constexpr int Q_TABLE_SIZE = 1 << (Q_WINDOW - 2);
// A scalar below 2^256 has a wNAF of at most 257 digits.
constexpr int WNAF_MAX = 258;

typedef p256_limb_t fe[NEURAI_P256_LIMBS]; // field element, Montgomery domain
typedef p256_limb_t sc[NEURAI_P256_LIMBS]; // scalar mod n, Montgomery domain

bool IsZero32(const uint8_t a[32])
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; ++i) acc |= a[i];
    return acc == 0;
}

// Big-endian comparison of 32-byte integers: memcmp orders them correctly.
int Cmp32(const uint8_t a[32], const uint8_t b[32]) { return memcmp(a, b, 32); }

// out = a - b for big-endian 32-byte integers, a >= b.
void Sub32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int v = int(a[i]) - int(b[i]) - borrow;
        borrow = v < 0;
        out[i] = uint8_t(v + (borrow ? 256 : 0));
    }
}

// out = a + b for big-endian 32-byte integers; the sum must fit.
void Add32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    int carry = 0;
    for (int i = 31; i >= 0; --i) {
        int v = int(a[i]) + int(b[i]) + carry;
        carry = v >> 8;
        out[i] = uint8_t(v & 0xff);
    }
}

void Reverse32(uint8_t out[32], const uint8_t in[32])
{
    for (int i = 0; i < 32; ++i) out[i] = in[31 - i];
}

// --- Field arithmetic (mod p), inputs strictly below p --------------------

void FeFromBE(fe out, const uint8_t in[32])
{
    uint8_t le[32];
    Reverse32(le, in);
    fe plain;
    fiat_p256_from_bytes(plain, le);
    fiat_p256_to_montgomery(out, plain);
}

void FeToBE(uint8_t out[32], const fe in)
{
    fe plain;
    fiat_p256_from_montgomery(plain, in);
    uint8_t le[32];
    fiat_p256_to_bytes(le, plain);
    Reverse32(out, le);
}

void FeCopy(fe out, const fe in) { memcpy(out, in, sizeof(fe)); }

bool FeIsZero(const fe a)
{
    p256_limb_t nz;
    fiat_p256_nonzero(&nz, a);
    return nz == 0;
}

bool FeEqual(const fe a, const fe b)
{
    fe d;
    fiat_p256_sub(d, a, b);
    return FeIsZero(d);
}

void FeOne(fe out) { fiat_p256_set_one(out); }

// out = base^exp, exp big-endian, plain square-and-multiply (public data).
void FePow(fe out, const fe base, const uint8_t exp[32])
{
    fe acc, b;
    FeCopy(b, base);
    FeOne(acc);
    for (int i = 0; i < 256; ++i) {
        fiat_p256_square(acc, acc);
        if ((exp[i >> 3] >> (7 - (i & 7))) & 1) fiat_p256_mul(acc, acc, b);
    }
    FeCopy(out, acc);
}

// --- Scalar arithmetic (mod n), inputs strictly below n -------------------

void ScFromBE(sc out, const uint8_t in[32])
{
    uint8_t le[32];
    Reverse32(le, in);
    sc plain;
    fiat_p256_scalar_from_bytes(plain, le);
    fiat_p256_scalar_to_montgomery(out, plain);
}

void ScToBE(uint8_t out[32], const sc in)
{
    sc plain;
    fiat_p256_scalar_from_montgomery(plain, in);
    uint8_t le[32];
    fiat_p256_scalar_to_bytes(le, plain);
    Reverse32(out, le);
}

// out = a^(n-2) = a^-1 for a != 0 (Fermat; n is prime).
void ScInverse(sc out, const sc a)
{
    sc acc;
    fiat_p256_scalar_set_one(acc);
    for (int i = 0; i < 256; ++i) {
        fiat_p256_scalar_square(acc, acc);
        if ((N_MINUS_2_BE[i >> 3] >> (7 - (i & 7))) & 1) fiat_p256_scalar_mul(acc, acc, a);
    }
    memcpy(out, acc, sizeof(sc));
}

// --- Points ---------------------------------------------------------------

struct Jacobian {
    fe X, Y, Z; // affine (X/Z^2, Y/Z^3); Z == 0 is the point at infinity
};

struct Affine {
    fe x, y;
};

bool IsInfinity(const Jacobian& p) { return FeIsZero(p.Z); }

void SetInfinity(Jacobian& p)
{
    memset(&p, 0, sizeof(p));
    FeOne(p.X);
    FeOne(p.Y);
}

// dbl-2001-b (a = -3). Safe when out aliases in; infinity maps to infinity.
void Double(Jacobian& out, const Jacobian& in)
{
    if (IsInfinity(in)) {
        out = in;
        return;
    }
    fe delta, gamma, beta, alpha, t1, t2, x3, y3, z3;
    fiat_p256_square(delta, in.Z);
    fiat_p256_square(gamma, in.Y);
    fiat_p256_mul(beta, in.X, gamma);
    fiat_p256_sub(t1, in.X, delta);
    fiat_p256_add(t2, in.X, delta);
    fiat_p256_mul(alpha, t1, t2);
    fiat_p256_add(t1, alpha, alpha);
    fiat_p256_add(alpha, t1, alpha); // alpha = 3 (X - delta)(X + delta)
    // X3 = alpha^2 - 8 beta
    fiat_p256_square(x3, alpha);
    fiat_p256_add(t1, beta, beta);   // 2 beta
    fiat_p256_add(t1, t1, t1);       // 4 beta
    fiat_p256_add(t2, t1, t1);       // 8 beta
    fiat_p256_sub(x3, x3, t2);
    // Z3 = (Y + Z)^2 - gamma - delta
    fiat_p256_add(z3, in.Y, in.Z);
    fiat_p256_square(z3, z3);
    fiat_p256_sub(z3, z3, gamma);
    fiat_p256_sub(z3, z3, delta);
    // Y3 = alpha (4 beta - X3) - 8 gamma^2
    fiat_p256_sub(t1, t1, x3);
    fiat_p256_mul(y3, alpha, t1);
    fiat_p256_square(t2, gamma);
    fiat_p256_add(t2, t2, t2);
    fiat_p256_add(t2, t2, t2);
    fiat_p256_add(t2, t2, t2);       // 8 gamma^2
    fiat_p256_sub(y3, y3, t2);
    FeCopy(out.X, x3);
    FeCopy(out.Y, y3);
    FeCopy(out.Z, z3);
}

// General Jacobian addition (add-2007-bl without the 2x scaling). Handles
// infinity on either side, P == Q (doubling) and P == -Q (infinity).
void Add(Jacobian& out, const Jacobian& a, const Jacobian& b)
{
    if (IsInfinity(a)) { out = b; return; }
    if (IsInfinity(b)) { out = a; return; }
    fe z1z1, z2z2, u1, u2, s1, s2, h, r, t;
    fiat_p256_square(z1z1, a.Z);
    fiat_p256_square(z2z2, b.Z);
    fiat_p256_mul(u1, a.X, z2z2);
    fiat_p256_mul(u2, b.X, z1z1);
    fiat_p256_mul(t, b.Z, z2z2);
    fiat_p256_mul(s1, a.Y, t);
    fiat_p256_mul(t, a.Z, z1z1);
    fiat_p256_mul(s2, b.Y, t);
    fiat_p256_sub(h, u2, u1);
    fiat_p256_sub(r, s2, s1);
    if (FeIsZero(h)) {
        if (FeIsZero(r)) {
            Jacobian d;
            Double(d, a);
            out = d;
        } else {
            SetInfinity(out);
        }
        return;
    }
    fe hh, hhh, v, x3, y3, z3;
    fiat_p256_square(hh, h);
    fiat_p256_mul(hhh, h, hh);
    fiat_p256_mul(v, u1, hh);
    // X3 = r^2 - HHH - 2V
    fiat_p256_square(x3, r);
    fiat_p256_sub(x3, x3, hhh);
    fiat_p256_sub(x3, x3, v);
    fiat_p256_sub(x3, x3, v);
    // Y3 = r (V - X3) - S1 HHH
    fiat_p256_sub(t, v, x3);
    fiat_p256_mul(y3, r, t);
    fiat_p256_mul(t, s1, hhh);
    fiat_p256_sub(y3, y3, t);
    // Z3 = Z1 Z2 H
    fiat_p256_mul(z3, a.Z, b.Z);
    fiat_p256_mul(z3, z3, h);
    FeCopy(out.X, x3);
    FeCopy(out.Y, y3);
    FeCopy(out.Z, z3);
}

// Mixed addition a + (bx, by) with an affine second operand (Z2 = 1).
void AddAffine(Jacobian& out, const Jacobian& a, const fe bx, const fe by)
{
    if (IsInfinity(a)) {
        FeCopy(out.X, bx);
        FeCopy(out.Y, by);
        FeOne(out.Z);
        return;
    }
    fe z1z1, u2, s2, h, r, t;
    fiat_p256_square(z1z1, a.Z);
    fiat_p256_mul(u2, bx, z1z1);
    fiat_p256_mul(t, a.Z, z1z1);
    fiat_p256_mul(s2, by, t);
    fiat_p256_sub(h, u2, a.X);
    fiat_p256_sub(r, s2, a.Y);
    if (FeIsZero(h)) {
        if (FeIsZero(r)) {
            Jacobian d;
            Double(d, a);
            out = d;
        } else {
            SetInfinity(out);
        }
        return;
    }
    fe hh, hhh, v, x3, y3, z3;
    fiat_p256_square(hh, h);
    fiat_p256_mul(hhh, h, hh);
    fiat_p256_mul(v, a.X, hh);
    fiat_p256_square(x3, r);
    fiat_p256_sub(x3, x3, hhh);
    fiat_p256_sub(x3, x3, v);
    fiat_p256_sub(x3, x3, v);
    fiat_p256_sub(t, v, x3);
    fiat_p256_mul(y3, r, t);
    fiat_p256_mul(t, a.Y, hhh);
    fiat_p256_sub(y3, y3, t);
    fiat_p256_mul(z3, a.Z, h);
    FeCopy(out.X, x3);
    FeCopy(out.Y, y3);
    FeCopy(out.Z, z3);
}

void ToAffine(Affine& out, const Jacobian& in)
{
    fe zinv, zinv2, zinv3;
    FePow(zinv, in.Z, P_MINUS_2_BE);
    fiat_p256_square(zinv2, zinv);
    fiat_p256_mul(zinv3, zinv2, zinv);
    fiat_p256_mul(out.x, in.X, zinv2);
    fiat_p256_mul(out.y, in.Y, zinv3);
}

// Odd multiples 1G, 3G, ..., (2^(G_WINDOW-1) - 1)G in affine form, built
// once (thread-safe static initialization).
struct GeneratorTable {
    Affine point[G_TABLE_SIZE];
    GeneratorTable()
    {
        Jacobian g, g2, acc;
        FeFromBE(g.X, GX_BE);
        FeFromBE(g.Y, GY_BE);
        FeOne(g.Z);
        Double(g2, g);
        acc = g;
        for (int i = 0; i < G_TABLE_SIZE; ++i) {
            ToAffine(point[i], acc);
            Add(acc, acc, g2);
        }
    }
};

const GeneratorTable& GetGeneratorTable()
{
    static const GeneratorTable table;
    return table;
}

// Width-w NAF of a big-endian scalar below 2^256, least significant digit
// first. Returns the number of digits.
int ComputeWNAF(int8_t out[WNAF_MAX], const uint8_t scalar[32], int w)
{
    // Five 64-bit little-endian words: subtracting a negative digit can
    // carry past bit 256 for scalars close to 2^256.
    uint64_t k[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 32; ++i) {
        k[i / 8] |= uint64_t(scalar[31 - i]) << (8 * (i % 8));
    }
    memset(out, 0, WNAF_MAX);
    const uint64_t mask = (uint64_t{1} << w) - 1;
    const int64_t half = int64_t{1} << (w - 1);
    int len = 0;
    while ((k[0] | k[1] | k[2] | k[3] | k[4]) != 0) {
        int8_t digit = 0;
        if (k[0] & 1) {
            int64_t mod = int64_t(k[0] & mask);
            if (mod >= half) mod -= int64_t{1} << w;
            digit = int8_t(mod);
            if (mod > 0) {
                // Clears the low bits: no borrow beyond the first word.
                k[0] -= uint64_t(mod);
            } else {
                uint64_t add = uint64_t(-mod);
                for (int i = 0; i < 5 && add; ++i) {
                    const uint64_t prev = k[i];
                    k[i] += add;
                    add = k[i] < prev ? 1 : 0;
                }
            }
        }
        out[len++] = digit;
        for (int i = 0; i < 4; ++i) k[i] = (k[i] >> 1) | (k[i + 1] << 63);
        k[4] >>= 1;
    }
    return len;
}

} // namespace

StructuralResult ParsePublicKey(const uint8_t* pub, size_t len, PublicKey& out) noexcept
{
    if (len != PUBKEY_SIZE) return StructuralResult::PUBKEY_SIZE_INVALID;
    if (pub[0] != 0x02 && pub[0] != 0x03) return StructuralResult::PUBKEY_PREFIX_INVALID;
    const uint8_t* xb = pub + 1;
    if (Cmp32(xb, P_BE) >= 0) return StructuralResult::PUBKEY_X_OUT_OF_RANGE;

    fe x, x2, x3, three_x, b, rhs, y, y2;
    FeFromBE(x, xb);
    FeFromBE(b, B_BE);
    fiat_p256_square(x2, x);
    fiat_p256_mul(x3, x2, x);
    fiat_p256_add(three_x, x, x);
    fiat_p256_add(three_x, three_x, x);
    fiat_p256_sub(rhs, x3, three_x);
    fiat_p256_add(rhs, rhs, b); // x^3 - 3x + b
    FePow(y, rhs, P_SQRT_EXP_BE);
    fiat_p256_square(y2, y);
    if (!FeEqual(y2, rhs)) return StructuralResult::PUBKEY_NOT_ON_CURVE;

    uint8_t yb[32];
    FeToBE(yb, y);
    if ((yb[31] & 1) != (pub[0] & 1)) {
        // y == 0 has no odd root; the prime-order curve has no such point,
        // but reject rather than return the wrong parity.
        if (FeIsZero(y)) return StructuralResult::PUBKEY_NOT_ON_CURVE;
        fiat_p256_opp(y, y);
        FeToBE(yb, y);
    }
    memcpy(out.x, xb, 32);
    memcpy(out.y, yb, 32);
    return StructuralResult::OK;
}

StructuralResult ParseSignature(const uint8_t* sig, size_t len, Signature& out) noexcept
{
    if (len == 0) {
        out.empty = true;
        memset(out.r, 0, 32);
        memset(out.s, 0, 32);
        return StructuralResult::OK;
    }
    if (len != SIG_SIZE) return StructuralResult::SIG_SIZE_INVALID;
    const uint8_t* r = sig;
    const uint8_t* s = sig + 32;
    if (IsZero32(r) || Cmp32(r, N_BE) >= 0) return StructuralResult::SIG_R_OUT_OF_RANGE;
    if (IsZero32(s) || Cmp32(s, N_BE) >= 0) return StructuralResult::SIG_S_OUT_OF_RANGE;
    if (Cmp32(s, HALF_N_BE) > 0) return StructuralResult::SIG_HIGH_S;
    out.empty = false;
    memcpy(out.r, r, 32);
    memcpy(out.s, s, 32);
    return StructuralResult::OK;
}

bool Verify(const PublicKey& pub, const Signature& sig, const uint8_t* msg, size_t msglen) noexcept
{
    if (sig.empty) return false;

    // e = SHA-256(msg) mod n. e < 2^256 < 2n, so one subtraction suffices.
    uint8_t e[32];
    CSHA256().Write(msg, msglen).Finalize(e);
    if (Cmp32(e, N_BE) >= 0) Sub32(e, e, N_BE);

    // w = s^-1, u1 = e w, u2 = r w (mod n).
    sc s_m, w, e_m, r_m, u1_m, u2_m;
    ScFromBE(s_m, sig.s);
    ScInverse(w, s_m);
    ScFromBE(e_m, e);
    ScFromBE(r_m, sig.r);
    fiat_p256_scalar_mul(u1_m, e_m, w);
    fiat_p256_scalar_mul(u2_m, r_m, w);
    uint8_t u1[32], u2[32];
    ScToBE(u1, u1_m);
    ScToBE(u2, u2_m);

    // Odd multiples of Q: 1Q, 3Q, ..., (2^(Q_WINDOW-1) - 1)Q.
    Jacobian qtab[Q_TABLE_SIZE];
    FeFromBE(qtab[0].X, pub.x);
    FeFromBE(qtab[0].Y, pub.y);
    FeOne(qtab[0].Z);
    Jacobian q2;
    Double(q2, qtab[0]);
    for (int i = 1; i < Q_TABLE_SIZE; ++i) Add(qtab[i], qtab[i - 1], q2);

    int8_t naf1[WNAF_MAX], naf2[WNAF_MAX];
    const int len1 = ComputeWNAF(naf1, u1, G_WINDOW);
    const int len2 = ComputeWNAF(naf2, u2, Q_WINDOW);
    const int len = len1 > len2 ? len1 : len2;

    const GeneratorTable& gtab = GetGeneratorTable();
    Jacobian acc;
    SetInfinity(acc);
    fe neg;
    for (int i = len - 1; i >= 0; --i) {
        Double(acc, acc);
        const int d1 = naf1[i];
        if (d1 > 0) {
            AddAffine(acc, acc, gtab.point[(d1 - 1) / 2].x, gtab.point[(d1 - 1) / 2].y);
        } else if (d1 < 0) {
            fiat_p256_opp(neg, gtab.point[(-d1 - 1) / 2].y);
            AddAffine(acc, acc, gtab.point[(-d1 - 1) / 2].x, neg);
        }
        const int d2 = naf2[i];
        if (d2 > 0) {
            Add(acc, acc, qtab[(d2 - 1) / 2]);
        } else if (d2 < 0) {
            Jacobian negq = qtab[(-d2 - 1) / 2];
            fiat_p256_opp(negq.Y, negq.Y);
            Add(acc, acc, negq);
        }
    }
    if (IsInfinity(acc)) return false;

    // x(R) mod n == r, without an inversion: x(R) = X / Z^2, and x(R) < p,
    // so x(R) mod n == r iff x(R) == r or x(R) == r + n (when r + n < p).
    fe z2, rz, rfe;
    fiat_p256_square(z2, acc.Z);
    FeFromBE(rfe, sig.r); // r < n < p
    fiat_p256_mul(rz, rfe, z2);
    if (FeEqual(acc.X, rz)) return true;
    if (Cmp32(sig.r, P_MINUS_N_BE) < 0) {
        uint8_t rn[32];
        Add32(rn, sig.r, N_BE);
        FeFromBE(rfe, rn);
        fiat_p256_mul(rz, rfe, z2);
        if (FeEqual(acc.X, rz)) return true;
    }
    return false;
}

StructuralResult VerifyStrict(const uint8_t* pub, size_t publen,
                              const uint8_t* sig, size_t siglen,
                              const uint8_t* msg, size_t msglen,
                              bool& valid) noexcept
{
    valid = false;
    PublicKey key;
    StructuralResult res = ParsePublicKey(pub, publen, key);
    if (res != StructuralResult::OK) return res;
    Signature parsed;
    res = ParseSignature(sig, siglen, parsed);
    if (res != StructuralResult::OK) return res;
    valid = Verify(key, parsed, msg, msglen);
    return StructuralResult::OK;
}

} // namespace p256
} // namespace crypto
