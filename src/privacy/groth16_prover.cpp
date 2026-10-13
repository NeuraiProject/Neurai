// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/groth16_prover.h"

#include "crypto/mcl_backend.h"
#include "random.h"

#include <mcl/bn.hpp>

#include <algorithm>
#include <thread>

namespace privacy {
namespace {

using mcl::Fp;
using mcl::Fp2;
using mcl::Fr;
using mcl::G1;
using mcl::G2;

constexpr size_t FIELD_BYTES = 32;
constexpr size_t G1_BYTES = 2 * FIELD_BYTES;
constexpr size_t G2_BYTES = 4 * FIELD_BYTES;
constexpr size_t COEF_BYTES = 12 + FIELD_BYTES;

// BN254 base and scalar field moduli, little-endian, as stored in .zkey headers.
const char* const BN254_Q = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
const char* const BN254_R = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
// Primitive 2^28-th root of unity used by ffjavascript: 5^((r-1)/2^28) mod r.
const char* const ROOT_2_28 = "19103219067921713944291392827692070036145651957329286315305642004821462161904";
constexpr uint32_t MAX_POWER = 28;

uint32_t ReadU32(const uint8_t* p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}

uint64_t ReadU64(const uint8_t* p)
{
    return uint64_t(ReadU32(p)) | uint64_t(ReadU32(p + 4)) << 32;
}

struct Constants {
    Fp fpInvR;      //!< 2^-256 mod q: from Montgomery to plain base field values
    Fr frInvR2;     //!< 2^-512 mod r: coefficients are stored premultiplied by R^2
    std::array<Fr, MAX_POWER + 1> roots;
};

const Constants& GetConstants()
{
    static const Constants constants = [] {
        Constants c;
        Fp fpR;
        Fp::pow(fpR, Fp(2), 256);
        Fp::inv(c.fpInvR, fpR);
        Fr frR, frInvR;
        Fr::pow(frR, Fr(2), 256);
        Fr::inv(frInvR, frR);
        c.frInvR2 = frInvR * frInvR;
        c.roots[MAX_POWER].setStr(ROOT_2_28);
        for (int k = MAX_POWER - 1; k >= 0; --k) c.roots[k] = c.roots[k + 1] * c.roots[k + 1];
        return c;
    }();
    return constants;
}

/** Compares a 256-bit little-endian number with a decimal constant. The moduli
 *  cannot be loaded as field elements (they reduce to zero). */
bool SameNumber(const uint8_t* le, const char* decimal)
{
    std::string text;
    std::vector<uint32_t> words(8);
    for (int i = 0; i < 8; ++i) words[i] = ReadU32(le + 4 * i);
    while (std::any_of(words.begin(), words.end(), [](uint32_t w) { return w != 0; })) {
        uint64_t rem = 0;
        for (int i = 7; i >= 0; --i) {
            const uint64_t cur = (rem << 32) | words[i];
            words[i] = static_cast<uint32_t>(cur / 10);
            rem = cur % 10;
        }
        text.insert(text.begin(), char('0' + rem));
    }
    return text == decimal;
}

Fp FromMontgomery(const uint8_t* p)
{
    Fp value;
    value.setLittleEndianMod(p, FIELD_BYTES);
    return value * GetConstants().fpInvR;
}

bool DecodeG1(const uint8_t* p, G1& out)
{
    const Fp x = FromMontgomery(p), y = FromMontgomery(p + FIELD_BYTES);
    if (x.isZero() && y.isZero()) {
        out.clear();
        return true;
    }
    bool valid = false;
    out.set(&valid, x, y, false);
    return valid;
}

bool DecodeG2(const uint8_t* p, G2& out)
{
    Fp2 x, y;
    x.a = FromMontgomery(p);
    x.b = FromMontgomery(p + FIELD_BYTES);
    y.a = FromMontgomery(p + 2 * FIELD_BYTES);
    y.b = FromMontgomery(p + 3 * FIELD_BYTES);
    if (x.isZero() && y.isZero()) {
        out.clear();
        return true;
    }
    bool valid = false;
    out.set(&valid, x, y, false);
    return valid;
}

template <typename Point, typename Decoder>
bool DecodePoints(const ProvingKey& key, size_t offset, size_t count, size_t stride, Decoder decode, std::vector<Point>& out)
{
    out.resize(count);
    const uint8_t* base = key.data.data() + offset;
    for (size_t i = 0; i < count; ++i) {
        if (!decode(base + i * stride, out[i])) return false;
    }
    return true;
}

/** Multi-scalar multiplication split across threads (mcl is built without OpenMP). */
template <typename Point>
Point MultiExp(std::vector<Point>& points, const Fr* scalars, size_t n)
{
    Point result;
    result.clear();
    if (n == 0) return result;
    const size_t hardware = std::max<size_t>(1, std::thread::hardware_concurrency());
    const size_t threads = std::min<size_t>({hardware, 16, (n + 4095) / 4096});
    std::vector<Point> partial(threads);
    std::vector<std::thread> workers;
    const size_t chunk = (n + threads - 1) / threads;
    for (size_t t = 0; t < threads; ++t) {
        const size_t begin = t * chunk, end = std::min(n, begin + chunk);
        if (begin >= end) {
            partial[t].clear();
            continue;
        }
        workers.emplace_back([&, t, begin, end] { Point::mulVec(partial[t], points.data() + begin, scalars + begin, end - begin); });
    }
    for (std::thread& worker : workers) worker.join();
    for (const Point& p : partial) result += p;
    return result;
}

/** In-place radix-2 FFT over Fr: evaluations of the coefficient vector at root^i. */
void Fft(std::vector<Fr>& a, const Fr& root)
{
    const size_t n = a.size();
    for (size_t i = 1, j = 0; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
    std::vector<Fr> twiddles;
    for (size_t len = 2; len <= n; len <<= 1) {
        const size_t half = len / 2;
        Fr step;
        Fr::pow(step, root, static_cast<int64_t>(n / len));
        twiddles.resize(half);
        twiddles[0] = 1;
        for (size_t j = 1; j < half; ++j) twiddles[j] = twiddles[j - 1] * step;
        for (size_t i = 0; i < n; i += len) {
            for (size_t j = 0; j < half; ++j) {
                const Fr u = a[i + j];
                const Fr v = a[i + j + half] * twiddles[j];
                a[i + j] = u + v;
                a[i + j + half] = u - v;
            }
        }
    }
}

void InverseFft(std::vector<Fr>& a, const Fr& root)
{
    Fr inverseRoot, inverseN;
    Fr::inv(inverseRoot, root);
    Fft(a, inverseRoot);
    Fr::inv(inverseN, Fr(static_cast<int64_t>(a.size())));
    for (Fr& value : a) value *= inverseN;
}

/** From evaluations on the domain to evaluations on the odd coset (inc * w^i). */
void ToOddCoset(std::vector<Fr>& a, const Fr& root, const Fr& inc)
{
    InverseFft(a, root);
    Fr factor = 1;
    for (Fr& value : a) {
        value *= factor;
        factor *= inc;
    }
    Fft(a, root);
}

void CompressG1(const G1& point, uint8_t* out)
{
    G1 p(point);
    p.normalize();
    p.x.serialize(out, FIELD_BYTES);
    if (p.y.isNegative()) out[FIELD_BYTES - 1] |= 0x80;
}

void CompressG2(const G2& point, uint8_t* out)
{
    G2 p(point);
    p.normalize();
    p.x.a.serialize(out, FIELD_BYTES);
    p.x.b.serialize(out + FIELD_BYTES, FIELD_BYTES);
    const bool negative = p.y.b.isZero() ? p.y.a.isNegative() : p.y.b.isNegative();
    if (negative) out[2 * FIELD_BYTES - 1] |= 0x80;
}

Fr RandomScalar()
{
    // 64 random bytes so that the reduction modulo r is unbiased
    uint8_t bytes[64];
    GetStrongRandBytes(bytes, 32);
    GetStrongRandBytes(bytes + 32, 32);
    Fr value;
    value.setLittleEndianMod(bytes, sizeof(bytes));
    return value;
}

} // namespace

bool LoadProvingKey(std::vector<uint8_t> data, ProvingKey& key, std::string& error)
{
    key = ProvingKey{};
    key.data = std::move(data);
    const std::vector<uint8_t>& d = key.data;
    if (d.size() < 12 || std::string(d.begin(), d.begin() + 4) != "zkey" || ReadU32(&d[4]) != 1) {
        error = "not a version 1 zkey file";
        return false;
    }
    const uint32_t nSections = ReadU32(&d[8]);
    std::array<size_t, 11> offset{}, size{};
    size_t pos = 12;
    for (uint32_t i = 0; i < nSections; ++i) {
        if (pos + 12 > d.size()) {
            error = "truncated zkey file";
            return false;
        }
        const uint32_t id = ReadU32(&d[pos]);
        const uint64_t length = ReadU64(&d[pos + 4]);
        pos += 12;
        if (length > d.size() - pos) {
            error = "truncated zkey section";
            return false;
        }
        if (id < offset.size()) {
            if (size[id] || offset[id]) {
                error = "duplicate zkey section";
                return false;
            }
            offset[id] = pos;
            size[id] = length;
        }
        pos += length;
    }
    if (size[1] < 4 || ReadU32(&d[offset[1]]) != 1) {
        error = "zkey is not a Groth16 key";
        return false;
    }
    const size_t h = offset[2];
    if (size[2] < 4 + FIELD_BYTES + 4 + FIELD_BYTES + 12 + 3 * G1_BYTES + 3 * G2_BYTES ||
        ReadU32(&d[h]) != FIELD_BYTES || !SameNumber(&d[h + 4], BN254_Q) ||
        ReadU32(&d[h + 36]) != FIELD_BYTES || !SameNumber(&d[h + 40], BN254_R)) {
        error = "zkey is not for the BN254 curve";
        return false;
    }
    key.nVars = ReadU32(&d[h + 72]);
    key.nPublic = ReadU32(&d[h + 76]);
    key.domainSize = ReadU32(&d[h + 80]);
    key.header = h + 84;
    while ((1u << key.power) < key.domainSize) ++key.power;
    if (key.domainSize == 0 || (1u << key.power) != key.domainSize || key.power >= MAX_POWER ||
        key.nPublic + 1 > key.nVars) {
        error = "invalid zkey dimensions";
        return false;
    }
    key.coeffs = offset[4];
    key.coeffsSize = size[4];
    key.pointsA = offset[5];
    key.pointsB1 = offset[6];
    key.pointsB2 = offset[7];
    key.pointsC = offset[8];
    key.pointsH = offset[9];
    if (size[4] < 4 || (size[4] - 4) % COEF_BYTES != 0 || (size[4] - 4) / COEF_BYTES != ReadU32(&d[offset[4]]) ||
        size[5] != size_t(key.nVars) * G1_BYTES || size[6] != size_t(key.nVars) * G1_BYTES ||
        size[7] != size_t(key.nVars) * G2_BYTES || size[8] != size_t(key.nVars - key.nPublic - 1) * G1_BYTES ||
        size[9] != size_t(key.domainSize) * G1_BYTES) {
        error = "inconsistent zkey sections";
        return false;
    }
    return true;
}

bool ProveGroth16(const ProvingKey& key, const std::vector<FieldLE>& witness, Groth16Proof& proof, std::string& error)
{
    if (!MCL_InitSanityCheck()) {
        error = "elliptic curve backend unavailable";
        return false;
    }
    if (witness.size() != key.nVars) {
        error = "witness size does not match the proving key";
        return false;
    }
    const Constants& k = GetConstants();
    const size_t n = key.domainSize;

    std::vector<Fr> w(key.nVars);
    for (size_t i = 0; i < w.size(); ++i) w[i].setLittleEndianMod(witness[i].data(), FIELD_BYTES);

    // Evaluations of A and B on the domain from the sparse QAP coefficients.
    std::vector<Fr> a(n), b(n), c(n);
    for (size_t i = 0; i < n; ++i) a[i].clear(), b[i].clear();
    const uint8_t* coef = key.data.data() + key.coeffs + 4;
    const size_t nCoef = (key.coeffsSize - 4) / COEF_BYTES;
    for (size_t i = 0; i < nCoef; ++i, coef += COEF_BYTES) {
        const uint32_t matrix = ReadU32(coef), constraint = ReadU32(coef + 4), signal = ReadU32(coef + 8);
        if (matrix > 1 || constraint >= n || signal >= key.nVars) {
            error = "invalid zkey coefficient";
            return false;
        }
        Fr value;
        value.setLittleEndianMod(coef + 12, FIELD_BYTES);
        value *= k.frInvR2;
        (matrix == 0 ? a : b)[constraint] += value * w[signal];
    }
    for (size_t i = 0; i < n; ++i) c[i] = a[i] * b[i];

    const Fr& root = k.roots[key.power];
    const Fr& inc = k.roots[key.power + 1];
    ToOddCoset(a, root, inc);
    ToOddCoset(b, root, inc);
    ToOddCoset(c, root, inc);
    std::vector<Fr> h(n);
    for (size_t i = 0; i < n; ++i) h[i] = a[i] * b[i] - c[i];

    std::vector<G1> g1;
    std::vector<G2> g2;
    if (!DecodePoints<G1>(key, key.pointsA, key.nVars, G1_BYTES, DecodeG1, g1)) return error = "invalid zkey point", false;
    G1 piA = MultiExp(g1, w.data(), key.nVars);
    if (!DecodePoints<G1>(key, key.pointsB1, key.nVars, G1_BYTES, DecodeG1, g1)) return error = "invalid zkey point", false;
    G1 piB1 = MultiExp(g1, w.data(), key.nVars);
    if (!DecodePoints<G2>(key, key.pointsB2, key.nVars, G2_BYTES, DecodeG2, g2)) return error = "invalid zkey point", false;
    G2 piB = MultiExp(g2, w.data(), key.nVars);
    const size_t nPrivate = key.nVars - key.nPublic - 1;
    if (!DecodePoints<G1>(key, key.pointsC, nPrivate, G1_BYTES, DecodeG1, g1)) return error = "invalid zkey point", false;
    G1 piC = MultiExp(g1, w.data() + key.nPublic + 1, nPrivate);
    if (!DecodePoints<G1>(key, key.pointsH, n, G1_BYTES, DecodeG1, g1)) return error = "invalid zkey point", false;
    const G1 resH = MultiExp(g1, h.data(), n);

    G1 alpha1, beta1, delta1;
    G2 beta2, delta2;
    const uint8_t* hp = key.data.data() + key.header;
    if (!DecodeG1(hp, alpha1) || !DecodeG1(hp + G1_BYTES, beta1) || !DecodeG2(hp + 2 * G1_BYTES, beta2) ||
        !DecodeG1(hp + 2 * G1_BYTES + 2 * G2_BYTES, delta1) || !DecodeG2(hp + 3 * G1_BYTES + 2 * G2_BYTES, delta2)) {
        error = "invalid zkey verification point";
        return false;
    }

    const Fr r = RandomScalar(), s = RandomScalar();
    G1 term;
    G2 term2;
    piA += alpha1;
    G1::mul(term, delta1, r);
    piA += term;
    piB += beta2;
    G2::mul(term2, delta2, s);
    piB += term2;
    piB1 += beta1;
    G1::mul(term, delta1, s);
    piB1 += term;
    piC += resH;
    G1::mul(term, piA, s);
    piC += term;
    G1::mul(term, piB1, r);
    piC += term;
    G1::mul(term, delta1, -(r * s));
    piC += term;

    piA.normalize();
    piB.normalize();
    piC.normalize();
    CompressG1(piA, proof.compressed.data());
    CompressG2(piB, proof.compressed.data() + 32);
    CompressG1(piC, proof.compressed.data() + 96);
    proof.a = {piA.x.getStr(10), piA.y.getStr(10)};
    proof.b = {{{piB.x.a.getStr(10), piB.x.b.getStr(10)}, {piB.y.a.getStr(10), piB.y.b.getStr(10)}}};
    proof.c = {piC.x.getStr(10), piC.y.getStr(10)};
    proof.publicSignals.assign(witness.begin() + 1, witness.begin() + 1 + key.nPublic);
    return true;
}

} // namespace privacy
