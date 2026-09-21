// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/groth16_bn254.h"
#include "crypto/mcl_backend.h"
#include <mcl/bn.hpp>
#include <algorithm>
#include <vector>
namespace {
using mcl::G1; using mcl::G2; using mcl::Fp; using mcl::Fp2;
using Scalar = mcl::Fr;
static bool negative(const Fp& v) { return v.isNegative(); }
static bool negative(const Fp2& v) { return v.b.isZero() ? v.a.isNegative() : v.b.isNegative(); }
static bool scalar(Scalar& value, const uint8_t* be)
{
    uint8_t le[32]; std::reverse_copy(be, be+32, le);
    return value.deserialize(le, 32) == 32;
}
static bool field(Fp& value, const uint8_t* le) { return value.deserialize(le, 32) == 32; }
static bool field(Fp2& value, const uint8_t* le) { return field(value.a, le) && field(value.b, le+32); }
static size_t encode(uint8_t* out, const Fp& v) { return v.serialize(out, 32); }
static size_t encode(uint8_t* out, const Fp2& v) {
    return encode(out, v.a) == 32 && encode(out+32, v.b) == 32 ? 64 : 0;
}
static bool subgroup(const G1&) { return true; } // BN_SNARK1 G1 has cofactor 1
static bool subgroup(const G2& p) { return p.isValidOrder(); }
template<typename Point> static bool decode_point(Point& out, const uint8_t* data, size_t size)
{
    if (data[size-1] & 0x40) return false; // no infinity, also rejects 0xc0
    uint8_t raw[64]; std::copy(data, data+size, raw);
    const bool sign = (raw[size-1] & 0x80) != 0;
    raw[size-1] &= 0x3f;
    typename Point::Fp x, y, rhs;
    if (!field(x, raw)) return false;
    Point::getWeierstrass(rhs, x);
    if (!Point::Fp::squareRoot(y, rhs)) return false;
    if (negative(y) != sign) y = -y;
    if (negative(y) != sign) return false; // sign bit on y=0
    bool valid = false;
    // sqrt above establishes the curve equation. Explicit G2 order check
    // below avoids dependence on the ambient verifyOrder setting.
    out.set(&valid, x, y, false);
    if (!valid || out.isZero() || !subgroup(out)) return false;
    if (encode(raw, x) != size) return false;
    if (negative(y)) raw[size-1] |= 0x80;
    return std::equal(raw, raw+size, data);
}
static bool decode(G1& out, const uint8_t* data) { return decode_point(out, data, 32); }
static bool decode(G2& out, const uint8_t* data) { return decode_point(out, data, 64); }
static G1 combine(const std::vector<G1>& ic, const std::vector<Scalar>& scalars)
{
    G1 acc = ic[0], term;
    for (size_t j = 0; j < scalars.size(); ++j) {
        G1::mul(term, ic[j+1], scalars[j]);
        G1::add(acc, acc, term);
    }
    return acc;
}
static bool equation(const G1& a, const G2& b, const G1& alpha, const G2& beta,
    const G1& acc, const G2& gamma, const G1& c, const G2& delta)
{
    G1 ps[4] = {a, -alpha, -acc, -c};
    G2 qs[4] = {b, beta, gamma, delta};
    mcl::Fp12 product, reduced;
    mcl::millerLoopVec(product, ps, qs, 4);
    mcl::finalExp(reduced, product);
    return reduced.isOne();
}

}
namespace neurai::zk {
Result Verify(std::span<const uint8_t> vk, std::span<const uint8_t> proof,
              std::span<const uint8_t> inputs) noexcept
{
    if (inputs.empty() || inputs.size() > MAX_INPUTS*32 || inputs.size()%32) return Result::INPUT_COUNT;
    if (!MCL_InitSanityCheck()) return Result::INTERNAL;
    try {
        const size_t k=inputs.size()/32;
        std::vector<Scalar> scalars(k);
        for (size_t j=0;j<k;++j)
            if (!scalar(scalars[j],inputs.data()+32*j)) return Result::INPUT_RANGE;
        if (vk.size()<296 || vk.size()>776) return Result::VK_ENCODING;
        uint64_t n=0;
        for (unsigned j=0;j<8;++j) n |= uint64_t(vk[224+j]) << (8*j);
        if (n<2 || n>17 || vk.size()!=232+32*n) return Result::VK_ENCODING;
        G1 alpha; G2 beta,gamma,delta;
        if (!decode(alpha,vk.data()) || !decode(beta,vk.data()+32) ||
            !decode(gamma,vk.data()+96) || !decode(delta,vk.data()+160)) return Result::VK_ENCODING;
        std::vector<G1> ic(n);
        for (size_t j=0;j<n;++j)
            if (!decode(ic[j],vk.data()+232+32*j)) return Result::VK_ENCODING;
        if (n!=k+1) return Result::INPUT_COUNT;
        if (proof.size()!=128) return Result::PROOF_ENCODING;
        G1 a,c; G2 b;
        if (!decode(a,proof.data()) || !decode(b,proof.data()+32) || !decode(c,proof.data()+96)) return Result::PROOF_ENCODING;
        return equation(a,b,alpha,beta,combine(ic,scalars),gamma,c,delta) ? Result::VALID : Result::INVALID;
    } catch (...) { return Result::INTERNAL; }
}
}
