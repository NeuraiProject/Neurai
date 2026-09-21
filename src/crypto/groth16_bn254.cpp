// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/groth16_bn254.h"
#include "crypto/mcl_backend.h"
#include <mcl/bn.hpp>
#include <algorithm>
#include <vector>
#include <array>
#include <mutex>
#include <semaphore>
#include "crypto/sha256.h"
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
static G1 combine(const std::array<G1,17>& ic, const std::vector<Scalar>& scalars)
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

using Digest = std::array<uint8_t,32>;
struct PreparedVK {
    G1 alpha;
    G2 beta, gamma, delta;
    std::array<G1,17> ic;
    size_t n = 0;
};
struct VKEntry { Digest key{}; PreparedVK value; bool present=false; };
struct ResultEntry { Digest key{}; bool present=false; };
struct Cache {
    std::mutex mutex;
    std::array<VKEntry,256> vks;
    std::array<ResultEntry,4096> results;
    size_t vk_slots=256, result_slots=4096;
    neurai::zk::CacheInfo info{};
};
static Cache cache;
static_assert(sizeof(Cache)<2*1024*1024, "NIP-018 cache resident bound");
static std::counting_semaphore<4> executions(4);
struct Execution {
    Execution() {
        executions.acquire();
        try {
            std::lock_guard<std::mutex> lock(cache.mutex);
            ++cache.info.active;
            cache.info.peak=std::max(cache.info.peak,cache.info.active);
        } catch (...) { executions.release(); throw; }
    }
    ~Execution() {
        { std::lock_guard<std::mutex> lock(cache.mutex); --cache.info.active; }
        executions.release();
    }
};
static Digest hash(std::span<const uint8_t> bytes)
{
    Digest result;
    CSHA256().Write(bytes.data(),bytes.size()).Finalize(result.data());
    return result;
}
static size_t slot(const Digest& key, size_t capacity)
{
    return (size_t(key[0]) | (size_t(key[1])<<8)) % capacity;
}
static Digest result_key(const Digest& vk, std::span<const uint8_t> proof,
                         std::span<const uint8_t> inputs)
{
    static const char tag[]="NeuraiZKVerify";
    static const Digest domain=hash({reinterpret_cast<const uint8_t*>(tag),sizeof(tag)-1});
    const uint8_t prefix[2]={1,static_cast<uint8_t>(inputs.size()/32)};
    Digest result;
    CSHA256().Write(domain.data(),32).Write(domain.data(),32).Write(prefix,2)
        .Write(vk.data(),32).Write(inputs.data(),inputs.size()).Write(proof.data(),proof.size())
        .Finalize(result.data());
    return result;
}

}
namespace neurai::zk {
static Result VerifyImpl(std::span<const uint8_t> vk, std::span<const uint8_t> proof,
              std::span<const uint8_t> inputs, bool use_cache)
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
        const Digest vk_hash=hash(vk);
        const Digest key=proof.size()==128 ? result_key(vk_hash,proof,inputs) : Digest{};
        PreparedVK prepared;
        // mcl fields can only be initialized after MCL_InitSanityCheck above.
        for(auto& point:prepared.ic) point.clear();
        bool found=false;
        if (use_cache) {
            std::lock_guard<std::mutex> lock(cache.mutex);
            if (cache.result_slots && proof.size()==128) {
                const auto& entry=cache.results[slot(key,cache.result_slots)];
                if (entry.present && entry.key==key) { ++cache.info.result_hits; return Result::VALID; }
            }
            if (cache.vk_slots) {
                const auto& entry=cache.vks[slot(vk_hash,cache.vk_slots)];
                if (entry.present && entry.key==vk_hash) {
                    prepared=entry.value; found=true; ++cache.info.vk_hits;
                }
            }
        }
        if (!found) {
            prepared.n=n;
            if (!decode(prepared.alpha,vk.data()) || !decode(prepared.beta,vk.data()+32) ||
                !decode(prepared.gamma,vk.data()+96) || !decode(prepared.delta,vk.data()+160)) return Result::VK_ENCODING;
            for (size_t j=0;j<n;++j)
                if (!decode(prepared.ic[j],vk.data()+232+32*j)) return Result::VK_ENCODING;
            if (use_cache) {
                std::lock_guard<std::mutex> lock(cache.mutex);
                if (cache.vk_slots) {
                    auto& entry=cache.vks[slot(vk_hash,cache.vk_slots)];
                    if(entry.present && entry.key!=vk_hash) ++cache.info.vk_evictions;
                    entry.present=false;
                    entry.key=vk_hash; entry.value=prepared; entry.present=true;
                }
            }
        }
        n=prepared.n; // cached VK must still match this invocation's input count
        if (n!=k+1) return Result::INPUT_COUNT;
        if (proof.size()!=128) return Result::PROOF_ENCODING;
        G1 a,c; G2 b;
        if (!decode(a,proof.data()) || !decode(b,proof.data()+32) || !decode(c,proof.data()+96)) return Result::PROOF_ENCODING;
        if (!equation(a,b,prepared.alpha,prepared.beta,combine(prepared.ic,scalars),prepared.gamma,c,prepared.delta))
            return Result::INVALID;
        if (use_cache) {
            std::lock_guard<std::mutex> lock(cache.mutex);
            if(cache.result_slots) {
                auto& entry=cache.results[slot(key,cache.result_slots)];
                if(entry.present && entry.key!=key) ++cache.info.result_evictions;
                entry.key=key; entry.present=true;
            }
        }
        return Result::VALID;
    } catch (...) { return Result::INTERNAL; }
}
Result Verify(std::span<const uint8_t> vk, std::span<const uint8_t> proof,
              std::span<const uint8_t> inputs, bool use_cache) noexcept
{
    try { Execution execution; return VerifyImpl(vk,proof,inputs,use_cache); }
    catch (...) { return Result::INTERNAL; }
}
void ResetCaches(size_t vk_slots, size_t result_slots)
{
    std::lock_guard<std::mutex> lock(cache.mutex);
    for(auto& entry:cache.vks) entry.present=false;
    for(auto& entry:cache.results) entry.present=false;
    cache.vk_slots=std::min(vk_slots,cache.vks.size());
    cache.result_slots=std::min(result_slots,cache.results.size());
    const auto active=cache.info.active;
    cache.info={}; cache.info.active=active; cache.info.peak=active;
}
CacheInfo GetCacheInfo()
{
    std::lock_guard<std::mutex> lock(cache.mutex);
    auto info=cache.info; info.bytes=sizeof(cache)+sizeof(executions); return info;
}
std::array<uint8_t,32> VerificationCacheKey(std::span<const uint8_t> vk,
    std::span<const uint8_t> proof, std::span<const uint8_t> inputs)
{
    return result_key(hash(vk),proof,inputs);
}

}
