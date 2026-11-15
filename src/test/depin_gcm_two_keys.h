// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#ifndef NEURAI_TEST_DEPIN_GCM_TWO_KEYS_H
#define NEURAI_TEST_DEPIN_GCM_TWO_KEYS_H

#include "crypto/aes.h"

#include <cstdint>
#include <string>
#include <vector>

/**
 * AES-GCM does not commit to its key: one ciphertext and tag can be valid
 * under two keys, and open to a different text under each. This builds such a
 * ciphertext, for the tests that check that two recipients of one envelope
 * cannot read different texts.
 *
 * Under key1 the result opens to firstText followed by noise; under key2, to
 * noise, then secondText, then noise. Texts are padded with spaces to whole
 * blocks. The last block is solved for so that the tag is the same under
 * both keys (multiplication in GF(2^128) as GCM defines it).
 */
namespace depin_test {

struct GcmBlock {
    uint64_t hi = 0, lo = 0;
};

inline GcmBlock GcmLoad(const unsigned char* p)
{
    GcmBlock b;
    for (int i = 0; i < 8; ++i) b.hi = (b.hi << 8) | p[i];
    for (int i = 8; i < 16; ++i) b.lo = (b.lo << 8) | p[i];
    return b;
}

inline void GcmStore(const GcmBlock& b, unsigned char* p)
{
    for (int i = 0; i < 8; ++i) p[i] = (b.hi >> (56 - 8 * i)) & 0xff;
    for (int i = 0; i < 8; ++i) p[8 + i] = (b.lo >> (56 - 8 * i)) & 0xff;
}

inline GcmBlock GcmXor(const GcmBlock& a, const GcmBlock& b)
{
    GcmBlock r;
    r.hi = a.hi ^ b.hi;
    r.lo = a.lo ^ b.lo;
    return r;
}

inline GcmBlock GcmMul(const GcmBlock& x, const GcmBlock& y)
{
    GcmBlock z, v = y;
    for (int i = 0; i < 128; ++i) {
        const uint64_t bit = i < 64 ? (x.hi >> (63 - i)) & 1 : (x.lo >> (127 - i)) & 1;
        if (bit) z = GcmXor(z, v);
        const bool carry = v.lo & 1;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        if (carry) v.hi ^= 0xe100000000000000ULL;
    }
    return z;
}

inline GcmBlock GcmInverse(const GcmBlock& x)
{
    // x^(2^128 - 2): 127 ones and a zero, from the most significant bit
    GcmBlock r;
    r.hi = 0x8000000000000000ULL;
    for (int i = 127; i >= 0; --i) {
        r = GcmMul(r, r);
        if (i >= 1) r = GcmMul(r, x);
    }
    return r;
}

inline GcmBlock GcmAes(const std::vector<unsigned char>& key, const unsigned char in[16])
{
    unsigned char out[16];
    AES256Encrypt(key.data()).Encrypt(out, in);
    return GcmLoad(out);
}

/** The block the key gives for counter `n` of a 96-bit nonce */
inline GcmBlock GcmCounter(const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce, uint32_t n)
{
    unsigned char in[16];
    for (int i = 0; i < 12; ++i) in[i] = nonce[i];
    for (int i = 0; i < 4; ++i) in[12 + i] = (n >> (24 - 8 * i)) & 0xff;
    return GcmAes(key, in);
}

inline GcmBlock GcmHash(const GcmBlock& h, const std::vector<unsigned char>& aad, const std::vector<unsigned char>& ciphertext)
{
    GcmBlock x;
    for (const std::vector<unsigned char>* data : {&aad, &ciphertext}) {
        for (size_t at = 0; at < data->size(); at += 16) {
            unsigned char block[16] = {0};
            for (size_t i = 0; i < 16 && at + i < data->size(); ++i) block[i] = (*data)[at + i];
            x = GcmMul(GcmXor(x, GcmLoad(block)), h);
        }
    }
    GcmBlock lengths;
    lengths.hi = uint64_t(aad.size()) * 8;
    lengths.lo = uint64_t(ciphertext.size()) * 8;
    return GcmMul(GcmXor(x, lengths), h);
}

/** nonce || ciphertext || tag, valid under key1 and under key2 with the same `aad` */
inline std::vector<unsigned char> GcmTwoKeys(const std::vector<unsigned char>& key1, const std::vector<unsigned char>& key2,
                                             const std::vector<unsigned char>& nonce, const std::vector<unsigned char>& aad,
                                             std::string firstText, std::string secondText)
{
    firstText.resize((firstText.size() + 15) / 16 * 16, ' ');
    secondText.resize((secondText.size() + 15) / 16 * 16, ' ');
    const size_t first = firstText.size() / 16, second = secondText.size() / 16;
    std::vector<GcmBlock> blocks;
    for (size_t i = 0; i < first; ++i)
        blocks.push_back(GcmXor(GcmLoad(reinterpret_cast<const unsigned char*>(&firstText[16 * i])),
                                GcmCounter(key1, nonce, i + 2)));
    for (size_t i = 0; i < second; ++i)
        blocks.push_back(GcmXor(GcmLoad(reinterpret_cast<const unsigned char*>(&secondText[16 * i])),
                                GcmCounter(key2, nonce, first + i + 2)));
    blocks.emplace_back();
    const auto bytes = [&blocks]() {
        std::vector<unsigned char> out(16 * blocks.size());
        for (size_t i = 0; i < blocks.size(); ++i) GcmStore(blocks[i], &out[16 * i]);
        return out;
    };

    // The last block enters the hash multiplied by H^2: solve for the block
    // that makes both tags equal
    const unsigned char zero[16] = {0};
    const GcmBlock h1 = GcmAes(key1, zero), h2 = GcmAes(key2, zero);
    const GcmBlock j1 = GcmCounter(key1, nonce, 1), j2 = GcmCounter(key2, nonce, 1);
    const GcmBlock difference = GcmXor(GcmXor(j1, j2), GcmXor(GcmHash(h1, aad, bytes()), GcmHash(h2, aad, bytes())));
    blocks.back() = GcmMul(difference, GcmInverse(GcmXor(GcmMul(h1, h1), GcmMul(h2, h2))));

    std::vector<unsigned char> sealed = nonce;
    const std::vector<unsigned char> ciphertext = bytes();
    sealed.insert(sealed.end(), ciphertext.begin(), ciphertext.end());
    unsigned char tag[16];
    GcmStore(GcmXor(j1, GcmHash(h1, aad, ciphertext)), tag);
    sealed.insert(sealed.end(), tag, tag + 16);
    return sealed;
}

} // namespace depin_test

#endif // NEURAI_TEST_DEPIN_GCM_TWO_KEYS_H
