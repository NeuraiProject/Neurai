// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// BLAKE2b-256 (RFC 7693) reference implementation, native 32-byte
// digest. Derived from RFC 7693 Appendix C and the BLAKE2 official
// C reference (CC0 / public domain).
//
// Parameters pinned per NIP-030 §3.7:
//   digest_length=32, key_length=0, fanout=1, depth=1,
//   leaf_length=0, node_offset=0, node_depth=0, inner_length=0,
//   salt=zero, personalization=zero.

#include "crypto/blake2b.h"

#include <cstring>

namespace crypto {

namespace {

// BLAKE2b initialization vector (RFC 7693 §2.6, IV[0..7]).
static constexpr uint64_t kIV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// Sigma permutation table (RFC 7693 §2.7).
static constexpr unsigned char kSigma[12][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
};

inline uint64_t LoadLE64(const unsigned char* p)
{
    return  (uint64_t)p[0]        |
           ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

inline void StoreLE64(unsigned char* p, uint64_t x)
{
    p[0] = (unsigned char)(x);
    p[1] = (unsigned char)(x >>  8);
    p[2] = (unsigned char)(x >> 16);
    p[3] = (unsigned char)(x >> 24);
    p[4] = (unsigned char)(x >> 32);
    p[5] = (unsigned char)(x >> 40);
    p[6] = (unsigned char)(x >> 48);
    p[7] = (unsigned char)(x >> 56);
}

inline uint64_t Rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

inline void G(uint64_t v[16], unsigned a, unsigned b, unsigned c,
              unsigned d, uint64_t x, uint64_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = Rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = Rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = Rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = Rotr64(v[b] ^ v[c], 63);
}

// Compression function F (RFC 7693 §3.2).
void Compress(uint64_t h[8], const unsigned char block[128],
              uint64_t t0, uint64_t t1, bool last)
{
    uint64_t v[16];
    uint64_t m[16];

    for (int i = 0; i < 8; ++i) v[i] = h[i];
    for (int i = 0; i < 8; ++i) v[8 + i] = kIV[i];

    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    for (int i = 0; i < 16; ++i)
        m[i] = LoadLE64(block + i * 8);

    for (int r = 0; r < 12; ++r) {
        const unsigned char* s = kSigma[r];
        G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[8 + i];
}

} // namespace

void Blake2b256(const unsigned char* data, size_t len,
                unsigned char hash[32])
{
    // Initialize state h[] with IV xored against the parameter block:
    //   parameter block (RFC 7693 §2.5) for unkeyed BLAKE2b-256:
    //     digest_length = 32, key_length = 0, fanout = 1, depth = 1,
    //     leaf_length = 0, node_offset = 0, node_depth = 0,
    //     inner_length = 0, reserved = 0, salt = 0, personal = 0.
    //   Encoded as the first 64 bytes of the parameter block, packed
    //   little-endian:
    //     h[0] = IV[0] ^ 0x0000_0001_0101_0020
    //          (digest=32 | key=0 | fanout=1 | depth=1)
    //     h[1..7] = IV[1..7] xor 0 (all other params zero).
    uint64_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = kIV[i];
    h[0] ^= 0x0000000001010020ULL;

    uint64_t t = 0;
    unsigned char buf[128];
    size_t buf_len = 0;

    // Absorb full 128-byte blocks except possibly the last.
    while (len > 128) {
        std::memcpy(buf, data, 128);
        t += 128;
        Compress(h, buf, (uint64_t)t, 0, false);
        data += 128;
        len  -= 128;
    }

    // Final block: pad with zeros to 128 bytes, mark last.
    std::memset(buf, 0, sizeof(buf));
    if (len > 0) std::memcpy(buf, data, len);
    buf_len = len;
    t += buf_len;
    Compress(h, buf, (uint64_t)t, 0, true);

    // Output: first 32 bytes of h[] as little-endian.
    for (int i = 0; i < 4; ++i)
        StoreLE64(hash + i * 8, h[i]);
}

} // namespace crypto
