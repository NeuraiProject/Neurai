// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/merkle_inclusion.h"

#include "crypto/blake2b.h"
#include "crypto/keccak256.h"
#include "crypto/sha256.h"

#include <cstring>

namespace nip031 {

namespace {

// Initial running-hash for the chosen scheme. Returns false if the
// scheme constraints on `leaf` are violated (currently only scheme 0x01
// imposes one: leaf must be exactly 32 bytes).
bool InitRunning(const unsigned char* leaf, size_t leafLen,
                  uint8_t scheme, unsigned char out[32])
{
    switch (scheme) {
        case SCHEME_BITCOIN_NEURAI:
            if (leafLen != 32) return false;
            std::memcpy(out, leaf, 32);
            return true;
        case SCHEME_SHA256_PLAIN:
            CSHA256().Write(leaf, leafLen).Finalize(out);
            return true;
        case SCHEME_KECCAK256_PLAIN:
            crypto::Keccak256(leaf, leafLen, out);
            return true;
        case SCHEME_BLAKE2B_PLAIN:
            crypto::Blake2b256(leaf, leafLen, out);
            return true;
        default:
            return false;
    }
}

void NodeHash(uint8_t scheme, const unsigned char in[64], unsigned char out[32])
{
    switch (scheme) {
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

} // namespace

bool VerifyMerkleInclusion(const unsigned char* leaf,    size_t leafLen,
                            uint8_t scheme,
                            const unsigned char* proof,  size_t proofLen,
                            const unsigned char  root[32])
{
    if (proofLen < 1) return false;

    const uint8_t depth = proof[0];
    if (depth > NIP031_MAX_DEPTH) return false;

    const size_t siblingsBytes = static_cast<size_t>(depth) * 32u;
    const size_t bitmapBytes   = (depth + 7u) / 8u;
    if (proofLen != 1 + siblingsBytes + bitmapBytes) return false;

    const unsigned char* sibPtr = proof + 1;
    const unsigned char* bitmap = proof + 1 + siblingsBytes;

    unsigned char running[32];
    if (!InitRunning(leaf, leafLen, scheme, running)) return false;

    unsigned char buf[64];
    for (uint8_t i = 0; i < depth; ++i) {
        const bool runningOnRight = ((bitmap[i / 8] >> (i % 8)) & 1u) != 0;
        if (runningOnRight) {
            std::memcpy(buf,      sibPtr + i * 32, 32);
            std::memcpy(buf + 32, running,         32);
        } else {
            std::memcpy(buf,      running,         32);
            std::memcpy(buf + 32, sibPtr + i * 32, 32);
        }
        NodeHash(scheme, buf, running);
    }

    return std::memcmp(running, root, 32) == 0;
}

} // namespace nip031
