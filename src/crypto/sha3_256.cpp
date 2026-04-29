// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha3_256.h"
#include "crypto/ethash/include/ethash/keccak.h"

#include <cstdint>
#include <cstring>

namespace crypto {

// SHA3-256 sponge: rate = 1088 bits = 136 bytes (= 17 lanes), capacity =
// 512 bits, output = 256 bits = 32 bytes. Padding rule (FIPS-202):
// append the multi-rate-padding sequence  pad10*1  with the
// SHA3 domain-separation suffix `01` prepended, so the last byte
// XOR-ed in is 0x06, and the high bit of the last block byte is
// set (0x80). For Keccak (NIP-030) the suffix is the empty string
// and the byte XOR-ed is 0x01 instead — that is the only
// difference between the two functions.
//
// State is 25 64-bit lanes; we manipulate as little-endian words.
// Ethash's keccakf1600 expects the state already in little-endian
// uint64 form.

namespace {

inline uint64_t load_le_u64(const uint8_t* p)
{
    uint64_t w;
    std::memcpy(&w, p, sizeof(w));
    // The hosts we target (x86-64, ARM64) are all little-endian.
    // If a big-endian target is ever supported, byteswap here.
    return w;
}

inline void store_le_u64(uint8_t* p, uint64_t w)
{
    std::memcpy(p, &w, sizeof(w));
}

} // namespace

void SHA3_256(const unsigned char* data, size_t len,
              unsigned char hash[32])
{
    constexpr size_t RATE_BYTES = 136; // (1600 - 2*256) / 8

    uint64_t state[25] = {0};

    // Absorb full blocks.
    while (len >= RATE_BYTES) {
        for (size_t i = 0; i < RATE_BYTES / 8; ++i) {
            state[i] ^= load_le_u64(data + i * 8);
        }
        ethash_keccakf1600(state);
        data += RATE_BYTES;
        len  -= RATE_BYTES;
    }

    // Last partial block: copy remaining bytes into a zero-padded
    // RATE_BYTES buffer, then apply FIPS-202 padding bytes.
    uint8_t last_block[RATE_BYTES] = {0};
    std::memcpy(last_block, data, len);
    last_block[len] = 0x06;                    // SHA3 domain separator
    last_block[RATE_BYTES - 1] |= 0x80;        // pad10*1 final bit

    for (size_t i = 0; i < RATE_BYTES / 8; ++i) {
        uint64_t w;
        std::memcpy(&w, last_block + i * 8, 8);
        state[i] ^= w;
    }
    ethash_keccakf1600(state);

    // Squeeze 256 bits = 32 bytes from the start of the state.
    for (size_t i = 0; i < 4; ++i) {
        store_le_u64(hash + i * 8, state[i]);
    }
}

} // namespace crypto
