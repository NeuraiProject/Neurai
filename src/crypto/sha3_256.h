// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-034a: SHA3-256 (FIPS 202).
//
// Differs from Keccak-256 (NIP-030) only in the domain-separation
// padding byte (0x06 vs Keccak's 0x01). Reuses the in-tree
// Keccak-f[1600] permutation from
// src/crypto/ethash/lib/keccak/keccakf1600.c.

#ifndef NEURAI_CRYPTO_SHA3_256_H
#define NEURAI_CRYPTO_SHA3_256_H

#include <cstddef>

namespace crypto {

/** SHA3-256 (FIPS 202). Output is exactly 32 bytes.
 *  Test vector:  SHA3-256("") =
 *    a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
 */
void SHA3_256(const unsigned char* data, size_t len,
              unsigned char hash[32]);

} // namespace crypto

#endif // NEURAI_CRYPTO_SHA3_256_H
