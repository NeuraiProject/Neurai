// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_CRYPTO_KECCAK256_H
#define NEURAI_CRYPTO_KECCAK256_H

#include <cstddef>

namespace crypto {

/** NIP-030: Keccak-256 (NOT FIPS-202 SHA-3). Pre-standardization
 *  padding rule (0x01). Used by Ethereum and every EVM chain.
 *  Wrapper over the in-tree ethash::keccak256 implementation
 *  (src/crypto/ethash/include/ethash/keccak.hpp). */
void Keccak256(const unsigned char* data, size_t len,
               unsigned char hash[32]);

} // namespace crypto

#endif // NEURAI_CRYPTO_KECCAK256_H
