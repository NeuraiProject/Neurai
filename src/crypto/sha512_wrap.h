// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-034a: thin wrapper over the in-tree CSHA512 to expose a
// single-call SHA-512 hash function with the same API style as
// crypto::Keccak256 / crypto::Blake2b256 (see src/crypto/keccak256.h
// and src/crypto/blake2b.h).
//
// No new SHA-512 implementation: the underlying class is in
// src/crypto/sha512.{h,cpp} and is already covered by FIPS 180-4
// known-answer tests in src/test/crypto_tests.cpp.

#ifndef NEURAI_CRYPTO_SHA512_WRAP_H
#define NEURAI_CRYPTO_SHA512_WRAP_H

#include <cstddef>

namespace crypto {

/** SHA-512 (FIPS 180-4) — single-call API.
 *
 *  Output is exactly 64 bytes (CSHA512::OUTPUT_SIZE). The wrapper
 *  is named *_Wrap to avoid colliding with the SHA512 macro that
 *  some third-party headers define.
 */
void SHA512_Wrap(const unsigned char* data, size_t len,
                  unsigned char hash[64]);

} // namespace crypto

#endif // NEURAI_CRYPTO_SHA512_WRAP_H
