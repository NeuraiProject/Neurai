// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-034a: BLAKE3-256 (32-byte output) — single-call API.
//
// Wraps the vendored BLAKE3 reference C implementation under
// src/crypto/blake3/. The vendor sources are upstream BLAKE3 v1.5.4
// (CC0 / Apache-2.0 / Apache-2.0 with LLVM exception, see the
// LICENSE_* files in src/crypto/blake3/). Only the portable code
// path is built; SIMD-specialised translation units (avx2, avx512,
// sse2, sse41, neon) are intentionally NOT compiled because the
// portable path is the canonical reference and its outputs match
// upstream KAT vectors bit-exactly. Disabling SIMD also keeps the
// consensus build reproducible across compiler / target arch
// combinations.

#ifndef NEURAI_CRYPTO_BLAKE3_WRAP_H
#define NEURAI_CRYPTO_BLAKE3_WRAP_H

#include <cstddef>

namespace crypto {

/** BLAKE3 with the default 32-byte output.
 *  Test vector:  Blake3_256("") =
 *    af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
 */
void Blake3_256(const unsigned char* data, size_t len,
                unsigned char hash[32]);

} // namespace crypto

#endif // NEURAI_CRYPTO_BLAKE3_WRAP_H
