// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// BLAKE2b-256 with RFC 7693 default parameters. See NIP-030 §3.7 for
// the exact parameter pinning (digest=32, key=0, fanout=1, depth=1,
// salt=zero, person=zero, sequential mode).
//
// Reference implementation derived from RFC 7693 Appendix C and the
// BLAKE2 official C reference (CC0 / public domain by the BLAKE2
// team). Single-call API only; no streaming.

#ifndef NEURAI_CRYPTO_BLAKE2B_H
#define NEURAI_CRYPTO_BLAKE2B_H

#include <cstddef>
#include <cstdint>

namespace crypto {

/** NIP-030: BLAKE2b with native 32-byte digest (NOT a post-hoc
 *  truncation of BLAKE2b-512). Output matches
 *  hashlib.blake2b(data, digest_size=32).digest() and `b2sum -l 256`.
 *  Test vector for empty input:
 *      0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
 *  Test vector for "abc":
 *      bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319 */
void Blake2b256(const unsigned char* data, size_t len,
                unsigned char hash[32]);

} // namespace crypto

#endif // NEURAI_CRYPTO_BLAKE2B_H
