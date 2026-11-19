// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-060: strict-profile ECDSA verification over NIST P-256 (secp256r1)
// with SHA-256, backing OP_CHECKSIG_P256 (slot 0xe0).
//
// The acceptance rules are CONSENSUS critical and must stay bit-exact with
// NIP-060 §4.4:
//   - public key: exactly 33 bytes, SEC 1 compressed (02/03 || X), X < p,
//     X^3 - 3X + b a square modulo p (the point is then on the curve and,
//     with cofactor 1, in the prime-order group);
//   - signature: empty, or exactly 64 bytes r || s (IEEE P1363), with
//     1 <= r <= n-1 and 1 <= s <= floor(n/2) (low S);
//   - digest: e = SHA-256(msg) read big-endian, reduced modulo n;
//   - equation: R = (e/s)G + (r/s)Q, valid iff R != O and x(R) mod n == r.
//
// The API is split in three steps so that the script interpreter can charge
// its hash budget after the encodings are validated and before the
// signature is verified (NIP-060 §4.5): ParsePublicKey, ParseSignature and
// Verify. The key is decompressed once, in ParsePublicKey.
//
// Field and scalar arithmetic come from Fiat Cryptography (formally
// verified, src/crypto/p256/fiat). Point arithmetic and the double scalar
// multiplication are variable time: verification only handles public data.

#ifndef NEURAI_CRYPTO_P256_H
#define NEURAI_CRYPTO_P256_H

#include <cstddef>
#include <cstdint>

namespace crypto {
namespace p256 {

constexpr size_t PUBKEY_SIZE = 33;
constexpr size_t SIG_SIZE = 64;

/** Structural validation outcome. Maps to the NIP-060 §4.8 error codes:
 *    PUBKEY_SIZE_INVALID          -> SCRIPT_ERR_P256_PUBKEY_SIZE
 *    PUBKEY_PREFIX_INVALID,
 *    PUBKEY_X_OUT_OF_RANGE,
 *    PUBKEY_NOT_ON_CURVE          -> SCRIPT_ERR_P256_PUBKEY_ENCODING
 *    SIG_SIZE_INVALID             -> SCRIPT_ERR_P256_SIG_SIZE
 *    SIG_R_OUT_OF_RANGE,
 *    SIG_S_OUT_OF_RANGE,
 *    SIG_HIGH_S                   -> SCRIPT_ERR_P256_SIG_ENCODING
 */
enum class StructuralResult {
    OK,
    PUBKEY_SIZE_INVALID,   // != 33 bytes
    PUBKEY_PREFIX_INVALID, // first byte not 0x02 / 0x03
    PUBKEY_X_OUT_OF_RANGE, // X >= p
    PUBKEY_NOT_ON_CURVE,   // X^3 - 3X + b is not a square modulo p
    SIG_SIZE_INVALID,      // neither 0 nor 64 bytes
    SIG_R_OUT_OF_RANGE,    // r == 0 || r >= n
    SIG_S_OUT_OF_RANGE,    // s == 0 || s >= n
    SIG_HIGH_S,            // s > floor(n/2)
};

/** A validated public key: the affine point, decompressed once, as
 *  big-endian coordinates. Only ParsePublicKey creates valid instances. */
struct PublicKey {
    uint8_t x[32];
    uint8_t y[32];
};

/** A validated signature: either empty, or r and s in range with low S. */
struct Signature {
    bool empty{true};
    uint8_t r[32];
    uint8_t s[32];
};

/** Size, prefix, X < p and curve membership; decompresses the point. */
StructuralResult ParsePublicKey(const uint8_t* pub, size_t len, PublicKey& out) noexcept;

/** Size 0 or 64; 1 <= r < n; 1 <= s <= floor(n/2). */
StructuralResult ParseSignature(const uint8_t* sig, size_t len, Signature& out) noexcept;

/** Checks the ECDSA equation for e = SHA-256(msg). Returns false for an
 *  empty signature. Both arguments must come from the Parse functions. */
bool Verify(const PublicKey& pub, const Signature& sig, const uint8_t* msg, size_t msglen) noexcept;

/** The three steps in one call, for tests and tools. `valid` is set only
 *  when the result is OK (false for an empty signature). */
StructuralResult VerifyStrict(const uint8_t* pub, size_t publen,
                              const uint8_t* sig, size_t siglen,
                              const uint8_t* msg, size_t msglen,
                              bool& valid) noexcept;

} // namespace p256
} // namespace crypto

#endif // NEURAI_CRYPTO_P256_H
