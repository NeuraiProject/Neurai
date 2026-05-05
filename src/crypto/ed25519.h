// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-035: strict-profile Ed25519 verification primitive backing
// OP_CHECKSIG_ED25519 (slot 0xdd, SCRIPT_VERIFY_ED25519 bit 39).
//
// The acceptance rules below are CONSENSUS critical and must stay
// bit-exact with NIP-035 §4.4. The eventual ref10 / SUPERCOP backend
// is wrapped to enforce this strict profile; see ed25519.cpp.
//
// Profile (NIP-035 §4.4):
//   - non-cofactored RFC 8032 PureEd25519 verification equation
//         [S]B == R + [H(R || A || msg)]A
//   - reject non-canonical compressed encodings of A or R (y >= p)
//   - reject A or R outside the prime-order subgroup ([l]·P != O)
//   - reject non-canonical S (S >= l)
//   - reject decoded points that fail the on-curve relation
//   - no ZIP-215 leniency, no cofactored acceptance equation

#ifndef NEURAI_CRYPTO_ED25519_H
#define NEURAI_CRYPTO_ED25519_H

#include <cstddef>

namespace crypto {
namespace ed25519 {

/** Sizes from RFC 8032 (Ed25519 / edwards25519). */
constexpr size_t PUBKEY_SIZE = 32;
constexpr size_t SIG_SIZE    = 64;

/** Strict-profile structural validation outcome. The categories map
 *  1:1 to the NIP-035 §4.5 SCRIPT_ERR_ED25519_* codes:
 *
 *    OK                    -> proceed to verify (or push 0/1)
 *    SIG_SIZE_INVALID      -> SCRIPT_ERR_ED25519_SIG_SIZE
 *    PUBKEY_SIZE_INVALID   -> SCRIPT_ERR_ED25519_PUBKEY_SIZE
 *    PUBKEY_*              -> SCRIPT_ERR_ED25519_PUBKEY_ENCODING
 *    SIG_R_*, SIG_S_*      -> SCRIPT_ERR_ED25519_SIG_ENCODING
 */
enum class StructuralResult {
    OK,
    SIG_SIZE_INVALID,
    PUBKEY_SIZE_INVALID,
    PUBKEY_NON_CANONICAL,    // y >= p
    PUBKEY_NOT_ON_CURVE,     // decompression failed (no valid x)
    PUBKEY_NON_SUBGROUP,     // [l]A != identity
    SIG_R_NON_CANONICAL,     // R.y >= p
    SIG_R_NOT_ON_CURVE,
    SIG_R_NON_SUBGROUP,
    SIG_S_NON_CANONICAL      // S >= l
};

/** Validate the canonical Edwards25519 compressed encoding of a public
 *  key plus the prime-order-subgroup membership required by the strict
 *  profile. Returns OK only when every NIP-035 §4.4 rule passes. */
StructuralResult ValidatePubkey(const unsigned char* pubkey, size_t len);

/** Validate the canonical encoding of a 64-byte signature plus the
 *  prime-order-subgroup membership of R and the canonical-scalar bound
 *  on S. Returns OK only when every NIP-035 §4.4 rule passes. */
StructuralResult ValidateSignature(const unsigned char* sig, size_t len);

/** Strict-profile PureEd25519 verification.
 *
 *  Returns true iff every structural check above passes AND the
 *  non-cofactored verification equation [S]B == R + [H(R||A||msg)]A
 *  holds, where H is SHA-512 per RFC 8032.
 *
 *  Returns false for any failure mode (structural or cryptographic).
 *  Callers needing to distinguish "malformed" (consensus error) from
 *  "well-formed but invalid" (push 0) MUST call ValidatePubkey() and
 *  ValidateSignature() first; this is exactly what the
 *  OP_CHECKSIG_ED25519 handler does.
 */
bool VerifyStrict(const unsigned char* pubkey, size_t pubkey_len,
                  const unsigned char* sig,    size_t sig_len,
                  const unsigned char* msg,    size_t msg_len);

} // namespace ed25519
} // namespace crypto

#endif // NEURAI_CRYPTO_ED25519_H
