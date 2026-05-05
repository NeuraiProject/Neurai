// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-035: strict-profile Ed25519 verification.
//
// This file is the strict-profile WRAPPER around the vendored ref10
// backend (src/crypto/ed25519/ref10.c, derived from libsodium's
// crypto_core/ed25519/ref10/ed25519_ref10.c). All consensus-critical
// acceptance rules from NIP-035 §4.4 live here:
//
//   - canonical 32-byte y < p encoding for A and R
//     (ge25519_is_canonical from ref10)
//   - decompression to a curve point
//     (ge25519_frombytes returns 0 only when (x, y) is on the curve)
//   - prime-order subgroup membership: [l]·A == identity
//     (ge25519_is_on_main_subgroup from ref10 — note: the related
//     ge25519_has_small_order is *only* a small-torsion check and is
//     deliberately NOT used; the strict profile must reject any point
//     with non-zero torsion component, not only the 8 small-order ones)
//   - canonical S < l (sc25519_is_canonical)
//   - non-cofactored verification equation [S]B == R + [H(R||A||msg)]A,
//     enforced as exact byte equality of the recomputed R against
//     sig[0..32]
//
// Anything ZIP-215 lenient is intentionally absent.

#include "crypto/ed25519.h"

#include "crypto/sha512.h"

#include <cstring>

extern "C" {
#include "crypto/ed25519/ref10_types.h"
}

namespace crypto {
namespace ed25519 {

// Strict-profile subgroup test for a decoded p3 point.
//
// `ge25519_is_on_main_subgroup(p)` enforces [l]p == identity, which
// rejects every mixed-torsion encoding and 7 of the 8 pure-torsion
// points (including the order-2 generator (0, -1)). The 8th torsion
// point — the identity (0, 1) — is mathematically in the prime-order
// subgroup, so it slips past on its own. We additionally require
// `!ge25519_has_small_order(p)`, which returns true for the full
// 8-torsion subgroup. Combined, this rejects:
//   - any point with non-zero torsion component (mixed),
//   - the 7 non-identity pure-torsion points,
//   - the identity itself (which would otherwise allow a trivial
//     universal forgery: any (R, s) with R = [s]B verifies under the
//     identity pubkey).
// Result: only points of order exactly l (the prime-order subgroup
// minus identity) are accepted, matching NIP-035 §4.4.
static bool InPrimeOrderSubgroupStrict(const ge25519_p3& p)
{
    return ge25519_is_on_main_subgroup(&p) && !ge25519_has_small_order(&p);
}

StructuralResult ValidatePubkey(const unsigned char* pubkey, size_t len)
{
    if (len != PUBKEY_SIZE) return StructuralResult::PUBKEY_SIZE_INVALID;
    if (!ge25519_is_canonical(pubkey)) return StructuralResult::PUBKEY_NON_CANONICAL;

    ge25519_p3 A;
    if (ge25519_frombytes(&A, pubkey) != 0) return StructuralResult::PUBKEY_NOT_ON_CURVE;
    if (!InPrimeOrderSubgroupStrict(A)) return StructuralResult::PUBKEY_NON_SUBGROUP;
    return StructuralResult::OK;
}

StructuralResult ValidateSignature(const unsigned char* sig, size_t len)
{
    if (len != SIG_SIZE) return StructuralResult::SIG_SIZE_INVALID;
    if (!ge25519_is_canonical(sig)) return StructuralResult::SIG_R_NON_CANONICAL;
    if (!sc25519_is_canonical(sig + 32)) return StructuralResult::SIG_S_NON_CANONICAL;

    ge25519_p3 R;
    if (ge25519_frombytes(&R, sig) != 0) return StructuralResult::SIG_R_NOT_ON_CURVE;
    if (!InPrimeOrderSubgroupStrict(R)) return StructuralResult::SIG_R_NON_SUBGROUP;
    return StructuralResult::OK;
}

bool VerifyStrict(const unsigned char* pubkey, size_t pubkey_len,
                  const unsigned char* sig,    size_t sig_len,
                  const unsigned char* msg,    size_t msg_len)
{
    if (ValidatePubkey(pubkey, pubkey_len)   != StructuralResult::OK) return false;
    if (ValidateSignature(sig, sig_len)      != StructuralResult::OK) return false;

    // Decode A negated for the verify-equation rearrangement
    //     [S]·B - [H]·A = R   <=>   [H]·(-A) + [S]·B = R
    // ge25519_frombytes_negate_vartime cannot fail for a pubkey that
    // already passed ValidatePubkey, but check the return value to
    // satisfy strict-aliasing reviewers.
    ge25519_p3 A_neg;
    if (ge25519_frombytes_negate_vartime(&A_neg, pubkey) != 0) return false;

    unsigned char h[64];
    CSHA512().Write(sig, 32)
             .Write(pubkey, 32)
             .Write(msg, msg_len)
             .Finalize(h);
    sc25519_reduce(h); // h[0..32] is now H(R||A||msg) mod l

    ge25519_p2 R_prime;
    ge25519_double_scalarmult_vartime(&R_prime, h, &A_neg, sig + 32);

    unsigned char R_prime_bytes[32];
    ge25519_tobytes(R_prime_bytes, &R_prime);

    return std::memcmp(R_prime_bytes, sig, 32) == 0;
}

} // namespace ed25519
} // namespace crypto
