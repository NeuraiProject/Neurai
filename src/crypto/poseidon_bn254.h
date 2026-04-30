// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_CRYPTO_POSEIDON_BN254_H
#define NEURAI_CRYPTO_POSEIDON_BN254_H

#include <cstddef>
#include <cstdint>

namespace crypto {

/** NIP-036: Poseidon hash over the BN254 scalar field Fr.
 *
 *  Hashes a byte string via the §3.5 byte sponge (CHUNK = 31 bytes,
 *  rate = 2, capacity = 1, t = 3 state, R_F = 8 full + R_P = 57 partial
 *  rounds, x^5 S-box). The output is the first Fr element of the
 *  squeezed state, serialised as big-endian 32 bytes.
 *
 *  Compatibility: the underlying permutation matches arnaucube/poseidon-rs
 *  (which is itself circomlib- / go-iden3-crypto-compatible — see the
 *  upstream pin in poseidon_bn254_constants.h). The byte sponge built
 *  on top is NIP-036 specific; spec-pinned vectors live in
 *  src/test/data/poseidon_vectors.json and §3.6 of the NIP.
 */
void PoseidonBN254(const unsigned char* data, size_t len,
                   unsigned char hash[32]);

// =====================================================================
// Internal API — exposed for unit tests in src/test/poseidon_tests.cpp.
// Not API-stable. Consumers other than the in-tree tests should ignore
// this namespace.
// =====================================================================
namespace poseidon_bn254_detail {

/** A BN254 scalar-field element.
 *
 *  Stored as 4 little-endian uint64_t limbs in MONTGOMERY form: the
 *  value X is represented as X*R mod r, where R = 2^256 and r is the
 *  BN254 scalar-field modulus. All Fr* helpers below operate on the
 *  Montgomery representation; conversion to/from canonical happens at
 *  the API boundary (FrFromCanonical / FrToCanonical / FrFromBytesBE /
 *  FrToBytesBE). Equal Fr values have identical limbs (MontMul reduces
 *  modulo r at the end of every multiplication).
 */
struct Fr {
    uint64_t limbs[4];
};

/** Construct an Fr from 4 little-endian canonical (non-Montgomery)
 *  limbs. The value must be < r; this is not checked in release builds. */
Fr FrFromCanonical(const uint64_t canonical_limbs[4]);

/** Extract the 4 little-endian canonical limbs of an Fr. */
void FrToCanonical(const Fr& a, uint64_t out_limbs[4]);

/** Construct an Fr from a 32-byte big-endian buffer. The caller must
 *  ensure the encoded value is < r; NIP §3.5 left-pads each 31-byte
 *  chunk with a zero high byte, guaranteeing values < 2^248 < r. */
Fr FrFromBytesBE(const unsigned char bytes32[32]);

/** Serialise an Fr as 32 big-endian bytes (canonical form). */
void FrToBytesBE(const Fr& x, unsigned char bytes32[32]);

Fr FrAdd(const Fr& a, const Fr& b);
Fr FrSub(const Fr& a, const Fr& b);
Fr FrMul(const Fr& a, const Fr& b);

/** x^5 (the Poseidon S-box). Implemented as three multiplications:
 *  x^2 = x*x, x^4 = x^2*x^2, x^5 = x^4*x. */
Fr FrPow5(const Fr& x);

bool FrEqual(const Fr& a, const Fr& b);

/** Apply the Poseidon-on-BN254 permutation in place to a t=3 state.
 *
 *  Round structure: R_F = 8 full rounds (split as 4 head + 4 tail)
 *  surrounding R_P = 57 partial rounds. Each round (a) adds the t
 *  round-constants into the state, (b) applies the x^5 S-box to all
 *  elements (full round) or only to state[0] (partial round), and
 *  (c) multiplies the state by the 3x3 MDS matrix. Constants come
 *  from poseidon_bn254_constants.h (pinned at arnaucube/poseidon-rs).
 *
 *  Compatibility check: for state == {0, 1, 2} (capacity 0, inputs
 *  1 and 2), the resulting state[0] in canonical BE bytes equals
 *  0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a,
 *  which matches Poseidon([1, 2]) under circomlibjs / go-iden3-crypto /
 *  arnaucube/poseidon-rs. */
void Permutation(Fr state[3]);

} // namespace poseidon_bn254_detail
} // namespace crypto

#endif // NEURAI_CRYPTO_POSEIDON_BN254_H
