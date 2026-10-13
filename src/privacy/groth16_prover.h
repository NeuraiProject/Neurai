// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_GROTH16_PROVER_H
#define NEURAI_PRIVACY_GROTH16_PROVER_H

#include "privacy/circom_witness.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace privacy {

/** Groth16 BN254 proving key in snarkjs .zkey format. Sections are referenced
 *  in place in the file bytes; points are decoded when proving. */
struct ProvingKey {
    std::vector<uint8_t> data;
    uint32_t nVars = 0;
    uint32_t nPublic = 0;
    uint32_t domainSize = 0;
    uint32_t power = 0;
    // Offsets and sizes of the sections used by the prover
    size_t header = 0, coeffs = 0, coeffsSize = 0, pointsA = 0, pointsB1 = 0, pointsB2 = 0, pointsC = 0, pointsH = 0;
};

/** Parses and checks a .zkey file. */
bool LoadProvingKey(std::vector<uint8_t> data, ProvingKey& key, std::string& error);

struct Groth16Proof {
    /** Node encoding (OP_ZKVERIFY profile 1): compressed A, B, C, 128 bytes. */
    std::array<uint8_t, 128> compressed{};
    /** Affine coordinates as decimal strings, in snarkjs order. */
    std::array<std::string, 2> a;
    std::array<std::array<std::string, 2>, 2> b;
    std::array<std::string, 2> c;
    /** Public signals (witness wires 1..nPublic). */
    std::vector<FieldLE> publicSignals;
};

/** Computes a Groth16 proof for a full witness (see ComputeWitness), with the
 *  same QAP and encodings as snarkjs 0.7.6. */
bool ProveGroth16(const ProvingKey& key, const std::vector<FieldLE>& witness, Groth16Proof& proof, std::string& error);

} // namespace privacy

#endif // NEURAI_PRIVACY_GROTH16_PROVER_H
