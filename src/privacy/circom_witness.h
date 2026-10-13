// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_CIRCOM_WITNESS_H
#define NEURAI_PRIVACY_CIRCOM_WITNESS_H

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

class UniValue;

namespace privacy {

/** Field element as 32 little-endian bytes (canonical, below the circuit prime). */
using FieldLE = std::array<uint8_t, 32>;

/** One circuit input signal (possibly an array, flattened in row-major order). */
using CircuitInput = std::pair<std::string, std::vector<FieldLE>>;

/** Converts a JSON input object (as used by snarkjs: decimal strings, numbers and
 *  nested arrays) into flattened circuit inputs. */
bool ParseCircuitInputs(const UniValue& json, std::vector<CircuitInput>& out, std::string& error);

/** Runs a circom 2 witness generator (.wasm) with the wasm3 interpreter.
 *  The result has one element per circuit wire, wire 0 being the constant 1. */
bool ComputeWitness(const std::vector<uint8_t>& wasm, const std::vector<CircuitInput>& inputs,
                    std::vector<FieldLE>& witness, std::string& error);

} // namespace privacy

#endif // NEURAI_PRIVACY_CIRCOM_WITNESS_H
