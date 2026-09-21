// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_CRYPTO_GROTH16_BN254_H
#define NEURAI_CRYPTO_GROTH16_BN254_H
#include <span>
#include <array>
#include "crypto/backend_error.h"
#include <cstddef>
#include <cstdint>
namespace neurai::zk {
constexpr std::size_t MAX_INPUTS = 16;
enum class Result { VALID, INVALID, INPUT_COUNT, INPUT_RANGE, VK_ENCODING, PROOF_ENCODING, INTERNAL };
/** Strict NIP-018 profile 1. Inputs are concatenated 32-byte BE scalars.
 * INTERNAL denotes a local backend failure, not an invalid proof.
 * No witness empty-proof semantics here: the interpreter owns that path.
 */
Result Verify(std::span<const uint8_t> vk, std::span<const uint8_t> proof,
              std::span<const uint8_t> inputs, bool use_cache = true) noexcept;
/** Fixed-storage caches. Configuration/reset is intended for quiescent tests.
 * Zero slots disables the corresponding cache; values are capped at 256/4096.
 * No untrusted-sized allocations; at most four concurrent backend executions.
 */
struct CacheInfo {
    std::size_t vk_hits, result_hits, vk_evictions, result_evictions;
    std::size_t bytes, active, peak;
};
void ResetCaches(std::size_t vk_slots = 256, std::size_t result_slots = 4096);
CacheInfo GetCacheInfo();
std::array<uint8_t,32> VerificationCacheKey(std::span<const uint8_t> vk,
    std::span<const uint8_t> proof, std::span<const uint8_t> inputs);
/** Consensus callers must use this wrapper, so INTERNAL cannot become INVALID. */
inline Result VerifyChecked(std::span<const uint8_t> vk, std::span<const uint8_t> proof,
                            std::span<const uint8_t> inputs)
{
    const auto result = Verify(vk, proof, inputs);
    if (result == Result::INTERNAL) throw CryptoBackendError();
    return result;
}
}
#endif
