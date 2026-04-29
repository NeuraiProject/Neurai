// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-031: native Merkle inclusion verifier.

#ifndef NEURAI_SCRIPT_MERKLE_INCLUSION_H
#define NEURAI_SCRIPT_MERKLE_INCLUSION_H

#include <cstddef>
#include <cstdint>

namespace nip031 {

// Tree-scheme selectors. A scheme bundles every byte-level convention:
// whether the leaf is prehashed, which hash function is used at the
// node level, and whether nodes are hashed once or twice.
enum TreeScheme : uint8_t {
    SCHEME_BITCOIN_NEURAI   = 0x01, // 32-B prehashed leaf, double-SHA256 nodes
    SCHEME_SHA256_PLAIN     = 0x02, // raw leaf, single-SHA256
    SCHEME_KECCAK256_PLAIN  = 0x03, // raw leaf, single Keccak-256 (NIP-030)
    SCHEME_BLAKE2B_PLAIN    = 0x04, // raw leaf, single BLAKE2b-256 (NIP-030)
};

// Maximum tree depth supported by the verifier. Keeps the proof
// element below 1 KiB so it fits comfortably under the
// MAX_PQ_SCRIPT_ELEMENT_SIZE (3072) cap that NIP-031 reuses.
static constexpr uint8_t NIP031_MAX_DEPTH = 32;

/**
 * Verify that `leaf` (leafLen bytes) is included under `root` (must
 * point to exactly 32 bytes), given a serialised path `proof` of
 * `proofLen` bytes.
 *
 * proof layout:
 *   depth (1 B) || siblings (32 B * depth) || bitmap (ceil(depth/8) B)
 *
 * Bitmap bit i (LSB-first, byte-by-byte) is 0 when the running hash at
 * level i is on the LEFT of its sibling, 1 when on the RIGHT.
 *
 * Returns false (no abort, no exception) on any malformed input:
 *   - depth > NIP031_MAX_DEPTH
 *   - proofLen != 1 + 32*depth + ceil(depth/8)
 *   - scheme not in {0x01, 0x02, 0x03, 0x04}
 *   - scheme == 0x01 and leafLen != 32
 *
 * The helper does NOT consult script-verify flags. Scheme-availability
 * gating (NIP-030 dependency for 0x03/0x04) is the caller's
 * responsibility — see the OP_CHECKMERKLEINCLUSION handler in
 * EvalScript.
 *
 * `root` must point to exactly 32 bytes; the caller is responsible for
 * checking the size of the corresponding stack element before calling.
 */
bool VerifyMerkleInclusion(const unsigned char* leaf,    size_t leafLen,
                            uint8_t scheme,
                            const unsigned char* proof,  size_t proofLen,
                            const unsigned char  root[32]);

} // namespace nip031

#endif // NEURAI_SCRIPT_MERKLE_INCLUSION_H
