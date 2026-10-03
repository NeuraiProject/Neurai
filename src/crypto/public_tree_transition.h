// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_CRYPTO_PUBLIC_TREE_TRANSITION_H
#define NEURAI_CRYPTO_PUBLIC_TREE_TRANSITION_H
#include <cstddef>
#include <vector>
namespace neurai::public_tree {
using Bytes = std::vector<unsigned char>;
// Experimental profile 2: five fixed witness chunks, a contract-selected form,
// and the same public input order as the C5 Groth16 circuit. See the specification.
static constexpr size_t CHUNKS = 5;
static constexpr size_t CHUNK_BYTES = 3072;
static constexpr size_t MAX_WORK_PER_SCRIPT = 1024;
// Shape-only preflight, no hashing. Caller charges the returned work up front.
bool TransitionCost(const Bytes& transcript, unsigned form, size_t& cost);
// Public tree predicate only. Caller MUST also verify the Groth16 proof and
// enforce the custody transaction. No cache bypass or implicit authorization.
bool VerifyTransition(const Bytes& transcript, unsigned form, const Bytes& inputs);
// Experimental profile 3: independent transaction-authenticated old/new digests,
// a historical note-root witness, and portable Groth16 public inputs. A valid
// public predicate alone NEVER authorizes a spend. The contract must obtain
// both digests by introspection and jointly require this predicate and Groth16.
bool PortableTransitionCost(const Bytes& transcript, unsigned form, size_t& cost);
bool VerifyPortableTransition(const Bytes& transcript, unsigned form,
                              const Bytes& oldDigest, const Bytes& newDigest,
                              const Bytes& inputs);
}
#endif
