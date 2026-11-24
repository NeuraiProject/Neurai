// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_SCRIPT_ASSETAUTH_H
#define NEURAI_SCRIPT_ASSETAUTH_H

#include "amount.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "uint256.h"

#include <cstdint>
#include <string>
#include <vector>

// NIP-054: OP_CHECKASSETAUTH (P2AH inside AuthScript).
//
// A call authorizes the spend when at least M (or G, when an owner kept at
// the evaluated destination leaves it) distinct roles of its list approve the
// transaction. A role approves by a direct signature (its owner token spent
// from P2PKH or a strict AuthScript family with SIGHASH_ALL) or by a vote
// carrying the proposal hash as its NIP-043 transfer message. Votes switch on
// the asynchronous mode: expiry and a fixed transaction shape.
//
// Policy version 1 (NIP-054 v5): a vote is the owner token spent from any
// other script, carrying H. Policy version 2 (NIP-054 v7): a vote is a
// reference input (NIP-014) whose output holds the owner token at a direct
// signature destination, carrying H2; the token is not spent. Both versions
// share the flag and the activation height.

/** Policy version 1: votes by spent input (NIP-054 v5). */
static constexpr int ASSETAUTH_POLICY_VERSION = 1;
/** Policy version 2: votes by reference input (NIP-054 v7). */
static constexpr int ASSETAUTH_POLICY_VERSION_2 = 2;
/** Highest number of roles in one policy. */
static constexpr int ASSETAUTH_MAX_ROLES = 16;
/** Stack items consumed by a version 1 call besides its roles: c, a, b, T, version, M, G, n. */
static constexpr size_t ASSETAUTH_FIXED_ITEMS = 8;
/** A version 2 call also consumes r. */
static constexpr size_t ASSETAUTH_FIXED_ITEMS_V2 = ASSETAUTH_FIXED_ITEMS + 1;

/** One decoded OP_CHECKASSETAUTH call. */
struct AssetAuthCall {
    int version{0};
    int M{0};
    int G{0};
    std::vector<std::string> roles; //!< strictly increasing; owner names (checked when evaluating)
    int64_t c{0};                   //!< proposal inputs 0..c-1
    int64_t a{0};                   //!< proposal output prefix 0..a-1
    int64_t b{0};                   //!< proposal output suffix, the last b outputs
    int64_t r{0};                   //!< version 2: proposal reference inputs 0..r-1; votes follow
    int64_t T{0};                   //!< expiry height
};

/**
 * Decode a call from the top of the stack:
 *   version 1: ... <c> <a> <b> <T> <1> <M> <G> <role_1> ... <role_n> <n>
 *   version 2: ... <c> <a> <b> <r> <T> <2> <M> <G> <role_1> ... <role_n> <n>
 * Integers are minimally encoded script numbers of up to 4 bytes. Checks the
 * stack depth, the integer encodings, the version, M, G and n, the byte order
 * of the roles and the sign of c, a, b, r, T. Whether the roles are owner
 * names is checked by EvaluateAssetAuth once their work is charged. On
 * success `consumed` is n + 8, or n + 9 for version 2. Does not touch the
 * stack.
 */
bool DecodeAssetAuthCall(const std::vector<std::vector<unsigned char>>& stack, AssetAuthCall& call,
                         size_t& consumed, ScriptError* serror);

/**
 * Serialized proposal message (NIP-054 §3.8): m for version 1, which commits
 * every reference input, and m2 for version 2, which commits r and the
 * reference inputs 0..r-1. Requires c, a + b and r in range.
 */
std::vector<unsigned char> AssetAuthProposalMessage(const CTransaction& tx, uint8_t chainId,
                                                    const AssetAuthCall& call);

/**
 * H = TaggedHash("NeuraiAssetAuthProposal", m) for version 1 and
 * H2 = TaggedHash("NeuraiAssetAuthProposalV2", m2) for version 2.
 */
uint256 AssetAuthProposalHash(const std::vector<unsigned char>& message, int version = ASSETAUTH_POLICY_VERSION);

/**
 * Name work of one execution: ceil(|name| / 32) for every role and for every
 * asset name carried by a spent output or by an output of the transaction,
 * and, for version 2, by a referenced output. Validating a name is the costly
 * step of the evaluation and grows with its length. `prevouts` must hold the
 * spent output of every input and `refOutputs`, for version 2, the referenced
 * output of every reference input; `flags` decide whether OP_2/OP_3 asset
 * scripts are read as assets, as in EvaluateAssetAuth.
 */
uint64_t AssetAuthNameWork(const AssetAuthCall& call, const CTransaction& tx, const std::vector<CTxOut>& prevouts,
                           script_verify_flags flags, const ReferencedOutputs* refOutputs = nullptr);

/**
 * Work units charged by one execution:
 * 1 + inputs + outputs + references + ceil(|m| / 64) + name work, where
 * `nRefs` is the number of reference inputs for version 2 and 0 for version 1.
 */
uint64_t AssetAuthWork(const CTransaction& tx, size_t messageSize, uint64_t nameWork, size_t nRefs = 0);

/**
 * Evaluate a decoded call against the spending transaction (NIP-054 §3.5 to
 * §3.11). `prevouts` must hold the spent output of every input and, for a
 * version 2 call in a transaction with reference inputs, `refOutputs` the
 * referenced output of each one. Charges `budget` when it is set, before
 * checking any name. `fUsedHeight` is set when the result depended on the
 * chain height (asynchronous mode), so the mempool re-validates on tip changes.
 */
bool EvaluateAssetAuth(const AssetAuthCall& call, const CTransaction& tx, unsigned int nIn,
                       const std::vector<CTxOut>& prevouts, const ChainContext& context,
                       script_verify_flags flags, AssetAuthWorkBudget* budget,
                       bool& fUsedHeight, ScriptError* serror,
                       const ReferencedOutputs* refOutputs = nullptr);

/** Destination of a scriptPubKey: the script without its asset suffix. */
CScript AssetAuthDestination(const CScript& scriptPubKey);

/**
 * NIP-043 strict transfer-message reader shared with OP_INPUTASSETFIELD and
 * OP_OUTPUTASSETFIELD selector 0x08 (defined in interpreter.cpp). Returns
 * false when the script is not a transfer or carries no message.
 */
bool GetTransferMessage(const CScript& script, std::vector<unsigned char>& result);

#endif // NEURAI_SCRIPT_ASSETAUTH_H
