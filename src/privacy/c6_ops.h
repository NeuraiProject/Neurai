// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_C6_OPS_H
#define NEURAI_PRIVACY_C6_OPS_H

#include "primitives/transaction.h"
#include "privacy/c6_scan.h"
#include "privacy/circom_witness.h"
#include "privacy/groth16_prover.h"
#include "privacy/notes.h"

#include <functional>
#include <optional>

namespace privacy {

/** XNA pool rules: deposits and recipient amounts are multiples of 100 XNA;
 *  a withdrawal below 100 XNA must empty its note. */
constexpr uint64_t C6_QUANTUM = 10000000000ULL;

/** Private construction of one operation (port of c6-operations.js). Holds
 *  secret witness values: keep it in memory only and drop it after proving. */
struct C6Prepared {
    std::string operation; //!< "D", "W" or "T1".."T3"
    std::vector<CircuitInput> inputs;
    std::vector<Bytes32> publics; //!< big-endian field elements, circuit order
    std::vector<SealedNote> created;
    Bytes publication; //!< empty for a withdrawal without change
    Bytes payout;      //!< withdrawal destination script
    COutPoint funding; //!< deposit funding coin
    uint64_t amount = 0; //!< deposited, withdrawn or (transfers) sent to recipients
    uint64_t fee = 0;
    std::vector<Bytes32> cms;
    std::vector<Bytes32> nfs;
    bool hasChange = false;
};

/** An owned note and its membership in a historical root. */
struct C6Spend {
    Bytes note;
    uint32_t index = 0;
    std::vector<Bytes32> path;
    Bytes32 root{};
    /** Descriptor of the address that holds the note, where change goes back.
     *  Required for C7 (the note does not carry the diversifier); C6 derives it
     *  from the note when absent. */
    std::optional<Recipient> changeTo;
};

bool PrepareC6Deposit(const C6Config& config, const Recipient& self, uint64_t amount, uint64_t fee,
                      const COutPoint& funding, uint64_t fundingValue, C6Prepared& out, std::string& error);

bool PrepareC6Withdrawal(const C6Config& config, const C6Spend& spend, const Bytes32& spendSecret, uint64_t amount,
                         uint64_t fee, const Bytes& payoutScript, C6Prepared& out, std::string& error);

/** One recipient of a private transfer. */
struct C6Payment {
    Recipient recipient;
    uint64_t amount = 0;
};

/** Private transfer of one note to one to three recipients (multiples of 100 XNA);
 *  the remainder minus the fee goes back to the note's address as change. The
 *  form is T1..T3 after the outputs, change included (port of prepareTransfer). */
bool PrepareC6Transfer(const C6Config& config, const C6Spend& spend, const Bytes32& spendSecret,
                       const std::vector<C6Payment>& payments, uint64_t fee, C6Prepared& out, std::string& error);

/** Computes the witness, proves, checks the public signals against the wallet's
 *  intent and verifies the proof with the node's verifier. */
bool ProveC6(const C6Config& config, const C6Prepared& prepared, const std::vector<uint8_t>& wasm, const ProvingKey& key,
             std::array<uint8_t, 128>& proof, std::string& error, const std::function<void(const std::string&)>& stage = {});

/** Builds the pool transaction for a proven operation on top of the scanned state
 *  (port of buildC6Transaction). The deposit funding input is left unsigned at
 *  index fundingInput. */
bool BuildC6Transaction(const C6Config& config, const C6PoolState& state, const C6Prepared& prepared,
                        const std::array<uint8_t, 128>& proof, CMutableTransaction& tx, int& fundingInput,
                        std::string& form, std::string& error);

/** Standard destinations accepted as funding and payout: P2PKH and strict
 *  PQ (witness v2) or ECDSA (witness v3) programs. */
bool IsC6Destination(const Bytes& script);

} // namespace privacy

#endif // NEURAI_PRIVACY_C6_OPS_H
