# Covenants on Neurai

## Overview

Neurai integrates a full covenant system into its Script engine, enabling spending conditions that go far beyond traditional signature-based authorization. A **covenant** is a script that constrains *how* funds (or assets) may be spent — not just *who* can spend them. This allows the creation of self-enforcing smart contracts directly at the consensus layer, without relying on external virtual machines or trusted third parties.

The covenant system is built on a set of cooperating opcodes organized in five categories:

| Category | Opcodes |
|----------|---------|
| Covenant primitives | `OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK` |
| Transaction introspection | `OP_TXHASH`, `OP_TXFIELD`, `OP_TXLOCKTIME`, `OP_OUTPUTVALUE`, `OP_OUTPUTSCRIPT`, `OP_INPUTCOUNT`, `OP_OUTPUTCOUNT` |
| Asset introspection | `OP_OUTPUTASSETFIELD`, `OP_INPUTASSETFIELD` |
| Byte manipulation | `OP_CAT`, `OP_SPLIT`, `OP_REVERSEBYTES` |
| 64-bit arithmetic | `OP_MUL`, `OP_DIV`, `OP_MOD` (plus upgraded `OP_ADD`/`OP_SUB`) |

These opcodes execute inside **AuthScript** (witness version 1), a new script execution environment that extends SegWit with post-quantum signature support and a tagged commitment scheme.

---

## AuthScript: The Covenant Execution Environment

All covenants run inside AuthScript programs. An AuthScript output has the form:

```
OP_1 <32-byte commitment>
```

The 32-byte commitment is computed as:

```
TaggedHash("NeuraiAuthScript", authType || [pubkey] || witnessScript)
```

There are three authentication types:

| AuthType | Byte | Description |
|----------|------|-------------|
| Script-only | `0x00` | No key authorization. The witness script alone determines spending conditions. Ideal for pure covenants. |
| Post-quantum | `0x01` | Requires an ML-DSA-44 signature from a committed public key, then evaluates the witness script. |
| Classical | `0x02` | Requires an ECDSA/secp256k1 signature from a committed compressed public key, then evaluates the witness script. |

The witness stack for spending is structured as:

```
<authType> [<signature> <pubkey>] <arg1> <arg2> ... <witnessScript>
```

This design separates authentication (who) from authorization logic (what and how), allowing covenants to be written as pure script logic while optionally requiring key-holder approval.

---

## Covenant Building Blocks

### OP_CHECKTEMPLATEVERIFY (CTV) — Rigid Templates

CTV (BIP 119) is the simplest and most restrictive covenant primitive. It verifies that the spending transaction exactly matches a pre-committed template hash. The hash commits to:

- Transaction version and locktime
- Number and sequence of all inputs
- Number, amounts, and scripts of all outputs
- The index of the input being evaluated

**Properties:**
- The template is fully deterministic — there is no flexibility in the spending transaction.
- The hash does NOT commit to input prevouts, so the covenant works regardless of which UTXO funds it.
- Uses single-SHA256 with precomputed sub-hashes to prevent quadratic hashing.

**Example: Batched Payout**

An exchange can commit to paying 100 users in a single CTV output. When spent, the transaction must produce exactly those 100 outputs with the exact amounts. No signer can alter the destinations or amounts.

```
<template_hash> OP_CHECKTEMPLATEVERIFY
```

### OP_CHECKSIGFROMSTACK (CSFS) — Oracle Integration

CSFS verifies a signature against an arbitrary message (not the transaction hash). This enables scripts to act on externally signed data.

**Stack:** `<sig> <msg> <pubkey> → <true|false>`

The message is hashed with single-SHA256 before verification. Both ECDSA and ML-DSA-44 (post-quantum) public keys are supported.

**Example: Price Oracle**

A covenant that only releases funds if an oracle attests that the XNA/USD price exceeds a threshold:

```
<oracle_pubkey> OP_CHECKSIGFROMSTACK
OP_VERIFY
// ... remaining spending conditions
```

### OP_TXHASH — Flexible Commitments

OP_TXHASH produces a double-SHA256 hash over a configurable combination of transaction fields. A single-byte bitmask selects which fields to include:

| Bit | Field |
|-----|-------|
| 0 | Transaction version |
| 1 | Transaction locktime |
| 2 | All input prevouts |
| 3 | All input sequences |
| 4 | All serialized outputs |
| 5 | Current input's prevout |
| 6 | Current input's sequence |
| 7 | Current input index |

This is strictly more flexible than CTV: by choosing which bits to set, a script can commit to some transaction properties while leaving others free.

**Example: Output-Only Covenant**

Commit only to the outputs (bit 4 = `0x10`), allowing the transaction to have any inputs:

```
0x10 OP_TXHASH
<expected_outputs_hash> OP_EQUAL
```

### Transaction Introspection Opcodes

These opcodes push raw transaction data onto the stack for arithmetic comparison and script construction:

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_TXFIELD` | `<selector> → <raw bytes>` | Returns fields from the spent UTXO (value, AuthScript commitment, or full scriptPubKey) |
| `OP_TXLOCKTIME` | `→ <4 bytes>` | Pushes the transaction's nLockTime |
| `OP_OUTPUTVALUE` | `<index> → <amount>` | Pushes the satoshi amount of an output |
| `OP_OUTPUTSCRIPT` | `<index> → <scriptPubKey>` | Pushes the raw scriptPubKey of an output |
| `OP_INPUTCOUNT` | `→ <count>` | Pushes the number of inputs |
| `OP_OUTPUTCOUNT` | `→ <count>` | Pushes the number of outputs |

### Asset Introspection Opcodes

Unique to Neurai, these opcodes allow covenants to reason about the native asset layer:

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_OUTPUTASSETFIELD` | `<index> <selector> → <value>` | Reads a field from an output's asset payload |
| `OP_INPUTASSETFIELD` | `<index> <selector> → <value>` | Reads a field from an input's prevout asset payload |

**Asset field selectors:**

| Selector | Field | Available On |
|----------|-------|-------------|
| `0x01` | Asset name | All types |
| `0x02` | Amount | All types |
| `0x03` | Units (decimals) | New, Reissue |
| `0x04` | Reissuable flag | New, Reissue |
| `0x05` | Has IPFS flag | New |
| `0x06` | IPFS hash | New, Reissue |
| `0x07` | Asset type | All types |

### Byte Manipulation Opcodes

These opcodes provide the glue logic needed to construct and parse data on the stack:

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_CAT` | `<a> <b> → <a\|\|b>` | Concatenate two byte strings (max 520 bytes) |
| `OP_SPLIT` | `<data> <n> → <left> <right>` | Split a byte string at position n |
| `OP_REVERSEBYTES` | `<data> → <reversed>` | Reverse byte order in place |

### 64-Bit Arithmetic

All arithmetic opcodes operate on 8-byte signed integers with overflow protection. The re-enabled opcodes `OP_MUL`, `OP_DIV`, and `OP_MOD` complement the upgraded `OP_ADD` and `OP_SUB`. Results that would overflow int64 or equal `INT64_MIN` are rejected.

---

## Covenant Patterns

The following patterns illustrate how the opcodes compose to build practical smart contracts.

### 1. Vault with Time-Locked Recovery

A vault that allows immediate spending to a hot wallet (with a limit) or delayed spending to a cold wallet after a timelock.

```
// Witness script (AuthType 0x02 — classical key required)
//
// Branch 1: Spend to hot wallet, max 1 XNA per tx
OP_IF
    // Verify output 0 goes to the hot wallet
    0 OP_OUTPUTSCRIPT
    <hot_wallet_script> OP_EQUAL OP_VERIFY

    // Verify output 0 value <= 100000000 (1 XNA)
    0 OP_OUTPUTVALUE
    100000000 OP_LESSTHANOREQUAL OP_VERIFY

    // Verify output 1 returns change to this same covenant
    1 OP_OUTPUTSCRIPT
    0x03 OP_TXFIELD    // Get own scriptPubKey
    OP_EQUAL OP_VERIFY

    // Exactly 2 outputs
    OP_OUTPUTCOUNT 2 OP_NUMEQUALVERIFY

    OP_TRUE

// Branch 2: Cold recovery after 144 blocks
OP_ELSE
    // Require 144-block relative timelock
    <144> OP_CHECKSEQUENCEVERIFY OP_DROP

    // Verify output goes to cold wallet
    0 OP_OUTPUTSCRIPT
    <cold_wallet_script> OP_EQUAL

OP_ENDIF
```

**How it works:**
- The key holder can spend up to 1 XNA at a time to the hot wallet. The remaining balance must return to the same covenant (recursive covenant via `OP_TXFIELD` + `OP_OUTPUTSCRIPT`).
- After 144 blocks of inactivity, the full balance can be swept to the cold wallet.
- An attacker who compromises the key can only drain 1 XNA per block.

### 2. On-Chain DEX (Asset Swap Covenant)

A trustless limit order that exchanges an exact amount of one Neurai asset for another.

```
// Seller locks ASSET_A in this covenant. Buyer must provide ASSET_B.
//
// AuthType 0x00 — no key, pure covenant

// Verify exactly 3 outputs
OP_OUTPUTCOUNT 3 OP_NUMEQUALVERIFY

// Output 0: ASSET_B to the seller
0 0x01 OP_OUTPUTASSETFIELD        // asset name of output 0
<ASSET_B_name> OP_EQUALVERIFY

0 0x02 OP_OUTPUTASSETFIELD        // amount of ASSET_B in output 0
<required_amount_B> OP_NUMEQUALVERIFY

0 OP_OUTPUTSCRIPT
<seller_address_script> OP_EQUALVERIFY

// Output 1: ASSET_A to the buyer
1 0x01 OP_OUTPUTASSETFIELD
<ASSET_A_name> OP_EQUALVERIFY

1 0x02 OP_OUTPUTASSETFIELD
<offered_amount_A> OP_NUMEQUALVERIFY

// Output 2: XNA change (fee handling)
OP_OUTPUTCOUNT 3 OP_NUMEQUALVERIFY

OP_TRUE
```

**How it works:**
- The seller creates a UTXO locked by this covenant containing `ASSET_A`.
- Anyone can spend it, but ONLY if they produce a transaction that sends `required_amount_B` of `ASSET_B` to the seller's address and sends `ASSET_A` to themselves.
- No intermediary, no escrow, no counterparty risk. The swap is atomic by consensus.

### 3. Recurring Payment Stream

A covenant that releases a fixed amount of XNA per time period, enforcing a payment schedule.

```
// AuthType 0x00 — pure covenant, anyone can trigger the payment

// Enforce minimum timelock (e.g., 1 day = 1440 blocks)
OP_TXLOCKTIME
<start_time + (period * N)> OP_GREATERTHANOREQUAL OP_VERIFY

// Payment output (output 0)
0 OP_OUTPUTVALUE
<payment_amount> OP_NUMEQUALVERIFY

0 OP_OUTPUTSCRIPT
<recipient_script> OP_EQUALVERIFY

// Remainder returns to this covenant (output 1)
1 OP_OUTPUTSCRIPT
0x03 OP_TXFIELD
OP_EQUALVERIFY

// Verify remaining balance is correct
0x01 OP_TXFIELD                   // spent UTXO value (8 bytes)
OP_REVERSEBYTES                    // to CScriptNum format if needed
<payment_amount> OP_SUB
1 OP_OUTPUTVALUE
OP_NUMEQUALVERIFY

// Exactly 2 outputs
OP_OUTPUTCOUNT 2 OP_NUMEQUALVERIFY

OP_TRUE
```

### 4. Congestion Control (CTV Tree)

A single UTXO can commit to paying hundreds of recipients through a tree of CTV transactions, each level expanding into more outputs.

```
Level 0 (1 UTXO):
  <root_hash> OP_CHECKTEMPLATEVERIFY

Level 1 (4 UTXOs, each with a CTV):
  <hash_A> OP_CHECKTEMPLATEVERIFY
  <hash_B> OP_CHECKTEMPLATEVERIFY
  <hash_C> OP_CHECKTEMPLATEVERIFY
  <hash_D> OP_CHECKTEMPLATEVERIFY

Level 2 (16 final payments):
  Standard P2PKH/P2WPKH outputs
```

**How it works:**
- A service (e.g., mining pool, exchange) creates a single on-chain transaction committing to a payout tree.
- Each recipient can unilaterally claim their payment by broadcasting the branch of the tree that leads to their output.
- Only the paths that are actually claimed consume block space.

### 5. Asset Issuance Gate

A covenant that controls asset reissuance, requiring multi-party approval and enforcing metadata constraints.

```
// AuthType 0x01 — post-quantum key required (governance key)

// Verify the reissue output has the correct asset name
0 0x01 OP_OUTPUTASSETFIELD
<GOVERNED_ASSET_name> OP_EQUALVERIFY

// Cap the reissue amount
0 0x02 OP_OUTPUTASSETFIELD
<max_reissue_amount> OP_LESSTHANOREQUAL OP_VERIFY

// Ensure the asset remains reissuable
0 0x04 OP_OUTPUTASSETFIELD
1 OP_NUMEQUALVERIFY

// Require oracle attestation of off-chain approval
<governance_oracle_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY

// Return the owner token to this covenant
1 OP_OUTPUTSCRIPT
0x03 OP_TXFIELD
OP_EQUALVERIFY

OP_TRUE
```

### 6. Trustless Escrow with Timeout

A two-of-three escrow that automatically refunds after a deadline, with no trusted party needed to release funds.

```
// AuthType 0x00 — pure covenant

OP_IF
    // Happy path: buyer and seller agree
    // Both must sign (provide CSFS signatures on agreed message)
    <buyer_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY
    <seller_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY

    // Verify the payout structure
    0 OP_OUTPUTVALUE
    <agreed_amount> OP_NUMEQUALVERIFY

    OP_TRUE

OP_ELSE
    OP_IF
        // Dispute: arbitrator + one party
        <arbitrator_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY

        OP_TRUE

    OP_ELSE
        // Timeout: refund to buyer after 2016 blocks (~1.4 days)
        <2016> OP_CHECKSEQUENCEVERIFY OP_DROP

        0 OP_OUTPUTSCRIPT
        <buyer_refund_script> OP_EQUALVERIFY

        OP_TRUE

    OP_ENDIF
OP_ENDIF
```

### 7. DePIN Device Payment Channel

A covenant designed for IoT/DePIN devices that can receive micropayments for services, with periodic on-chain settlement.

```
// AuthType 0x02 — device key (classical ECDSA)

// The device accumulates signed payment attestations off-chain.
// Settlement covenant verifies the total and distributes funds.

// Verify oracle-signed usage report
<network_oracle_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY

// Output 0: payment to device operator
0 OP_OUTPUTVALUE
// Amount is calculated from the usage data on the stack
OP_DUP <rate_per_unit> OP_MUL
OP_NUMEQUALVERIFY

// Output 1: remaining balance to service covenant
1 OP_OUTPUTSCRIPT
0x03 OP_TXFIELD
OP_EQUALVERIFY

OP_OUTPUTCOUNT 2 OP_NUMEQUALVERIFY

OP_TRUE
```

---

## Combining Opcodes: A Composition Reference

The power of the covenant system comes from composing opcodes. Here is a reference of common compositions:

### Recursive Covenants (Self-Perpetuating Scripts)

```
// Read own scriptPubKey
0x03 OP_TXFIELD

// Verify an output pays back to the same script
<n> OP_OUTPUTSCRIPT
OP_EQUALVERIFY
```

This pattern makes a covenant that persists across transactions — the output must contain the same spending conditions, creating a state machine that lives on-chain.

### Value Conservation Check

```
// Total input value
0x01 OP_TXFIELD          // value of spent UTXO (8 bytes LE)

// Sum output values
0 OP_OUTPUTVALUE
1 OP_OUTPUTVALUE
OP_ADD

// Difference is the fee
OP_SUB
<max_fee> OP_LESSTHANOREQUAL OP_VERIFY
```

### Asset Amount Conservation

```
// Input asset amount
0 0x02 OP_INPUTASSETFIELD

// Output asset amounts
0 0x02 OP_OUTPUTASSETFIELD
1 0x02 OP_OUTPUTASSETFIELD
OP_ADD

// Must be equal (no asset inflation)
OP_NUMEQUALVERIFY
```

### Constructing a Script on the Stack

```
// Build a P2WPKH scriptPubKey: OP_0 <20-byte-hash>
0x00          // OP_0
<pubkey_hash> // 20 bytes
OP_CAT

// Verify output 0 pays to this constructed script
0 OP_OUTPUTSCRIPT
OP_EQUALVERIFY
```

### Endianness Conversion for Comparison

```
// OP_OUTPUTVALUE returns little-endian int64
0 OP_OUTPUTVALUE

// Convert to big-endian for comparison with external data
OP_REVERSEBYTES

<big_endian_threshold> OP_GREATERTHANOREQUAL
```

### Parsing Structured Data

```
// Extract fields from a serialized structure
<serialized_data>

// First 4 bytes: version
4 OP_SPLIT       // stack: <version_4bytes> <rest>
OP_SWAP

// Next 32 bytes: hash
32 OP_SPLIT      // stack: <version> <hash_32bytes> <remainder>
```

---

## Design Principles

### Minimal Trust

Covenants enforce rules at the consensus layer. No multisig committee, no oracle network, and no smart-contract platform is required for the core spending logic. Oracles (via CSFS) are optional additions for external data, not a requirement for the covenant mechanism itself.

### Composability

Each opcode does one thing well. Complex behavior emerges from composition rather than from monolithic opcodes. `OP_CAT` + `OP_OUTPUTSCRIPT` builds script verification. `OP_OUTPUTVALUE` + `OP_MUL` builds price calculations. `OP_INPUTASSETFIELD` + `OP_OUTPUTASSETFIELD` builds conservation rules.

### Graceful Degradation

Every opcode introduced via NOP replacement (`OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK`, `OP_TXHASH`, `OP_TXFIELD`, `OP_SPLIT`) falls back to NOP behavior when its activation flag is not set. Re-enabled opcodes (`OP_CAT`, `OP_MUL`, `OP_DIV`, `OP_MOD`) return `SCRIPT_ERR_DISABLED_OPCODE` when their flag is not set. This ensures soft-fork compatibility.

### Post-Quantum Readiness

AuthScript supports ML-DSA-44 (FIPS 204) signatures natively. Covenants that use AuthType `0x01` are protected against quantum attacks on the authentication layer, while the covenant logic itself (hash-based commitments, script evaluation) is inherently quantum-resistant.

### Asset-Native

Unlike overlay protocols or token standards built on top of generic scripting, Neurai's asset introspection opcodes operate directly on the consensus-validated asset layer. The script engine can verify asset names, amounts, types, and metadata without parsing serialized data — the node has already validated the asset payload before script evaluation begins.

---

## Security Considerations

### Stack Element Size Limit

All data pushed onto the stack is bounded by the effective per-element cap: `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes) by default, or `MAX_PQ_SCRIPT_ELEMENT_SIZE` (3072 bytes) when `SCRIPT_VERIFY_CHECKSIGFROMSTACK` is active (NIP-018). This applies to `OP_CAT` results, `OP_OUTPUTSCRIPT` returns, `OP_REFINPUTFIELD` returns, and `OP_TXFIELD` outputs. Scripts that exceed the effective limit fail cleanly. Under CSFS, an additional `MAX_STACK_BYTES` (256 KiB) cap bounds the total bytes held on `stack + altstack`.

### Quadratic Hashing Prevention

Both CTV and TXHASH use precomputed sub-hashes (`PrecomputedTransactionData`) to ensure O(1) evaluation per input. A transaction with N inputs evaluating the same opcode does O(N) total work, not O(N²).

### Arithmetic Overflow Protection

All 64-bit arithmetic operations use compiler intrinsics (`__builtin_add_overflow`, `__builtin_mul_overflow`) or equivalent manual bounds checking. Division by zero and `INT64_MIN` edge cases are explicitly handled. No undefined behavior is possible.

### Signature Malleability

CSFS follows the same `NULLFAIL` semantics as `OP_CHECKSIG`: under `SCRIPT_VERIFY_NULLFAIL`, a non-empty signature that fails verification causes the entire script to fail (rather than pushing false). This prevents signature grinding attacks.

---

## Comparison with Other Covenant Approaches

| Feature | Neurai Covenants | Bitcoin (proposed) | Ethereum |
|---------|-----------------|-------------------|----------|
| CTV (BIP 119) | Integrated | Proposed (not activated) | N/A (Turing-complete) |
| CSFS | Integrated | Proposed (not activated) | Native (ecrecover) |
| OP_CAT | Integrated | Proposed (not activated) | Native (bytes.concat) |
| Transaction introspection | 7 opcodes | Not available | Native (msg.value, etc.) |
| Native asset introspection | 2 opcodes | N/A (no native assets) | ERC-20 calls |
| Post-quantum auth | ML-DSA-44 AuthScript | Not available | Not available |
| Execution model | Non-Turing-complete Script | Non-Turing-complete Script | Turing-complete EVM |
| Gas/fee model | Counted sigops, bounded script | Counted sigops, bounded script | Metered gas |

---

## Policy-layer signing verification (NIP-020)

Post-signing verification in `signrawtransactionwithkey`, `neurai-tx`, and
the internal `SignSignature` path goes through a single helper
`GetStandardScriptVerifyFlagsWithConsensusOptIns(consensus)` that augments
`STANDARD_SCRIPT_VERIFY_FLAGS` with every consensus opt-in the chain has
active (`AUTHSCRIPT`, `CAT`, `CTV`, `CSFS`, `TXHASH`, `TXFIELD`, `SPLIT`,
`REVERSEBYTES`, `OUTPUTVALUE`, `OUTPUTSCRIPT`, `OUTPUTASSETFIELD`,
`INPUTASSETFIELD`, `64BIT_INTEGERS`, `TXLOCKTIME`, `INPUTOUTPUTCOUNT`,
`REFINPUTS`). Signing on testnet/regtest therefore honors the wider PQ
element cap and the other opt-ins, completing the sign-and-relay round-
trip for P2WSH with PQ-sized witnessScripts.

Mainnet relay of PQ witness items is still gated by
`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80` in `IsWitnessStandard`
(reject reason `bad-witness-nonstandard`). NIP-021 is the follow-up
policy change for that path.

## Further Reading

- [New OP_Codes Reference](new-opcodes-depin-branch.md) — Detailed specification of each opcode (byte values, flags, stack effects, error codes)
- [Atomic Swaps](atomicswaps.md) — Cross-chain atomic swap protocol
- [DePIN Client Protocol](depinreceivemsg.md) — DePIN messaging layer documentation
