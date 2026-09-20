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

### Strict AuthScript activation schedule

Testnet activates strict PQ witness v2 (`tpq1z…`), strict ECDSA witness v3
(`tnq1r…`) and NIP-041 destination introspection at **block 440000**.
This height also enables the strict-flag rules described below for v1 mixed
multisig. Earlier blocks retain their previous validation rules. Wallet and
mempool admission use the next block's height, so strict addresses become
available with the tip at 439999. Nodes must run the updated software before
block 440000. This is a scheduled consensus change, not deployment by this
repository alone.

Mainnet remains unscheduled. Regtest remains active from height 0 by default;
`-strictauthscriptheight` can override the height for regtest activation tests.

### Mixed ECDSA/PQ multisig in witness v1

At `nStrictAuthScriptHeight`, `SCRIPT_VERIFY_AUTHSCRIPT_STRICT` also enables
family-independent signature encoding checks in v1 `OP_CHECKMULTISIG` and
`OP_CHECKMULTISIGVERIFY`. A nonempty signature of `ML_DSA_44_SIG_SIZE + 1` bytes
is treated as ML-DSA-44 plus its sighash byte; other signatures use ECDSA
encoding checks. The existing encoding flags, sighash checks, pubkey checks,
NULLDUMMY and NULLFAIL rules still apply. Empty signatures remain deliberately
invalid signatures, not authorization.

A signature skips candidate keys of the other family without consuming the
signature. It must still verify against a matching key in script order. Thus
`1 <ECDSA pubkey> <PQ pubkey> 2 CHECKMULTISIG` can be satisfied by either key.
This is alternative authorization, not a requirement for both algorithms;
use a 2-of-2 threshold when both signatures are required.

Before this height, signature encoding is checked against each candidate key,
preserving historical validation, including mixed-family failures. This is a
consensus change that enables previously rejected spends, and must be included
in the activation release. Mainnet/testnet heights remain unscheduled. The
change applies only to witness v1 script execution (native or P2SH-wrapped);
it does not change CHECKSIG, Legacy/v0 multisig, or the fixed v2/v3 templates.

---

## Covenant Building Blocks

### OP_CHECKTEMPLATEVERIFY (CTV) — Rigid Templates

CTV (BIP 119) is the simplest and most restrictive covenant primitive. It verifies that the spending transaction exactly matches a pre-committed template hash. The hash commits to:

- Transaction version and locktime
- Number and sequence of all inputs
- Serialized scriptSigs, if any input has a non-empty scriptSig
- Number, amounts, and scripts of all outputs
- For transaction version 3, the reference input count and ordered outpoints (NIP-014)
- The index of the input being evaluated

**Properties:**
- The template fixes the fields listed above, including complete output scripts and asset suffixes.
- It does not commit to ordinary input prevouts or witness data. Reference outpoints in v3 are committed separately, so changing or reordering them changes the template.
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

### OP_TXHASH — Flexible Commitments (NIP-042)

`OP_TXHASH` (`0xb5`, NOP6) consumes exactly two bytes: a nonzero 16-bit
little-endian mask. Bits 0–8 are defined (511 valid masks); bits 9–15 and
all other selector lengths fail with `SCRIPT_ERR_TXHASH`.

| Bit | Serialized field |
|-----|------------------|
| 0 | Transaction version, uint32 LE |
| 1 | Transaction locktime, uint32 LE |
| 2 | SHA256d of concatenated input outpoints |
| 3 | SHA256d of concatenated input sequences, uint32 LE each |
| 4 | SHA256d of concatenated serialized outputs |
| 5 | Current input's outpoint (32 raw hash bytes + uint32 LE index) |
| 6 | Current input's sequence, uint32 LE |
| 7 | Current input index, uint32 LE |
| 8 | SHA256d of concatenated reference outpoints, in their original order |

Selected fields are concatenated in bit order, after the two-byte mask:

```text
tag = SHA256("NeuraiTxHash")
digest = SHA256(tag || tag || mask_le16 || selected_fields)
```

Sub-hashes use double SHA256; the final tagged hash uses single SHA256.
There is no count prefix in the outpoint, sequence, output or reference lists.
Each output contains an int64 LE value followed by a CompactSize-prefixed
script, including its full witness program and asset suffix. Bits 5–7 require
a valid current input index. For non-v3 transactions or an empty reference
list, bit 8 contributes `SHA256d("")`.

Unselected fields remain free. No mask commits to scriptSigs or witness data.
Bit 8 binds reference **outpoints**, unlike checking only their destination
scripts. Reordering references changes the digest precisely when bit 8 is set.
The tag does not identify a network, application or oracle; protocols needing
that separation must include their own application/network tag in the signed
message.

**Output-only covenant** (the push contains bytes `10 00`, not a Script number):

```text
<10 00> OP_TXHASH <expected_digest> OP_EQUAL
```

**Outputs and references authorized by an oracle:**

```text
witness arguments: [oracle_signature]
script: <10 01> OP_TXHASH <oracle_pubkey> OP_CHECKSIGFROMSTACK
```

CSFS verifies a signature over `SHA256(digest)`, with a trailing signature-type
byte removed before verification. This applies to both ECDSA and ML-DSA-44.
A saved ML-DSA signature must verify, but randomized signing need not reproduce
its bytes. To bind an application, sign `SHA256(app_tag || digest)` and build
that message with `<app_tag> <10 01> OP_TXHASH OP_CAT`.

**No references:** `<00 01> OP_TXHASH` yields raw digest bytes
`308542cb639a0e6ac414070f3be7c7e13827c7dde337c4d1202853376519fab1`.
These are hash bytes, not the reversed `uint256::GetHex()` display order.

Activation uses `nTxHashHeight`: block **1 of the reset testnet**, block 0 of
regtest by default, and no scheduled mainnet height. `-txhashheight=<n>` is a
regtest-only override. `SCRIPT_VERIFY_TXHASH` governs selector and digest
together; the old format is removed. Before activation the opcode is NOP6 in
consensus and discouraged by standard policy. Mempool checks use the next
block's height and revalidate entries when a reorg crosses activation.

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
| `OP_OUTPUTAUTHDEST` | `<index> → <33 bytes>` | NIP-041: pushes the AuthScript destination of an output as `version || commitment` |

#### AuthScript destination introspection (NIP-041)

`OP_OUTPUTAUTHDEST` (`0xc2`) and selector `0x04` of `OP_TXFIELD` (spent input) and
`OP_REFINPUTFIELD` (reference input) return the destination of a script as exactly
33 bytes: the witness version (`01` generic AuthScript, `02` strict post-quantum,
`03` strict ECDSA) followed by the 32-byte program in its original byte order.
They activate at the same height as the strict AuthScript families.

Unlike the NIP-023 operations (`OP_OUTPUTAUTHCOMMITMENT`, selector `0x02`), which
return 32 bytes, only understand witness v1 and merely peek at the first 34 bytes,
these operations require a well-formed script: either the exact native program
`OP_n 0x20 <32 bytes>`, or that program followed by a valid asset wrapper
(`OP_XNA_ASSET <payload> OP_DROP`, nothing after it, payload deserializable).
Trailing instructions, malformed wrappers, other witness versions or program
lengths make the operation fail. Because the version is part of the result, the
same 32 bytes under another version never satisfy a covenant.

NIP-041 parses the payload within the pushed bytes and rejects leftovers. Hashes
use a dedicated strict reader: tag `0x12` (IPFS) or `0x54` (transaction metadata),
canonical CompactSize length 32, and exactly 32 data bytes. An issuance hash flag
must be 0 or 1; flag 1 requires the hash. Transfers and reissues may omit the hash;
a transfer with a hash may additionally carry exactly eight expiration bytes.
Unknown tags, truncated hashes, different lengths and trailing bytes fail.
Historical asset field parsers retain their existing behavior; this validation
is specific to the three NIP-041 destination queries.

This identifies the destination only. A covenant that cares about which asset is
paid, and how much, must still check them with `OP_OUTPUTASSETFIELD`. The NIP-023
operations keep their behaviour unchanged for existing contracts.

```
// "Output 0 must pay the strict post-quantum destination X"
0 OP_OUTPUTAUTHDEST  <02 || X>  OP_EQUALVERIFY
```

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

Every opcode introduced via NOP replacement (`OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK`, `OP_TXHASH`, `OP_TXFIELD`, `OP_SPLIT`) falls back to NOP behavior when its activation flag is not set. Re-enabled opcodes (`OP_CAT`, `OP_MUL`, `OP_DIV`, `OP_MOD`) return `SCRIPT_ERR_DISABLED_OPCODE` when their flag is not set. These rules define pre-activation evaluation; activating stack-changing opcodes still requires the network's coordinated consensus upgrade.

### Post-Quantum Readiness

AuthScript supports ML-DSA-44 (FIPS 204) signatures natively. Covenants that use AuthType `0x01` are protected against quantum attacks on the authentication layer, while the covenant logic itself (hash-based commitments, script evaluation) is inherently quantum-resistant.

### Asset-Native

Unlike overlay protocols or token standards built on top of generic scripting, Neurai's asset introspection opcodes operate directly on the consensus-validated asset layer. The script engine can verify asset names, amounts, types, and metadata without parsing serialized data — the node has already validated the asset payload before script evaluation begins.

---

## Security Considerations

### Stack Element Size Limit

All data pushed onto the stack is bounded by the effective per-element cap: `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes) by default, or `MAX_PQ_SCRIPT_ELEMENT_SIZE` (3072 bytes) when `SCRIPT_VERIFY_CHECKSIGFROMSTACK` is active (NIP-018). This applies to `OP_CAT` results, `OP_OUTPUTSCRIPT` returns, `OP_REFINPUTFIELD` returns, and `OP_TXFIELD` outputs. Scripts that exceed the effective limit fail cleanly. Under CSFS, an additional `MAX_STACK_BYTES` (256 KiB) cap bounds the total bytes held on `stack + altstack`.

### Quadratic Hashing Prevention

CTV and TXHASH use precomputed sub-hashes (`PrecomputedTransactionData`) for O(1) evaluation per opcode after the cache is populated. Without a populated cache, each execution that selects a list hashes that list again in O(n) time.

### Arithmetic Overflow Protection

All 64-bit arithmetic operations use compiler intrinsics (`__builtin_add_overflow`, `__builtin_mul_overflow`) or equivalent manual bounds checking. Division by zero and `INT64_MIN` edge cases are explicitly handled. No undefined behavior is possible.

### CSFS Signature Operation Accounting

With `SCRIPT_VERIFY_CHECKSIGFROMSTACK` active, each CSFS instruction counts as
one signature operation for either ECDSA or PQ. Counting is static: instructions
in unexecuted branches count too, while opcode bytes inside pushed data do not.
The existing scale applies: four cost units for legacy/P2SH, one for witness.
P2SH's per-input policy limit includes these instructions when activated.

Legacy creation-time scans include active CSFS in scriptSigs and outputs. Bare
spent output scripts are also charged for their top-level CSFS instructions,
so outputs created before activation cannot verify CSFS without a spend-time
charge. Revealed P2SH and witness scripts use their respective accounting paths.
A bare CSFS output can therefore be charged at both creation and redemption.
The old context-free counters retain their defaults and NOP5 contributes zero
when the activation flag is absent. Mempool accounting uses the network's
consensus opt-in flags, matching the contextual block-validation path.

### CHECKSIGADD and Ed25519 Signature Operation Accounting

With their respective verification flags enabled, `OP_CHECKSIGADD` and
`OP_CHECKSIG_ED25519` each add one static sigop, using the same scale as CSFS:
four cost units in legacy/P2SH, one in witness. The flags are independent;
a disabled opcode contributes no optional sigops and its execution continues
to fail with BAD_OPCODE. Unexecuted branches count; bytes inside pushes do not.
Bare spent output scripts are charged at redemption as well as creation,
including outputs created before opcode activation. P2SH policy includes these
operations in its per-input limit. Mempool and contextual block validation use
the activated counters, as does the reported coinbase template cost.

CHECKSIGADD's existing dynamic surcharge of eight against MAX_OPS_PER_SCRIPT
is unchanged and separate from the global sigop budget. One global sigop per
signature is consistent with CSFS and AuthScript authentication; it is not a
claim that ECDSA, ML-DSA and Ed25519 have equal CPU costs.

This tightens consensus on networks where these opcodes are already enabled
(testnet and regtest). It does not set a new activation schedule or establish
compatibility with every historical testnet block; deployment needs coordination.

### Height activation of signature opcodes

CSFS, CHECKSIGADD and Ed25519 share `nSignatureOpcodesHeight`. Their individual
capability switches only take effect at or above that height. Mainnet leaves
the height unscheduled (`INT_MAX`); testnet and regtest retain height zero.
`-signatureopcodesheight=N` overrides the height only on regtest.

Block validation supplies the block's height explicitly. Mempool admission,
including its second consensus-flags check, uses the next block's height.
The same rule gates sigop accounting and the related witness/P2SH policy.
Signing/RPC defaults follow the next height of the loaded chain; before loading
a chain they default to zero. The standalone offline transaction tool has no
chain tip and therefore uses that zero default.

On a reorganization or connection crossing this height, the existing script-rule
mempool sweep revalidates affected entries. Entries whose stored sigop cost no
longer matches are evicted with descendants, rather than leaving stale package
sizes/costs. They can be retransmitted and admitted under the new rules. The
second pass after reorg readmission covers temporarily missing parents. Reorgs
that do not cross a script-rule activation height do not trigger this full sweep.
This does not introduce a separate historical accounting schedule on testnet.

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

NIP-021 ties the P2WSH per-stack-item relay cap in `IsWitnessStandard`
to CSFS activation: the effective cap is `MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE`
(3072 B, `MAX_PQ_SCRIPT_ELEMENT_SIZE`) when `csfsActive` is true, and
`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE` (80 B) otherwise. On testnet/regtest
(`nCSFSEnabled = true`) PQ-sized witness items relay normally; on mainnet
(`nCSFSEnabled = false`) the 80-byte cap remains in effect and oversize
items are rejected with reason `bad-witness-nonstandard` until CSFS
is activated on mainnet.

## SNARK-friendly hashing: `OP_POSEIDON` (NIP-036)

`OP_POSEIDON` (slot `0xc9`) implements the Poseidon hash over the BN254
scalar field — the same hash used by `circom`, `snarkjs`,
`go-iden3-crypto`, and Polygon zkEVM for in-circuit commitments. Because
it is ~100× cheaper inside a SNARK circuit than SHA-256, it makes
NIP-016 `OP_ZKVERIFY` practically usable for proofs that hash data on
the prover side and want the verifier to match the same hash on-chain.

### Stack contract

```
<data> OP_POSEIDON → <32-byte BE Fr element>
```

Output is always 32 bytes (one BN254 Fr element, big-endian). Fits under
`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80` so it never trips the
standardness cap for downstream items.

### Activation and flag-off behaviour

- Slot `0xc9` was previously **`bad-opcode`**, never a reserved NOP.
- Activation gates on `consensus.nPoseidonEnabled` (true on
  testnet/regtest from genesis, false on mainnet until a future
  activation NIP). Activation is a hard fork.
- With `SCRIPT_VERIFY_POSEIDON` (bit 38) **unset**, the handler returns
  `SCRIPT_ERR_BAD_OPCODE` — *not* `DISCOURAGE_UPGRADABLE_NOPS`. This
  matches the activation pattern of NIP-026 / NIP-030 / NIP-031 /
  NIP-034a and avoids consensus splits between flag-on and flag-off
  nodes.
- Stack underflow with the flag on returns `SCRIPT_ERR_INVALID_STACK_OPERATION`.
- The flag check runs **before** the underflow check by design, so
  flag-off scripts always fail with `BAD_OPCODE` regardless of stack
  contents.

### Per-script byte budget (NIP-036 §3.7)

To bound worst-case validation cost, the handler enforces a per-script
cumulative input-byte budget:

```
MAX_POSEIDON_INPUT_BYTES_PER_SCRIPT = 30720   // 30 KiB
```

The interpreter carries a `nPoseidonInputBytes` counter alongside
`nOpCount`. Each `OP_POSEIDON` invocation adds the popped item's size
to that counter; when the new total would exceed the 30 KB ceiling, the
handler returns `SCRIPT_ERR_POSEIDON_BUDGET` before doing any Poseidon
work.

This budget is generous enough to cover post-quantum scripts: hashing a
single ML-DSA-44 public key (1312 B) plus a signature (2420 B) plus a
short message and a few intermediate hashes is well under 30 KB. It also
keeps the worst-case Poseidon-saturated script at ~10.9 ms on CI
hardware (~1× `OP_CHECKMULTISIG`-saturated, ~5× under the 5× DoS gate).

A naïve per-opcode 520 B input cap was considered and rejected during
the NIP-036 v2 review because it would lock out PQ-sized inputs —
NIP-018 specifically widened `EffectiveMaxScriptElementSize` to 3072 B
for PQ pushes, and we keep that capability available to `OP_POSEIDON`
callers.

### Worked example: ZK + PQ commitment

```
<sig_pq> <pubkey_pq> OP_VERIFY_PQSIG_SOMETHING       // ML-DSA verify
<pubkey_pq> OP_POSEIDON <commitment> OP_EQUALVERIFY  // 1312 B → 32 B → equality
```

This single-call Poseidon on a 1312 B input only costs ~960 µs on CI
hardware and consumes 1312 B of the 30 720 B budget — comfortable
headroom for additional commitments inside the same script.

---

## Further Reading

- [New OP_Codes Reference](new-opcodes-depin-branch.md) — Detailed specification of each opcode (byte values, flags, stack effects, error codes)
- [Atomic Swaps](atomicswaps.md) — Cross-chain atomic swap protocol
- [DePIN Client Protocol](depinreceivemsg.md) — DePIN messaging layer documentation
- [NIP-036 v2](../NIP/Pendiente/036-OP_POSEIDON-v2.md) — Full Poseidon-on-BN254 specification, byte sponge, DoS analysis

### AuthScript contract address encoding

Generic witness v1 uses Bech32m HRP `nc` on mainnet and `tnc` on
testnet/regtest: `nc1p…` / `tnc1p…`. The former `nq1p…` / `tnq1p…`
representations are rejected; no legacy-prefix alias or address migration is
provided. This changes address encoding only, not commitments or consensus.
Strict PQ v2 keeps `pq1z…` / `tpq1z…`; strict ECDSA v3 keeps
`nq1r…` / `tnq1r…`. Qt generates strict v2 receiving destinations for PQ
wallets once activated. Generic v1 construction remains available through
the existing RPC paths for contracts. Old testnet address-book strings and
external integrations must be updated; this is intentionally incompatible.


## NIP-043: state-thread primitives

These three capabilities have independent height gates: reset testnet block 1,
regtest height 0, mainnet unscheduled. Regtest overrides are
`-assetmessageheight`, `-inputfieldheight`, and `-merkleposeidonheight`.
They do not implement ZK, MAST or custody; those remain separate dependencies.

* `OP_OUTPUTASSETFIELD`, `OP_INPUTASSETFIELD`, `OP_REFINPUTASSETFIELD`: selector
  `08` requires `SCRIPT_VERIFY_ASSETMESSAGEFIELD` (bit 45). It reads only a
  transfer payload within its single push, followed by `OP_DROP` and no
  trailing script. After name and amount it requires `54 20 <32 bytes>` or
  `12 20 <32 bytes>` and optionally exactly eight expiration bytes. The result
  is the 32-byte message or the 34-byte IPFS multihash. Absent, truncated,
  noncanonical or unknown encodings fail; old selectors are unchanged.
  Both known asset markers are recognizable; the asset consensus rules still
  govern which marker can appear in a new output at each height.
* `OP_INPUTFIELD` (`c4`, bit 46): `(index selector -- field)`. Selector `01`
  returns raw eight-byte LE nValue, **including with 64-bit arithmetic active**;
  `02` returns the historical v1 commitment, `03` the complete spent script,
  and `04` the strict NIP-041 version-plus-commitment (also requires AUTHDEST).
  It indexes spent inputs, never reference inputs. Unknown selectors, unavailable
  prevouts, invalid indices and fields over the effective element limit fail.
  Its preactivation behavior is BAD_OPCODE. Reference-field behavior is unchanged.
* Merkle scheme `05` requires MERKLE_INCLUSION, POSEIDON and
  `SCRIPT_VERIFY_MERKLE_POSEIDON` (bit 47). A node is the first field element of
  `Permutation(0,left,right)`, not the NIP-036 byte sponge. Leaf, siblings and
  root must be canonical BN254 field elements in 32-byte big-endian form.
  Depth is 1..32; bitmap order and unused-bit behavior match NIP-031. Each
  structurally complete path is charged `62 * depth` against the same per-script
  Poseidon budget as OP_POSEIDON, before cryptographic work, even if verification
  later fails. Malformed paths return false; insufficient budget aborts with
  POSEIDON_BUDGET. Scheme 05 unavailable also returns false, preserving the
  existing unknown-scheme behavior; disabling the whole opcode yields BAD_OPCODE.

Reproducible first-deliverable example: `scripts/review-contract-thread-regtest.py`.
It constructs a real UNIQUE thread under AuthScript v1 with 32-byte state and an
ECDSA or ML-DSA-44 CSFS oracle signing `DOMAIN || old_state || new_state`
exactly as in NIP-043 §8. DOMAIN binds the network genesis and UNIQUE issuance
outpoint; the transfer scripts are compared in full. This is a
state-transition integration test, not a private pool or an audited application.


## NIP-044 AuthScript trees (initial integration)

Witness v1 additionally supports markers `0x10` (NoAuth), `0x11` (ML-DSA global)
and `0x12` (compressed ECDSA global), gated by `SCRIPT_VERIFY_AUTHSCRIPT_TREE`
(bit 44) and the base AuthScript flag. The final two witness items are the leaf
script and `0x01 || siblings` control block, with siblings ordered leaf-to-root
and depth at most 32. Commitment version `0x04` hashes the ordinary descriptor
and the sorted-pair Merkle root. Existing `0x00/0x01/0x02` spends are unchanged.

Transaction signatures use `TaggedHash("NeuraiAuthTreeSig", 0x01 || role ||
authType || program || leafHash || baseSighash)`. The message is 99 bytes; role
is 0 for global authentication and 1 for internal CHECKSIG/CHECKSIGADD/MULTISIG.
The base is the ordinary AuthScript sighash using the complete witness marker.
CSFS and Ed25519 still sign explicit messages using their existing conventions.

Sigops come from the penultimate witness item, plus one for global authentication
only. The control block is not Script. Initial arguments are limited to 1000;
leaf size is at most 10000 bytes. TREE does not raise the 201-opcode budget or
widen the effective argument-element limit by itself.

Activation: reset testnet height 1, regtest 0 with `-authscripttreeheight`, mainnet
unscheduled. No live network has been updated by this integration. Wallet tree
import, backup and automatic leaf selection are not implemented. Manual contract
signing uses the explicit tree context API; arbitrary partial-signature merging
is unsupported and does not fall back to the historical domain.

See [NIP-044 v2](../NIP/Pendiente/044-AuthScript-Arbol-de-Scripts-MAST-v2.md)
and [validation evidence](../NIP/bench/nip044-integracion.md).

### Asset replacement policy (NIP025-patch1)

Asset operations may use ordinary BIP68/CSV sequence numbers. The former
consensus requirement that every input use a sequence of at least `0xfffffffe`
has been removed for the reset-network deployment; such a removal is a
consensus relaxation on a network that enforced the old rule. Do not deploy
this revision as an uncoordinated update to that network.

Transaction replacement is disabled by default (`-mempoolreplacement=0`), as
before. When enabled, ordinary XNA replacements retain the existing opt-in RBF
rules. A replacement involving asset inputs, asset outputs or administrative
asset outputs is rejected with `replacement-involves-assets`. This includes a
replacement that would evict an asset operation indirectly through an ordinary
ancestor. The bounded eviction set is classified from live chain/mempool coins;
no protection metadata is persisted. Read-only reference inputs alone do not
trigger protection.

Initial admission of a valid asset operation remains possible even if its
CSV sequence signals BIP125. That signal does not promise effective
replaceability under local policy. The wallet's `bumpfee` RPC remains deprecated;
this change does not enable it or redefine BIP125 reporting.

This policy does not confer finality, prevent conflicting valid blocks, or
prevent expiry/eviction. It also prevents legitimate replacement fee bumps and
allows a protected child to pin an ordinary parent. Applications must account
for these limits; CPFP is an option only where outputs, package limits and miner
support allow it. Asset balances, permission checks and signatures remain
consensus requirements independent of this replacement policy.
