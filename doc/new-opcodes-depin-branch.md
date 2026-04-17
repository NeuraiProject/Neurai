# New OP_Codes in the DePIN-Test Branch

This document describes all new and re-enabled opcodes introduced in the `DePIN-Test` branch compared to `main`. Each opcode is documented with its byte value, stack effects, parameters, activation flag, error codes, and intended use. Opcodes are grouped by functional similarity.

---

## Table of Contents

1. [Covenant & Template Opcodes](#1-covenant--template-opcodes)
   - [OP_CHECKTEMPLATEVERIFY (CTV)](#11-op_checktemplateverify-ctv)
   - [OP_CHECKSIGFROMSTACK (CSFS)](#12-op_checksigfromstack-csfs)
2. [Transaction Introspection Opcodes](#2-transaction-introspection-opcodes)
   - [OP_TXHASH](#21-op_txhash)
   - [OP_TXFIELD](#22-op_txfield)
   - [OP_TXLOCKTIME](#23-op_txlocktime)
   - [OP_OUTPUTVALUE](#24-op_outputvalue)
   - [OP_OUTPUTSCRIPT](#25-op_outputscript)
   - [OP_INPUTCOUNT](#26-op_inputcount)
   - [OP_OUTPUTCOUNT](#27-op_outputcount)
3. [Asset Introspection Opcodes](#3-asset-introspection-opcodes)
   - [OP_OUTPUTASSETFIELD](#31-op_outputassetfield)
   - [OP_INPUTASSETFIELD](#32-op_inputassetfield)
4. [Reference Input Introspection Opcodes](#4-reference-input-introspection-opcodes)
   - [OP_REFINPUTCOUNT](#41-op_refinputcount)
   - [OP_REFINPUTFIELD](#42-op_refinputfield)
   - [OP_REFINPUTASSETFIELD](#43-op_refinputassetfield)
5. [Byte Manipulation Opcodes](#5-byte-manipulation-opcodes)
   - [OP_CAT](#51-op_cat)
   - [OP_SPLIT](#52-op_split)
   - [OP_REVERSEBYTES](#53-op_reversebytes)
6. [64-Bit Arithmetic (Re-enabled Opcodes)](#6-64-bit-arithmetic-re-enabled-opcodes)
   - [OP_MUL](#61-op_mul)
   - [OP_DIV](#62-op_div)
   - [OP_MOD](#63-op_mod)
   - [64-Bit Overflow-Safe Arithmetic on Existing Opcodes](#64-64-bit-overflow-safe-arithmetic-on-existing-opcodes)

---

## 1. Covenant & Template Opcodes

These opcodes enable scripts to constrain how a transaction may spend funds, creating "covenants" — spending conditions that go beyond simple signature verification.

---

### 1.1 OP_CHECKTEMPLATEVERIFY (CTV)

| Property | Value |
|---|---|
| **Byte Value** | `0xb3` (replaces `OP_NOP4`) |
| **Activation Flag** | `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` (bit 18) |
| **Consensus Parameter** | `nCTVEnabled` |
| **Error Code** | `SCRIPT_ERR_CHECKTEMPLATEVERIFY` |
| **BIP Reference** | BIP 119 |

**Stack Effect:**

```
Before: <32-byte-hash>
After:  <32-byte-hash>  (NOP-upgrade semantics: stack is NOT popped)
```

**Description:**

OP_CHECKTEMPLATEVERIFY verifies that the spending transaction matches a pre-committed template hash. The hash is computed using single-SHA256 over the following fields in order:

1. `nVersion` (4 bytes LE)
2. `nLockTime` (4 bytes LE)
3. Hash of all scriptSigs (single SHA256, only if any scriptSig is non-empty)
4. Number of inputs (4 bytes LE)
5. Hash of all input sequences (single SHA256)
6. Number of outputs (4 bytes LE)
7. Hash of all serialized outputs (single SHA256)
8. Input index being evaluated (4 bytes LE)

**Behavior:**

- If the flag is not set, behaves as `OP_NOP4`. Under `DISCOURAGE_UPGRADABLE_NOPS`, rejected by policy.
- If the top stack element is not exactly 32 bytes, behaves as NOP (future upgrade path). Under `DISCOURAGE_UPGRADABLE_NOPS`, rejected by policy.
- If the hash matches, execution continues. If it does not match, the script fails.
- Uses `PrecomputedTransactionData` CTV cache (`ctvHashSequences`, `ctvHashOutputs`, `ctvHashScriptSigs`) for O(1) per-input evaluation, preventing quadratic hashing.

**Use Cases:**

- Congestion control (batched payouts committed in advance)
- Vaults (time-locked withdrawal paths)
- Non-interactive payment channels
- Trustless escrow with deterministic spending paths

---

### 1.2 OP_CHECKSIGFROMSTACK (CSFS)

| Property | Value |
|---|---|
| **Byte Value** | `0xb4` (replaces `OP_NOP5`) |
| **Activation Flag** | `SCRIPT_VERIFY_CHECKSIGFROMSTACK` (bit 19) |
| **Consensus Parameter** | `nCSFSEnabled` |
| **Error Code** | `SCRIPT_ERR_CHECKSIGFROMSTACK` |

**Stack Effect:**

```
Before: <sig> <msg> <pubkey>
After:  <true|false>
```

**Description:**

OP_CHECKSIGFROMSTACK verifies a signature against an arbitrary message (not the transaction sighash). The message is hashed with single-SHA256 before verification. Both ECDSA (secp256k1) and post-quantum (ML-DSA-44) public keys are supported.

**Behavior:**

- If the flag is not set, behaves as `OP_NOP5`. Under `DISCOURAGE_UPGRADABLE_NOPS`, rejected by policy.
- Requires 3 stack elements: signature, message, and public key.
- Signature and public key encoding rules follow the same validation as `OP_CHECKSIG` (DER encoding for ECDSA, size checks for ML-DSA-44).
- The trailing hashtype byte in the signature is stripped before verification (same convention as `OP_CHECKSIG`).
- Under `SCRIPT_VERIFY_NULLFAIL`, a non-empty failing signature causes script failure.
- Pushes `OP_TRUE` or `OP_FALSE` onto the stack.

**Use Cases:**

- Oracle-signed data verification on-chain
- Delegation of signing authority
- Cross-chain proof verification
- Arbitrary message attestation in scripts

---

## 2. Transaction Introspection Opcodes

These opcodes allow scripts to inspect properties of the spending transaction itself, enabling covenants and smart-contract-like behavior.

---

### 2.1 OP_TXHASH

| Property | Value |
|---|---|
| **Byte Value** | `0xb5` (replaces `OP_NOP6`) |
| **Activation Flag** | `SCRIPT_VERIFY_TXHASH` (bit 20) |
| **Consensus Parameter** | `nTXHASHEnabled` |
| **Error Code** | `SCRIPT_ERR_TXHASH` |

**Stack Effect:**

```
Before: <1-byte field_selector>
After:  <32-byte hash>
```

**Description:**

OP_TXHASH computes a double-SHA256 hash over a configurable subset of the spending transaction's fields. The field selector is a single byte where each bit selects a field:

| Bit | Mask | Field |
|-----|------|-------|
| 0 | `0x01` | `nVersion` (4 bytes LE) |
| 1 | `0x02` | `nLockTime` (4 bytes LE) |
| 2 | `0x04` | Double-SHA256 of all input prevouts |
| 3 | `0x08` | Double-SHA256 of all input sequences |
| 4 | `0x10` | Double-SHA256 of all serialized outputs |
| 5 | `0x20` | Serialized prevout of current input |
| 6 | `0x40` | Sequence number of current input |
| 7 | `0x80` | Index of current input (uint32 LE) |

**Behavior:**

- If the flag is not set, behaves as `OP_NOP6`.
- The selector must be exactly 1 byte; otherwise, the script fails.
- Selector `0x00` is invalid (fails).
- Selected fields are concatenated in bit order and hashed with double-SHA256 (CHash256).
- Reuses `PrecomputedTransactionData` BIP143 cache for prevouts/sequences/outputs sub-hashes (O(1) vs O(n)).

**Use Cases:**

- Flexible covenant construction (commit to specific transaction fields)
- Partial sighash emulation in script
- Custom transaction commitment schemes

---

### 2.2 OP_TXFIELD

| Property | Value |
|---|---|
| **Byte Value** | `0xb6` (replaces `OP_NOP7`) |
| **Activation Flag** | `SCRIPT_VERIFY_TXFIELD` (bit 21) |
| **Consensus Parameter** | `nTXFIELDEnabled` |
| **Error Code** | `SCRIPT_ERR_TXFIELD` |

**Stack Effect:**

```
Before: <1-byte selector>
After:  <raw field bytes>
```

**Description:**

Unlike OP_TXHASH (which returns a hash), OP_TXFIELD returns raw bytes of a single field from the UTXO being spent. It requires the signature checker to have access to the spent scriptPubKey.

| Selector | Field | Size |
|----------|-------|------|
| `0x01` | `nValue` of the spent UTXO | 8 bytes (int64 LE) |
| `0x02` | 32-byte AuthScript commitment from the spent scriptPubKey | 32 bytes |
| `0x03` | Full `scriptPubKey` of the spent UTXO | Variable (max 520 bytes) |

**Behavior:**

- If the flag is not set, behaves as `OP_NOP7`.
- Selector must be exactly 1 byte.
- Selector `0x02` requires the spent scriptPubKey to start with `OP_1 0x20 <32 bytes>` (witness v1 format).
- Selector `0x03` fails if the scriptPubKey exceeds `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes).

**Use Cases:**

- Recursive DEX covenants (read own commitment to rebuild spending conditions)
- Self-referencing scripts that verify their own value or script
- AuthScript commitment introspection

---

### 2.3 OP_TXLOCKTIME

| Property | Value |
|---|---|
| **Byte Value** | `0xc5` |
| **Activation Flag** | `SCRIPT_VERIFY_TXLOCKTIME` (bit 25) |
| **Consensus Parameter** | `nTXLOCKTIMEEnabled` |
| **Error Code** | `SCRIPT_ERR_TXLOCKTIME` |

**Stack Effect:**

```
Before: (empty)
After:  <4-byte nLockTime>
```

**Description:**

OP_TXLOCKTIME pushes the transaction's `nLockTime` field onto the stack as raw 4-byte little-endian data. Unlike `OP_CHECKLOCKTIMEVERIFY` (which compares against a threshold), this opcode provides the raw value for arbitrary arithmetic and comparison in script.

**Use Cases:**

- Time-dependent logic in covenants
- Comparison-based branching on lock time values
- Combining with arithmetic opcodes for expiry calculations

---

### 2.4 OP_OUTPUTVALUE

| Property | Value |
|---|---|
| **Byte Value** | `0xcc` |
| **Activation Flag** | `SCRIPT_VERIFY_OUTPUTVALUE` (bit 24) |
| **Consensus Parameter** | `nOUTPUTVALUEEnabled` |
| **Error Code** | `SCRIPT_ERR_OUTPUTVALUE` |

**Stack Effect:**

```
Before: <output_index>
After:  <amount>
```

**Description:**

OP_OUTPUTVALUE reads the satoshi amount of the specified output in the spending transaction. The output index is consumed from the stack as a `CScriptNum`.

**Behavior:**

- The output index must be non-negative and within the transaction's output range.
- Returns the amount as raw 8-byte little-endian int64.
- When `SCRIPT_VERIFY_64BIT_INTEGERS` is active, the 8-byte value is converted to a `CScriptNum` encoding for compatibility with arithmetic opcodes.

**Use Cases:**

- Enforce minimum/maximum output amounts in covenants
- Verify fee calculations in script
- DEX price enforcement

---

### 2.5 OP_OUTPUTSCRIPT

| Property | Value |
|---|---|
| **Byte Value** | `0xcd` |
| **Activation Flag** | `SCRIPT_VERIFY_OUTPUTSCRIPT` (bit 26) |
| **Consensus Parameter** | `nOUTPUTSCRIPTEnabled` |
| **Error Code** | `SCRIPT_ERR_OUTPUTSCRIPT` |

**Stack Effect:**

```
Before: <output_index>
After:  <scriptPubKey bytes>
```

**Description:**

OP_OUTPUTSCRIPT pushes the raw `scriptPubKey` of the specified output onto the stack.

**Behavior:**

- The output index must be non-negative and within range.
- The resulting scriptPubKey must not exceed `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes); otherwise, the script fails.

**Use Cases:**

- Recursive covenants (verify an output pays to the same script)
- Enforce specific destination addresses
- Combine with OP_CAT to construct and verify output scripts

---

### 2.6 OP_INPUTCOUNT

| Property | Value |
|---|---|
| **Byte Value** | `0xd0` |
| **Activation Flag** | `SCRIPT_VERIFY_INPUTOUTPUTCOUNT` (bit 30) |
| **Consensus Parameter** | `nINPUTOUTPUTCOUNTEnabled` |
| **Error Code** | `SCRIPT_ERR_INPUTOUTPUTCOUNT` |

**Stack Effect:**

```
Before: (empty)
After:  <input count as CScriptNum>
```

**Description:**

OP_INPUTCOUNT pushes the number of inputs in the spending transaction onto the stack as a `CScriptNum`.

**Use Cases:**

- Enforce transaction structure (e.g., "exactly 2 inputs required")
- Loop bounds for introspection patterns
- Anti-fee-sniping constraints

---

### 2.7 OP_OUTPUTCOUNT

| Property | Value |
|---|---|
| **Byte Value** | `0xd1` |
| **Activation Flag** | `SCRIPT_VERIFY_INPUTOUTPUTCOUNT` (bit 30) |
| **Consensus Parameter** | `nINPUTOUTPUTCOUNTEnabled` |
| **Error Code** | `SCRIPT_ERR_INPUTOUTPUTCOUNT` |

**Stack Effect:**

```
Before: (empty)
After:  <output count as CScriptNum>
```

**Description:**

OP_OUTPUTCOUNT pushes the number of outputs in the spending transaction onto the stack as a `CScriptNum`. Shares the same activation flag and consensus parameter as OP_INPUTCOUNT.

**Use Cases:**

- Enforce transaction structure (e.g., "exactly 3 outputs required")
- Covenant constraints on output topology
- Combine with OP_OUTPUTVALUE/OP_OUTPUTSCRIPT for full output enumeration

---

## 3. Asset Introspection Opcodes

These opcodes are unique to Neurai's asset layer and allow scripts to read asset metadata from transaction inputs and outputs. They enable on-chain smart contracts that reason about asset transfers, issuances, and reissuances.

---

### 3.1 OP_OUTPUTASSETFIELD

| Property | Value |
|---|---|
| **Byte Value** | `0xce` |
| **Activation Flag** | `SCRIPT_VERIFY_OUTPUTASSETFIELD` (bit 27) |
| **Consensus Parameter** | `nOUTPUTASSETFIELDEnabled` |
| **Error Code** | `SCRIPT_ERR_OUTPUTASSETFIELD` |

**Stack Effect:**

```
Before: <output_index> <1-byte selector>
After:  <field value>
```

**Description:**

OP_OUTPUTASSETFIELD extracts a specific field from the asset payload attached to a transaction output. The output is identified by index and the field by a selector byte.

**Field Selectors:**

| Selector | Field | Applies To | Return Type |
|----------|-------|------------|-------------|
| `0x01` | Asset name | Transfer, New, Reissue, Owner | String bytes |
| `0x02` | Amount | Transfer, New, Reissue, Owner | 8-byte int64 LE |
| `0x03` | Units (decimal places) | New, Reissue | 1 byte |
| `0x04` | Reissuable flag | New, Reissue | 1 byte (0 or 1) |
| `0x05` | Has IPFS flag | New | 1 byte (0 or 1) |
| `0x06` | IPFS hash | New (if hasIPFS), Reissue (if set) | Variable bytes |
| `0x07` | Asset type | All | 1 byte (enum) |

**Behavior:**

- Selector `0x00` and `>= 0x08` are invalid.
- If the output does not contain an asset payload, the script fails.
- When `SCRIPT_VERIFY_64BIT_INTEGERS` is active and selector is `0x02` (amount), the raw 8-byte value is converted to `CScriptNum` encoding.
- Recognizes all asset operation types: Transfer, New (including MsgChannel, Qualifier, Restricted), Reissue, and Owner.

**Use Cases:**

- DEX covenants that verify correct asset amounts in outputs
- Enforce asset transfer rules in script
- Verify asset metadata (units, reissuability) during reissuance

---

### 3.2 OP_INPUTASSETFIELD

| Property | Value |
|---|---|
| **Byte Value** | `0xcf` |
| **Activation Flag** | `SCRIPT_VERIFY_INPUTASSETFIELD` (bit 29) |
| **Consensus Parameter** | `nINPUTASSETFIELDEnabled` |
| **Error Code** | `SCRIPT_ERR_INPUTASSETFIELD` |

**Stack Effect:**

```
Before: <input_index> <1-byte selector>
After:  <field value>
```

**Description:**

OP_INPUTASSETFIELD is the input-side counterpart to OP_OUTPUTASSETFIELD. It reads asset fields from the prevout (previous output) referenced by a specified input. It uses the same selector table as OP_OUTPUTASSETFIELD.

**Behavior:**

- Requires access to all prevout `CTxOut` objects via the `m_allPrevouts` vector in the signature checker.
- The input index must be within range of both `txTo->vin` and `m_allPrevouts`.
- Same selector validation and asset-type detection as OP_OUTPUTASSETFIELD.
- Same 64-bit integer conversion for selector `0x02`.

**Use Cases:**

- Verify that input asset amounts match output asset amounts (conservation rules)
- Cross-input asset type validation
- Atomic swap scripts that verify asset properties on both sides

---

## 4. Reference Input Introspection Opcodes

These opcodes allow scripts to read fields from **reference inputs** — UTXOs declared in the transaction's `vrefin` vector that are inspected but **not spent**. Reference inputs are the foundation for oracle-fed covenants, cross-UTXO order matching, DePIN state feeds, and any pattern where a script needs to read external state without consuming it.

All three opcodes are gated by `SCRIPT_VERIFY_REFINPUTS` (bit 31, consensus parameter `nREFINPUTSEnabled`). When the flag is not active they behave as NOPs, with `DISCOURAGE_UPGRADABLE_NOPS` support.

Reference inputs are transported in a dedicated `vrefin` vector alongside `vin` and `vout` in the transaction serialization. Unlike regular inputs, they do not require signatures and do not consume the referenced UTXOs; their sole purpose is to make external state available for introspection during script evaluation. The `OP_REFINPUT*` family provides the primitives to read values, commitments, scripts, and asset fields from those referenced outputs.

---

### 4.1 OP_REFINPUTCOUNT

| Property | Value |
|---|---|
| **Byte Value** | `0xd4` |
| **Activation Flag** | `SCRIPT_VERIFY_REFINPUTS` (bit 31) |
| **Consensus Parameter** | `nREFINPUTSEnabled` |
| **Error Code** | `SCRIPT_ERR_REFINPUTCOUNT` |

**Stack Effect:**

```
Before: (empty)
After:  <ref count as CScriptNum>
```

**Description:**

OP_REFINPUTCOUNT pushes the number of reference inputs declared in `vrefin` for the spending transaction as a `CScriptNum`.

**Behavior:**

- If the flag is not set, behaves as a NOP.
- If reference outputs are unavailable to the signature checker (e.g., the transaction was not validated with `vrefin` resolution), the script fails.
- Returns `0` when the transaction has no reference inputs.

**Use Cases:**

- Gate script branches on the presence of reference inputs (e.g., "oracle data required").
- Loop bounds for scripts that iterate over multiple reference inputs.
- Distinguish between covenant variants that consult external state and those that do not.

---

### 4.2 OP_REFINPUTFIELD

| Property | Value |
|---|---|
| **Byte Value** | `0xd2` |
| **Activation Flag** | `SCRIPT_VERIFY_REFINPUTS` (bit 31) |
| **Consensus Parameter** | `nREFINPUTSEnabled` |
| **Error Code** | `SCRIPT_ERR_REFINPUTFIELD` |

**Stack Effect:**

```
Before: <ref_index> <1-byte selector>
After:  <raw field bytes>
```

**Description:**

OP_REFINPUTFIELD reads a field from the resolved output referenced by entry `ref_index` of `vrefin`. Selectors are aligned with `OP_TXFIELD` so that introspection of reference inputs and of the spent input use the same vocabulary.

| Selector | Field | Size |
|----------|-------|------|
| `0x01` | `nValue` of the referenced output | 8 bytes (int64 LE) |
| `0x02` | 32-byte AuthScript commitment from the referenced `scriptPubKey` | 32 bytes |
| `0x03` | Full `scriptPubKey` of the referenced output | Variable (max 520 bytes) |

**Behavior:**

- If the flag is not set, behaves as a NOP.
- The selector must be exactly 1 byte; selector `0x00` and `>= 0x04` are invalid.
- `ref_index` must be non-negative and within the range of `vrefin`.
- Selector `0x02` requires the referenced `scriptPubKey` to start with `OP_1 0x20 <32 bytes>` (witness v1 format); otherwise the script fails.
- Selector `0x03` fails if the referenced `scriptPubKey` exceeds `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes).
- When `SCRIPT_VERIFY_64BIT_INTEGERS` is active and selector is `0x01`, the raw 8-byte value is converted to `CScriptNum` encoding for direct use with arithmetic opcodes.

**Use Cases:**

- Oracle-fed covenants (read an oracle UTXO's commitment without spending it).
- Cross-UTXO order matching (read an external order's price and state).
- DePIN contracts that verify a device-state UTXO before releasing payment.
- Shared-state references (e.g., a rate-limit UTXO consulted by many spenders).

---

### 4.3 OP_REFINPUTASSETFIELD

| Property | Value |
|---|---|
| **Byte Value** | `0xd3` |
| **Activation Flag** | `SCRIPT_VERIFY_REFINPUTS` (bit 31) |
| **Consensus Parameter** | `nREFINPUTSEnabled` |
| **Error Code** | `SCRIPT_ERR_REFINPUTASSETFIELD` |

**Stack Effect:**

```
Before: <ref_index> <1-byte selector>
After:  <field value>
```

**Description:**

OP_REFINPUTASSETFIELD extracts a field from the asset payload of the output referenced by entry `ref_index` of `vrefin`. Selectors match `OP_OUTPUTASSETFIELD` / `OP_INPUTASSETFIELD` exactly, and the opcode recognizes all seven asset operation types: Transfer, New, MsgChannel, Qualifier, Restricted, Reissue, and Owner.

| Selector | Field | Applies To | Return Type |
|----------|-------|------------|-------------|
| `0x01` | Asset name | Transfer, New, Reissue, Owner | String bytes |
| `0x02` | Amount | Transfer, New, Reissue, Owner | 8-byte int64 LE |
| `0x03` | Units (decimal places) | New, Reissue | 1 byte |
| `0x04` | Reissuable flag | New, Reissue | 1 byte (0 or 1) |
| `0x05` | Has IPFS flag | New | 1 byte (0 or 1) |
| `0x06` | IPFS hash | New (if hasIPFS), Reissue (if set) | Variable bytes |
| `0x07` | Asset type | All | 1 byte (enum) |

**Behavior:**

- If the flag is not set, behaves as a NOP.
- The selector must be exactly 1 byte; selector `0x00` and `>= 0x08` are invalid.
- `ref_index` must be non-negative and within the range of `vrefin`.
- If the referenced output does not contain an asset payload recognized by any of the seven parsers, the script fails.
- When `SCRIPT_VERIFY_64BIT_INTEGERS` is active and selector is `0x02` (amount), the raw 8-byte value is converted to `CScriptNum` encoding.

**Use Cases:**

- Oracle assets (e.g., a price-feed asset whose quantity encodes the price).
- Reading the state of an external order UTXO (token id, remaining quantity) for matching.
- LP/vault contracts that check the composition of a reserve UTXO before accepting a trade.
- Conservation checks across reference and output assets in complex swap topologies.

---

## 5. Byte Manipulation Opcodes

These opcodes provide low-level byte-string operations that are essential building blocks for constructing and deconstructing data on the stack.

---

### 5.1 OP_CAT

| Property | Value |
|---|---|
| **Byte Value** | `0x7e` (original Bitcoin opcode, re-enabled) |
| **Activation Flag** | `SCRIPT_VERIFY_CAT` (bit 17) |
| **Consensus Parameter** | `nCATEnabled` |
| **BIP Reference** | BIP 347 |

**Stack Effect:**

```
Before: <x1> <x2>
After:  <x1+x2>
```

**Description:**

OP_CAT concatenates the top two stack elements. This opcode was disabled in Bitcoin in 2010 and is re-enabled here with a safety bound.

**Behavior:**

- Requires at least 2 stack elements.
- The combined size must not exceed `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes); otherwise, fails with `SCRIPT_ERR_PUSH_SIZE`.
- `vch2` is appended to `vch1` in-place, then `vch2` is removed from the stack.
- When the `SCRIPT_VERIFY_CAT` flag is not set, OP_CAT returns `SCRIPT_ERR_DISABLED_OPCODE` (original behavior).

**Use Cases:**

- Build complex data structures on the stack
- Construct scriptPubKeys for covenant verification
- Merkle proof verification
- Combine with OP_SPLIT for substring operations

---

### 5.2 OP_SPLIT

| Property | Value |
|---|---|
| **Byte Value** | `0xb7` (replaces `OP_NOP8`) |
| **Activation Flag** | `SCRIPT_VERIFY_SPLIT` (bit 22) |
| **Consensus Parameter** | `nSPLITEnabled` |
| **Error Code** | `SCRIPT_ERR_SPLIT` |

**Stack Effect:**

```
Before: <data> <n>
After:  <data[0..n-1]> <data[n..]>
```

**Description:**

OP_SPLIT is the inverse of OP_CAT. It splits a byte array into two parts at position `n`.

**Behavior:**

- If the flag is not set, behaves as `OP_NOP8`.
- `n` is read as a `CScriptNum` and must satisfy `0 <= n <= len(data)`.
- If `n` is negative or greater than the data length, the script fails.
- The original element is replaced with two new elements: `data[0..n-1]` (left) and `data[n..]` (right).

**Use Cases:**

- Extract fixed-width fields from serialized data
- Parse structured byte strings
- Substring extraction when combined with OP_CAT

---

### 5.3 OP_REVERSEBYTES

| Property | Value |
|---|---|
| **Byte Value** | `0xbc` |
| **Activation Flag** | `SCRIPT_VERIFY_REVERSEBYTES` (bit 23) |
| **Consensus Parameter** | `nREVERSEBYTESEnabled` |

**Stack Effect:**

```
Before: <data>
After:  <reversed data>
```

**Description:**

OP_REVERSEBYTES reverses the byte order of the top stack element in place.

**Behavior:**

- Requires at least 1 stack element.
- The reversal is done in-place on the stack (no new allocation needed).
- Works on any length, including empty byte strings.

**Use Cases:**

- Endianness conversion (little-endian to big-endian and vice versa)
- Hash byte-order normalization (e.g., converting txid display order)
- Data format interoperability

---

## 6. 64-Bit Arithmetic (Re-enabled Opcodes)

The `SCRIPT_VERIFY_64BIT_INTEGERS` flag (bit 28, consensus parameter `n64BitIntegersEnabled`) widens the numeric domain of `CScriptNum` from 4 bytes to 8 bytes. This affects both the re-enabled opcodes below and all existing arithmetic opcodes (`OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB`, `OP_NEGATE`, `OP_ABS`, `OP_NOT`, `OP_0NOTEQUAL`, `OP_WITHIN`, comparison operators).

All 64-bit arithmetic operations use overflow-safe implementations that reject results at `INT64_MIN` (−9,223,372,036,854,775,808) to maintain the sign-magnitude invariant of `CScriptNum`.

---

### 6.1 OP_MUL

| Property | Value |
|---|---|
| **Byte Value** | `0x95` (original Bitcoin opcode, re-enabled) |
| **Activation Flag** | `SCRIPT_VERIFY_64BIT_INTEGERS` (bit 28) |
| **Consensus Parameter** | `n64BitIntegersEnabled` |
| **Error Code** | `SCRIPT_ERR_MUL_OVERFLOW` |

**Stack Effect:**

```
Before: <a> <b>
After:  <a * b>
```

**Description:**

OP_MUL multiplies the top two stack elements as 64-bit signed integers. Originally disabled in Bitcoin, it is re-enabled only when the 64-bit integers flag is set.

**Behavior:**

- When `SCRIPT_VERIFY_64BIT_INTEGERS` is not set, returns `SCRIPT_ERR_DISABLED_OPCODE`.
- Both operands are decoded as `CScriptNum` with 8-byte maximum.
- Uses compiler built-ins (`__builtin_mul_overflow`) or manual bounds checking to detect overflow.
- Fails if the result overflows `int64_t` range or equals `INT64_MIN`.

---

### 6.2 OP_DIV

| Property | Value |
|---|---|
| **Byte Value** | `0x96` (original Bitcoin opcode, re-enabled) |
| **Activation Flag** | `SCRIPT_VERIFY_64BIT_INTEGERS` (bit 28) |
| **Consensus Parameter** | `n64BitIntegersEnabled` |
| **Error Codes** | `SCRIPT_ERR_DIV_BY_ZERO`, `SCRIPT_ERR_DIV_OVERFLOW` |

**Stack Effect:**

```
Before: <a> <b>
After:  <a / b>
```

**Description:**

OP_DIV performs integer division of `a` by `b`. Re-enabled only with 64-bit integers.

**Behavior:**

- Fails with `SCRIPT_ERR_DIV_BY_ZERO` if `b == 0`.
- Fails with `SCRIPT_ERR_DIV_OVERFLOW` if `a == INT64_MIN` and `b == -1` (two's complement overflow).
- Fails if the result equals `INT64_MIN`.
- Uses truncation toward zero (C99/C++11 semantics).

---

### 6.3 OP_MOD

| Property | Value |
|---|---|
| **Byte Value** | `0x97` (original Bitcoin opcode, re-enabled) |
| **Activation Flag** | `SCRIPT_VERIFY_64BIT_INTEGERS` (bit 28) |
| **Consensus Parameter** | `n64BitIntegersEnabled` |
| **Error Codes** | `SCRIPT_ERR_MOD_BY_ZERO`, `SCRIPT_ERR_MOD_OVERFLOW` |

**Stack Effect:**

```
Before: <a> <b>
After:  <a % b>
```

**Description:**

OP_MOD computes the remainder of `a` divided by `b`. Re-enabled only with 64-bit integers.

**Behavior:**

- Fails with `SCRIPT_ERR_MOD_BY_ZERO` if `b == 0`.
- Fails with `SCRIPT_ERR_MOD_OVERFLOW` if `a == INT64_MIN` and `b == -1`.
- Fails if the result equals `INT64_MIN`.

---

### 6.4 64-Bit Overflow-Safe Arithmetic on Existing Opcodes

When `SCRIPT_VERIFY_64BIT_INTEGERS` is active, the following existing opcodes are upgraded to operate on 8-byte `CScriptNum` values with overflow protection:

| Opcode | New Error Code |
|--------|---------------|
| `OP_ADD` | `SCRIPT_ERR_ADD_OVERFLOW` |
| `OP_SUB` | `SCRIPT_ERR_SUB_OVERFLOW` |
| `OP_1ADD` | `SCRIPT_ERR_ADD_OVERFLOW` |
| `OP_1SUB` | `SCRIPT_ERR_SUB_OVERFLOW` |
| `OP_NEGATE` | `SCRIPT_ERR_NEGATE_OVERFLOW` |
| `OP_ABS` | `SCRIPT_ERR_NEGATE_OVERFLOW` |

The unary opcodes `OP_NOT` and `OP_0NOTEQUAL` also operate on 64-bit values but cannot overflow. Comparison and conditional opcodes (`OP_NUMEQUAL`, `OP_LESSTHAN`, `OP_WITHIN`, etc.) accept 8-byte inputs.

---

## Summary Table

| Opcode | Byte | Replaces | Flag Bit | Group |
|--------|------|----------|----------|-------|
| `OP_CHECKTEMPLATEVERIFY` | `0xb3` | `OP_NOP4` | 18 | Covenant |
| `OP_CHECKSIGFROMSTACK` | `0xb4` | `OP_NOP5` | 19 | Covenant |
| `OP_TXHASH` | `0xb5` | `OP_NOP6` | 20 | TX Introspection |
| `OP_TXFIELD` | `0xb6` | `OP_NOP7` | 21 | TX Introspection |
| `OP_TXLOCKTIME` | `0xc5` | — | 25 | TX Introspection |
| `OP_OUTPUTVALUE` | `0xcc` | — | 24 | TX Introspection |
| `OP_OUTPUTSCRIPT` | `0xcd` | — | 26 | TX Introspection |
| `OP_INPUTCOUNT` | `0xd0` | — | 30 | TX Introspection |
| `OP_OUTPUTCOUNT` | `0xd1` | — | 30 | TX Introspection |
| `OP_OUTPUTASSETFIELD` | `0xce` | — | 27 | Asset Introspection |
| `OP_INPUTASSETFIELD` | `0xcf` | — | 29 | Asset Introspection |
| `OP_REFINPUTFIELD` | `0xd2` | — | 31 | Reference Input Introspection |
| `OP_REFINPUTASSETFIELD` | `0xd3` | — | 31 | Reference Input Introspection |
| `OP_REFINPUTCOUNT` | `0xd4` | — | 31 | Reference Input Introspection |
| `OP_CAT` | `0x7e` | (re-enabled) | 17 | Byte Manipulation |
| `OP_SPLIT` | `0xb7` | `OP_NOP8` | 22 | Byte Manipulation |
| `OP_REVERSEBYTES` | `0xbc` | — | 23 | Byte Manipulation |
| `OP_MUL` | `0x95` | (re-enabled) | 28 | 64-Bit Arithmetic |
| `OP_DIV` | `0x96` | (re-enabled) | 28 | 64-Bit Arithmetic |
| `OP_MOD` | `0x97` | (re-enabled) | 28 | 64-Bit Arithmetic |

---

## Activation Status

All opcodes listed above are controlled by individual consensus parameters in `Consensus::Params`. As of this branch:

- **Testnet / Regtest**: All opcodes are **enabled** (`true`).
- **Mainnet**: All opcodes are **disabled** (`false`) pending future activation via consensus upgrade.

Each opcode degrades gracefully when its flag is not set — NOP-replacing opcodes behave as their original NOP, while re-enabled opcodes return `SCRIPT_ERR_DISABLED_OPCODE`.
