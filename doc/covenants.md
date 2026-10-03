# Covenants on Neurai

## Overview

Neurai integrates a full covenant system into its Script engine, enabling spending conditions that go far beyond traditional signature-based authorization. A **covenant** is a script that constrains *how* funds (or assets) may be spent — not just *who* can spend them. This allows the creation of self-enforcing smart contracts directly at the consensus layer, without relying on external virtual machines or trusted third parties.

The covenant system is built on a set of cooperating opcodes. The table below
lists them by category; [New OP_Codes Reference](new-opcodes-depin-branch.md)
gives the byte values, flags and error codes of the original set.

| Category | Opcodes |
|----------|---------|
| Covenant primitives | `OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK`, `OP_TXHASH` |
| Spent input introspection | `OP_TXFIELD`, `OP_INPUTFIELD`, `OP_INPUTVALUE`, `OP_INPUTCOUNT` |
| Output introspection | `OP_OUTPUTVALUE`, `OP_OUTPUTSCRIPT`, `OP_OUTPUTAUTHCOMMITMENT`, `OP_OUTPUTAUTHDEST`, `OP_OUTPUTCOUNT` |
| Transaction and chain context | `OP_TXLOCKTIME`, `OP_CHAINCONTEXT` |
| Reference inputs (tx v3, NIP-014) | `OP_REFINPUTCOUNT`, `OP_REFINPUTFIELD`, `OP_REFINPUTASSETFIELD` |
| Asset introspection | `OP_OUTPUTASSETFIELD`, `OP_INPUTASSETFIELD`, `OP_REFINPUTASSETFIELD` |
| Byte manipulation | `OP_CAT`, `OP_SPLIT`, `OP_REVERSEBYTES` |
| 64-bit arithmetic | `OP_MUL`, `OP_DIV`, `OP_MOD` (plus the existing numeric opcodes widened to 8 bytes) |
| Hashes | `OP_KECCAK256`, `OP_BLAKE2B`, `OP_BLAKE3`, `OP_SHA3_256`, `OP_SHA512`, `OP_POSEIDON` |
| Additional signatures | `OP_CHECKSIGADD`, `OP_CHECKSIG_ED25519` |
| Proof verification | `OP_CHECKMERKLEINCLUSION`, `OP_ZKVERIFY` |

Each opcode is gated by its own consensus flag, not by the script version.
Once active, they also evaluate in Legacy, P2SH and witness v0 scripts; only
`OP_ZKVERIFY` is restricted to AuthScript. **AuthScript** (witness version 1)
is the intended environment: it extends SegWit with post-quantum signature
support, a tagged commitment scheme and larger execution budgets (NIP-046).

---

## AuthScript: The Covenant Execution Environment

Covenants are designed to run inside AuthScript programs. An AuthScript output has the form:

```
OP_1 <32-byte commitment>
```

The program may also be wrapped in P2SH, and an asset-carrying output appends
the asset suffix (`OP_1 <32 bytes> OP_XNA_ASSET <payload> OP_DROP`). The
32-byte commitment is computed as:

```
TaggedHash("NeuraiAuthScript", 0x01 || authType || [HASH160(pubkey)] || SHA256(witnessScript))
TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)
```

The leading `0x01` is the commitment version of generic witness v1 (the strict
families use `0x02`/`0x03`, and NIP-044 script trees use `0x04`). The 20-byte
key hash is present only for authType `0x01` and `0x02`.

There are three authentication types for a single script (NIP-044 adds
`0x10`–`0x12` for script trees, see below):

| AuthType | Byte | Description |
|----------|------|-------------|
| Script-only | `0x00` | No key authorization. The witness script alone determines spending conditions. Ideal for pure covenants. |
| Post-quantum | `0x01` | Requires an ML-DSA-44 signature from the public key whose hash is committed, then evaluates the witness script. |
| Classical | `0x02` | Requires an ECDSA/secp256k1 signature from the public key whose hash is committed, then evaluates the witness script. Standard policy requires a compressed key. |

The witness stack for spending is structured as:

```
<authType> [<signature> <pubkey>] <arg1> <arg2> ... <witnessScript>
```

The witness script starts with only `<arg1> ... <argN>` on its stack (`argN`
on top), and must finish with exactly one true element. The envelope signature
is checked before the script runs; it uses the AuthScript sighash
(`SIGVERSION_AUTHSCRIPT`, BIP143-style, with the authType committed and, for v3
transactions, the reference inputs). Signatures checked inside the script
(`OP_CHECKSIG`, `OP_CHECKMULTISIG`, `OP_CHECKSIGADD`) commit authType `0x00`,
which keeps them in a separate domain from the envelope signature.

This design separates authentication (who) from authorization logic (what and how), allowing covenants to be written as pure script logic while optionally requiring key-holder approval.

### AuthScript contract address encoding

Generic witness v1 uses Bech32m HRP `nc` on mainnet and `tnc` on
testnet/regtest: `nc1p…` / `tnc1p…`. The former `nq1p…` / `tnq1p…`
representations are rejected; no legacy-prefix alias or address migration is
provided. This changes address encoding only, not commitments or consensus.
Strict PQ v2 keeps `pq1z…` / `tpq1z…`; strict ECDSA v3 keeps
`nq1r…` / `tnq1r…`.

The wallet address type is chosen with `-addresstype=legacy|pq|ecdsa` when the
wallet file is created (default `legacy`) and stored in it; opening an existing
wallet with a different `-addresstype` is an init error, and without the option
the stored type is used (`getwalletinfo` reports it). In the GUI, the
first-run wallet dialog (create or restore from seed words) offers the three
types, preset to `-addresstype`; when restoring, the type must be the one the
wallet was created with, since each type derives its own keys. The type is what the
wallet hands out by default, in Qt and over RPC (`getnewaddress`,
`getaccountaddress`, `getrawchangeaddress`, change outputs, the asset RPCs and
mining):

| `-addresstype` | Default | Also on request |
|---|---|---|
| `legacy` | Legacy (Base58) | strict v3 (`"ecdsa"`) |
| `pq` | strict v2 | strict v3 (`"ecdsa"`) |
| `ecdsa` | strict v3 | none: it never hands out Legacy |

`pq` and `ecdsa` require `-bip44=1` (their keys derive from the mnemonic seed:
`m_pq` and `m/84'` branches). Their addresses are handed out at any time, even
with no network or no scheduled activation, but nothing pays to them until
AuthScript and the strict families apply to the next block: before that, a
strict address does not decode for paying (sends to it are refused), policy
rejects outputs to it, and the wallet refuses change to its family, mining to
it and asset operations that would create such an output. There is no Legacy
fallback. `-pqwallet` was replaced by `-addresstype=pq` and is refused at startup.
Generic v1 is a contract family: contracts are built and signed by
contract tooling, and the wallet never manages v1. It does not hand out v1
addresses, does not count v1 outputs as its own (whatever spend data an older
wallet file holds), does not sign messages for them and does not store v1
spend data. Old testnet address-book strings and external integrations must be
updated; this is intentionally incompatible.

### Reset testnet activation schedule

The reset testnet runs blocks 1-9 with the rules that predate the new NIPs,
and **block 10** is the first block that applies all of them:

- the opt-in switches (`nOptInFeaturesHeight`): AuthScript v1, the introspection
  and hash opcodes, 64-bit arithmetic, OP_CAT/OP_SPLIT/CTV, tx v3 with `vrefin`
  (NIP-014) and the strict OP_XNA_ASSET placement rule;
- strict AuthScript families and NIP-041 (`nStrictAuthScriptHeight`);
- CSFS, Ed25519 and CHECKSIGADD (`nSignatureOpcodesHeight`);
- TXHASH (NIP-042), the NIP-043 primitives, NIP-044 script trees, NIP-046
  budgets, `OP_ZKVERIFY` with its public-tree profile, and the Poseidon work
  budget;
- the NIP-040 asset marker (`rvn` outputs before block 10, `xna` from block 10;
  legacy `rvn` UTXOs stay spendable) and the DEPIN transfer state;
- NIP-028: 30-second blocks, the subsidy halved (and its halving interval
  doubled to 28,800 blocks, ~10 days as before), a 120-block reorg cap (60
  minutes, as before), the block version flag `0x40000000` required on every
  block and peers below protocol 70029 dropped.

The reset testnet keeps the `RUEN` message start and port 19100. It announces
protocol 70030 and refuses peers below it from the first handshake, which keeps
nodes of the previous testnet (same message start, protocol 70029) out; its new
genesis keeps the chains apart. Regtest also announces 70030; mainnet keeps
70029 for now.

Assets, RIP5 and the asset VersionBits deployments are active from genesis as a
pure rule (`nAssetsActiveFromGenesis`), and the v1.0.6 consensus fixes apply
from genesis. Block validation uses
the height of the block; wallet and mempool admission use the next block's
height, so new-rule transactions are accepted with the tip at block 9.

Mainnet remains unscheduled. Regtest applies everything from height 0 by
default, except the NIP-040 marker and the DEPIN transfer state (height 1) and
NIP-028, which only `-blocktimereductionheight` schedules. The regtest-only
options `-optinfeaturesheight`, `-strictauthscriptheight`,
`-signatureopcodesheight` and the per-feature overrides (`-txhashheight`,
`-assetmessageheight`, `-inputfieldheight`, `-merkleposeidonheight`,
`-authscripttreeheight`, `-authscriptbudgetheight`, `-zkverifyheight`,
`-zkpublictreeheight`, `-poseidonworkheight`, `-nip040height`,
`-depinstateheight`) move the heights for activation tests.

### Strict AuthScript activation schedule

Strict PQ witness v2 (`tpq1z…`), strict ECDSA witness v3 (`tnq1r…`) and NIP-041
destination introspection activate at block 10 of the reset testnet (see
above). This height also enables the strict-flag rules described below for v1
mixed multisig. Earlier blocks retain their previous validation rules. Wallet
and mempool admission use the next block's height, so strict addresses become
available with the tip at block 9.

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
use a 2-of-2 threshold when both signatures are required. ML-DSA-44 keys
(1313 bytes) and signatures (2421 bytes) only fit under the 3072-byte element
cap, which CSFS, CHECKSIGADD, OP_CHECKMERKLEINCLUSION or OP_ZKVERIFY enable
(all active from block 10 of the reset testnet).

Before this height, signature encoding is checked against each candidate key,
preserving historical validation, including mixed-family failures. This is a
consensus change that enables previously rejected spends, and must be included
in the activation release. Mainnet remains unscheduled. The
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
- Like the NOP it replaces, the opcode leaves its argument on the stack; a final
  32-byte hash counts as true. An argument of any other size makes it a NOP,
  discouraged by standard policy.

**Example: Batched Payout**

An exchange can commit to paying 100 users in a single CTV output. When spent, the transaction must produce exactly those 100 outputs with the exact amounts. No signer can alter the destinations or amounts.

```
<template_hash> OP_CHECKTEMPLATEVERIFY
```

### OP_CHECKSIGFROMSTACK (CSFS) — Oracle Integration

CSFS verifies a signature against an arbitrary message (not the transaction hash). This enables scripts to act on externally signed data.

**Stack:** `<sig> <msg> <pubkey> → <true|false>`

The message is hashed with single-SHA256 before verification. Both ECDSA and ML-DSA-44 (post-quantum) public keys are supported. There is no `OP_CHECKSIGFROMSTACKVERIFY`; follow the opcode with `OP_VERIFY`.

**Example: Price Oracle**

A covenant that only releases funds if an oracle attests that the XNA/USD price exceeds a threshold:

```
// Witness arguments: <oracle_sig> <price>, where <price> is a script number
OP_DUP <threshold> OP_GREATERTHAN OP_VERIFY   // the attested price is high enough
<oracle_pubkey> OP_CHECKSIGFROMSTACK          // the oracle signed SHA256(<price>)
OP_VERIFY
// ... remaining spending conditions
```

As written, any earlier attestation above the threshold can be replayed. A
real oracle message also carries a timestamp, or is bound to the spending
transaction with `OP_TXHASH` (see below).

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

Activation uses `nTxHashHeight`: block **10 of the reset testnet**, block 0 of
regtest by default, and no scheduled mainnet height. `-txhashheight=<n>` is a
regtest-only override. `SCRIPT_VERIFY_TXHASH` governs selector and digest
together; the old format is removed. Before activation the opcode is NOP6 in
consensus and discouraged by standard policy. Mempool checks use the next
block's height and revalidate entries when a reorg crosses activation.

### Transaction Introspection Opcodes

These opcodes push transaction data onto the stack for comparison, arithmetic
and script construction. Indices are script numbers; selectors are single
bytes.

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_TXFIELD` | `<selector> → <field>` | Field of the spent UTXO: `01` value, `02` v1 commitment (32 bytes), `03` full scriptPubKey, `04` destination (NIP-041) |
| `OP_INPUTFIELD` | `<index> <selector> → <field>` | Same selectors for any spent input (NIP-043) |
| `OP_INPUTVALUE` | `<index> → <amount>` | Value of an input's prevout (NIP-024) |
| `OP_INPUTCOUNT` | `→ <count>` | Number of inputs |
| `OP_OUTPUTVALUE` | `<index> → <amount>` | Value of an output |
| `OP_OUTPUTSCRIPT` | `<index> → <scriptPubKey>` | Full scriptPubKey of an output, including any asset suffix |
| `OP_OUTPUTAUTHCOMMITMENT` | `<index> → <32 bytes>` | v1 commitment of an output (NIP-023) |
| `OP_OUTPUTAUTHDEST` | `<index> → <33 bytes>` | Destination of an output as `version \|\| program` (NIP-041) |
| `OP_OUTPUTCOUNT` | `→ <count>` | Number of outputs |
| `OP_TXLOCKTIME` | `→ <4 bytes>` | The transaction's nLockTime |
| `OP_CHAINCONTEXT` | `<selector> → <number>` | `01` height, `02` median time past, `03` chain id (NIP-026) |
| `OP_REFINPUTCOUNT` | `→ <count>` | Number of reference inputs (tx v3) |
| `OP_REFINPUTFIELD` | `<index> <selector> → <field>` | `OP_INPUTFIELD` selectors for a reference input |

There is no opcode that returns the index of the input being evaluated. A
covenant that needs its own value can require a single input
(`OP_INPUTCOUNT 1 OP_NUMEQUALVERIFY`) and read `0 OP_INPUTVALUE`.

#### Value encodings

Some fields are script numbers, ready for arithmetic; others are raw
little-endian bytes. With `SCRIPT_VERIFY_64BIT_INTEGERS` active:

| Returns a script number | Returns raw bytes |
|-------------------------|-------------------|
| `OP_OUTPUTVALUE`, `OP_INPUTVALUE` | `OP_TXFIELD 01`, `OP_INPUTFIELD 01` (8 bytes LE) |
| `OP_REFINPUTFIELD 01` | `OP_TXLOCKTIME` (4 bytes LE) |
| Asset amounts (selector `02`) | Asset units, flags and type (1 byte each) |
| `OP_INPUTCOUNT`, `OP_OUTPUTCOUNT`, `OP_REFINPUTCOUNT`, `OP_CHAINCONTEXT` | |

Without 64-bit integers, values and asset amounts are also raw 8-byte fields.
Standard policy enforces `SCRIPT_VERIFY_MINIMALDATA`, under which numeric
opcodes reject non-minimal encodings. A raw field therefore cannot be used reliably
in arithmetic in a relayable transaction: compare it with `OP_EQUAL` against bytes
of the same length instead. For example, a reissuable flag is checked with
`<01> OP_EQUAL`, and a value with `0x01 OP_TXFIELD <8-byte LE> OP_EQUAL`.

#### AuthScript destination introspection (NIP-041)

`OP_OUTPUTAUTHDEST` (`0xc2`) and selector `0x04` of `OP_TXFIELD` (spent input),
`OP_INPUTFIELD` (any spent input, NIP-043) and `OP_REFINPUTFIELD` (reference
input) return the destination of a script as exactly
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
is specific to the NIP-041 destination queries.

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
| `OP_REFINPUTASSETFIELD` | `<index> <selector> → <value>` | Reads a field from a reference input's asset payload |

**Asset field selectors:**

| Selector | Field | Encoding | Available On |
|----------|-------|----------|-------------|
| `0x01` | Asset name | Raw string | All types |
| `0x02` | Amount (1.0 unit = 100000000) | Script number with 64-bit integers, else 8 bytes LE | All types |
| `0x03` | Units (decimals) | 1 byte (`ff` = unchanged on reissue) | New, Reissue |
| `0x04` | Reissuable flag | 1 byte | New, Reissue |
| `0x05` | Has IPFS flag | 1 byte | New |
| `0x06` | IPFS hash | Raw bytes | New, Reissue (when present) |
| `0x07` | Asset type | 1 byte | All types |
| `0x08` | Transfer message (NIP-043) | 32 bytes, or a 34-byte IPFS multihash | Transfer |

"New" covers new, message-channel, qualifier and restricted issuances. On a
reissue output, the amount is the quantity being added. The operation fails
when the output carries no asset or the selector does not apply to its type.

### Byte Manipulation Opcodes

These opcodes provide the glue logic needed to construct and parse data on the stack:

| Opcode | Stack Effect | Description |
|--------|-------------|-------------|
| `OP_CAT` | `<a> <b> → <a\|\|b>` | Concatenate two byte strings (result limited to the effective element size: 520 bytes, or 3072 with the PQ cap) |
| `OP_SPLIT` | `<data> <n> → <left> <right>` | Split a byte string at position n (0 ≤ n ≤ length); `<right>` ends on top |
| `OP_REVERSEBYTES` | `<data> → <reversed>` | Reverse byte order (little-endian ↔ big-endian) |

### 64-Bit Arithmetic

With `SCRIPT_VERIFY_64BIT_INTEGERS`, numeric operands may be up to 8 bytes
(signed int64) instead of 4. This covers the arithmetic, comparison and
boolean opcodes (`OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_NUMEQUAL`,
`OP_LESSTHAN`, `OP_WITHIN`, `OP_MIN`, …) and the re-enabled `OP_MUL`,
`OP_DIV` and `OP_MOD`. Results that would overflow int64 or equal `INT64_MIN`
are rejected, as are division and modulo by zero. Stack indices
(`OP_PICK`, `OP_ROLL`), `OP_SPLIT` positions, introspection indices and
multisig counts stay at 4 bytes; `OP_CHECKLOCKTIMEVERIFY` and
`OP_CHECKSEQUENCEVERIFY` keep 5.

---

## Covenant Patterns

The following patterns illustrate how the opcodes compose to build practical
smart contracts. They assume the reset-testnet rule set, where 64-bit integers
are active, so `OP_OUTPUTVALUE`, `OP_INPUTVALUE` and asset amounts are script
numbers (see [Value encodings](#value-encodings)). Script numbers such as
`<max_fee>` are constants written into the script when it is created; the
patterns check every output and value that matters, as a real contract must
(see [Covenant pitfalls](#covenant-pitfalls)).

### 1. Rate-Limited Vault with Recovery Path

A vault that lets a hot key withdraw at most 1 XNA per block, while a recovery
key can move the whole balance, but only to a cold wallet.

```
// Witness script (AuthType 0x00 — each branch checks its own key)
// Witness arguments: <hot_sig> 1   or   <recovery_sig> 0 (empty)

// The fee is paid from the vault itself, so the spend has exactly one input,
// and "0 OP_INPUTVALUE" is the value of this vault UTXO.
OP_INPUTCOUNT 1 OP_NUMEQUALVERIFY

OP_IF
    // Branch 1: hot key, at most 1 XNA per block
    <hot_pubkey> OP_CHECKSIGVERIFY
    1 OP_CHECKSEQUENCEVERIFY OP_DROP     // the vault UTXO must be confirmed

    OP_OUTPUTCOUNT 2 OP_NUMEQUALVERIFY

    // Output 0: at most 1 XNA to the hot wallet
    0 OP_OUTPUTSCRIPT <hot_wallet_script> OP_EQUALVERIFY
    0 OP_OUTPUTVALUE 100000000 OP_LESSTHANOREQUAL OP_VERIFY

    // Output 1: the change returns to this same covenant...
    1 OP_OUTPUTSCRIPT
    0x03 OP_TXFIELD                      // own scriptPubKey
    OP_EQUALVERIFY

    // ...keeping everything except the payment and at most <max_fee>
    0 OP_INPUTVALUE 0 OP_OUTPUTVALUE OP_SUB
    <max_fee> OP_SUB
    1 OP_OUTPUTVALUE
    OP_LESSTHANOREQUAL

OP_ELSE
    // Branch 2: recovery key, everything to the cold wallet
    <recovery_pubkey> OP_CHECKSIGVERIFY
    OP_OUTPUTCOUNT 1 OP_NUMEQUALVERIFY
    0 OP_OUTPUTSCRIPT <cold_wallet_script> OP_EQUAL
OP_ENDIF
```

**How it works:**
- The hot key can pay up to 1 XNA per spend to the hot wallet. The rest must
  return to the same covenant (recursive covenant via `OP_TXFIELD` +
  `OP_OUTPUTSCRIPT`), and at most `<max_fee>` can go to fees.
- `1 OP_CHECKSEQUENCEVERIFY` requires the vault UTXO to be confirmed, so
  withdrawals cannot be chained inside one block. An attacker who steals the
  hot key gets at most 1 XNA per block.
- The owner reacts with the recovery key, which can only pay the cold wallet.
  A leaked recovery key cannot redirect the funds either.

### 2. On-Chain DEX (Asset Swap Covenant)

A trustless limit order: anyone can take the locked asset by paying a fixed
amount of another asset to the seller in the same transaction.

```
// The seller locks ASSET_A in this covenant.
// AuthType 0x00 — no envelope key; the cancel branch checks the seller's key.
// <seller_dest> is the 33-byte AuthScript destination (version || program)
// of an address the seller uses for this order only.
// Witness arguments: 1 (fill)   or   <seller_sig> 0 (cancel)

OP_IF
    // Fill: output 0 pays exactly <price_B> of ASSET_B to the seller
    0 0x01 OP_OUTPUTASSETFIELD <ASSET_B_name> OP_EQUALVERIFY
    0 0x02 OP_OUTPUTASSETFIELD <price_B> OP_NUMEQUALVERIFY
    0 OP_OUTPUTAUTHDEST <seller_dest> OP_EQUAL
OP_ELSE
    // Cancel: the seller takes the order back
    <seller_pubkey> OP_CHECKSIG
OP_ENDIF
```

**How it works:**
- The taker spends the order UTXO together with their own `ASSET_B` and XNA
  inputs. Output 0 pays `ASSET_B` to the seller, and `ASSET_A` goes wherever
  the taker chooses; consensus asset rules already prevent creating or losing
  assets in a transfer.
- Amounts are raw transaction amounts (1.0 asset unit = 100000000).
- The destination is checked with `OP_OUTPUTAUTHDEST`, not `OP_OUTPUTSCRIPT`.
  `OP_OUTPUTSCRIPT` returns the full scriptPubKey, including the
  `OP_XNA_ASSET <payload> OP_DROP` suffix of an asset output, so comparing it
  with a bare address script never matches.
- A fresh seller destination per order prevents double satisfaction: otherwise
  two identical orders spent in one transaction could both be satisfied by a
  single payment output.
- The swap is atomic: either the whole transaction is valid, or nothing moves.

### 3. Recurring Payment Stream

A covenant that releases a fixed amount of XNA per period to a fixed recipient.

```
// AuthType 0x00 — pure covenant, anyone can trigger the payment.
// The fee is paid from the covenant balance: one input, two outputs.
OP_INPUTCOUNT 1 OP_NUMEQUALVERIFY
OP_OUTPUTCOUNT 2 OP_NUMEQUALVERIFY

// One payment per period: the covenant UTXO must be <period> blocks old
// (e.g. 1440 blocks ≈ 1 day at 60-second blocks). The remainder output is a
// new UTXO, so the next payment waits another full period.
<period> OP_CHECKSEQUENCEVERIFY OP_DROP

// Output 0: the payment
0 OP_OUTPUTVALUE <payment_amount> OP_NUMEQUALVERIFY
0 OP_OUTPUTSCRIPT <recipient_script> OP_EQUALVERIFY

// Output 1: the remainder returns to this covenant...
1 OP_OUTPUTSCRIPT
0x03 OP_TXFIELD
OP_EQUALVERIFY

// ...minus the payment and at most <max_fee>
0 OP_INPUTVALUE <payment_amount + max_fee> OP_SUB
1 OP_OUTPUTVALUE
OP_LESSTHANOREQUAL
```

A relative timelock (`OP_CHECKSEQUENCEVERIFY`) is used instead of comparing
`OP_TXLOCKTIME` with a constant: the spender chooses `nLockTime`, and a fixed
absolute threshold would allow every remaining payment as soon as it passes.
When the balance falls below `payment_amount + max_fee`, the remainder can no
longer be paid out; a real contract adds a final branch for it.

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
  Ordinary recipient outputs (Legacy, strict v2/v3 or AuthScript)
```

**How it works:**
- A service (e.g., mining pool, exchange) creates a single on-chain transaction committing to a payout tree.
- Each recipient can unilaterally claim their payment by broadcasting the branch of the tree that leads to their output.
- Only the paths that are actually claimed consume block space.
- Each template fixes its outputs, and therefore its fee, when the tree is built.

### 5. Asset Reissuance Gate

A covenant that holds an owner token and lets a governance key reissue the
asset only within limits and with an oracle's approval of the exact outputs.

```
// The covenant holds the owner token GOVERNED_ASSET!.
// AuthType 0x01 — post-quantum governance key required.
// Witness arguments: <oracle_sig>

// Consensus places the reissue output last, so index it from the output count.
OP_OUTPUTCOUNT 1 OP_SUB

OP_DUP 0x01 OP_OUTPUTASSETFIELD <GOVERNED_ASSET_name> OP_EQUALVERIFY

// Cap the amount added by this reissue
OP_DUP 0x02 OP_OUTPUTASSETFIELD <max_reissue_amount> OP_LESSTHANOREQUAL OP_VERIFY

// The asset must stay reissuable
0x04 OP_OUTPUTASSETFIELD <01> OP_EQUALVERIFY

// The oracle signs the digest of all outputs (mask 0x0010), so its approval
// covers this exact reissue and cannot be replayed
<10 00> OP_TXHASH <governance_oracle_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY

// Output 0 returns the owner token to this covenant
0 OP_OUTPUTSCRIPT
0x03 OP_TXFIELD
OP_EQUAL
```

Flags such as the reissuable byte are compared as bytes (`<01> OP_EQUALVERIFY`):
the field is a single raw byte, and `00` is not a minimally encoded number.

### 6. Escrow with Timeout

A 2-of-3 escrow between buyer, seller and arbitrator that refunds the buyer
after a deadline.

```
// AuthType 0x00 — the keys are checked inside the script.
// Witness arguments: <> <sig_1> <sig_2> 1   or   0 (empty) for the refund

OP_IF
    // Release: any two of the three parties sign the transaction itself.
    // With SIGHASH_ALL their signatures commit to the outputs and fix the payout.
    2 <buyer_pubkey> <seller_pubkey> <arbitrator_pubkey> 3 OP_CHECKMULTISIG

OP_ELSE
    // Timeout: after 2016 blocks (~1.4 days at 60-second blocks) anyone may
    // return the whole balance to the buyer, minus at most <max_fee>
    <2016> OP_CHECKSEQUENCEVERIFY OP_DROP
    OP_INPUTCOUNT 1 OP_NUMEQUALVERIFY
    OP_OUTPUTCOUNT 1 OP_NUMEQUALVERIFY
    0 OP_OUTPUTSCRIPT <buyer_refund_script> OP_EQUALVERIFY
    0 OP_INPUTVALUE 0 OP_OUTPUTVALUE OP_SUB
    <max_fee> OP_LESSTHANOREQUAL

OP_ENDIF
```

The keys may mix ECDSA and ML-DSA-44 (see
[Mixed ECDSA/PQ multisig in witness v1](#mixed-ecdsapq-multisig-in-witness-v1)).
Without the output and value checks, the keyless timeout branch would let
anyone send a dust amount to the buyer and the rest elsewhere.

### 7. DePIN Device Payment Channel

A covenant designed for IoT/DePIN devices: a service balance pays the device
operator according to usage reported by an oracle.

```
// AuthType 0x02 — device key (classical ECDSA)
// Witness arguments: <usage> <oracle_sig>
// <usage> is a minimally encoded script number. The oracle signs
// SHA256(usage || txhash(current outpoint)), so a report is valid for this
// UTXO only and cannot be replayed after settlement.

OP_OVER                              // copy <usage>
<20 00> OP_TXHASH OP_CAT             // message = usage || outpoint digest
<network_oracle_pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY

// Output 0: usage × rate to the device operator
<rate_per_unit> OP_MUL
0 OP_OUTPUTVALUE OP_NUMEQUALVERIFY
0 OP_OUTPUTSCRIPT <operator_script> OP_EQUALVERIFY

// Output 1: the remaining balance returns to this covenant
1 OP_OUTPUTSCRIPT
0x03 OP_TXFIELD
OP_EQUALVERIFY

OP_INPUTCOUNT 1 OP_NUMEQUALVERIFY
OP_OUTPUTCOUNT 2 OP_NUMEQUALVERIFY

// Nothing but the payment and at most <max_fee> leaves the covenant
0 OP_INPUTVALUE 0 OP_OUTPUTVALUE OP_SUB
<max_fee> OP_SUB
1 OP_OUTPUTVALUE
OP_LESSTHANOREQUAL
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

Both scripts include any asset suffix, so for an asset-carrying covenant the
output must also carry the same asset payload, including the same amount. When
the amount may change, compare only the destination and check the amount
separately:

```
0x04 OP_TXFIELD                      // own version || program (33 bytes)
<n> OP_OUTPUTAUTHDEST
OP_EQUALVERIFY
<n> 0x02 OP_OUTPUTASSETFIELD <new_amount> OP_NUMEQUALVERIFY
```

### Value Conservation Check

```
// Single-input spend: input 0 is this covenant
OP_INPUTCOUNT 1 OP_NUMEQUALVERIFY

// Input value minus the sum of outputs 0 and 1 is the fee
0 OP_INPUTVALUE
0 OP_OUTPUTVALUE
1 OP_OUTPUTVALUE
OP_ADD
OP_SUB
<max_fee> OP_LESSTHANOREQUAL OP_VERIFY
```

`0x01 OP_TXFIELD` also returns the spent value, but as raw 8-byte
little-endian bytes even with 64-bit integers active, which arithmetic rejects
under standard policy (see [Value encodings](#value-encodings)).

### Asset Amount Distribution

Consensus already forbids creating or destroying assets in a transfer. A
covenant uses the amount fields to decide how the input amount is split among
outputs:

```
// Input asset amount (input 0 holds the asset)
0 0x02 OP_INPUTASSETFIELD

// Output asset amounts
0 0x02 OP_OUTPUTASSETFIELD
1 0x02 OP_OUTPUTASSETFIELD
OP_ADD

// Outputs 0 and 1 together carry the whole input amount
OP_NUMEQUALVERIFY
```

### Constructing a Script on the Stack

```
// Build an AuthScript v1 scriptPubKey: OP_1 0x20 <32-byte commitment>
<51 20>        // OP_1, then a 32-byte push opcode
<commitment>   // 32 bytes
OP_CAT

// Verify output 0 pays to this constructed script (an XNA-only output)
0 OP_OUTPUTSCRIPT
OP_EQUALVERIFY
```

The prefix bytes are pushed as data: `OP_0` or `OP_1` on their own would push
an empty vector or the number 1, not the opcode byte.

### Byte-Order Conversion

`OP_REVERSEBYTES` converts between the little-endian fields returned by raw
introspection and big-endian data from outside Neurai, such as an oracle
message in network byte order:

```
// <amount_be> is an 8-byte big-endian amount from an authenticated message
0x01 OP_TXFIELD          // spent value, raw 8-byte little-endian
OP_REVERSEBYTES          // now big-endian
<amount_be> OP_EQUALVERIFY
```

Use the result for byte comparison or hashing only. Numeric opcodes read
little-endian script numbers, so a reversed value cannot be used in arithmetic,
and values that are already script numbers (such as `OP_OUTPUTVALUE` with
64-bit integers active) need no conversion.

### Parsing Structured Data

```
// Extract fields from a serialized structure
<serialized_data>

// First 4 bytes: version
4 OP_SPLIT       // stack: <version> <rest>

// Next 32 bytes: hash
32 OP_SPLIT      // stack: <version> <hash> <remainder>
```

`OP_SPLIT` leaves the right-hand part on top, so each call continues with the
rest of the data.

---

## Design Principles

### Minimal Trust

Covenants enforce rules at the consensus layer. No multisig committee, no oracle network, and no smart-contract platform is required for the core spending logic. Oracles (via CSFS) are optional additions for external data, not a requirement for the covenant mechanism itself.

### Composability

Each opcode does one thing well. Complex behavior emerges from composition rather than from monolithic opcodes. `OP_CAT` + `OP_OUTPUTSCRIPT` builds script verification. `OP_OUTPUTVALUE` + `OP_MUL` builds price calculations. `OP_INPUTASSETFIELD` + `OP_OUTPUTASSETFIELD` builds distribution rules.

### Graceful Degradation

Before its flag is set, each new opcode behaves as the byte did on older nodes:

- Opcodes that replace a NOP (`OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK`,
  `OP_TXHASH`, `OP_TXFIELD`, `OP_SPLIT`) act as that NOP. Standard policy
  rejects them through `DISCOURAGE_UPGRADABLE_NOPS`.
- Re-enabled opcodes (`OP_CAT`, `OP_MUL`, `OP_DIV`, `OP_MOD`) return
  `SCRIPT_ERR_DISABLED_OPCODE`, even inside an unexecuted branch.
- Opcodes in previously unassigned bytes (`OP_REVERSEBYTES` and every other
  new opcode) return `SCRIPT_ERR_BAD_OPCODE` when executed. They are not NOPs,
  so a node with the flag off never accepts a script that an older node
  rejects.

`OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`,
`OP_2MUL`, `OP_2DIV`, `OP_LSHIFT` and `OP_RSHIFT` remain disabled. Activating
any of the new opcodes still requires the network's coordinated consensus
upgrade.

### Post-Quantum Readiness

AuthScript supports ML-DSA-44 (FIPS 204) signatures natively. Covenants that use AuthType `0x01` are protected against quantum attacks on the authentication layer, while the covenant logic itself (hash-based commitments, script evaluation) is inherently quantum-resistant. This holds only if every key checked inside the script (`OP_CHECKSIG`, multisig, CSFS oracles) is also ML-DSA-44; an ECDSA or Ed25519 key anywhere in the script is a classical point of failure.

### Asset-Native

Unlike overlay protocols or token standards built on top of generic scripting, Neurai's asset introspection opcodes operate directly on the consensus-validated asset layer. The script engine can verify asset names, amounts, types, and metadata without parsing serialized data — the node has already validated the asset payload before script evaluation begins.

---

## Security Considerations

### Stack Element Size Limit

All data pushed onto the stack is bounded by the effective per-element cap:
`MAX_SCRIPT_ELEMENT_SIZE` (520 bytes) by default, or
`MAX_PQ_SCRIPT_ELEMENT_SIZE` (3072 bytes, NIP-018) when any of
`SCRIPT_VERIFY_CHECKSIGFROMSTACK`, `SCRIPT_VERIFY_CHECKSIGADD`,
`SCRIPT_VERIFY_MERKLE_INCLUSION` or `SCRIPT_VERIFY_ZKVERIFY` is active. This
applies to pushes, witness arguments, `OP_CAT` results and the fields returned
by `OP_OUTPUTSCRIPT`, `OP_TXFIELD`, `OP_INPUTFIELD` and `OP_REFINPUTFIELD`.
Scripts that exceed the effective limit fail cleanly. Under the same flags (and
under the NIP-046 budget in AuthScript), `MAX_STACK_BYTES` (256 KiB) bounds the
total bytes held on `stack + altstack`.

### Quadratic Hashing Prevention

CTV and TXHASH use precomputed sub-hashes (`PrecomputedTransactionData`) for
O(1) evaluation per opcode. The CTV sub-hashes are computed for every
transaction. TXHASH reuses the BIP143 lists, which are only computed for
transactions with witness data; in a transaction without witness data, each
execution that selects a list hashes it again in O(n) time.

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

CHECKSIGADD's existing dynamic surcharge of eight against the per-script
operation limit (201, or 512 in AuthScript under NIP-046) is unchanged and
separate from the global sigop budget. One global sigop per
signature is consistent with CSFS and AuthScript authentication; it is not a
claim that ECDSA, ML-DSA and Ed25519 have equal CPU costs.

### Height activation of signature opcodes

CSFS, CHECKSIGADD and Ed25519 share `nSignatureOpcodesHeight`. Their individual
capability switches only take effect at or above that height. Mainnet leaves
the height unscheduled (`INT_MAX`); the reset testnet uses block 10 and regtest
height zero.
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

CSFS follows the same `NULLFAIL` semantics as `OP_CHECKSIG`: under
`SCRIPT_VERIFY_NULLFAIL`, a non-empty signature that fails verification causes
the entire script to fail (rather than pushing false). NULLFAIL is a standard
policy rule (BIP146), not consensus: in a block, a failing signature pushes
false.

The trailing signature-type byte of a CSFS signature is removed before
verification and is not part of the signed message, so a third party can
change it without invalidating the signature. Covenants must not depend on the
exact bytes of a CSFS signature (for example, by hashing them).

### Covenant Pitfalls

Introspection makes it easy to write a covenant that checks less than it seems
to. Common mistakes:

- **Unchecked outputs and values.** Constraining one output says nothing about
  the others. Fix the output count, and bound the fee with the input value
  (`0 OP_INPUTVALUE` in a single-input spend). Otherwise a keyless branch lets
  anyone send dust to the intended recipient and the rest elsewhere.
- **Asset suffixes.** `OP_OUTPUTSCRIPT` and `OP_TXFIELD 03` return the whole
  scriptPubKey, including `OP_XNA_ASSET <payload> OP_DROP`. To check where an
  asset goes, compare `OP_OUTPUTAUTHDEST` and check name and amount with
  `OP_OUTPUTASSETFIELD`.
- **Double satisfaction.** Checks indexed by output position do not know which
  input they belong to. Two identical covenants spent in one transaction can
  both be satisfied by a single output. Make each instance unique (for example,
  a fresh destination per order) or limit the number of inputs.
- **Locktime.** `OP_TXLOCKTIME` returns the field the spender chose. `nLockTime`
  is only enforced when an input has a non-final sequence, so a script that
  compares it with a constant does not enforce a time. Use
  `OP_CHECKLOCKTIMEVERIFY` or `OP_CHECKSEQUENCEVERIFY`; for the chain height
  or median time past, use `OP_CHAINCONTEXT`.
- **Replayable attestations.** A CSFS message that does not depend on the
  spending transaction can be reused. Bind it with `OP_TXHASH` (outputs or the
  current outpoint), or include a timestamp or nonce that the script checks.
- **Raw fields in arithmetic.** See [Value encodings](#value-encodings).
- **Reissue position.** Consensus puts the reissue output last; index it with
  `OP_OUTPUTCOUNT 1 OP_SUB`, not with a fixed position.

---

## Comparison with Other Covenant Approaches

| Feature | Neurai Covenants | Bitcoin (proposed) | Ethereum |
|---------|-----------------|-------------------|----------|
| CTV (BIP 119) | Integrated | Proposed (not activated) | N/A (Turing-complete) |
| CSFS | Integrated | Proposed (not activated) | Native (ecrecover) |
| OP_CAT | Integrated | Proposed (not activated) | Native (bytes.concat) |
| Transaction introspection | `OP_TXHASH` and 13 field opcodes | Not available | Native (msg.value, etc.) |
| Native asset introspection | 3 opcodes | N/A (no native assets) | ERC-20 calls |
| Post-quantum auth | ML-DSA-44 AuthScript | Not available | Not available |
| Execution model | Non-Turing-complete Script | Non-Turing-complete Script | Turing-complete EVM |
| Gas/fee model | Counted sigops, op and hash budgets (NIP-046) | Counted sigops, bounded script | Metered gas |

---

## Policy-layer signing verification (NIP-020)

Post-signing verification applies `STANDARD_SCRIPT_VERIFY_FLAGS` plus every
consensus opt-in active at the next block height (AuthScript and its strict
families, the covenant, introspection, hash, signature and proof opcodes,
64-bit integers, reference inputs and the NIP-043/044/046 rules). `neurai-tx`
and the internal `SignSignature`/`ProduceSignature` path use the helper
`GetStandardScriptVerifyFlagsWithConsensusOptIns(consensus)`; the
`signrawtransaction` RPC computes the same set for the tip height plus one.
Signing on testnet/regtest therefore honors the wider PQ element cap and the
other opt-ins, completing the sign-and-relay round-trip for witness scripts
with PQ-sized items. `neurai-tx` has no chain tip and uses height 0, so on the
reset testnet (activation at block 10) its post-signing check applies none of
the opt-ins.

NIP-021 ties the P2WSH per-stack-item relay cap in `IsWitnessStandard` to the
opcodes that need large items: the cap is
`MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE` (3072 B, `MAX_PQ_SCRIPT_ELEMENT_SIZE`)
when `OP_CHECKMERKLEINCLUSION` is active for the next block, or when the
signature opcodes are (CSFS, Ed25519 or CHECKSIGADD), and
`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE` (80 B) otherwise. On testnet/regtest
PQ-sized witness items relay normally once these rules are active; on mainnet,
where their heights are unscheduled, the 80-byte cap remains in effect and
oversize items are rejected with reason `bad-witness-nonstandard`.
`IsWitnessStandard` also limits a standard transaction to four `OP_ZKVERIFY`
operations.

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

Output is always 32 bytes (one BN254 Fr element, big-endian).

### Activation and flag-off behaviour

- Slot `0xc9` was previously **`bad-opcode`**, never a reserved NOP.
- Activation gates on `consensus.nPoseidonEnabled` (true on
  testnet/regtest, applied from the opt-in activation height: block 10
  of the reset testnet, genesis on regtest; false on mainnet until a
  future activation NIP). Activation is a hard fork.
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

### Poseidon work budget

`SCRIPT_VERIFY_POSEIDON_WORK` (bit 49, `nPoseidonWorkHeight`: block 10 of the
reset testnet, regtest height 0 with `-poseidonworkheight`, mainnet
unscheduled) adds a second, independent budget counted in Poseidon
permutations. It does not replace the per-script byte budget, which is still
checked first.

- `OP_POSEIDON` costs `n / 62 + 1` permutations for an `n`-byte input.
- Merkle scheme `05` costs its depth.
- `OP_ZKVERIFY` profile `02` costs its public-tree transition cost.

A block may contain at most `MAX_BLOCK_POSEIDON_WORK` = 200000 permutations
(`bad-blk-poseidon-work`), and a standard transaction at most
`MAX_STANDARD_TX_POSEIDON_WORK` = 20000 (`bad-txns-poseidon-work`). A script
that exceeds the budget fails with `Poseidon work budget exceeded`.

### Worked example: ZK + PQ commitment

```
// Witness arguments: <sig_pq> <pubkey_pq>
OP_DUP OP_POSEIDON <commitment> OP_EQUALVERIFY   // 1313 B key → 32 B → equality
OP_CHECKSIG                                      // ML-DSA-44 signature over the transaction
```

This single-call Poseidon on a 1313-byte serialized key costs about 1 ms on
CI hardware and consumes 1313 B of the 30 720 B budget — comfortable headroom
for additional commitments inside the same script.

---

## NIP-043: state-thread primitives

These three capabilities have independent height gates: reset testnet block 10,
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

Activation: reset testnet height 10, regtest 0 with `-authscripttreeheight`, mainnet
unscheduled. No live network has been updated by this integration. Wallet tree
import, backup and automatic leaf selection are not implemented. Manual contract
signing uses the explicit tree context API; arbitrary partial-signature merging
is unsupported and does not fall back to the historical domain.

The design is specified in NIP-044 v2.

## Asset replacement policy (NIP025-patch1)

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

## NIP-046: AuthScript execution budgets

`SCRIPT_VERIFY_AUTHSCRIPT_BUDGET` (bit 48) is enabled at block 10 of the
reset testnet, and at regtest height 0. Regtest accepts
`-authscriptbudgetheight=N` (`-1` disables). Mainnet defaults to `INT_MAX`;
activation requires a separately chosen `nAuthScriptBudgetHeight`.

With this flag, `SIGVERSION_AUTHSCRIPT` uses a 512-operation limit, including
existing CHECKSIGADD and MULTISIG surcharges. Legacy and witness v0 retain
201. MAST uses the selected leaf's AuthScript execution; the outer P2SH script
retains its own rules. Strict v2/v3 templates and block/transaction sigop limits
are unchanged. Unexecuted branches count opcodes, but incur no hash charges.

Each AuthScript execution has 65536 classic hash units. Simple hashes cost
input length + 64, HASH160/HASH256 cost length + 160. CSFS charges its explicit
message hash after encoding checks and before calling the checker, including
empty signatures. Merkle scheme 01 costs 224 per level; schemes 02–04 cost
leaf length + 64 + 128 per level. Structurally unhashable classic proofs retain
their false result without charges. Well-formed incorrect proofs pay. Charges
precede hashing; exhaustion returns `AuthScript hash budget exceeded`.
Poseidon retains its separate 30720-byte budget, shared with Merkle scheme 05.

Initial arguments are limited to 1000 elements and 262144 bytes, with existing
per-element limits. Envelope signatures, pubkeys, leaf script and MAST control
are not execution arguments. Main stack plus altstack obey the same byte cap
after each opcode. The flag alone does not widen elements. A leading DROP
cannot conceal an initially oversized stack.

Flags follow the height of the block being validated; mempool uses the next
height. Both activation directions revalidate pending transactions and remove
invalid entries and descendants. Script-cache results remain flag-specific.
These are consensus rules, not only relay policy. Testnet activation is for
experimentation; resource benchmarks and mainnet deployment review remain
separate from functional correctness tests.

## NIP-016: `OP_ZKVERIFY` integration (experimental)

`OP_ZKVERIFY` (`0xc3`, verification flag bit 43) executes only in
`SIGVERSION_AUTHSCRIPT`, including NIP-044 leaves. Its stack is
`proof vk input_1 ... input_k k profile -> bool`. Profile is the byte `01`
(Groth16 over BN254) or, with the public-tree rule below, `02`; `k` is a
minimal Script number of at most four bytes, in `[1,16]`.
Public inputs are canonical 32-byte big-endian BN254 scalars. Verification
keys and proofs use the strict compressed arkworks encoding described in
NIP-016. The script must authenticate the verification key and bind the
public inputs to its intended statement.

An empty proof produces false after checking profile, count and inputs,
without parsing the verification key. A nonempty invalid proof fails the
script. Local backend failures take the operational-error path, rather than
marking a block or peer invalid.

Each opcode in a revealed AuthScript script/MAST leaf costs **280 sigops**, including unexecuted branches. Bytes in pushes and MAST
control blocks do not count. Standard transactions allow at most four such
opcodes across all inputs. The flag also enables the existing 3072-byte
item cap and 256-KiB stack-byte limit.

Activation is scheduled at height 10 on reset testnet and defaults to height
0 on regtest (`-zkverifyheight`, `-1` disables). Mainnet remains unscheduled.
Fixed-size positive-result and prepared-VK caches are implemented. Calibration
sets the cost to 280: the largest measured uncached invalid-equation sample
was 214.52 times the ECDSA median; a 25% margin rounded upward gives 280.
Exact policy/block boundaries and cold blocks with 285 distinct VKs pass.
This is evidence for the measured x86-64 build, not a universal time bound.
The remaining NIP-016 checklist is still required before deployment. The
legacy 32-bit `libneuraiconsensus` ABI does not expose this flag.

### Profile 02: public-tree transitions (experimental C5)

`SCRIPT_VERIFY_ZK_PUBLIC_TREE` (bit 50) enables profile `02`, which verifies a
Poseidon public-tree state transition (a commitment tree plus indexed
nullifier and commitment trees, with depth-32 paths) bound to the public
inputs, and then the Groth16 proof. It requires `SCRIPT_VERIFY_ZKVERIFY` and
`SCRIPT_VERIFY_POSEIDON_WORK`; without them, profile `02` fails with a bad
profile error. The stack is:

```
chunk_1 ... chunk_5 form proof vk input_1 ... input_k k 02 -> bool
```

The five chunks carry the transition transcript, each at most 3072 bytes;
after the first short chunk, the remaining ones must be empty. `form` is a
script number in `[0,8)`. The transition cost is charged before any hashing,
against a per-script allowance of 1024 permutations and against the shared
Poseidon work budget.

Activation: reset testnet height 10, regtest 0 (`-zkpublictreeheight`, `-1`
disables), mainnet unscheduled. `getblockchaininfo` reports the state under
`zk_public_tree`. Testnet nodes must upgrade before spending C5 outputs.

---

## Further Reading

- [New OP_Codes Reference](new-opcodes-depin-branch.md) — Detailed specification of the original covenant opcodes (byte values, flags, stack effects, error codes)
- [Atomic Swaps](atomicswaps.md) — Cross-chain atomic swap protocol
- [DePIN Client Protocol](depinreceivemsg.md) — DePIN messaging layer documentation
- `scripts/review-contract-thread-regtest.py` — Reproducible NIP-043 state-thread example on regtest
