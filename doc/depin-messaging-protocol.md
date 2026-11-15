# DePIN Messaging Protocol Specification (protocol 6)

This document specifies the DePIN messaging protocol of Neurai at the level an
implementer needs to write an independent client or library in any language:
the on-chain access model, byte-exact wire formats, content cryptography and
references to the RPC authentication contract. It is normative
where it says MUST/SHOULD; the node source is the reference implementation.

Companion documents:

- [`depin-pool-state.md`](depin-pool-state.md) — strict wire budgets, signed
  admission-sequence reads, durable moderation and state v3.
- [`depinreceivemsg.md`](depinreceivemsg.md) — the RPC-by-RPC integration
  guide (argument semantics, examples, paging). This specification defers to
  it for parameter details and does not repeat them.
- [`depin-guide.md`](depin-guide.md) — operating a service node (configuration,
  indexes, wallet requirements).
- `contrib/depin/regtest_walkthrough.sh` — an executable end-to-end run of
  protocol 6 functional regressions against a disposable regtest node.

Reference code: `src/depinmsgpool.{h,cpp}` (message, pool, access),
`src/depinecies.{h,cpp}` (envelope), `src/depinchallenge.{h,cpp}`
(authentication), `src/depinpoolkey.{h,cpp}` (pool key),
`src/depinrpc.{h,cpp}` (RPC codec, reply signing/encryption) and
`src/rpc/depin.cpp` (RPC dispatcher),
`src/rpc/messages.cpp` (local wallet/query business logic). An independent
reference implementation of the envelope, which produces the test vectors, is
`contrib/devtools/depin-format3-vectors.py`.

DePIN messaging is experimental and currently available on **testnet and
regtest** only. Protocol **6** rejects old RPC formats/signatures and uses
envelope format **3** only: formats 1 and 2 are neither written nor read.
Clients MUST verify the bootstrap and require protocol 6. External SDKs are to
be updated after the node; no external implementation is certified here.

---

## 1. Overview

DePIN messaging is an **off-chain, encrypted, ephemeral** message pool whose
membership is defined by **on-chain token holdings**. Message delivery does
not create chain transactions or fees; eligibility changes do. Messages
expire (7 days by default), with optional local durable retention.

Parties:

| Party | Holds | Role |
|---|---|---|
| **Holder / client** | its own secp256k1 private key | Reads and publishes. Encrypts, decrypts, signs locally. Never hands its key to anything. |
| **Service node** (`neuraid`) | the **pool key** | Keeps the in-memory pool for one token subtree, enforces access, authenticates readers, signs every reply. Cannot read message content. |
| **RPC proxy** (e.g. `neurai-rpc-proxy`) | the node's RPC credentials | Whitelists the DePIN RPCs, applies per-IP abuse control. Untrusted by design: the protocol assumes it may withhold, replay or tamper, and makes that detectable. |
| **Token owner** | the owner token `&TOKEN!` | Issues holdings and sections, freezes holders, purges the pool. |

The chain defines eligibility, the holder key authenticates and decrypts,
and a pinned pool key authenticates the service response. A malicious pool
can lie about its directory or withhold data: clients must independently
validate intended recipients. Neither a signature nor recipient authorization proves an arbitrary
server follows authorization rules.

What is, and is not, confidential:

- Confidential: message content (per-recipient envelope), challenge nonces and
  every reply bound to an address (encrypted for that address).
- Bound: the envelope of a message opens only under the header it was made
  for (section, sender, time, type, network). The same envelope published
  under another header does not open for its recipients.
- Public: token names, the section hierarchy, who holds what, which
  addresses have revealed keys — all of it is chain data. Sections protect
  content, not membership. The envelope metadata of a submission (sender,
  token, timestamp, recipient destination IDs) is visible to the node.

---

## 2. On-chain model

### 2.1 DePIN assets

A DePIN asset is a Neurai asset whose name starts with `&`:

```
root asset      &NAME              NAME matches [A-Z0-9._]{3,}
section         &NAME/SUB[/SUB...] components match [A-Z0-9._]+
owner token     &NAME!   &NAME/SUB!
```

(`DEPIN_INDICATOR = ^[&][A-Z0-9._]{3,}$`,
`SUB_DEPIN_INDICATOR = ^&[A-Z0-9._]+\/[A-Z0-9._/]+$`.) Units are 0: holdings
are whole numbers.

DePIN assets are **soulbound**: a holder cannot transfer them. Only the
owner token can move them (`issue`, `transfer` from the owner, `freezedepin`,
`unfreezedepin`), with a single exception — a holder may burn its own holding
(`selfrevokedepin`). Creating `&NAME/SUB` requires `&NAME!`, so only the root
owner (or whoever it hands a section's owner token to) opens sections; issuing
a section hands `&NAME/SUB!` to the receiving address.

### 2.2 Active holders and access

An address is **active** for an asset when all of the following hold:

1. positive balance of the asset;
2. not frozen by the owner for that `(asset, address)` pair (`freezedepin`);
3. not self-revoked for that pair (`selfrevokedepin`).

**Access is inherited downward.** An address has access to token `T` when it
is active for `T` or for any ancestor of `T` (`&A/B/C` → `&A/B` → `&A`).
Restrictions are per `(asset, address)`: an address frozen in `&A/B` but
active in `&A` keeps access to `&A/B`, because the root grants the branch.

**Owner access** (for purging) works the same way over owner tokens: an
address has owner access to `T` when it holds `T!` or the owner token of an
ancestor of `T`.

A service node serves one **pool root** `R` (`-depinmsgtoken`) and the
subtree below it. Ancestors *above* `R` are outside the pool: holders of
`&A` are not recipients of a pool rooted at `&A/B`, and recipient resolution
for publishing stops at `R` (`depingetancestorrecipients` in
[the client guide](depinreceivemsg.md#methods-and-operational-recovery)).

New publications validate the sender and every declared recipient against
current connected-chain permissions. Private subsets are allowed; any invalid
recipient rejects the entire signed message (`-26`). An old challenge does
not override a confirmed freeze. Authorization includes the latest connected
block, excludes the mempool and follows reorganizations. A node with an old
tip or too much header lag denies permission-dependent calls (`-10`). See
[authorization and restoration](depin-authorization.md) for the exact lock,
freshness, restart and client retry contracts.

Query RPCs (all public, cacheable, no authentication):

| RPC | Returns |
|---|---|
| `checkdepinvalidity "asset" "address"` | `has_asset`, `amount`, `valid` (1 = active), `blocked` |
| `listdepinholders "asset"` | every holder with `valid` |
| `listdepinaddresses "asset" (count) (start)` | holders with a revealed pubkey: `address, pubkey, valid` |
| `getpubkey "address"` | `pubkey`, `revealed`, `height`, `txid` |
| `depingetancestorrecipients request` (`token`, `args.max_results`, `args.stop_at`) | active holders with revealed keys over the ancestor chain ([client guide](depinreceivemsg.md#methods-and-operational-recovery)) |

### 2.3 Revealed public keys

Every cryptographic operation that targets an address needs its public key,
and the destination hides the public key until the address **spends** at least
once. The node keeps a public-key index (`-pubkeyindex`) of keys recovered
from spends. An address that has never spent:

- cannot be a recipient (no key to encrypt for);
- cannot authenticate (the node encrypts the challenge for its key);
- cannot publish (the node verifies the message signature against its key).

Clients MUST treat "address has not revealed its public key" as an expected,
user-facing condition and instruct the user to spend once from the address.

### 2.4 Address types

Authentication and recipient encryption support **Legacy P2PKH** (valid
secp256k1 keys, compressed or uncompressed) and **strict ECDSA witness v3**
(`nq1r…` / `tnq1r…`, compressed secp256k1 keys). Generic AuthScript v1,
P2SH and strict PQ are not messaging identities. Each exact destination must
hold its own required asset; sharing a public key does not share permissions.
See [depin-ecdsa.md](depin-ecdsa.md) for commitment verification and wire rules.

---

## 3. Cryptographic primitives and encodings

| Primitive | Definition |
|---|---|
| Curve | secp256k1. Public keys are **compressed** (33 bytes, `02`/`03` prefix), except that a Legacy P2PKH identity may reveal an uncompressed key (65 bytes, `04` prefix; §2.4). |
| `SHA256(x)` | FIPS 180-4 SHA-256. |
| `SHA256d(x)` | `SHA256(SHA256(x))` (Bitcoin "hash256"). |
| `hash160(x)` | `RIPEMD160(SHA256(x))`. The P2PKH payload of an address is `hash160(pubkey)`. |
| `HMAC-SHA256` | RFC 2104. CBC is present in the source for historical reasons and **not used**. |
| `HKDF(salt, ikm, info)` | HKDF-SHA256 (RFC 5869) with a 32-byte output: `PRK = HMAC-SHA256(salt, ikm)`, result `HMAC-SHA256(PRK, info ‖ 0x01)`. |
| `ECDH(d, Q)` | libsecp256k1 `secp256k1_ecdh` with the **default hash function**: `SHA256(prefix ‖ x)` where `(x, y) = d·Q`, `prefix = 0x02` if `y` is even, `0x03` if odd. Output 32 bytes. |
| AES-256-GCM | 32-byte key, **12-byte nonce**, **16-byte tag**. Additional authenticated data as stated where it is used. Ciphertext has the plaintext's length. |
| Base64 | RFC 4648 with padding, for compact signatures. |
| Hex | Lowercase, for everything else. |

### 3.1 Serialization

Message and envelope structures use Bitcoin's serialization. The RPC uses the
separate U32-length codec in the [request contract](depin-request-signatures.md):

- integers little-endian (`int64` = 8 bytes, `uint8` = 1 byte);
- `CompactSize(n)`: `n < 253` → 1 byte; `≤ 0xFFFF` → `0xFD` + LE16;
  `≤ 0xFFFFFFFF` → `0xFE` + LE32; else `0xFF` + LE64;
- `string` and `vector<uint8>`: `CompactSize(len) ‖ bytes`;
- `CPubKey`: `CompactSize(len) ‖ bytes` (`0x21` + 33 bytes);
- `uint160`: 20 raw bytes (the same bytes as in the address payload);
- `uint256` in a structure (contexts, commitments): 32 raw bytes, in the order
  SHA-256 produced them;
- destination id: `0x00 ‖ hash160` (Legacy) or `0x03 ‖ commitment32` (strict
  ECDSA, the raw 32 bytes, not the reversed display hex);
- `map<K, V>`: `CompactSize(count)` followed by `K ‖ V` pairs **in ascending
  byte order of K** (`memcmp` of the serialized key).

### 3.2 Hash display order

A `uint256` produced by `SHA256d` is displayed by the node (and parsed from
JSON) with its **bytes reversed**, as Bitcoin does for txids. Therefore:

- `hash` fields and `after_hash` arguments are `hex(reverse(digest))`;
- content signatures are computed over the **unreversed** 32-byte digest.

RPC request/response SHA256 hashes instead use direct digest hex. Network,
instance and request IDs are decoded from their displayed hex in left-to-right
order by the RPC codec; do not apply the message/uint256 reversal there.

### 3.3 Message signing (recoverable, `signmessage`-compatible)

Used for complete RPC operation requests and response poolsig. The
message-magic wrapper below is unchanged; the signed texts are specified
in [depin-request-signatures.md](depin-request-signatures.md).

```
msghash(text) = SHA256d( ser_string("Neurai Signed Message:\n") ‖ ser_string(text) )
```

where `ser_string` is `CompactSize(len) ‖ bytes`. The signature is a 65-byte
**compact recoverable** ECDSA signature `header ‖ r ‖ s` with
`header = 27 + recid + 4` for compressed keys (`27 + recid` for an uncompressed
Legacy key), encoded in base64. Verification
recovers the public key from the signature and checks
the recovered key against the exact destination: `hash160(recovered)` for
Legacy, or the witness-v3 strict AuthScript commitment for ECDSA. Signing is deterministic
(RFC 6979): the same key and text always give the same signature. Any
wallet's `signmessage` / `verifymessage` is interoperable. Strict ECDSA first
binds `msghash(text)` through `StrictAuthScriptMessageHash`: SHA256d of
`ser_string("Neurai Strict AuthScript Message") || U8(3) || commitment_raw32 ||
msghash(text)_raw32`. Compact recovery uses that bound hash, preventing
cross-family reuse of a signature from the same key.

### 3.4 Message signatures (DER)

Used for `CDepinMessage.signature` only: a **DER-encoded** ECDSA signature
over the 32-byte message digest (§5.2), verified with the sender's revealed
public key (`secp256k1_ecdsa_verify`; the node normalizes high-`s` values,
but producers SHOULD emit low-`s`). Typically 70–72 bytes.

---

## 4. Envelope, format 3 (`CECIESEncryptedMessage`)

One construction serves three uses: the message content (§5), the submission
envelope for the pool key (`depinsubmitmsg`, see
[the client guide](depinreceivemsg.md#methods-and-operational-recovery)), and
every reply bound to an address (§6). It encrypts a plaintext once for **N
recipients** identified by destination id, and binds it to a **context**:
what it was made for. An envelope opens only under the context it was made
under.

### 4.1 Contexts

`net` is the hash of the genesis block of the network, 32 bytes **in display
order**: the bytes of the `network` hex of the protocol. `str(s)` is
`CompactSize(len) ‖ ASCII bytes`.

```
context(message)  = SHA256( str("Neurai/DePIN/message/v3") ‖ net ‖ ser_string(token)
                            ‖ ser_string(senderAddress) ‖ LE64(timestamp) ‖ uint8(messageType) )
context(reply)    = SHA256( str("Neurai/DePIN/reply/v3")  ‖ net )
context(submit)   = SHA256( str("Neurai/DePIN/submit/v3") ‖ net )
```

The context of a message is its whole signed header (§5), on one network.
`senderAddress` is the canonical string of the address. These are single
SHA-256; the message identifier (§5.2) is the only double hash.

### 4.2 Wire format

```
CECIESEncryptedMessage :=
  prefix             00 03
  ephemeralPubKey    CPubKey                    (0x21 ‖ 33 bytes, compressed)
  commitment         uint256                    32 raw bytes, no length
  encryptedPayload   vector<uint8>              nonce(12) ‖ ciphertext ‖ tag(16)
  recipientKeys      map<destination id, vector<uint8>>  id → nonce(12) ‖ wrappedKey(32) ‖ tag(16)
```

Rejected, by every reader and by the pool: any other prefix, an invalid or
uncompressed ephemeral key, an empty ciphertext, zero recipients or more than
the limit, unknown destination types, ids out of order or repeated, wrapped
keys that are not exactly 60 bytes, non-minimal `CompactSize`, and trailing
bytes. Each wrapped key package is exactly 60 bytes; `encryptedPayload` is
`28 + len(plaintext)` bytes. The hex of this serialization is what travels in
`encrypted_payload_hex`, in `depinsubmitmsg`'s `args.encrypted` and in every
`encrypted` reply field.

### 4.3 Encryption

```
e      ← random 32-byte scalar (ephemeral private key), E = e·G (compressed)
K      ← random 32 bytes                        # content key
n      ← random 12 bytes
(C, t) = AES-256-GCM-Encrypt(key=K, nonce=n, plaintext, aad=context)
encryptedPayload = n ‖ C ‖ t
commitment       = SHA256( str("Neurai/DePIN/commit/v3") ‖ context ‖ K )

for each verified (address, public key P):
    id     = destination_id(address)
    S      = ECDH(e, P)
    W      = HKDF(salt=context, ikm=S, info = str("Neurai/DePIN/wrap/v3") ‖ ser_vector(E) ‖ ser_vector(id))
    n_r    ← random 12 bytes
    (c, τ) = AES-256-GCM-Encrypt(key=W, nonce=n_r, plaintext=K)   # c is 32 bytes, no aad
    recipientKeys[id] = n_r ‖ c ‖ τ
```

`ser_vector(E)` is the 34 bytes `0x21 ‖ E`; `ser_vector(id)` is the length
byte and the serialized id. Discard `e` and `K` after encryption. Plaintext
MUST be non-empty.

### 4.4 Decryption (recipient with private key `d` and destination id `id`)

```
entry  = recipientKeys[id]                       # absent ⇒ not for this recipient, not an error
S      = ECDH(d, ephemeralPubKey)
W      = HKDF(salt=context, ikm=S, info = str("Neurai/DePIN/wrap/v3") ‖ ser_vector(E) ‖ ser_vector(id))
K      = AES-256-GCM-Decrypt(key=W, nonce=entry[0:12], ct=entry[12:44], tag=entry[44:60])
require commitment == SHA256( str("Neurai/DePIN/commit/v3") ‖ context ‖ K )   # constant time
plain  = AES-256-GCM-Decrypt(key=K, nonce=payload[0:12], ct=payload[12:-16], tag=payload[-16:], aad=context)
```

The context is the one of the use the reader expects: the header of the
message it received, the reply context for an answer, the submit context for
a submission. A failure after the entry is found (either GCM tag, or the
commitment) means the envelope is addressed to this key and **is not
authentic**: do not show or act on it. Never retry with another format.

What this guarantees:

- The envelope is bound to its context: the same envelope under another
  header (another sender, section, time, type or network) does not open.
- Two recipients that **accept** the same envelope obtain the same content key
  and the same text (AES-GCM alone does not commit to its key; the
  commitment does). It does not guarantee that every recipient can open it.
- It does not prove authorship: a recipient can read a text and publish it
  again as a new message of its own.

---

## 5. The message (`CDepinMessage`)

### 5.1 Wire format

```
CDepinMessage :=
  token            string          e.g. "&NEWS/GENERAL"
  senderAddress    string          canonical Legacy or strict ECDSA address
  timestamp        int64           Unix seconds, sender's clock
  messageType      uint8           0x01 private, 0x02 group
  encryptedPayload vector<uint8>   serialized CECIESEncryptedMessage (§4)
  signature        vector<uint8>   DER ECDSA signature (§3.4)
```

The plaintext inside `encryptedPayload` is the message **content as UTF-8
bytes, with no framing**, encrypted under the context of the header (§4.1). Applications that need structure (replies, media
references, formatting) define it inside the content; the protocol does not.
`messageType` is carried and validated (only `0x01`/`0x02` are accepted) but
the node treats both identically; `0x02` is the conventional value.

### 5.2 Identifier and signature

```
digest = SHA256d( context(message) ‖ ser_vector(encryptedPayload) )
hash   = hex(reverse(digest))             # the "hash" field, also the paging cursor
signature = DER-ECDSA(senderKey, digest)  # over the unreversed digest
```

The digest covers the whole header (through its context), the network and the
envelope. A verifier recomputes it from what it received and its own network.
The pool is keyed by `hash`; a message with a known hash is rejected as a
duplicate.

### 5.2.1 Reading a message

A recipient reads a message in this order and stops at the first failure:

1. the envelope is format 3 (§4.2);
2. the section is the one it is reading, or one inside it, and the network is
   its own (the envelope proves the header was not changed, not that it is the
   one the reader is after);
3. it computes the context and the digest;
4. the public key belongs to `senderAddress` (`sender_pubkey_hex` is served
   with every message; it can also be read from the chain) and the signature
   verifies over the digest;
5. it opens the envelope (§4.4).

Only then is the text shown, or handed to whatever executes commands, which
applies its own checks. `depinopenmsg` does steps 1 and 3 to 5 with a wallet
key; the caller compares the section.

### 5.3 Acceptance rules (what the node checks on submission)

A message is stored only if **all** of the following hold, in this order:

1. `token` is the pool root or inside its subtree;
2. `messageType ∈ {0x01, 0x02}`;
3. `timestamp ≤ now + 60` (seconds) and not below the durable retention floor;
4. `now − timestamp ≤ expiry` (default 168 h; `messageexpiryhours` in
   `depingetmsginfo`);
5. content ciphertext is nonempty and its plaintext length is at most
   `maxmessagesize` (default 1024 bytes, maximum 10240), excluding GCM and
   key overhead; the conservative ECIES wire bound is
   `114 + maxmessagesize + 94 * maxrecipients`;
6. `encryptedPayload` passes the bounded strict decoder of format 3 (§4.2).
   The node cannot open the envelope: recipients still authenticate it
   (context, commitment and both GCM layers), and an envelope copied under
   another header is admitted and does not open for them;
7. `signature` verifies against the sender's **revealed** public key (§2.3);
8. `senderAddress` has inherited access to `token` (§2.2);
9. every declared recipient has current inherited access to the message
   token (a valid subset is allowed; rejection code `-26`);
10. the pool size limit is not exceeded;
11. `hash` is neither in the pool nor covered by a durable moderation mark.

The node checks that every declared recipient is enabled; it does not require
the complete holder set or prove that a malicious sender has not shared the
plaintext elsewhere. Receivers filter what they can
see by `recipientKeys` membership — an address sees a message when it is the
sender or has an entry in `recipientKeys` — and decryption is the final
boundary.

### 5.4 Expiry

`expired ⇔ now − timestamp > expiry`. The node removes expired messages
periodically (default every 300 s). Remote reception, local wallet reads and
MCP polling exclude expired entries using one reference time per snapshot,
even before cleanup and even for the sender. At exactly `timestamp + expiry`
a message is still eligible. Section counters exclude expired entries;
physical pool statistics can include them until cleanup releases storage.
Expiry cannot erase copies already downloaded. Messages are not
persistent unless the operator enables `-depinpoolpersist`; clients MUST NOT
assume a message is retrievable later. When enabled, restoration validates
historical signatures and format without requiring all historical participants
to retain access; every new read still requires the reader's current permission.
Moderation marks persist independently. State v3 synchronously stores retained
admissions and moderation. What earlier versions stored (`depinstate-v2`,
`depinpool.dat`) uses other envelope formats and is not read. See
[the state contract](depin-pool-state.md) for exact limits, sequence read
signatures, retention toggles and recovery.

---

## 6. RPC authentication and transport (protocol 6)

[depin-request-signatures.md](depin-request-signatures.md) defines the exact
common object, binary field order, single-SHA256 request/response domains,
normalization, limits, bootstrap and structured errors. It supersedes the
protocol 2 positional interface and REQ/GET/CLEAR/RESP/READ-SEQUENCE-v1
preimages. Every migrated method takes one request object, either positional
or named as request. Wallet signing is `depinsignrpc method request` for an
explicit remote identity; previous signing helpers are removed.

Authenticate the response against the pinned key and the request hash
computed locally before decoding/decrypting. Public queries remain public;
their signed reply binds every query argument and a fresh request ID.
Addressed results/errors are encrypted for that address, subject to early
parse/readiness/key-lookup failures documented in the contract. A wrapped
error is never a successful operation.

A pin includes endpoint, network, pool root and pool key. Without an independent
pin, self-consistent first contact is trust on first use and can be replaced by
an active intermediary. Never silently change a recorded pin. Signed bootstrap
supplies the current random instance and server_time_ms. Restarts, key resets
and backward clock jumps invalidate operation proofs. Nonce loss does not
invalidate a durable sequence cursor.

## 7. Integration, limits and security

Use [the client guide](depinreceivemsg.md) for challenge/read/list/submit/purge
flows, and [the state contract](depin-pool-state.md) for cursor and storage
recovery. [Current authorization](depin-authorization.md) uses the connected
active chain under cs_main, including cached changes and reorganizations;
service readiness precedes index reads. Local wallet/bot operations retain
current permission checks and admission validation. A challenge authorizes an
operation; it is not a content-decryption key. A node that also holds a
recipient key (for a wallet or bot) can decrypt content addressed to that key;
a relay holding only its pool key cannot.

Private timestamps allow ±60000 ms inclusive; public/bootstrap queries use
fresh request correlation instead of a timestamp gate. Challenges last 30 s,
chained receive challenges 300 s, at most four per address and 10000 total.
Replay protection for timestamp operations is separately bounded at 10000
entries and never evicts live proofs to accept a new request. Loss of an
acknowledgment does not imply that a signed operation did not execute.

Content limits remain 20 recipients by default, maximum 50; 1024 plaintext
bytes by default, maximum 10240; signed-message decode at most 16384 bytes;
4 MiB plaintext per reply; expiry 168 h by default, maximum 720 h. Storage
version 3, envelope format 3 and cursor version 1 are numbered independently
of the RPC protocol.

Pool key derivation remains `m/44'/<coin>'/200'/<change>/0` of the service
wallet, coin 1 on testnet/regtest, change 1 on testnet and 0 otherwise. Mainnet
coin 1900 is reserved here; the historical Legacy wallet derivation remains
unchanged. Do not alter wallet derivation during this RPC migration.

Always verify content signatures, both GCM authentication tags and the
commitment, under the context of the header received; a strict structural
decoder does not authenticate another user's content. Generate fresh
ephemeral keys, content keys and GCM nonces; discard ephemeral scalars and
content keys.
The service learns sender, asset, timestamps and recipient IDs from the inner
message. No anonymity or forward secrecy against theft of a recipient's
static secp256k1 private key is provided. Revocation prevents authorized future
downloads and does not erase ciphertext already downloaded. A newly added
holder does not gain a recipient key for old messages automatically.

The recipient list is fixed by the sender. Recipient authorization rejects unauthorized declared
recipients on an honest node, but cannot constrain a malicious server/sender
or plaintext sharing. Comparing independent RPC sources and a local allowlist
is client policy still to implement. A poolsig authenticates the response,
not on-chain truth about its directory. TLS and deployment proxy restrictions
remain operator responsibilities; local wallet RPCs must stay private.

## 8. Executable vectors and tests

The [15 canonical RPC request vectors](../src/test/data/depin_rpc_v6.json)
come from an independent Python encoder in contrib/devtools. C++ checks the
exact bytes/hash/preimage. The [envelope vectors](../src/test/data/depin_format3.json)
come from `contrib/devtools/depin-format3-vectors.py`, an implementation of §4
and §5 that shares no code with the node: every intermediate value (context,
shared secrets, wrap keys, commitment, digest) and 18 cases, valid and
altered, each with the step where each reader stops. The cases that change a
header carry a new valid signature, so that what fails is the envelope. C++
checks all of them. The independent functional client reconstructs all
request/response preimages, builds envelopes of format 3, compares wallet
signing with signmessage and verifies responses before decryption. The
protocol 6 walkthrough also writes public interoperability material (signed
request and bootstrap response) in its disposable test directory, without
wallet keys or RPC cookies.

Run `contrib/depin/regtest_walkthrough.sh` after configuring/building the
functional test environment. Permission and pool-state functional tests cover
real connected chain changes, storage and process kills. The historical
protocol 2 and 5 authentication vectors are not valid protocol 6 examples. The membership context
revision is implemented; external library migration remains future work; no node-only
result certifies an external library or all production failure modes.
