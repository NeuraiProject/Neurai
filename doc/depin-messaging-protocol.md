# DePIN Messaging Protocol Specification (protocol 3)

This document specifies the DePIN messaging protocol of Neurai at the level an
implementer needs to write an independent client or library in any language:
the on-chain access model, byte-exact wire formats, content cryptography and
references to the RPC authentication contract. It is normative
where it says MUST/SHOULD; the node source is the reference implementation.

Companion documents:

- [`depin-pool-state.md`](depin-pool-state.md) — strict wire budgets, signed
  admission-sequence reads, durable moderation and state v2 migration.
- [`depinreceivemsg.md`](depinreceivemsg.md) — the RPC-by-RPC integration
  guide (argument semantics, examples, paging). This specification defers to
  it for parameter details and does not repeat them.
- [`README.md`](README.md) — operating a service node (configuration,
  indexes, wallet requirements).
- `contrib/depin/regtest_walkthrough.sh` — an executable end-to-end run of
  protocol 3 functional regressions against a disposable regtest node.

Reference code: `src/depinmsgpool.{h,cpp}` (message, pool, access),
`src/depinecies.{h,cpp}` (ECIES), `src/depinchallenge.{h,cpp}`
(authentication), `src/depinpoolkey.{h,cpp}` (reply signing/encryption),
`src/depinrpc.{h,cpp}` and `src/rpc/depin.cpp` (RPC 3 codec/dispatcher),
`src/rpc/messages.cpp` (local wallet/query business logic). A JavaScript implementation of the message
cryptography exists in the
[DePIN-Messaging](https://github.com/NeuraiProject/DePIN-Messaging) repository.

DePIN messaging is experimental and currently available on **testnet and
regtest** only. Protocol **3** rejects old RPC formats/signatures. Clients
MUST verify the bootstrap and require protocol 3. External SDKs are to be
updated after the node; no external implementation is certified here.

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
validate intended recipients. Neither a signature nor P1 proves an arbitrary
server follows authorization rules.

What is, and is not, confidential:

- Confidential: message content (per-recipient ECIES), challenge nonces and
  every reply bound to an address (encrypted for that address).
- Public: token names, the section hierarchy, who holds what, which
  addresses have revealed keys — all of it is chain data. Sections protect
  content, not membership. The envelope metadata of a submission (sender,
  token, timestamp, recipient hash160s) is visible to the node.

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
for publishing stops at `R` (§8.3).

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
| `depingetancestorrecipients "token" (max) ("stop_at")` | active holders with revealed keys over the ancestor chain (§8.3) |

### 2.3 Revealed public keys

Every cryptographic operation that targets an address needs its public key,
and the chain only exposes a hash160 until the address **spends** at least
once. The node keeps a public-key index (`-pubkeyindex`) of keys recovered
from spends. An address that has never spent:

- cannot be a recipient (no key to encrypt for);
- cannot authenticate (the node encrypts the challenge for its key);
- cannot publish (the node verifies the message signature against its key).

Clients MUST treat "address has not revealed its public key" as an expected,
user-facing condition and instruct the user to spend once from the address.

### 2.4 Address types

Authentication and recipient encryption are defined for **P2PKH addresses
backed by compressed secp256k1 keys** (`hash160(compressed pubkey)`). Other
address types cannot authenticate and are not recipients.

---

## 3. Cryptographic primitives and encodings

| Primitive | Definition |
|---|---|
| Curve | secp256k1. Public keys are **compressed** (33 bytes, `02`/`03` prefix). |
| `SHA256(x)` | FIPS 180-4 SHA-256. |
| `SHA256d(x)` | `SHA256(SHA256(x))` (Bitcoin "hash256"). |
| `hash160(x)` | `RIPEMD160(SHA256(x))`. The P2PKH payload of an address is `hash160(pubkey)`. |
| `HMAC`, CBC | Present in the source for historical reasons; **not used** by this protocol. |
| `ECDH(d, Q)` | libsecp256k1 `secp256k1_ecdh` with the **default hash function**: `SHA256(prefix ‖ x)` where `(x, y) = d·Q`, `prefix = 0x02` if `y` is even, `0x03` if odd. Output 32 bytes. |
| `KDF(secret, n)` | Counter-mode SHA-256: `T_i = SHA256(secret ‖ BE32(i))`, `i = 1, 2, …`; output is the first `n` bytes of `T_1 ‖ T_2 ‖ …`. For `n = 32` this is simply `SHA256(secret ‖ 00000001)`. |
| AES-256-GCM | 32-byte key, **12-byte nonce**, **16-byte tag**, **no AAD**. Ciphertext has the plaintext's length. |
| Base64 | RFC 4648 with padding, for compact signatures. |
| Hex | Lowercase, for everything else. |

### 3.1 Serialization

Message and ECIES structures use Bitcoin's serialization. RPC 3 uses the
separate U32-length codec in the [request contract](depin-request-signatures.md):

- integers little-endian (`int64` = 8 bytes, `uint8` = 1 byte);
- `CompactSize(n)`: `n < 253` → 1 byte; `≤ 0xFFFF` → `0xFD` + LE16;
  `≤ 0xFFFFFFFF` → `0xFE` + LE32; else `0xFF` + LE64;
- `string` and `vector<uint8>`: `CompactSize(len) ‖ bytes`;
- `CPubKey`: `CompactSize(len) ‖ bytes` (`0x21` + 33 bytes);
- `uint160`: 20 raw bytes (the same bytes as in the address payload);
- `map<K, V>`: `CompactSize(count)` followed by `K ‖ V` pairs **in ascending
  byte order of K** (`memcmp`).

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
message-magic wrapper below is unchanged; the v3 signed texts are specified
in [depin-request-signatures.md](depin-request-signatures.md).

```
msghash(text) = SHA256d( ser_string("Neurai Signed Message:\n") ‖ ser_string(text) )
```

where `ser_string` is `CompactSize(len) ‖ bytes`. The signature is a 65-byte
**compact recoverable** ECDSA signature `header ‖ r ‖ s` with
`header = 27 + recid + 4` (compressed keys), encoded in base64. Verification
recovers the public key from the signature and checks
`hash160(recovered) == address payload`. Signing is deterministic
(RFC 6979): the same key and text always give the same signature. Any
wallet's `signmessage` / `verifymessage` is interoperable.

### 3.4 Message signatures (DER)

Used for `CDepinMessage.signature` only: a **DER-encoded** ECDSA signature
over the 32-byte message digest (§5.2), verified with the sender's revealed
public key (`secp256k1_ecdsa_verify`; the node normalizes high-`s` values,
but producers SHOULD emit low-`s`). Typically 70–72 bytes.

---

## 4. ECIES envelope (`CECIESEncryptedMessage`)

One construction serves three purposes: the message content (§5), the
submission envelope for the pool key (§8.3), and every reply bound to an
address (§6.2). It encrypts a plaintext once for **N recipients** identified
by address.

### 4.1 Wire format

```
CECIESEncryptedMessage :=
  ephemeralPubKey    CPubKey                      (0x21 ‖ 33 bytes)
  encryptedPayload   vector<uint8>                nonce(12) ‖ ciphertext ‖ tag(16)
  recipientKeys      map<uint160, vector<uint8>>  hash160 → nonce(12) ‖ wrappedKey(32) ‖ tag(16)
```

Each recipient entry is exactly 60 bytes; `encryptedPayload` is
`28 + len(plaintext)` bytes. The hex of this serialization is what travels in
`encrypted_payload_hex`, in `depinsubmitmsg.encrypted` and in every
`encrypted` reply field.

### 4.2 Encryption

```
e      ← random 32-byte scalar (ephemeral private key), E = e·G (compressed)
K      = KDF(e, 32)                       # content key, derived from the ephemeral SCALAR
n      ← random 12 bytes
(C, t) = AES-256-GCM-Encrypt(key=K, nonce=n, plaintext)
encryptedPayload = n ‖ C ‖ t

for each recipient public key P (address = hash160(P)):
    S      = ECDH(e, P)
    W      = KDF(S, 32)
    n_r    ← random 12 bytes
    (c, τ) = AES-256-GCM-Encrypt(key=W, nonce=n_r, plaintext=K)   # c is 32 bytes
    recipientKeys[hash160(P)] = n_r ‖ c ‖ τ
```

Note the content key is the KDF of the ephemeral **private scalar**, not of a
random key: anyone holding `e` can decrypt, so `e` MUST be discarded after
encryption. Plaintext MUST be non-empty.

### 4.3 Decryption (recipient with private key `d`, address `A`)

```
entry  = recipientKeys[hash160(d·G)]      # absent ⇒ "not encrypted for this recipient"
S      = ECDH(d, ephemeralPubKey)
W      = KDF(S, 32)
K      = AES-256-GCM-Decrypt(key=W, nonce=entry[0:12], ct=entry[12:44], tag=entry[44:60])
plain  = AES-256-GCM-Decrypt(key=K, nonce=payload[0:12], ct=payload[12:-16], tag=payload[-16:])
```

Both GCM tags MUST verify; a failure is an integrity error, not a decoding
issue.

---

## 5. The message (`CDepinMessage`)

### 5.1 Wire format

```
CDepinMessage :=
  token            string          e.g. "&NEWS/GENERAL"
  senderAddress    string          base58 P2PKH address
  timestamp        int64           Unix seconds, sender's clock
  messageType      uint8           0x01 private, 0x02 group
  encryptedPayload vector<uint8>   serialized CECIESEncryptedMessage (§4)
  signature        vector<uint8>   DER ECDSA signature (§3.4)
```

The plaintext inside `encryptedPayload` is the message **content as UTF-8
bytes, with no framing**. Applications that need structure (replies, media
references, formatting) define it inside the content; the protocol does not.
`messageType` is carried and validated (only `0x01`/`0x02` are accepted) but
the node treats both identically; `0x02` is the conventional value.

### 5.2 Identifier and signature

```
digest = SHA256d( ser_string(token) ‖ ser_string(senderAddress) ‖ LE64(timestamp)
                  ‖ uint8(messageType) ‖ ser_vector(encryptedPayload) )
hash   = hex(reverse(digest))             # the "hash" field, also the paging cursor
signature = DER-ECDSA(senderKey, digest)  # over the unreversed digest
```

The signed bytes are exactly the wire serialization of the first five
fields, so a verifier re-serializes what it received and needs nothing else.
The pool is keyed by `hash`; a message with a known hash is rejected as a
duplicate.

### 5.3 Acceptance rules (what the node checks on submission)

A message is stored only if **all** of the following hold, in this order:

1. `token` is the pool root or inside its subtree;
2. `messageType ∈ {0x01, 0x02}`;
3. `timestamp ≤ now + 60` (seconds);
4. `now − timestamp ≤ expiry` (default 168 h; `messageexpiryhours` in
   `depingetmsginfo`);
5. content ciphertext is nonempty and its plaintext length is at most
   `maxmessagesize` (default 1024 bytes, maximum 10240), excluding GCM and
   key overhead; the conservative ECIES wire bound is
   `80 + maxmessagesize + 81 * maxrecipients`;
6. `encryptedPayload` passes the bounded strict ECIES decoder: valid compressed
   ephemeral key, minimal CompactSize, 1..`maxrecipients` entries in canonical
   hash160 order without duplicates, exactly 60-byte wrapped keys and no
   trailing bytes. Recipients still authenticate both GCM layers;
7. the pool size limit is not exceeded;
8. `signature` verifies against the sender's **revealed** public key (§2.3);
9. `senderAddress` has inherited access to `token` (§2.2);
10. every declared recipient has current inherited access to the message
    token (a valid subset is allowed; rejection code `-26`);
11. `hash` is neither in the pool nor covered by a durable moderation mark,
    and the timestamp is above the durable retention floor.

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
Moderation marks persist independently. State v2 synchronously stores retained
admissions and moderation; it explicitly migrates v1 without deleting the
original. See [the state contract](depin-pool-state.md) for exact limits,
sequence read signatures, retention toggles, migration and recovery.

---

## 6. RPC authentication and transport (protocol 3)

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
version 2 and cursor version 1 do not imply RPC version 2.

Pool key derivation remains `m/44'/<coin>'/200'/<change>/0` of the service
wallet, coin 1 on testnet/regtest, change 1 on testnet and 0 otherwise. Mainnet
coin 1900 is reserved here; the historical Legacy wallet derivation remains
unchanged. Do not alter wallet derivation during this RPC migration.

Always verify content signatures and both GCM authentication tags; a strict
structural decoder does not authenticate another user's content. Generate
fresh ephemeral keys, content keys and GCM nonces; discard ephemeral scalars.
The service learns sender, asset, timestamps and recipient IDs from the inner
message. No anonymity or forward secrecy against theft of a recipient's
static Legacy private key is provided. Revocation prevents authorized future
downloads and does not erase ciphertext already downloaded. A newly added
holder does not gain a recipient key for old messages automatically.

The recipient list is fixed by the sender. P1 rejects unauthorized declared
recipients on an honest node, but cannot constrain a malicious server/sender
or plaintext sharing. Comparing independent RPC sources and a local allowlist
is client policy still to implement. A poolsig authenticates the response,
not on-chain truth about its directory. TLS and deployment proxy restrictions
remain operator responsibilities; local wallet RPCs must stay private.

## 8. Executable vectors and tests

The [13 canonical RPC request vectors](../src/test/data/depin_rpc_v3.json)
come from an independent Python encoder in contrib/devtools. C++ checks the
exact bytes/hash/preimage. The independent functional client reconstructs
all request/response preimages, compares wallet signing with signmessage and
verifies responses before decryption. The protocol 3 walkthrough also writes
public interoperability material (signed request and bootstrap response) in
its disposable test directory, without wallet keys or RPC cookies.

Run `contrib/depin/regtest_walkthrough.sh` after configuring/building the
functional test environment. Permission and pool-state functional tests cover
real connected chain changes, storage and process kills. The historical
protocol 2 authentication vectors are not valid RPC 3 examples. P7 context
revision and external library migration remain future work; no node-only
result certifies an external library or all production failure modes.
