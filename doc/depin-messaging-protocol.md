# DePIN Messaging Protocol Specification (protocol 2)

This document specifies the DePIN messaging protocol of Neurai at the level an
implementer needs to write an independent client or library in any language:
the on-chain access model, the byte-exact wire formats, every cryptographic
construction, the authentication scheme and the RPC surface. It is normative
where it says MUST/SHOULD; the node source is the reference implementation.

Companion documents:

- [`depinreceivemsg.md`](depinreceivemsg.md) — the RPC-by-RPC integration
  guide (argument semantics, examples, paging). This specification defers to
  it for parameter details and does not repeat them.
- [`README.md`](README.md) — operating a service node (configuration,
  indexes, wallet requirements).
- `contrib/depin/regtest_walkthrough.sh` — an executable end-to-end run of
  the protocol against a regtest node, with 41 checks.

Reference code: `src/depinmsgpool.{h,cpp}` (message, pool, access),
`src/depinecies.{h,cpp}` (ECIES), `src/depinchallenge.{h,cpp}`
(authentication), `src/depinpoolkey.{h,cpp}` (reply signing/encryption),
`src/rpc/messages.cpp` (RPCs). A JavaScript implementation of the message
cryptography exists in the
[DePIN-Messaging](https://github.com/NeuraiProject/DePIN-Messaging) repository.

DePIN messaging is experimental and currently available on **testnet and
regtest** only. Protocol 2 is a breaking change from protocol 1; clients MUST
check `depingetmsginfo.protocol == 2`.

---

## 1. Overview

DePIN messaging is an **off-chain, encrypted, ephemeral** message pool whose
membership is defined by **on-chain token holdings**. Nothing in it touches
the blockchain: no fees, no permanence; messages expire (7 days by default).

Parties:

| Party | Holds | Role |
|---|---|---|
| **Holder / client** | its own secp256k1 private key | Reads and publishes. Encrypts, decrypts, signs locally. Never hands its key to anything. |
| **Service node** (`neuraid`) | the **pool key** | Keeps the in-memory pool for one token subtree, enforces access, authenticates readers, signs every reply. Cannot read message content. |
| **RPC proxy** (e.g. `neurai-rpc-proxy`) | the node's RPC credentials | Whitelists the DePIN RPCs, applies per-IP abuse control. Untrusted by design: the protocol assumes it may withhold, replay or tamper, and makes that detectable. |
| **Token owner** | the owner token `&TOKEN!` | Issues holdings and sections, freezes holders, purges the pool. |

Trust model in one sentence: the **chain** decides who may participate, the
**holder's key** proves identity and decrypts, the **pool key** (pinned by the
client) authenticates the service, and **nothing in between** can read,
forge or silently alter anything.

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

Query RPCs (all public, cacheable, no authentication):

| RPC | Returns |
|---|---|
| `checkdepinvalidity "asset" "address"` | `has_asset`, `amount`, `valid` (1 = active), `blocked` |
| `listdepinholders "asset"` | every holder with `valid` |
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
| `HMAC`, CBC | Present in the source for historical reasons; **not used** by protocol 2. |
| `ECDH(d, Q)` | libsecp256k1 `secp256k1_ecdh` with the **default hash function**: `SHA256(prefix ‖ x)` where `(x, y) = d·Q`, `prefix = 0x02` if `y` is even, `0x03` if odd. Output 32 bytes. |
| `KDF(secret, n)` | Counter-mode SHA-256: `T_i = SHA256(secret ‖ BE32(i))`, `i = 1, 2, …`; output is the first `n` bytes of `T_1 ‖ T_2 ‖ …`. For `n = 32` this is simply `SHA256(secret ‖ 00000001)`. |
| AES-256-GCM | 32-byte key, **12-byte nonce**, **16-byte tag**, **no AAD**. Ciphertext has the plaintext's length. |
| Base64 | RFC 4648 with padding, for compact signatures. |
| Hex | Lowercase, for everything else. |

### 3.1 Serialization

All binary structures use Bitcoin's serialization:

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
- signatures are computed over the **unreversed** 32-byte digest.

### 3.3 Message signing (recoverable, `signmessage`-compatible)

Used for challenge requests, challenge responses and `poolsig`.

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
5. `encryptedPayload` is non-empty and `≤ maxmessagesize × maxrecipients`
   bytes (defaults 1024 × 20);
6. **if** `encryptedPayload` deserializes as a `CECIESEncryptedMessage`,
   its `recipientKeys` has at most `maxrecipients` entries (default 20, hard
   cap 50). A payload that does *not* deserialize is not rejected by this
   rule in the current node: it is stored (within the size cap) but can never
   be delivered, because visibility is decided by `recipientKeys` membership
   and an unparseable payload has no entries (only its sender sees it listed,
   and cannot decrypt it either). Producers MUST emit well-formed payloads;
   a future node version may reject malformed ones outright;
7. the pool size limit is not exceeded;
8. `signature` verifies against the sender's **revealed** public key (§2.3);
9. `senderAddress` has inherited access to `token` (§2.2);
10. `hash` is not already in the pool.

The node does **not** check that `recipientKeys` matches the legitimate
holder set: the sender chooses its readers, and a sender can always add an
extra reader (it knows the plaintext anyway). Receivers filter what they can
see by `recipientKeys` membership — an address sees a message when it is the
sender or has an entry in `recipientKeys` — and decryption is the final
boundary.

### 5.4 Expiry

`expired ⇔ now − timestamp > expiry`. The node removes expired messages
periodically (default every 300 s) and never returns them. Nothing is
persistent unless the operator enables `-depinpoolpersist`; clients MUST NOT
assume a message is retrievable later.

---

## 6. Transport and reply authentication

### 6.1 JSON-RPC

Every operation is a standard Neurai JSON-RPC 1.0/2.0 call on the node's RPC
port, normally reached through an RPC proxy as `POST /rpc` with the usual
`{"jsonrpc","id","method","params"}` body. Positional and named parameters
are both accepted; a skipped optional parameter arrives as `null`. There is
no other port, socket or endpoint.

### 6.2 Reply wrappers

Every DePIN reply is one of two shapes, and **both carry `poolsig`**:

```json
{ "body": "<hex of UTF-8 JSON>", "poolsig": "<base64>" }          plain reply
{ "encrypted": "<hex CECIESEncryptedMessage>", "poolsig": "<base64>" }   reply bound to an address
```

- *Plain* replies (`depingetmsginfo`, `depinpoolstats`, `depinmcpstatus`,
  `depinlistsections` without arguments) put the canonical JSON of the
  result, hex-encoded, in `body`.
- *Bound* replies (everything that takes an address) encrypt the result JSON
  with §4 for that address's revealed key, single recipient keyed by the
  address's hash160.

The hex is what is signed, so a client hashes **the string it received** and
never a re-serialization.

### 6.3 `poolsig`

```
preimage = "DEPIN-RESP|" method "|" token "|" address "|" challenge "|" sha256hex(bodystr)
poolsig  = signmessage(poolKey, preimage)                       # §3.3
```

- `method`: the RPC name; `token`, `address`, `challenge`: the request's
  values, each `""` when the method has no such argument (`depinchallenge`
  and `depinsubmitmsg` have an empty `challenge`). Plain replies that take
  no token — `depingetmsginfo`, `depinpoolstats`, `depinmcpstatus`,
  `depinlistsections` without arguments — bind the **pool root** as `token`;
  `depingetancestorrecipients` binds the token it was asked about. A client
  therefore needs to know the pool root to verify those replies, which is
  why the root is part of the pin (§6.4);
- `bodystr`: the **ASCII hex string** of `body` or `encrypted`, exactly as
  received; `sha256hex` is lowercase hex of a single SHA-256 of it;
- verified against the pool key: `recover(poolsig, msghash(preimage))` MUST
  equal the pinned key (`depinpoolpkey`), equivalently
  `verifymessage depinpoolkeyaddress poolsig preimage`.

With a pinned pool key, clients MUST verify `poolsig` **before** decoding
or decrypting, and MUST treat a missing or invalid `poolsig` as a protocol
error. Binding the request's token, address and challenge into the preimage
makes a reply unusable for any other request, so a proxy cannot substitute
one reply for another. The one situation in which there is no pin yet — the
first `depingetmsginfo` of a first contact — is handled in §6.4 and is the
only time a `body` is decoded before being authenticated.

### 6.4 The pin, first contact and the pool root

A **pin** is the tuple

```
( service identity, pool root token, pool public key )
```

— the endpoint the client talks to (URL or operator), the `token` the
service serves, and `depinpoolpkey` (with `depinpoolkeyaddress` derivable
from it). The root belongs in the pin because the plain replies bind it into
the `poolsig` preimage (§6.3): a client that only stored the key cannot even
build the preimage of `depingetmsginfo` without knowing the token. Both are
recorded together after bootstrap and used together afterwards.

`depingetmsginfo` publishes `depinpoolpkey` and `token` **inside `body`**,
and `body` is signed by that same key. On first contact there is therefore
nothing to authenticate the reply against. The cases MUST be kept apart:

- **Full pin available** (key and root shipped with the application,
  published by the token's project, confirmed out of band, or recorded on an
  earlier contact): build the preimage from the *pinned* root, verify
  `poolsig` against the *pinned* key **before** interpreting `body`; then the
  announced `depinpoolpkey` and `token` MUST equal the pin. A mismatch is an
  alert to surface to the user — never something to accept silently or to
  "re-pin" over.
- **Key pinned, root not yet known** (e.g. the application ships only the
  key): read **`body.token` and nothing else** as untrusted input, build the
  preimage with it, verify `poolsig` against the pinned key, and only then
  interpret the rest of `body`. A successful verification confirms the token
  too, since the signed bytes contain it; store it alongside the key. No
  other field may be acted on before the signature verifies.
- **No pin at all** (trust on first use): decode `body` only as **untrusted
  TOFU material**, recover the signer from `poolsig` (§3.3) using
  `body.token` in the preimage, and check that it equals the announced
  `depinpoolpkey` and hashes to `depinpoolkeyaddress`; only then record
  `(service, token, key)` as the pin, with whatever confirmation the
  application's policy requires. This self-consistency check proves that the
  reply was produced by the holder of the announced key and that token, key
  and signature were not altered independently of each other. It does
  **not** authenticate the service: a proxy that substitutes its own key (and
  token) on first contact is undetectable by the protocol alone. Only an
  out-of-band pin removes that exposure, which is why projects SHOULD publish
  their service's pool key together with its pool root.

The pool key is derived deterministically from the service wallet
(`m/44'/<coin>'/200'/<change>/0`, change = 1 on testnet, 0 otherwise), so a
correctly operated service keeps its key.

What a wrong pin can cost is bounded: content is never readable by the node,
so the exposure is metadata and availability (withheld or trimmed replies),
which is exactly what `poolsig` against a correct pin prevents.

---

## 7. Authentication

Reads and purges are authenticated per call with a **single-use challenge**
signed by the holder's key. There are no sessions, cookies or bearer tokens:
nothing a proxy observes lets it act on the holder's behalf.

### 7.1 Requesting a challenge — `DEPIN-REQ`

The request itself is signed, so that nobody can spend a holder's quota or
evict its live challenges by merely naming its address:

```
t        = current Unix time in MILLISECONDS (client clock)
preimage = "DEPIN-REQ|" type "|" token "|" address "|" t       type ∈ {receive, admin}
sig      = signmessage(holderKey, preimage)                   # §3.3
call     depinchallenge token address t sig (type)
```

The node accepts the request only if **all** hold, in this order, and
touches no per-address state until step 3:

1. `|t − node_now_ms| ≤ 60 000` and `sig` verifies for `address`;
2. `address` is P2PKH with a revealed key, `token` is inside the pool, and
   `address` has access (`receive`: holder access; `admin`: owner access);
3. `sig` has not been presented before (replay guard, remembered for
   120 s);
4. the address is under its issuance quota (default 20 per minute).

Milliseconds matter: signatures are deterministic, so two requests with the
same `t` are the same request and the second is a replay. A client MUST use
its real clock and MUST NOT reuse a signed request.

The reply is a bound reply (§6.2) for `address`; decrypted:

```json
{ "challenge": "<64 hex>", "expires_in": 30, "type": "receive" }
```

A challenge is bound to `(token, address, type)`, expires after 30 s and is
consumed by its first valid use. The node keeps at most 4 live challenges per
address (issuing a 5th evicts the oldest) and 10 000 in total.

### 7.2 Using a challenge — `DEPIN-GET` / `DEPIN-CLEAR`

```
receive:  preimage = "DEPIN-GET|"   token "|" address "|" challenge
admin:    preimage = "DEPIN-CLEAR|" token "|" address "|" challenge
sig      = signmessage(holderKey, preimage)
```

`token` MUST be the one the challenge was issued for (`depinreceivemsg`,
`depinlistsections` scope, `depinclearmsg` scope — by equality, never by
subtree). The node verifies form → challenge exists and is unexpired →
signature → access (re-checked at use) → consume, atomically. A failed call
does **not** consume the challenge, so a third party cannot burn it.

### 7.3 Chaining

Every authenticated bound reply (`depinreceivemsg`, `depinlistsections` in
address mode) contains `next_challenge` and `next_expires_in` (300 s): a
fresh challenge for the same `(token, address, receive)`. Signing it for the
next call replaces another `depinchallenge`, so a client that keeps reading
calls `depinchallenge` once per conversation. Chained challenges do not count
against the issuance quota but do count against the 4-live cap.

---

## 8. RPC surface

Argument semantics and examples are in [`depinreceivemsg.md`](depinreceivemsg.md).

### 8.1 Service and chain information (plain replies, no auth)

| RPC | Decoded `body` |
|---|---|
| `depingetmsginfo` | `enabled, token, cipher ("AES-256-GCM"), maxrecipients, maxmessagesize, messageexpiryhours, maxpoolsizemb, messages, memoryusage, protocol (2), depinpoolpkey, depinpoolkeyaddress, depinwallet` |
| `depinpoolstats` | aggregate counters (`total_messages`, sizes, by age) |
| `depinmcpstatus` | status of the optional AI responder |
| `depinlistsections` (no args) | `{"sections": [{name, label, depth}, …]}` — names are public chain data |
| `depingetancestorrecipients token (max) (stop_at)` | recipients of a branch (§8.3); its `poolsig` binds the queried `token`, the four above bind the pool root |

### 8.2 Authenticated reads (bound replies)

| RPC | Challenge | Decrypted result |
|---|---|---|
| `depinchallenge token address timestamp signature (type)` | — (signed request, §7.1) | `challenge, expires_in, type` |
| `depinreceivemsg token address challenge signature (timestamp "after_hash" limit)` | `receive` for `token` | `{messages: [{hash, token, sender, timestamp, message_type, encrypted_payload_hex, signature_hex}], has_more, next_challenge, next_expires_in}`, oldest first; `limit ≤ 1000`; `timestamp` filters `≥ timestamp − 1`; `after_hash` is an exclusive cursor that MUST be a hash visible to the address |
| `depinlistsections address scope challenge signature` | `receive` for `scope` | `{sections: [{name, label, depth, access, messages?}], next_challenge, next_expires_in}` limited to `scope`'s subtree |

Visibility in `depinreceivemsg`: messages in the requested subtree whose
`senderAddress` is the caller or whose `recipientKeys` contains the caller's
hash160.

### 8.3 Publishing — `depinsubmitmsg`

```
depinsubmitmsg {"sender": "<address>", "encrypted": "<hex>"}
```

Client procedure:

1. `depingetmsginfo` → pool root `R`, `maxrecipients`, `depinpoolpkey`,
   `depinpoolkeyaddress` (verify `poolsig`, check the pin).
2. `depingetancestorrecipients token maxrecipients R` → `recipients:
   [{address, pubkey}]`, the deduplicated active holders with revealed keys of
   `token` and of each ancestor **up to and including `R`**. If `truncated`
   is true the set exceeds the limit: the client MUST NOT send (the node
   would refuse anyway). `skipped_no_pubkey` reports holders that cannot be
   reached.
3. Build the `CECIESEncryptedMessage` of the content for those public keys
   (§4.2); the sender SHOULD include itself if it wants to re-read its own
   messages on another device (the node shows a sender its own messages
   regardless, but decryption needs a key entry).
4. Fill `token`, `senderAddress`, `timestamp = now`, `messageType = 0x02`,
   `encryptedPayload`; compute the digest and `signature` (§5.2); serialize
   the `CDepinMessage` (§5.1) and hex-encode it.
5. Encrypt that **hex string** (as ASCII bytes) with §4.2 for the single
   recipient `depinpoolpkey` keyed by `hash160(depinpoolpkey)` (=
   `depinpoolkeyaddress`); hex-encode the envelope.
6. Call `depinsubmitmsg` with `sender` and the envelope hex.

Node procedure: open the envelope with the pool key → hex-decode and
deserialize the `CDepinMessage` → `sender` MUST equal `senderAddress` →
sender has a revealed key → signature verifies → sender has access to
`token` → per-sender submission quota (default 20 per minute) → §5.3 → store.
The reply is bound to the sender: `{result: "success", hash, timestamp, …}`.
The node never sees the content; the envelope only hides the message's
metadata from the proxy.

### 8.4 Purging — `depinclearmsg` (owners)

```
depinclearmsg scope address challenge signature ("all" | hours)
```

Removes the messages of `scope`'s subtree (`""` = the pool root = the whole
pool), all of them or those older than `hours`. Requires an `admin`
challenge issued for exactly `scope` (for the root, request it by name) to an
address with owner access to `scope` (§2.2). Reply bound to the address:
`{removed, remaining, …}`.

### 8.5 Local wallet helpers (never exposed by a proxy)

`depinsignrequest`, `depinsignchallenge`, `depindecrypt`, `depinsendmsg`,
`depingetmsg`, `depinpoolpkey` exist for `neurai-cli` scripting on a node
that holds the keys. A proxy MUST NOT whitelist them; a client library MUST
NOT depend on them.

---

## 9. Client flows

**Bootstrap**

1. `depingetmsginfo`. With a full pin `(service, root, key)`: build the
   preimage from the pinned root, verify `poolsig` against the pinned key,
   then check the announced `depinpoolpkey` and `token` equal the pin. With
   only the key pinned: read `body.token` alone to build the preimage,
   verify, then store the token with the key. Without a pin: decode `body`
   as untrusted material, check the key recovered from `poolsig` equals the
   announced `depinpoolpkey`, and register `(service, token, key)` (§6.4) —
   this is consistency, not authentication of the first contact. Record
   `maxrecipients` and `protocol` from the verified body.
2. `depinlistsections` (plain) for the section list; `checkdepinvalidity` /
   `getpubkey` to explain to the user why an address may not take part.

**Read loop** for `(token, address)`

1. §7.1: sign `DEPIN-REQ`, `depinchallenge`, verify `poolsig`, decrypt →
   `challenge`.
2. Sign `DEPIN-GET`, `depinreceivemsg` with `after_hash` = last seen hash
   (or `""`), `limit` ≤ 1000; verify `poolsig` (preimage includes the
   challenge); decrypt.
3. For each message: verify `signature_hex` over the recomputed digest with
   the sender's key (`getpubkey`, cacheable), check `token` is inside the
   requested subtree, decrypt `encrypted_payload_hex` with §4.3; drop
   anything that fails.
4. Keep `next_challenge`; continue from 2 while `has_more` or on the next
   poll within 300 s; otherwise back to 1.

**Publish**: §8.3. **Purge**: §8.4 with an `admin` challenge.

On HTTP 429 from the proxy, wait `Retry-After` seconds; do not retry sooner.

---

## 10. Abuse control and errors

| Layer | Rule | Effect |
|---|---|---|
| Node, per address | challenges issued + messages accepted ≤ `depinratelimit`/minute (default 20), counting only the address's own authenticated requests | JSON-RPC error `-1` "Rate limited…" |
| Node, per address | ≤ 4 live challenges; issuance requests single-use within ±60 s | oldest evicted / `-32600` "Request authentication failed…" |
| Node, global | ≤ 10 000 live challenges, ≤ 10 000 remembered requests | `-1` "Too many pending…" |
| Proxy, per IP | `depin*` calls ≤ `depin_rate_limit`/minute (default 60); excess blocks the IP for `depin_ban_minutes` (default 60) | HTTP **429** + `Retry-After`, body `{error, description}` |
| Proxy | method not whitelisted | HTTP 404 `{error: "Not in whitelist"}` |

JSON-RPC error codes used by the DePIN RPCs (`error.code`):

| Code | Meaning here |
|---|---|
| `-32600` | authentication failed: request window/signature/replay, challenge missing/expired/wrong bindings/signature, access lost |
| `-8` | malformed parameter (type, hex, arity, unknown `after_hash`, `limit > 1000`, bad scope) |
| `-5` | invalid address, or address without a revealed public key |
| `-22` | envelope or message fails to deserialize |
| `-25` | envelope cannot be opened with the pool key, or sender/signature/access mismatch on submit |
| `-1` | service disabled, pool key not loaded, rate limited, pool refused the message (§5.3 rule text in `message`) |

`error.message` is human-readable and stable enough to surface; clients
SHOULD branch on `code` and show `message`.

---

## 11. Constants and limits

| Constant | Value |
|---|---|
| `protocol` | 2 |
| Message magic | `"Neurai Signed Message:\n"` |
| Request preimage | `DEPIN-REQ\|<type>\|<token>\|<address>\|<ms>` |
| Challenge preimages | `DEPIN-GET\|…`, `DEPIN-CLEAR\|…` (`<token>\|<address>\|<challenge>`) |
| Reply preimage | `DEPIN-RESP\|<method>\|<token>\|<address>\|<challenge>\|<sha256hex(body)>` |
| Request window | ±60 s (`DEPIN_REQUEST_WINDOW_MS = 60000`) |
| Challenge lifetime | 30 s issued, 300 s chained |
| Live challenges | 4 per address, 10 000 total |
| Issuance / submission quota | 20 per address and minute (node default) |
| Challenge nonce | 32 random bytes, 64 hex |
| Recipients | default 20, hard maximum 50 |
| Content size | default 1024 bytes (`-depinmsgsize`, max 10 240); payload cap = size × recipients |
| Expiry | default 168 h (max 720 h) |
| Timestamp skew accepted on submit | +60 s |
| Page size | `limit ≤ 1000` |
| Pool key derivation | `m/44'/<coin>'/200'/<change>/0` of the service wallet (change = 1 on testnet, 0 on regtest/mainnet) |

---

## 12. Security considerations for implementers

- **Verify before you trust anything**: `poolsig` on every reply against the
  pinned key, then the message signature against the sender's revealed key,
  then decrypt. Never display content that failed any step.
- **The proxy is an adversary in the model.** Everything it can do is
  denial of service; the protocol is designed so that it cannot read, forge
  or substitute — *once the pool key is pinned*. Do not weaken that by
  fetching `depinpoolpkey` on every run and trusting it: the first contact
  is the one moment the protocol cannot protect (§6.4), so make it happen
  once, with an out-of-band pin whenever one exists.
- **Keys never leave the client.** No RPC in protocol 2 takes a private key;
  a library that needs one of the wallet-only helpers (§8.5) is using the
  wrong interface.
- **Discard the ephemeral scalar** after encrypting (§4.2): it decrypts the
  message.
- **Recipient snapshot**: the recipient set is fixed by the sender at
  encryption time; newly issued holders do not gain access to older
  ciphertexts. A sender can include readers outside the holder set; the
  chain-derived set is a policy the client enforces, not a cryptographic
  guarantee about other senders.
- **Metadata is public**: token holdings, sections and revealed keys are on
  chain; the node sees sender, token, timestamp and recipient hash160s. Do
  not promise anonymity.
- **Clocks**: the request window is ±60 s and submissions may be at most 60 s
  in the future; a device with a badly skewed clock cannot authenticate or
  publish. Surface the node's reported time from the error message.
- **Determinism**: never reuse a signed request (§7.1); never reuse a GCM
  nonce with the same key (always random).
- **Expiry is real**: treat the pool as a transient channel; persist what the
  user needs locally.

---

## 13. Test vectors

The vectors below were produced by a regtest node running this protocol
(`contrib/depin/regtest_walkthrough.sh`-style setup). They allow a library to
check its implementation of §3–§7 without a node. Regtest addresses and keys
are used; the constructions are identical on testnet.

All of them are checked by `contrib/depin/verify_vectors.py` (pure Python
plus `cryptography` for AES-GCM) against `contrib/depin/vectors.txt`, which
holds the same values in `key=value` form:

```
python3 contrib/depin/verify_vectors.py contrib/depin/vectors.txt
```

### 13.1 Keys

```
holder address  tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n
holder WIF      cW8vy4nJbZZ4W4L8CsRZp22h3WeWrCXgNwrm1264wW8VAmzHMuJ4   ** REGTEST ONLY -- never fund or reuse this key **
holder pubkey   032abff8246242d5d16a80148018d683ad5415edc1164ab1c3d90e57760bc5f0f3
sender address  tQPMWuhNSyFQnMzf8NgGD5RfN95J17G8hp   (holder of the root &TEST)
sender pubkey   02f737ef588350e23ab39b8cd8599ac45431e7f5cc4bd5d5c0172ef44bf0470728
pool pubkey     03649c7a094c76b63995e60f891c13d9440b12b65b46ad8426cb153789e816b01b
pool address    tDudNSQstiVQu3Prbs7yFwbYtDrcU19eKJ
```

Checks: `hash160(pubkey)` equals the base58check payload of the address;
`WIF` decodes to the private scalar of `pubkey`.

### 13.2 Challenge request (§7.1) and challenge use (§7.2)

```
preimage   DEPIN-REQ|receive|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|1730000000000
signature  IIMy0pTVnBwcxFYaqFsxaGbsNvXPuRbQ7Deey3kMIQ1jRhUZ+HQgoTfeDslbQ83yqyJ6vptnBa1DC31VqD74dhs=

preimage   DEPIN-GET|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
signature  IB7YZLyXRnACLiZFCE4UIyYIfIwMsNqMLtzLuO5CdayuBZLDeXvp9PuYoBnUh84DOyuMPNt3Bvrbrb5yhlzdRd8=
```

Both are `signmessage(holderKey, preimage)` (§3.3): recovering the key from
the base64 signature over `SHA256d(ser_string(magic) ‖ ser_string(preimage))`
yields `holder pubkey`. They are deterministic: an implementation with the
holder WIF MUST reproduce them byte for byte.

### 13.3 Plain reply and `poolsig` (§6.2–6.3): `depingetmsginfo`

```
body     7b22656e61626c6564223a747275652c22746f6b656e223a222654455354222c22636970686572223a224145532d3235362d47434d222c226d6178726563697069656e7473223a32302c226d61786d65737361676573697a65223a313032342c226d657373616765657870697279686f757273223a3136382c226d6178706f6f6c73697a656d62223a3130302c226d65737361676573223a302c226d656d6f72797573616765223a302c226d656d6f727975736167656d62223a302c2270726f746f636f6c223a322c22646570696e706f6f6c706b6579223a22303336343963376130393463373662363339393565363066383931633133643934343062313262363562343661643834323663623135333738396538313662303162222c22646570696e706f6f6c6b657961646472657373223a22744475644e5351737469565175335072627337794677625974447263553139654b4a222c22646570696e77616c6c6574223a2277616c6c65742e646174227d
poolsig  H8MOG9VPuYvSghphjmuIns5quiTry+AMrC4kMIXEGyxXQFArA3wnsXq3C8wyNWCLOYsNNNYJXfGen269pyOqp3g=
preimage DEPIN-RESP|depingetmsginfo|&TEST|||<sha256hex(body)>
```

`body` decodes to the JSON `{"enabled":true,"token":"&TEST","cipher":"AES-256-GCM","maxrecipients":20,"maxmessagesize":1024,"messageexpiryhours":168,"maxpoolsizemb":100,"messages":0,"memoryusage":0,"memoryusagemb":0,"protocol":2,"depinpoolpkey":"03649c7a094c76b63995e60f891c13d9440b12b65b46ad8426cb153789e816b01b","depinpoolkeyaddress":"tDudNSQstiVQu3Prbs7yFwbYtDrcU19eKJ","depinwallet":"wallet.dat"}`. Recovering the key from
`poolsig` over the preimage yields `pool pubkey`.

### 13.4 Bound reply (§4, §6.2): `depinchallenge "&TEST/SEC" <holder> …`

```
encrypted  21031bae8e5d21da97921fde5b34b587fe675993c987127c9e866c6cb8d5499f59258dafef8621927216be40e33dc6f0319b89806c6db29367ee296808c019d3ce6d0ca950533d2cf123ad79acdd6ba19520ab57dad2b5464cdae78b98d4fb0091284cf0bdf59ea500c0481f53c8841506e00c0d985520c1a37c2f6a5cbbd01ba050ef0e568f47a2a5fab7778c1f886fd4bd4e875cca9d1fb4db252457006913a06e37e0b623de9c5a4adde4b067c9eb01c8d12daa260a43e5e3b63329bdc33451e41069223cec93f1b7e583c3f182dc8ff5b09a038eea23413472d55e940f5c5422dd43c5027bd20a215090be78996c9145e59f537b5391bd13f6724aed33a9d01a
poolsig    IEVB0i5eNa1/E0L7yr99MdrVbnYd21MqpemILA0NShpGXBQXSH3PobiKDo5rO6lI1PHSpzgz62/C1vw3lckcHg8=
preimage   DEPIN-RESP|depinchallenge|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n||<sha256hex(encrypted)>
plaintext  {"challenge":"9bbd728c3e35285321c594a6925b537d743ad11da328163715363511deeae8ef","expires_in":30,"type":"receive"}
```

Parsing `encrypted` gives `ephemeralPubKey` (`21` ‖ 33 bytes), the 12 ‖ n ‖ 16
payload and one `recipientKeys` entry keyed by the holder's hash160;
decrypting with the holder WIF (§4.3) yields `plaintext`.

### 13.5 Bound reply bound to a challenge: `depinreceivemsg` (empty pool)

```
challenge  9bbd728c3e35285321c594a6925b537d743ad11da328163715363511deeae8ef
signature  IHpzi6TQUw3zps5j8BOWVegmqd/E1Atnugkto15aROxTCSIMlGFfYubkPXAUwEcuqGqgOnKADnoFxNbbvFz9Pgw=            (over DEPIN-GET|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|<challenge>)
encrypted  2102412d44ae14acca0e0c74019da1f751a55f760033bc61385adea8f75ab140a229a64c586a20e3bc225421d3330ec9befa02fd3abad1b064f56776e3a2fd502e1d0bce752d03cfa5c53b7a25afd8d8b63dce0ec51882d2e8db32666dfb877cd4e42dd749276523a0566f0535c4e4a07e89f6844ca96940d1e486e331d19f3823f39ac684b1c7ef860e6b9e0bde6f899f39854efb4fbf11fa56e1b587bffe77e3cba4763022ac6933997abafc87763cd72e477fea36aceb99bcaf090283024d2fc225f395a1c56a8701c8d12daa260a43e5e3b63329bdc33451e41069223c15aaf005a3967beba4089a8a654a82fe59186868cffa9e5dd2d2f8ea1e2cc1096615e176d8a31addf9c226ad394bbd537d367495b5d9586040e05033
poolsig    HwuCWkrExACb3QnCMyYjNMuagzLxEwDDncrpoAqPx4mgcoi7aXjRkQ0nJsEkNF3+EgEt7mPdeqFAqdaZsYhaH7M=
preimage   DEPIN-RESP|depinreceivemsg|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|9bbd728c3e35285321c594a6925b537d743ad11da328163715363511deeae8ef|<sha256hex(encrypted)>
plaintext  {"messages":[],"has_more":false,"next_challenge":"db3c27106853eafbb8fba74e72f66a5dd307d9a3edb0859eb516f3d6f9b6e3bd","next_expires_in":300}
```


### 13.6 A message (§5): hash, signature, content

As returned by `depinreceivemsg` to the holder after the root holder published
`"Hello from the spec"` to `&TEST/SEC` (recipients: the holder and the sender):

```
token                  &TEST/SEC
sender                 tQPMWuhNSyFQnMzf8NgGD5RfN95J17G8hp
timestamp              1787377444
message_type           group   (0x02)
encrypted_payload_hex  21025e1412adc694b76b41f77ba6d5a19e737c9ec9c317efa0da0c9d6d732c534ea22f639854b52a4af28fb1b37df0ce56f65d19d0c4fd5667f1f4ce1d18595a88e4a6284f1d88f9cfd9ba38379637b3360e02bf893cfba6b589dd64de3933fd0abf043be229f63ca6b48207135bacdfd24d8423c269ba2a22aecd92b9cfdaf2f150755e5d8550eec2d407e95d63586e0f2f9b32fd8b58268bb54584fee07dbb355b2e8fc8d12daa260a43e5e3b63329bdc33451e41069223c567a7b741bff039ebe95413fc54ea16d2cb3c5271403fbbdb37c401791000f9c120f73f9aa51f421a960bc25cd28b5fbed7c8a1216064a095434494b
signature_hex          304402200dc1f0e5d40ea8d78525d41e1d6a4a667cf03576d1052a65e2bbb613eabd97d202203f3a1b31d9109795c6137049bcdc298a06d60daddf7b8b6b8ab626c0e20911c4
hash                   4e397239a092448ba9690e7383e316ebb9fcdccab4c3796f2e4647e34f1ed614
```

Checks:

- `digest = SHA256d(ser_string(token) ‖ ser_string(sender) ‖ LE64(timestamp)
  ‖ 0x02 ‖ ser_vector(encryptedPayload))`; `hex(reverse(digest))` equals
  `hash`.
- `signature_hex` is a DER ECDSA signature over `digest` (unreversed) that
  verifies with `sender pubkey`.
- `encrypted_payload_hex` parses as a `CECIESEncryptedMessage` with two
  recipient entries; decrypting with the holder WIF yields
  `Hello from the spec`.

### 13.7 Negative vectors: what MUST be rejected

Each case is a deterministic mutation of a value above, so any library can
reproduce it; `verify_vectors.py` runs all of them. "Reject" means the
library MUST NOT decode, display or act on the result.

| # | Mutation | Expected outcome |
|---|---|---|
| N1 | §13.3 `poolsig`: base64-decode, XOR `0x01` into byte 40 (inside `s`), re-encode | key recovered over the preimage ≠ `pool pubkey` (or recovery fails) → reject the reply |
| N2 | §13.3 `body`: decode the JSON and re-serialize it with sorted keys (`{"cipher":…,"depinpoolkeyaddress":…}`), hex-encode, verify the original `poolsig` against it | `sha256hex` differs → recovered key ≠ `pool pubkey` → reject. Hash the string received, never a re-serialization |
| N3 | §13.4 `encrypted`: XOR `0x01` into the **last byte** (the outer GCM tag) | outer AES-GCM authentication fails → no plaintext, reject |
| N4 | §13.4 `encrypted`: XOR `0x01` into the last byte of the holder's `recipientKeys` entry (its GCM tag) | key-unwrap authentication fails → reject before touching the payload |
| N5 | §13.4 `encrypted`: decrypt with the **sender** key (`root_holder`) | no `recipientKeys` entry for `hash160(sender pubkey)` → "not encrypted for this recipient" |
| N6 | §13.6 `signature_hex`: XOR `0x01` into the last byte | DER signature does not verify → drop the message |
| N7 | §13.6 `timestamp + 1` (or any field change) with the original `hash` and `signature_hex` | recomputed digest ≠ `hash` and signature fails → drop the message |
| N8 | §13.5 `poolsig` verified with the §13.4 preimage (empty challenge) | binding mismatch → reject: the reply is tied to its challenge |

