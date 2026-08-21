# DePIN client integration guide (protocol 2)

This document describes the RPC surface that an external, non-custodial
DePIN client or library needs in order to authenticate, read and decrypt
messages, and to publish them. It is written for clients that hold the
user's private key themselves; the node never sees it. Everything here is
served by the node's standard JSON-RPC interface, normally through an RPC
proxy such as `neurai-rpc-proxy` that whitelists the DePIN methods. There is
no separate DePIN port.

This is protocol 2, a breaking change: there is no unauthenticated read, no
unsigned reply, no unencrypted reply bound to an address, and no bare-hex
submit. `depingetmsginfo.protocol` is `2`
on nodes that implement it.

DePIN messaging is experimental and off-chain. Token names, token holdings,
section names, and the hierarchy are public blockchain data. Message content
is protected by encryption, not by the existence or membership of a channel.

## Concepts

The node pool is configured with a DePIN token such as `&NEWS`. That token is
the pool root. Its sub-assets are hierarchical sections:

```
&NEWS
&NEWS/GENERAL
&NEWS/GENERAL/SPORT
```

A request for `&NEWS` covers the whole pool subtree. A request for
`&NEWS/GENERAL` covers that section and its descendants, but not its parent or
siblings.

An address is *active* for an asset only when it has a positive balance and is
neither owner-frozen nor self-revoked for that `(asset, address)` pair. Access
is inherited: a holder of `&NEWS` has access to every descendant; a holder of
only `&NEWS/GENERAL` has access only to that branch.

An address takes part only if it has **revealed its public key** on chain
(spent from it at least once): the node encrypts for that key and verifies
signatures against it.

## The pool key and `poolsig`

Each service node derives one secp256k1 *pool key* from a dedicated wallet.
It does two things: it opens the envelope around submitted messages, and it
signs every DePIN reply.

`depingetmsginfo` publishes the identity of the service: the pool public
key. Like every reply that is not bound to an address, it is a signed plain
body:

```json
{ "body": "7b22656e61626c6564223a747275652c...", "poolsig": "IMn3..." }
```

`body` is the hex encoding of the UTF-8 JSON; decoded it reads

```json
{
  "enabled": true,
  "token": "&NEWS",
  "maxrecipients": 20,
  "protocol": 2,
  "depinpoolpkey": "02ab...",
  "depinpoolkeyaddress": "N...",
  "depinwallet": "wallet.dat"
}
```

**Pin the pool key.** Everything `depingetmsginfo` returns arrives through
the proxy you are about to talk to, and a hostile proxy could replace it on
first contact. A client pins `depinpoolpkey` the first time it talks to a
service (trust on first use), stores it with the service's identity, and
treats a later change as an alert, never as something to accept silently. A
pin shipped with the application or published by the token's project removes
even the first-contact exposure. What a wrong pin could cost is bounded:
message content is encrypted per recipient and never readable by the node or
by anything in between; the risks are metadata of the submit envelope and
replies being withheld or trimmed, which is exactly what `poolsig` against a
correct pin prevents.

Once the pool key is pinned, every reply can be checked. `poolsig` is the
pool key's compact signature (base64) over the canonical preimage

```
DEPIN-RESP|<method>|<token>|<address>|<challenge>|<sha256hex(body)>
```

where `body` is the string value of the reply's `encrypted` field (replies
bound to an address) or of its `body` field (plain replies), **exactly as
received**: hash the ASCII hex string, never a re-serialisation of the JSON.
`address` and `challenge` are the request's (empty when the method has none,
e.g. `depingetmsginfo`). The scheme is `signmessage`-compatible, so a client
with a node can check it with
`verifymessage <depinpoolkeyaddress> <poolsig> "<preimage>"`. Verify before
decrypting or decoding: the signature is over the transported string
(encrypt-then-sign). Replies without a valid `poolsig` must be treated as a
protocol error, not as a degraded mode.

## Authentication: `depinchallenge`

```
depinchallenge "token" "address" timestamp "signature" ( "type" )
```

1. `token` — pool root or a section inside it. The challenge is bound to it.
2. `address` — the holder's P2PKH address, public key revealed.
3. `timestamp` — Unix time in **milliseconds** at which the request was signed.
4. `signature` — the address's signature over the request (below).
5. `type` — `receive` (default) for reads; `admin` for `depinclearmsg`.

**The request is signed.** Before asking, sign with the address's key, in the
standard message-signing scheme (`signmessage`; compact signature, base64):

```
DEPIN-REQ|<type>|<token>|<address>|<timestamp>
```

e.g. `DEPIN-REQ|receive|&MYTOKEN/SEC|NXholder...|1730000000000`. The node
accepts the request only if `timestamp` is within 60 s of its own clock and
the signature has never been presented before (signatures are deterministic,
so two requests in the same millisecond would be the same request — use the
real clock). A request that fails this is refused before anything else is
looked at: nothing is stored, no quota is touched. That is the point: without
it, anyone could name a holder's address and spend its issuance quota or
evict its live challenges, since the reply being encrypted only stops the use
of the nonce, not the damage of asking for it. A proxy or network observer
that captures a signed request cannot reuse it either.

A `receive` challenge is issued only to an active holder of `token` or of one
of its ancestors; an `admin` challenge only to a holder of the owner token of
`token` or of an ancestor. Anyone else gets an error and nothing is stored.

The reply is encrypted for `address` and signed:

```json
{ "encrypted": "<hex>", "poolsig": "<base64>" }
```

Decrypt `encrypted` (see "Opening an encrypted reply") to obtain

```json
{ "challenge": "<64 hex>", "expires_in": 30, "type": "receive" }
```

Then sign, with the address's key and the standard message-signing scheme
(`signmessage`; compact signature, base64):

```
DEPIN-GET|<token>|<address>|<challenge>      type receive
DEPIN-CLEAR|<token>|<address>|<challenge>    type admin
```

and pass the challenge and the signature to the RPC within 30 seconds. A
challenge is single-use: the first valid call consumes it. A call that fails
— wrong signature, a nonce issued for other bindings, an address that lost
access in between — does **not** consume it, so nobody can burn your
challenge by guessing. The node keeps at most 4 live challenges per address
(a fifth evicts the oldest) and 10 000 in total, and issues at most
`-depinratelimit` (default 20) per address and minute. Only the address's own
requests — correctly signed, fresh, and passing the access checks — count
towards either: a request that is refused never touches the quota or the
live challenges of the address it names, and nobody but the key holder can
make an accepted one. The limiter itself tracks at most 10 000 addresses;
when it is full of live entries a new address is refused until some leave
the window.

**Chained challenges.** Every authenticated reply (`depinreceivemsg`,
`depinlistsections` in address mode) carries, inside its encrypted body,
`next_challenge`: a fresh nonce for the same token and address, valid for
`next_expires_in` seconds (300). Sign it for the next call exactly like one
from `depinchallenge`. A client that keeps reading within that window calls
`depinchallenge` once and never again — the effect of a session without one:
every request is still individually signed, every nonce is still single-use,
and nothing a proxy sees lets it act on the holder's behalf.

On a node that holds the address's key, `depinsignrequest "address" "token"
("type")` signs a request (returns `timestamp`, `signature`, `preimage`),
`depinsignchallenge "address" "token" "challenge" ("type")` signs a nonce and
`depindecrypt "address" "encrypted"` opens an encrypted reply; all three are
local wallet RPCs for `neurai-cli` scripting and are never whitelisted by
proxies.

## `depinreceivemsg`

```
depinreceivemsg "token" "address" "challenge" "signature" ( timestamp "after_hash" limit )
```

1. `token` — pool root or a section served by the node.
2. `address` — the holder address: recipient selector and encryption target.
3. `challenge` — a `receive` challenge issued for exactly `token` and `address`.
4. `signature` — base64 signature of `DEPIN-GET|<token>|<address>|<challenge>`.
5. `timestamp` — optional Unix timestamp. When non-zero, messages whose
   timestamp is at least `timestamp - 1` are returned.
6. `after_hash` — optional cursor. Use `""` to start at the oldest available
   message.
7. `limit` — optional page size. `0` or omitted returns the unpaginated
   array. Values above 1000 are rejected.

Named invocation works; skipped optional parameters arrive as JSON `null` and
are treated as absent. The old `token address ...` form is rejected by arity
or type before the pool is touched.

Example JSON-RPC request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "depinreceivemsg",
  "params": ["&NEWS/GENERAL", "N...", "<challenge>", "<signature>", 0, "", 25]
}
```

The reply is always `{ "encrypted": "<hex>", "poolsig": "<base64>" }`. Its
`poolsig` preimage uses `method = depinreceivemsg`, the request's `token`,
`address` and `challenge`, and the `encrypted` hex as body. Decrypted, it is
always an object:

```json
{
  "messages": [
    {
      "hash": "...",
      "token": "&NEWS/GENERAL",
      "sender": "N...",
      "timestamp": 1730000000,
      "message_type": "group",
      "encrypted_payload_hex": "...",
      "signature_hex": "..."
    }
  ],
  "has_more": false,
  "next_challenge": "<64 hex>",
  "next_expires_in": 300
}
```

`has_more` is only meaningful with `limit > 0`. Messages are ordered from
oldest to newest. Save the last returned `hash` and use it as `after_hash`
for the next page; sign `next_challenge` for that call. Supplying a hash that
is not in the address's visible result is an error.

The challenge proves control of the address; what the address can actually
read is still fixed cryptographically by the recipient list embedded in each
message. A sender also sees its own messages.

## Opening an encrypted reply

Deserialize the `encrypted` hex as `CECIESEncryptedMessage` and decrypt it
with the private key for the requested address (the recipient entry is keyed
by that address's hash160). The plaintext is exactly the JSON described for
each method. Encryption of replies never depends on anything the client sent
beyond the address: an address without a revealed public key is refused, it
does not get a plaintext reply.

This transport wrapper is independent from the message payload encryption
below.

## Decrypting `encrypted_payload_hex`

DePIN group messages use hybrid encryption:

1. The sender encrypts the content once with a fresh symmetric key.
2. One ECIES-wrapped copy of that symmetric key is included for every
   recipient public key.
3. The recipient locates its wrapped key, decrypts it with its private key,
   then decrypts the common content.

The recipient set is fixed when the message is sent. Acquiring a token later,
revealing a public key later, or being un-frozen later does not grant access to
older ciphertexts that did not include that key.

## Required client validation

Before displaying a decrypted message, a library should:

1. Verify `signature_hex` against the message hash and `sender` address. The
   signed hash is the message identifier itself — the `hash` field — computed
   as:

   ```text
   doubleSHA256(
     serialize(token) ||
     serialize(senderAddress) ||
     int64(timestamp) ||
     uint8(messageType) ||
     vector(encryptedPayload)
   )
   ```

   where `serialize()`/`vector()` are Bitcoin-style serializations
   (compact-size length prefix followed by the bytes) and `messageType` is
   `0x01` for private or `0x02` for group. This is the only signature format
   the node accepts: every message in a pool was verified against the
   sender's revealed public key when it was submitted, and a client verifies
   it again. The signature is DER-encoded secp256k1.
2. Verify that the returned `token` belongs to the requested scope. For a
   root request, any descendant is valid; for `&NEWS/GENERAL`, only
   `&NEWS/GENERAL` and its descendants are valid. Do not require literal token
   equality for a subtree request.
3. Reject malformed, duplicated, or unexpectedly large encrypted payloads
   according to the library's own resource limits.
4. Verify `poolsig` on every reply against the anchored pool key, before
   decrypting. A library must refuse to use a pool key that is neither
   anchored nor pinned.

## Publishing: `depinsubmitmsg`

```
depinsubmitmsg {"sender": "N...", "encrypted": "<hex>"}
```

The client prepares the complete `CDepinMessage` itself:

1. Read `depingetmsginfo` for the pool root, its recipient limit and
   `depinpoolpkey`.
2. Resolve recipients with `depingetancestorrecipients "<token>" <limit>
   "<pool root>"`: the active, deduplicated union of holders of the token and
   of its ancestors *up to the pool root*, with their revealed public keys.
   Stopping at the pool root matters: holders of ancestors the pool does not
   serve would otherwise become extra readers. If the result is `truncated`,
   do not send; the node refuses oversized recipient sets too.
3. Encrypt the content once and ECIES-wrap the content key for every
   recipient public key; fill `token`, `senderAddress`, `timestamp`,
   `messageType`; sign the message hash with the sender's key.
4. Serialize the message, hex-encode it, and wrap that hex in an ECIES
   envelope for `depinpoolpkey` (recipient keyed by `depinpoolkeyaddress`).
5. Call `depinsubmitmsg` with the sender address and the envelope hex. The
   node opens the envelope, checks that `sender` is the signer, verifies the
   signature against the sender's revealed key, checks the sender's inherited
   access to the token, and stores the message.

The reply is encrypted for the sender and signed. There is no bare-hex form.
Submissions are limited per sender and minute (`-depinratelimit`, default
20); over the limit the node answers an error without touching the message.
The count is taken only after the signature and the sender's access have
been verified, so an envelope forged in someone else's name is refused on
the signature and does not spend that sender's quota.

## `depinlistsections`

```
depinlistsections                                       names only
depinlistsections "address" "scope" "challenge" "signature"
```

Without arguments the reply is a signed plain body that decodes to
`{"sections": [...]}` with the `name`, `label` and `depth` of every section:
names are public chain data.
With the four arguments — and only with all four — it adds `access` and,
where there is access, the `messages` counter, limited to the subtree of
`scope`; the challenge is a `receive` challenge issued for `scope`, and the
reply is encrypted for the address and carries `next_challenge` like
`depinreceivemsg`. A holder of a single section therefore sees its own tab,
not its siblings; a holder of the root sees everything.

## `depinclearmsg` (owners)

```
depinclearmsg "scope" "address" "challenge" "signature" ( "all" | hours )
```

Purges `scope`'s subtree (`""` = the pool root = the whole pool). The
challenge must be an `admin` challenge issued for exactly `scope` — for the
root, request it for the root by name — to an address holding the owner token
of `scope` or of an ancestor. Equality, not subtree: a challenge for
`&NEWS/GENERAL` purges neither the pool nor `&NEWS/OTHER`, and a challenge
for `&NEWS` does not purge `&NEWS/GENERAL` by name. The mode is validated
before the challenge is consumed, so a typo does not cost a challenge.

## Related RPCs

- `depingetancestorrecipients` — recipient discovery (see "Publishing").
- `depinpoolstats`, `depinmcpstatus` — aggregate counters, signed plain
  bodies.
- `depingetmsg`, `depinsendmsg`, `depinsignrequest`, `depinsignchallenge`, `depindecrypt`,
  `depinpoolpkey` — local wallet RPCs of a node that holds the keys; never
  reachable through a proxy.

## Compatibility and limits

- Protocol 2 replaces protocol 1 entirely on testnet: clients that call
  `depinreceivemsg token address`, submit bare hex, or expect plaintext
  replies stop working. Check `depingetmsginfo.protocol`.
- A pool configured at `&NEWS/GENERAL` serves only that subtree. Holders of
  `&NEWS` are not automatically recipients for that different pool.
- The pool has a configured recipient maximum (hard-capped at 50). Submission
  fails rather than silently dropping recipients when the set exceeds it.
- A holder without a revealed public key cannot be included in ECIES group
  encryption and cannot authenticate; both are expected and reported.
- Abuse control is split between the node (per address and minute: challenges
  issued and messages accepted) and the RPC proxy in front of it (per origin
  IP and minute, with a temporary block on excess, answered as HTTP 429 with
  `Retry-After`). A client that receives 429 should back off for the indicated
  time rather than retry.
- Only P2PKH (secp256k1) addresses can authenticate; the pool key, the
  envelope and `poolsig` are secp256k1 as well.
