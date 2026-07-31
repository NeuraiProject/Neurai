# DePIN client integration guide

This document describes the RPC surface that an external, non-custodial
DePIN client or library needs in order to read and decrypt messages. It is
written for clients that hold the user's private key themselves; the node
returns encrypted messages and does not decrypt their content for the client.

DePIN messaging is experimental and off-chain. Token names, token holdings,
section names, and the hierarchy are public blockchain data. Message content
is protected by encryption, not the existence or membership of a channel.

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

## `depinreceivemsg`

```
depinreceivemsg "token" "address" (timestamp) ("after_hash") (limit)
```

Arguments:

1. `token` — pool root or a section served by the node.
2. `address` — the client address used as the recipient selector and, when
   available, as the response-encryption target.
3. `timestamp` — optional Unix timestamp. When non-zero, messages whose
   timestamp is at least `timestamp - 1` are returned.
4. `after_hash` — optional cursor. Use `""` to start at the oldest available
   message.
5. `limit` — optional page size. `0` or omitted returns the unpaginated,
   backwards-compatible array. Values above 1000 are rejected.

Example JSON-RPC request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "depinreceivemsg",
  "params": ["&NEWS/GENERAL", "N...", 0, "", 25]
}
```

With `limit > 0`, the result is:

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
  "has_more": false
}
```

Without pagination, the result is the `messages` array directly. Messages are
ordered from oldest to newest. Save the last returned `hash` and use it as
`after_hash` for the next page. Supplying a hash that is not in the address's
visible result is an error.

### Scope is not authentication

`depinreceivemsg` validates the address syntax but does **not** ask the caller
to prove ownership of that address. Its `token` argument is a convenient UI
scope, not an authorization mechanism. The actual visibility rule is the
cryptographic recipient list embedded in each message; an address can decrypt
only a payload encrypted for its revealed public key. A sender also sees its
own messages.

Clients exposed to an untrusted transport should use the gateway
challenge/response protocol for authenticated reads, or otherwise treat this
RPC as an untrusted retrieval endpoint and enforce cryptographic validation
locally.

## Response privacy layer

When the node has a wallet available and the requested address has a revealed
public key, the whole RPC result may be wrapped as:

```json
{ "encrypted": "hex_ecies_blob" }
```

Deserialize the blob as `CECIESEncryptedMessage` and decrypt it with the
private key for the requested address. The plaintext is exactly the array or
paginated object described above. A library must handle both wrapped and plain
responses.

This wrapper encrypts to the client address; it is not, by itself, an
authenticated server-identity protocol. Use a trusted node RPC connection or
authenticate the transport/server separately when that property is required.

This transport/privacy wrapper is independent from the message payload
encryption below.

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
   the node accepts for normally signed messages, including everything
   submitted through `depinsubmitmsg`: signatures over the legacy preimage
   (the same fields without `messageType`) are rejected. The signature is
   DER-encoded secp256k1 by the key behind the sender's revealed public key.

   Exception: messages accepted through the pre-authenticated gateway path of
   `depinsendmsg` are authorized by the gateway challenge/response instead of
   a message signature. The node stores a 65-byte all-zero sentinel in
   `signature_hex` and skips signature verification for them, so they cannot
   be verified cryptographically. Whether to display them is a client policy
   decision tied to how much it trusts the serving gateway session — see
   "Scope is not authentication" above.
2. Verify that the returned `token` belongs to the requested scope. For a
   root request, any descendant is valid; for `&NEWS/GENERAL`, only
   `&NEWS/GENERAL` and its descendants are valid. Do not require literal token
   equality for a subtree request.
3. Reject malformed, duplicated, or unexpectedly large encrypted payloads
   according to the library's own resource limits.
4. Authenticate the RPC transport or expected server separately when that
   property is required; the optional response wrapper alone does not provide
   server authentication.

## Recipient discovery for send-capable clients

Clients that encrypt messages themselves can resolve candidate recipients with:

```
depingetancestorrecipients "token" (max_results) ("stop_at")
```

It returns the active, deduplicated union of holders of the requested token
and its ancestors, with their revealed public keys. `stop_at` is inclusive and
lets a caller stop at a configured pool root; omitted means the absolute root.
The result is exact by asset name: querying `&TOKEN` never matches
`&TOKEN/CHILD` or `&TOKENE`.

This is an informational query, not a sending decision. It may return
`truncated: true`; a truncated list must never be used as a complete group
recipient list. Check the `*_complete` flags before interpreting skipped
counts as totals. The command requires both `-assetindex` and `-pubkeyindex`.

For ordinary remote sending, prefer `depinsendmsg`: it queries the remote
pool's `INFO` first, uses that pool's root as `stop_at`, and applies the
remote pool's recipient limit before encrypting. This prevents encrypting for
holders of ancestors that the remote pool does not serve.

## Related RPCs

- `depingetmsg` — wallet-backed local or remote retrieval and decryption.
- `depinsendmsg` — wallet-backed remote send and signing.
- `depinlistsections` — section names for UI tabs. Its optional address mode
  adds access and message counters, but is intentionally available only over
  node RPC; the unauthenticated DePIN port returns names only.
- `depingetmsginfo` — pool configuration and status.

## Compatibility and limits

- Legacy clients that request only the pool root keep their previous scope:
  the root includes the complete served subtree.
- A pool configured at `&NEWS/GENERAL` serves only that subtree. Holders of
  `&NEWS` are not automatically recipients for that different pool.
- The sending pool has a configured recipient maximum (hard-capped at 50).
  Sending fails rather than silently dropping recipients when the eligible
  set exceeds it.
- A holder without a revealed public key cannot be included in ECIES group
  encryption. This is expected and is reported by sender-side RPCs.
