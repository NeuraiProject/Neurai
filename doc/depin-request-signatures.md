# DePIN RPC 5: complete request and response signatures

Date: 2026-10-22. ECDSA extension base: `d39ef51` (request signing and
membership renewal implemented).

**Status: implemented in the node over this base.** The service is on testnet:
the change goes into the node first, and libraries and applications are
updated afterward. Protocol **5**, without accepting protocol 2/3/4 formats or
signatures in the migrated operations. The executable contract is in
`depinrpc.cpp` and `rpc/depin.cpp`.

## Scope and migration

Request signing authenticates the operation and its effective parameters, in
addition to checking current permissions. It covers challenge requests, reads,
personal section listing, administration and remote submission. Membership renewal adds the
current pool revision to every complete request.
Sequence reads use that same scheme. The old
GET/CLEAR/REQ and READ-SEQUENCE-v1 prefixes are not alternative execution paths.

The RPC version is independent of the versions of the durable pool state, the cursor
and message encryption. Request signing requires neither re-encrypting the history nor
changing its content signature. The node and wallet helpers are updated
together; external libraries are updated afterwards. Until they
are updated, old clients receive a protocol rejection, not a partially
compatible operation. No switch is included to restore the weak
signatures.

## Identity and service context

Every request is bound to:

- Version 5, the exact RPC method and the authentication class.
- The network's genesis hash, from `GetConsensus().hashGenesisBlock`.
- The pool's compressed public key and the configured root.
- A random 32-byte `instance_id`, regenerated on startup, on resetting/changing
  the pool key, or on detecting any clock rollback.
- A random 32-byte `membership_revision`: it changes on relevant
  membership/directory events, invalidating the pool's RECEIVE and ADMIN challenges.
- A random 32-byte `request_id`, fresh for every client operation.
- Unix timestamp in milliseconds, address, scope and challenge where applicable.
- Effective arguments normalized with the method-specific schema.

Two different nodes require requests signed for each destination. The client
can keep the same content message, prepare an envelope for each pool
and sign both operations. Sharing the pool key between replicas does not
share `instance_id` or turn nonces into transferable authorizations.
Local helpers receive the destination's identity: they do not assume that the
node hosting the wallet is the receiving node.

## Transport and canonical representation

Every migrated remote RPC takes a request object, instead of combining the
old positional arguments with new rules. Common keys:
`protocol`, `network`, `pool_pubkey`, `pool_root`, `instance_id`, `request_id`,
`membership_revision`, `timestamp_ms`, `token`, `address`, `challenge`, `args`, `signature`.
The method and class are reconstructed from the executed RPC; a method name
sent inside `args` is not trusted.

Unknown or duplicate keys are rejected in the request objects and in the
cursor. Required fields do not accept null. Only the optional fields defined
by each schema accept omission/null, and they are replaced by their effective
value before signing. Integer fields reject implicit conversions from booleans,
numbers in strings, fractions and exponential notation. The CLI converts the object as JSON, without reinterpreting its numbers. Integers
are int64; a JavaScript client must preserve them without loss
above 2^53. Printable ASCII text: root/token up to 128 bytes, address
up to 64, Base64 signature up to 128. 32-byte identifiers: 64 hexadecimal
characters; compressed key: 66. No additional common fields are allowed.

The preimage does not depend on re-serializing JSON. Definitions:

- `U8`, `U16`, `U32`: fixed-width unsigned integers, little-endian.
- `I64`: 64-bit little-endian integer, two's complement representation.
- `B(x)`: `U32(len(x))` followed by the exact bytes of `x`.
- `S(x)`: `B(x)` for ASCII text. Methods, assets and addresses are neither
  trimmed nor silently case-converted.
- `H(x)`: 32 bytes decoded from the displayed hexadecimal, left to
  right; not the reversed internal serialization of `uint256`. Incoming
  hexadecimal is strict and lowercase, without prefixes or spaces.
- Public keys: 33 valid compressed bytes. Nonces: `B` of 0 or 32 bytes.

In fixed order:

```text
R = S("Neurai/DePIN/RPC/request") || U16(5) || S(method) || U8(auth_kind)
    || H(network) || B(pool_pubkey) || S(pool_root) || H(instance_id)
    || H(membership_revision) || H(request_id) || I64(timestamp_ms) || S(token) || S(address)
    || B(challenge) || B(method_args)
request_hash = SHA256(R)
preimage = "DEPIN-RPC-REQUEST-v5|" + lowercase_hex(request_hash)
```

The recoverable compact secp256k1 Base64 signature scheme used by
`SignDepinChallengePreimage` is retained: message signing applies its current
magic and hash to this text. `request_hash` is single SHA256 with direct
hexadecimal output, not the `ToString()` of an internal hash. The signature is
not part of `R`.

Classes: `0=public`, `1=timestamp`, `2=receive`, `3=admin`. Classes 2/3 require
a nonce issued for the address, scope and type; class 1 uses a freshness
window and a replay log. Empty address/challenge/signature are mandatory
for the public class; they do not open a public variant of a private method.

## Operation schemas

All common fields are included even if their value is the defined empty value.
The method-specific arguments are concatenated in this order, without JSON labels:

| Method / variant | Class | `token` and canonical arguments |
|---|---|---|
| `depinchallenge` | timestamp | Exact scope; `U8(type)` with `0=receive`, `1=admin` |
| `depinreceivemsg` | receive | Exact scope; `I64(timestamp)`, `B(after_hash)`, `I64(limit)`; defaults 0, empty, 0; timestamp >=0, limit 0..1000 |
| `depinreceiveseq` | receive | Exact scope; `U8(continuation)`, `H(stream_id)`, `I64(after_seq)`, `I64(limit)`, `I64(from_timestamp)`; the first page uses flag 0, zero stream, sequence 0; defaults 100 and 0; limit 1..1000, sequence/filter >=0 |
| `depinlistsections`, personal | receive | Exact scope; no additional arguments |
| `depinclearmsg` | admin | Normalized scope; `U8(mode)`, `I64(hours)`; `0=expired`, `1=all`, `2=hours`; hours required, 0..floor(INT64_MAX/3600), only in mode 2; zero in the others |
| `depinsubmitmsg` | timestamp | Empty common token; `B(outer ECIES envelope bytes)` |
| `depingetancestorrecipients` | public | Queried token; `I64(max_results)`, `S(effective stop_at)`; max_results defaults to 1000, range 1..10000; an omitted/null/empty stop_at resolves to the root |
| `depinlistsections`, public | public | Pool root, no arguments; does not return personal counters |
| `depinpoolstats`, `depinmcpstatus` | public | Pool root, no arguments |

The legacy read's `timestamp` is signed as expressed by the API, before its
inclusive one-second adjustment is applied. Sequence continuation includes
the six fields of its current cursor, normalized: version 1, stream, sequence,
scope, address and filter. Its scope/address/filter must match those of
the operation; it is not enough for the object to have any six keys.

For administration, the empty scope allowed by the interface resolves to the
root before signing. `expired`, `all` and `hours=0` are three distinct intents;
no signature is valid for another. The default mode explicitly signs
`expired`, never an ambiguous absence. The time semantics of hour-based
purging are unchanged.

For submission, the empty common token avoids revealing, outside the ECIES,
the section that currently travels inside the envelope. The operation
signature covers all bytes of the envelope; the inner signature still covers
content and metadata. After decryption, the sender, scope and current
permissions of all participants are checked as before. The inner signature
alone no longer authorizes an RPC v5 submission, and the outer signature does
not authorize content that fails inner validation.

Public queries do not need a user key: the server binds
its signed response to the exact query and to the `request_id`. This makes it
possible to detect parameters altered by a proxy without turning public
information into private information.

## Discovery, responses and errors

`depingetmsginfo` is the only bootstrap: it accepts the reduced object with version 5,
request_id and timestamp_ms, in order to discover the identity before it can be
included in a complete request. To compute `R`, it uses the public class, zero network/instance/membership_revision,
an empty pool_pubkey, and empty root/token/address/challenge/args. The other RPCs
require an explicit identity that matches the current service.

The bootstrap response advertises network, pool key, root, instance_id,
`accepted_protocols: [5]` and `server_time_ms`, inside its signed body. The signature of that first response does not replace pinning
the key or the client's independent comparison against other sources. A bootstrap response sent
to the wrong destination must be detected against the identity the client
expects, when it already knows it.

All migrated remote responses use a separate domain:

```text
Q = S("Neurai/DePIN/RPC/response") || U16(5) || S(method)
    || H(served_network) || B(served_pool_pubkey) || S(served_pool_root)
    || H(served_instance_id) || H(served_membership_revision)
    || I64(membership_height) || H(membership_blockhash)
    || request_hash || U8(body_kind) || B(body_bytes)
preimage = "DEPIN-RPC-RESPONSE-v5|" + lowercase_hex(SHA256(Q))
```

`body_kind=0` corresponds to public JSON and `1` to ECIES. `body_bytes` are the
bytes decoded from the hex carried in `body` or `encrypted`, exactly one
of those fields. The wrapper advertises protocol, served identity, request_hash,
body type and poolsig. The client computes its own request_hash and requires it
to match: it does not take the received hash as a substitute for its original
request.

The body directly contains the result or `{"error": {"code": ...,
"message": ..., "data": {"depin_error": ..., "expected_protocol": 5}}}`. The
existing codes are retained: for example `-10` service not fresh, `-26`
unauthorized recipient and `-20` purge storage failure. The
reasons include `unsupported_protocol`, `invalid_parameters`,
`service_mismatch`, `request_expired`, `signature_invalid`, `request_replayed`,
`replay_capacity`, `challenge_invalid`, `rate_limited`, `service_not_ready`,
`service_disabled`, `public_key_unavailable`, `storage_failure`,
`operation_failed` and `membership_stale`. Not every permission rejection has its own reason.

Errors that occur after the request has been normalized and the user's public
key obtained are signed and encrypted for that address, even if its
authentication fails. Earlier failures are JSON-RPC transport errors: shape,
version, normalization, unavailable service, unrevealed user key or
missing pool key. The availability barrier precedes asset/key index lookups:
no attempt is made to encrypt an error by consulting an index that is not ready.
There is no private success response in cleartext. An unsigned error does not
authenticate renewal or migration instructions.

The wrapper has exactly the twelve keys `protocol`, `network`,
`pool_pubkey`, `pool_root`, `instance_id`, `membership_revision`,
`membership_height`, `membership_blockhash`, `request_hash`, `body_kind`,
`body` **or** `encrypted`, and `poolsig`. Verify the pinned key, local hash,
signature, shape and confidentiality before interpreting the body. For a private
result, additionally require membership_revision to equal the request's. The C++
verifier authenticates the wrapper; the client applies this check after opening
the body, distinguishing errors from results. For any result,
also require the requested identity/instance; a change requires a verified
bootstrap and a new request. A client that interprets a signed error from a
different instance must limit it to diagnostics, verify the already pinned key
and its local request_hash, and never treat it as success or change the pin.

## Replay, consumption and failures

Authenticated requests accept timestamp_ms within the inclusive window of
±60000 ms around the server clock. Bootstrap and public queries do not apply
that window: the signed response is correlated with the fresh random request_id
and the local hash of the query, and they remain available for diagnostics with
skewed clocks. The client may use the freshly verified server_time_ms
to prepare private requests; do not reuse time information indefinitely.
The 30/300 s challenge TTLs are retained. `request_id`
is signed in every method and correlates the responses. Challenge requests and
submissions additionally keep a bounded log of accepted request_hash values;
read/admin nonces remain single-use, atomically.
The log holds 10000 entries and rejects new ones when it is full, without
evicting protected entries. Each entry lasts until timestamp_ms + 60000 inclusive,
which can be 120 s after admission if the request was at the future edge of the window.
Pruning uses an ordered index of expiries and does not scan the whole log
on every query. Replay/capacity are checked before quota is consumed; only
an authenticated and authorized request enters the log.

A restart changes instance_id: neither old timestamped signatures nor
previous challenges become usable again. Any clock rollback observed on entry to an RPC rotates instance_id
and clears challenges/replay before authorizing. A stopped clock does not remove
protected entries; a forward jump prunes them, and a later rollback
rotates the instance. The time for the initial check is captured only once
under cs_main, and is also used to check the challenge. No replay protection is claimed after a rollback of a
full image of the running process.

Shape, version, identity, arguments, signature and permissions are verified
before consuming nonces or executing operations. An altered or invalid request
does not consume the challenge of another valid request or the quota of an
impersonated address. Read/admission/purge keep current-permission checks consistent under cs_main.
A valid signature does not prevent a later failure of storage or of sending
the response; that can consume the nonce and leave the result unknown to the
client. Explicit recovery with bounded retries is required, without promising
exactly-once delivery.

## Membership, renewal and membership errors

[Membership renewal is implemented](depin-membership.md): every response signs the pool
revision, its reference height and its reference hash. They are wrapper fields; bootstrap
repeats them in the body and advertises membership_policy=pool_challenges_and_signed_requests.
The height/hash identifies the revision's reference, not necessarily the
most recent tip. Opaque revisions from different pools/instances are not compared
as counters. The signature does not certify that the node follows the correct global chain.

All private requests, including challenge issuance and submission, require
the current revision. A valid signature over an earlier revision produces
-32600 with data.depin_error=membership_stale, the current membership_revision,
refresh_recipients=true and renew_challenge=true, in a signed and encrypted error.
It neither executes the operation nor consumes quota/replay. If the client
updates the revision but reuses an invalidated nonce, it gets challenge_invalid.
A user who has lost permissions does not obtain a new challenge either.

Public queries accept an old revision so that the
directory can be refreshed: their response binds the exact hash of that query
to the served revision. Before resending, update recipients/policy, re-encrypt
and re-sign as appropriate, and obtain a new challenge if the operation
needs one. Keep the message cursor as long as the stream does not change; membership renewal
does not reset the history or the sequences. Use bounded retries and backoff
under repeated changes. The server does not rewrite the keys of a signed message.

Earlier protocols are rejected. The domain changes to v5 and U16(5), in
addition to the new fields: adding an outer field without changing its
signature is not valid. External libraries and the proxy must migrate after
the node.

## RPC usage and helpers

Every remote method takes **one** `request` parameter, as `[object]` or
`{"request": object}` in JSON-RPC. Bootstrap:

```json
{"protocol":5,"request_id":"<fresh random 32-byte lowercase hex>","timestamp_ms":1792660000000}
```

Complete object (the placeholders must be replaced with valid values):

```json
{
  "protocol":5,"network":"<genesis>","pool_pubkey":"<pinned key>",
  "pool_root":"&GROUP","instance_id":"<verified current instance>",
  "membership_revision":"<verified directory revision>",
  "request_id":"<fresh random 32-byte hex>","timestamp_ms":1792660000000,
  "token":"&GROUP/SEC","address":"<Legacy or strict ECDSA holder>",
  "challenge":"<receive nonce>","args":{"cursor":null,"limit":100,"from_timestamp":0},
  "signature":""
}
```

In the unlocked local wallet, `depinsignrpc "depinreceiveseq" object`
returns `request` containing the signature, plus `preimage` and
`request_hash`. The destination is the one in the object; it may differ from
the wallet's node. Send that request to the remote RPC with the same method.
The helper signs the requested object; it neither checks that the remote
destination is honest nor contacts it. Do not expose it on the proxy.

`depinsignrequest`, `depinsignchallenge` and `depinsignreadseq` have been removed
from the RPC table. `depinsendmsg`, `depingetmsg`, `depindecrypt` and
`depinpoolpkey` remain local; the internal bot uses local admission/reads and keeps
its permission checks. There is no public fallback to old signatures.

## Vectors and validation

- [15 request vectors](../src/test/data/depin_rpc_v5.json) with bytes,
  SHA256 and preimage, generated by [independent Python struct/hashlib code](../contrib/devtools/depin-v5-vectors.py).
- [C++ tests](../src/test/depinrpc_tests.cpp): codec, defaults/null, integers,
  duplicates, cursor, response, capacity, clock and concurrent replay.
- [Independent functional client](../test/functional/test_framework/depin.py):
  reconstructs preimages without calling the C++ codec, compares the wallet
  signer with signmessage and verifies responses before decrypting. It is test
  infrastructure, not an already migrated external library.
- [Real RPC regression](../test/functional/feature_depin_request_signatures.py):
  tampered parameters/methods/identity, old formats, HTTP duplicates,
  concurrency, restart and clock; complemented by the permission and state
  regtests, and the signed rejection of a purge that exceeds the moderation-mark capacity.

Consensus, mining, P2P, content encryption, state format 2 and cursor 1 are
unchanged. The physical full-disk test of durable moderation is not re-run here:
its earlier evidence is retained, and the protocol 5 capacity RPC error is
added. Nor are all failure possibilities, the GUI, the deployed proxy
configuration, production load or external libraries certified.

Membership renewal is implemented in the node; each external library/application requires its own integration and testing. Request signing does not
turn a signed directory into proof of asset holding: keep the client's
independent comparison and recipient policy. Theft of
a Legacy key can expose historical messages encrypted for it; the ephemeral
ECIES key and its per-response rotation do not provide forward secrecy
against theft of that recipient key.

## Strict ECDSA addresses and RPC 5

RPC 5 keeps the RPC 4 fields and changes the version integer and both
signature domains to `v5`. It accepts canonical Legacy and strict ECDSA addresses;
it does not accept RPC 4 or earlier requests. Bootstrap advertises
`address_types: ["legacy", "ecdsa"]` and `ecies_formats: [1, 2]`. Clients
must implement [the exact identities and ECIES 2](depin-ecdsa.md) before
using this version. Historical Legacy ECIES, storage 2 and cursor 1 are
retained. The RPC 3 and 4 vectors remain as historical references.
