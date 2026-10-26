# DePIN client integration guide (protocol 5)

The node accepts RPC protocol **5** only for remote messaging calls. Upgrade
the node first, then libraries/applications. Positional protocol 2/3 calls and
GET/CLEAR/REQ/READ-SEQUENCE-v1 proofs are rejected. The content wire format,
Legacy-only ECIES, storage version 2 and cursor version 1 remain unchanged;
RPC 5 adds typed ECIES 2 destinations ([depin-ecdsa.md](depin-ecdsa.md)).

The byte-exact request/response contract, field types, defaults and limits
are in [depin-request-signatures.md](depin-request-signatures.md). Content
cryptography is in [depin-messaging-protocol.md](depin-messaging-protocol.md);
[depin-pool-state.md](depin-pool-state.md) specifies sequencing, moderation
and recovery. External libraries have not yet been migrated.

## Discover and pin the service

Send `depingetmsginfo` one JSON object (illustrative placeholders):

```json
{"protocol":5,"request_id":"<fresh random 32-byte lowercase hex>","timestamp_ms":1792660000000}
```

JSON-RPC params may be `[request]` or `{"request":request}`. CLI accepts that
object as one JSON argument or as `-named request='…'`. Its request hash uses
the explicit bootstrap normalization in the RPC contract.

Verify the wrapper against the expected pool key and your locally computed
request hash before decoding its body. A pin should include endpoint, network,
pool root and compressed pool key. A self-signed first contact without a known
pin provides self-consistency only: obtain the pin independently or apply an
explicit trust-on-first-use policy. Never silently replace it from a reply.
The signed body advertises protocol 5, `accepted_protocols: [5]`, network,
`instance_id`, `server_time_ms`, pool key/root, limits and state capabilities.

Bootstrap/public queries do not enforce a clock window. Generate a new random
request_id for each query, impose a local response timeout, and verify the
response's correlation. Use newly verified server_time_ms to prepare private
requests if the local clock is skewed. An old bootstrap must not supply time
or an instance indefinitely.

## Prepare and sign every private operation

All non-bootstrap methods take the common object. Example of a first
sequence page, after obtaining a receive nonce:

```json
{
  "protocol":5,"network":"<genesis>","pool_pubkey":"<pinned key>",
  "pool_root":"&GROUP","instance_id":"<verified current instance>",
  "membership_revision":"<verified directory revision>",
  "request_id":"<fresh random 32-byte hex>","timestamp_ms":1792660000000,
  "token":"&GROUP/SEC","address":"<Legacy or strict ECDSA holder>",
  "challenge":"<receive nonce>",
  "args":{"cursor":null,"limit":100,"from_timestamp":0},"signature":""
}
```

Reconstruct canonical bytes locally, hash them and sign the request preimage
with the key bound to the exact Legacy or strict ECDSA address. Do not sign arbitrary text supplied by a remote
node. A local signing wallet offers:

```text
depinsignrpc "depinreceiveseq" request
```

It returns `request` containing the signature, plus `preimage` and
`request_hash`. It signs the explicit remote identity; it does not assume
that the signing wallet node is the destination. Send the signed request to
that destination with the same method. Do not expose wallet helpers on a
public proxy. The old three signing helpers are removed.

## Obtain, consume and chain challenges

Call `depinchallenge` with empty challenge, args `{"type":"receive"}` or
`{"type":"admin"}`, and a timestamp-signed common request. Its encrypted
body contains `challenge`, `expires_in:30` and `type`. Both issue and use
require current permission; freezing, self-revoking, moving holdings or
owner changes take effect under the active-chain contract in
[depin-authorization.md](depin-authorization.md).

Receive/list-personal calls sign that nonce **and the exact operation**.
Their successful bodies normally include `next_challenge` and
`next_expires_in:300`; sign a new request with it for the next call. Nonces
are single-use and bound to exact scope/address/type. Invalid parameters,
wrong signature or permission failure do not consume a valid nonce. An
otherwise authorized operation can consume it before a storage/response
failure: never assume all errors leave it usable.

## Verify and open the response

Require the exact wrapper schema: protocol, network, pool_pubkey, pool_root,
instance_id, membership_revision, membership_height, membership_blockhash,
request_hash, body_kind, exactly one of body/encrypted, poolsig.
Compare request_hash with your own canonical request, enforce confidentiality,
and verify the v5 response preimage against the pinned key. The signature
covers decoded body bytes, method and service context. It does **not** use
the old DEPIN-RESP string/hash-of-hex construction.

Public bodies are hex of exact JSON bytes. Private bodies are ECIES for the
request address; after verification, decrypt and authenticate both GCM layers.
Local `depindecrypt address encrypted` can open it when that wallet owns the
key. A private success body must never be accepted in cleartext.

A body containing `error` is a failure, even though JSON-RPC returned a
result wrapper. Check its code and `data.depin_error`. Syntax, unavailable
service and unavailable-key errors can be ordinary JSON-RPC errors before
a wrapper can be constructed. Treat these as unauthenticated transport
failures; they do not authorize repinning or changing the requested operation.

## Membership changes

Each wrapper signs membership_revision, membership_height and membership_blockhash.
Every complete request includes the required membership_revision. All confirmed
relevant pool changes invalidate RECEIVE and ADMIN challenges. Public directory
refresh accepts the previous revision; private operations require the current
one, including challenge issuance and submission. The reference can be older
than the current tip; compare its hash as well as height, scoped to this service.

On the signed membership_stale error, refresh recipients/policy, obtain a fresh
challenge as needed, rebuild the prepared content when recipients changed, and
sign a new request. Do not automatically retry the same proof. Keep your message
cursor while its stream remains valid. Use bounded retries/backoff under churn.
A private success must match the request's revision; public refresh or a signed
stale-context error can legitimately announce a newer revision. Verify all
metadata before updating local context. A frozen user cannot renew access.
See [depin-membership.md](depin-membership.md) for exact events and semantics.

## Methods and operational recovery

- `depinreceiveseq`: prefer this admission-order cursor. Save the complete
  returned six-field cursor even on empty pages; keep scope/address/filter
  fixed. A restart with retention preserves the stream, but requires fresh
  instance/challenge. A changed stream requires a null cursor and hash
  deduplication. Do not use the sender timestamp as a moving cursor.
- `depinreceivemsg`: timestamp/after_hash/limit live inside args and are all
  signed. The old time/anchor limitations remain; expiry or deletion can
  remove an anchor. It also has a 4 MiB reply budget when limit is zero.
- `depinlistsections`: a public request has empty address/challenge/signature
  and token equal to the root; a personal request requires a receive nonce
  and is scoped to its token, with current counters/access.
- `depingetancestorrecipients`: public, but verify the response against your
  actual max_results and stop_at query. Default stop_at is the serving root.
  A valid pool signature proves the service answered; verify eligibility
  through independent sources and your own recipient policy.
- `depinsubmitmsg`: build and content-sign CDepinMessage, wrap its hex for
  the pool using ECIES, put that hex in args.encrypted, keep common token
  empty, and sign the whole request as the same sender in address. Its
  timestamp proof is replay-protected. Inner signature and every declared
  recipient's current permission are still checked.
- `depinclearmsg`: requires an admin nonce. args.mode is expired (default),
  all or hours; only hours mode includes the required integer args.hours.
  Zero hours preserves same-second/future messages and is distinct from
  all. Empty common token normalizes to the root before signing. A valid
  signature cannot be reused for another threshold, mode or scope.
- `depinpoolstats` and `depinmcpstatus`: public root-scoped requests with
  empty args and authentication fields; useful for service diagnostics.

If instance changes (restart/key reset/clock rollback), verify bootstrap
again and prepare a newly signed request. The v5 request is not portable
between nodes, methods, roots or networks. Do not reuse request_id.

On -10 use bounded backoff. On -26 refresh membership and recipient policy,
then encrypt/sign a **new** message if appropriate. A lost submit response
can leave its outcome unknown; inspect by hash before a deliberate retry.
Never automatically repeat a destructive operation after a lost response.
No exactly-once guarantee spans process failure or full process snapshots.

For each delivered message reconstruct its content digest, verify the DER
sender signature, decode strict ECIES and authenticate GCM before displaying
plaintext. Neither pool signatures nor a successful download prove that
arbitrary content ciphertext will decrypt correctly.

## Executable examples and remaining work

`contrib/depin/regtest_walkthrough.sh` runs the disposable protocol 5
functional walkthrough. It exercises actual HTTP and positional/named CLI,
parameter tampering, replay, clock rollback, restart and signed replies.
It creates independent test wallets and does not reuse DATADIR. Configure
the functional framework and build neuraid/neurai-cli first. Additional
permission and durable-state regressions remain separate tests.

A challenge is an authorization nonce, not a content-decryption key. A node
with a wallet/bot recipient key can decrypt content addressed to that key; a
relay with only the pool key cannot. Legacy P2PKH and strict ECDSA witness v3 authenticate/decrypt; see
[the address and ECIES contract](depin-ecdsa.md).
Content uses per-message random keys,
but stealing a recipient's static secp256k1 key can expose captured historical
ciphertexts. A freeze denies future authorized downloads; it cannot revoke
ciphertext or plaintext already obtained. A malicious directory can cause
senders to encrypt for an unintended key unless clients verify recipients.
Pool-wide membership renewal is implemented; external library/proxy migration remains pending.
See [the membership contract](depin-membership.md) for refresh and mandatory challenges.
