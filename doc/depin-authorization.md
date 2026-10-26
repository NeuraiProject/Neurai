# DePIN message authorization

This describes historical message restoration, recipient authorization and
current-permission checks (2026-10-21). For subsequent
strict encoding, sequence reads and durable state, see
[depin-pool-state.md](depin-pool-state.md). The signed user message framing remains unchanged. RPC 5 additionally supports
strict ECDSA destinations with [typed ECIES recipients](depin-ecdsa.md);
Legacy-only ECIES keeps its original bytes.

## Publications and recipients

`AddMessage` is the admission boundary for remote submission, local wallet
sending and MCP replies. Every new publication requires an active sender
and an active Legacy P2PKH or strict ECDSA address for **every declared
`recipientKeys` destination**, for the message's token or an ancestor up to the configured pool
root. A positive balance must also pass owner-freeze and self-revocation
checks. An active ancestor still grants access when a child pair is frozen.
Owner tokens grant administration, not readership.

Private messages and subsets are allowed. The pool rejects the whole signed
message if any declared recipient fails; it never removes entries or rewrites
a signed payload. Remote rejection uses RPC code `-26` and the recognizable
text `Recipient not authorized:`. Other validation errors retain their
existing codes. A valid signature authenticates the sender's choice; it does
not prove that a directory response was honest or complete.

The pool cannot prove that a sender did not share plaintext or a content key
elsewhere. A malicious service can bypass its own admission policy. Clients
should independently verify recipient holdings and key/address bindings,
compare independent RPC sources and apply their chosen whitelist. Holding
the pool's transport key alone does not decrypt user-only message content.

## Connected chainstate and operations in progress

Authorization follows the **active, fully connected chain**, including its
latest block (one confirmation). Mempool transfers and restrictions do not
change permissions. Reorganizations change authorization with the active
branch; orphaned restrictions do not remain authoritative.

Under `cs_main`, a new, empty local `CAssetsCache` reads balances through
`GetBestAssetAddressAmount`: connected dirty balances override disk. Reads
go into the local cache, not the global balance map. Restrictions use
`passets->CheckForDEPINRestriction` under the same lock. Owner checks use the
same balance path. No authorization-triggered full chainstate/UTXO flush is
needed. Recipient directories merge persisted rows with dirty balances;
section directories merge persisted metadata with pending creations/deletions.
Their cached names are invalidated by a tip change; permissions are not cached.

RPCs retain `cs_main` from the readiness and permission checks through nonce
consumption and message selection, insertion or purge. A block cannot change
permissions halfway through that operation. If a request finishes selecting
its response before a freeze connects, that already authorized response can
still arrive afterward. Revocation cannot recall downloaded copies or an
already authorized response. A request after the block connects sees the new
permissions, even with an unexpired nonce.

Lock order is `cs_main` before pool, section-cache, wallet and challenge locks.
Admission does signature/permission work before taking the pool lock. Raw
pool snapshots are internal storage helpers, not authorized download APIs.
The MCP model/network request runs outside `cs_main`; local reply resolution
and admission run together afterward.

## Service availability

Permission-dependent service calls fail closed during import, reindex, IBD,
missing chainstate, insufficient chain work, an old active tip or excessive
lag behind known headers. IBD's historical latch alone is insufficient.
Checks precede directory work and hold through authorization/effect.

| Option | Default | Constraint |
|---|---:|---|
| `-depinmaxtipage` | 3600 seconds | Positive; equality is allowed |
| `-depinmaxheaderlag` | 2 blocks | Nonnegative; equality is allowed |

These are operational freshness bounds, not a guarantee of global consensus
or protection against an isolated node with no knowledge of a competing tip.
A tip older than one hour stops permission-dependent DePIN service rather
than authorizing from stale data. Operators can choose stricter bounds.

The RPC error is `-10`, with `DePIN service not ready:` and a reason. It applies
to challenge issuance/use, publication, receive, purge, recipient/section
listings, and local wallet reads. Diagnostics (`depingetmsginfo`, pool and MCP
stats), local signing and decryption remain available. `depingetmsginfo`'s
signed plain `body` adds `ready`, `not_ready_reason`, `authorization_height`,
`known_headers`, `tip_age_seconds`, `maxtipage` and `maxheaderlag`.

## Restoring historical messages

`-depinpoolpersist` remains **off by default**. With it enabled, startup uses a
private restoration path. It checks signatures, strict ECIES encoding,
type, scope, timestamps/expiry, existing size/count budgets and duplicates,
without requiring historical senders or recipients to retain their assets.
Current reader permissions are still checked at download time, including for
an old challenge and after restart. Local wallet reads and MCP polling also
recheck current permission before selecting messages.

Restoration does not provide an RPC import bypass. A new submission of the
same old message goes through current admission checks. A bad magic header
is preserved for inspection rather than deleting the only source file.

The durable pool state now stores retained messages, sequences and durable moderation in state
version 2; version 1 is imported explicitly, preserving its original. A
saved, verified sender key permits signature checking after a reorg removes
the key-reveal transaction. The loader cannot prove an operator-controlled
file was originally admitted under an earlier chainstate. Disabling message
retention leaves new messages volatile; moderation remains durable. See the
state contract for retention toggles, migration and failure handling.

## Client and library changes

Clients should recognize temporary `-10` unavailability and back off without
assuming authorization was granted. On `-26`, refresh membership, check keys
and the client's recipient policy, then encrypt and sign a **new** message if
still appropriate. Replaying the old ciphertext does not update its keys.
Use bounded retries; never silently discard an intended recipient or treat a
truncated directory as complete. Preserve verification of signed wrappers.

The node implements complete method/parameter signatures and
[membership context](depin-membership.md) under
[RPC protocol 5](depin-request-signatures.md). Every relevant confirmed pool
change invalidates RECEIVE/ADMIN challenges; stale operation proofs and sends
require refresh. Current permission is still rechecked. A reorganization never
reactivates an invalidated nonce. External libraries remain pending.
