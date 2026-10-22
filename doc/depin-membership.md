# DePIN pool membership context (P7 / RPC 4)

Implemented on the node, 2026-10-22, over `4c460b3`. The user chose pool-wide
renewal after membership changes, including RECEIVE and ADMIN challenges,
plus a signed current-context requirement on remote submission. This extends
P2 with **RPC protocol 4**, rejecting protocol 3 and older requests. Content
ECIES/message signatures, persistence version 2 and cursor version 1 stay
unchanged. External libraries remain for the later migration.

## Context and confirmed transitions

Each serving pool has a random 32-byte `membership_revision`. It is scoped to
network, pinned pool key, configured root and RPC process instance. It is an
opaque equality token, not a counter shared across nodes. A relevant event
creates a fresh value; undoing the event creates another value and never
restores an earlier epoch. Restart/key reset also loses all challenges and
starts a new context. Clock rollback rotates the separate RPC instance.

The node observes the per-block asset cache and the revealed-key index on the
actual ConnectTip path. It publishes only after the connected asset/UTXO state
and chainActive agree, under cs_main. DisconnectTip also publishes after undo.
The observer changes service metadata and challenge state; block validation
rules, proof of work and consensus serialization do not change.

The whole pool renews for served-root/descendant asset balance operations,
creation/removal, owner changes, owner freezes/unfreezes, self-restrictions
and transfer-state changes. Thus an ancestor operation renews its dependent
sections; a child event also renews other sections in that pool. Events are
conservative: an operation involving a served asset may renew even if its
net usable-reader set is unchanged. Ancestors above the configured pool root
are excluded, matching P3's permission boundary.

A first valid Legacy key revelation for an address holding a served asset or
owner token also renews the context. Repeated spends with the same already
indexed key do not. The key index currently retains learned public keys when
blocks disconnect; undo does not promise to erase this knowledge. Reorgs
still invalidate any orphaned context reference. The context's block hash and
height identify its reference, which can remain older than the current tip
through unrelated blocks.

Empty blocks, unrelated assets (including names sharing a root prefix),
unrelated key revelations and mempool-only transactions do not ordinarily
renew the context. Invalid requests/signatures never trigger an epoch change.
A missed notification, root change or orphaned reference triggers conservative
renewal before serving a later request. A reorg which removes the initial
reference may therefore renew even if the disconnected block had no asset
operation. No old challenge is revived by returning to a previous branch.

## Bounded observation, without chainstate flushing

The observer uses local per-block changes, not the accumulated global dirty
sets. A later unrelated block does not repeat an earlier notification.
First key revelations are checked against dirty balances plus a read-only
reverse address-asset iterator. The iterator respects serialized key ordering
and does not assume assets are lexicographically prefix-sorted on disk.

Extra dirty/persisted holder exploration shares a 10000-row budget per block
and batches newly revealed addresses. Missing/incomplete observations renew
conservatively rather than assuming the directory did not change. This can
cause extra renewal in very large pools. No observer-induced UTXO/asset flush
or unbounded recipient scan is required. The ephemeral context/challenge store
does not accumulate a per-block history.

## Request and response contract

The [RPC contract](depin-request-signatures.md) gives exact canonical bytes.
Every complete request adds the required lowercase-hex `membership_revision`
after instance_id in its signed binary representation. Bootstrap stays the
three-field object and canonicalizes that revision to 32 zero bytes.

Every response wrapper adds signed fields:

- `membership_revision`: 64 lowercase hex characters.
- `membership_height`: integer reference height, -1 only without a chain tip.
- `membership_blockhash`: displayed reference block hash, 32 decoded bytes.

They enter the v4 response preimage after instance_id, before request_hash.
Bootstrap repeats them inside its body and advertises
`membership_policy: "pool_challenges_and_signed_requests"`. P3 readiness
still controls availability; a diagnostic context does not override ready=false.

Public queries accept an old revision so clients can refresh their directory.
Private operations, including challenge issuance and submission, require the
current revision. The caller's signature is checked before a stale-revision
error is disclosed. A same-revision read still checks nonce existence and
current permission. Metadata signatures authenticate the node's statement;
they do not prove that a malicious operator's directory is correct.

## Polling, renewal and sending

A successful poll includes the current signed context. If membership changed
since its nonce was issued, the old operation instead gets a signed/encrypted
error -32600 with data.depin_error=membership_stale, current revision,
refresh_recipients=true and renew_challenge=true. No operation, rate quota
or replay entry is consumed for that rejection. RECEIVE and ADMIN nonces were
already invalidated by the actual chain event.

The client refreshes recipient data and its whitelist policy, obtains a new
challenge if required, and signs a new operation using that context. It must
compare the verified directory's response revision with the one it will use.
Another change before use produces another explicit rejection: retry with
bounded backoff, not an unlimited loop. Updating only the revision while
keeping an invalidated nonce fails with challenge_invalid. A revoked reader
cannot obtain a new receive challenge; a previous owner cannot renew admin.

For a prepared send, update recipients and rebuild/re-sign content as needed,
wrap it for the pool and sign the operation with the directory's revision.
A new member invalidates old prepared sends even if all previously selected
recipients remain eligible. After a verified refresh, explicit subsets/private
messages remain allowed. A current revision does not prove that the client
actually downloaded or displayed the complete directory: P1 checks each
declared recipient, and recipient selection remains client policy.

P1 rejects the whole message if one declared recipient is disabled; the node
does not strip individual wrapped keys from a sender-signed payload. P3 checks
current permissions on download as well as issuance/use. Membership renewal
does not revoke downloaded ciphertext/plaintext or an already authorized
response, provide forward secrecy, or reset message cursors. Retain the cursor
through context renewal; restart the scan only if its stream changes.

## Validation and limits

The real-chain [functional regression](../test/functional/feature_depin_membership.py)
checks unchanged blocks/unrelated roots, mempool vs confirmation, all-challenge
renewal, stale receive/admin/issuance/send, denial for revoked users, explicit
subsets, joins, dirty and persisted first-key revelations, section/ancestor
changes, owner changes, reorgs, concurrency and restart with retained messages.
The permission regression now requires fresh nonces after reorganizations.
C++ cases cover observer scope, read-only bounded index reads, unchanged
quotas/replay on stale failures and response metadata/signature tampering.

[Evidence and exact results](../NIP/NIP_SIN_NUMERO/actualizacion-depin-evidencias-20261021/p7/README.md)
identify source inputs and sanitizer limitations. External SDK/application
refresh handling, C1 independent sources/allowlists, deployment proxy policy
and production load remain separate work. The service makes no guarantee
against an isolated/malicious chain view, arbitrary operator database edits,
full live-process snapshot rollback or exhausted entropy/storage resources.
