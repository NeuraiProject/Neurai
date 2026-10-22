# DePIN strict encoding, sequence reads and durable moderation

Node contract for P5, P4, P8 and P9b, 2026-10-22. Authorization follows
[depin-authorization.md](depin-authorization.md). The user message and ECIES
wire encodings stay unchanged. Remote RPCs now use protocol **5** and the
common request/signature contract in
[depin-request-signatures.md](depin-request-signatures.md). Storage version 2
and cursor version 1 are independent of the RPC version. Discover capabilities
through the verified `depingetmsginfo` body: `sequence_rpc`, `state_format: 2`,
`stream_id`, `admission_sequence`, `tombstones`, `max_message_wire_bytes` and
`max_reply_plaintext_bytes`.

## Strict encoding and resource budgets (P5)

The dedicated decoder checks lengths before allocating vectors. CompactSize
integers must use their shortest encoding. ECIES must have:

- Exactly one compressed, valid 33-byte secp256k1 ephemeral public key.
- A payload of `12-byte nonce || nonempty ciphertext || 16-byte GCM tag`.
- A nonempty recipient map, in ascending serialized destination byte order,
  with no duplicate IDs. Legacy-only ECIES uses 20-byte IDs; mixed/strict
  ECIES 2 uses a type byte and a 20-byte Legacy or 32-byte strict ECDSA ID.
  See [the exact format and canonical rules](depin-ecdsa.md). Each entry has a vector of exactly
  60 bytes: `12-byte nonce || 32-byte wrapped key || 16-byte GCM tag`.
- No trailing bytes.

`-depinmsgsize` / `maxmessagesize` now explicitly bounds **content plaintext
bytes**, excluding nonce, tag and recipient key overhead: default 1024,
maximum 10240. This replaces the old, looser `size * recipients` payload
rule. The ciphertext length exposes the plaintext length; the node does not
need to decrypt content to enforce it. Recipient count is configured
separately, default 20, maximum 50.

For plaintext budget `P` and recipient budget `R`, the conservative ECIES
wire budget is `82 + P + 94*R` bytes. Actual canonical encoding is usually
smaller because the two CompactSize fields do not need nine bytes each.
The signed inner `CDepinMessage` has an independent **16384-byte** total
decode budget; token, sender and signature fields are bounded at 128, 64
and 80 bytes. Every accepted configuration fits within that total.

The submission transport is a separate ECIES envelope. It must have **only
the pool as recipient**. Its plaintext is ASCII hex of the serialized signed
message, at most 32768 bytes. Before `ParseHex`, the RPC rejects hex longer
than `2 * (80 + 32768 + 81)` characters, invalid hex and malformed ECIES.
After decryption it bounds the hex again and rejects trailing inner bytes.
The outer request `address` must match the signed sender and its protocol 5
operation signature must verify. That proof does not replace inner signature
or current permission checks.

Encrypted RPC replies have a **4 MiB plaintext JSON budget**, independent of
content size. Both receive RPCs build bounded pages under the pool lock;
their conservative per-message charge covers hex expansion and JSON
metadata. Even legacy `limit=0` may return `has_more=true` because of this
byte budget. `depindecrypt` also bounds hex before parsing and uses the
strict decoder, including the required recipient ID.

Malformed submission errors retain existing classes: `-8` for invalid
outer parameters/size, `-22` for decoding/structure errors (including a
missing recipient in local decryption), `-25` for failed transport decryption, `-1` for
invalid decoded messages/admission, and `-26` for unauthorized recipients.
Local decryption authenticates both GCM layers. The pool cannot authenticate
users' content tags or wrapped keys without their private keys: a correctly
shaped but cryptographically bad content payload can still be admitted.
Recipients must reject it, never display unauthenticated plaintext.

## Reading by admission sequence (P4)

```
depinreceiveseq request
depinsignrpc "depinreceiveseq" request
```

Include the ordinary `receive` challenge in the common signed request; cursor,
limit and from_timestamp belong in its args object. For a first scan pass null
as cursor;
`limit` defaults to 100 and accepts 1..1000; `from_timestamp` defaults to 0
and accepts nonnegative int64 values. It is an explicit historical filter
`message.timestamp >= from_timestamp`, with no legacy one-second overlap.
Keep it unchanged throughout a continuation. Do not advance it automatically
to the last sender timestamp: late publications can have earlier timestamps.

The decrypted result is:

```json
{
  "messages": [
    {"sequence": 12, "hash": "...", "token": "&GROUP", "sender": "...",
     "timestamp": 1792540000, "message_type": "group",
     "encrypted_payload_hex": "...", "signature_hex": "..."}
  ],
  "cursor": {"version": 1, "stream_id": "64 hex characters", "after_seq": 12,
             "scope": "&GROUP", "address": "...", "from_timestamp": 0},
  "has_more": false,
  "next_challenge": "...", "next_expires_in": 300
}
```

Entries are ordered by local admission sequence, independent of the
sender's timestamp or hash. The cursor is the exact six-field object in
the last response, including when that response was empty. It can advance
over inaccessible, expired, filtered or deleted entries; it does not need
the previous message to remain in the pool. At the end it advances to the
stream's current high-water mark. New admissions after that point still
appear on the next call. `has_more` means another eligible entry existed in
that snapshot beyond the count/byte budget. Selection checks current reader
permission and one reference time, as in the legacy RPC.

Scope, address, filter and version must match the cursor; a sequence ahead
of the stream or another stream ID is rejected with `-8`. A malformed
parameter, bad signature or stale cursor does **not** consume the challenge.
A successful selection consumes it exactly once before responding. If
encryption/transport fails afterward, obtain a new challenge and reuse the
last saved cursor; deduplicate by hash.

The stream ID is scoped to the local pool. Do not compare sequences from
different nodes, pool roots or stream IDs. On `DePIN stream changed`, restart
with `null`, retaining the intended historical filter, and deduplicate any
history already held by hash. An unchanged ID survives normal and abrupt
restarts with message retention enabled. Volatile restarts, migration and
recovery that loses a complete record create a new ID; no continuity is
claimed with the previous stream. Sequence exhaustion at int64 maximum
rejects admissions explicitly rather than wrapping.

### Request and response signatures

Both sequence and timestamp reads use the complete protocol 5 signature in
[the RPC contract](depin-request-signatures.md). This covers method, network/pool
identity, instance, unique request ID, timestamp, scope/address/nonce and every
effective argument. The cursor's stream and sequence are signature-bound; its
version/scope/address/filter must also match the operation. Null/omitted
arguments normalize to defaults. A continuation at sequence zero still has
flag 1 and binds its stream. The old READ-SEQUENCE-v1 proof and wallet helper
are rejected/removed, with no RPC fallback.

Responses bind the request hash computed by the client and encrypt the full
page/cursor. Challenges are memory-only; restart changes the RPC instance and
requires a fresh challenge even if the durable cursor survives.

`depinreceivemsg` retains its timestamp/after_hash semantics **inside args**,
but also requires the v5 common signature. Its anchor may disappear through
expiry/deletion and its time cursor can miss late timestamps. Prefer the
sequence method when updating libraries. Operators must add it to their proxy
allowlist.

## Durable moderation (P8)

Authorized `depinclearmsg` operations write a hash tombstone and erase the
matching stored message in **one synchronous LevelDB batch before success**.
Scope boundaries and strict age thresholds are unchanged: section owners
cannot clear parents or siblings; `0` hours preserves same-second/future
messages while `all` selects them. Deletion includes an inactive retained
checkpoint when message retention is disabled; `removed` counts unique
hashes from memory and that checkpoint. Re-enabling retention cannot undo it.

The marks are local to the configured pool root and network datadir, and
remain durable **even with `-depinpoolpersist=0`**. A mark is checked before
admission and historical restoration. A new privacy envelope does not change
the signed message hash and cannot bypass the mark. A newly signed, changed
message with another hash is a new publication; the node cannot recognize
and censor all repeats of its encrypted plaintext.

Retain marks through `message.timestamp + 720h`, the largest supported TTL,
including equality. Raising the configured TTL cannot revive a moderated
hash. Expired marks can be pruned on startup or another purge. Pruning also
advances a durable minimum accepted timestamp; after a clock jump forward
and back, old hashes remain inadmissible by date even though their marks
have gone. A large incorrect clock jump can therefore make the service
reject newly dated messages until time catches up. Correct the clock and
inspect the preserved state; do not erase moderation state as a routine fix.

`-depintombstonelimit` defaults to 100000, maximum 1000000. If a deletion
would exceed it, the **whole operation fails**, removes nothing, and drops
no live mark. This is recoverable by increasing capacity or waiting until
marks can safely expire. Disk/sync/read failures reject the operation,
acknowledge no removal and disable permission-dependent service (`-10` on
subsequent calls) until restart. The failing purge reports `-20`. The
storage outcome of an I/O error can be uncertain: recovery may find the
entire batch or none, never an intentionally acknowledged partial batch.
Do not retry by discarding the state directory.

Protocol 5 binds administrative mode and age to the exact operation.
Changing expired to all, or altering hours, cannot reuse the proof. A purge
error is a signed/encrypted error body, never a success result. If the nonce
was consumed before storage failed, obtain a new one explicitly; do not
automatically repeat an administrative action after a lost response.

## Persistence and migration (P9b)

State lives at `depinstate-v2/<hash(serialized pool root)>` under the selected
network datadir. It reuses the node's LevelDB wrapper: WAL framing/checksums,
checksum verification, paranoid recovery and atomic synchronous batches.
There is no new ad hoc flat-file journal. Logical state version 2 stores:

- Critical version/root/stream/high-water/retention/migration metadata and
  the minimum accepted timestamp.
- Hash-indexed bounded message records containing admission sequence, signed
  wire message and a previously verified sender public key. This key is
  service metadata, outside the signed message/hash. Restoration checks its
  address binding and signature even if a reorg removed the key-reveal tx.
- Hash-indexed tombstone expiry values.
- Quarantined bounded complete invalid message records for diagnosis.

Message retention is off by default. When enabled, every acknowledged new
admission writes message + high-water metadata synchronously. It does not
wait for shutdown. Expiry/deletion never rewinds the counter. Shutdown can
also write a checkpoint, but crash durability does not depend on it.
Without retention, messages and the current stream are volatile; moderation
still syncs. Temporarily disabling retention preserves a prior checkpoint
under a fresh reserved identity. Re-enabling can restore its remaining
valid history, but cannot recover messages from volatile runs. A new cursor
is required. Moderation during those runs also edits that prior checkpoint.

Critical unreadable/incompatible metadata, malformed tombstones, inconsistent
sequence counters and unreadable record framing fail startup explicitly,
preserving the directory. A complete record with an invalid signed message
is quarantined and excluded; the counter is preserved and stream ID rotated
to report the discontinuity. Normal expiry and intentional deletion create
holes without rotating a retained stream. No repair tool scans ciphertext
for invented record boundaries. Checksums detect accidental corruption;
they do not authenticate operator-controlled storage against malicious edits.

On first retained startup, `depinpool.dat` version 1 is imported once using
bounded reads. It checks magic, version, count, file budget and trailing
data. Complete semantically invalid records can be skipped; truncation or a
length that prevents framing aborts migration. Historical permission rules
remain those of P9a. A new stream and new local sequences are assigned in
file order; v1 never recorded admission order, so it cannot be reconstructed.
The original remains untouched; a `.v1.bak` copy is also kept on successful
import. Migration completion and imported entries commit together. An
initial volatile startup does not suppress a later first migration.

These guarantees assume the filesystem/device honors synchronous writes.
They cover normal process crashes and detected corruption; they do not
recover missing/deleted files, malicious database edits, storage rollback to
an old backup, or a device that lies about durability. In particular, a
missing WAL suffix cannot always be distinguished from an uncommitted crash
tail. Preserve backups of the **whole stopped state directory**, not chosen
database files. Restoring an older backup can lose later moderation marks;
rotating a stream alone cannot recreate them. Stop the service and preserve
the damaged directory for diagnosis if startup fails. Do not silently reset
metadata or remove tombstones to resume service.

## Validation and remaining client work

The focused C++ tests cover strict encodings, bounded lengths, tags at
decryption, sequences/gaps/late timestamps, scope/age, retention toggles,
capacity exhaustion, clock rollback, v1 migration, quarantine and critical
corruption. `feature_depin_pool_state.py` uses an independent Python encoder
and system OpenSSL, real regtest submissions and abrupt process kills. It
also crosses the reply byte budget with 250 maximum-size messages.
`feature_depin_messaging_permissions.py` covers connected permissions,
reorganizations, revocations and concurrency. The real disk-full case is
opt-in (`DEPIN_DISK_FULL_TEST=1`) and requires a disposable filesystem of at
most 1 GiB; ordinary test runs never fill the developer's disk.

External libraries have deliberately not been changed. Their final migration
must check canonical encoding, explicit size semantics, strict decryption,
signed service identity, cursor storage/recovery, proxy allowlisting and
bounded handling of `-8`, `-10` and `-26`. No passing node test certifies an
untested external client. Full method signing P2 is implemented in the node;
P7 pool renewal is implemented; external migrations remain pending.
