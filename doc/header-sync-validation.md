# Header synchronization

Introduced in `b778146`. No activation height or block/transaction validity
rules are changed. The mainnet anchors are trusted validation data: they
authenticate header prefixes whose proof of work can then be omitted.
Their generation and review requirements are documented in
[header-anchors.md](../contrib/devtools/header-anchors.md).

## Implementation

- Validation/mining and `getkawpowhash` use separate, thread-safe light-context
  caches. Each epoch has one shared construction attempt; construction and waiting
  happen outside the cache mutex. Failures reach all waiters and allow a retry.
- Mainnet has 866 independently verified anchors, every 2,000 blocks through
  height 1,732,000. `-checkpoints=0` disables their use. Testnet and regtest have
  no anchors. A mismatch falls back to normal verification.
- Eligible KAWPOW headers are verified outside `cs_main` in single-epoch windows
  of at most `min(4 * nScriptCheckThreads, 64)` headers. Acceptance remains serial
  and authoritative. Small batches, incoherent heights, other algorithms and
  disabled concurrency retain the existing path. Successful workers write
  separate byte-sized marks, read only after joining.
- A window pins its context through acceptance, including a serial retry.
  Allocation and worker failures are local errors, not peer misbehavior.

The completed-context capacities are two for validation and one for the RPC.
At the mainnet heights used for validation (October 2026) those entries
occupied approximately 135 MB together.
In-progress constructions and contexts retained by callers can raise the peak;
this is not a process-wide memory limit.

`getibdstatus` reports header-validation progress. Its
`average_validation_us` includes batches of already-known headers, so it must
not be read as the cost of a batch containing only new headers.

## Tests

The concurrency tests include shared construction, failures, eviction pressure,
pin reservations, real KAWPOW vectors and simultaneous hashing. Header tests
cover false heights, epoch boundaries, invalid cheap prefixes, speculative work
counts, authoritative acceptance after checkpoint changes, processing the
remaining suffix, and notifications outside `cs_main`. The suites also run
under ThreadSanitizer and with `--enable-debug` (`DEBUG_LOCKORDER`).

## Effect

From an empty datadir, a single mainnet run reached the peers' announced
header height in about 20 minutes, against about 2 hours before this change.
Most of the improvement comes from the verified anchors; parallel verification
reduces the remaining unanchored work. Contextual validation still runs for
anchored headers. This measures header synchronization only, not complete block
synchronization or reindexing.

## Anchor provenance

Mainnet anchor provenance is checked into
[`contrib/devtools/header-anchors/2026-10-08`](../contrib/devtools/header-anchors/2026-10-08/README.md).
The provenance records retain source revisions, anchor digests and verification
heights.

Block import during `-reindex` and `-loadblock` is described in
[reindex-validation.md](reindex-validation.md).
