# Header synchronization optimization: validation record

Introduced in `b778146`, based on `eebd0cf`. No activation height or
block/transaction validity rules are changed. The mainnet anchors are trusted
validation data: they authenticate header prefixes whose proof of work can then
be omitted.
Their generation and review requirements are documented in
[header-anchors.md](../contrib/devtools/header-anchors.md).

This record describes validation of that implementation. It does not report
a rerun of later changes.

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
At the heights used for validation those entries occupied approximately
135 MB together.
In-progress constructions and contexts retained by callers can raise the peak;
this is not a process-wide memory limit.

## Tests

| Check | Result |
| --- | --- |
| Final release `make check VERBOSE=1` | 1,303 node cases; utilities, secp256k1 and univalue pass |
| Final `--enable-debug` (`-O0`, `DEBUG_LOCKORDER`) `make check VERBOSE=1` | Same 1,303 cases and supporting checks pass |
| Final related release groups | 54 cases pass |
| Anchors with serial verification, built independently | 35 related cases pass |
| Actual anchor-data group, run separately | Four cases pass in both final build modes and the serial variant |
| Cache under ThreadSanitizer | 13 cases pass |
| Header windows under ThreadSanitizer and `DEBUG_LOCKORDER` | 15 cases pass |
| Offline anchor generator | Six cases pass |

The concurrency tests include shared construction, failures, eviction pressure,
pin reservations, real KAWPOW vectors and simultaneous hashing. Header tests
cover false heights, epoch boundaries, invalid cheap prefixes, speculative work
counts, authoritative acceptance after checkpoint changes, processing the
remaining suffix, and notifications outside `cs_main`.

Three cache mutations and seven header-processing mutations cause test failures.
An additional mutation taking `cs_main` before parallel verification triggers
`AssertLockNotHeld`. Final release and debug suites included the anchor-data
tests, and the tested sources were checked against the implementation.

## Measurement method

Each measured node starts with an empty datadir. The measurements end when its
header height reaches the maximum height initially announced by its peers;
they do **not** measure complete block synchronization or reindexing. Sampling
is approximately once per minute, with additional RPC lock delays. Completion
times use the observation timestamp, or the original completion file timestamp
for earlier runs, rather than the time at which a blocked RPC was requested.

The final serial-anchor and parallel-anchor variants were measured sequentially
with matching resource limits, node options and peer selection. Earlier
reference and intermediate runs had different peer selection and concurrent
workloads, so the full table is not a controlled percentage comparison.
The parallel-only trial used an intermediate implementation; the combined
measurement uses the final implementation, including notification batching.
The RPC's `average_validation_us` includes batches of already-known headers, so
it must not be read as the cost of a batch containing only new headers.

| Variant | Header time (min) | Header timeouts | Peak RSS (MiB) | RPC mean batch validation (ms) |
| --- | ---: | ---: | ---: | ---: |
| Original reference | 125.3 | 4 | 1367 | 1488.0 |
| Safe caches only | 129.2 | 4 | 1387 | 1901.7 |
| Parallel verification, no anchors (intermediate) | 68.0 | 1 | 1339 | 609.8 |
| Anchors with serial verification | 21.3 | 0 | 1272 | 203.7 |
| Anchors and parallel verification (final) | 20.1 | 0 | 1287 | 224.0 |

- Anchors with serial verification: the anchored prefix reached height 1,732,000 after 16.4 min; 4.9 min remained until the completion sample.
- Anchors and parallel verification (final): the anchored prefix reached height 1,732,000 after 17.2 min; 2.9 min remained until the completion sample.

These are single-run observations, rounded to match the sampling resolution. The initial targets vary as mainnet advances. The large improvement comes from the verified anchors; parallelism reduces the remaining unanchored work. Contextual validation still runs for anchored headers. The earlier reference/configuration limitations above apply.

## Provenance and related validation

Mainnet anchor provenance is checked into
[`contrib/devtools/header-anchors/2026-10-08`](../contrib/devtools/header-anchors/2026-10-08/README.md).
The provenance records retain source revisions, anchor digests and verification
heights. Environment-specific paths, machine identifiers and invocation details
are omitted from the public record.

Phase 3 (`-reindex`/`-loadblock`) is a separate change based on the completed
phases above. Its implementation, tests and complete before/after reindex
measurements are recorded in [reindex-validation.md](reindex-validation.md).
These pruned header-synchronization trials do not establish its end-to-end
benefit.
