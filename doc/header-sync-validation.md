# Header synchronization optimization: validation record

Work performed on 7–8 October 2026, based on
`eebd0cfdc43d134a91147233574804ef9a09665d`. No activation height or block/transaction
validity rules are changed. The new mainnet anchors are trusted validation data:
they authenticate header prefixes whose proof of work can then be omitted.
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
At current mainnet heights those entries occupy approximately 135 MB together.
In-progress constructions and contexts retained by callers can raise the peak;
this is not a process-wide memory limit.

## Tests

Linux Docker, GCC 13, Ubuntu 24.04:

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
`AssertLockNotHeld`. ThreadSanitizer required `setarch x86_64 -R` in its isolated
test container because the default address layout prevented startup; no host
ASLR setting was changed.

An initial final build omitted the new anchor-data test file because generated
Makefiles were stale. That run is not counted as final validation. After
`autogen.sh` and reconfiguration using the original `CONFIG_SITE`, the four
cases were run separately and both complete suites were repeated. The final
release and debug trees match all 34 files in the tested source overlay.

## Measurement method

Each measured node starts with an empty datadir. The measurements end when its
header height reaches the maximum height initially announced by its peers;
they do **not** measure complete block synchronization or reindexing. Sampling
is approximately once per minute, with additional RPC lock delays. Completion
times use the observation timestamp, or the original completion file timestamp
for earlier runs, rather than the time at which a blocked RPC was requested.

The remote host is an Intel Core i9-14900K with 32 logical CPUs. The container
has a 12-CPU quota and 24 GiB memory limit. Node options include `-par=4`,
`-dbcache=512`, `-prune=2048`, `-disablewallet`, `-debug=net` and `-debug=bench`.
The two final variants run sequentially with the same six explicit peers and
without our compilation or test jobs running alongside them.

The earlier reference used eight DNS-selected peers, while phase 0 and the
parallel-only trial used six explicit peers. Those earlier runs overlapped other
synchronizations and builds. They provide observed IBD timings, not a controlled
percentage improvement. The parallel-only trial used the preserved r2 snapshot;
the combined measurement uses the final code, including notification batching.
The RPC's `average_validation_us` includes batches of already-known headers, so
it must not be read as the cost of a batch containing only new headers.

| Variant | Header time (min) | Header timeouts | Peak RSS (MiB) | RPC mean batch validation (ms) |
| --- | ---: | ---: | ---: | ---: |
| Original reference | 125.3 | 4 | 1367 | 1488.0 |
| Safe caches only | 129.2 | 4 | 1387 | 1901.7 |
| Parallel verification, no anchors (r2) | 68.0 | 1 | 1339 | 609.8 |
| Anchors with serial verification | 21.3 | 0 | 1272 | 203.7 |
| Anchors and parallel verification (final) | 20.1 | 0 | 1287 | 224.0 |

- Anchors with serial verification: the anchored prefix reached height 1,732,000 after 16.4 min; 4.9 min remained until the completion sample.
- Anchors and parallel verification (final): the anchored prefix reached height 1,732,000 after 17.2 min; 2.9 min remained until the completion sample.

These are single-run observations, rounded to match the sampling resolution. The initial targets vary as mainnet advances. The large improvement comes from the verified anchors; parallelism reduces the remaining unanchored work. Contextual validation still runs for anchored headers. The earlier reference/configuration limitations above apply.

## Evidence and remaining optional work

Mainnet anchor provenance is checked into
[`contrib/devtools/header-anchors/2026-10-08`](../contrib/devtools/header-anchors/2026-10-08/README.md).
Session logs, source overlays, binary checksums, configurations and timelines are
preserved in `/home/docker-test/header-sync-20261007` on the authorized Docker
host and `tmp/header-sync-independent-20261007` locally. Runtime data is ignored
by Git and must be retained separately if the review is moved elsewhere.

Phase 3 (`-reindex`/`-loadblock`) is a separate change based on the completed
phases above. Its implementation, tests and complete before/after reindex
measurements are recorded in [reindex-validation.md](reindex-validation.md).
These pruned header-synchronization trials do not establish its end-to-end
benefit.
