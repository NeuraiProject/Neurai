# Reindex and block import optimization: validation record

Phase 3 of the header synchronization plan, requested on 8 October 2026 and
based on `b778146efed029aa939092f624ca83cb523c1904`. This change reuses a PoW
check within a single call; it adds no anchors and changes no activation
heights or block validity rules.

## Implementation

`AcceptBlockHeader` reports whether it actually checked PoW in the current
call. The report starts false and remains false for an already-known header,
genesis, or a header whose check was skipped using a preverified mark.
`AcceptBlock` retains `cs_main` throughout header and block validation. Only
a fresh successful check allows its subsequent `CheckBlock` call to omit PoW.
Merkle, transaction and contextual checks retain their existing behavior.

After the remaining context-free checks succeed, `fChecked` is retained as
before. It is neither an index flag nor a serialized field. A header accepted
through an anchor cannot use this optimization when its block later arrives.
Reading a block again for connection retains the existing validation path.

When both import steps would perform full KAWPOW, the new header now needs one
full check instead of two. Headers that were already known and checkpoint
shortcuts retain their existing validation requirements. This is not a promise
to halve complete reindex time: reading, contextual checks, connecting blocks,
scripts and database writes still cost time, and connection may itself require
PoW checks. The benefit concerns `-reindex` and `-loadblock` importing new
headers; `-reindex-chainstate` and normal reception of blocks with known
headers do not gain this reduction.

## Tests

The new `block_import_tests` group uses the real `LoadExternalBlockFile` path
with serialized blocks and the existing full-KAWPOW counter. Its 11 cases cover:

- One full check per new header, followed by successful connection and UTXOs.
- Retained PoW validation for known headers, including a falsely preverified
  header with a valid cheap hash and an invalid mix.
- Reindex's deferred processing of a child stored before its parent.
- Bad PoW, corrupted Merkle data and retry with the correct body, multiple
  coinbases, and an incorrect coinbase height.
- Preservation of completed block checks without serializing `fChecked`.
- SHA256d block import and rejection of bad SHA256d PoW.

Ubuntu 24.04 Docker, GCC 13:

| Check | Result |
| --- | --- |
| New import group, release | 11 cases pass |
| New import group, `DEBUG_LOCKORDER` | 11 cases pass |
| Complete release `make check VERBOSE=1` | 1,314 node cases; utilities, secp256k1 and univalue pass |
| Complete debug `make check VERBOSE=1` | Same 1,314 cases and supporting checks pass |
| Restore the redundant PoW check | Import tests fail (exit 201) |
| Skip PoW for known headers too | Import tests fail (exit 201) |
| Lose the completed block check cache | Import tests fail (exit 201) |

Test preparation was corrected before these final runs: bad-PoW candidates
use a half-range target rather than searching for failures at regtest's nearly
unrestricted target, and the out-of-order child's difficulty is calculated
from its parent. Both compiled source trees match the final validation and
test files. The production implementation did not need changes during testing.

## Complete reindex measurement

Preparation and measurement are isolated from the existing services on the
authorized Docker host. A separate mainnet copy was synchronized without
pruning through height 1,814,000. The benchmark runs the reference and optimized
binaries sequentially on copies of the same frozen block files,
with `-reindex -stopafterblockimport -dbcache=512 -par=4 -prune=0`, networking
disabled, and the same 12-CPU / 24-GiB container limits. Our builds and unit
tests finish before either measurement starts.

This is one sequential comparison on a shared Intel Core i9-14900K host.
Other host activity was present (observed load averages around 5–12 on 32
logical CPUs), so scheduling, CPU frequency and shared caches can affect
elapsed times. The import tests independently establish the removed duplicate
work by counting full KAWPOW checks.

The driver records binary and input-file hashes, elapsed time, peak RSS, and
the final chain height/hash, UTXO statistics and asset metadata. It requires
identical final state and restores the original block-file input before the
second run if reindex truncated preallocated padding.

Both runs completed successfully on 8 October 2026. The frozen input contained
29 block files (3,807,516,159 bytes) and complete blocks through height
1,814,024. The reference and optimized runs used identical arguments and block
file bytes; neither run changed those input bytes.

| Full reindex, including connection and shutdown | Reference `b778146` | Phase 3 |
| --- | --- | --- |
| Elapsed time | 10,657.3 s (2 h 57 min 37 s) | 6,492.9 s (1 h 48 min 13 s) |
| Peak RSS observed | 2,574,836 KiB | 2,576,108 KiB |

This run took **39.1% less elapsed time** (1.64 times as fast), saving about
69 minutes. This is the observed end-to-end result on this host, not a general
guarantee or a measurement of initial network synchronization. Timing includes
startup and clean shutdown, sampled at two-second intervals; the subsequent
RPC snapshots are outside the timed interval.

Final state matches:

- Height: **1,814,024**.
- Best block: `0000000000296bd625fb0bde0e6ca90497609516d10c5efabbaff83e2f553af8`.
- UTXO `hash_serialized_2`: `331331be0e0da1be22703f9f0256c0f94c53730a75cd2880fd487bc3ac1d4275`.
- 3,291,969 outputs, 257,258 transactions and exactly
  **17,569,891,649.73574570 XNA** in the UTXO statistics.
- All metadata for **100 assets**, including exact amounts. The raw asset RPC
  response is byte-identical between runs (SHA256
  `e53e17fa761fa4830ceda8e7632cbf9323ac3a8cddbe0c9bb2ecfae5b6f35e03`).

The final comparison parses the raw RPC responses with decimal arithmetic,
avoiding the rounding in the driver's initial JSON summary. Only UTXO
`disk_size` is excluded: LevelDB's physical sizes differ (160,301,928 and
163,192,034 bytes), while all logical UTXO statistics match.

Full logs, binaries, block files, source checksums and the drivers are retained
in `/home/docker-test/header-sync-20261007/phase3` on the authorized test host.
A compact copy of the test logs, benchmark evidence and exact state comparison
is kept locally in `tmp/reindex-validation-20261008/final-evidence.tar.gz`.
The test nodes and containers are stopped after validation. No commit was made.
