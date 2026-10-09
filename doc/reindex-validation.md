# Reindex and block import optimization: validation record

Introduced in `16e9e18`, based on `b778146`. This change reuses a PoW
check within a single call; it adds no anchors and changes no activation
heights or block validity rules.

This record describes validation of that implementation. It does not report
a rerun of later changes.

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

| Check | Result |
| --- | --- |
| New import group, release | 11 cases pass |
| New import group, `DEBUG_LOCKORDER` | 11 cases pass |
| Complete release `make check VERBOSE=1` | 1,314 node cases; utilities, secp256k1 and univalue pass |
| Complete debug `make check VERBOSE=1` | Same 1,314 cases and supporting checks pass |
| Restore the redundant PoW check | Import tests fail (exit 201) |
| Skip PoW for known headers too | Import tests fail (exit 201) |
| Lose the completed block check cache | Import tests fail (exit 201) |

The tested release and debug sources were checked against the implementation.

## Complete reindex measurement

The reference and optimized binaries were measured sequentially using identical
copies of frozen mainnet block files, matching node options and resource limits,
and networking disabled. The complete block history through height 1,814,024
was used for both runs.

This is a single comparison. Resource contention, scheduling and caching can
affect elapsed times. The import tests independently establish the removed
duplicate work by counting full KAWPOW checks.

The driver records binary and input-file hashes, elapsed time, peak RSS, and
the final chain height/hash, UTXO statistics and asset metadata. It requires
identical final state and restores the original block-file input before the
second run if reindex truncated preallocated padding.

Both runs completed successfully and preserved the input block-file bytes.

| Full reindex, including connection and shutdown | Reference `b778146` | Phase 3 |
| --- | --- | --- |
| Elapsed time | 10,657.3 s (2 h 57 min 37 s) | 6,492.9 s (1 h 48 min 13 s) |
| Peak RSS observed | 2,574,836 KiB | 2,576,108 KiB |

This run took **39.1% less elapsed time** (1.64 times as fast), saving about
69 minutes. This is an observed end-to-end result, not a general
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
`disk_size` is excluded because LevelDB's physical layout can differ while all
logical UTXO statistics match.
