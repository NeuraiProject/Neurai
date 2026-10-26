# Reindex and block import

Introduced in `16e9e18`. This change reuses a PoW check within a single call;
it adds no anchors and changes no activation heights or block validity rules.

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

The `block_import_tests` group uses the real `LoadExternalBlockFile` path
with serialized blocks and the existing full-KAWPOW counter. It covers:

- One full check per new header, followed by successful connection and UTXOs.
- Retained PoW validation for known headers, including a falsely preverified
  header with a valid cheap hash and an invalid mix.
- Reindex's deferred processing of a child stored before its parent.
- Bad PoW, corrupted Merkle data and retry with the correct body, multiple
  coinbases, and an incorrect coinbase height.
- Preservation of completed block checks without serializing `fChecked`.
- SHA256d block import and rejection of bad SHA256d PoW.

## Effect

In a single comparison on the same frozen mainnet block files (through height
1,814,024, networking disabled), a complete `-reindex` took about 1 h 48 min
instead of about 2 h 58 min, with the same peak memory and an identical final
chain state, UTXO set and asset metadata. This is an observed result, not a
general guarantee or a measurement of initial network synchronization.
A second full reindex on 26 October 2026, with the 2.0.0 candidate and block
files up to height 1,840,569, reproduced the same state at height 1,814,024.

Header synchronization is described in
[header-sync-validation.md](header-sync-validation.md).
