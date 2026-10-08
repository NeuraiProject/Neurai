# Initial verified mainnet anchors

Both generated headers matched byte for byte after each node had validated
blocks beyond checkpoint 1,733,712. These were independent datadirs on two
physical machines, operated by the same person, using public mainnet peers.
No database or block-index files were copied between them.

| Source | Build and verification | Validated height when collected |
| --- | --- | --- |
| `dev128-baseline` | Unmodified `eebd0cfdc43d134a91147233574804ef9a09665d`, serial header verification, no anchor implementation | 1,738,122 |
| `trantor-independent` | Started with that same build; switched at 386,000 headers and zero blocks to the tested parallel implementation with an **empty** anchor list; `-checkpoints=0` throughout | 1,738,497 |

The independent build's base commit alone does not identify its source.
`independent-source-manifest.json` records every file in its source overlay
and the SHA-256 of the preserved archive. That snapshot predates the final
notification batching change; it is the build actually used for verification.
The RPC arguments, source tips and output digests are recorded in the two JSON
provenance files. Their different source tips do not affect the fixed anchor set.

- Header SHA-256: `cc2f3df19e8382e44d877a30863c59dbcd6fcbfe0d9d0846fadcb75b9350067b`.
- Prefix SHA-256 (concatenated lowercase hexadecimal hashes): `a81616274f7a23ddf0912a090369faf7c5eef88f2a64bbf80db728154c8b1c66`.
- Count: 866; interval: 2,000; last anchor: 1,732,000.
- The nine existing checkpoints on anchor heights also match.

Session evidence is preserved locally in
`tmp/header-sync-independent-20261007` and remotely in
`/home/docker-test/header-sync-20261007`. It includes the exact generated files,
generator invocations, binary checksums, source overlay, upgrade heights,
configuration and synchronization timelines. Preserve those artifacts with the
review; the ignored runtime directory is not included in a source commit.

To reproduce the data, follow [the generation procedure](../../header-anchors.md)
against two independently verified nodes. Do not treat matching RPC output alone
as evidence that their proof of work was checked. Do not change an existing entry
when adding anchors in a later release.
