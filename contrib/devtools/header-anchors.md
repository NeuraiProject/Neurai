# Generating header anchors

An anchor authenticates the preceding linked headers and permits skipping their
proof of work. Treat changes to these hashes as changes to trusted validation
data. Matching output from two nodes is necessary; it does not, by itself, prove
that either node checked the underlying chain.

Use two independently synced mainnet nodes on different machines or operated by
different people. Both must have checked the full KAWPOW proof of every header in
the new range. At least one must sync with `-checkpoints=0`, which disables the
header anchors. Wait until **blocks**, as well as headers, have reached the
checkpoint used for generation.

Run the same command independently on each machine, adjusting the source identity
and connection arguments:

```sh
python3 contrib/devtools/gen-header-anchors.py \
  --cli /path/to/neurai-cli --datadir /path/to/mainnet \
  --checkpoint-height 1733712 \
  --checkpoint-hash 000000000065bd9be24a1328484cc1904c5d6f8bc8986088bb1f84c26bed6897 \
  --source-id machine-and-operator --source-commit FULL_NODE_COMMIT \
  --output /path/to/chainparamsanchors.h
```

The header is deterministic. The adjacent `.json` file records the node version,
source commit, source tip, RPC command and output hashes. Preserve the exact
generator command and evidence of the node's build and synchronization alongside
these files. The script checks mainnet's genesis, the checkpoint, sufficient
validated height and whether the chain reorganized during collection.

For an uncommitted test build, record its base with `--source-commit` and supply
`--source-changes /path/to/source-changes.tar`. Preserve that exact archive and
the binary checksums. Its SHA-256 is included in the provenance; the base commit
alone must not be presented as the source of a modified binary. Record upgrades
during synchronization, including the height and both builds, in the evidence.

Compare the generated headers byte for byte with `cmp`. Include both provenance
files and their hashes in the review. Only then copy the agreed header into
`src/chainparamsanchors.h` and populate mainnet's `HeaderAnchors()`. Testnet and
regtest must stay empty. Check that every checkpoint on an anchor height matches.

For an update, supply `--previous /path/to/previous-release/chainparamsanchors.h`.
The existing output is used as the previous version when `--previous` is omitted.
Existing hashes cannot change or disappear; only new entries may be appended.
Retain a digest of the previous prefix in the unit test as an independent check.

Run the generator's offline tests with:

```sh
python3 contrib/devtools/test_gen_header_anchors.py
```

The generator does not enable an anchor automatically, change consensus
parameters, or publish anything.

The first enabled set has 866 mainnet anchors through height 1,732,000, bounded
by checkpoint 1,733,712. Its independent provenance is in
[`header-anchors/2026-10-08`](header-anchors/2026-10-08/README.md). The unit tests
check the existing checkpoints, empty test networks, and a fixed digest of this
prefix so subsequent sets can only append.
