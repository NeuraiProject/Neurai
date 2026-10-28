# Asset rewards, snapshots and channel messages

Node contract for asset reward distributions and asset channel messages
(NIP-048). The node computes and verifies; it never pays. It records who held
an asset at a block, computes a deterministic distribution plan that commits to
every payment, builds batches that the operator signs and broadcasts, and tells
what was paid. A chain-wide index serves the messages that owner and message
channel tokens carry. None of this changes consensus.

## Options and stores

| Option | Default | Effect |
| --- | --- | --- |
| `-assetrewards` | on with `-assetindex` or when `rewards/` exists | Snapshot stores used by the reward RPCs, which also need `-assetindex` |
| `-assetmessages` | on when `messages/` exists | The wallet's legacy message inbox (`viewallmessages`, `subscribetochannel`, ...) |
| `-disablemessaging` | 0 | Same as `-assetmessages=0`; refused together with `-assetmessages=1` |
| `-minrewardheight=<n>` | 60 | Blocks the chain must be past a snapshot before a plan is computed |
| `-minsnapshotnotice=<n>` | 60 | Blocks an announcement must precede the snapshot height to count as timely |
| `-maxsnapshotrequests=<n>` | 16 | Different assets whose snapshot can be requested at one height; 0 for no limit |
| `-channelmessageindex` | 0 | Chain-wide channel message index; refused with `-prune` |
| `-pubkeyindex` | 0 | Needed by `getsnapshotrecipients` |

A data directory that already has `messages/` or `rewards/` keeps using it;
a new one creates them only when asked. Turning a module off never deletes its
store. `getblockchaininfo` reports `asset_services`: for each module whether it
is active and whether its store is on disk, and for rewards whether
`-assetindex` is on. DePIN messaging (`-depinmsg`) is a separate system.

## Distributing a reward

1. **Announce the height (recommended).** `getsnapshotannouncement "ASSET"
   height` returns a message. The holder of the owner token sends the token to
   its own address with that message, at least `-minsnapshotnotice` blocks
   before the height:

   ```
   neurai-cli transfer "ASSET!" 1 "<owner token address>" "<message>"
   ```

   Other nodes see it (see [Channel messages](#channel-messages)) and capture
   the same snapshot, so they can check the plan without trusting the issuer.
2. **Request the snapshot** before the chain reaches the height:
   `requestsnapshot "ASSET" height`. Each node that requests it captures it
   when it connects that block, reading every holder, so a node accepts at
   most `-maxsnapshotrequests` different assets at one height. Repeating a
   request changes nothing.
3. **Compute the plan** once the chain is `-minrewardheight` blocks past the
   height:

   ```
   neurai-cli getdistributionplan "ASSET" height "XNA" 1000 "<excluded addresses>" \
       '{"remainder": "payer", "announcement": {"txid": "<announcement txid>"}}'
   ```

   The result lists every recipient with its amount, the zero shares, the
   excluded holders with a reason, the remainder and the `plan_hash`. Nothing
   is spent or locked. The operator approves the plan by its hash and may
   publish the hash as a channel message.
4. **Give recipients their proof.** `getdistributionproof {plan} "address"`
   returns an RFC 6962 inclusion proof against the plan's Merkle root.
5. **Build each batch.** `getdistributionbatches {plan} ( {"max_outputs": n} )`
   splits the payments, in plan order, into batches of at most `max_outputs`
   recipients (default 500, at most 1000). In the paying wallet:

   ```
   neurai-cli createdistributionbatch "<plan_hash>" '<plan>' 0 '{"max_fee": 0.1}'
   ```

   The call recomputes the plan and refuses a different hash, builds one
   transaction for the batch (asset inputs and asset change included), signs
   it with the wallet's keys, locks its inputs and returns it **without
   broadcasting**. Store the result (txid, hex, anchor, inputs) in the batch
   records, then send it with `sendrawtransaction`.
6. **Follow the batches.** `verifydistribution {plan} [records]` classifies
   every batch from its recorded versions. Build only the batches it reports
   as `unknown` (never built) or `conflicting`.

The node keeps the plans computed at the current tip: proofs for every
recipient and the batches of a plan cost one computation per block, not one
per call.

`{plan}` is an object with the parameters of `getdistributionplan`:
`asset_name`, `snapshot_height`, `distribution_asset_name`, `amount` and,
optionally, `exception_addresses`, `remainder`, `allow_legacy_snapshot`,
`announcement`, `qualifier`, `weights`, `report`, `allocation` and
`min_held`.

### Batch states and recovery

| State | Meaning | Action |
| --- | --- | --- |
| `confirmed` | A version that pays the batch has the required confirmations (default 6) | Paid |
| `confirming` | A version is in the active chain with fewer confirmations | Wait; its recipients stay reserved |
| `pending` | A version is in the mempool, or signed with all inputs unspent | Rebroadcast it; do not build a new one |
| `conflicting` | Every version has an input spent by another transaction | Check what that transaction paid, then rebuild the rest with a new anchor |
| `unknown` | No recorded version, or the node cannot tell | Review before building anything |

Every version of a batch spends the same **anchor**, the first XNA input of the
first version, so at most one version can confirm. To build a new version
(for instance after the first one left the mempool), release the earlier
version's inputs with `lockunspent true` and pass its anchor:
`createdistributionbatch ... '{"anchor": {"txid": "...", "vout": n}}'`.
Wallet locks are kept in memory only.

Records passed to `verifydistribution` are signed versions, as hex or as
`{"hex": ..., "block_hash": ...}`. A version is located through its block hash,
`-txindex` or one of its unspent outputs; telling `conflicting` from a
confirmed version whose outputs were all spent needs `-txindex` or the block
hash. A version that does not pay its batch exactly is reported and ignored.

Batches do not rely on replace-by-fee, which is off by default and never
accepted for asset transactions. Fees are estimated by the wallet (`max_fee`
sets a ceiling); a stuck batch can be bumped with a child transaction that
spends its XNA change, or rebuilt with the same anchor once its version has
left the mempool.

`distributereward` no longer pays and fails with error -32; the node never
builds or retries payments by itself. `getdistributestatus` still reads the
records of earlier distributions.

## Snapshots

| `format` | Captured by | Commits to |
| --- | --- | --- |
| 0 | releases before NIP-048 | Holders only, no block identity; plans need `allow_legacy_snapshot` |
| 1 | early NIP-048 builds | Holders and the block hash |
| 2 | this release | Holders, block hash and holder state |

A snapshot is bound to the block it was captured on. When that block is
disconnected the snapshot is dropped, and the pending request captures a new
one when a block at that height is connected. Holder state is, per holder, a
freeze for the asset (restricted asset freeze or DEPIN owner freeze), a DEPIN
self-revocation and the qualifier tags of the address, plus the asset's global
freeze. `getsnapshot` shows all of it.

`replaysnapshot "ASSET" height ( "expected_snapshot_hash" )` rebuilds the
holders and their state at the height from the blocks and their undo data,
without any snapshot, and compares the hash with the stored snapshot
(`matches_stored`) and with a given hash (`matches_expected`). It reads every
block from asset activation, so it is slow on a long chain and refused on a
pruned node.

## Eligibility and allocation

A holder is excluded, with the first reason that applies, when it is in
`exception_addresses` (`exception`), a burn address (`burn`), the asset is
globally frozen (`globally_frozen`), the holder is frozen (`frozen`) or
self-revoked (`self_revoked`), it lacks the plan's `qualifier` tag
(`missing_qualifier`), it holds less than `min_held` (`below_minimum`), or the
plan has report weights and none for it (`no_weight`). Freezes and
self-revocations exclude holders whenever the snapshot has holder state.

Each eligible holder receives `floor(A * w / W)` whole units of the
distribution asset, where `w` is its holding (its report weight, or 1 with
equal allocation), `W` the sum and `A` the amount, which must be a whole
number of units. Products use 256-bit integers. The undivided remainder stays
with the payer (`"remainder": "payer"`, the default) or goes one unit at a
time to the largest fractional parts, ties broken by output script
(`"largest"`).

- `allocation`: `"holdings"` (the default) splits in proportion to the
  holdings, or to the report weights; `"equal"` gives every eligible holder
  the same share, whatever it holds, for instance one share per DEPIN device.
  `"equal"` cannot be combined with `weights`.
- `min_held`: only holders with at least this amount of the asset, in either
  allocation. For instance `{"allocation": "equal", "min_held": 100}` splits
  the amount equally among the holders of 100 tokens or more.
- `qualifier`: only holders tagged with it at the height, for instance
  `"#VERIFIED_DEVICE"`. Needs a format 2 snapshot.
- `weights`: `{"address": weight, ...}`, positive integers from a work report.
  They replace the holdings. The node never measures work: the plan shows that
  it follows the report, not that the report is true.
- `report`: `{"txid": ..., "block_hash": ...}`, the owner token transfer whose
  message is the report hash; the node checks it like an announcement.

## Plan format

All hashes are SHA-256 of a one-byte tag followed by the fields. Strings and
scripts carry a CompactSize length, integers are little endian, 256-bit values
are their 32 bytes in internal order. RPCs show block hashes and txids
reversed, as usual, and the other hashes in hash output order.

| Hash | Tag | Fields after the tag |
| --- | --- | --- |
| Leaf | `0x00` | output script, amount (int64) |
| Merkle node | `0x01` | left, right |
| Plan | `0x02` | see below |
| Snapshot, format 1 | `0x03` | asset, height (int32), block hash, count, then (script, held int64) by script |
| Batch id | `0x04` | plan hash, max outputs (uint32), batch index (uint32) |
| Announcement | `0x05` | network, asset, height (int32) |
| Snapshot, format 2 | `0x06` | asset, height, block hash, global freeze (uint8), count, then (script, held, flags (uint8: 1 frozen, 2 self-revoked), sorted tags) by script |
| Report | `0x07` | count, then (address, weight int64) by address |

Recipients are ordered by output script. The Merkle tree follows RFC 6962: one
leaf is its own root, larger trees split at the largest power of two smaller
than the leaf count, and an empty tree hashes to SHA-256 of nothing.

The plan hash covers: version (uint8), network, asset, snapshot height (int32),
snapshot block hash, snapshot hash, then from version 2 the announcement txid
(zero if none), from version 3 the qualifier and the report hash (zero if
none), from version 4 the allocation (uint8: 0 holdings, 1 equal) and the
minimum holding (int64, 0 if none), and finally the distribution asset, amount
(int64), remainder policy (uint8: 0 payer, 1 largest), sorted exception
addresses, distributed amount, remainder (int64 each), recipient count
(uint32) and Merkle root. Version 1 is a plain plan, version 2 names an
announcement, version 3 has a qualifier or report weights, version 4 has equal
allocation or a minimum holding.

[`src/test/data/nip048_vectors.json`](../src/test/data/nip048_vectors.json)
holds vectors for every hash, proof and allocation rule, generated by
`contrib/devtools/nip048-vectors.py` from the Python reference in
`test/functional/test_framework/nip048.py` and checked by the unit tests. An
implementation outside the node can use the same file.

### What each piece of evidence shows

| Evidence | Shows | Does not show |
| --- | --- | --- |
| Plan hash anchored on the owner token | The owner committed to this plan at that block | That the plan is correct |
| Inclusion proof | The payment is part of the plan | That the amount is right or that nobody is missing |
| `verifydistribution` | The payments match the plan | That the plan is correct |
| Recomputing the plan from the snapshot | The plan is correct and complete under its rules | That a report's measurements are true |

`getdistributionplan` reports `verifiability`: `announced` when the height was
announced with enough notice, so other nodes could capture the snapshot;
`late_announcement`; or `unannounced`, when recipients rely on the issuer's
snapshot or on `replaysnapshot`.

## Channel messages

A channel message is a message carried by an owner token (`NAME!`) or a message
channel token (`NAME~CHANNEL`) sent back to the address it came from. With
`-channelmessageindex` the node indexes every such message of every channel,
whatever the wallet, in `indexes/channelmessages/`:

```
neurai-cli getchannelmessages "ASSET!" '{"from_height": 1000, "include_expired": true}'
```

Options: `from_height`, `to_height`, `include_expired`, `reference_time`,
`message` (only messages with that payload), `include_tx` (raw transaction),
`include_proof` (a proof checked with `verifytxoutproof`) and `limit`
(default 1000, at most 10000). A page never splits a block, so its last block
may go past the limit; `next_from_height` is the `from_height` of the next
page, or null when there is none. Each message
shows its channel, `authority` (`owner` or `channel`), txid, height, block,
expiry, payload (IPFS hash or 64-hex hash), sender address and, when the
transaction has one, the data of its `OP_RETURN` output. `op_return_matches`
is true when the message is the SHA-256 of that data: content the token holder
published in full, without IPFS.

Expiry is decided at query time against `reference_time`, by default the
median time past of the tip, so nodes with the same chain answer alike. Records
of blocks that leave the active chain are ignored rather than deleted. Enabling
the index on a synced node indexes the missing blocks at startup; a restart
resumes where it stopped. REST:
`GET /rest/channelmessages/<FROM-HEIGHT>/<CHANNEL>.json` (see
[REST-interface.md](REST-interface.md)).

To find a snapshot announcement:
`getchannelmessages "ASSET!" '{"message": "<message from getsnapshotannouncement>"}'`.

## Encrypted bulletins to holders

`getsnapshotrecipients "ASSET" height` lists the holders of a snapshot for an
encrypted message to all of them, encrypted as DePIN messages are: `ready`
(P2PKH or strict ECDSA address with its public key in `-pubkeyindex`, which is
returned), `key_not_revealed`, or `unsupported_type` (post-quantum and script
addresses), with their freeze and self-revocation. Encryption, storage and
reading happen outside the node.

## Limits

- The channel message index checks at startup that every block is indexed, but
  does not compare records byte by byte with a rebuild.
- `verifydistribution` does not search for payments whose txids were lost;
  without records they need manual review.
- Snapshot announcements and channel messages use the 64-hex or IPFS message
  field; an `OP_RETURN` payload is relayed up to 512 bytes on testnet and
  regtest and 83 bytes on mainnet (`-datacarriersize`).
