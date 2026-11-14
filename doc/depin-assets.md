# DEPIN assets: rules an operator should know

DEPIN assets are experimental and available on testnet and regtest only. This
page collects the rules of the asset itself that are easy to assume wrong. The
messaging service built on top of it is described in
[depin-guide.md](depin-guide.md).

## Names

| Element | Form | Rule |
|---|---|---|
| Root | `&NAME` | `A-Z 0-9 . _`, at least three characters after `&` |
| Section | `&NAME/SUB` | Issued by transferring the owner token of its parent |
| Owner token | `&NAME!` | Created with the asset; transferable |

A name is at most 120 characters long, sections included. The limit of asset
names is 121 and one character is kept for the `!` of the owner token, as in
every other asset type.

## Who can do what

- The owner acts by spending and re-emitting the owner token in the same
  transaction. That lifts the soulbound rule; it does not replace signatures:
  **the owner cannot take units out of a holder's address**, because spending
  them still needs the holder's key.
- The owner token is transferable. Whoever receives it holds every power over
  the asset and its holders.
- A restriction is tied to the address that holds the units: a key-hash address
  or an AuthScript address (generic v1, strict v2 and v3). Two addresses of the
  same key are different addresses with independent restrictions.
  Script-hash addresses cannot hold assets and cannot be frozen or unfrozen.

## Transfer state

`CLOSED` (default) → `OPEN` → `CLOSED`, and `CLOSED` → `SEALED`.

- `SEALED` is final and only forbids opening again. It does **not** freeze the
  supply: the owner can still distribute and move units under the owner escort.

## Freeze, unfreeze and self-revocation

- `unfreezedepin` clears both the owner freeze and a self-revocation. The owner
  can therefore reactivate an address its holder revoked, without the holder's
  consent. A holder that revokes an address because its key leaked depends on
  the owner not undoing it.
- A freeze and a self-revocation of the same address can confirm in the same
  block; the address is then both frozen and self-revoked.

## Rules are judged against the tip

Every DEPIN rule is evaluated against the state at the connected tip, not
against earlier transactions of the block being built.

- A `CLOSE` or a freeze and a pending holder transfer are both valid against
  the tip, so they **can** confirm in the same block, and the transfer then
  escapes the close or the freeze. If a block confirms the close or the freeze
  first, the pending transfer is judged again and dropped. Neither outcome is
  guaranteed: do not rely on a freeze catching a transfer that is already
  pending, nor on a pending transfer getting through.
- One pending owner operation per (asset, address) and one pending transfer
  state operation per asset are accepted to the mempool. Pending operations are
  judged again whenever the tip changes, also after a reorganization, and the
  ones that are no longer valid are dropped.

## Known limitation: `verifychain` at check level 4

This also concerns the tags and restrictions of restricted assets.

`verifychain` at check level 4, and `-checklevel=4` at start-up, undo the last
blocks in memory and connect them again. All of them are undone into a single
asset cache. When two of those blocks changed the same piece of asset state,
that cache keeps the value restored by the more recent of the two, and an older
block that depended on the earlier value is judged against the wrong one. This
has been observed with the verifier string of a restricted asset that changed
twice within the blocks being checked: a valid transfer in an older block was
reported as unconnectable.

Level 4 can produce false positives in these scenarios. Such a failure alone
does not prove corruption; it does not rule out real corruption either. Normal
validation and reorganisations undo and connect each block with a cache of its
own and are not affected. The default check level is 3.
