# C7 privacy pool: NeuraiZK/v3 notes

**Status: testnet experiment. Not audited. The keys of any C7 deployment made with these tools are TEST keys.**

C7 is the successor of the C6 XNA privacy pool. A wallet has one viewing key per account and any number of
unlinkable receiving addresses. Every note record carries a one-byte view tag. Scanning costs one ristretto255
multiplication per record, whatever the number of addresses. The construction is adapted from Zcash Orchard
(diversified addresses, ZIP 212 style `epk` check) over ristretto255. Consensus does not change. The C6 note
commitment, nullifier and ownership relations (CP1) stay as they are.

This directory is the public reference. It contains:
- the byte-level specification below;
- an independent Python implementation (`c7_ref.py`);
- the vector generator (`gen_c7_vectors.py`, writing `src/test/data/privacy_c7_vectors.json`);
- cross-checks against libsodium and the Zcash `fpe` crate;
- the contract framing (`c7_contract.py`) and the birth tool (`deploy_c7.py`).

The node's C++ implementation is `src/privacy/c7.{h,cpp}`, used by the Qt wallet through `src/privacy/c6_*`. It is
tested by `src/test/privacy_c7_tests.cpp` with the same vectors.

## Notation

- `‖` is concatenation.
- `u32le` and `u64le` are little-endian integers.
- `[k]·P` is scalar multiplication in ristretto255 (RFC 9496), whose group order is
  `ℓ = 2^252 + 27742317777372353535851937790883648493`.
- `ToScalar(x)` reduces 64 bytes, read little-endian, modulo `ℓ`.
- `BLAKE2b-n(p, x)` is RFC 7693 with an `n`-byte output, no key and no salt. The personalization `p` is ASCII
  zero-padded to 16 bytes.
- `PoseidonBytes` is the CP1 Poseidon sponge of `src/crypto/poseidon_bn254.cpp`.

## Instance

A pool instance is born from the emission of the UNIQUE asset `NAME#POOL` (`identity`, 1 to 64 printable ASCII
bytes):

```text
domain  = SHA256("NeuraiPoolC7/domain" ‖ 0x01 ‖ genesis ‖ emission txid ‖ u32le(emission vout)
                 ‖ u8(len(identity)) ‖ identity)                  hashes in internal byte order
assetId = SHA256("NeuraiPool/asset/XNA")
ctx     = PoseidonBytes("NeuraiPoolCtx" ‖ 0x01 ‖ domain ‖ assetId ‖ u64le(1) ‖ 0^32)     public input 0 of every proof
tag     = SHA256("NeuraiZK/v3/instance" ‖ domain ‖ assetId)[0..4)
```

Birth rules, all checked by wallets:
- the birth transaction spends the `NAME#POOL` emission and the owner token `NAME!`;
- output 0 is the state;
- output 1 sends `NAME!` to the network's global burn address, so the creator keeps no power over the name;
- the root `NAME` is issued as non-reissuable;
- each wallet release pins `{identity, emission outpoint, commitment}` per network. Everything else (domain, ctx,
  leaves, commitment) is recomputed from public data.

## Keys

The keys start from the NeuraiZK/v2 private root `R` and its HKDF (see `neurai-privacy/docs/nzk-v2-derivation.md`):

```text
PRK = HMAC-SHA256("NeuraiZK/v2/account", R);  expand32(info) = HMAC-SHA256(PRK, info ‖ 0x01)
Q   = family ‖ u32le(account) ‖ domain ‖ assetId
P   = family ‖ u32le(account) ‖ u32le(branch) ‖ u32le(index) ‖ domain ‖ assetId

ivk = ToScalar(BLAKE2b-512("NeuraiZKv3_ivk", expand32("NeuraiZK/v3/ivk" ‖ Q)))     ivk = 0 fails explicitly
dk  = expand32("NeuraiZK/v3/dk" ‖ Q)

spendSecret = expand32("NeuraiZK/v3/spend" ‖ P)                                   all zero fails explicitly
owner = PoseidonBytes("NIP043/owner/CP1" ‖ domain ‖ spendSecret)
nk    = PoseidonBytes("NIP043/nk/CP1" ‖ domain ‖ spendSecret)
j     = branch · 2^32 + index          branch ∈ {0, 1}, index ∈ [0, 2^31 − 1], account ∈ [0, 2^31 − 1]
d     = LEBS2OSP_88(FF1-AES256(dk, tweak "", radix 2, I2LEBSP_88(j)))          11 bytes, as Zcash
G_d   = map(expand_message_xmd_SHA-512(d ‖ domain ‖ assetId, "NeuraiZKv3-gd", 64))   RFC 9380 + RFC 9496
pk_d  = [ivk]·G_d
```

`map` is the RFC 9496 one-way map of 64 bytes, which is `crypto_core_ristretto255_from_hash` in libsodium.

## Address

The address is Bech32m with HRP `nzk`, `tnzk` or `rnzk`, without the 90-character limit. Its payload is
`0x03 ‖ owner (32) ‖ d (11) ‖ pk_d (32) ‖ tag (4)`, 80 bytes in total. A parser rejects:
- a wrong HRP, length, version or instance tag;
- an `owner` that is zero or not a canonical BN254 field element;
- a `pk_d` that is not a canonical ristretto255 encoding or is the identity.

## Note record (230 bytes)

The note is the CP1 note `0x01 ‖ domain ‖ assetId ‖ owner ‖ pk_d ‖ u64le(amount) ‖ rho`, 169 bytes. Its commitment is
`cm = PoseidonBytes("NIP043/cm/CP1" ‖ note)`.

```text
esk  = ToScalar(BLAKE2b-512("NeuraiZKv3_esk", rho ‖ domain ‖ assetId))       esk = 0: choose another rho
epk  = [esk]·G_d                    S = [esk]·pk_d
vtag = BLAKE2b-256("NeuraiZKv3_vtag", S ‖ epk)[0]
K    = BLAKE2b-256("NeuraiZKv3_KDF", S ‖ epk)
ct   = ChaCha20-Poly1305(K, nonce 0^12, aad "NIP043/note/CP2" ‖ domain ‖ cm, note ‖ d)          196 bytes
record = 0x02 ‖ vtag ‖ epk ‖ ct
```

## Scanning

Each record is read together with the `cm` published at its position.

**Receive-only scanner** (`ivk`, `dk`). It runs these steps, and each failure has the reason name used by the vectors:
1. `epk` must be a canonical encoding (`epk-invalid`) and not the identity (`epk-identity`).
2. Compute `S = [ivk]·epk`.
3. Check the tag (`vtag-mismatch`).
4. Decrypt (`aead-failed`). Check the note format (`note-malformed`) and that it belongs to this instance
   (`note-instance`).
5. Invert `j = FF1⁻¹(dk, d)`. Reject a branch above 1 or an index of 2^31 or more (`index-out-of-range`).
6. Check that `pk_d = [ivk]·G_d` (`pk_d-mismatch`).
7. Check that `epk = [esk(rho)]·G_d` (`epk-mismatch`).
8. Check `cm` (`cm-mismatch`).

The result is "received, ownership not verified". It has no nullifier and no spend state, and it must never be shown
as spendable balance.

**Full scanner** (with the wallet words). It runs the same steps, then derives `spendSecret` for `(branch, index)` and
checks `owner` (`owner-mismatch`). The note is then owned, with `nf = PoseidonBytes("NIP043/nf/CP1" ‖ domain ‖ nk ‖
rho ‖ cm)`.

## Consensus invariants

The profile 3 predicate (`src/crypto/portable_tree_transition.cpp`) does not read note records. C7 circuits must keep:
- the public input and transcript layout of every form (D, T1–T4, W, J2);
- the withdrawal-without-publication constant `PoseidonBytes("NeuraiPoolC6/no-publication" ‖ 01)`.

## Contract, keys and deployment

C7 reuses the C6 circuits, verifying keys and proving files unchanged. The circuits only see the note bytes, and a
canonical ristretto255 `pk_d` satisfies the C6 view-field constraint. The withdrawal dummy note is never published.
The contract changes only the publication framing (`c7_contract.py`):
- note records are 230 bytes;
- the first byte of each record is fixed to `0x02`;
- J2 carries its record at `[98, 328)`.

`c7_contract.py` builds on the C6 constructors of a checkout (`scripts/pool_c6_*.py` and
`NIP/bench/nip043_v3_scripts.py`). These are not published yet.

`deploy_c7.py` makes a verifiable birth on testnet or regtest. It needs a node with a funded wallet: on testnet, about
1013 XNA (1000 for the root asset, 10 for the UNIQUE, and a 2 XNA birth coin, 1.9 of which comes back).

```sh
python3 deploy_c7.py --rpc-config rpc.json --name C7TEST1023A --out out/
```

It prints the pin `{identity, emission, commitment}` and writes `c7-testnet.json`. For neurai-qt, the `privacy-c7`
folder holds that config and the C6 proving files (`D`, `T1`, `T2`, `T3`, `W` `.wasm` and `.zkey`). Until the pin is
added to `C7Pins()` in `src/privacy/c6_config.cpp`, the wallet loads the instance only with `-privacypoolunpinned`,
and shows that it is not pinned.

## Testnet instance

| Field | Value |
|---|---|
| Identity | `C7TEST1023A#POOL` (owner token `C7TEST1023A!` burned at the birth output 1) |
| Emission | `8bc6445bb44d6adb2e9c5d59b5ed1e7f6971662a8a571888bc1120060901e3a2:3` |
| Birth | `8336537aab139fa78e9a219affaefa7f2c86eb8787c36600c6a270babd8763fa:0`, height 75836 |
| Domain | `8d3b692f54fdd047b0cbf011dcdace31935e7e3cd63ac606aa3a6ee59e674142` |
| Context | `017622c8fc4f395c371b25584a670112e73760ee1da24cbcb1e3821885f4944d` |
| Commitment | `a90ce546a03d4b6a83ba8d7680eced7f8adaf1ff7cf71c4fa9f35badcd158be2` (pinned in `C7Pins()`) |

`c7-testnet.json` is its config. neurai-qt uses this folder as `privacy-c7` once the C6 proving files are copied into
it (`D`, `T1`, `T2`, `T3`, `W` `.wasm` and `.zkey`, the same files and digests as `../privacy-c6`). They are not stored
in git, and the wallet checks each one against the digests in the config.

## Running the checks

```sh
contrib/privacypool/privacy-c7/run-tests.sh
```

The script needs Docker. It checks that the vectors file is up to date, runs the unit tests, recomputes the vectors with
libsodium (C) and OpenSSL, and compares 216 diversifiers with the `fpe` crate used by the Zcash `orchard` crate. To
regenerate the vectors after a deliberate change, run `python3 gen_c7_vectors.py --write`.
