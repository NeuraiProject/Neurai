# Neurai 1.0.x release notes (1.0.0 to 1.0.7)

<!-- Sources: the git tags 1.0.0 to 1.0.7, the code at each tag (git show <tag>:<path>),
     commit messages, and the GitHub release texts
     (api.github.com/repos/NeuraiProject/Neurai/releases), read on 2026-10-26.
     Where a release text and the code disagree, this document follows the code. -->

Neurai is a proof-of-work blockchain with native assets. Its coin is XNA. The
node software (`neuraid`, `neurai-qt`, `neurai-cli`, `neurai-tx`) is a fork of
Ravencoin, which is itself a fork of Bitcoin Core.

Neurai starts from **Ravencoin v4.6.1** (upstream tag commit `7864c39c2b`,
16 August 2022). The first commit of this repository (`ad2ef7c`, "Neurai
Project", 17 April 2023) imports that release with Raven renamed to Neurai and
RVN to XNA. It also changes the chain parameters, the block subsidy, the
branding and the Qt download URL. All other files match Ravencoin v4.6.1. The
mainnet genesis block is dated the same day.

This document covers the whole 1.0 series, from 1.0.0 to 1.0.7. There was never
a 1.0.1 tag.

The files that used to be in `doc/release-notes/` (0.15.0, 0.15.0.1, 1.0.0,
1.0.2, 2.0.4, 2.1.0, 2.2.2 and 2.4.0) were Bitcoin Core and Ravencoin release
notes with the project name replaced. None of them described a Neurai release,
so they have been removed.

## Release overview

| Version | Tag commit | Tag date | GitHub release | Consensus change | Upgrade |
|---|---|---|---|---|---|
| 1.0.0 | `65d97af` | 2023-05-20 | 2023-05-21 | First tagged release. The network launched on 2023-04-17. | — |
| 1.0.2 | `42b97f0` | 2023-05-31 | 2023-05-31 | Mainnet asset burn addresses | Mandatory |
| 1.0.3 | `61bed49` | 2023-11-17 | 2023-11-19 | Testnet burn addresses | Optional on mainnet; required on testnet |
| 1.0.4 | `675d16b` | 2024-02-14 | 2024-02-15 | Testnet only | Optional on mainnet; required on testnet |
| 1.0.5 | `7024d90` | 2025-11-05 | 2025-11-05 | None | Optional ("Non-mandatory Update") |
| 1.0.6 | `59c697f` | 2026-08-13 | 2026-08-13 | Two soft-fork rules from height 1,739,500 | Mandatory |
| 1.0.7 | `835faae` | 2026-10-10 | 2026-10-10 | No new activation; stricter header checks | Recommended |

Since height 1,739,500, mainnet enforces rules that versions before 1.0.6 do not
check. The oldest version that follows mainnet consensus is 1.0.6. The
recommended version is 1.0.7.

---

## Neurai 1.0.0

- Tag: `65d97af`, 2023-05-20.
- GitHub release: 2023-05-21, "Binaries for Neurai 1.0.0".

Mainnet started on 2023-04-17 with the code of `ad2ef7c`, which already had
version 1.0.0. The eight commits between that import and the tag:

- add network details to the README;
- add checkpoints and a DNS seed;
- replace the icons and images;
- change the GUI colours;
- add the `Neuron` unit.

All the parameters below come from the code at tag `1.0.0`.

### Changes from Ravencoin v4.6.1

Consensus and chain:

- New genesis blocks for mainnet, testnet and regtest.
- KAWPOW from block 1 on mainnet and testnet. Ravencoin used X16R, then X16Rv2,
  and moved to KAWPOW on 2020-05-06.
- Dark Gravity Wave from block 1 (Ravencoin: block 338,778). `powLimit` and
  `kawpowLimit` are both set to the maximum target, 2^256 − 1.
- A new emission curve (see [Emission](#emission)). The reward starts at 50,000
  XNA and falls 5% every 14,400 blocks, followed by fixed tiers. Ravencoin pays
  5,000 RVN and halves it every 2,100,000 blocks.
- The asset deployments inherited from Ravencoin are rescheduled for 2023, with
  short version-bits windows (see [Assets](#assets)).
- Asset burn amounts are doubled. One burn address per network is used for all
  asset types.
- Deep-reorganisation protection needs at least 6 connected peers (Ravencoin: 4).

Inherited from Ravencoin v4.6.1 without change:

- the 60-second block target;
- `MAX_MONEY` of 21,000,000,000 coins;
- coinbase maturity of 100 blocks;
- the 8,000,000 block weight and serialized size limits;
- the protocol version (70028);
- the DGW implementation (`src/pow.cpp` is identical apart from the renaming).

P2P:

- New ports, network magic bytes and DNS seeds (tables below).
- The hard-coded fixed seed lists are empty, so peer discovery uses DNS seeds.

Wallet:

- Mainnet addresses start with `N` (P2PKH) or `p` (P2SH).
- The mainnet BIP44 coin type is `0` (Ravencoin: `175`). The README gives the
  derivation path `m/44'/0'/0'/0`.
- The data directory is `~/.neurai` on Linux, `%APPDATA%\Neurai` on Windows and
  `~/Library/Application Support/Neurai` on macOS. The configuration file is
  `neurai.conf`.

GUI:

- Neurai branding and icons, with a purple colour scheme.
- New display unit `Neuron`, equal to 1 base unit (0.00000001 XNA). In the
  1.0 series its description in the unit selector wrongly reads
  "Micro-Neurais (1 / 1 000 000)"; this is corrected in 2.0.0.
- The transaction explorer link points to `explorer.neurai.org`.
- The price ticker is still Ravencoin's: Binance BTC and USDT pairs (`XNABTC`,
  `XNAUSDT`). It was replaced in 1.0.3.

Assets:

- The names `XNA`, `NEURAI` and `NEURAICOIN` are reserved, as are the same names
  with a leading `#`.

### Network identity

| Parameter | Mainnet | Testnet | Regtest | Ravencoin 4.6.1 mainnet |
|---|---|---|---|---|
| P2P port | 19000 | 19100 | 19200 | 8767 |
| RPC port | 19001 | 19101 | 19201 | 8766 |
| Message start | `4e 45 55 52` ("NEUR") | `52 55 45 4e` ("RUEN") | `52 55 45 4e` | `52 41 56 4e` ("RAVN") |
| P2PKH prefix | 53 (`N…`) | 127 (`t…`) | 127 (`t…`) | 60 (`R…`) |
| P2SH prefix | 117 (`p…`) | 196 (`2…`) | 196 | 122 |
| WIF prefix | 128 | 239 | 239 | 128 |
| BIP32 xpub / xprv | `0488B21E` / `0488ADE4` | `043587CF` / `04358394` | `043587CF` / `04358394` | `0488B21E` / `0488ADE4` |
| BIP44 coin type | 0 | 1 (0 in 1.0.2 and 1.0.3) | 1 | 175 |
| DNS seeds | `dns.neurai.org`, `seed1`–`seed4.neuracrypt.org`, `neurai.satopool.com` | `testnet1`–`testnet3.neuracrypt.org` | none | — |

### Genesis blocks

| | Mainnet | Testnet | Regtest |
|---|---|---|---|
| Hash | `00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806` | `0000006af8b8297448605b0283473ec712f9768f81cc7eae6269b875dee3b0cf` | `0b2c703dc93bb63a36c4e33b85be4855ddbca2ac951a7a0a29b8de0408200a3c` as asserted in 1.0.0 (corrected in 1.0.7, see there) |
| Time | 1681720840 (2023-04-17 08:40:40 UTC) | 1681720840 | 1681720840 |
| Nonce / bits / version | 7131026 / `0x1e00ffff` / 4 | 57837983 / `0x1e00ffff` / 2 | 1 / `0x207fffff` / 4 |
| Merkle root | `4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951` | same | same |
| Coinbase reward | 50,000 XNA | 50,000 XNA | 50,000 XNA |

Coinbase message: `Fortune 16/April/2023  Elon Musk agrees A.I. will hit people
like an asteroid`. The genesis hash is the X16R hash of the header
(`GetX16RHash`).

### Consensus parameters

| Parameter | Mainnet | Testnet | Regtest | Ravencoin 4.6.1 mainnet |
|---|---|---|---|---|
| Block target spacing | 60 s | 60 s | 60 s | 60 s |
| Proof of work | X16R genesis, KAWPOW from block 1 | same as mainnet | X16Rv2 (KAWPOW activation set to 2083-07-14) | X16R → X16Rv2 (2019-10-01) → KAWPOW (2020-05-06) |
| Difficulty adjustment | DGW v3, 180-block window, from block 1 | from block 1 | from block 200 | from block 338,778 |
| `powLimit` / `kawpowLimit` | 2^256 − 1 / 2^256 − 1 | same | same | `00000fff…` / `0000000000ff…` |
| Subsidy interval | 14,400 blocks (5% reduction) | 14,400 | 14,400 | 2,100,000 (halving) |
| Initial subsidy | 50,000 XNA | 50,000 XNA | 50,000 XNA | 5,000 RVN |
| `MAX_MONEY` | 21,000,000,000 XNA | same | same | 21,000,000,000 RVN |
| Coinbase maturity | 100 blocks | 100 | 100 | 100 |
| Max block weight / serialized size | 8,000,000 / 8,000,000 | same | same | same |
| BIP34 / BIP65 / BIP66 / CSV / SegWit flags | enabled | enabled | enabled | enabled |
| Max reorg depth / min peers / min tip age | 60 / 6 / 12 h | 60 / 6 / 12 h | 60 / 4 / 12 h | 60 / 4 / 12 h |

Proof-of-work timeline:

- **Mainnet and testnet.** `nKAWPOWActivationTime` is the genesis time plus one
  second, so every block after genesis is a KAWPOW block. The X16R and X16Rv2
  switch times inherited from Ravencoin (2019) are earlier than the genesis
  block, and no block after genesis uses those algorithms.
- **Regtest.** KAWPOW is effectively disabled (activation time 3582830167), so
  regtest blocks use X16Rv2.
- **First 180 blocks.** DGW returns the limit target until 180 blocks exist. It
  also returns `kawpowLimit` until its 180-block window holds only KAWPOW blocks.

### Emission

`GetBlockSubsidy` uses the interval number n = floor(height / 14,400). One
interval is about 10 days at the 60-second target.

| Intervals | Heights | Reward per block |
|---|---|---|
| 0–35 | 0–518,399 | 50,000 × 0.95^n XNA: 50,000 at n = 0, about 8,304.17 at n = 35 |
| 36–71 | 518,400–1,036,799 | 5,000 XNA |
| 72–107 | 1,036,800–1,555,199 | 4,000 XNA |
| 108–143 | 1,555,200–2,073,599 | 3,000 XNA |
| 144–179 | 2,073,600–2,591,999 | 2,000 XNA |
| 180–215 | 2,592,000–3,110,399 | 1,000 XNA |
| 216–382 | 3,110,400–5,515,199 | 500 XNA |
| 383 and later | from 5,515,200 | 0 |

The schedule emits about 21,106 million XNA in total (21,106,329,307 XNA from
height 1 to the last reward at height 5,515,199). `MAX_MONEY` (21,000,000,000
XNA) only limits individual amounts, not the total supply. For n below 36, the reward is computed in
floating point (`50000 * COIN * pow(0.95, halvings)`) and converted to an
integer amount. `doc/mining-behavior.md` (added in 1.0.7) explains why this
expression must not be replaced.

### Assets

Neurai inherits the full Ravencoin asset layer:

- main assets, sub-assets and unique assets;
- message channels and messaging (RIP5);
- qualifiers, sub-qualifiers and restricted assets;
- the related RPCs and GUI.

The asset rules are gated by the inherited version-bits (BIP9) deployments,
rescheduled for Neurai:

| Deployment | Bit | Mainnet window / threshold | Ravencoin 4.6.1 mainnet window / threshold |
|---|---|---|---|
| `ASSETS` (RIP2) | 6 | 144 / 108 | 2016 / 1814 |
| `MSG_REST_ASSETS` (RIP5 messaging and restricted assets) | 7 | 144 / 108 | 2016 / 1714 |
| `TRANSFER_SCRIPT_SIZE` | 8 | 288 / 208 | 2016 / 1714 |
| `ENFORCE_VALUE` | 9 | 144 / 108 | 2016 / 1411 |
| `COINBASE_ASSETS` | 10 | 500 / 400 | 2016 / 1411 |

Activation schedule:

- **Mainnet.** Every deployment has start time 1684274400 (2023-05-16 22:00 UTC)
  and timeout 1704063599 (2023-12-31 22:59:59 UTC). These values did not change
  up to 1.0.7.
- **Testnet and regtest.** Start time 0 and the same timeout. The testnet
  timeout was extended in 1.0.4, the regtest timeout in 1.0.7.
- **Height-based parameters.** `nAssetActivationHeight`,
  `nMessagingActivationBlock` and `nRestrictedActivationBlock` are 10 on mainnet
  and testnet (Ravencoin: 435,456 / 1,092,672 / 1,092,672) and 0 on regtest.

Mainnet activation heights (`getblockchaininfo`, field `since` of
`bip9_softforks`):

| Deployment | Active since height |
|---|---|
| `ASSETS` | 40,608 |
| `MSG_REST_ASSETS` | 40,608 |
| `ENFORCE_VALUE` | 40,608 |
| `TRANSFER_SCRIPT_SIZE` | 40,896 |
| `COINBASE_ASSETS` | 41,500 |

Burn amounts are twice Ravencoin's:

| Operation | Neurai | Ravencoin 4.6.1 |
|---|---|---|
| Issue main asset | 1,000 XNA | 500 RVN |
| Reissue | 200 XNA | 100 RVN |
| Issue sub-asset | 200 XNA | 100 RVN |
| Issue unique asset | 10 XNA | 5 RVN |
| Issue message channel | 200 XNA | 100 RVN |
| Issue qualifier | 2,000 XNA | 1,000 RVN |
| Issue sub-qualifier | 200 XNA | 100 RVN |
| Issue restricted asset | 3,000 XNA | 1,500 RVN |
| Add null-qualifier tag | 0.2 XNA | 0.1 RVN |

In 1.0.0 every operation burns to one address per network: mainnet
`NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr`, testnet and regtest
`tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy`. Version 1.0.2 introduced separate mainnet
addresses.

### Checkpoints

Mainnet checkpoints in 1.0.0: 0 (genesis), 1,000, 5,000, 10,000, 20,000, 27,000,
37,000 and 43,000. `nMinimumChainWork` and `defaultAssumeValid` are still zero.

---

## Neurai 1.0.2

- Tag: `42b97f0`, 2023-05-31. GitHub release: the same day.
- The tag commit's message reads "This version is mandatory".
- GitHub release text: "Add some checkpoints. Updated QT dependencies. Added
  burn addresses. Small corrections in the images."

The version string passed through 1.0.0.1 and 1.0.1 between the 1.0.0 and 1.0.2
tags (`6cc6bf7`, `0472712`, `04b5b34`). Neither version was tagged or published
on GitHub.

### Consensus (mandatory)

Each mainnet asset operation now has its own burn address:

| Operation | Burn address |
|---|---|
| Issue main asset | `NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr` (unchanged) |
| Reissue | `NXReissueAssetXXXXXXXXXXXXXXWLe4Ao` |
| Issue sub-asset | `NXissueSubAssetXXXXXXXXXXXXXX6B2JF` |
| Issue unique asset | `NXissueUniqueAssetXXXXXXXXXXUBzP4Z` |
| Issue message channel | `NXissueMsgChanneLAssetXXXXXXTUzrtJ` |
| Issue qualifier | `NXissueQuaLifierXXXXXXXXXXXXWurNcU` |
| Issue sub-qualifier | `NXissueSubQuaLifierXXXXXXXXXV71vM3` |
| Issue restricted asset | `NXissueRestrictedXXXXXXXXXXXWpXx4H` |
| Add null-qualifier tag | `NXaddTagBurnXXXXXXXXXXXXXXXXWucUTr` |

Transaction validation checks the burn output (`CheckIssueBurnTx` and
`CheckReissueBurnTx`). Nodes on 1.0.0 and on 1.0.2 therefore disagree on every
operation in the table except main-asset issuance. The change has no activation
height: it applies to the whole chain.

No such operation was mined before 1.0.2: a full mainnet `-reindex` with the
current rules (October 2026, through height 1,814,024) validates every block
with these checks and reaches the same final state.

Other chain changes:

- Mainnet checkpoints 55,300, 58,150 and 61,000.
- `nMinimumChainWork` and `defaultAssumeValid` are set. The assume-valid hash is
  the block 58,150 checkpoint; the code comment says "block 58000".
- The testnet BIP44 coin type changed from 1 to 0. Version 1.0.4 restored it to 1.

### P2P

- The default `-maxconnections` rises from 125 to 256. The commit message says
  "128 > 256"; the code changes 125.
- New mainnet DNS seeds: `seed1.neurai.org`, `seed2.neurai.org`,
  `neurai-ipv6.neuraiexplorer.com` and `neurai-ipv4.neuraiexplorer.com`.
  `neurai.satopool.com` had been added just before 1.0.0.

### RPC

- `estimatefee` no longer needs `-deprecatedrpc=estimatefee`.
- `getinfo` no longer returns the `deprecation-warning` field.

### GUI

- `neuraiexplorer.com` added as a second transaction explorer (`59e2272`,
  "Thanks Satolight").
- Image corrections.

### Build

- The Qt 5.12.11 source in `depends` now downloads from
  `download.qt.io/new_archive`.

---

## Neurai 1.0.3

- Tag: `61bed49`, 2023-11-17. GitHub release: 2023-11-19.
- GitHub release items:
  - add checkpoints and fix typos;
  - take the price from CoinGecko;
  - "Fix typo in halving system";
  - add a `.gitignore`;
  - update the Dockerfiles for Linux and Windows;
  - update the wallet images;
  - add a directory with Dockerfiles.

### Consensus

Testnet:

- Each asset operation gets its own burn address (`tX…`, `08c7b30`).
- Testnet `nMinimumChainWork` and `defaultAssumeValid` are reset to zero.

Checkpoints:

- New mainnet checkpoints: 70,100, 158,000, 190,000, 216,000, 235,000 and
  304,000.

### P2P

- The duplicate `seed1.neuracrypt.org` entry is removed.
- New mainnet DNS seeds: `seed3.neurai.org` and `main-seed.neurai.top`.
- New testnet DNS seeds: `testnet1.neurai.org` and `test-seed.neurai.top`.

### GUI

- The price ticker shows XNA in USD from the CoinGecko API and refreshes every
  240 seconds. It used to show Binance BTC/USDT pairs, refreshed every
  10 seconds. During development the ticker briefly used Xeggex.
- The welcome dialog dates the chain's start to 2023 instead of 2018.
- Wallet icons and images updated.

### Build and Docker

- `doc/build-ubuntu.md` with dependencies for Ubuntu 20.04 and 22.04.
- `doc/docker/` gains three Dockerfiles: one builds Linux x86_64 binaries, one
  builds Windows x86_64 binaries, and one runs a node.
- `scripts/` with build and packaging helper scripts.
- New `.gitignore`.
- Source headers again credit the Ravencoin developers, next to the Neurai
  developers.
- The README gains network details (ports, derivation path).
- `doc/release-notes/release-notes-1.0.0.md` and `-1.0.2.md` were added in this
  version. Both contained the Ravencoin 2.4.0 text and have now been removed.

---

## Neurai 1.0.4

- Tag: `675d16b`, 2024-02-14. GitHub release: 2024-02-15.
- GitHub release items:
  - add checkpoints;
  - document the testnet configuration in the README;
  - change the buffer value;
  - update the burn addresses;
  - update the testnet BIP44 coin type;
  - update the date that activates assets on testnet.

### Consensus

Mainnet: no rule change.

Testnet (testnet nodes need 1.0.4):

- The timeout of every asset deployment moves from 2023-12-31 to 1893452400
  (2029-12-31 23:00 UTC), so that the deployments can activate on testnet.
- New burn addresses for every operation except main-asset issuance
  (`tAsset…`, `tSubAsset…`, `tUniqueAsset…`, `tMsgChanneLAsset…`,
  `tQuaLifier…`, `tSubQuaLifier…`, `tRestricted…`, `tTagBurn…`).
- The BIP44 coin type returns to 1.

Mainnet checkpoint 432,000.

### P2P

- The default `-maxreceivebuffer` rises from 5,000 to 500,000 (units of
  1,000 bytes).
- The default `-maxsendbuffer` rises from 1,000 to 100,000.

### Other

- `configure.ac` sets the copyright to "2023-2024" and the copyright holder to
  "Neurai Devs". Version 1.0.5 changes these to "2025" and "Neurai".
- A stray `.vscode/settings.json` is removed.

One release asset is named `neurai-1.0.4.0.WITH.NEW.DERIVATION.-x86_64-linux-gnu.tar.gz`.
The code at the tag still uses coin type 0 on mainnet. The README later
documents `m/44'/1900'/0'/0` "for HW like Onekey" (`e3ae720`, `b27ca7a`, both
in 1.0.5).

The variant binaries ("NEW.DERIVATION" in 1.0.4, "SLIP44-1900" in 1.0.5–1.0.7)
are not built from the release tags. For 1.0.6, the `SLIP44-1900` branch
(`0742c33`) only changes the mainnet BIP44 coin type to 1900
(`m/44'/1900'/…`). The same seed gives different addresses in a variant build
and in a standard build. The standard builds keep coin type 0, and so does
2.0.0, so that existing wallets and exchange integrations keep working.

---

## Neurai 1.0.5

- Tag: `7024d90`, 2025-11-05. GitHub release: the same day, "Non-mandatory
  Update".
- GitHub release items:
  - update the URLs in `depends`;
  - update `chainTxData`;
  - update the Docker files;
  - add Neurai links to the Qt wallet.

### Consensus

No rule change. Chain data:

- Mainnet checkpoints 1,180,000 and 1,330,000.
- `chainTxData` updated: 1,885,721 transactions at 2025-11-03 05:57 UTC, about
  0.02 tx/s.

Two commits add only commented-out placeholders and change no behaviour: a
future `OP_IOT_ASSET` opcode name (`0b277c0`) and a larger OP_RETURN relay size
(`cb88f6d`).

### P2P

- The `seed1`–`seed4.neuracrypt.org` DNS seeds are removed.
- `node.neurai.org` is added.

### GUI

- New **Links** menu: Website, Explorer, WebWallet, BGrid, Telegram and X
  (Twitter).
- The package name is now "Neurai" instead of "Neurai Core". This shows in
  window titles, the About dialog and `-version`.

### Build and Docker

- Dead download URLs replaced:
  - in `depends`: libSM, libX11, libXau, libXext, libxcb, qrencode, xcb_proto,
    xextproto, xproto, xtrans and zlib;
  - in `contrib/install_db4.sh`.
- GitHub Actions:
  - builds run on Ubuntu 20.04;
  - `actions/cache` updated to v4;
  - the separate dependency workflows are removed.
- `contrib/Dockerfile` exposes 19000/19001 instead of the inherited
  8766/8767.
- The Dockerfiles under `doc/docker/` are updated for 1.0.5.
- New `doc/build-docker.md`.
- Copyright headers name "The Neurai developers".

The GitHub release includes Blockbook builds `neurai-1.0.5.0.SLIP44-0` and
`neurai-1.0.5.0.SLIP44-1900`.

---

## Pre-release: 1.0.6b1_DePIN (DePIN messaging test)

- Tag: `1.0.6b1_DePIN` (`6507fce`), 2025-11-15.
- GitHub release: "Neurai 1.0.6 DePIN Messaging TEST", described as a beta that
  must not be used in a wallet with funds.

This test build is not part of the 1.0.x line:

- It is 18 commits on top of 1.0.5 on the `DePIN-Test` branch, and was never
  merged into `main`.
- Neither 1.0.6 nor 1.0.7 contains its code.
- Its `configure.ac` already reports version 1.0.6, but it lacks the 1.0.6
  consensus rules. It must not be used on mainnet after height 1,739,500.

It added an experimental token-gated, encrypted messaging pool:

- ECIES encryption and ECDSA-signed messages;
- `-pubkeyindex`;
- the `-depinmsg*` and `-depinpool*` options;
- a server port, 19002 by default;
- the RPCs `depinsendmsg`, `depingetmsg`, `depinsubmitmsg`, `depingetmsginfo`,
  `depingetpoolcontent`, `depinpoolstats` and `depinclearmsg`.

Development of DePIN continues on the `DePIN-Test` line, which leads to the 2.0
test builds. Those builds are outside the scope of this document.

---

## Neurai 1.0.6

- Tag: `59c697f`, 2026-08-13. GitHub release: the same day, "Neurai 1.0.6 -
  Mandatory Soft Fork".
- Merged as pull request #6 (`Neurai-fix-invalid_blocks`).

### Consensus (mandatory soft fork)

Two independent rules activate together at **height 1,739,500 on mainnet**
(`>=`). They are active from height 0 on testnet and regtest. The release
coordinated activation for around 2026-08-16. It also states that the chain was
audited beforehand and that neither vulnerability showed any sign of prior
exploitation.

**1. KAWPOW header height (`bad-blk-height`).**

The problem:

- In older versions, `CheckBlockHeader` accepted KAWPOW headers with a cheap
  check (only the hash computed from the supplied `mix_hash`) whenever the
  header declared a height at or below the last checkpoint.
- That height is chosen by the miner. A block mined above the last checkpoint
  could declare a lower height and skip the full KAWPOW verification.

The fix:

- New consensus parameter `nKAWPOWHeaderHeightCheckActivation`.
- From that height, `ContextualCheckBlockHeader` rejects a KAWPOW header whose
  declared `nHeight` differs from the parent height + 1, with DoS score 100.
- Pre-KAWPOW headers are exempt.

**2. Asset transfer amount range and overflow.**

The problem:

- `Consensus::CheckTxAssets` summed transfer amounts per asset in a signed
  64-bit value and only checked that inputs equal outputs.
- With crafted amounts, the sum could overflow while each output carried a huge
  value.
- The release notes that this matches the fix Ravencoin already deployed
  (commit `1ecb6598`).

The fix:

- New consensus parameter `nAssetTransferOverflowCheckActivation`.
- From that height, each input and output amount must lie in [0, `MAX_MONEY`].
  The running total is checked before each addition, so it can neither exceed
  `MAX_MONEY` nor overflow.
- The height comes from the context: `pindex->nHeight` in `ConnectBlock`, and
  the spend height for mempool acceptance.
- New reject reasons:
  - `bad-txns-input-asset-amount-negative`
  - `bad-txns-input-asset-amount-toolarge`
  - `bad-txns-input-asset-totalInputs-toolarge`
  - `bad-txns-transfer-asset-amount-negative`
  - `bad-txns-transfer-asset-amount-toolarge`
  - `bad-txns-transfer-asset-totalOutputs-toolarge`

Chain data:

- New mainnet checkpoint 1,733,712.
- `nMinimumChainWork` and `defaultAssumeValid` move to that block.

### Block index recovery

These changes let nodes that stored headers affected by issue 1 restart without
a manual reindex:

- `LoadBlockIndexGuts` skips stored entries whose rebuilt header fails PoW
  instead of aborting. The log names at most 32 of them.
- `PruneBrokenBlockIndex` removes placeholder entries left by a skipped parent,
  together with all their descendants.
- If the chainstate tip is missing from the cleaned index, the node rebuilds
  the chainstate from the block files without asking.
- On `-reindex`, `-reindex-chainstate` and that automatic rebuild, the asset and
  restricted-asset databases are wiped and rebuilt with the chainstate. The
  message, my-restricted and rewards databases are left untouched.

### Build and Docker

- `doc/docker/` is reorganised:
  - `bin/` holds BuildKit Dockerfiles that build Linux x86_64 and Windows
    x86_64 binaries from the local source tree;
  - `node/` holds a standalone node image with an entrypoint script;
  - `compose-node/` holds a Docker Compose setup configured through `.env`.
- The tag tree also contains compiled Linux binaries under `build-out/`. They
  were removed right after the tag (`2d4bc83`, in 1.0.7).

### Tests

- New unit tests for both rules, the activation gates and the block-index
  recovery (`asset_tx_tests`, `kawpow_tests`).

---

## Neurai 1.0.7

- Tag: `835faae`, 2026-10-10. GitHub release: the same day, "Neurai 1.0.7 -
  Recommended Update".
- Merged as pull request #8 (`Neurai-fix-mining-security`).
- The GitHub release summarises the changes as:
  - improved stability across validation, mining and RPC;
  - faster initial sync and block processing;
  - refreshed checkpoints and sync data;
  - better startup, import and reindex handling;
  - better build compatibility;
  - more tests.

### Consensus and validation

1.0.7 adds no activation height. The 1.0.6 rules are unchanged. Header and block
admission becomes stricter at every height:

- **Checkpoint shortcut limited.** The cheap check (`mix_hash` only) now applies
  only to headers that are already in the block index and are ancestors of the
  last checkpoint. Every newly received KAWPOW header gets full KAWPOW
  verification, including `mix_hash` (`high-hash`, `invalid-mix-hash`).
- **KAWPOW height bound.** A header is rejected with `bad-kawpow-height-range`
  (DoS 100) if its declared height is outside the supported ethash epochs, or
  more than 7,500 above the height implied by its parent. This check runs
  before any epoch context is built. If the parent is unknown, the node checks
  the bound against its best known header instead. A failure is then a local,
  retryable error (`kawpow-height-unavailable`) and the peer is not penalised.
- **Difficulty first.** `nBits` is checked against the parent before full PoW
  and before transaction checks. This applies to headers, full blocks and forced
  submissions. A full block with an unknown parent is deferred
  (`block-parent-unavailable`) without penalising the sender.
- **Startup PoW audit.** On startup, the node fully re-verifies the KAWPOW
  headers in the block index that sit at or below the last checkpoint but are
  not its ancestors. Headers that fail are disconnected and marked invalid, as
  are their descendants. If the block or undo data needed to rewind is missing,
  the node stops and suggests `-reindex`.
- **Known-invalid headers.** The same recovery runs when a block whose header was
  already indexed fails full PoW during normal processing.
- **Index consistency.** A stored block index entry is accepted only if its
  rebuilt hash equals its database key.
- **Chain data.**
  - New mainnet checkpoint 1,816,500.
  - `nMinimumChainWork` and `defaultAssumeValid` move to that block.
  - `chainTxData` updated: 2,439,721 transactions at 2026-10-09 16:39 UTC.

KAWPOW epoch contexts are now capped at epoch 896 (`ETHASH_MAX_EPOCH_NUMBER`),
about 128 MiB of light cache. KAWPOW headers at height 6,727,500 or above are
therefore rejected. The code comment asks for the limit to be reviewed before
the chain approaches that height.

This is a known limit: it will be raised in a future release, well before the
chain reaches that height.

### P2P

- **Peer time adjustment.**
  - The default `-maxtimeadjustment` falls from 4,200 s (70 minutes, inherited
    from Ravencoin) to 300 s.
  - Only persistent outbound peers contribute time samples. Inbound, feeler and
    one-shot connections still report their offset in `getpeerinfo`.
  - Extreme peer timestamps can no longer overflow the offset.
  - `-maxtimeadjustment=0` uses the system clock only.
  - See `doc/mining-time.md` for pool settings.
- **Compact blocks.** A compact block whose header fails for a local reason is
  no longer processed further, and the peer is not penalised. Reconstructed
  blocks that fail `CheckBlock` are passed to block processing, so legacy
  indexed headers that fail full PoW get marked invalid.

### Mining

- **Block templates.** `getblocktemplate` keeps up to 16 KAWPOW templates for
  the current tip. Before, it kept only the latest one. The list is cleared when
  the tip changes.
- **Locking.** Templates are copied under `cs_main` and hashed outside the lock.
- **Epoch context caches.** Validation and RPC use separate thread-safe caches
  of KAWPOW epoch contexts, ported from the DePIN branch.
- **Submission results.** The results of `pprpcsb` and `submitblock` are
  synchronised, and their state is kept for callbacks still in flight.
- **Internal CPU miner (`setgenerate`).**
  - It now iterates the 64-bit `nNonce64` for KAWPOW blocks. Before, it
    incremented the 32-bit `nNonce`, which KAWPOW headers do not serialize, so
    it repeated the same work.
  - It stores the mix hash of the solution and rebuilds the template when the
    nonce range is exhausted.
  - It stops and joins its threads on `setgenerate false`.
  - `getgenerate` reports the value of the latest `setgenerate` call.
  - See `doc/mining-behavior.md`.

### RPC

- `pprpcsb` and `getkawpowhash` validate their input:
  - `header_hash` and `mix_hash` must be exactly 64 hexadecimal digits, in
    upper, lower or mixed case;
  - `nonce` is 1 to 16 hexadecimal digits, with an optional `0x` prefix.
- `getkawpowhash` also checks its other arguments:
  - the optional `target` must be 64 hexadecimal digits;
  - the height must be an unsigned 32-bit integer, within the ethash limit and
    no more than 10 blocks above the tip.
- If the KAWPOW context cannot be allocated, both calls return an RPC error
  ("KAWPOW context unavailable").
- `pprpcsb` runs the KAWPOW header admission check before hashing.
- `getkawpowhash` registers the named argument `target`.

### Wallet

- `ScanForMessageChannels` takes `cs_main` before `cs_messaging`, matching the
  lock order used by validation.

### Startup and performance

- Importing block files that do not start with the genesis block (`-loadblock`,
  `bootstrap.dat`) no longer crashes at startup.
- Division of 256-bit integers by a divisor of 32 bits or fewer uses a
  word-at-a-time path. This speeds up DGW and initial sync without changing
  results.

### Regtest

- Earlier releases asserted a regtest genesis hash that, per the code comment,
  belonged to a different genesis block. The assertion now expects
  `6d7844e7ab81aa230e4ec37e12d344339098c523a6e92ddac3ab1148000fa2e4`. This code
  base refuses to compile without assertions, so `-regtest` aborted at startup
  in 1.0.0–1.0.6.
- Regtest uses DGW's minimum-difficulty branch (`fPowAllowMinDifficultyBlocks`
  and `fPowNoRetargeting`).
- Its version-bits timeouts move to 2029-12-31.

### Build and Docker

- Missing standard headers (`<stdexcept>`, `<set>`) are added for newer
  compilers.
- `build-out/` is removed from the tree and ignored.
- Docker Compose:
  - wallet and RPC settings through environment variables;
  - log rotation;
  - a shutdown timeout;
  - a first-start configuration script.
- `doc/docker/docker-hub/1.0.6/` defines the published image
  `neuraiproject/neurai-node:v1.0.6`: stripped binaries on a `debian:11-slim`
  runtime, `linux/amd64` only.

### Tests and documentation

- New unit tests: block work admission, KAWPOW admission and index recovery,
  epoch context cache, mining concurrency, miner nonces, mining RPC hex parsing,
  time data and `arith_uint256`.
- New standalone functional tests: block work admission, import without genesis,
  internal mining and P2P time adjustment.
- New `feature_regtest.py`.
- New documents: `doc/mining-behavior.md`, `doc/mining-time.md` and a
  `test/README.md` section.

---

## Credits

The Neurai developers.

Thanks to the Ravencoin developers, whose v4.6.1 release is the base of Neurai,
and to the Bitcoin Core developers.
