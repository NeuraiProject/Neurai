(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Neurai version 2.0.0 is now available from:

  <https://github.com/NeuraiProject/Neurai/releases>

<!-- TODO: release date (not scheduled yet). The tag will be `2.0.0`
(existing tags have no "v" prefix, e.g. 1.0.7). -->

This is a new major version release. It brings the rule set developed on the
`DePIN-Test` branch: AuthScript with post-quantum (ML-DSA-44) signatures,
covenant and introspection opcodes, zero-knowledge proof verification, DePIN
assets and messaging, silent payments and a privacy pool prototype.

**No new consensus rule is scheduled on mainnet by this release.** The new
rules are active on testnet and regtest only; every mainnet activation height
comes from one constant, `MAINNET_FORK_HEIGHT`, which is unset (`INT_MAX`),
and mainnet is to adopt them in a single coordinated hard fork in a later
release. See [Consensus](#consensus).

A full mainnet `-reindex` of the release code accepts the whole mainnet history
and reproduces exactly the chain state of the 8 October 2026 reference run (see
[reindex-validation.md](reindex-validation.md)).

The maintenance fixes released in 1.0.6 and 1.0.7 (KAWPOW header height,
asset transfer overflow check, peer time adjustment, internal miner nonces,
faster `uint256` division, startup without genesis, difficulty check before
proof of work) are included unchanged and are not repeated below.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/NeuraiProject/Neurai/issues>

For questions, use the Neurai Discord: <https://discord.gg/j2WgJjgj8t>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Neurai-Qt` (on Mac)
or `neuraid`/`neurai-qt` (on Linux).

A mainnet node that does not use `-addressindex` or `-spentindex` needs no
further step.

Indexes that need a reindex
---------------------------

- **`-addressindex`, `-spentindex`, `-pubkeyindex`.** The internal format of
  these indexes changed (destination index schema version 1, needed for
  post-quantum and AuthScript destinations). A node started with any of them
  on a data directory built by an earlier version refuses to start and asks
  to rebuild the indexes with `-reindex`. Restart once with `-reindex`. One
  full mainnet reindex measurement is in
  [reindex-validation.md](reindex-validation.md).
- **Enabling `-pubkeyindex`** (new, required by DePIN messaging and
  `getpubkey`) on an existing data directory also requires `-reindex`: the
  index flags are only recorded when the block index is created. The startup
  errors for `-addressindex`, `-spentindex`, `-timestampindex` and
  `-pubkeyindex` now ask for `-reindex`; they used to name
  `-reindex-chainstate`, which does not change them.
- **`-silentpaymentindex`** (new) does not need a reindex on an unpruned node:
  it is built at startup from block and undo data. A pruned node needs
  `-reindex` to enable it.

Wallets
-------

- Existing wallets open unchanged, with address type `legacy`.
- `-addresstype=legacy|pq|ecdsa` only takes effect when a new wallet file is
  created; the type is stored in the wallet. Opening an existing wallet with
  a different `-addresstype` is a startup error. `pq` and `ecdsa` require
  `-bip44=1`. See [Wallet](#wallet).
- A newly created wallet now rescans the whole chain on its first start (so
  that a wallet restored from recovery words finds its history). On mainnet
  this takes a while.
- On mainnet the BIP44 coin type stays 0 (`m/44'/0'/…`), so existing wallets
  and exchange integrations keep working. Wallets created with the
  SLIP44-1900 variant builds of 1.0.5–1.0.7 use `m/44'/1900'/…` and derive
  different addresses from the same seed.

Testnet reset
-------------

Testnet was restarted from a new genesis block (2026-09-26). The new chain:

- uses SHA256d proof of work instead of KAWPOW;
- keeps the `RUEN` message start and port 19100, but announces protocol
  70030 and refuses older peers, so earlier versions cannot connect to it;
- stores its data in `testnet/` instead of `testnet7/`. The old `testnet7/`
  directory is not read, and its coins do not exist on the new chain;
- has new DNS seeds.

Upgrading from DePIN-Test development builds
--------------------------------------------

This only concerns testnet and regtest users of earlier builds of the
`DePIN-Test` branch (for example the `1.0.6b1_DePIN` and `2.0.0_101326_TEST`
tags):

- The remote DePIN RPCs accept **protocol 5 only**: each takes one signed
  `request` object. Positional protocol 2 calls and protocol 3/4 requests are
  rejected. Upgrade the node first, then clients, libraries and the RPC proxy
  (add `depinreceiveseq` to its allowlist). The signing helpers
  `depinsignchallenge`, `depinsignrequest` and `depinsignreadseq` were
  replaced by `depinsignrpc`. See [depinreceivemsg.md](depinreceivemsg.md).
- A service node that ran with `-depinpoolpersist=1` imports its
  `depinpool.dat` (version 1) once into `depinstate-v2/<hash>/` (LevelDB) on
  the first start with retention enabled. The original file is left
  untouched and a `.v1.bak` copy is kept. Moderation marks are always stored
  there, even with `-depinpoolpersist=0`. Back up the whole stopped state
  directory, not single files. See [depin-pool-state.md](depin-pool-state.md).
- Generic AuthScript (witness v1) addresses are encoded as `nc1p…` /
  `tnc1p…`; the former `nq1p…` / `tnq1p…` strings are rejected.
- `-pqwallet` is refused at startup; use `-addresstype=pq` for a new wallet.
- `-mempoolreplacement=1` and `-walletrbf=1` are refused at startup: remove
  them from `neurai.conf`. Transactions are no longer replaced, and on
  testnet and regtest a sequence that only signals replaceability is invalid
  (no-RBF sequence rule, block 10 of testnet). Tools that set `0xfffffffd`
  must use `0xfffffffe`, `0xffffffff` or a BIP 68 relative lock. The first
  start checks the blocks the node already has against the rule (see
  [No-RBF sequence rule](#no-rbf-sequence-rule)).
- Restart testnet and regtest nodes once with `-reindex-chainstate` (or
  `-reindex`). Blocks connected by earlier builds have no DEPIN restriction
  undo record, and the node refuses to start until it rebuilds them. Mainnet
  nodes need no action.

Downgrading warning
-------------------

- **Indexes.** After the reindex, the address, spent and public-key indexes
  use the new format. Version 1.0.7 does not check the schema version and is
  not designed to read the new entries: after downgrading, restart 1.0.7 once
  with `-reindex`.
- **Wallets.** A wallet created or opened by this release can contain records
  that 1.0.7 does not know (`addresstype`, AuthScript spend data, the strict
  key pool, silent payment records). Wallets of type `pq` or `ecdsa` hold keys
  for address families that 1.0.7 cannot spend. Back up `wallet.dat` before
  upgrading; to downgrade, restore that backup instead of opening a wallet used
  by this release with 1.0.7.
- **Testnet.** Older versions cannot follow the reset testnet.

Compatibility
==============

Neurai runs on operating systems using the Linux kernel, on Windows 10
(version 1809 or later) and Windows 11, and on macOS 12 or later. The Windows
and macOS minimums come from Qt 6.8, which the wallet GUI is built with
([Qt 6.8 supported platforms](https://doc.qt.io/qt-6.8/supported-platforms.html));
earlier Windows releases (Vista, 7, 8) and macOS releases are not supported.

Neurai should also work on most other Unix-like systems but is not
frequently tested on them.

Notable changes
===============

Consensus
---------

Each rule activates at its own height. Block validation uses the height of
the block being validated; the mempool, the wallet and block templates use
the height of the next block, and a reorganization that crosses an activation
height revalidates the mempool.

- **Mainnet:** nothing scheduled.
- **Testnet:** blocks 1-9 run the previous rules; block 10
  (`TESTNET_FEATURES_HEIGHT`) is the first block that applies the new ones,
  except the C6 proof profile (block 100).
- **Regtest:** everything is active from height 0 by default, except the
  NIP-040 marker and the DEPIN transfer state (height 1) and NIP-028 (only
  scheduled with `-blocktimereductionheight`). The regtest-only options in
  the last column move the heights for activation tests; they are listed by
  `-help-debug`. `-forkheight=<n>` moves all of them at once, as mainnet will
  activate them, and the single-rule options given with it still move one
  rule.
- **Asset block version:** on testnet and regtest, which activate assets by
  height, a block at or below the activation height does not need the asset
  version bit. A node past the activation used to reject a competing chain
  that starts there, because it checked the bit against its own tip.

| Change | NIP | Mainnet | Testnet | Regtest (default, override) |
|---|---|---|---|---|
| AuthScript (witness v1): tagged script commitments with script-only, ML-DSA-44 or ECDSA authentication; addresses `nc1p…` / `tnc1p…` | — | not scheduled | 10 | 0, `-optinfeaturesheight` |
| Strict AuthScript families: witness v2 post-quantum (`pq1z…` / `tpq1z…`) and witness v3 ECDSA (`nq1r…` / `tnq1r…`); family-independent signature checks in v1 `OP_CHECKMULTISIG` (mixed ECDSA/PQ multisig) | — | not scheduled | 10 | 0, `-strictauthscriptheight` |
| AuthScript destination introspection: `OP_OUTPUTAUTHDEST`, selector `0x04` | NIP-041 | not scheduled | 10 | 0, `-strictauthscriptheight` |
| Covenant and introspection opcodes: `OP_CHECKTEMPLATEVERIFY` (BIP 119), `OP_CAT` (BIP 347), `OP_SPLIT`, `OP_REVERSEBYTES`, `OP_TXFIELD`, `OP_TXLOCKTIME`, `OP_OUTPUTVALUE`, `OP_OUTPUTSCRIPT`, `OP_INPUTCOUNT`, `OP_OUTPUTCOUNT`, `OP_OUTPUTASSETFIELD`, `OP_INPUTASSETFIELD`; 64-bit script numbers with `OP_MUL`, `OP_DIV`, `OP_MOD` re-enabled | — | not scheduled | 10 | 0, `-optinfeaturesheight` |
| Transaction version 3 with reference inputs (`vrefin`); `OP_REFINPUTCOUNT`, `OP_REFINPUTFIELD`, `OP_REFINPUTASSETFIELD` | NIP-014 | not scheduled | 10 | 0, `-optinfeaturesheight` |
| `OP_OUTPUTAUTHCOMMITMENT`, `OP_INPUTVALUE`, `OP_CHAINCONTEXT` | NIP-023, NIP-024, NIP-026 | not scheduled | 10 | 0, `-optinfeaturesheight` |
| Hash and proof opcodes: `OP_KECCAK256`, `OP_BLAKE2B`, `OP_CHECKMERKLEINCLUSION`, `OP_BLAKE3`, `OP_SHA3_256`, `OP_SHA512`, `OP_POSEIDON` | NIP-030, NIP-031, NIP-034a, NIP-036 | not scheduled | 10 | 0, `-optinfeaturesheight` |
| Strict `OP_XNA_ASSET` placement rule | — | not scheduled | 10 | 0, `-optinfeaturesheight` |
| Signature opcodes `OP_CHECKSIGFROMSTACK`, `OP_CHECKSIG_ED25519`, `OP_CHECKSIGADD`. CSFS and CHECKSIGADD (as do `OP_CHECKMERKLEINCLUSION` and `OP_ZKVERIFY`) raise the stack element limit to 3072 bytes, enough for ML-DSA-44 keys (1313 bytes) and signatures (2421 bytes) | NIP-035, NIP-039, NIP-018 | not scheduled | 10 | 0, `-signatureopcodesheight` |
| `OP_TXHASH` with a 16-bit field mask | NIP-042 | not scheduled | 10 | 0, `-txhashheight` |
| State-thread primitives: transfer-message selector `0x08`, `OP_INPUTFIELD`, Poseidon Merkle scheme `05` | NIP-043 | not scheduled | 10 | 0, `-assetmessageheight`, `-inputfieldheight`, `-merkleposeidonheight` |
| AuthScript script trees | NIP-044 | not scheduled | 10 | 0, `-authscripttreeheight` |
| AuthScript execution budgets (512 operations, hash units, initial argument limits) | NIP-046 | not scheduled | 10 | 0, `-authscriptbudgetheight` |
| `OP_ZKVERIFY` (Groth16 over BN254, AuthScript only), profile `01` | NIP-016 | not scheduled | 10 | 0, `-zkverifyheight` |
| `OP_ZKVERIFY` profile `02`: public-tree transitions (C5, experimental) | — | not scheduled | 10 | 0, `-zkpublictreeheight` |
| `OP_ZKVERIFY` profile `03`: portable-tree transitions (C6, experimental) | — | not scheduled | **100** | 0, `-zkportabletreeheight` |
| P2AH: `OP_CHECKASSETAUTH` (`0xdf`, AuthScript only), M of N owner tokens approve a spend by direct signature or by a vote bound to a proposal hash; work budget of 450,000 units per block and 45,000 per standard transaction. See [covenants.md](covenants.md) | NIP-054 | not scheduled | **100** | 0, `-assetauthheight` |
| Poseidon work budget: at most 200,000 permutations per block (20,000 per standard transaction) | — | not scheduled | 10 | 0, `-poseidonworkheight` |
| Asset payload marker `rvn` → `xna` for new asset outputs; existing `rvn` outputs stay spendable | NIP-040 | not scheduled | 10 | 1, `-nip040height` |
| DEPIN transfer state (open, close, seal) | — | not scheduled | 10 | 1, `-depinstateheight` |
| No-RBF sequence rule: every non-coinbase input uses sequence `0xffffffff`, `0xfffffffe` or, in a version 2 or 3 transaction, a BIP 68 relative lock; a value that only signals BIP 125 replaceability makes the transaction invalid (`bad-txns-rbf-sequence`). See [No-RBF sequence rule](#no-rbf-sequence-rule) | — | not scheduled | 10 | 0, `-rbfbanheight` |
| Block time 60 s → 30 s, subsidy halved with the halving interval doubled to 28,800 blocks, 120-block reorganization limit, block version bit `0x40000000` required | NIP-028 | not scheduled | 10 | not scheduled, `-blocktimereductionheight` |

<!-- TODO: confirm the NIP numbers. No NIP is given in doc/ for AuthScript,
the strict families, the first opcode set, the strict OP_XNA_ASSET rule, the
C5/C6 profiles, the Poseidon work budget or the DEPIN transfer state. The
docs call OP_ZKVERIFY NIP-016; src/script/interpreter.h labels
SCRIPT_VERIFY_ZKVERIFY "NIP-018". Profile 03 (C6) is not described in
covenants.md. -->

### No-RBF sequence rule

Replace-by-fee is prohibited by consensus from the activation height. A
sequence below `0xfffffffe` must be a relative lock that BIP 68 enforces (bit
31 clear in a transaction of version 2 or higher), so `OP_CHECKSEQUENCEVERIFY`
and `OP_CHECKLOCKTIMEVERIFY` keep working; a value with no consensus meaning,
such as `0xfffffffd`, is invalid. The coinbase input is exempt. On the running
testnet the rule is retroactive from block 10: a scan of blocks 10 to 91,005
found no input that breaks it.

A node checks the rule whenever it connects a block, including blocks read
back from disk by `-reindex-chainstate`, `reconsiderblock` or
`verifychain`. At startup it also checks, once, the blocks of its active chain
that it connected without the rule (with an earlier build, or with a higher
`-rbfbanheight` on regtest). If one of them breaks the rule, the node refuses
to start until the chainstate is rebuilt with `-reindex-chainstate`, which
rejects that block. A pruned node that no longer has the block needs
`-reindex`.

A rule on blocks cannot decide which of two conflicting transactions is
mined; a miner can still choose either. What the rule removes is the
replaceability signal from the protocol, and the node no longer replaces
transactions at all (see the relay policy under [P2P and network](#p2p-and-network)).

Two asset rules follow the activation height of the strict AuthScript
families (testnet block 10, regtest genesis, mainnet the unified fork):

- **DEPIN assets** (`&NAME`, sections `&NAME/SUB`, owner tokens `&NAME!`)
  exist from that height; before it they are rejected
  (`bad-txns-depin-not-enabled`). DePIN messaging accepts a DEPIN token on
  any network that schedules DEPIN assets, whatever the height of the tip.
  See [DePIN](#depin).
- **Asset name length:** 121 characters (`MAX_NAME_LENGTH_EXTENDED`) from that
  height, 31 before it.

Rules that depend on the network rather than on a height:

- **Proof of work:** testnet and regtest use SHA256d (regtest previously ran
  the X16R path). Mainnet is unchanged.
- **Coinbase maturity:** 5 blocks on testnet (100 on mainnet and regtest), now
  a consensus parameter (`nCoinbaseMaturity`).
- **Reset testnet:** assets, RIP5 and the asset VersionBits deployments are
  active from genesis, as are the 1.0.6 KAWPOW header-height and asset
  overflow rules. The reissue exception for two assets of the previous testnet
  (`GAMINGWEB`, `UINT8`) is gone; neither exists on the reset testnet.

Opcode details, encodings and covenant patterns are in
[covenants.md](covenants.md) and
[new-opcodes-depin-branch.md](new-opcodes-depin-branch.md); see also
[bips.md](bips.md).

P2P and network
---------------

- **Protocol version.** Mainnet announces 70029 (was 70028); the minimum peer
  version is unchanged (70025). Testnet and regtest announce 70030. The reset
  testnet refuses peers below 70030, and from the NIP-028 height it also
  disconnects peers below 70029. `getnetworkinfo` reports the version of the
  selected network.
- **Faster initial header sync.** Mainnet ships 866 independently verified
  header anchors, one every 2,000 blocks through height 1,732,000; KAWPOW
  proof of work is not recomputed for anchored headers. Remaining KAWPOW
  headers are verified in parallel outside `cs_main`; acceptance stays
  serial. `-checkpoints=0` disables the anchors; testnet and regtest have
  none. In one measurement, header sync went from 125 to 20 minutes. This
  also fixes a data race in the KAWPOW light-context cache. See
  [header-sync-validation.md](header-sync-validation.md).
- **Header sync diagnostics:** new `getibdstatus` RPC, and the same figures in
  the debug window of the GUI.
- **Reindex and `-loadblock`** check the proof of work of a new header once
  instead of twice. One full mainnet reindex took 39% less time. See
  [reindex-validation.md](reindex-validation.md).
- **`-listenonion` is now off by default.** The automatic hidden service
  requests an onion v2 service (`NEW:RSA1024`), which Tor removed. Using Tor
  as an outgoing proxy still works. See [tor.md](tor.md).

Relay policy:

- The default mempool package limits were raised: `-limitancestorcount` and
  `-limitdescendantcount` from 200 to 500, `-limitancestorsize` and
  `-limitdescendantsize` from 250 to 750 kB.
- Transaction replacement (BIP 125) was removed on every network: a
  transaction that conflicts with one in the mempool is always rejected
  (`txn-mempool-conflict`), whatever its fee and sequences.
  `replacement-involves-assets` no longer exists. A stuck transaction is
  raised with a child that spends one of its outputs (CPFP) or abandoned in
  the wallet once it leaves the mempool (`-mempoolexpiry`, 14 days by
  default).
- Where the no-RBF sequence rule applies to the next block, the mempool
  refuses replaceability signals, and the transactions admitted before with a
  signal are evicted, with their descendants, when the rule activates.
- `-datacarriersize` defaults to 512 bytes from the height of the opt-in
  switches for the next block (testnet block 10, regtest genesis, mainnet the
  unified fork) and to 83 bytes before it.
- Where the new rules are active (testnet, regtest): outputs to an AuthScript
  family that is not yet active for the next block are refused; the P2WSH
  per-item relay limit rises from 80 to 3,072 bytes when the Merkle or
  signature opcodes are active (NIP-021); a standard transaction may contain
  at most four `OP_ZKVERIFY` and 20,000 Poseidon permutations.
- Post-signing verification in the wallet, `signrawtransaction` and
  `neurai-tx` applies the consensus opt-ins active at the next block
  (NIP-020). `neurai-tx` has no chain tip and uses height 0.

Mining
------

- Testnet and regtest mine with SHA256d. Mainnet mining (KAWPOW) is
  unchanged.
- From block 10, testnet targets 30-second blocks (NIP-028). Dark Gravity
  Wave keeps its 180-block window and sums the target spacing of each block
  in it, so a window that crosses the activation height does not jump; the
  minimum-difficulty rule uses the spacing in force. Every testnet block from
  that height must set version bit `0x40000000`.
- Block templates respect the Poseidon work limit, count the signature
  operations of the new signature opcodes, and skip transactions whose
  reference inputs are spent by another transaction in the template.
- `generatetoaddress` refuses an AuthScript address whose family is not active
  for the next block.
- Known limit: KAWPOW epochs are capped at 896 (`ETHASH_MAX_EPOCH_NUMBER`), so
  mainnet headers from height 6,727,500 are rejected. The limit will be raised
  in a future release, well before the chain reaches that height.

Wallet
------

- **Encrypted wallets.** Encrypting a wallet could leave the unencrypted BIP39
  mnemonic in unused space of `wallet.dat` (about one encryption in five in
  tests): Berkeley DB filled part of a new page with whatever its buffer held
  before. Berkeley DB is now built with `--enable-umrw` (`depends` and
  `contrib/install_db4.sh`), which fills that space; a build linked against a
  Berkeley DB without it does not get this protection. A wallet encrypted by
  an earlier version is rewritten once on its first load (`Rewriting
  encrypted wallet ... once` in the log); older versions ignore the record
  that marks it. Copies and backups made earlier keep whatever they hold: if
  one may have been exposed, move the funds to a new wallet.
- **Address types.** `-addresstype` selects what a new wallet hands out by
  default, in the GUI and over RPC (`getnewaddress`, `getaccountaddress`,
  `getrawchangeaddress`, change, the asset RPCs and mining):

  | `-addresstype` | Default | Also on request |
  |---|---|---|
  | `legacy` (default) | Legacy (Base58) | strict v3 (`"ecdsa"`) |
  | `pq` | strict v2 (post-quantum) | strict v3 (`"ecdsa"`) |
  | `ecdsa` | strict v3 | none: never hands out Legacy |

  `getnewaddress` and `getrawchangeaddress` take a new `address_type`
  argument. Strict addresses are handed out at any time, but nothing pays to
  them until the network activates them (today: testnet and regtest); there
  is no Legacy fallback. The wallet never manages generic AuthScript v1
  addresses, which are a contract family. `getwalletinfo` reports the type.
  See [covenants.md](covenants.md#authscript-contract-address-encoding).
- **Post-quantum keys.** `pq` wallets derive ML-DSA-44 keys from the BIP39
  mnemonic seed. New RPCs: `listpqaddresses`, `dumpextkeypq` (master
  `xpqp…` key) and `exportxpqpub`.
- **Silent payments (NIP-047).** A wallet of type `ecdsa`, or one with an
  imported view key, has a reusable payment code (`nsp1…` / `tnsp1…`,
  Bech32m, derived under `m/352'`). Every payment to the code lands on a new
  strict ECDSA (witness v3) output, so silent payments only work where that
  family is active (testnet, regtest). The wallet scans blocks, the mempool
  and reorganizations. Received payments are not combined by automatic coin
  selection unless `-mixsilentpayments=1`. RPCs: `getsilentpaymentcode`,
  `decodesilentpaymentcode`, `sendsilentpayments`, `listsilentpayments`,
  `getsilentpaymentinfo`, `rescansilentpayments`,
  `exportsilentpaymentviewkey`, `importsilentpaymentviewkey`,
  `repairsilentpaymentidentity`. The GUI can send to codes and shows the code
  in Receive.
- `signrawtransaction` can sign strict ECDSA (witness v3) inputs with the keys
  passed in `privkeys`.
- The seed, mnemonic and passphrase are kept in secure memory and wiped when
  the wallet is locked.
- Amounts with 11 integer digits (the full 21-billion supply) are now parsed
  by the RPC interface and the GUI.

GUI:

- New look (Inter font, light and dark palettes), top header navigation and
  status badges, redesigned overview.
- Redesigned first-run dialog: create or restore, recovery words, choice of
  address type (preset to `-addresstype`) and backup confirmation. When
  restoring, the type must be the one the wallet was created with.
- New option "Use the test network (testnet) from the next start";
  `-testnet`/`-regtest` take precedence.
- DePIN management in the restricted assets page, and a Privacy page on
  testnet (see [Privacy pool](#privacy-pool)).

DePIN
-----

DePIN assets and messaging are experimental and available on **testnet and
regtest only**.

**Assets.** A DEPIN asset (`&NAME`, sections `&NAME/SUB`, owner tokens
`&NAME!`) is soulbound: only the owner can move it, freeze or unfreeze a
holder (`freezedepin`, `unfreezedepin`), and a holder can revoke its own
holding (`selfrevokedepin`), which stays at the address but is no longer
valid. From the DEPIN transfer state height the owner
can open transfers (`opendepin`), close them again (`closedepin`) or seal the
asset irreversibly (`sealdepin`); `createrawtransaction` accepts the matching
`open_depin`, `close_depin` and `seal_depin` outputs. Queries:
`checkdepinvalidity`, `listdepinholders`, `listdepinaddresses`.

Freezes and self-revocations are consistent across nodes and
reorganizations:

- The self-revocation lookup has its own cache. It used to share the
  owner-freeze cache key, so the contents of a node's cache could change
  whether a freeze was valid.
- It also sees undo entries that are still pending a flush.
- Undoing a block restores exactly the restriction state the block changed,
  from a record written whenever the block is connected.
- A confirmed freeze, self-revocation or close evicts only the pending holder
  transfers it makes invalid; self-revocations and transfers escorted by the
  owner token stay in the mempool.
- `verifychain 4` (and `-checklevel=4`) reconnects each block against the
  asset state of its own past. It used to check freezes, self-revocations
  and the other asset rules against the state at the tip, so it reported a
  valid unfreeze as unconnectable once the holder was no longer frozen.

**Messaging.** An off-chain, encrypted and expiring message pool for the
holders of one token subtree (`-depinmsgtoken`), served over the node's
JSON-RPC port, usually behind an RPC proxy. Content is encrypted for each
recipient (ECIES with AES-256-GCM). Access follows on-chain holdings,
inherited from ancestor sections. A service node needs `-assetindex`,
`-pubkeyindex`, a wallet-enabled build and an unencrypted legacy BIP44
service wallet for the pool key (`-depinwallet` when several wallets are
loaded).

- **Protocol 5.** Each remote method takes one `request` object that binds
  the method, network, pool key and root, the instance, the membership
  revision, a fresh request ID, a millisecond timestamp, the token, address
  and challenge, and every effective argument. Private operations are signed
  by the holder's address; public queries leave the authentication fields
  empty. Every reply is signed with the pool key, and replies to an address
  are encrypted for it. `depingetmsginfo` is the bootstrap. A local wallet
  signs requests with `depinsignrpc`. See
  [depin-request-signatures.md](depin-request-signatures.md) and
  [depinreceivemsg.md](depinreceivemsg.md).
- **Membership.** Each pool has a random `membership_revision`, renewed by any
  relevant confirmed change (holdings, sections, owners, freezes,
  self-revocations, transfer state, first key revelation). A renewal
  invalidates all receive and admin challenges; a request signed for an old
  revision gets a signed `membership_stale` error. See
  [depin-membership.md](depin-membership.md).
- **Identities.** Legacy P2PKH and strict ECDSA (witness v3) addresses can
  authenticate and receive. Messages that include a strict ECDSA recipient
  use the typed ECIES 2 format. See [depin-ecdsa.md](depin-ecdsa.md).
- **Authorization** follows the connected active chain, not the mempool.
  Permission-dependent calls fail with `-10` during import, reindex or IBD,
  when the tip is older than `-depinmaxtipage` (3600 s) or when known headers
  lead by more than `-depinmaxheaderlag` (2 blocks). Every declared recipient
  must be authorized, or the whole message is rejected (`-26`). See
  [depin-authorization.md](depin-authorization.md).
- **Pool state.** Strict bounded decoders; `-depinmsgsize` limits content
  plaintext bytes (default 1024, maximum 10240); up to 20 recipients by
  default (maximum 50); expiry 168 hours by default (maximum 720). New
  admission-order reads with a durable cursor (`depinreceiveseq`). Moderation
  marks are written synchronously to `depinstate-v2/` before `depinclearmsg`
  succeeds (`-depintombstonelimit`, default 100,000). Message retention across
  restarts stays optional (`-depinpoolpersist`, default 0). See
  [depin-pool-state.md](depin-pool-state.md).
- **MCP worker.** With `-depinmcp=1` the node answers messages that start with
  a command prefix (`-depinmcpkey`, default `/ai`) by querying an HTTP
  chat-completions endpoint (`-depinmcpurl` and `-depinmcpendpoint`, default
  `http://localhost:1234` and `/v1/chat/completions`), and signs its replies
  with `-depinmcpaddress`. Status: `depinmcpstatus`.

The service node guide is [depin-guide.md](depin-guide.md); the protocol
specification is [depin-messaging-protocol.md](depin-messaging-protocol.md).

Privacy pool
------------

Experimental and not audited. The pool contracts are AuthScript state threads,
so they only exist where AuthScript is active (testnet, regtest), and the GUI
page is disabled on mainnet.

- **Consensus building blocks** (testnet): `OP_ZKVERIFY` with the public-tree
  (C5, profile `02`) and portable-tree (C6, profile `03`, from block 100)
  transitions, and `OP_POSEIDON`.
- **RPC prototype:** `getprivacypoolinfo` and `getprivacypoolupdates` return
  the public history of a pool given its birth outpoint, with no registry,
  new index or consensus rule. They need `-spentindex` and `-txindex`. Pages
  hold 1 to 1000 transitions (default 100) and at most 1 MiB of raw
  transactions. See [covenants.md](covenants.md#privacy-pool-history-rpc-prototype).
- **GUI Privacy page:** deposit, private transfer and withdrawal for the C6
  XNA pool, with NeuraiZK/v2 identities derived from the recovery words and
  `tnzk` addresses. Proofs are generated inside the wallet (Groth16 on the
  `mcl` backend, circuit witnesses with `wasm3`). C7 pool instances
  (NeuraiZK/v3 notes, wallet side only, no consensus change) are preferred
  when configured. The pool configuration is looked up in `-privacypooldir`,
  the network data directory or next to the executable; a C7 instance that
  is not pinned in the build needs `-privacypoolunpinned`.

Indexes and REST
----------------

- New `-pubkeyindex`: public keys revealed by spends, used by DePIN messaging
  and by the new `getpubkey` RPC.
- New `-silentpaymentindex` for NIP-047 light clients: for each block, the
  eligible transactions with native witness v3 outputs, their public tweak
  and those outputs, plus the v3 outputs the block spends. Served by
  `getsilentpaymentindexinfo`, `getsilentpaymenttweaks`,
  `getsilentpaymenttweaksrange` and by REST: `/rest/spindexinfo.json`,
  `/rest/sptweaks/v1/<BLOCK-HASH>` and `/rest/sptweaksrange/v1/<HEIGHT>/<COUNT>`
  (bin, hex, json). Records are checked at startup;
  `-checksilentpaymentindex` sets how many of the last blocks are rebuilt and
  compared (default 6). See [REST-interface.md](REST-interface.md).
- New `-channelmessageindex` (NIP-048): every message carried by an owner
  token or a message channel token back to its own address, whatever the
  wallet, served by `getchannelmessages` and
  `/rest/channelmessages/<FROM-HEIGHT>/<CHANNEL>.json`. Expiry is decided at
  query time, so nodes with the same chain answer alike; records of blocks
  that leave the active chain are ignored, not deleted. Enabling it on a
  synced node indexes the missing blocks at startup; it needs unpruned blocks. See
  [asset-rewards-and-messages.md](asset-rewards-and-messages.md), which also
  covers reward plans, snapshots and eligibility.
- New address, spent and public-key index format (see
  [How to Upgrade](#indexes-that-need-a-reindex)).
- Spent index entries of disconnected blocks are now erased, so
  `getspentinfo` no longer reports spends that a reorganization removed.
- `getaddressdeltas` accepts `"assetName": "*"` for all assets.
- `getblock` verbosity 3 adds a `prevout` object, with the spent output, to
  each input.
- `/rest/chaininfo.json` and `getblockchaininfo` report `asset_marker`,
  `zk_public_tree` and `zk_portable_tree`. Transaction JSON includes `vrefin`
  for version 3 transactions with reference inputs.

Build system
------------

- C++20 is required (was C++17): GCC 12 or later, or Clang 14 or later.
- The GUI uses Qt 6 (6.8.3 in depends) instead of Qt 5 (5.12.11 in 1.0.7),
  with Wayland support on Linux.
- liboqs 0.16.0 is required; `configure` fails without it. The depends system
  builds it.
- Boost 1.81 or later is required.
- Ubuntu 24.04 is the minimum for native builds; 22.04 is no longer
  supported (build with Docker there). See [build-ubuntu.md](build-ubuntu.md)
  and [build-docker.md](build-docker.md).
- The pinned NIP-018 `mcl` backend only supports x86-64 and ARM64, so 32-bit
  ARM is no longer supported. 32-bit Windows is not supported (Qt 6). See
  [build-unix.md](build-unix.md) and
  [build-raspberrypi.md](build-raspberrypi.md).
- macOS packages are cross-compiled from Linux with OSXCross (macOS 14.5
  SDK, clang/LLD 18) for Intel (`x86_64`) and Apple Silicon (`arm64`), and are
  shipped as unsigned ZIP and `.tar.gz` archives; there is no DMG. See
  [build-osx.md](build-osx.md).
- The release builds of the CI are `windows`, `linux`,
  `linux-disable-wallet`, `osx` `x86_64` and `osx` `arm64`. See
  [release-process.md](release-process.md).
- New `--with-build-tag=TAG` appends a tag to the user agent, for example
  `/Neurai:2.0.0(20261014-28d3403)/`.
- New bundled code: the `mcl` pairing library (pinned, private namespaces),
  libsodium's ref10 Ed25519 backend, BLAKE3, `wasm3` 0.5.0 and Monocypher
  4.0.2. They are listed in [dependencies.md](dependencies.md).
- `neurai-tx` now links on Windows (it relied on weak symbols that MinGW
  does not resolve from static libraries).
- See [dependencies.md](dependencies.md) for the versions of the external
  dependencies.

Configuration option changes
----------------------------

New options:

- Indexes: `-pubkeyindex`, `-silentpaymentindex`,
  `-checksilentpaymentindex=<n>`, `-channelmessageindex` (NIP-048; not with
  `-prune`).
- Wallet: `-addresstype=<type>` (`legacy`, `pq` or `ecdsa`; default
  `legacy`), `-mixsilentpayments` (default 0).
- DePIN service: `-depinmsg`, `-depinmsgtoken=<token>`, `-depinwallet=<file>`,
  `-depinratelimit=<n>` (default 20 per address and minute),
  `-depinmsgmaxusers=<n>` (default 20), `-depinmsgsize=<n>` (default 1024),
  `-depinmsgexpire=<n>` (default 168 hours), `-depinpoolsize=<n>` (default
  100 MB), `-depinpoolpersist` (default 0), `-depintombstonelimit=<n>`
  (default 100000), `-depinmaxtipage=<n>` (default 3600),
  `-depinmaxheaderlag=<n>` (default 2), `-depinmsgcleanupinterval=<n>`
  (default 300 s).
- DePIN MCP worker: `-depinmcp`, `-depinmcpurl`, `-depinmcpendpoint`,
  `-depinmcpkey`, `-depinmcpaddress`, `-depinmcpinterval`, `-depinmcpprefix`,
  `-depinmcptimeout`, `-depinmcpapikey`, `-depinmcpratelimit`,
  `-depinmcpglobalratelimit`, `-depinmcpconcurrency`, `-depinmcpcontext`,
  `-depinmcpmaxtokens`, `-depinmcptemperature`, `-depinmcpfragsize`,
  `-depinmcpmaxfragments`.
- Regtest only (shown with `-help-debug`): `-optinfeaturesheight`,
  `-strictauthscriptheight`, `-signatureopcodesheight`, `-txhashheight`,
  `-assetmessageheight`, `-inputfieldheight`, `-merkleposeidonheight`,
  `-authscripttreeheight`, `-authscriptbudgetheight`, `-zkverifyheight`,
  `-zkpublictreeheight`, `-zkportabletreeheight`, `-poseidonworkheight`,
  `-nip040height`, `-depinstateheight`, `-rbfbanheight`,
  `-blocktimereductionheight`.
- GUI only: `-privacypooldir=<dir>` and, with `-help-debug`,
  `-privacypoolunpinned`.
- `neurai-tx`: new command `refin=TXID:VOUT` adds a reference input (and
  forces a version 3 transaction). The `replaceable` command was removed, and
  a sequence that only signals replaceability is reported on stderr as a
  warning (`neurai-tx` cannot know whether the no-RBF sequence rule applies
  yet).
- Legacy asset modules (NIP-048): `-assetmessages`, `-assetrewards`,
  `-minsnapshotnotice=<n>` (default 60 blocks), `-maxsnapshotrequests=<n>`
  (different assets whose snapshot can be requested at one height, default
  16, 0 for no limit); `-minrewardheight`, which already existed, is now
  listed in the help.

Changed defaults:

- `-limitancestorcount` and `-limitdescendantcount`: 200 → 500.
- `-limitancestorsize` and `-limitdescendantsize`: 250 → 750 kB.
- `-datacarriersize`: 83 → 512 bytes from the unified fork height (testnet
  block 10, regtest genesis); mainnet keeps 83 until its fork height.
- `-listenonion`: 1 → 0.
- `-maxreorg`: 120 from the NIP-028 height (testnet block 10, mainnet the
  unified fork); 60 before it.

Changed behavior:

- A new data directory no longer gets the legacy `messages/` and `rewards/`
  stores unless asked: `-assetmessages=1` for messages, `-assetrewards=1` or
  `-assetindex` for rewards. A data directory that already has a store keeps
  using it, and turning a module off never deletes its store.
- `-disablemessaging` is now the same as `-assetmessages=0`, and combining it
  with `-assetmessages=1` is refused at startup. A bare `-disablemessaging`
  now disables legacy asset messaging; it used to leave it enabled. Neither
  option affects DePIN messaging (`-depinmsg`).
- Snapshot requests are stored by height and asset (existing ones are moved
  at startup). Each block used to read every request ever made, and two
  requests could overwrite each other (height 12 of `3ABC` and height 123 of
  `ABC`). A snapshot reads its holders in one pass instead of restarting the
  scan every 100 holders, which made the capture grow with the square of the
  holder count while the block connected.

Removed options: `-mempoolreplacement` and `-walletrbf`. Asking for
replacement (`-mempoolreplacement=1`, `-mempoolreplacement=fee` or
`-walletrbf=1`) is refused at startup; `0` is accepted and ignored so existing
configuration files still load. `-pqwallet`, which only existed in
development builds, is refused at startup with a pointer to
`-addresstype=pq`.

Low-level RPC changes
----------------------

New RPCs (52):

- DePIN messaging, remote protocol 5, one `request` argument each:
  `depingetmsginfo`, `depinchallenge`, `depinreceivemsg`, `depinreceiveseq`,
  `depinsubmitmsg`, `depinclearmsg`, `depinlistsections`,
  `depingetancestorrecipients`, `depinpoolstats`, `depinmcpstatus`.
- DePIN messaging, local: `depinsignrpc "method" request`,
  `depinsendmsg "token" "message" "fromaddress"`,
  `depingetmsg "token" ( "fromaddress" )`, `depindecrypt "address" "encrypted"`,
  `depinpoolpkey`, `listdepinaddresses "asset_name" ( count start )`.
- DePIN assets: `checkdepinvalidity`, `listdepinholders`, `freezedepin`,
  `unfreezedepin`, `selfrevokedepin`, `opendepin`, `closedepin`, `sealdepin`.
- Silent payments, wallet: `getsilentpaymentcode`, `decodesilentpaymentcode`,
  `sendsilentpayments`, `listsilentpayments`, `getsilentpaymentinfo`,
  `rescansilentpayments`, `exportsilentpaymentviewkey`,
  `importsilentpaymentviewkey`, `repairsilentpaymentidentity`.
- Silent payment index: `getsilentpaymentindexinfo`, `getsilentpaymenttweaks`,
  `getsilentpaymenttweaksrange`.
- Post-quantum wallet: `listpqaddresses`, `dumpextkeypq`,
  `exportxpqpub count ( chain offset )`.
- Privacy pool: `getprivacypoolinfo pool ( limit )`,
  `getprivacypoolupdates pool ( cursor limit )`.
- Other: `getpubkey "address"` (needs `-pubkeyindex`), `getibdstatus`.
- Reward plans (NIP-048): `getdistributionplan "asset_name" snapshot_height
  "distribution_asset_name" amount ( "exception_addresses" {options} )`
  computes, without spending, how an amount is split among the holders in a
  snapshot, in whole units of the distribution asset, and returns a plan hash
  that commits to the snapshot, the parameters and every payment.
  `getdistributionproof {plan} "address"` returns a recipient's Merkle
  inclusion proof, `getdistributionbatches {plan} ( {options} )` splits the
  payments into batches, and `verifydistribution {plan} [batches] ( {options} )`
  classifies each batch from the operator's records (confirmed, confirming,
  pending, conflicting or unknown). In the wallet, `createdistributionbatch
  "plan_hash" {plan} batch_index ( {options} )` builds, funds and signs one
  batch bound to the approved plan hash, locks its inputs and returns it
  without broadcasting. `getsnapshotannouncement "asset_name" height` returns
  the message the owner token carries to announce a snapshot height in
  advance, so other nodes request the same snapshot; a plan that names the
  announcement commits to it. `replaysnapshot "asset_name" height` rebuilds a
  snapshot from the blocks and their undo data and returns its hash, for nodes
  that did not capture it.
- Reward eligibility (NIP-048): snapshots record, per holder, freezes, DEPIN
  self-revocations and qualifier tags at their height; plans exclude frozen
  and self-revoked holders and accept a `qualifier` filter and the `weights`
  of a work report anchored on the owner token (`report`). With
  `"allocation": "equal"` every eligible holder gets the same share, whatever
  it holds (for instance one share per DEPIN device), and `min_held` excludes
  holders with less than a minimum holding, in either allocation.
  `getsnapshotrecipients "asset_name" height` lists the holders with what an
  encrypted bulletin to them needs (public key revealed or not, address type
  supported or not).
- Channel message index (NIP-048): `getchannelmessages "channel" ( {options} )`
  returns every message of an owner token or message channel from
  `-channelmessageindex`, with its authority, payload, expiry and any
  `OP_RETURN` data of the same transaction, optionally with the raw
  transaction and a `gettxoutproof` proof. At most `limit` messages per call
  (default 1000), without splitting a block; `next_from_height` starts the
  next page.

Changed RPCs (arguments and request format):

- `getnewaddress ( "account" "address_type" )`: new `address_type` argument.
- `getrawchangeaddress ( "address_type" )`: new `address_type` argument.
- `createrawtransaction`: new 4th argument `refinputs` (reference inputs,
  forces a version 3 transaction); `outputs` can also be an ordered array of
  single-key objects, which allows repeated addresses; asset quantities
  accept JSON strings; reissue outputs accept `units`; new `open_depin`,
  `close_depin` and `seal_depin` outputs. `refinputs` can also be passed as a
  named argument.
- `getblock`: new verbosity 3.
- `createrawtransaction`: an explicit input `sequence` that only signals
  replaceability is refused once the no-RBF sequence rule applies to the next
  block.
- `getaddressdeltas`: `assetName` accepts `"*"`.
- `distributereward` no longer sends payments: it fails with error -32 and
  points to `getdistributionplan`. The node no longer builds or retries reward
  payments on new blocks, so a distribution never pays by itself when funds
  arrive. `getdistributestatus` still reads the records of earlier
  distributions.

Result changes:

- `getblockchaininfo`: new `asset_marker`, `zk_public_tree`,
  `zk_portable_tree`.
- `getwalletinfo`: new `addresstype`, and `keypoolsize_strict_ecdsa` /
  `keypoolsize_strict_ecdsa_internal`.
- An RPC call still running when the node shuts down, such as
  `waitfornewblock`, gets its reply; the HTTP server used to close the
  connection before sending it.
- `dumpwallet`: unused keys of the strict ECDSA keypool are marked
  `reserve=1`, like those of the legacy keypool; they used to appear as
  `change=1`. Post-quantum keys are dumped with the strict v2 address the
  wallet hands out, and keep their labels; the dump used to show a generic
  AuthScript v1 address and mark labelled keys as `change=1`.
- `getmasterkeyinfo`: new `wallet_type`, `address_type`,
  `strict_ecdsa_derivation_path` (ecdsa wallets),
  `external_derivation_path`, `internal_derivation_path` and post-quantum key
  information.
- `getnetworkinfo`: `protocolversion` is the version of the selected network
  (70030 on testnet and regtest).
- `getblockchaininfo`: new `asset_services` with the state of the legacy
  messages and rewards stores.
- `getsnapshot`: new `block_hash`, `snapshot_hash`, `format` and, for
  snapshots with holder state, `global_frozen` and per owner `frozen`,
  `self_revoked` and `tags`. A snapshot is now bound
  to the block it was captured on; if that block is disconnected the snapshot
  is dropped and captured again when a block at that height is connected.
- `viewallmessages`, `viewallmessagechannels`: with messaging disabled or its
  database unavailable they return the explanatory message; they used to
  return an empty string.
- Reward and snapshot RPCs: with the reward stores closed they fail with error
  -20 and a message naming `-assetrewards` (`getdistributestatus` used to
  return -32600).
- `listtransactions`, `listsinceblock`, `gettransaction`: the
  `bip125-replaceable` field was removed (it always said `"no"`).

Removed RPCs: `bumpfee`, which already failed on every call ("bumpfee has
been deprecated").

For users of DePIN-Test development builds: `depinsignchallenge`,
`depinsignrequest` and `depinsignreadseq` were removed in favour of
`depinsignrpc`, `depingetpoolcontent` (present in `1.0.6b1_DePIN`) was
removed, and the remote DePIN RPCs listed above replaced their positional
arguments with the single protocol 5 `request` object.

Credits
=======

The Neurai developers.

Thanks to the Ravencoin developers and to the Bitcoin Core developers.
