# Privacy pool files for neurai-qt (C6 XNA, testnet)

Test files for the Privacy section of the Qt wallet. They pin one pool
instance and hold the circuits that the wallet proves locally.

| File | Purpose |
|------|---------|
| `c6-testnet.json` | Pool instance: profile `C6-XNA-TEST-J2-v2`, state thread `C6TEST261004A#POOL` born at `ba82867c…76e7:0` (height 22121), contract leaves, verifying keys, fee levels and artifact digests. Same file as the web wallet and NeuraiWallet. |
| `D.wasm`, `D.zkey` | Deposit circuit: circom witness generator and Groth16 proving key. |
| `W.wasm`, `W.zkey` | Withdrawal circuit. |
| `T1`, `T2`, `T3` `.wasm`/`.zkey` | Private transfer circuits (one, two or three output notes, change included). |
| `*.vk.json` | snarkjs verifying keys, for reference (the wallet uses the binary keys pinned in `c6-testnet.json`). |

The `.wasm` and `.zkey` files (about 64 MB) are not stored in git: they are
distributed separately and must be copied into this folder. The wallet checks
the size and SHA-256 of every `.wasm` and `.zkey` against `c6-testnet.json`
before using it, so their download source does not need to be trusted. It also
checks the config itself (pool context, verifying key digests, contract
commitment and birth state).

## Where the wallet looks for them

The first folder that contains `c6-testnet.json`:

1. `-privacypooldir=<folder>`
2. `privacy-c6` inside the testnet data directory: `~/.neurai/testnet/privacy-c6` on
   Linux, `%APPDATA%\Neurai\testnet\privacy-c6` on Windows,
   `~/Library/Application Support/Neurai/testnet/privacy-c6` on macOS
3. `privacy-c6` next to the `neurai-qt` executable, or on macOS next to
   `Neurai-Qt.app`

The simplest way is to extract the wallet zip and this folder's zip into the
same directory.

## Use

Run `neurai-qt -testnet` (or tick **Use the test network (testnet) from the
next start** in Wallet → Options and restart) with a wallet created from
recovery words (English BIP39), open **Privacy** and press **Open private
wallet**. The private wallet
is derived from the words as in NeuraiWallet (NeuraiZK/v2, family from the
wallet address type), so both wallets show the same notes.

- Deposit: multiples of 100 XNA. The wallet first sends itself one coin of
  exactly amount + pool fee; once it confirms, Deposit proves and broadcasts.
- Withdraw: multiples of 100 XNA (the rest becomes a private change note), or
  below 100 XNA the whole note (amount + fee = note).
- Private transfer: send part of a note to one to three private (`tnzk1…`)
  addresses, multiples of 100 XNA each; the rest minus the fee comes back as
  change. At most three outputs, change included.
- Notes become spendable two blocks after they are published.

Only the XNA pool on testnet is supported. Joining two notes (J2) is not
available in the Qt wallet yet, but notes created by joins are found and can be
spent.
