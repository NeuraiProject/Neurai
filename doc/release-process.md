Release Process
====================

Before every release candidate:

* Update translations see [translation_process.md](translation_process.md#synchronising-translations).

* Update manpages, see [gen-manpages.sh](../contrib/devtools/README.md#gen-manpagessh).

Before every minor and major release:

* Update [bips.md](bips.md) to account for changes since the last release.
* Update version in `configure.ac` (don't forget to set `CLIENT_VERSION_IS_RELEASE` to `true`)
* Write release notes (see below)
* Update `src/chainparams.cpp` nMinimumChainWork with information from the getblockchaininfo rpc.
* Update `src/chainparams.cpp` defaultAssumeValid  with information from the getblockhash rpc.
  - The selected value must not be orphaned so it may be useful to set the value two blocks back from the tip.
  - Testnet should be set some tens of thousands back from the tip due to reorgs there.
  - This update should be reviewed with a reindex-chainstate with assumevalid=0 to catch any defect
     that causes rejection of blocks in the past history.

Before every major release:

* Update hardcoded [seeds](../contrib/seeds/README.md), see [this pull request](https://github.com/bitcoin/bitcoin/pull/7415) for an example.
* Update [`BLOCK_CHAIN_SIZE` and `CHAIN_STATE_SIZE`](../src/qt/intro.cpp) to the current size plus some overhead.
* Update `src/chainparams.cpp` chainTxData with statistics about the transaction count and rate.

### First time / New builders


    git clone https://github.com/NeuraiProject/Neurai.git

### Neurai maintainers/release engineers, suggestion for writing release notes

Write release notes. git shortlog helps a lot, for example:

    git shortlog --no-merges v(current version, e.g. 0.7.2)..v(new version, e.g. 0.8.0)

Generate list of authors:

    git log --format='%aN' "$*" | sort -ui | sed -e 's/^/- /'

Tag version (or release candidate) in git

    git tag -s v(new version, e.g. 0.8.0)


### Build binaries.

Release binaries are built with the depends system. The CI workflow
([build-neurai.yml](../.github/workflows/build-neurai.yml)) builds `windows`,
`linux`, `linux-disable-wallet` and `osx` (`x86_64` and `arm64`) with the
scripts in [`.github/scripts/`](../.github/scripts/): `00-install-deps.sh <os>`,
then `02`…`06` (copy dependencies, export paths, configure and build, binary
checks, package). The macOS stages use `contrib/mac-cross`; see
[build-osx.md](build-osx.md). See also [build-docker.md](build-docker.md).


Codesigner only: Create Windows detached signatures:
- Only one person handles codesigning. Everyone else should skip to the next step.
- Only sign builds that other builders have reproduced and confirmed.

macOS packages are not signed with an Apple Developer certificate or
notarized (the ARM64 linker signature is ad-hoc); see [build-osx.md](build-osx.md).

Codesigner only: Sign the windows binaries:

    tar xf neurai-${VERSION}-win64-unsigned.tar.gz
    ./detached-sig-create.sh -key /path/to/codesign.key   # contrib/windeploy/detached-sig-create.sh
    Enter the passphrase for the key when prompted
    signature-win.tar.gz will be created

### After binaries are built:

- Create `SHA256SUMS.asc` for the builds, and GPG-sign it:

```bash
sha256sum * > SHA256SUMS
```

The list of files should be:
```
neurai-${VERSION}-x86_64-linux-gnu.tar.gz
neurai-${VERSION}-macos-x86_64.tar.gz
neurai-${VERSION}-macos-x86_64-unsigned.zip
neurai-${VERSION}-macos-arm64.tar.gz
neurai-${VERSION}-macos-arm64-unsigned.zip
neurai-${VERSION}-win64-setup.exe
neurai-${VERSION}-win64.zip
```

- GPG-sign it, delete the unsigned file:
```
gpg --digest-algo sha256 --clearsign SHA256SUMS # outputs SHA256SUMS.asc
rm SHA256SUMS
```
(the digest algorithm is forced to sha256 to avoid confusion of the `Hash:` header that GPG adds with the SHA256 used for the files)
Note: check that SHA256SUMS itself doesn't end up in SHA256SUMS, which is a spurious/nonsensical entry.

- Upload zips and installers, as well as `SHA256SUMS.asc` from last step, to the github-release page.

- Update neurai.org version

- Announce the release:

  - Optionally twitter, reddit /r/Neurai, ... but this will usually sort out itself

  - Archive release notes for the new version to `doc/release-notes/` (main branch and branch of the release)

  - Create a [new GitHub release](https://github.com/NeuraiProject/Neurai/releases/new) with a link to the archived release notes.

  - Celebrate
