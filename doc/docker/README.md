Neurai - Docker
==============

Dockerfiles and helpers to build Neurai binaries or run a node in containers.
For the images listed below, run `docker build` from the repository root. See
[../build-docker.md](../build-docker.md) for a step-by-step guide.

For release binaries with a selectable branch, `user`/`server` profiles, and
automatic extraction to `create-bin/tests/output`, see [create-bin/README.md](create-bin/README.md).
Those Linux, Windows and macOS builds use `doc/docker/create-bin` as their build context.

Images
---------------------

| File | Base | Source built | Output |
|---|---|---|---|
| `Dockerfile-Linux64-bin-v2` | Debian 12 | clones the `DePIN-Test` branch from GitHub | neuraid, neurai-cli, neurai-tx, neurai-qt and tests (depends, Qt 6) |
| `Dockerfile-Linux64-qc` | Debian 12 | local checkout (`COPY .`) | multi-stage; runtime image with neuraid, neurai-cli, neurai-tx, neurai-qt |
| `Dockerfile-Linux64-qc-depin-testnet` | Debian 12 | local checkout | headless neuraid and neurai-cli (`NO_QT=1`) |
| `Dockerfile-Linux64-qc-depin-testnet-qt` | Debian 12 | local checkout | neuraid, neurai-cli, neurai-tx, neurai-qt |
| `Dockerfile-Win64-bin-v2` | Ubuntu 24.04 | clones the `DePIN-Test` branch from GitHub | Windows x86_64 neuraid, neurai-cli, neurai-qt (same steps as the CI `windows` job; no neurai-tx) |

The images that clone from GitHub ignore local changes; use the `qc` images
to build the working tree.

Helpers
---------------------

- `extract-linux64-binaries.sh [image] [output-dir]` copies neuraid,
  neurai-cli, neurai-tx and neurai-qt out of an image (default image
  `neurai-linux64-bin`, default output `./artifacts/linux64`).

Default ports
---------------------

| Network | P2P | RPC |
|---|---|---|
| mainnet | 19000 | 19001 |
| testnet | 19100 | 19101 |
| regtest | 19200 | 19201 |
