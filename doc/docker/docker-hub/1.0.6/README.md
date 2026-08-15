# Neurai node v1.0.6 for Docker Hub

This directory builds the image published as `neuraiproject/neurai-node:v1.0.6`.
It reuses the standalone node definition from `../../node/` (same entrypoint and
configuration surface), pinned to the `1.0.6` release tag and with two
publication-oriented changes: the binaries are stripped and the runtime stage
uses `debian:11-slim`, which together keep the pushed image small.

The build clones the official Neurai repository; it does not use the parent
working tree. The image is `linux/amd64` only, because `depends` is built with
`HOST=x86_64-pc-linux-gnu`.

## Build and publish

Run from this directory:

```bash
docker build -t neuraiproject/neurai-node:v1.0.6 .

# Smoke test before pushing.
docker run --rm neuraiproject/neurai-node:v1.0.6 -version

docker login -u neuraiproject
docker push neuraiproject/neurai-node:v1.0.6

# Optionally move the floating tag to this release.
docker tag neuraiproject/neurai-node:v1.0.6 neuraiproject/neurai-node:latest
docker push neuraiproject/neurai-node:latest
```

`docker login` should use a Docker Hub access token with write access to the
`neuraiproject` organization, not the account password.

## Run the published image

Without cloning anything:

```bash
docker volume create neurai-data
docker run -d --name neurai-node --restart unless-stopped \
  --stop-timeout 300 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 19000:19000 \
  -v neurai-data:/data \
  neuraiproject/neurai-node:v1.0.6
```

`--stop-timeout 300` gives `neuraid` time to flush its databases on shutdown
instead of being killed after the 10-second default, and the log options rotate
the container log so it cannot grow unbounded.

Or with Compose, using the example in this directory:

```bash
cp .env.example .env
docker compose up -d
```

The Compose file already applies the same protections: rotated container logs,
a five-minute stop grace period, a raised open-file limit, and a health check
based on `neurai-cli getblockchaininfo` (visible in `docker compose ps`).

`/data` persists the blockchain, wallet data, RPC cookie, and `neurai.conf`.
The entrypoint generates `neurai.conf` only when the volume does not already
contain one, so environment variables apply on the first start; afterwards,
edit the persisted `/data/neurai.conf` and restart the container.

## Configuration

The full option list is documented in `../../node/README.md` and shown in
`.env.example`. In short:

- Indexes: `NEURAI_TXINDEX`, `NEURAI_ASSETINDEX`, `NEURAI_ADDRESSINDEX`,
  `NEURAI_TIMESTAMPINDEX`, `NEURAI_SPENTINDEX` (reindexing rules noted in
  `.env.example`).
- Wallet: `NEURAI_DISABLE_WALLET`, `NEURAI_WALLET_FILE`,
  `NEURAI_WALLET_BROADCAST`, `NEURAI_WALLET_RBF`.
- RPC: `NEURAI_RPC_PORT`, `NEURAI_RPC_BIND`, `NEURAI_RPC_ALLOW_IP`,
  `NEURAI_RPC_USER`/`NEURAI_RPC_PASSWORD` (cookie auth when empty).
- ZMQ publishers: `NEURAI_ZMQ_PUB_*`, disabled while empty.
- Resources: `NEURAI_DB_CACHE`, `NEURAI_MAX_CONNECTIONS`, `NEURAI_PRUNE`,
  `NEURAI_MAX_MEMPOOL`, `NEURAI_SCRIPT_THREADS`.
- Anything else: `NEURAI_EXTRA_CONF` (newline-separated `neurai.conf` lines),
  or pass daemon flags directly after the image name, e.g.
  `docker run ... neuraiproject/neurai-node:v1.0.6 -reindex`.

Example indexer node with wallet and RPC reachable from a private network:

```bash
docker run -d --name neurai-node --restart unless-stopped \
  --stop-timeout 300 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 19000:19000 -p 19001:19001 \
  -v neurai-data:/data \
  -e NEURAI_TXINDEX=1 -e NEURAI_ASSETINDEX=1 -e NEURAI_ADDRESSINDEX=1 \
  -e NEURAI_RPC_BIND=0.0.0.0 -e NEURAI_RPC_ALLOW_IP=172.16.0.0/12 \
  -e NEURAI_RPC_USER=user -e NEURAI_RPC_PASSWORD=change-me \
  neuraiproject/neurai-node:v1.0.6
```

P2P port `19000` is intended to be public. Keep RPC/REST (`19001`) and ZMQ
private unless authentication and network access controls are explicitly
configured.
