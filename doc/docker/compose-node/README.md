# Neurai node with Docker Compose

This directory is self-contained: `node/` is a copy of the standalone node
image definition and builds from the official Neurai Git repository.

```bash
cd doc/docker/compose-node
cp .env.example .env
docker compose up -d --build
```

The named `neurai-data` volume persists the blockchain, wallet data, RPC cookie,
and `neurai.conf`. Stop or recreate the service without `-v` to preserve it.

Only P2P port `19000` is published. RPC stays inside the Compose network by
default; do not add a public `19001` mapping unless authentication and
`rpcallowip` are deliberately configured.

The environment values in `.env` initialize `neurai.conf` only on the first
start of a volume. For later changes, edit the persisted configuration and run
`docker compose restart`. The example includes wallet, RPC, index, cache,
script-thread, mempool, and ZMQ settings. Wallet support is enabled by default.

Changing index settings after syncing is not immediate: `assetindex` requires
`-reindex`, while address, spent, and timestamp indexes require
`-reindex-chainstate`. Do not enable `prune` together with `txindex`.

ZMQ publishers can be enabled at first start with the `NEURAI_ZMQ_PUB_*`
variables in `.env`. For example, `NEURAI_ZMQ_PUB_RAW_TX=tcp://0.0.0.0:28332`
makes the publisher reachable to trusted services on the same Compose network
as `tcp://neurai:28332`. ZMQ has no authentication, so keep it private unless a
separate network control exists.
