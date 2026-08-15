# Neurai Linux node

This image clones and builds the official Neurai repository at the `1.0.6` tag.
It does not use the parent working tree, so build it using this directory as its
context:

```bash
docker build -t neurai-node:local doc/docker/node
```

Run a persistent mainnet node:

```bash
docker volume create neurai-data
docker run -d --name neurai-node --restart unless-stopped \
  --stop-timeout 300 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 19000:19000 \
  -v neurai-data:/data \
  neurai-node:local
```

`--stop-timeout 300` gives `neuraid` time to flush its databases on shutdown
instead of being killed after the 10-second default, and the log options rotate
the container log so it cannot grow unbounded.

`/data` is the persistent volume and contains the blockchain, wallet data, RPC
cookie, and `neurai.conf`. The entrypoint creates `neurai.conf` only when it is
missing; it never overwrites an existing configuration.

On the first start, environment variables configure the generated file. This
includes wallet options (`NEURAI_DISABLE_WALLET`, `NEURAI_WALLET_FILE`), indexes
(`NEURAI_TXINDEX`, `NEURAI_ASSETINDEX`, `NEURAI_ADDRESSINDEX`,
`NEURAI_TIMESTAMPINDEX`, `NEURAI_SPENTINDEX`), RPC settings
(`NEURAI_RPC_PORT`, `NEURAI_RPC_BIND`, `NEURAI_RPC_ALLOW_IP`,
`NEURAI_RPC_THREADS`, `NEURAI_RPC_WORK_QUEUE`), and resource settings
(`NEURAI_DB_CACHE`, `NEURAI_SCRIPT_THREADS`, `NEURAI_MAX_MEMPOOL`).
`NEURAI_EXTRA_CONF` accepts newline-separated `neurai.conf` entries. To change
an existing node, edit `/data/neurai.conf` and restart the container. Index
changes require the appropriate reindexing procedure.

ZMQ is available through `NEURAI_ZMQ_PUB_HASH_BLOCK`,
`NEURAI_ZMQ_PUB_HASH_TX`, `NEURAI_ZMQ_PUB_RAW_BLOCK`,
`NEURAI_ZMQ_PUB_RAW_TX`, and `NEURAI_ZMQ_PUB_RAW_MESSAGE`. They are disabled
by default. For a trusted service in the same Docker network, use an endpoint
such as `tcp://0.0.0.0:28332`; the subscriber connects to the node service on
that port. Do not publish a ZMQ TCP port to an untrusted network.

The image exposes P2P port `19000` and RPC/REST port `19001`. The example only
publishes P2P. Keep RPC private unless you configure strong authentication and a
trusted network allowlist.
