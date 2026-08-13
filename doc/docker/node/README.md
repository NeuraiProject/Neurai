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
  -p 19000:19000 \
  -v neurai-data:/data \
  neurai-node:local
```

`/data` is the persistent volume and contains the blockchain, wallet data, RPC
cookie, and `neurai.conf`. The entrypoint creates `neurai.conf` only when it is
missing; it never overwrites an existing configuration.

On the first start, the following environment variables configure the generated
file: `NEURAI_TXINDEX`, `NEURAI_ASSETINDEX`, `NEURAI_ADDRESSINDEX`,
`NEURAI_TIMESTAMPINDEX`, `NEURAI_REST`, `NEURAI_PRUNE`,
`NEURAI_MAX_CONNECTIONS`, `NEURAI_RPC_USER`, `NEURAI_RPC_PASSWORD`, and
`NEURAI_EXTRA_CONF`. `NEURAI_EXTRA_CONF` accepts newline-separated `neurai.conf`
entries. To change a running node's configuration later, edit `/data/neurai.conf`
and restart the container.

ZMQ is available through `NEURAI_ZMQ_PUB_HASH_BLOCK`,
`NEURAI_ZMQ_PUB_HASH_TX`, `NEURAI_ZMQ_PUB_RAW_BLOCK`,
`NEURAI_ZMQ_PUB_RAW_TX`, and `NEURAI_ZMQ_PUB_RAW_MESSAGE`. They are disabled
by default. For a trusted service in the same Docker network, use an endpoint
such as `tcp://0.0.0.0:28332`; the subscriber connects to the node service on
that port. Do not publish a ZMQ TCP port to an untrusted network.

The image exposes P2P port `19000` and RPC/REST port `19001`. The example only
publishes P2P. Keep RPC private unless you configure strong authentication and a
trusted network allowlist.
