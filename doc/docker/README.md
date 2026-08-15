# Neurai Docker Guide

This directory contains Docker workflows for building Neurai binaries and
running a persistent Linux node.

## Requirements

- Docker Engine 24 or newer with BuildKit enabled.
- Docker Compose v2 for `compose-node/`.
- Internet access while building: node images clone the official Neurai repository
  and build dependencies are downloaded by `depends/`.
- Several GB of free disk space and enough RAM for a C++ build. A Linux host is
  recommended for the Linux build and node images.

Run all commands below from the repository root unless stated otherwise.

## Build binary artifacts

`bin/` contains Dockerfiles that build the local checkout and export artifacts
directly to the host:

```bash
docker build -f doc/docker/bin/Dockerfile-Linux64-bin \
  --target artifacts --output type=local,dest=build-out/linux64 .

docker build -f doc/docker/bin/Dockerfile-Win64-bin \
  --target artifacts --output type=local,dest=build-out/win64 .
```

The Linux output contains `neuraid`, `neurai-cli`, and `neurai-qt`. The Windows
output contains their `.exe` equivalents. The headless Linux build is available
through `bin/Dockerfile-Node-Linux` and writes to `build-out/node-linux`.

## Run a standalone Linux node

`node/` builds from the official Neurai repository and stores all runtime data
in `/data`:

```bash
docker build -t neurai-node:local doc/docker/node
docker volume create neurai-data
docker run -d --name neurai-node --restart unless-stopped \
  --stop-timeout 300 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 19000:19000 \
  -v neurai-data:/data \
  neurai-node:local
```

`--stop-timeout` gives `neuraid` time to flush its databases on shutdown, and
the log options rotate the container log so it cannot grow unbounded.

The volume persists the blockchain, wallet data, RPC cookie, and `neurai.conf`.
The configuration file is generated only when it does not already exist, so
environment settings apply on the first start of a volume. For a reproducible
build, override the default `1.0.6` release tag with another tag or branch:

```bash
docker build --build-arg NEURAI_REF=<tag-or-branch> \
  -t neurai-node:local doc/docker/node
```

P2P port `19000` is intended to be public. RPC/REST (`19001`) and ZMQ should
remain private unless authentication and network access controls are explicitly
configured.

## Run with Docker Compose

`compose-node/` is self-contained and includes a copy of the standalone node
definition:

```bash
cd doc/docker/compose-node
cp .env.example .env
docker compose up -d --build
```

Edit `.env` before the first start to select the source ref, enable indexes, or
configure optional ZMQ publishers. For example, a trusted service on the same
Compose network can subscribe to:

```env
NEURAI_ZMQ_PUB_RAW_TX=tcp://0.0.0.0:28332
```

It can then connect to `tcp://neurai:28332`. ZMQ has no authentication; do not
publish that port to an untrusted network.

## Publish a release to Docker Hub

`docker-hub/` contains one directory per published release. Each is
self-contained, pins the release tag, and produces the image pushed to the
`neuraiproject/neurai-node` repository:

```bash
cd doc/docker/docker-hub/1.0.6
docker build -t neuraiproject/neurai-node:v1.0.6 .
docker push neuraiproject/neurai-node:v1.0.6
```

See `docker-hub/1.0.6/README.md` for the full publish checklist and a Compose
example that runs the published image without building anything locally.

## Check status and logs

Standalone node:

```bash
docker ps --filter name=neurai-node
docker logs --tail 100 -f neurai-node
docker inspect neurai-node
```

Compose node, from `doc/docker/compose-node`:

```bash
docker compose ps
docker compose logs --tail 100 -f neurai
docker compose exec neurai neurai-cli -datadir=/data getblockchaininfo
```

## Stop, remove, and clean up

Stopping or removing a container does not remove its named volume:

```bash
docker stop neurai-node
docker rm neurai-node

# Or, from compose-node:
docker compose down
```

To delete all node data permanently, remove the volume explicitly. This cannot
be undone:

```bash
docker volume rm neurai-data

# Compose uses this project-scoped volume name by default:
docker compose down -v
```

Remove a locally built image only when it is no longer needed:

```bash
docker rmi neurai-node:local
```
