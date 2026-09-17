#!/bin/bash
# NIP-041 covenant example on regtest. Host-side wrapper:
#   - starts a disposable regtest node inside the build container (neurai-strict)
#   - runs the JS driver in a Node container sharing that container's network
# Usage: bash scripts/strict-authscript-covenant-regtest.sh [path-to-neurai-scripts]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LIBS="${1:-/home/mark/src/AAA-experimento/librerias-neurai/neurai-scripts}"
NODE_IMAGE="${NODE_IMAGE:-node:20-bookworm}"
BUILD_CONTAINER="${BUILD_CONTAINER:-neurai-strict}"
BASE=/tmp/strict-covenant

docker exec "$BUILD_CONTAINER" bash -c "pkill -9 neuraid; sleep 1; rm -rf $BASE; mkdir -p $BASE; /root/Neurai/src/neuraid -regtest -server -listen=0 -txindex=1 -fallbackfee=0.001 -printtoconsole=0 -rpcuser=u -rpcpassword=p -rpcport=18521 -datadir=$BASE -daemon >/dev/null; for i in \$(seq 1 120); do /root/Neurai/src/neurai-cli -regtest -datadir=$BASE -rpcport=18521 -rpcuser=u -rpcpassword=p getblockcount >/dev/null 2>&1 && break; sleep 1; done"

docker run --rm --network "container:$BUILD_CONTAINER" \
  -v "$LIBS":/libs/neurai-scripts:ro -v "$HERE":/s:ro \
  "$NODE_IMAGE" node /s/strict-authscript-covenant-regtest.mjs
RC=$?
docker exec "$BUILD_CONTAINER" bash -c "/root/Neurai/src/neurai-cli -regtest -datadir=$BASE -rpcport=18521 -rpcuser=u -rpcpassword=p stop >/dev/null 2>&1"
exit $RC
