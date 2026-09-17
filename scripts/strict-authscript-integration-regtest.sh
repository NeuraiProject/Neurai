#!/bin/bash
# Integration checks for the strict AuthScript families and NIP-041 on regtest:
#   1. a block with a strict-prefixed asset output below the activation height is rejected;
#   2. full blocks validate identically with 1, 4 and 8 script-check threads, through
#      normal relay, level-4 startup verification, reindex and initial sync;
#   3. compact blocks carrying strict outputs are reconstructed from the mempool.
# Host-side wrapper: node phases run inside the build container, the covenant driver
# (scripts/strict-authscript-covenant-regtest.mjs) runs in a Node container that shares
# its network namespace.
# Usage: bash scripts/strict-authscript-integration-regtest.sh [path-to-neurai-scripts]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LIBS="${1:-/home/mark/src/AAA-experimento/librerias-neurai/neurai-scripts}"
NODE_IMAGE="${NODE_IMAGE:-node:20-bookworm}"
C="${BUILD_CONTAINER:-neurai-strict}"
INNER=/src/scripts/strict-authscript-integration-inner.sh
RC=0
docker exec "$C" bash -c "pkill -9 neuraid; sleep 1; true"
echo "=== phase 1: strict asset output below the activation height"
docker exec "$C" bash "$INNER" phase1 || RC=1
echo "=== phase 2a: blocks across the activation height, 1 vs 8 script threads"
docker exec "$C" bash "$INNER" phase2a || RC=1
echo "=== phase 2 (covenants): NIP-041 contract spends mined by the 1-thread node"
docker run --rm --network "container:$C" -e RPC_URL=http://127.0.0.1:18541 \
  -v "$LIBS":/libs/neurai-scripts:ro -v "$HERE":/s:ro "$NODE_IMAGE" node /s/strict-authscript-covenant-regtest.mjs | grep "^PASS\|^FAIL\|^RESULT" || RC=1
echo "=== phase 2b: agreement, compact blocks, deep verification, reindex, initial sync"
docker exec "$C" bash "$INNER" phase2b || RC=1
docker exec "$C" bash -c "pkill -9 neuraid; true"
[ "$RC" -eq 0 ] && echo "INTEGRATION RESULT: OK" || echo "INTEGRATION RESULT: FAILURES"
exit $RC
