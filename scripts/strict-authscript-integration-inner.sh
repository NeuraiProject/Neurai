#!/bin/bash
# Container-side phases of scripts/strict-authscript-integration-regtest.sh.
# Usage: strict-authscript-integration-inner.sh <phase1|phase2a|phase2b>
set -u
BIN=/root/Neurai/src
BASE=/tmp/strict-integ
STATE=$BASE/state
ACT=120
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3 (got '$1', want '$2')"; fi; }
jget() { local code=$1; shift; python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$code" "$@"; }
COMMON="-regtest -server -txindex=1 -addressindex=1 -assetindex=1 -fallbackfee=0.001 -printtoconsole=0 -rpcuser=u -rpcpassword=p -keypool=3"
cli() { local name=$1 port=$2; shift 2; "$BIN/neurai-cli" -regtest -datadir="$BASE/$name" -rpcport="$port" -rpcuser=u -rpcpassword=p "$@"; }
waitrpc() { for i in $(seq 1 180); do if cli "$1" "$2" getblockcount >/dev/null 2>&1; then return 0; fi; sleep 1; done; echo "node $1 did not start"; tail -5 "$BASE/$1/regtest/debug.log"; exit 1; }
stopnode() { cli "$1" "$2" stop >/dev/null 2>&1; for i in $(seq 1 60); do pgrep -f "datadir=$BASE/$1 " >/dev/null || return 0; sleep 1; done; pkill -9 -f "datadir=$BASE/$1 "; }
finish() { echo "PHASE RESULT: PASS=$PASS FAIL=$FAIL"; [ "$FAIL" -eq 0 ]; }

# ---------------------------------------------------------------------------------
# Phase 1: a block carrying a strict-prefixed ASSET output below the activation
# height must be rejected. Node M has the families active from genesis and mines
# it; node V activates at $ACT and receives M's blocks one by one via submitblock.
phase1() {
  rm -rf "$BASE"; mkdir -p "$BASE/M" "$BASE/V" "$STATE"
  M() { cli M 18531 "$@"; }; V() { cli V 18532 "$@"; }
  "$BIN/neuraid" $COMMON -listen=0 -connect=0 -datadir="$BASE/M" -rpcport=18531 -daemon >/dev/null
  "$BIN/neuraid" $COMMON -listen=0 -connect=0 -datadir="$BASE/V" -rpcport=18532 -strictauthscriptheight=$ACT -daemon >/dev/null
  waitrpc M 18531; waitrpc V 18532

  local miner; miner=$(M getnewaddress)
  M generatetoaddress 110 "$miner" >/dev/null
  local strict; strict=$(M getnewaddress "" ecdsa)
  M sendtoaddress "$strict" 5 >/dev/null
  M generatetoaddress 1 "$miner" >/dev/null
  local hCoin; hCoin=$(M getblockcount)                 # strict COIN output: consensus-permissive below activation
  M issue INTEG 1000 >/dev/null
  M generatetoaddress 1 "$miner" >/dev/null
  M transfer INTEG 10 "$strict" >/dev/null
  M generatetoaddress 1 "$miner" >/dev/null
  local hAsset; hAsset=$(M getblockcount)               # strict ASSET output: invalid below activation
  M generatetoaddress 2 "$miner" >/dev/null
  local tipM; tipM=$(M getblockcount)
  check "$([ "$hAsset" -lt "$ACT" ] && echo below)" "below" "the strict asset block (height $hAsset) is below V's activation height $ACT"

  local h res reject=""
  for h in $(seq 1 "$tipM"); do
    res=$(V submitblock "$(M getblock "$(M getblockhash "$h")" 0)" 2>&1)
    if [ -n "$res" ] && [ "$res" != "null" ] && [ -z "$reject" ]; then reject="$h:$res"; fi
  done
  echo "  first rejection reported by V: ${reject:-none}"
  check "$(V getblockcount)" "$((hAsset-1))" "V stops right before the block with the strict asset output"
  check "$([ "$(V getblockcount)" -ge "$hCoin" ] && echo accepted)" "accepted" "V accepted the earlier block with a strict COIN output (permissive below activation)"
  check "${reject%%:*}" "$hAsset" "the first block V rejected is the strict asset block"
  case "$reject" in *asset*|*xna*|*bad-txns*) ok "rejection reason names the asset rule (${reject#*:})";; *) bad "unexpected rejection reason (${reject#*:})";; esac
  check "$(V getblockhash $((hAsset-1)))" "$(M getblockhash $((hAsset-1)))" "V and M agree on the chain up to the last valid block"
  stopnode M 18531; stopnode V 18532
  finish
}

# ---------------------------------------------------------------------------------
# Phase 2a: two connected nodes, same activation height. N1 = PQ wallet, 1 script
# thread. N2 = classic wallet, 8 script threads, compact-block logging.
startN1() { "$BIN/neuraid" $COMMON -listen=1 -port=18641 -datadir="$BASE/N1" -rpcport=18541 -pqwallet=1 -par=1 -strictauthscriptheight=$ACT "$@" -daemon >/dev/null; }
startN2() { "$BIN/neuraid" $COMMON -listen=1 -port=18642 -datadir="$BASE/N2" -rpcport=18542 -par=8 -debug=cmpctblock -connect=127.0.0.1:18641 -strictauthscriptheight=$ACT "$@" -daemon >/dev/null; }
N1() { cli N1 18541 "$@"; }; N2() { cli N2 18542 "$@"; }
syncmempool() { for i in $(seq 1 40); do
  local missing; missing=$(python3 -c 'import json,sys; a=set(json.loads(sys.argv[1])); b=set(json.loads(sys.argv[2])); print(len(a^b))' "$(N1 getrawmempool)" "$(N2 getrawmempool)")
  [ "$missing" = "0" ] && return 0; sleep 1; done; echo "  (mempool sync timeout)"; }
syncblocks() { for i in $(seq 1 120); do [ "$(N1 getbestblockhash)" = "$(N2 getbestblockhash)" ] && return 0; sleep 1; done; return 1; }
mine() { syncmempool; N1 generatetoaddress "$1" "$(cat $STATE/n1_miner)" >/dev/null; syncblocks; }

phase2a() {
  mkdir -p "$BASE/N1" "$BASE/N2" "$STATE"
  startN1; waitrpc N1 18541; startN2; waitrpc N2 18542
  N1 getnewaddress > $STATE/n1_miner
  N1 generatetoaddress $((ACT-1)) "$(cat $STATE/n1_miner)" >/dev/null; syncblocks
  check "$(N2 getblockcount)" "$((ACT-1))" "both nodes at the last inactive height"
  local A_PQ A_EC B_EC B_LEG
  A_PQ=$(N1 getnewaddress "" pq); A_EC=$(N1 getnewaddress "" ecdsa); B_EC=$(N2 getnewaddress "" ecdsa); B_LEG=$(N2 getnewaddress)
  echo "$A_PQ" > $STATE/a_pq; echo "$A_EC" > $STATE/a_ec; echo "$B_EC" > $STATE/b_ec; echo "$B_LEG" > $STATE/b_leg
  # Block $ACT, the first active one: strict coin outputs and a strict asset issuance, relayed first.
  N1 sendtoaddress "$A_PQ" 20 >/dev/null; N1 sendtoaddress "$A_EC" 20 >/dev/null; N1 sendtoaddress "$B_EC" 20 >/dev/null; N1 sendtoaddress "$B_LEG" 500 >/dev/null
  N1 issue INTEG2 1000 "$A_EC" >/dev/null && ok "asset issued to a strict ECDSA address for the first active block" || bad "issue to strict address failed"
  mine 1
  check "$(N2 getblockcount)" "$ACT" "N2 (8 script threads) accepted the first active block"
  # Blocks above: strict spends (4-item witnesses), asset moves between strict families, multi-input txs.
  local i
  for i in 1 2 3; do N1 sendtoaddress "$B_LEG" 15 >/dev/null; N1 sendtoaddress "$A_PQ" 7 >/dev/null; N2 sendtoaddress "$A_EC" 3 >/dev/null; done
  N1 transfer INTEG2 50 "$A_PQ" >/dev/null; mine 1
  N1 transfer INTEG2 20 "$B_EC" >/dev/null; mine 1
  N2 transfer INTEG2 5 "$A_PQ" >/dev/null && ok "classic wallet moved the asset out of its strict ECDSA address" || bad "asset transfer from N2 strict address failed"
  mine 2
  check "$(N2 listmyassets | jget '"%.1f" % float(d.get("INTEG2", 0))')" "15.0" "asset balances agree on the 8-thread node"
  echo "$(N1 getblockcount)" > $STATE/height_before_js
  finish
}

# Phase 2b: after the JS covenant driver ran against N1.
phase2b() {
  syncblocks && ok "N2 followed every block of the covenant run" || bad "N2 did not reach N1's tip"
  local tip height; tip=$(N1 getbestblockhash); height=$(N1 getblockcount)
  check "$([ "$height" -gt "$(cat $STATE/height_before_js)" ] && echo grew)" "grew" "covenant run added blocks with OP_OUTPUTAUTHDEST / selector 0x04 spends (tip $height)"
  check "$(N2 getbestblockhash)" "$tip" "1-thread and 8-thread nodes agree on the tip"

  local log="$BASE/N2/regtest/debug.log" rec recmp
  rec=$(grep -c "Successfully reconstructed block" "$log")
  recmp=$(grep "Successfully reconstructed block" "$log" | python3 -c 'import sys,re; print(sum(1 for l in sys.stdin if int(re.search(r"(\d+) txn from mempool", l).group(1)) > 0))')
  check "$([ "$rec" -gt 0 ] && echo yes)" "yes" "N2 reconstructed compact blocks ($rec)"
  check "$([ "$recmp" -gt 0 ] && echo yes)" "yes" "compact blocks rebuilt with transactions taken from the mempool ($recmp)"
  local hashAct; hashAct=$(N1 getblockhash $ACT)
  check "$(grep "Successfully reconstructed block $hashAct" "$log" | wc -l | tr -d ' ')" "1" "the first active block (strict asset issuance inside) arrived as a compact block"

  echo "== deep startup verification on the 8-thread node (-checklevel=4 -checkblocks=0: disconnects and reconnects across the activation height)"
  stopnode N2 18542; startN2 -checklevel=4 -checkblocks=0; waitrpc N2 18542
  check "$(N2 getbestblockhash)" "$tip" "tip unchanged after level-4 verification of the whole chain"
  echo "== full reindex with 8 script threads"
  stopnode N2 18542; startN2 -reindex; waitrpc N2 18542
  for i in $(seq 1 180); do [ "$(N2 getblockcount 2>/dev/null)" = "$height" ] && break; sleep 1; done
  check "$(N2 getbestblockhash)" "$tip" "8-thread reindex reproduces the same tip"
  check "$(N2 listmyassets | jget '"%.1f" % float(d.get("INTEG2", 0))')" "15.0" "asset state identical after the reindex"
  echo "== chainstate reindex with 1 script thread"
  stopnode N1 18541; startN1 -reindex-chainstate; waitrpc N1 18541
  for i in $(seq 1 180); do [ "$(N1 getblockcount 2>/dev/null)" = "$height" ] && break; sleep 1; done
  check "$(N1 getbestblockhash)" "$tip" "1-thread chainstate reindex reproduces the same tip"
  echo "== fresh node, 4 script threads, initial sync from scratch"
  mkdir -p "$BASE/N3"
  "$BIN/neuraid" $COMMON -listen=0 -datadir="$BASE/N3" -rpcport=18543 -par=4 -connect=127.0.0.1:18641 -strictauthscriptheight=$ACT -daemon >/dev/null
  waitrpc N3 18543
  for i in $(seq 1 180); do [ "$(cli N3 18543 getbestblockhash 2>/dev/null)" = "$tip" ] && break; sleep 1; done
  check "$(cli N3 18543 getbestblockhash)" "$tip" "fresh 4-thread node syncs to the same tip"
  stopnode N3 18543; stopnode N2 18542; stopnode N1 18541
  finish
}

case "${1:-}" in phase1) phase1;; phase2a) phase2a;; phase2b) phase2b;; *) echo "usage: $0 phase1|phase2a|phase2b"; exit 2;; esac
