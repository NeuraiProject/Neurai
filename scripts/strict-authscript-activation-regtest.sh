#!/bin/bash
# Regtest exercise of the height-based activation of the strict AuthScript
# families (witness v2 PQ, v3 ECDSA), including a reorganisation across the
# activation height. Runs inside the Docker build container.
# Node A: PQ wallet, -strictauthscriptheight=120.
# Node F: address factory with the default regtest activation (height 0), never
#         connected to A; it only produces strict address strings.
set -u
BIN=/root/Neurai/src
BASE=/tmp/strict-activation
ACT=120
rm -rf "$BASE"; mkdir -p "$BASE/A" "$BASE/F"
COMMON="-regtest -server -listen=0 -txindex=1 -fallbackfee=0.001 -printtoconsole=0 -rpcuser=u -rpcpassword=p -keypool=3"
A() { "$BIN/neurai-cli" -regtest -datadir="$BASE/A" -rpcport=18511 -rpcuser=u -rpcpassword=p "$@"; }
F() { "$BIN/neurai-cli" -regtest -datadir="$BASE/F" -rpcport=18512 -rpcuser=u -rpcpassword=p "$@"; }
startA() { "$BIN/neuraid" $COMMON -datadir="$BASE/A" -rpcport=18511 -addresstype=pq -strictauthscriptheight=$ACT -daemon >/dev/null; }
startF() { "$BIN/neuraid" $COMMON -datadir="$BASE/F" -rpcport=18512 -daemon >/dev/null; }
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3 (got '$1', want '$2')"; fi; }
jget() { local code=$1; shift; python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$code" "$@"; }
waitrpc() { for i in $(seq 1 120); do if "$@" getblockcount >/dev/null 2>&1; then return 0; fi; sleep 1; done; echo "node did not start"; exit 1; }
mine() { A generatetoaddress "$1" "$A_LEG" >/dev/null; }
inmempool() { A getrawmempool | jget 'sys.argv[2] in d' "$1"; }

echo "== start"
startA; waitrpc A
startF; waitrpc F
# Below activation a PQ wallet hands out strict v2 addresses, but nothing can
# pay to them until then (and generic v1 is a contract family it never
# manages), so its funds come from a Legacy key made by F and imported into A.
A_LEG=$(F getnewaddress)
A importprivkey "$(F dumpprivkey "$A_LEG")" "" false
ALT_LEG=$(F getnewaddress)   # coinbase address for the alternative branch (makes its blocks differ)
F_EC=$(F getnewaddress "" ecdsa)          # a syntactically valid strict ECDSA address
check "${F_EC:0:5}" "tnq1r" "factory node (activation height 0) produces strict addresses"

echo "== below activation (tip 110, next block 111 < $ACT)"
mine 110
check "$(A getblockcount)" "110" "tip height"
# Addresses are handed out below activation; paying to them is what is refused.
A_EARLY_PQ=$(A getnewaddress "" pq 2>&1)
A_EARLY_EC=$(A getnewaddress "" ecdsa 2>&1)
check "${A_EARLY_PQ:0:5}" "tpq1z" "strict PQ address handed out below activation"
check "${A_EARLY_EC:0:5}" "tnq1r" "strict ECDSA address handed out below activation"
if A sendtoaddress "$A_EARLY_PQ" 1 >/dev/null 2>&1; then bad "must not pay to the wallet's own strict address below activation"; else ok "sendtoaddress to its own strict address refused below activation"; fi
check "$(A validateaddress "$F_EC" | jget 'str(d["isvalid"])')" "False" "strict address is not decodable below activation"
if A sendtoaddress "$F_EC" 1 >/dev/null 2>&1; then bad "must not pay to a strict address below activation"; else ok "sendtoaddress to a strict address refused below activation"; fi
check "$(A getwalletinfo | jget 'str("keypoolsize_strict_ecdsa" in d)')" "False" "no strict ECDSA keypool below activation"

echo "== at the boundary (tip 119, next block $ACT is the first active one)"
mine 9
check "$(A getblockcount)" "119" "tip height"
A_PQ=$(A getnewaddress "" pq 2>&1)
A_EC=$(A getnewaddress "" ecdsa 2>&1)
check "${A_PQ:0:5}" "tpq1z" "strict PQ address available once the next block is active"
check "${A_EC:0:5}" "tnq1r" "strict ECDSA address available once the next block is active"
check "$(A validateaddress "$F_EC" | jget 'str(d["isvalid"])')" "True" "strict address decodable at the boundary"
# Raw funding with nLockTime 0: a wallet sendtoaddress sets nLockTime to the
# current height (anti fee-sniping), which would make the payment non-final
# after the reorg below and hide the mempool re-admission we want to observe.
fund_raw() {
  local raw; raw=$(A createrawtransaction "[]" "{\"$1\":10}")
  local funded; funded=$(A fundrawtransaction "$raw" | jget 'd["hex"]')
  A sendrawtransaction "$(A signrawtransaction "$funded" | jget 'd["hex"]')"
}
T_FUND_PQ=$(fund_raw "$A_PQ")
T_FUND_EC=$(fund_raw "$A_EC")
A_EC2=$(A getnewaddress "" ecdsa)
T_FUND_EC2=$(fund_raw "$A_EC2")           # spent later by a transaction left PENDING across the reorg
T_FUND_EARLY=$(fund_raw "$A_EARLY_EC")    # the address handed out below activation
mine 1
check "$(A getblockcount)" "$ACT" "tip is the activation block"
B_ACT=$(A getblockhash $ACT)
B_PREV=$(A getblockhash $((ACT-1)))
check "$(A getrawtransaction "$T_FUND_PQ" true | jget 'd["confirmations"]')" "1" "payment to strict PQ confirmed in the activation block"
check "$(A listunspent 1 9999 "[\"$A_EARLY_EC\"]" | jget 'str(len(d))')" "1" "address handed out below activation receives once active"

# spend_all ADDR DEST -> txid (explicit UTXO, whole amount minus fee)
spend_all() {
  local u; u=$(A listunspent 1 9999 "[\"$1\"]" | jget 'json.dumps(d[0])')
  local raw; raw=$(A createrawtransaction "[{\"txid\":\"$(echo "$u"|jget 'd["txid"]')\",\"vout\":$(echo "$u"|jget 'd["vout"]')}]" "{\"$2\":$(echo "$u" | jget '"%.8f" % (d["amount"]-0.05)')}")
  A sendrawtransaction "$(A signrawtransaction "$raw" | jget 'd["hex"]')"
}
T_SPEND_PQ=$(spend_all "$A_PQ" "$A_LEG")
T_SPEND_EC=$(spend_all "$A_EC" "$A_LEG")
mine 1
check "$(A getrawtransaction "$T_SPEND_PQ" true | jget 'd["confirmations"]')" "1" "strict PQ spend confirmed above activation"
check "$(A getrawtransaction "$T_SPEND_EC" true | jget 'd["confirmations"]')" "1" "strict ECDSA spend confirmed above activation"
# A strict spend that is only pending (never mined) when the reorg happens.
T_PENDING=$(spend_all "$A_EC2" "$A_LEG")
check "$(inmempool "$T_PENDING")" "True" "pending strict ECDSA spend admitted above activation"
TIP_BEFORE=$(A getbestblockhash)

echo "== reorganise below the activation height (invalidate block $((ACT-1)) -> tip $((ACT-2)))"
A invalidateblock "$B_PREV" >/dev/null
check "$(A getblockcount)" "$((ACT-2))" "tip went below activation"
if A sendtoaddress "$A_PQ" 1 >/dev/null 2>&1; then bad "strict payments must be refused again below activation"; else ok "sendtoaddress to a strict address refused again after the reorg"; fi
check "$(A validateaddress "$A_PQ" | jget 'str(d["isvalid"])')" "False" "strict address not decodable again after the reorg"
# Disconnected transactions go back through mempool acceptance under the rules
# of the new next block (inactive). Paying TO a v2/v3 output is refused by
# policy below activation: consensus would still treat it as an unknown witness
# version, so the output would not be protected. SPENDING one is an
# upgradable-witness spend that policy discourages.
check "$(inmempool "$T_FUND_PQ")" "False" "payment to strict PQ NOT re-admitted below activation (unprotected output)"
check "$(inmempool "$T_SPEND_PQ")" "False" "strict PQ spend NOT re-admitted below activation (discouraged upgradable witness)"
check "$(inmempool "$T_SPEND_EC")" "False" "strict ECDSA spend NOT re-admitted below activation"
check "$(inmempool "$T_PENDING")" "False" "strict spend that was already pending is evicted when the tip crosses below activation"

echo "== return to the original chain"
A reconsiderblock "$B_PREV" >/dev/null
check "$(A getbestblockhash)" "$TIP_BEFORE" "original tip restored"
check "$(A getrawtransaction "$T_SPEND_PQ" true | jget 'd["confirmations"]')" "1" "strict PQ spend confirmed again"
check "$(A validateaddress "$A_PQ" | jget 'str(d["isvalid"])+"/"+str(d["ismine"])')" "True/True" "strict address usable again"

echo "== alternative branch crossing the activation height again"
A invalidateblock "$B_PREV" >/dev/null
A generatetoaddress 1 "$ALT_LEG" >/dev/null  # new block ACT-1 on a different branch
# The payment to strict PQ was refused below activation; the next block is the
# first active one, so the wallet can submit it again.
A sendrawtransaction "$(A gettransaction "$T_FUND_PQ" | jget 'd["hex"]')" >/dev/null
A generatetoaddress 3 "$ALT_LEG" >/dev/null  # blocks ACT .. ACT+2 on the new branch
check "$(A getblockcount)" "$((ACT+2))" "new branch is above activation"
check "$([ "$(A getblockhash $ACT)" != "$B_ACT" ] && echo different)" "different" "activation block differs on the new branch"
check "$(A getrawtransaction "$T_FUND_PQ" true | jget 'd["confirmations"] >= 1')" "True" "payment to strict PQ mined on the new branch"
# The wallet still holds the strict spend that the mempool refused below
# activation. Above activation on the new branch the very same transaction is valid.
check "$(inmempool "$T_SPEND_PQ")" "False" "refused strict spend is still out of the mempool"
T_RESENT=$(A sendrawtransaction "$(A gettransaction "$T_SPEND_PQ" | jget 'd["hex"]')")
check "$T_RESENT" "$T_SPEND_PQ" "the same strict PQ spend is accepted once the branch is above activation"
A generatetoaddress 1 "$ALT_LEG" >/dev/null
check "$(A getrawtransaction "$T_SPEND_PQ" true | jget 'd["confirmations"]')" "1" "strict PQ output spent on the new branch"

echo "== restart: activation context is restored from the loaded tip"
A stop >/dev/null; for i in $(seq 1 30); do pgrep -f "datadir=$BASE/A" >/dev/null || break; sleep 1; done
startA; waitrpc A
check "$(A validateaddress "$A_EC" | jget 'str(d["isvalid"])+"/"+str(d["ismine"])')" "True/True" "strict address valid and mine after restart above activation"
NEW_PQ=$(A getnewaddress "" pq 2>&1)
check "${NEW_PQ:0:5}" "tpq1z" "strict PQ address available after restart"

A stop >/dev/null; F stop >/dev/null; sleep 2
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
