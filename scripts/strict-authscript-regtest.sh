#!/bin/bash
# Local regtest exercise of the strict AuthScript families (witness v2 PQ, v3 ECDSA).
# Runs inside the Docker build container (see doc/docker). Two nodes: A = PQ wallet, B = classic wallet.
# Usage: bash scripts/strict-authscript-regtest.sh   (expects binaries under /root/Neurai/src)
set -u
BIN=/root/Neurai/src
BASE=/tmp/strict-regtest
rm -rf "$BASE"; mkdir -p "$BASE/A" "$BASE/B" "$BASE/C"
COMMON="-regtest -server -listen=1 -txindex=1 -addressindex=1 -spentindex=1 -pubkeyindex=1 -assetindex=1 -fallbackfee=0.001 -printtoconsole=0 -rpcuser=u -rpcpassword=p -keypool=5"
A() { "$BIN/neurai-cli" -regtest -datadir="$BASE/A" -rpcport=18501 -rpcuser=u -rpcpassword=p "$@"; }
B() { "$BIN/neurai-cli" -regtest -datadir="$BASE/B" -rpcport=18502 -rpcuser=u -rpcpassword=p "$@"; }
PASS=0; FAIL=0
C() { "$BIN/neurai-cli" -regtest -datadir="$BASE/C" -rpcport=18503 -rpcuser=u -rpcpassword=p "$@"; }
startC() { "$BIN/neuraid" $COMMON -datadir="$BASE/C" -port=18603 -rpcport=18503 -connect=127.0.0.1:18601 -daemon >/dev/null; }
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3 (got '$1', want '$2')"; fi; }
jget() { local code=$1; shift; python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$code" "$@"; }
# Wait until every tx in B's mempool has reached A (P2P propagation) before A mines.
syncmempool() { for i in $(seq 1 30); do
  local missing; missing=$(python3 -c 'import json,sys; a=set(json.loads(sys.argv[1])); b=set(json.loads(sys.argv[2])); print(len(b-a))' "$(A getrawmempool)" "$(B getrawmempool 2>/dev/null || echo '[]')")
  [ "$missing" = "0" ] && return 0; sleep 1; done; echo "  (mempool sync timeout)"; }
mine() { syncmempool; A generatetoaddress "$1" "$A_DEF" >/dev/null; sleep 1; }
startA() { "$BIN/neuraid" $COMMON -datadir="$BASE/A" -port=18601 -rpcport=18501 -addresstype=pq -daemon >/dev/null; }
startB() { "$BIN/neuraid" $COMMON -datadir="$BASE/B" -port=18602 -rpcport=18502 -connect=127.0.0.1:18601 -daemon >/dev/null; }
waitrpc() { for i in $(seq 1 120); do if "$@" getblockcount >/dev/null 2>&1; then return 0; fi; sleep 1; done; echo "node did not start"; exit 1; }
waitsync() { for i in $(seq 1 30); do [ "$(A getblockcount)" = "$(B getblockcount)" ] && return 0; sleep 1; done; bad "nodes did not sync"; }

echo "== start nodes"
startA; waitrpc A
startB; waitrpc B

echo "== addresses"
A_DEF=$(A getnewaddress)   # PQ wallet default: strict PQ v2 (also the mining address)
A_PQ=$(A getnewaddress "" pq)
A_EC=$(A getnewaddress "" ecdsa)
B_LEG=$(B getnewaddress)
B_EC=$(B getnewaddress "" ecdsa)
echo "A_DEF=$A_DEF"; echo "A_PQ=$A_PQ"; echo "A_EC=$A_EC"; echo "B_LEG=$B_LEG"; echo "B_EC=$B_EC"
if A getnewaddress "" authscript >/dev/null 2>&1; then bad "the wallet must never hand out generic v1 (contract) addresses"; else ok "the wallet never hands out generic v1 (contract) addresses"; fi
check "${A_DEF:0:5}" "tpq1z" "A default address is strict PQ v2"
check "${A_PQ:0:5}" "tpq1z" "A strict PQ address prefix"
check "${A_EC:0:5}" "tnq1r" "A strict ECDSA address prefix"
check "${B_EC:0:5}" "tnq1r" "B strict ECDSA address prefix"
check "$(A validateaddress "$A_PQ" | jget 'str(d["family"])+"/"+str(d["witness_version"])+"/"+str(d["ismine"])')" "pq/2/True" "validateaddress A_PQ"
check "$(A validateaddress "$A_EC" | jget 'str(d["family"])+"/"+str(d["witness_version"])+"/"+str(d["ismine"])')" "ecdsa/3/True" "validateaddress A_EC"
check "$(B validateaddress "$A_PQ" | jget 'str(d["isvalid"])+"/"+str(d["ismine"])')" "True/False" "B sees A_PQ valid, not mine"
if B getnewaddress "" pq >/dev/null 2>&1; then bad "B (classic wallet) must not create strict PQ addresses"; else ok "B refuses strict PQ address"; fi
if A getnewaddress "" foo >/dev/null 2>&1; then bad "unknown address_type must fail"; else ok "unknown address_type rejected"; fi
# Same wallet: pq / ecdsa strict addresses from A; legacy must fail in a PQ wallet
if A getnewaddress "" legacy >/dev/null 2>&1; then bad "PQ wallet must not create legacy"; else ok "PQ wallet refuses legacy address"; fi

echo "== cross HRP/version address must be invalid"
CROSS=$(python3 - "$A_PQ" <<'PY'
import sys
CH="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(v):
    G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; c=1
    for x in v:
        b=c>>25; c=((c&0x1ffffff)<<5)^x
        for i in range(5):
            c^=G[i] if (b>>i)&1 else 0
    return c
def hrpexp(h): return [ord(c)>>5 for c in h]+[0]+[ord(c)&31 for c in h]
def enc(hrp,data):
    pm=polymod(hrpexp(hrp)+data+[0]*6)^0x2bc830a3
    return hrp+"1"+"".join(CH[d] for d in data+[(pm>>5*(5-i))&31 for i in range(6)])
a=sys.argv[1]; data=[CH.index(c) for c in a[a.rfind("1")+1:-6]]
print(enc("tnq",data))
PY
)
check "$(A validateaddress "$CROSS" | jget 'str(d["isvalid"])')" "False" "tnq HRP with witness v2 payload rejected ($CROSS)"

# spend_from NODE ADDR DEST AMOUNT LABEL -> prints txid; uses one UTXO of ADDR
spend_from() {
  local node=$1 addr=$2 dest=$3 amt=$4 label=$5
  local u; u=$($node listunspent 1 9999 "[\"$addr\"]" | jget 'json.dumps([x for x in d if x["amount"]>=float(sys.argv[2])][0])' "$amt" 2>/dev/null)
  if [ -z "$u" ]; then bad "$label: no utxo at $addr with >= $amt"; return 1; fi
  local txid vout
  txid=$(echo "$u" | jget 'd["txid"]'); vout=$(echo "$u" | jget 'd["vout"]')
  local outamt; outamt=$(echo "$u" | jget '"%.8f" % (d["amount"] - 0.05)')  # 0.05 XNA fee covers ~2 kB PQ witnesses at 0.01 XNA/kB
  local raw; raw=$($node createrawtransaction "[{\"txid\":\"$txid\",\"vout\":$vout}]" "{\"$dest\":$outamt}")
  local signed; signed=$($node signrawtransaction "$raw")
  if [ "$(echo "$signed" | jget 'd["complete"]')" != "True" ]; then bad "$label: signing incomplete: $(echo "$signed" | head -c 300)"; return 1; fi
  local hex; hex=$(echo "$signed" | jget 'd["hex"]')
  local sent; sent=$($node sendrawtransaction "$hex" 2>&1)
  if [ ${#sent} -ne 64 ]; then bad "$label: send failed: $sent"; return 1; fi
  echo "$sent"
}

echo "== funding"
A generatetoaddress 1 "$A_PQ" >/dev/null   # coinbase straight to a strict PQ output
CB_PQ=$(A getblock "$(A getblockhash 1)" | jget 'd["tx"][0]')
A generatetoaddress 1 "$A_EC" >/dev/null   # coinbase straight to a strict ECDSA output
CB_EC=$(A getblock "$(A getblockhash 2)" | jget 'd["tx"][0]')
check "$(A getrawtransaction "$CB_PQ" true | jget 'd["vout"][0]["scriptPubKey"]["type"]')" "witness_v2_strict_pq" "coinbase paid to strict PQ output"
check "$(A getrawtransaction "$CB_EC" true | jget 'd["vout"][0]["scriptPubKey"]["type"]')" "witness_v3_strict_ecdsa" "coinbase paid to strict ECDSA output"
mine 120
waitsync
echo "A balance: $(A getbalance)  B balance: $(B getbalance)"
# Spend the two strict coinbases explicitly to B (raw path, explicit UTXO): proves
# the wallet signs strict coinbase outputs and that they are consensus-valid spends.
T_CBPQ=$(spend_from A "$A_PQ" "$B_LEG" 1 "spend strict PQ coinbase")
T_CBEC=$(spend_from A "$A_EC" "$B_LEG" 1 "spend strict ECDSA coinbase")
mine 1; waitsync
[ ${#T_CBPQ} -eq 64 ] && check "$(A getrawtransaction "$T_CBPQ" true | jget 'd["confirmations"]')" "1" "strict PQ coinbase spent (raw)" || bad "strict PQ coinbase spend: $T_CBPQ"
[ ${#T_CBEC} -eq 64 ] && check "$(A getrawtransaction "$T_CBEC" true | jget 'd["confirmations"]')" "1" "strict ECDSA coinbase spent (raw)" || bad "strict ECDSA coinbase spend: $T_CBEC"
[ ${#T_CBPQ} -eq 64 ] && check "$(A getrawtransaction "$T_CBPQ" true | jget 'len(d["vin"][0]["txinwitness"])')" "4" "PQ coinbase spend witness has 4 items"
# A pays itself through the normal wallet path (sendtoaddress): the wallet may
# later consume these outputs as inputs, so only the tx shape is checked here.
T_SELF=$(A sendtoaddress "$A_PQ" 10)
mine 1
check "$(A getrawtransaction "$T_SELF" true | jget 'd["confirmations"]')" "1" "sendtoaddress to own strict PQ address confirmed"
T_SELF2=$(A sendtoaddress "$B_EC" 5)
mine 1
check "$(A getrawtransaction "$T_SELF2" true | jget 'len(d["vin"][0]["txinwitness"])')" "4" "wallet coin selection spent the strict output (4-item witness)"
# Fund A's strict addresses FROM B (B cannot spend them), so they stay put for the matrix.
for i in 1 2 3; do B sendtoaddress "$A_PQ" 10 >/dev/null; B sendtoaddress "$A_EC" 10 >/dev/null; done
mine 1; waitsync
B sendtoaddress "$B_EC" 10 >/dev/null; mine 1; B sendtoaddress "$B_EC" 10 >/dev/null; mine 1; waitsync
check "$(A listunspent 1 9999 "[\"$A_PQ\"]" | jget 'len([x for x in d if abs(x["amount"]-10)<1e-8])')" "3" "A_PQ has 3 unspent payments of 10"
check "$(A listunspent 1 9999 "[\"$A_EC\"]" | jget 'len([x for x in d if abs(x["amount"]-10)<1e-8])')" "3" "A_EC has 3 unspent payments of 10"
check "$(A getaddressbalance "{\"addresses\":[\"$A_PQ\"]}" | jget 'd["balance"] > 0')" "True" "address index balance for A_PQ"
check "$(A getaddressutxos "{\"addresses\":[\"$A_EC\"]}" | jget 'len(d) >= 3')" "True" "address index utxos for A_EC"

echo "== top up B's legacy and strict ECDSA addresses from A right before the matrix"
for i in 1 2 3; do A sendtoaddress "$B_LEG" 10 >/dev/null; done
A sendtoaddress "$B_EC" 10 >/dev/null
mine 1; waitsync
check "$(B listunspent 1 9999 "[\"$B_LEG\"]" | jget 'len([x for x in d if abs(x["amount"]-10)<1e-8]) >= 3')" "True" "B_LEG has 3 payments of 10"
check "$(B listunspent 1 9999 "[\"$B_EC\"]" | jget 'len([x for x in d if abs(x["amount"]-10)<1e-8]) >= 1')" "True" "B_EC has a payment of 10"

echo "== 3x3 matrix: {legacy,pq,ecdsa} -> {legacy,pq,ecdsa} (explicit UTXO selection, raw signing)"
T_LL=$(spend_from B "$B_LEG" "$B_LEG" 1 "legacy->legacy")
T_LP=$(spend_from B "$B_LEG" "$A_PQ" 1 "legacy->pq")
T_LE=$(spend_from B "$B_LEG" "$B_EC" 1 "legacy->ecdsa")
T_PL=$(spend_from A "$A_PQ" "$B_LEG" 9 "pq->legacy")
T_PP=$(spend_from A "$A_PQ" "$A_PQ" 9 "pq->pq")
T_PE=$(spend_from A "$A_PQ" "$A_EC" 9 "pq->ecdsa")
T_EL=$(spend_from A "$A_EC" "$B_LEG" 9 "ecdsa->legacy")
T_EP=$(spend_from A "$A_EC" "$A_PQ" 9 "ecdsa->pq")
T_EE=$(spend_from B "$B_EC" "$B_EC" 9 "ecdsa->ecdsa")
mine 1; waitsync
for t in LL LP LE PL PP PE EL EP EE; do
  v=T_$t; txid=${!v}
  if [ ${#txid} -eq 64 ]; then
    conf=$(A getrawtransaction "$txid" true | jget 'd["confirmations"]')
    check "$conf" "1" "matrix $t confirmed"
  else bad "matrix $t not sent"; fi
done
echo "-- witness shape and vsize"
for t in PL EL LL; do
  v=T_$t; txid=${!v}
  [ ${#txid} -eq 64 ] || continue
  A getrawtransaction "$txid" true | python3 -c 'import json,sys; d=json.load(sys.stdin); print("  %s: vsize=%d size=%d witness_items=%s" % (sys.argv[1], d["vsize"], d["size"], [len(i.get("txinwitness",[])) for i in d["vin"]]))' "$t"
done
check "$(A getrawtransaction "$T_PL" true | jget 'len(d["vin"][0]["txinwitness"])')" "4" "pq spend witness has exactly 4 items"
check "$(A getrawtransaction "$T_EL" true | jget 'len(d["vin"][0]["txinwitness"])')" "4" "ecdsa spend witness has exactly 4 items"
check "$(A getrawtransaction "$T_PL" true | jget 'd["vin"][0]["txinwitness"][0]')" "01" "pq spend authType 0x01"
check "$(A getrawtransaction "$T_EL" true | jget 'd["vin"][0]["txinwitness"][0]')" "02" "ecdsa spend authType 0x02"
check "$(A getrawtransaction "$T_EL" true | jget 'd["vin"][0]["txinwitness"][3]')" "51" "ecdsa spend witnessScript is OP_TRUE"
check "$(A getrawtransaction "$T_PL" true | jget 'd["vout"][0]["scriptPubKey"]["type"]')" "pubkeyhash" "pq->legacy output type"
check "$(A getrawtransaction "$T_LP" true | jget 'd["vout"][0]["scriptPubKey"]["type"]')" "witness_v2_strict_pq" "legacy->pq output type"
check "$(A getrawtransaction "$T_LE" true | jget 'd["vout"][0]["scriptPubKey"]["type"]')" "witness_v3_strict_ecdsa" "legacy->ecdsa output type"
check "$(A getrawtransaction "$T_LP" true | jget 'd["vout"][0]["scriptPubKey"]["addresses"][0]')" "$A_PQ" "legacy->pq output address reconstructed"

echo "== change returns to the family of the spent inputs"
# change_type NODE ADDR -> funds a tx with one preset input from ADDR and prints the change output type
change_type() {
  local node=$1 addr=$2
  local u; u=$($node listunspent 1 9999 "[\"$addr\"]" | jget 'json.dumps([x for x in d if x["amount"]>=5][0])' 2>/dev/null)
  [ -z "$u" ] && { echo "no-utxo"; return; }
  local raw; raw=$($node createrawtransaction "[{\"txid\":\"$(echo "$u"|jget 'd["txid"]')\",\"vout\":$(echo "$u"|jget 'd["vout"]')}]" "{\"$B_LEG\":1}")
  local funded; funded=$($node fundrawtransaction "$raw")
  local pos; pos=$(echo "$funded" | jget 'd["changepos"]')
  $node decoderawtransaction "$(echo "$funded" | jget 'd["hex"]')" | jget 'd["vout"][int(sys.argv[2])]["scriptPubKey"]["type"]' "$pos"
}
check "$(change_type A "$A_PQ")" "witness_v2_strict_pq" "change of a strict PQ spend is strict PQ"
check "$(change_type A "$A_EC")" "witness_v3_strict_ecdsa" "change of a strict ECDSA spend is strict ECDSA (PQ wallet)"
check "$(change_type A "$A_DEF")" "witness_v2_strict_pq" "change of a spend from the PQ default address is strict PQ"
check "$(change_type B "$B_LEG")" "pubkeyhash" "change of a legacy spend is legacy"
check "$(change_type B "$B_EC")" "witness_v3_strict_ecdsa" "change of a strict ECDSA spend is strict ECDSA (classic wallet)"

echo "== mixed inputs: pq + ecdsa in one tx from A -> B_LEG"
u1=$(A listunspent 1 9999 "[\"$A_PQ\"]" | jget 'json.dumps([x for x in d if 5 <= x["amount"] <= 20][0])')
u2=$(A listunspent 1 9999 "[\"$A_EC\"]" | jget 'json.dumps([x for x in d if 5 <= x["amount"] <= 20][0])')
raw=$(A createrawtransaction "[{\"txid\":\"$(echo "$u1"|jget 'd["txid"]')\",\"vout\":$(echo "$u1"|jget 'd["vout"]')},{\"txid\":\"$(echo "$u2"|jget 'd["txid"]')\",\"vout\":$(echo "$u2"|jget 'd["vout"]')}]" "{\"$B_LEG\":$(python3 -c "import json; print('%.8f' % (json.loads('$u1')['amount'] + json.loads('$u2')['amount'] - 0.1))")}")  # 0.1 XNA fee for a ~2.1 kB tx
signed=$(A signrawtransaction "$raw")
check "$(echo "$signed" | jget 'd["complete"]')" "True" "mixed pq+ecdsa inputs signed"
T_MIX=$(A sendrawtransaction "$(echo "$signed" | jget 'd["hex"]')")
mine 1; waitsync
check "$(A getrawtransaction "$T_MIX" true | jget 'd["confirmations"]')" "1" "mixed input tx confirmed"

echo "== message signing"
SIG_PQ=$(A signmessage "$A_PQ" "hello pq")
SIG_EC=$(A signmessage "$A_EC" "hello ecdsa")
check "$(B verifymessage "$A_PQ" "$SIG_PQ" "hello pq")" "true" "verify PQ strict message on other node"
check "$(B verifymessage "$A_EC" "$SIG_EC" "hello ecdsa")" "true" "verify ECDSA strict message on other node"
check "$(B verifymessage "$A_EC" "$SIG_EC" "other")" "false" "wrong message rejected"
check "$(B verifymessage "$A_PQ" "$SIG_EC" "hello ecdsa")" "false" "signature bound to its family"

echo "== assets"
T_ISSUE=$(B issue STRICTTEST 1000 "$B_EC" | jget 'd[0]') && ok "issue STRICTTEST to strict ECDSA address" || bad "issue STRICTTEST failed"
mine 1; waitsync
check "$(A getrawtransaction "$T_ISSUE" true | jget 'd["confirmations"]')" "1" "issue tx confirmed on A"
A getrawtransaction "$T_ISSUE" true | jget 'print([(o["value"], o["scriptPubKey"].get("type"), (o["scriptPubKey"].get("addresses") or ["-"])[0][:14], o["scriptPubKey"].get("asset",{}).get("name")) for o in d["vout"]])' | tail -1
check "$(B listmyassets | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "1000.0" "B holds 1000 STRICTTEST"
check "$(B listassetbalancesbyaddress "$B_EC" | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "1000.0" "asset index: balance at strict ECDSA address (B)"
check "$(A listassetbalancesbyaddress "$B_EC" | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "1000.0" "asset index: balance at strict ECDSA address (A)"
check "$(A listaddressesbyasset STRICTTEST | jget 'str(len(d))')" "1" "listaddressesbyasset shows one holder"
T_TR1=$(B transfer STRICTTEST 10 "$A_PQ" | jget 'd[0]') && ok "transfer STRICTTEST to strict PQ address" || bad "transfer to PQ failed"
mine 1; waitsync
check "$(A getrawtransaction "$T_TR1" true | jget 'd["confirmations"]')" "1" "transfer-to-PQ tx confirmed on A"
check "$(A listmyassets | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "10.0" "A holds 10 STRICTTEST at strict PQ"
check "$(A listassetbalancesbyaddress "$A_PQ" | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "10.0" "asset index: balance at strict PQ address"
T_TR2=$(A transfer STRICTTEST 4 "$B_LEG" | jget 'd[0]') && ok "transfer STRICTTEST from strict PQ to legacy" || bad "transfer from PQ failed"
mine 1; waitsync
check "$(A getrawtransaction "$T_TR2" true | jget 'len(d["vin"][0]["txinwitness"])')" "4" "asset spend from strict PQ has 4-item witness"
check "$(A getrawtransaction "$T_TR2" true | jget 'sorted(set((o["scriptPubKey"].get("addresses") or ["-"])[0][:5] for o in d["vout"] if o["scriptPubKey"].get("asset") and (o["scriptPubKey"].get("addresses") or ["-"])[0] != sys.argv[2]))' "$B_LEG")" "['tpq1z']" "asset change of a strict PQ asset spend returns to strict PQ"
check "$(A listmyassets | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "6.0" "A keeps 6 STRICTTEST"
T_OWN=$(B transfer "STRICTTEST!" 1 "$A_EC" | jget 'd[0]') && ok "owner token to strict ECDSA address" || bad "owner token transfer failed"
mine 1; waitsync
check "$(A getrawtransaction "$T_OWN" true | jget 'd["confirmations"]')" "1" "owner token tx confirmed on A"
A getrawtransaction "$T_OWN" true | jget 'print([(o["value"], o["scriptPubKey"].get("type"), (o["scriptPubKey"].get("addresses") or ["-"])[0][:14], o["scriptPubKey"].get("asset",{}).get("name")) for o in d["vout"]])' | tail -1
check "$(A listmyassets | jget '"%.1f" % float(d.get("STRICTTEST!", 0))')" "1.0" "A holds owner token at strict ECDSA"
T_RE=$(A reissue STRICTTEST 100 "$A_PQ" | jget 'd[0]') && ok "reissue from strict ECDSA owner to strict PQ" || bad "reissue failed"
mine 1; waitsync
check "$(A listmyassets | jget '"%.1f" % float(d.get("STRICTTEST", 0))')" "106.0" "A holds 106 STRICTTEST after reissue"

echo "== restart A: persistence of strict spend data"
A stop >/dev/null; sleep 3
BAL_BEFORE=$(A getbalance 2>/dev/null || true)
startA; waitrpc A; sleep 2
check "$(A validateaddress "$A_PQ" | jget 'str(d["ismine"])')" "True" "A_PQ still mine after restart"
check "$(A validateaddress "$A_EC" | jget 'str(d["ismine"])')" "True" "A_EC still mine after restart"
T_R1=$(spend_from A "$A_PQ" "$B_LEG" 1 "pq spend after restart")
T_R2=$(spend_from A "$A_EC" "$B_LEG" 1 "ecdsa spend after restart")
mine 1; waitsync
[ ${#T_R1} -eq 64 ] && check "$(A getrawtransaction "$T_R1" true | jget 'd["confirmations"]')" "1" "pq spend after restart confirmed"
[ ${#T_R2} -eq 64 ] && check "$(A getrawtransaction "$T_R2" true | jget 'd["confirmations"]')" "1" "ecdsa spend after restart confirmed"

echo "== pubkey index (revealed keys of strict spends)"
A getaddressdeltas "{\"addresses\":[\"$A_PQ\"]}" >/dev/null 2>&1 && ok "getaddressdeltas on strict PQ address" || bad "getaddressdeltas failed"

echo "== encrypted wallet: strict ECDSA keypool (node C, classic wallet, -keypool=5)"
startC; waitrpc C
check "$(C getwalletinfo | jget 'str(d["keypoolsize_strict_ecdsa"])+"/"+str(d["keypoolsize_strict_ecdsa_internal"])')" "5/5" "strict ECDSA keypool pre-generated on wallet creation"
C encryptwallet "test-passphrase" >/dev/null 2>&1
for i in $(seq 1 30); do pgrep -f "datadir=$BASE/C" >/dev/null || break; sleep 1; done
startC; waitrpc C
check "$(C getwalletinfo | jget 'str(d["unlocked_until"])')" "0" "node C wallet is encrypted and locked"
check "$(C getwalletinfo | jget 'str(d["keypoolsize_strict_ecdsa"])+"/"+str(d["keypoolsize_strict_ecdsa_internal"])')" "5/5" "strict ECDSA keypool survives encryption and restart"
C_EC=$(C getnewaddress "" ecdsa)
check "${C_EC:0:5}" "tnq1r" "locked wallet hands out a strict ECDSA receive address"
check "$(C validateaddress "$C_EC" | jget 'str(d["ismine"])')" "True" "address from the locked pool is mine"
check "$(C getwalletinfo | jget 'str(d["keypoolsize_strict_ecdsa"])')" "4" "external strict pool decreased while locked"
A sendtoaddress "$C_EC" 10 >/dev/null; mine 1
for i in $(seq 1 30); do [ "$(A getblockcount)" = "$(C getblockcount)" ] && break; sleep 1; done
check "$(C listunspent 1 9999 "[\"$C_EC\"]" | jget 'len(d)')" "1" "locked wallet sees the payment to its strict ECDSA address"
check "$(change_type C "$C_EC")" "witness_v3_strict_ecdsa" "locked wallet builds strict ECDSA change from the internal pool"
check "$(C getwalletinfo | jget 'str(d["keypoolsize_strict_ecdsa_internal"])')" "4" "fundrawtransaction keeps its change key (same as the legacy keypool), taken from the internal strict pool"
for i in 1 2 3 4; do C getnewaddress "" ecdsa >/dev/null; done
if C getnewaddress "" ecdsa >/dev/null 2>&1; then bad "locked wallet must fail once the strict pool is exhausted"; else ok "exhausted strict pool fails cleanly while locked"; fi
C walletpassphrase "test-passphrase" 120 >/dev/null
C keypoolrefill >/dev/null
check "$(C getwalletinfo | jget 'str(d["keypoolsize_strict_ecdsa"])+"/"+str(d["keypoolsize_strict_ecdsa_internal"])')" "5/5" "strict ECDSA keypool refilled after unlock"
T_C=$(C sendtoaddress "$B_LEG" 3)
for i in $(seq 1 30); do A getrawtransaction "$T_C" >/dev/null 2>&1 && break; sleep 1; done   # wait for C -> A relay
mine 1
for i in $(seq 1 30); do [ "$(A getblockcount)" = "$(C getblockcount)" ] && break; sleep 1; done
check "$(A getrawtransaction "$T_C" true | jget 'd["confirmations"]')" "1" "unlocked encrypted wallet spends its strict ECDSA output"
check "$(A getrawtransaction "$T_C" true | jget 'sorted(o["scriptPubKey"]["type"] for o in d["vout"])')" "['pubkeyhash', 'witness_v3_strict_ecdsa']" "its change returns to strict ECDSA"
check "$(C getwalletinfo | jget 'd["keypoolsize_strict_ecdsa_internal"] >= 4')" "True" "internal strict pool stays stocked after a committed change"
C_EC2=$(C getnewaddress "" ecdsa)
C stop >/dev/null; sleep 3; startC; waitrpc C
check "$(C validateaddress "$C_EC2" | jget 'str(d["ismine"])')" "True" "strict ECDSA address persists across restart of the encrypted wallet"
C stop >/dev/null

echo "== stop"
A stop >/dev/null; B stop >/dev/null; sleep 2
echo "RESULT: PASS=$PASS FAIL=$FAIL"
# A printed FAIL must also fail the job invoking this script.
test "$FAIL" -eq 0
