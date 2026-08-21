#!/bin/bash
# DePIN protocol 2 walkthrough on regtest, single node, driven only through
# the RPC port (neurai-cli): wallet bootstrap, owner signature over the pool
# key, InitError paths, challenge -> sign -> authenticated calls, poolsig
# verification with verifymessage, and the legacy shapes being refused.
# Usage: contrib/depin/regtest_walkthrough.sh  (from anywhere, after building
# src/neuraid and src/neurai-cli). Env: DATADIR, RPCPORT.
set -u
cd "$(dirname "$0")/../.."
D=${DATADIR:-/tmp/neurai-rt-depin}
P=${RPCPORT:-19201}
CLI="./src/neurai-cli -datadir=$D -regtest -rpcuser=u -rpcpassword=p -rpcport=$P"
PASS=0; FAIL=0
ok()   { echo "  [ok]   $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$1" = "$2" ]; then ok "$3 ($1)"; else bad "$3: got '$1' expected '$2'"; fi; }
jqr()  { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(\"d$1\"))"; }
# Plain replies: {"body": <hex of the JSON>, "poolsig": ...}
jqb()  { python3 -c "import sys,json; d=json.load(sys.stdin); b=json.loads(bytes.fromhex(d['body']).decode()); print(eval(\"b$1\"))"; }

rm -rf "$D"; mkdir -p "$D"
cat > "$D/neurai.conf" <<EOF
regtest=1
server=1
listen=0
rpcuser=u
rpcpassword=p
rpcport=$P
rpcallowip=127.0.0.1
assetindex=1
pubkeyindex=1
addressindex=1
txindex=1
bip44=1
printtoconsole=0
EOF

start_node() { ./src/neuraid -datadir="$D" -regtest -daemon "$@" >/dev/null 2>&1; }
wait_rpc() { for i in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
stop_node() { $CLI stop >/dev/null 2>&1; for i in $(seq 1 60); do pgrep -f "neuraid -datadir=$D" >/dev/null || return 0; sleep 1; done; pkill -f "neuraid -datadir=$D"; sleep 2; }
last_log_error() { grep -E "Error:|DePIN service" "$D/regtest/debug.log" | tail -n 1; }

echo "== 1. bootstrap: owner (root), holder (section only), stranger -- all with revealed keys"
start_node; wait_rpc || { echo "node did not start"; tail -n 20 "$D/regtest/debug.log"; exit 1; }
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 150 "$ADDR" >/dev/null
$CLI issue "&TEST" 1000 "$ADDR" >/dev/null || { echo "issue failed"; stop_node; exit 1; }
$CLI generatetoaddress 1 "$ADDR" >/dev/null
OWNER=$($CLI listaddressesbyasset "&TEST!" | python3 -c "import sys,json; print(list(json.load(sys.stdin).keys())[0])")
HOLDER=$($CLI getnewaddress); STRANGER=$($CLI getnewaddress)
# Reveal public keys BEFORE handing out tokens: spending from an address that
# holds an asset output would move the asset to a change address. The owner
# revealed its key when the issuance spent its coinbase outputs.
for A in "$HOLDER" "$STRANGER"; do $CLI sendtoaddress "$A" 2 >/dev/null; done
$CLI generatetoaddress 1 "$ADDR" >/dev/null
for A in "$HOLDER" "$STRANGER"; do $CLI sendfromaddress "$A" "$ADDR" 1 >/dev/null || echo "  sendfromaddress $A failed"; done
$CLI generatetoaddress 1 "$ADDR" >/dev/null
$CLI issue "&TEST/SEC" 10 "$HOLDER" >/dev/null || { echo "section issue failed"; stop_node; exit 1; }
$CLI generatetoaddress 1 "$ADDR" >/dev/null
OWNER=$($CLI listaddressesbyasset "&TEST!" | python3 -c "import sys,json; print(list(json.load(sys.stdin).keys())[0])")
# The owner token moved to a change address when the section was issued; reveal
# that address's key by spending a pure-XNA UTXO of it, chosen by hand so the
# asset output stays where it is.
$CLI sendtoaddress "$OWNER" 2 >/dev/null; $CLI generatetoaddress 1 "$ADDR" >/dev/null
UTXO=$($CLI listunspent 1 9999 "[\"$OWNER\"]" | python3 -c "
import sys,json
for u in json.load(sys.stdin):
    if u.get('amount',0) >= 1.5 and not u.get('assetName'): print(u['txid'], u['vout'], '%.8f' % (u['amount'] - 0.05)); break")
set -- $UTXO
RAW=$($CLI createrawtransaction "[{\"txid\":\"$1\",\"vout\":$2}]" "{\"$ADDR\":$3}")
SIGNED=$($CLI signrawtransaction "$RAW" | jqr "['hex']")
$CLI sendrawtransaction "$SIGNED" >/dev/null || echo "  owner reveal tx failed"
$CLI generatetoaddress 1 "$ADDR" >/dev/null
echo "  owner=$OWNER holder=$HOLDER stranger=$STRANGER roothholder=$ADDR"
POOLPUB=$($CLI depinpoolpkey | jqr "['pubkey']")
POOLADDR=$($CLI depinpoolpkey | jqr "['address']")
SIG=$($CLI signmessage "$OWNER" "DEPIN-POOLKEY|&TEST|$POOLPUB")
STRANGERSIG=$($CLI signmessage "$STRANGER" "DEPIN-POOLKEY|&TEST|$POOLPUB")
echo "  poolpub=$POOLPUB pooladdr=$POOLADDR"
stop_node

echo "== 2. InitError paths"
start_node -depinmsg=1 -depinmsgtoken="&TEST"; sleep 3
if pgrep -f "neuraid -datadir=$D" >/dev/null; then bad "started without -depinpoolkeysig"; stop_node; else ok "refused without -depinpoolkeysig: $(last_log_error)"; fi
start_node -depinmsg=1 -depinmsgtoken="&TEST" -depinpoolkeysig="$STRANGERSIG"; sleep 3
if pgrep -f "neuraid -datadir=$D" >/dev/null; then bad "started with a non-owner signature"; stop_node; else ok "refused non-owner signature: $(last_log_error)"; fi
start_node -depinmsg=1 -depinmsgtoken="&TEST" -depinpoolkeysig="$SIG" -disablewallet; sleep 3
if pgrep -f "neuraid -datadir=$D" >/dev/null; then bad "started with -disablewallet"; stop_node; else ok "refused with -disablewallet: $(last_log_error)"; fi

echo "== 3. service up"
start_node -depinmsg=1 -depinmsgtoken="&TEST" -depinpoolkeysig="$SIG"; wait_rpc || { echo "service node did not start"; tail -n 5 "$D/regtest/debug.log"; exit 1; }
INFO=$($CLI depingetmsginfo)
IB=$(echo "$INFO" | jqr "['body']"); IH=$(printf %s "$IB" | sha256sum | cut -d' ' -f1)
check "$($CLI verifymessage "$POOLADDR" "$(echo "$INFO" | jqr "['poolsig']")" "DEPIN-RESP|depingetmsginfo|&TEST|||$IH")" "true" "poolsig of the plain depingetmsginfo body"
check "$(echo "$INFO" | jqb "['protocol']")" "2" "protocol"
check "$(echo "$INFO" | jqb "['depinpoolpkey']")" "$POOLPUB" "depinpoolpkey published"
check "$(echo "$INFO" | jqb "['depinpoolkeyowner']")" "$OWNER" "owner published"
check "$($CLI verifymessage "$OWNER" "$(echo "$INFO" | jqb "['depinpoolkeysig']")" "DEPIN-POOLKEY|&TEST|$POOLPUB")" "true" "published owner signature verifies with verifymessage"
echo "$IB" | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode())" | grep -q '"port"' && bad "port still published" || ok "no port field"
ss -ltnp 2>/dev/null | grep -q ":19002 " && bad "19002 listening" || ok "nothing listens on 19002"

echo "== 4. two messages in the pool (local wallet send): one to the root, one to the section"
check "$($CLI depinsendmsg "&TEST" "para el root" "$ADDR" | jqr "['result']")" "success" "depinsendmsg to &TEST"
check "$($CLI depinsendmsg "&TEST/SEC" "para la seccion" "$ADDR" | jqr "['result']")" "success" "depinsendmsg to &TEST/SEC"
check "$($CLI depingetmsginfo | jqb "['messages']")" "2" "two messages in pool"

echo "== 5. holder: challenge -> sign -> depinreceivemsg on its section, poolsig via verifymessage"
CH=$($CLI depinchallenge "&TEST/SEC" "$HOLDER")
ENC=$(echo "$CH" | jqr "['encrypted']"); PS=$(echo "$CH" | jqr "['poolsig']")
H=$(printf %s "$ENC" | sha256sum | cut -d' ' -f1)
check "$($CLI verifymessage "$POOLADDR" "$PS" "DEPIN-RESP|depinchallenge|&TEST/SEC|$HOLDER||$H")" "true" "poolsig of depinchallenge"
NONCE=$($CLI depindecrypt "$HOLDER" "$ENC" | jqr "['challenge']")
check "${#NONCE}" "64" "nonce decrypted with depindecrypt"
$CLI depinchallenge "&TEST" "$HOLDER" >/dev/null 2>&1 && bad "section holder got a root challenge" || ok "section holder gets no root challenge"
SIGN=$($CLI depinsignchallenge "$HOLDER" "&TEST/SEC" "$NONCE" | jqr "['signature']")
R=$($CLI depinreceivemsg "&TEST/SEC" "$HOLDER" "$NONCE" "$SIGN")
RENC=$(echo "$R" | jqr "['encrypted']"); RPS=$(echo "$R" | jqr "['poolsig']")
RH=$(printf %s "$RENC" | sha256sum | cut -d' ' -f1)
check "$($CLI verifymessage "$POOLADDR" "$RPS" "DEPIN-RESP|depinreceivemsg|&TEST/SEC|$HOLDER|$NONCE|$RH")" "true" "poolsig of depinreceivemsg (includes nonce)"
MSGS=$($CLI depindecrypt "$HOLDER" "$RENC")
check "$(echo "$MSGS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")" "1" "holder sees exactly its section's message"
check "$(echo "$MSGS" | jqr "[0]['token']")" "&TEST/SEC" "message token"
$CLI depinreceivemsg "&TEST/SEC" "$HOLDER" "$NONCE" "$SIGN" >/dev/null 2>&1 && bad "nonce reused" || ok "nonce is single-use"
$CLI depinreceivemsg "&TEST/SEC" "$HOLDER" >/dev/null 2>&1 && bad "legacy form accepted" || ok "legacy depinreceivemsg token address refused"
$CLI depinreceivemsg "&TEST/SEC" "$HOLDER" 1730000000 >/dev/null 2>&1 && bad "legacy form with timestamp accepted" || ok "legacy form with timestamp refused"
$CLI depinchallenge "&TEST/SEC" "$STRANGER" >/dev/null 2>&1 && bad "stranger got a challenge" || ok "stranger gets no challenge"
# A wrong signer does not burn the holder's nonce.
NONCE2=$($CLI depindecrypt "$HOLDER" "$($CLI depinchallenge "&TEST/SEC" "$HOLDER" | jqr "['encrypted']")" | jqr "['challenge']")
BADSIG=$($CLI depinsignchallenge "$STRANGER" "&TEST/SEC" "$NONCE2" | jqr "['signature']")
$CLI depinreceivemsg "&TEST/SEC" "$HOLDER" "$NONCE2" "$BADSIG" >/dev/null 2>&1 && bad "wrong signer accepted" || ok "wrong signer refused"
SIGN2=$($CLI depinsignchallenge "$HOLDER" "&TEST/SEC" "$NONCE2" | jqr "['signature']")
$CLI depinreceivemsg "&TEST/SEC" "$HOLDER" "$NONCE2" "$SIGN2" >/dev/null 2>&1 && ok "nonce survived the failed attempt" || bad "nonce was burned by the failed attempt"

echo "== 6. depinlistsections: names free, address mode authenticated and scoped"
check "$($CLI depinlistsections | jqb "['sections'][0]['name']")" "&TEST" "names-only form (plain body)"
$CLI depinlistsections "$HOLDER" >/dev/null 2>&1 && bad "one-argument form accepted" || ok "one-argument form refused"
NONCE3=$($CLI depindecrypt "$HOLDER" "$($CLI depinchallenge "&TEST/SEC" "$HOLDER" | jqr "['encrypted']")" | jqr "['challenge']")
SIGN3=$($CLI depinsignchallenge "$HOLDER" "&TEST/SEC" "$NONCE3" | jqr "['signature']")
L=$($CLI depindecrypt "$HOLDER" "$($CLI depinlistsections "$HOLDER" "&TEST/SEC" "$NONCE3" "$SIGN3" | jqr "['encrypted']")")
check "$(echo "$L" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['sections']))")" "1" "holder sees only its section"
check "$(echo "$L" | jqr "['sections'][0]['messages']")" "1" "section counter"
NONCE4=$($CLI depindecrypt "$ADDR" "$($CLI depinchallenge "&TEST" "$ADDR" | jqr "['encrypted']")" | jqr "['challenge']")
SIGN4=$($CLI depinsignchallenge "$ADDR" "&TEST" "$NONCE4" | jqr "['signature']")
L2=$($CLI depindecrypt "$ADDR" "$($CLI depinlistsections "$ADDR" "&TEST" "$NONCE4" "$SIGN4" | jqr "['encrypted']")")
check "$(echo "$L2" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['sections']))")" "2" "root holder sees both sections"

echo "== 7. depinclearmsg: owner-level, scope bound by equality"
$CLI depinclearmsg "all" >/dev/null 2>&1 && bad "legacy clearmsg accepted" || ok "legacy depinclearmsg all refused"
# The section's issuance handed its owner token (&TEST/SEC!) to the holder, so
# it may administer its section -- but not the root, and a stranger nothing.
$CLI depinchallenge "&TEST/SEC" "$HOLDER" "admin" >/dev/null 2>&1 && ok "section owner gets an admin challenge for its section" || bad "section owner denied an admin challenge"
$CLI depinchallenge "&TEST" "$HOLDER" "admin" >/dev/null 2>&1 && bad "section owner got a ROOT admin challenge" || ok "section owner gets no root admin challenge"
$CLI depinchallenge "&TEST/SEC" "$STRANGER" "admin" >/dev/null 2>&1 && bad "stranger got an admin challenge" || ok "stranger gets no admin challenge"
ANONCE=$($CLI depindecrypt "$OWNER" "$($CLI depinchallenge "&TEST/SEC" "$OWNER" "admin" | jqr "['encrypted']")" | jqr "['challenge']")
ASIG_ROOT=$($CLI depinsignchallenge "$OWNER" "&TEST" "$ANONCE" "admin" | jqr "['signature']")
$CLI depinclearmsg "" "$OWNER" "$ANONCE" "$ASIG_ROOT" "all" >/dev/null 2>&1 && bad "section challenge purged the pool" || ok "section challenge does not purge the pool"
ASIG=$($CLI depinsignchallenge "$OWNER" "&TEST/SEC" "$ANONCE" "admin" | jqr "['signature']")
C=$($CLI depindecrypt "$OWNER" "$($CLI depinclearmsg "&TEST/SEC" "$OWNER" "$ANONCE" "$ASIG" "all" | jqr "['encrypted']")")
check "$(echo "$C" | jqr "['removed']")" "1" "owner purged the section only"
check "$(echo "$C" | jqr "['remaining']")" "1" "root message remains"
RNONCE=$($CLI depindecrypt "$OWNER" "$($CLI depinchallenge "&TEST" "$OWNER" "admin" | jqr "['encrypted']")" | jqr "['challenge']")
RSIG=$($CLI depinsignchallenge "$OWNER" "&TEST" "$RNONCE" "admin" | jqr "['signature']")
C2=$($CLI depindecrypt "$OWNER" "$($CLI depinclearmsg "" "$OWNER" "$RNONCE" "$RSIG" "all" | jqr "['encrypted']")")
check "$(echo "$C2" | jqr "['removed']")" "1" "owner purged the pool with scope \"\" (root challenge)"

stop_node
echo "== RESULT: $PASS ok, $FAIL failed"
[ "$FAIL" -eq 0 ]
