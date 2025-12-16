#!/bin/bash
# Test script for depinpoolpkey RPC command

NEURAI_CLI="neurai-cli"
TESTNET_FLAG=""

# Check if testnet flag is provided
if [ "$1" == "--testnet" ]; then
    TESTNET_FLAG="-testnet"
    echo "Testing on TESTNET"
else
    echo "Testing on MAINNET"
fi

echo "============================================"
echo "Testing depinpoolpkey RPC Command"
echo "============================================"
echo ""

# Test 1: Check if wallet is available
echo "[Test 1] Checking wallet availability..."
if ! $NEURAI_CLI $TESTNET_FLAG getwalletinfo > /dev/null 2>&1; then
    echo "❌ FAIL: Wallet not available"
    exit 1
fi
echo "✅ PASS: Wallet is available"
echo ""

# Test 2: Check if wallet is unlocked
echo "[Test 2] Checking wallet lock status..."
WALLET_INFO=$($NEURAI_CLI $TESTNET_FLAG getwalletinfo)
if echo "$WALLET_INFO" | grep -q '"unlocked_until": 0'; then
    echo "⚠️  WARNING: Wallet is locked. Command may fail."
else
    echo "✅ PASS: Wallet is unlocked"
fi
echo ""

# Test 3: Call depinpoolpkey
echo "[Test 3] Calling depinpoolpkey..."
RESULT=$($NEURAI_CLI $TESTNET_FLAG depinpoolpkey 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ FAIL: Command returned error:"
    echo "$RESULT"
    exit 1
fi

echo "✅ PASS: Command executed successfully"
echo ""
echo "Result:"
echo "$RESULT" | jq .
echo ""

# Test 4: Validate response structure
echo "[Test 4] Validating response structure..."

PUBKEY=$(echo "$RESULT" | jq -r .pubkey 2>/dev/null)
ADDRESS=$(echo "$RESULT" | jq -r .address 2>/dev/null)
PATH=$(echo "$RESULT" | jq -r .path 2>/dev/null)

if [ -z "$PUBKEY" ] || [ "$PUBKEY" == "null" ]; then
    echo "❌ FAIL: Missing 'pubkey' field"
    exit 1
fi
echo "✅ PASS: 'pubkey' field present: $PUBKEY"

if [ -z "$ADDRESS" ] || [ "$ADDRESS" == "null" ]; then
    echo "❌ FAIL: Missing 'address' field"
    exit 1
fi
echo "✅ PASS: 'address' field present: $ADDRESS"

if [ -z "$PATH" ] || [ "$PATH" == "null" ]; then
    echo "❌ FAIL: Missing 'path' field"
    exit 1
fi
echo "✅ PASS: 'path' field present: $PATH"
echo ""

# Test 5: Validate derivation path
echo "[Test 5] Validating derivation path..."
if [ "$TESTNET_FLAG" == "-testnet" ]; then
    EXPECTED_PATH="m/44'/0'/200'/1/0"
else
    EXPECTED_PATH="m/44'/0'/200'/0/0"
fi

if [ "$PATH" != "$EXPECTED_PATH" ]; then
    echo "❌ FAIL: Expected path '$EXPECTED_PATH', got '$PATH'"
    exit 1
fi
echo "✅ PASS: Derivation path is correct for the network"
echo ""

# Test 6: Validate public key format (should be 66 hex chars for compressed pubkey)
echo "[Test 6] Validating public key format..."
PUBKEY_LENGTH=${#PUBKEY}
if [ $PUBKEY_LENGTH -ne 66 ]; then
    echo "⚠️  WARNING: Expected 66 hex chars (compressed pubkey), got $PUBKEY_LENGTH"
else
    echo "✅ PASS: Public key has correct length (66 hex chars)"
fi
echo ""

# Test 7: Validate address format
echo "[Test 7] Validating address format..."
if [ "$TESTNET_FLAG" == "-testnet" ]; then
    if [[ ! "$ADDRESS" =~ ^t[a-zA-Z0-9]{33}$ ]]; then
        echo "⚠️  WARNING: Address doesn't match testnet format (starts with 't')"
    else
        echo "✅ PASS: Address matches testnet format"
    fi
else
    if [[ ! "$ADDRESS" =~ ^N[a-zA-Z0-9]{33}$ ]]; then
        echo "⚠️  WARNING: Address doesn't match mainnet format (starts with 'N')"
    else
        echo "✅ PASS: Address matches mainnet format"
    fi
fi
echo ""

# Test 8: Consistency check (call twice, should return same result)
echo "[Test 8] Testing consistency (calling twice)..."
RESULT2=$($NEURAI_CLI $TESTNET_FLAG depinpoolpkey 2>&1)
PUBKEY2=$(echo "$RESULT2" | jq -r .pubkey 2>/dev/null)

if [ "$PUBKEY" != "$PUBKEY2" ]; then
    echo "❌ FAIL: Public key changed between calls"
    echo "  First call:  $PUBKEY"
    echo "  Second call: $PUBKEY2"
    exit 1
fi
echo "✅ PASS: Public key is consistent across calls"
echo ""

# Summary
echo "============================================"
echo "All tests completed successfully! ✅"
echo "============================================"
echo ""
echo "DePIN Pool Public Key Information:"
echo "  Public Key: $PUBKEY"
echo "  Address:    $ADDRESS"
echo "  Path:       $PATH"
echo ""
