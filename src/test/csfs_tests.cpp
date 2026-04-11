// Copyright (c) 2023-2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <vector>
#include <stdint.h>

#include <boost/test/unit_test.hpp>

// Flags matching standard mempool policy (includes STRICTENC/DERSIG)
static const unsigned int CSFS_FLAGS_STRICT = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_CHECKSIGFROMSTACK | SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_LOW_S;

// Minimal flags (no encoding checks)
static const unsigned int CSFS_FLAGS_MINIMAL = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_CHECKSIGFROMSTACK | SCRIPT_VERIFY_NULLFAIL;

static const unsigned int NO_CSFS_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static const unsigned int NO_CSFS_FLAGS_DISCOURAGE = NO_CSFS_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

namespace {

CMutableTransaction BuildCsfsTestTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    CTxIn vin;
    vin.prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);
    CTxOut vout;
    vout.nValue = 1000;
    vout.scriptPubKey = CScript() << OP_TRUE;
    tx.vout.push_back(vout);
    return tx;
}

// Helper: sign a message for CSFS (SHA256(msg) then sign, append hashtype byte)
std::vector<unsigned char> SignForCsfs(const CKey& key, const std::vector<unsigned char>& msg, unsigned char nHashType = SIGHASH_ALL)
{
    uint256 msgHash;
    CSHA256().Write(msg.data(), msg.size()).Finalize(msgHash.begin());

    std::vector<unsigned char> sig;
    bool ok = key.Sign(msgHash, sig);
    assert(ok);
    sig.push_back(nHashType);
    return sig;
}

// Helper: sign a message for CSFS WITHOUT appending a hashtype byte.
// This produces a raw signature (DER for ECDSA, ML_DSA_44_SIG_SIZE for PQ).
std::vector<unsigned char> SignForCsfsRaw(const CKey& key, const std::vector<unsigned char>& msg)
{
    uint256 msgHash;
    CSHA256().Write(msg.data(), msg.size()).Finalize(msgHash.begin());

    std::vector<unsigned char> sig;
    bool ok = key.Sign(msgHash, sig);
    assert(ok);
    return sig;
}

// Helper: evaluate a bare script
bool RunBareScript(const CScript& script, unsigned int flags, const CTransaction& tx, ScriptError* err = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    ScriptError serror;
    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (err) *err = serror;
    return result;
}

// Helper: evaluate a P2WSH-wrapped script via VerifyScript
bool RunP2WSH(const CScript& witnessScript, const std::vector<std::vector<unsigned char>>& witnessData,
              unsigned int flags, const CTransaction& tx, ScriptError* err = nullptr)
{
    // Build witness: data items + serialized witnessScript
    CScriptWitness witness;
    witness.stack = witnessData;
    witness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

    // P2WSH scriptPubKey: OP_0 <SHA256(witnessScript)>
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(scriptHash);

    // Empty scriptSig for witness
    CScript scriptSig;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    bool result = VerifyScript(scriptSig, scriptPubKey, &witness, flags, checker, &serror);
    if (err) *err = serror;
    return result;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(csfs_tests, BasicTestingSetup)

// ============================================================================
// ECDSA: Valid signature (bare script, minimal flags)
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_valid_signature)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'h', 'e', 'l', 'l', 'o'};
    std::vector<unsigned char> sig = SignForCsfs(key, msg);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    // Script: <sig> <msg> <pubkey> OP_CHECKSIGFROMSTACK
    CScript script;
    script << sig << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    BOOST_CHECK(RunBareScript(script, CSFS_FLAGS_MINIMAL, tx));
}

// ============================================================================
// ECDSA: Valid signature under strict encoding (policy flags)
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_valid_signature_strict)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'t', 'e', 's', 't'};
    std::vector<unsigned char> sig = SignForCsfs(key, msg, SIGHASH_ALL);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CScript script;
    script << sig << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    BOOST_CHECK(RunBareScript(script, CSFS_FLAGS_STRICT, tx));
}

// ============================================================================
// ECDSA: Wrong message fails
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_wrong_message)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'r', 'i', 'g', 'h', 't'};
    std::vector<unsigned char> wrongMsg = {'w', 'r', 'o', 'n', 'g'};
    std::vector<unsigned char> sig = SignForCsfs(key, msg);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CScript script;
    script << sig << wrongMsg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    ScriptError err;
    BOOST_CHECK(!RunBareScript(script, CSFS_FLAGS_MINIMAL, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_NULLFAIL);
}

// ============================================================================
// ECDSA: Empty signature returns false (no NULLFAIL error for empty sig)
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_empty_sig_returns_false)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'t', 'e', 's', 't'};
    std::vector<unsigned char> emptySig;
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    // Without NULLFAIL, empty sig -> pushes false, script succeeds
    CScript script;
    unsigned int flagsNoNullfail = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
    script << emptySig << msg << vchPubKey << OP_CHECKSIGFROMSTACK << OP_NOT;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    BOOST_CHECK(RunBareScript(script, flagsNoNullfail, tx));
}

// ============================================================================
// PQ: Valid ML-DSA-44 signature (bare script)
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_pq_valid_signature)
{
    const std::vector<unsigned char> pqSeed = ParseHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    CKey pqKey;
    pqKey.MakeNewKeyPQ(pqSeed);
    CPubKey pqPubkey = pqKey.GetPubKey();
    BOOST_CHECK(pqPubkey.IsPQ());

    std::vector<unsigned char> msg = {'p', 'q', 't', 'e', 's', 't'};
    std::vector<unsigned char> sig = SignForCsfs(pqKey, msg, SIGHASH_ALL);
    std::vector<unsigned char> vchPubKey(pqPubkey.begin(), pqPubkey.end());

    // Verify the sig has correct size: ML_DSA_44_SIG_SIZE + 1 (hashtype)
    BOOST_CHECK_EQUAL(sig.size(), ML_DSA_44_SIG_SIZE + 1);

    CScript script;
    script << sig << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    // Use strict flags (which enforce PQ sig size = ML_DSA_44_SIG_SIZE + 1)
    BOOST_CHECK(RunBareScript(script, CSFS_FLAGS_STRICT, tx));
}

// ============================================================================
// PQ: Wrong message fails
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_pq_wrong_message)
{
    const std::vector<unsigned char> pqSeed = ParseHex("0102030405060708091011121314151617181920212223242526272829303132");
    CKey pqKey;
    pqKey.MakeNewKeyPQ(pqSeed);
    CPubKey pqPubkey = pqKey.GetPubKey();

    std::vector<unsigned char> msg = {'r', 'i', 'g', 'h', 't'};
    std::vector<unsigned char> wrongMsg = {'w', 'r', 'o', 'n', 'g'};
    std::vector<unsigned char> sig = SignForCsfs(pqKey, msg, SIGHASH_ALL);
    std::vector<unsigned char> vchPubKey(pqPubkey.begin(), pqPubkey.end());

    CScript script;
    script << sig << wrongMsg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    ScriptError err;
    BOOST_CHECK(!RunBareScript(script, CSFS_FLAGS_STRICT, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_NULLFAIL);
}

// ============================================================================
// ECDSA via P2WSH wrapper
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_p2wsh)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'w', 's', 'h'};
    std::vector<unsigned char> sig = SignForCsfs(key, msg, SIGHASH_ALL);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    // witnessScript: <msg> <pubkey> OP_CHECKSIGFROMSTACK
    CScript witnessScript;
    witnessScript << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    // Witness data: [sig] (witnessScript is appended by helper)
    std::vector<std::vector<unsigned char>> witnessData = {sig};

    CMutableTransaction mtx = BuildCsfsTestTx();
    // Set the scriptPubKey of the output being spent
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    // (The checker doesn't actually look at scriptPubKey for our test, we just need VerifyScript to work)
    CTransaction tx(mtx);

    BOOST_CHECK(RunP2WSH(witnessScript, witnessData, CSFS_FLAGS_STRICT, tx));
}

// ============================================================================
// PQ via P2WSH wrapper
// NOTE: This test validates script engine / consensus behavior only.
// In standard mempool policy, P2WSH witness items are limited to 80 bytes
// (MAX_STANDARD_P2WSH_STACK_ITEM_SIZE in policy.h), which PQ signatures
// (~2421 bytes) and PQ pubkeys (~1313 bytes) exceed.  A real PQ CSFS
// transaction would need a policy exception or a different witness version
// to be relayed by standard nodes.
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_pq_p2wsh)
{
    const std::vector<unsigned char> pqSeed = ParseHex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    CKey pqKey;
    pqKey.MakeNewKeyPQ(pqSeed);
    CPubKey pqPubkey = pqKey.GetPubKey();
    BOOST_CHECK(pqPubkey.IsPQ());

    std::vector<unsigned char> msg = {'p', 'q', 'w', 's', 'h'};
    std::vector<unsigned char> sig = SignForCsfs(pqKey, msg, SIGHASH_ALL);
    std::vector<unsigned char> vchPubKey(pqPubkey.begin(), pqPubkey.end());

    BOOST_CHECK_EQUAL(sig.size(), ML_DSA_44_SIG_SIZE + 1);

    // witnessScript: <msg> <pubkey> OP_CHECKSIGFROMSTACK
    CScript witnessScript;
    witnessScript << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    std::vector<std::vector<unsigned char>> witnessData = {sig};

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    BOOST_CHECK(RunP2WSH(witnessScript, witnessData, CSFS_FLAGS_STRICT, tx));
}

// ============================================================================
// Disabled: treated as NOP5
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_disabled_as_nop5)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'m'};
    std::vector<unsigned char> sig = {0x01};
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CScript script;
    script << sig << msg << vchPubKey << OP_CHECKSIGFROMSTACK << OP_2DROP << OP_DROP << OP_TRUE;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    BOOST_CHECK(RunBareScript(script, NO_CSFS_FLAGS, tx));
}

BOOST_AUTO_TEST_CASE(csfs_disabled_discouraged)
{
    std::vector<unsigned char> msg = {'m'};
    std::vector<unsigned char> sig = {0x01};
    std::vector<unsigned char> pk = {0x02};

    CScript script;
    script << sig << msg << pk << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    ScriptError err;
    BOOST_CHECK(!RunBareScript(script, NO_CSFS_FLAGS_DISCOURAGE, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// ============================================================================
// Stack underflow
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_stack_underflow)
{
    std::vector<unsigned char> a = {0x01};
    std::vector<unsigned char> b = {0x02};

    CScript script;
    script << a << b << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    ScriptError err;
    unsigned int flagsNoNullfail = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
    BOOST_CHECK(!RunBareScript(script, flagsNoNullfail, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ============================================================================
// Regression: ECDSA signature WITHOUT hashtype byte under non-strict flags
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_no_hashtype_nonstrict)
{
    // Under minimal flags (no STRICTENC/DERSIG), a raw ECDSA signature without
    // a trailing hashtype byte passes CheckSignatureEncodingForPubKey (which
    // only enforces encoding under strict flags). However, CheckSigFromStack
    // unconditionally calls pop_back() — stripping the last DER byte — so the
    // truncated signature will fail DER parsing in Verify().
    // This test documents that CSFS requires signatures to carry a trailing
    // hashtype byte, consistent with OP_CHECKSIG convention.
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'r', 'a', 'w'};
    std::vector<unsigned char> rawSig = SignForCsfsRaw(key, msg);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    // Minimal CSFS flags: no STRICTENC, no DERSIG, no NULLFAIL
    unsigned int minimalFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSIGFROMSTACK;

    // Raw sig (no hashtype) should fail verification (pop_back corrupts DER)
    CScript scriptFail;
    scriptFail << rawSig << msg << vchPubKey << OP_CHECKSIGFROMSTACK << OP_NOT;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    // Without NULLFAIL, failure pushes false; OP_NOT makes script succeed
    BOOST_CHECK(RunBareScript(scriptFail, minimalFlags, tx));

    // Now verify the same signature WITH hashtype byte succeeds
    std::vector<unsigned char> sigWithHashtype = rawSig;
    sigWithHashtype.push_back(SIGHASH_ALL);

    CScript scriptOk;
    scriptOk << sigWithHashtype << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    BOOST_CHECK(RunBareScript(scriptOk, minimalFlags, tx));
}

// ============================================================================
// Regression: PQ signature WITHOUT hashtype byte under non-strict flags
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_pq_no_hashtype_nonstrict)
{
    // Same test for PQ: a raw ML-DSA-44 signature (2420 bytes) without hashtype
    // byte will have its last byte stripped by pop_back(), producing 2419 bytes
    // which OQS_SIG_verify rejects (expects exactly 2420).
    const std::vector<unsigned char> pqSeed = ParseHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    CKey pqKey;
    pqKey.MakeNewKeyPQ(pqSeed);
    CPubKey pqPubkey = pqKey.GetPubKey();
    BOOST_CHECK(pqPubkey.IsPQ());

    std::vector<unsigned char> msg = {'p', 'q', 'r', 'a', 'w'};
    std::vector<unsigned char> rawSig = SignForCsfsRaw(pqKey, msg);
    std::vector<unsigned char> vchPubKey(pqPubkey.begin(), pqPubkey.end());

    BOOST_CHECK_EQUAL(rawSig.size(), ML_DSA_44_SIG_SIZE); // 2420, no hashtype

    // Minimal CSFS flags: no STRICTENC, no DERSIG, no NULLFAIL
    unsigned int minimalFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSIGFROMSTACK;

    // Raw PQ sig (no hashtype) should fail verification (pop_back corrupts sig)
    CScript scriptFail;
    scriptFail << rawSig << msg << vchPubKey << OP_CHECKSIGFROMSTACK << OP_NOT;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    // Without NULLFAIL, failure pushes false; OP_NOT makes script succeed
    BOOST_CHECK(RunBareScript(scriptFail, minimalFlags, tx));

    // Now verify the same signature WITH hashtype byte succeeds
    std::vector<unsigned char> sigWithHashtype = rawSig;
    sigWithHashtype.push_back(SIGHASH_ALL);

    CScript scriptOk;
    scriptOk << sigWithHashtype << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    BOOST_CHECK(RunBareScript(scriptOk, minimalFlags, tx));
}

// ============================================================================
// Regression: ECDSA signature WITHOUT hashtype byte under strict flags
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_ecdsa_no_hashtype_strict)
{
    // Under strict flags, a raw ECDSA signature without hashtype is rejected
    // by CheckSignatureEncodingForPubKey before reaching CheckSigFromStack.
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> msg = {'s', 't', 'r'};
    std::vector<unsigned char> rawSig = SignForCsfsRaw(key, msg);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CScript script;
    script << rawSig << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    ScriptError err;
    BOOST_CHECK(!RunBareScript(script, CSFS_FLAGS_STRICT, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_HASHTYPE);
}

// ============================================================================
// Regression: PQ signature WITHOUT hashtype byte under strict flags
// ============================================================================

BOOST_AUTO_TEST_CASE(csfs_pq_no_hashtype_strict)
{
    // Under strict flags, a raw PQ signature (2420 bytes instead of 2421)
    // is rejected by CheckSignatureEncodingForPubKey (size != ML_DSA_44_SIG_SIZE + 1).
    const std::vector<unsigned char> pqSeed = ParseHex("0102030405060708091011121314151617181920212223242526272829303132");
    CKey pqKey;
    pqKey.MakeNewKeyPQ(pqSeed);
    CPubKey pqPubkey = pqKey.GetPubKey();

    std::vector<unsigned char> msg = {'p', 'q', 's'};
    std::vector<unsigned char> rawSig = SignForCsfsRaw(pqKey, msg);
    std::vector<unsigned char> vchPubKey(pqPubkey.begin(), pqPubkey.end());

    BOOST_CHECK_EQUAL(rawSig.size(), ML_DSA_44_SIG_SIZE); // no hashtype

    CScript script;
    script << rawSig << msg << vchPubKey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mtx = BuildCsfsTestTx();
    CTransaction tx(mtx);

    ScriptError err;
    BOOST_CHECK(!RunBareScript(script, CSFS_FLAGS_STRICT, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_DER);
}

BOOST_AUTO_TEST_SUITE_END()
