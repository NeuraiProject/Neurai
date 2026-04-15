// Copyright (c) 2023-2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"
#include "streams.h"
#include "version.h"

#include <vector>
#include <stdint.h>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags CTV_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHECKTEMPLATEVERIFY;
static constexpr script_verify_flags CTV_FLAGS_DISCOURAGE = CTV_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags NO_CTV_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_CTV_FLAGS_DISCOURAGE = NO_CTV_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

namespace {

CMutableTransaction BuildCtvTestTx(int numInputs = 1, int numOutputs = 1)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 500000;

    for (int i = 0; i < numInputs; i++) {
        CTxIn vin;
        vin.prevout.hash = uint256S("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        vin.prevout.n = i;
        vin.nSequence = 0xfffffffe;
        tx.vin.push_back(vin);
    }

    for (int i = 0; i < numOutputs; i++) {
        CTxOut vout;
        vout.nValue = (i + 1) * 1000 * COIN;
        vout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                            << std::vector<unsigned char>(20, (unsigned char)(i + 1))
                            << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(vout);
    }

    return tx;
}

// Recompute the CTV hash (BIP 119 DefaultCheckTemplateVerifyHash) for testing.
// This must match the implementation in interpreter.cpp.
uint256 ComputeCtvHash(const CTransaction& tx, uint32_t nIn)
{
    CSHA256 ss;

    uint32_t nVersion = tx.nVersion;
    ss.Write((const unsigned char*)&nVersion, 4);

    uint32_t nLockTime = tx.nLockTime;
    ss.Write((const unsigned char*)&nLockTime, 4);

    bool hasNonEmptyScriptSig = false;
    for (const auto& txin : tx.vin) {
        if (txin.scriptSig.size() > 0) {
            hasNonEmptyScriptSig = true;
            break;
        }
    }
    if (hasNonEmptyScriptSig) {
        CSHA256 scriptSigsHash;
        for (const auto& txin : tx.vin) {
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << txin.scriptSig;
            scriptSigsHash.Write((const unsigned char*)s.data(), s.size());
        }
        unsigned char scriptSigsResult[CSHA256::OUTPUT_SIZE];
        scriptSigsHash.Finalize(scriptSigsResult);
        ss.Write(scriptSigsResult, CSHA256::OUTPUT_SIZE);
    }

    uint32_t nInputs = tx.vin.size();
    ss.Write((const unsigned char*)&nInputs, 4);

    CSHA256 sequencesHash;
    for (const auto& txin : tx.vin) {
        uint32_t nSequence = txin.nSequence;
        sequencesHash.Write((const unsigned char*)&nSequence, 4);
    }
    unsigned char seqResult[CSHA256::OUTPUT_SIZE];
    sequencesHash.Finalize(seqResult);
    ss.Write(seqResult, CSHA256::OUTPUT_SIZE);

    uint32_t nOutputs = tx.vout.size();
    ss.Write((const unsigned char*)&nOutputs, 4);

    CSHA256 outputsHash;
    for (const auto& txout : tx.vout) {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << txout;
        outputsHash.Write((const unsigned char*)s.data(), s.size());
    }
    unsigned char outResult[CSHA256::OUTPUT_SIZE];
    outputsHash.Finalize(outResult);
    ss.Write(outResult, CSHA256::OUTPUT_SIZE);

    uint32_t inputIndex = nIn;
    ss.Write((const unsigned char*)&inputIndex, 4);

    uint256 result;
    ss.Finalize(result.begin());
    return result;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(ctv_tests, BasicTestingSetup)

// ============================================================================
// Correct hash succeeds
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_correct_hash_succeeds)
{
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    uint256 ctvHash = ComputeCtvHash(tx, 0);
    std::vector<unsigned char> vchHash(ctvHash.begin(), ctvHash.end());

    // Script: <hash> OP_CHECKTEMPLATEVERIFY OP_DROP OP_TRUE
    // (CTV is NOP-style: it does NOT pop the hash, so we DROP it manually)
    CScript script;
    script << vchHash << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(result);
}

// ============================================================================
// Wrong hash fails
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_wrong_hash_fails)
{
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    // Use a bogus 32-byte hash
    std::vector<unsigned char> wrongHash(32, 0xff);

    CScript script;
    script << wrongHash << OP_CHECKTEMPLATEVERIFY;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);
}

// ============================================================================
// Non-32-byte argument: NOP behavior (BIP 119 upgrade semantics)
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_non32byte_arg_acts_as_nop)
{
    // Without DISCOURAGE_UPGRADABLE_NOPS, non-32-byte arg should succeed (NOP)
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> shortArg(20, 0xaa);

    CScript script;
    script << shortArg << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(ctv_non32byte_arg_discouraged_by_policy)
{
    // With DISCOURAGE_UPGRADABLE_NOPS, non-32-byte arg fails by policy
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> shortArg(20, 0xaa);

    CScript script;
    script << shortArg << OP_CHECKTEMPLATEVERIFY;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, CTV_FLAGS_DISCOURAGE, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(ctv_empty_arg_acts_as_nop)
{
    // Empty argument (0 bytes) should also be treated as NOP
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> emptyArg;

    CScript script;
    script << OP_0 << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(result);
}

// ============================================================================
// Disabled (treated as NOP4)
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_disabled_as_nop4)
{
    // Without CTV flag, OP_CHECKTEMPLATEVERIFY acts as NOP4
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> anyArg(32, 0xbb);

    CScript script;
    script << anyArg << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

    ScriptError serror;
    TransactionSignatureChecker checker(&tx, 0, 0);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, NO_CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(ctv_disabled_discouraged)
{
    // Without CTV flag but with DISCOURAGE_UPGRADABLE_NOPS, NOP4 is rejected
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> anyArg(32, 0xbb);

    CScript script;
    script << anyArg << OP_CHECKTEMPLATEVERIFY;

    ScriptError serror;
    TransactionSignatureChecker checker(&tx, 0, 0);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, NO_CTV_FLAGS_DISCOURAGE, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// ============================================================================
// Empty stack fails
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_empty_stack_fails)
{
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    CScript script;
    script << OP_CHECKTEMPLATEVERIFY;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ============================================================================
// Cache equivalence: result with/without PrecomputedTransactionData must match
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_cache_equivalence)
{
    CMutableTransaction mtx = BuildCtvTestTx(3, 2);
    CTransaction tx(mtx);

    uint256 ctvHash = ComputeCtvHash(tx, 0);
    std::vector<unsigned char> vchHash(ctvHash.begin(), ctvHash.end());

    // With cache
    {
        CScript script;
        script << vchHash << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

        PrecomputedTransactionData txdata(tx);
        TransactionSignatureChecker checker(&tx, 0, 0, txdata);

        ScriptError serror;
        std::vector<std::vector<unsigned char>> stack;
        bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
        BOOST_CHECK(result);
    }

    // Without cache
    {
        CScript script;
        script << vchHash << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

        TransactionSignatureChecker checker(&tx, 0, 0);

        ScriptError serror;
        std::vector<std::vector<unsigned char>> stack;
        bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
        BOOST_CHECK(result);
    }
}

// ============================================================================
// Multiple inputs: hash differs per input index
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_different_input_index)
{
    CMutableTransaction mtx = BuildCtvTestTx(3, 2);
    CTransaction tx(mtx);

    uint256 hash0 = ComputeCtvHash(tx, 0);
    uint256 hash1 = ComputeCtvHash(tx, 1);
    uint256 hash2 = ComputeCtvHash(tx, 2);

    // Each input index produces a different hash
    BOOST_CHECK(hash0 != hash1);
    BOOST_CHECK(hash1 != hash2);
    BOOST_CHECK(hash0 != hash2);

    // Verify each hash is accepted at its corresponding input
    for (uint32_t i = 0; i < 3; i++) {
        uint256 h = ComputeCtvHash(tx, i);
        std::vector<unsigned char> vchHash(h.begin(), h.end());

        CScript script;
        script << vchHash << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

        PrecomputedTransactionData txdata(tx);
        TransactionSignatureChecker checker(&tx, i, 0, txdata);

        ScriptError serror;
        std::vector<std::vector<unsigned char>> stack;
        bool result = EvalScript(stack, script, CTV_FLAGS, checker, SIGVERSION_BASE, &serror);
        BOOST_CHECK(result);
    }
}

// ============================================================================
// P2WSH wrapper: CTV inside a witness script
// ============================================================================

BOOST_AUTO_TEST_CASE(ctv_p2wsh)
{
    CMutableTransaction mtx = BuildCtvTestTx();
    CTransaction tx(mtx);

    uint256 ctvHash = ComputeCtvHash(tx, 0);
    std::vector<unsigned char> vchHash(ctvHash.begin(), ctvHash.end());

    // witnessScript: <hash> OP_CHECKTEMPLATEVERIFY OP_DROP OP_TRUE
    CScript witnessScript;
    witnessScript << vchHash << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;

    // Witness: [] + witnessScript (CTV doesn't need witness data items)
    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

    // P2WSH scriptPubKey
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(scriptHash);

    CScript scriptSig;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    ScriptError serror;
    bool result = VerifyScript(scriptSig, scriptPubKey, &witness, CTV_FLAGS, checker, &serror);
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_SUITE_END()
