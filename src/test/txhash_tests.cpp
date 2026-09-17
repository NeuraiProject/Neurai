// Copyright (c) 2023-2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"
#include "streams.h"
#include "version.h"
#include "utilstrencodings.h"

#include <vector>
#include <stdint.h>

#include <boost/test/unit_test.hpp>

// Flags for OP_TXHASH testing
static constexpr script_verify_flags TXHASH_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TXHASH;
static constexpr script_verify_flags TXHASH_FLAGS_DISCOURAGE = TXHASH_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

// Field selector constants (must match interpreter.cpp)
static const unsigned char TXHASH_VERSION       = (1 << 0); // 0x01
static const unsigned char TXHASH_LOCKTIME      = (1 << 1); // 0x02
static const unsigned char TXHASH_PREVOUTS      = (1 << 2); // 0x04
static const unsigned char TXHASH_SEQUENCES     = (1 << 3); // 0x08
static const unsigned char TXHASH_OUTPUTS       = (1 << 4); // 0x10
static const unsigned char TXHASH_CUR_PREVOUT   = (1 << 5); // 0x20
static const unsigned char TXHASH_CUR_SEQUENCE  = (1 << 6); // 0x40
static const unsigned char TXHASH_INPUT_INDEX   = (1 << 7); // 0x80

namespace {

// Helper: build a simple transaction with configurable inputs/outputs
CMutableTransaction BuildTestTx(int numInputs = 1, int numOutputs = 1)
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
        vout.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, (unsigned char)(i + 1)) << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(vout);
    }

    return tx;
}

// Helper: run OP_TXHASH with a given selector on a transaction, return the result hash
// Returns true on success, false on script failure
bool RunTxHash(const CTransaction& tx, unsigned int nIn, unsigned char selector,
               std::vector<unsigned char>& resultHash, ScriptError* err = nullptr)
{
    // Script: <selector> OP_TXHASH
    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(1, selector) << OP_TXHASH << OP_TRUE;

    CScript scriptSig;
    CScriptWitness witness;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, nIn, 0, txdata);

    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, scriptPubKey, TXHASH_FLAGS, checker, SIGVERSION_BASE, &serror);

    if (err) *err = serror;

    if (result && stack.size() >= 1) {
        // The hash is on top of the stack (below OP_TRUE's result)
        // With script: <selector> TXHASH TRUE, stack will be [hash, true]
        // Actually: TXHASH replaces selector with hash, then TRUE pushes 1
        // Stack: [hash, 0x01]
        resultHash = stack[0]; // hash is at bottom
        return true;
    }
    return false;
}

// Helper: run OP_TXHASH via GetTxFieldHash directly (for precise testing)
bool DirectTxFieldHash(const CTransaction& tx, unsigned int nIn, unsigned char selector,
                       std::vector<unsigned char>& result, bool useCache = true)
{
    if (useCache) {
        PrecomputedTransactionData txdata(tx);
        TransactionSignatureChecker checker(&tx, nIn, 0, txdata);
        return checker.GetTxFieldHash(selector, result);
    } else {
        TransactionSignatureChecker checker(&tx, nIn, 0);
        return checker.GetTxFieldHash(selector, result);
    }
}

// Helper: compute expected double-SHA256 of data
uint256 DoubleHash(const unsigned char* data, size_t len)
{
    CHash256 hasher;
    hasher.Write(data, len);
    uint256 result;
    hasher.Finalize(result.begin());
    return result;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(txhash_tests, BasicTestingSetup)

// ============================================================================
// Basic selector validation tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_selector_zero_fails)
{
    // Selector 0x00 must fail (no fields selected)
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(!DirectTxFieldHash(tx, 0, 0x00, result));
}

BOOST_AUTO_TEST_CASE(txhash_selector_all_fields_succeeds)
{
    // Selector 0xFF (all fields) must succeed
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, 0xFF, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);
}

BOOST_AUTO_TEST_CASE(txhash_selector_must_be_one_byte)
{
    // Selector of 2+ bytes must fail via EvalScript (size != 1 check)
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    CScript scriptPubKey;
    std::vector<unsigned char> twoByteSelector = {0x01, 0x02};
    scriptPubKey << twoByteSelector << OP_TXHASH;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    BOOST_CHECK(!EvalScript(stack, scriptPubKey, TXHASH_FLAGS, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_TXHASH);
}

BOOST_AUTO_TEST_CASE(txhash_empty_stack_fails)
{
    // Empty stack must fail
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    CScript scriptPubKey;
    scriptPubKey << OP_TXHASH;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    BOOST_CHECK(!EvalScript(stack, scriptPubKey, TXHASH_FLAGS, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ============================================================================
// Individual field selector tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_version_only)
{
    // Selector 0x01 -> only version
    CMutableTransaction mtx = BuildTestTx();
    mtx.nVersion = 2;
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_VERSION, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    // Compute expected: double-SHA256 of little-endian uint32_t version=2
    uint32_t ver = 2;
    uint256 expected = DoubleHash((const unsigned char*)&ver, 4);
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_locktime_only)
{
    // Selector 0x02 -> only locktime
    CMutableTransaction mtx = BuildTestTx();
    mtx.nLockTime = 500000;
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_LOCKTIME, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    uint32_t locktime = 500000;
    uint256 expected = DoubleHash((const unsigned char*)&locktime, 4);
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_prevouts_only)
{
    // Selector 0x04 -> hashPrevouts
    CMutableTransaction mtx = BuildTestTx(2, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_PREVOUTS, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    // Compute expected: double-SHA256 of all serialized prevouts
    CHash256 prevoutsHasher;
    for (const auto& txin : tx.vin) {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << txin.prevout;
        prevoutsHasher.Write((const unsigned char*)s.data(), s.size());
    }
    uint256 expectedSubhash;
    prevoutsHasher.Finalize(expectedSubhash.begin());

    // Final hash wraps the sub-hash in another double-SHA256
    uint256 expected = DoubleHash(expectedSubhash.begin(), 32);
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_sequences_only)
{
    // Selector 0x08 -> hashSequences
    CMutableTransaction mtx = BuildTestTx(2, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_SEQUENCES, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    CHash256 seqHasher;
    for (const auto& txin : tx.vin) {
        uint32_t nSeq = txin.nSequence;
        seqHasher.Write((const unsigned char*)&nSeq, 4);
    }
    uint256 expectedSubhash;
    seqHasher.Finalize(expectedSubhash.begin());
    uint256 expected = DoubleHash(expectedSubhash.begin(), 32);
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_outputs_only)
{
    // Selector 0x10 -> hashOutputs
    CMutableTransaction mtx = BuildTestTx(1, 2);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_OUTPUTS, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    CHash256 outHasher;
    for (const auto& txout : tx.vout) {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << txout;
        outHasher.Write((const unsigned char*)s.data(), s.size());
    }
    uint256 expectedSubhash;
    outHasher.Finalize(expectedSubhash.begin());
    uint256 expected = DoubleHash(expectedSubhash.begin(), 32);
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_cur_prevout_only)
{
    // Selector 0x20 -> current input's prevout
    CMutableTransaction mtx = BuildTestTx(2, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_CUR_PREVOUT, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    // Expected: double-SHA256 of serialized prevout for input 0
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << tx.vin[0].prevout;
    uint256 expected = DoubleHash((const unsigned char*)s.data(), s.size());
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_cur_sequence_only)
{
    // Selector 0x40 -> current input's sequence
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_CUR_SEQUENCE, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    uint32_t nSeq = tx.vin[0].nSequence;
    uint256 expected = DoubleHash((const unsigned char*)&nSeq, 4);
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_input_index_only)
{
    // Selector 0x80 -> input index
    CMutableTransaction mtx = BuildTestTx(3, 1);
    CTransaction tx(mtx);

    for (unsigned int i = 0; i < 3; i++) {
        std::vector<unsigned char> result;
        BOOST_CHECK(DirectTxFieldHash(tx, i, TXHASH_INPUT_INDEX, result));
        BOOST_CHECK_EQUAL(result.size(), 32u);

        uint32_t idx = i;
        uint256 expected = DoubleHash((const unsigned char*)&idx, 4);
        BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
    }
}

// ============================================================================
// Combination tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_version_and_locktime)
{
    // Selector 0x03 -> version + locktime
    CMutableTransaction mtx = BuildTestTx();
    mtx.nVersion = 2;
    mtx.nLockTime = 123456;
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_VERSION | TXHASH_LOCKTIME, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);

    // Expected: double-SHA256(version_le32 || locktime_le32)
    CHash256 hasher;
    uint32_t ver = 2;
    uint32_t lt = 123456;
    hasher.Write((const unsigned char*)&ver, 4);
    hasher.Write((const unsigned char*)&lt, 4);
    uint256 expected;
    hasher.Finalize(expected.begin());
    BOOST_CHECK(std::vector<unsigned char>(expected.begin(), expected.end()) == result);
}

BOOST_AUTO_TEST_CASE(txhash_determinism)
{
    // Same transaction + selector must produce identical hash
    CMutableTransaction mtx = BuildTestTx(2, 2);
    CTransaction tx(mtx);

    std::vector<unsigned char> result1, result2;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, 0xFF, result1));
    BOOST_CHECK(DirectTxFieldHash(tx, 0, 0xFF, result2));
    BOOST_CHECK(result1 == result2);
}

BOOST_AUTO_TEST_CASE(txhash_different_selectors_different_hashes)
{
    // Different selectors must produce different hashes
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> r1, r2;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_VERSION, r1));
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_LOCKTIME, r2));
    BOOST_CHECK(r1 != r2);
}

BOOST_AUTO_TEST_CASE(txhash_different_inputs_different_index)
{
    // TXHASH_INPUT_INDEX for input 0 vs input 1 must differ
    CMutableTransaction mtx = BuildTestTx(2, 1);
    CTransaction tx(mtx);

    std::vector<unsigned char> r0, r1;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_INPUT_INDEX, r0));
    BOOST_CHECK(DirectTxFieldHash(tx, 1, TXHASH_INPUT_INDEX, r1));
    BOOST_CHECK(r0 != r1);
}

// ============================================================================
// Cache consistency tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_cache_vs_nocache_prevouts)
{
    // Result must be identical with and without PrecomputedTransactionData cache
    CMutableTransaction mtx = BuildTestTx(3, 2);
    CTransaction tx(mtx);

    std::vector<unsigned char> cached, nocache;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_PREVOUTS, cached, true));
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_PREVOUTS, nocache, false));
    BOOST_CHECK(cached == nocache);
}

BOOST_AUTO_TEST_CASE(txhash_cache_vs_nocache_sequences)
{
    CMutableTransaction mtx = BuildTestTx(3, 2);
    CTransaction tx(mtx);

    std::vector<unsigned char> cached, nocache;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_SEQUENCES, cached, true));
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_SEQUENCES, nocache, false));
    BOOST_CHECK(cached == nocache);
}

BOOST_AUTO_TEST_CASE(txhash_cache_vs_nocache_outputs)
{
    CMutableTransaction mtx = BuildTestTx(3, 2);
    CTransaction tx(mtx);

    std::vector<unsigned char> cached, nocache;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_OUTPUTS, cached, true));
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_OUTPUTS, nocache, false));
    BOOST_CHECK(cached == nocache);
}

BOOST_AUTO_TEST_CASE(txhash_cache_vs_nocache_all_fields)
{
    // Full 0xFF selector: cached vs uncached must match
    CMutableTransaction mtx = BuildTestTx(3, 3);
    CTransaction tx(mtx);

    std::vector<unsigned char> cached, nocache;
    BOOST_CHECK(DirectTxFieldHash(tx, 1, 0xFF, cached, true));
    BOOST_CHECK(DirectTxFieldHash(tx, 1, 0xFF, nocache, false));
    BOOST_CHECK(cached == nocache);
}

// ============================================================================
// Bounds check / edge case tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_cur_prevout_out_of_range)
{
    // nIn out of range must fail for TXHASH_CUR_PREVOUT
    CMutableTransaction mtx = BuildTestTx(1, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    // nIn=5, tx has only 1 input
    BOOST_CHECK(!DirectTxFieldHash(tx, 5, TXHASH_CUR_PREVOUT, result));
}

BOOST_AUTO_TEST_CASE(txhash_cur_sequence_out_of_range)
{
    // nIn out of range must fail for TXHASH_CUR_SEQUENCE
    CMutableTransaction mtx = BuildTestTx(1, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(!DirectTxFieldHash(tx, 5, TXHASH_CUR_SEQUENCE, result));
}

BOOST_AUTO_TEST_CASE(txhash_input_index_out_of_range)
{
    // nIn out of range must fail for TXHASH_INPUT_INDEX
    CMutableTransaction mtx = BuildTestTx(1, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(!DirectTxFieldHash(tx, 5, TXHASH_INPUT_INDEX, result));
}

BOOST_AUTO_TEST_CASE(txhash_zero_outputs_with_outputs_selector)
{
    // TX with 0 outputs + TXHASH_OUTPUTS should still succeed
    // (hash of empty set of outputs)
    CMutableTransaction mtx = BuildTestTx(1, 0);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_OUTPUTS, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);
}

BOOST_AUTO_TEST_CASE(txhash_single_input)
{
    // TX with 1 input + TXHASH_CUR_PREVOUT
    CMutableTransaction mtx = BuildTestTx(1, 1);
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_CUR_PREVOUT, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);
}

// ============================================================================
// Flag activation tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_disabled_treated_as_nop)
{
    // Without SCRIPT_VERIFY_TXHASH, OP_TXHASH is NOP6 and script succeeds
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    // Script: <0x01> OP_TXHASH OP_TRUE
    // Without TXHASH flag: NOP6 is a no-op, stack = [0x01, 0x01], script succeeds
    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(1, 0x01) << OP_TXHASH << OP_TRUE;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    script_verify_flags flags_no_txhash = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    BOOST_CHECK(EvalScript(stack, scriptPubKey, flags_no_txhash, checker, SIGVERSION_BASE, &serror));
}

BOOST_AUTO_TEST_CASE(txhash_disabled_discourage_nops_fails)
{
    // Without SCRIPT_VERIFY_TXHASH + DISCOURAGE_UPGRADABLE_NOPS: NOP6 fails
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(1, 0x01) << OP_TXHASH;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    script_verify_flags flags_discourage = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    BOOST_CHECK(!EvalScript(stack, scriptPubKey, flags_discourage, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// ============================================================================
// EvalScript integration tests
// ============================================================================

BOOST_AUTO_TEST_CASE(txhash_evalscript_pushes_hash)
{
    // Verify OP_TXHASH pushes a 32-byte hash onto the stack
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    // Script: <0xFF> OP_TXHASH OP_SIZE <32> OP_EQUALVERIFY OP_TRUE
    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(1, 0xFF) << OP_TXHASH;
    scriptPubKey << OP_SIZE << CScriptNum(32) << OP_EQUALVERIFY << OP_TRUE;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    BOOST_CHECK(EvalScript(stack, scriptPubKey, TXHASH_FLAGS, checker, SIGVERSION_BASE, &serror));
}

BOOST_AUTO_TEST_CASE(txhash_equalverify_same_tx)
{
    // Two TXHASH calls with same selector on same tx must produce equal results
    // Script: <0x01> OP_TXHASH <0x01> OP_TXHASH OP_EQUALVERIFY OP_TRUE
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);

    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(1, 0x01) << OP_TXHASH;
    scriptPubKey << std::vector<unsigned char>(1, 0x01) << OP_TXHASH;
    scriptPubKey << OP_EQUALVERIFY << OP_TRUE;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    BOOST_CHECK(EvalScript(stack, scriptPubKey, TXHASH_FLAGS, checker, SIGVERSION_BASE, &serror));
}

BOOST_AUTO_TEST_CASE(txhash_covenant_output_check)
{
    // Covenant pattern: OP_TXHASH + OP_EQUAL to enforce specific outputs
    // Compute the expected hash for TXHASH_OUTPUTS, embed it in the script,
    // and verify the script succeeds
    CMutableTransaction mtx = BuildTestTx(1, 1);
    CTransaction tx(mtx);

    // Get the expected hash
    std::vector<unsigned char> expectedHash;
    BOOST_CHECK(DirectTxFieldHash(tx, 0, TXHASH_OUTPUTS, expectedHash));

    // Script: <0x10> OP_TXHASH <expectedHash> OP_EQUAL
    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>(1, TXHASH_OUTPUTS) << OP_TXHASH;
    scriptPubKey << expectedHash << OP_EQUAL;

    ScriptError serror;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);
    std::vector<std::vector<unsigned char>> stack;

    BOOST_CHECK(EvalScript(stack, scriptPubKey, TXHASH_FLAGS, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(stack.size(), 1u);
    // Top of stack should be true (OP_EQUAL succeeded)
    BOOST_CHECK(CastToBool(stack.back()));
}


// Independent Python fingerprints cover the ordered results of ALL 255 masks,
// rather than comparing only two paths that could share the same hashing bug.
BOOST_AUTO_TEST_CASE(txhash_all_masks_family_vectors)
{
    struct Vector { const char* script; const char* fingerprint; };
    const Vector vectors[] = {
        {"76a914000102030405060708090a0b0c0d0e0f1011121388ac", "2ea01813056daa5fac482cbc29f7a95a00ed2ec1fa5dc825a0569be55e7a17a8"},
        {"76a914000102030405060708090a0b0c0d0e0f1011121388acc015786e61740843545641535345540065cd1d0000000075", "31c98646f6bab441d3a04ed0cf9d36bdf914d698e73c0c713ca297a85dece712"},
        {"5120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "6bde33c1a598eb83a5e32d2c0fba30247b78e8aeb79f8960178f2e0647678578"},
        {"5120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc015786e61740843545641535345540065cd1d0000000075", "d17a2ab61bd7d59770f4f044d53acd1b07cd002f6bd97207b51184c2bd87dac5"},
        {"5220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "35fce58bc56a0b128ab7db74d973fb67c7f5d88564a4789eacc13fe039b6afde"},
        {"5220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc015786e61740843545641535345540065cd1d0000000075", "5bb44f0a1e0eed172ecf130271263a6b6bae7d60ab52fca047316d67f1d20617"},
        {"5320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "ada1492ce975e06aaa3e83186454608d2a096f4166100bbed27dc6e203682759"},
        {"5320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc015786e61740843545641535345540065cd1d0000000075", "61cb1b03b3368ffbe5d0e31080edc7ae2b5cbe48ad42ed133a479e8e24c0394a"},
    };
    for (const auto& vector : vectors) {
        CMutableTransaction original;
        original.nVersion = 3;
        original.nLockTime = 123;
        original.vin.resize(2);
        original.vin[0].prevout = COutPoint(uint256S("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"), 7);
        original.vin[1].prevout = COutPoint(uint256S("3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"), 9);
        original.vin[0].nSequence = 0xfffffffe;
        original.vin[1].nSequence = 0xfffffffd;
        const auto script = ParseHex(vector.script);
        original.vout.emplace_back(100000, CScript(script.begin(), script.end()));
        original.vout.emplace_back(200000, CScript() << OP_TRUE);
        original.vrefin.emplace_back(uint256S("aa"), 7);
        original.vrefin.emplace_back(uint256S("bb"), 9);
        const CTransaction baseline(original);
        std::vector<std::vector<unsigned char>> expected(256);
        for (bool cached : {false, true}) {
            CSHA256 fingerprint;
            const PrecomputedTransactionData data(baseline);
            const TransactionSignatureChecker withCache(&baseline, 1, 0, data);
            const TransactionSignatureChecker withoutCache(&baseline, 1, 0);
            for (int mask = 1; mask <= 255; ++mask) {
                BOOST_TEST_CONTEXT("fingerprint=" << vector.fingerprint << " mask=" << mask << " cached=" << cached) {
                    std::vector<std::vector<unsigned char>> stack;
                    ScriptError error;
                    const CScript query = CScript() << std::vector<unsigned char>{static_cast<unsigned char>(mask)} << OP_TXHASH;
                    BOOST_REQUIRE(EvalScript(stack, query, TXHASH_FLAGS, cached ? withCache : withoutCache, SIGVERSION_BASE, &error));
                    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
                    BOOST_REQUIRE_EQUAL(stack.back().size(), 32U);
                    fingerprint.Write(stack.back().data(), 32);
                    if (!cached) expected[mask] = stack.back();
                    else BOOST_CHECK(stack.back() == expected[mask]);
                }
            }
            unsigned char digest[32];
            fingerprint.Finalize(digest);
            BOOST_CHECK(HexStr(digest, digest + 32) == vector.fingerprint);
        }
        const unsigned char affected[] = {1, 2, 4, 0x24, 8, 0x48, 16, 16, 0, 0, 0, 0, 0xe0, 16};
        for (int mutation = 0; mutation < 14; ++mutation) {
            CMutableTransaction changed = original;
            unsigned int index = 1;
            switch (mutation) {
            case 0: changed.nVersion = 2; break;
            case 1: ++changed.nLockTime; break;
            case 2: ++changed.vin[0].prevout.n; break;
            case 3: ++changed.vin[1].prevout.n; break;
            case 4: ++changed.vin[0].nSequence; break;
            case 5: ++changed.vin[1].nSequence; break;
            case 6: changed.vout[0].scriptPubKey[changed.vout[0].scriptPubKey.size() - 2] ^= 1; break;
            case 7: ++changed.vout[0].nValue; break;
            case 8: std::swap(changed.vrefin[0], changed.vrefin[1]); break;
            case 9: changed.vrefin.pop_back(); break;
            case 10: changed.vin[1].scriptWitness.stack = {{1, 2, 3}}; break;
            case 11: changed.vin[1].scriptSig << OP_TRUE; break;
            case 12: index = 0; break;
            case 13: std::swap(changed.vout[0], changed.vout[1]); break;
            }
            const CTransaction tx(changed);
            const PrecomputedTransactionData data(tx);
            const TransactionSignatureChecker withCache(&tx, index, 0, data);
            const TransactionSignatureChecker withoutCache(&tx, index, 0);
            for (int mask = 1; mask <= 255; ++mask) for (const auto* checker : {&withCache, &withoutCache}) {
                BOOST_TEST_CONTEXT("fingerprint=" << vector.fingerprint << " mutation=" << mutation << " mask=" << mask) {
                    std::vector<unsigned char> actual;
                    BOOST_REQUIRE(checker->GetTxFieldHash(mask, actual));
                    BOOST_CHECK_EQUAL(actual != expected[mask], (mask & affected[mutation]) != 0);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
