// Copyright (c) 2023-2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/standard.h"
#include "data/txhash_csfs_vectors.json.h"
#include <univalue.h>
#include "script/script.h"
#include "script/script_error.h"
#include "hash.h"
#include "crypto/common.h"
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
        vin.scriptWitness.stack = {{1}}; // exercise populated BIP143 caches
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
bool RunTxHash(const CTransaction& tx, unsigned int nIn, uint16_t selector,
               std::vector<unsigned char>& resultHash, ScriptError* err = nullptr)
{
    // Script: <selector> OP_TXHASH
    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>{static_cast<unsigned char>(selector), static_cast<unsigned char>(selector >> 8)} << OP_TXHASH << OP_TRUE;

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
bool DirectTxFieldHash(const CTransaction& tx, unsigned int nIn, uint16_t selector,
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

uint256 ExpectedHash(uint16_t mask, const unsigned char* data, size_t len)
{
    const auto tag = ParseHex("618cd8231ef0cfb834a51353a65ca5a7442562307a1855525e894a2dd1dcddee");
    const unsigned char selector[] = {static_cast<unsigned char>(mask), static_cast<unsigned char>(mask >> 8)};
    uint256 result;
    CSHA256().Write(tag.data(), tag.size()).Write(tag.data(), tag.size()).Write(selector, 2).Write(data, len).Finalize(result.begin());
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
    // All nine defined bits must succeed
    CMutableTransaction mtx = BuildTestTx();
    CTransaction tx(mtx);
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectTxFieldHash(tx, 0, 0x1FF, result));
    BOOST_CHECK_EQUAL(result.size(), 32u);
}

BOOST_AUTO_TEST_CASE(txhash_selector_reserved_bits_fail)
{
    // Bit 9 is reserved even though the selector has the correct length.
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

    // Tagged hash of selector and little-endian uint32_t version=2
    unsigned char ver[4]; WriteLE32(ver, 2);
    uint256 expected = ExpectedHash(1, (const unsigned char*)&ver, 4);
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

    unsigned char locktime[4]; WriteLE32(locktime, 500000);
    uint256 expected = ExpectedHash(2, (const unsigned char*)&locktime, 4);
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

    // Final tagged hash commits to the selector and the sub-hash.
    uint256 expected = ExpectedHash(4, expectedSubhash.begin(), 32);
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
        unsigned char nSeq[4]; WriteLE32(nSeq, txin.nSequence);
        seqHasher.Write((const unsigned char*)&nSeq, 4);
    }
    uint256 expectedSubhash;
    seqHasher.Finalize(expectedSubhash.begin());
    uint256 expected = ExpectedHash(8, expectedSubhash.begin(), 32);
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
    uint256 expected = ExpectedHash(16, expectedSubhash.begin(), 32);
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

    // Tagged hash of selector and serialized prevout for input 0
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << tx.vin[0].prevout;
    uint256 expected = ExpectedHash(32, (const unsigned char*)s.data(), s.size());
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

    unsigned char nSeq[4]; WriteLE32(nSeq, tx.vin[0].nSequence);
    uint256 expected = ExpectedHash(64, (const unsigned char*)&nSeq, 4);
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

        unsigned char idx[4]; WriteLE32(idx, i);
        uint256 expected = ExpectedHash(128, (const unsigned char*)&idx, 4);
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

    CDataStream fields(SER_GETHASH, 0);
    fields << uint32_t{2} << uint32_t{123456};
    const auto expected = ExpectedHash(3, reinterpret_cast<const unsigned char*>(fields.data()), fields.size());
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
    scriptPubKey << std::vector<unsigned char>{0x01, 0x00} << OP_TXHASH << OP_TRUE;

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
    scriptPubKey << std::vector<unsigned char>{0x01, 0x00} << OP_TXHASH;

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
    scriptPubKey << std::vector<unsigned char>{0xff, 0x01} << OP_TXHASH;
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
    scriptPubKey << std::vector<unsigned char>{0x01, 0x00} << OP_TXHASH;
    scriptPubKey << std::vector<unsigned char>{0x01, 0x00} << OP_TXHASH;
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
    scriptPubKey << std::vector<unsigned char>{TXHASH_OUTPUTS, 0x00} << OP_TXHASH;
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


// Independent Python fingerprints cover the ordered results of ALL 511 masks,
// rather than comparing only two paths that could share the same hashing bug.
BOOST_AUTO_TEST_CASE(txhash_all_masks_family_vectors)
{
    struct Vector { const char* script; const char* fingerprint; };
    const Vector vectors[] = {
        {"76a914000102030405060708090a0b0c0d0e0f1011121388ac", "f7fe6aebf499d2f73008c1efbdc3e889510e7cd28bb23d4efc5af1bf23ab9be3"},
        {"76a914000102030405060708090a0b0c0d0e0f1011121388acc015786e61740843545641535345540065cd1d0000000075", "e054d3414d451ee9051a5cde167610c32587e15597c36756fec9131e54e68dce"},
        {"5120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "a6392032a9367311188527d2122963ba13b6f2b08d50118b62e1c30404e7d454"},
        {"5120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc015786e61740843545641535345540065cd1d0000000075", "a6c3a58f690dfbe9df377556182cb185012b0d95e4d25e2d906ec371360d58be"},
        {"5220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "2dd0878c07efb933e01c66025bc8fe10a2bc575fbd432120762be5d89f569f3a"},
        {"5220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc015786e61740843545641535345540065cd1d0000000075", "36525809355b9ac493b28d146a13511e9ae4c19f6fa0ea357ad20f74a7d5a2a1"},
        {"5320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "a7ec40328a96e6bc80fe8c0388b5b4b9ac5a09ec87fe834be4c45d0cda78b437"},
        {"5320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc015786e61740843545641535345540065cd1d0000000075", "bf09ea6edbf18f9c7b8e989a71c9421a04987dcc5500c9b24acb8e4e9819e9fe"},
    };
    for (const auto& vector : vectors) {
        CMutableTransaction original;
        original.nVersion = 3;
        original.nLockTime = 123;
        original.vin.resize(2);
        original.vin[0].prevout = COutPoint(uint256S("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"), 7);
        original.vin[1].prevout = COutPoint(uint256S("3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"), 9);
        original.vin[0].nSequence = 0xfffffffe;
        original.vin[0].scriptWitness.stack = {{1}};
        original.vin[1].nSequence = 0xfffffffd;
        const auto script = ParseHex(vector.script);
        original.vout.emplace_back(100000, CScript(script.begin(), script.end()));
        original.vout.emplace_back(200000, CScript() << OP_TRUE);
        original.vrefin.emplace_back(uint256S("aa"), 7);
        original.vrefin.emplace_back(uint256S("bb"), 9);
        const CTransaction baseline(original);
        std::vector<std::vector<unsigned char>> expected(512);
        for (bool cached : {false, true}) {
            CSHA256 fingerprint;
            const PrecomputedTransactionData data(baseline);
            const TransactionSignatureChecker withCache(&baseline, 1, 0, data);
            const TransactionSignatureChecker withoutCache(&baseline, 1, 0);
            for (int mask = 1; mask <= 511; ++mask) {
                BOOST_TEST_CONTEXT("fingerprint=" << vector.fingerprint << " mask=" << mask << " cached=" << cached) {
                    std::vector<std::vector<unsigned char>> stack;
                    ScriptError error;
                    const CScript query = CScript() << std::vector<unsigned char>{static_cast<unsigned char>(mask), static_cast<unsigned char>(mask >> 8)} << OP_TXHASH;
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
        const uint16_t affected[] = {0x101, 2, 4, 0x24, 8, 0x48, 16, 16, 0x100, 0x100, 0, 0, 0xe0, 16};
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
            for (int mask = 1; mask <= 511; ++mask) for (const auto* checker : {&withCache, &withoutCache}) {
                BOOST_TEST_CONTEXT("fingerprint=" << vector.fingerprint << " mutation=" << mutation << " mask=" << mask) {
                    std::vector<unsigned char> actual;
                    BOOST_REQUIRE(checker->GetTxFieldHash(mask, actual));
                    BOOST_CHECK_EQUAL(actual != expected[mask], (mask & affected[mutation]) != 0);
                }
            }
        }
    }
}


BOOST_AUTO_TEST_CASE(txhash_invalid_selectors)
{
    const CTransaction tx(BuildTestTx());
    const TransactionSignatureChecker checker(&tx, 0, 0);
    for (const auto& selector : std::vector<std::vector<unsigned char>>{
            {}, {1}, {0x10}, {0xff}, {0, 0}, {0, 2}, {0xff, 0xff}, {1, 0, 0}}) {
        std::vector<std::vector<unsigned char>> stack;
        ScriptError error;
        BOOST_CHECK(!EvalScript(stack, CScript() << selector << OP_TXHASH,
                               TXHASH_FLAGS, checker, SIGVERSION_BASE, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_TXHASH);
    }
    std::vector<unsigned char> digest;
    for (int bit = 9; bit < 16; ++bit) {
        BOOST_CHECK(!checker.GetTxFieldHash(1U << bit, digest));
        BOOST_CHECK(!checker.GetTxFieldHash((1U << bit) | 0x1ff, digest));
    }
}

BOOST_AUTO_TEST_CASE(txhash_empty_refs_and_version)
{
    CMutableTransaction a = BuildTestTx();
    CMutableTransaction b = a;
    b.nVersion = 3;
    const CTransaction v2(a), v3(b);
    const auto expected = ParseHex("308542cb639a0e6ac414070f3be7c7e13827c7dde337c4d1202853376519fab1");
    for (bool cached : {false, true}) {
        std::vector<unsigned char> digest;
        BOOST_REQUIRE(DirectTxFieldHash(v2, 0, 0x100, digest, cached));
        BOOST_CHECK(digest == expected);
        BOOST_REQUIRE(DirectTxFieldHash(v3, 0, 0x100, digest, cached));
        BOOST_CHECK(digest == expected);
        for (uint16_t mask = 1; mask < 512; ++mask) {
            std::vector<unsigned char> x, y;
            BOOST_REQUIRE(DirectTxFieldHash(v2, 0, mask, x, cached));
            BOOST_REQUIRE(DirectTxFieldHash(v3, 0, mask, y, cached));
            BOOST_CHECK_EQUAL(x == y, !(mask & 1));
        }
    }
    // Invalid current input only matters if a current-input field is selected.
    std::vector<unsigned char> digest;
    BOOST_CHECK(DirectTxFieldHash(v3, 100, 0x100, digest));
    BOOST_CHECK(digest == expected);
}

BOOST_AUTO_TEST_CASE(txhash_old_mask_collision_is_separated)
{
    CMutableTransaction mtx = BuildTestTx();
    mtx.vin[0].nSequence = mtx.nVersion;
    const CTransaction tx(mtx);
    CDataStream version(SER_GETHASH, 0), sequence(SER_GETHASH, 0);
    version << uint32_t(tx.nVersion);
    sequence << tx.vin[0].nSequence;
    BOOST_CHECK(std::equal(version.begin(), version.end(), sequence.begin(), sequence.end())); // identical old preimages for 0x01/0x40
    std::vector<unsigned char> x, y;
    BOOST_REQUIRE(DirectTxFieldHash(tx, 0, 1, x));
    BOOST_REQUIRE(DirectTxFieldHash(tx, 0, 0x40, y));
    BOOST_CHECK(x != y);
}

BOOST_AUTO_TEST_CASE(txhash_partial_cache)
{
    CMutableTransaction mtx = BuildTestTx(2, 2);
    mtx.nVersion = 3;
    mtx.vrefin.emplace_back(uint256S("123456"), 9);
    const CTransaction tx(mtx);
    for (bool regular : {false, true}) for (bool references : {false, true}) {
        PrecomputedTransactionData data(tx);
        data.ready = regular;
        data.refInputsReady = references;
        const TransactionSignatureChecker checker(&tx, 0, 0, data);
        for (uint16_t mask = 1; mask < 512; ++mask) {
            std::vector<unsigned char> a, b;
            BOOST_REQUIRE(checker.GetTxFieldHash(mask, a));
            BOOST_REQUIRE(DirectTxFieldHash(tx, 0, mask, b, false));
            BOOST_CHECK(a == b);
        }
    }
}


BOOST_AUTO_TEST_CASE(txhash_csfs_fixed_vectors)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(std::string(reinterpret_cast<const char*>(json_tests::txhash_csfs_vectors), sizeof(json_tests::txhash_csfs_vectors))));
    BOOST_REQUIRE_EQUAL(vectors.size(), 2U);
    const auto flags = TXHASH_FLAGS | SCRIPT_VERIFY_AUTHSCRIPT | SCRIPT_VERIFY_CHECKSIGFROMSTACK |
        SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_LOW_S;
    for (const auto& vector : vectors.getValues()) {
        const auto pub = ParseHex(vector["pubkey"].get_str());
        const auto sig = ParseHex(vector["signature"].get_str());
        CMutableTransaction mtx = BuildTestTx();
        mtx.nVersion = 3;
        mtx.nLockTime = 0;
        mtx.vin[0].nSequence = 0xffffffff;
        mtx.vout = {CTxOut(100000, CScript() << OP_TRUE)};
        mtx.vrefin.emplace_back(uint256S("5f5e5d5c5b5a595857565554535251504f4e4d4c4b4a49484746454443424140"), 0x12345678);
        mtx.vrefin.emplace_back(uint256S("7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160"), 0x87654321);
        const CTransaction baseline(mtx);
        std::vector<unsigned char> digest;
        BOOST_REQUIRE(DirectTxFieldHash(baseline, 0, 0x110, digest));
        BOOST_CHECK_EQUAL(HexStr(digest), vector["digest"].get_str());
        uint256 signedHash;
        CSHA256().Write(digest.data(), digest.size()).Finalize(signedHash.begin());
        BOOST_CHECK_EQUAL(HexStr(signedHash.begin(), signedHash.end()), vector["signed_hash"].get_str());
        for (int mutation = 0; mutation < 6; ++mutation) {
            CMutableTransaction changed = mtx;
            auto signature = sig;
            uint16_t mask = 0x110;
            if (mutation == 1) mask = 0x100;
            if (mutation == 2) ++changed.vrefin[0].n;
            if (mutation == 3) std::swap(changed.vrefin[0], changed.vrefin[1]);
            if (mutation == 4) ++changed.vout[0].nValue;
            if (mutation == 5) signature[10] ^= 1;
            const CScript contract = CScript() << std::vector<unsigned char>{static_cast<unsigned char>(mask), static_cast<unsigned char>(mask >> 8)}
                << OP_TXHASH << pub << OP_CHECKSIGFROMSTACK;
            const auto commitment = GetAuthScriptCommitment(0, nullptr, contract);
            const CScript spk = CScript() << OP_1 << ToByteVector(commitment);
            changed.vin[0].scriptWitness.stack = {{0}, signature, std::vector<unsigned char>(contract.begin(), contract.end())};
            const CTransaction tx(changed);
            const PrecomputedTransactionData cache(tx);
            const TransactionSignatureChecker checker(&tx, 0, COIN, cache);
            ScriptError error;
            const bool valid = VerifyScript(CScript(), spk, &tx.vin[0].scriptWitness, flags, checker, &error);
            BOOST_TEST_CONTEXT(vector["algorithm"].get_str() << " mutation=" << mutation) {
                BOOST_CHECK_EQUAL(valid, mutation == 0);
                BOOST_CHECK_EQUAL(error, mutation == 0 ? SCRIPT_ERR_OK : SCRIPT_ERR_SIG_NULLFAIL);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
