// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-039: OP_CHECKSIGADD generic signature accumulator (slot 0xde).
// Tests gating, legacy/PQ encoding, NULLFAIL, sigop accounting, and the
// consensus per-element cap widening that ships with this opcode.

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

namespace {

// Flag combinations exercised by the suite.
//
// MANDATORY ≈ consensus-only path (just SCRIPT_VERIFY_P2SH per
// standard.h:66). STRICT adds the standard-relay encoding flags.
// CHECKSIGADD just gates the opcode; STRICT_CHECKSIGADD also turns on
// the encoding strictness that real relay sees.

static constexpr script_verify_flags FLAGS_NONE         = SCRIPT_VERIFY_NONE;
static constexpr script_verify_flags FLAGS_MANDATORY    = SCRIPT_VERIFY_P2SH;
static constexpr script_verify_flags FLAGS_CSA          = FLAGS_MANDATORY | SCRIPT_VERIFY_CHECKSIGADD;
static constexpr script_verify_flags FLAGS_CSA_STRICT   = FLAGS_CSA | SCRIPT_VERIFY_DERSIG
                                                                   | SCRIPT_VERIFY_STRICTENC
                                                                   | SCRIPT_VERIFY_LOW_S;
static constexpr script_verify_flags FLAGS_CSA_NULLFAIL = FLAGS_CSA_STRICT | SCRIPT_VERIFY_NULLFAIL;
static constexpr script_verify_flags FLAGS_CSA_DISCOURAGE = FLAGS_MANDATORY | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

// Build a minimal but well-formed transaction shell. The actual sighash
// only matters for the few tests that drive a real CheckSig — for the
// gating / encoding / cost tests we never reach a verify.
static CMutableTransaction BuildShellTx()
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

// Sign the SIGVERSION_BASE sighash of a bare scriptCode for input 0.
// Caller is responsible for ensuring the scriptCode they sign matches
// the post-FindAndDelete script the verifier will reconstruct.
static std::vector<unsigned char>
SignBare(const CKey& key, const CScript& scriptCode, const CTransaction& tx,
         unsigned char nHashType = SIGHASH_ALL)
{
    uint256 hash = SignatureHash(scriptCode, tx, 0, nHashType, 0, SIGVERSION_BASE);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    sig.push_back(nHashType);
    return sig;
}

// Run a bare script under EvalScript with a tx-bound checker so CheckSig
// works for the tests that need a real verify.
static bool RunBareScript(const CScript& script, script_verify_flags flags,
                          const CTransaction& tx, ScriptError* err = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    std::vector<std::vector<unsigned char>> stack;
    return EvalScript(stack, script, flags, checker, SIGVERSION_BASE, err);
}

// Run a bare script and additionally assert the top-of-stack is non-zero
// (mimics VerifyScript's final accept criterion).
static bool RunBareScriptAndCheckTrue(const CScript& script, script_verify_flags flags,
                                      const CTransaction& tx, ScriptError* err = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    std::vector<std::vector<unsigned char>> stack;
    if (!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, err)) return false;
    return !stack.empty() && CastToBool(stack.back());
}

// Build a credit/spend pair for a P2WSH wrapped witnessScript. SIGVERSION
// _WITNESS_V0 does not perform FindAndDelete, which is what we want when
// composing multiple CHECKSIGADDs with the same scriptCode for all sigs.
static std::pair<CMutableTransaction, CMutableTransaction>
BuildP2WSHCtx(const CScript& witnessScript)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    uint256 wsHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(wsHash.begin());
    txCredit.vout[0].scriptPubKey = CScript() << OP_0 << ToByteVector(wsHash);
    txCredit.vout[0].nValue = 1000;

    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].nValue = 1000;
    return {txCredit, txSpend};
}

// Sign a SIGVERSION_WITNESS_V0 sighash. scriptCode is the witnessScript.
static std::vector<unsigned char>
SignWitnessV0(const CKey& key, const CScript& witnessScript,
              const CMutableTransaction& txSpend, CAmount amount,
              unsigned char nHashType = SIGHASH_ALL)
{
    uint256 hash = SignatureHash(witnessScript, txSpend, 0, nHashType, amount, SIGVERSION_WITNESS_V0);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    sig.push_back(nHashType);
    return sig;
}

// Run a P2WSH-wrapped witnessScript with the supplied (non-script) witness
// stack items. The witnessScript is appended automatically.
static bool RunP2WSH(const CScript& witnessScript,
                    const std::vector<std::vector<unsigned char>>& witnessStack,
                    script_verify_flags flags,
                    CMutableTransaction& txCredit, CMutableTransaction& txSpend,
                    ScriptError* err = nullptr)
{
    CScriptWitness wit;
    wit.stack = witnessStack;
    wit.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));
    txSpend.vin[0].scriptWitness = wit;

    ScriptError serror;
    bool result = VerifyScript(
        CScript(),
        txCredit.vout[0].scriptPubKey,
        &wit,
        flags | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH,
        MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue,
                                          txCredit.vout[0].scriptPubKey),
        &serror);
    if (err) *err = serror;
    return result;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(checksigadd_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Group 1 — gating
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(flag_off_returns_bad_opcode)
{
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());

    CScript script = CScript() << std::vector<unsigned char>{} << CScriptNum(0) << pk << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_MANDATORY, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(flag_off_with_discourage_still_bad_opcode)
{
    // The slot 0xde was previously unassigned (not a NOP). Even with
    // SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS set, flag-off must still
    // return BAD_OPCODE, never DISCOURAGE_UPGRADABLE_NOPS.
    CScript script = CScript() << std::vector<unsigned char>{} << CScriptNum(0) << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA_DISCOURAGE, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(stack_underflow_returns_invalid_stack_op)
{
    // Only 2 items pushed; OP_CHECKSIGADD requires 3.
    CScript script = CScript() << std::vector<unsigned char>{} << CScriptNum(0) << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ---------------------------------------------------------------------------
// Group 2 — legacy semantics
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(legacy_valid_sig_increments)
{
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());

    // The verifier reconstructs scriptCode = entire script with the sig
    // push removed (FindAndDelete in SIGVERSION_BASE). So we must sign
    // the full body that remains after FindAndDelete — including the
    // trailing assertion — and prepend the sig push afterwards.
    CScript body = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD
                            << CScriptNum(1) << OP_NUMEQUAL;
    CTransaction tx(BuildShellTx());
    std::vector<unsigned char> sig = SignBare(key, body, tx);

    CScript script = (CScript() << sig) + body;
    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA_STRICT, tx));
}

BOOST_AUTO_TEST_CASE(legacy_wrong_sig_does_not_increment)
{
    // A well-formed signature produced for a DIFFERENT message. Without
    // NULLFAIL, OP_CHECKSIGADD must leave the count unchanged (no abort).
    CKey signKey; signKey.MakeNewKey(true);
    CKey pkOwner; pkOwner.MakeNewKey(true);
    auto pk = ToByteVector(pkOwner.GetPubKey());

    CScript scriptAfterFAD = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD;
    CTransaction tx(BuildShellTx());
    // Sign with a different key — encoding stays well-formed, verify fails.
    std::vector<unsigned char> sig = SignBare(signKey, scriptAfterFAD, tx);

    CScript script = (CScript() << sig) + scriptAfterFAD + (CScript() << CScriptNum(0) << OP_NUMEQUAL);

    // FLAGS_CSA_STRICT enables encoding checks but NOT NULLFAIL.
    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA_STRICT, tx));
}

BOOST_AUTO_TEST_CASE(legacy_wrong_sig_under_nullfail_aborts)
{
    CKey signKey; signKey.MakeNewKey(true);
    CKey pkOwner; pkOwner.MakeNewKey(true);
    auto pk = ToByteVector(pkOwner.GetPubKey());

    CScript scriptAfterFAD = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD;
    CTransaction tx(BuildShellTx());
    std::vector<unsigned char> sig = SignBare(signKey, scriptAfterFAD, tx);

    CScript script = (CScript() << sig) + scriptAfterFAD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA_NULLFAIL, tx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_NULLFAIL);
}

BOOST_AUTO_TEST_CASE(legacy_empty_sig_skips)
{
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());

    // Empty sig leaves count unchanged; assert count stays 0.
    CScript script = CScript() << std::vector<unsigned char>{} << CScriptNum(0) << pk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA_NULLFAIL, CTransaction(BuildShellTx())));
}

BOOST_AUTO_TEST_CASE(legacy_malformed_sig_under_strict_returns_encoding_err)
{
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());
    // 5-byte garbage signature — fails DER encoding under STRICTENC/DERSIG.
    std::vector<unsigned char> badSig = {0x30, 0x01, 0x02, 0x03, SIGHASH_ALL};

    CScript script = CScript() << badSig << CScriptNum(0) << pk << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA_STRICT, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK(err == SCRIPT_ERR_SIG_DER || err == SCRIPT_ERR_SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(legacy_malformed_sig_no_strict_does_not_abort)
{
    // Same garbage sig under MANDATORY-only flags (no DERSIG/STRICTENC/LOW_S):
    // no encoding error, signature simply fails to verify (no NULLFAIL set
    // either), counter unchanged.
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());
    std::vector<unsigned char> badSig = {0x30, 0x01, 0x02, 0x03, SIGHASH_ALL};

    CScript script = CScript() << badSig << CScriptNum(0) << pk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA, CTransaction(BuildShellTx())));
}

BOOST_AUTO_TEST_CASE(legacy_malformed_pubkey_no_strict_does_not_abort)
{
    // 5-byte garbage pubkey (not a valid secp encoding, prefix != 0x05).
    // Without STRICTENC/WITNESS_PUBKEYTYPE no encoding error is raised; the
    // verification path returns false and the counter stays unchanged.
    std::vector<unsigned char> badPk = {0x10, 0x11, 0x12, 0x13, 0x14};
    std::vector<unsigned char> emptySig{};

    CScript script = CScript() << emptySig << CScriptNum(0) << badPk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    // Empty sig => CheckSig is skipped entirely, counter unchanged. Assert
    // that we don't bail with an encoding error along the way.
    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA, CTransaction(BuildShellTx())));
}

// ---------------------------------------------------------------------------
// Group 3 — PQ semantics
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pq_canonical_pubkey_valid_sig_increments)
{
    const std::vector<unsigned char> seed = ParseHex(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);
    CPubKey pqPubKey = pqKey.GetPubKey();
    BOOST_REQUIRE(pqPubKey.IsPQ());
    std::vector<unsigned char> pk(pqPubKey.begin(), pqPubKey.end());
    BOOST_REQUIRE_EQUAL(pk.size(), 1U + ML_DSA_44_PUBKEY_SIZE);

    CScript body = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD
                            << CScriptNum(1) << OP_NUMEQUAL;
    CTransaction tx(BuildShellTx());
    std::vector<unsigned char> sig = SignBare(pqKey, body, tx);
    BOOST_REQUIRE_EQUAL(sig.size(), ML_DSA_44_SIG_SIZE + 1);

    CScript script = (CScript() << sig) + body;
    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA_STRICT, tx));
}

BOOST_AUTO_TEST_CASE(pq_pubkey_short_with_0x05_rejects_with_pq_pubkey_size)
{
    // 0x05-prefixed pubkey of non-canonical length must fire the NIP-039
    // mandatory prevalidation REGARDLESS of encoding flags.
    std::vector<unsigned char> shortPq(33, 0x00);
    shortPq[0] = 0x05;
    std::vector<unsigned char> emptySig{};

    CScript script = CScript() << emptySig << CScriptNum(0) << shortPq << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pq_pubkey_long_with_0x05_rejects_with_pq_pubkey_size)
{
    std::vector<unsigned char> longPq(2 + ML_DSA_44_PUBKEY_SIZE, 0x00);
    longPq[0] = 0x05;
    std::vector<unsigned char> emptySig{};

    CScript script = CScript() << emptySig << CScriptNum(0) << longPq << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pq_pubkey_one_byte_0x05_rejects)
{
    // Edge case: 1-byte pubkey {0x05}. Triggers the prevalidation because
    // size != 1 + ML_DSA_44_PUBKEY_SIZE.
    std::vector<unsigned char> shortPq = {0x05};
    std::vector<unsigned char> emptySig{};

    CScript script = CScript() << emptySig << CScriptNum(0) << shortPq << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQ_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pq_malformed_sig_under_strict_returns_encoding_err)
{
    const std::vector<unsigned char> seed = ParseHex(
        "0102030405060708091011121314151617181920212223242526272829303132");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);
    auto pk = ToByteVector(pqKey.GetPubKey());
    // 100-byte garbage sig — wrong size for ML-DSA-44.
    std::vector<unsigned char> badSig(100, 0xab);

    CScript script = CScript() << badSig << CScriptNum(0) << pk << OP_CHECKSIGADD;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(script, FLAGS_CSA_STRICT, CTransaction(BuildShellTx()), &err));
    // CheckSignatureEncodingForPubKey returns SCRIPT_ERR_SIG_DER for PQ
    // wrong-size under any of DERSIG / LOW_S / STRICTENC.
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_DER);
}

BOOST_AUTO_TEST_CASE(pq_malformed_sig_no_strict_does_not_abort)
{
    const std::vector<unsigned char> seed = ParseHex(
        "0102030405060708091011121314151617181920212223242526272829303132");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);
    auto pk = ToByteVector(pqKey.GetPubKey());
    std::vector<unsigned char> badSig(100, 0xab);

    CScript script = CScript() << badSig << CScriptNum(0) << pk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    // Under MANDATORY-only flags, no encoding error; CheckSig fails, count
    // stays at 0. The PQ-pubkey shape check still fires for the pubkey
    // itself but the canonical-size pk satisfies it.
    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA, CTransaction(BuildShellTx())));
}

BOOST_AUTO_TEST_CASE(pq_empty_sig_skips)
{
    const std::vector<unsigned char> seed = ParseHex(
        "0102030405060708091011121314151617181920212223242526272829303132");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);
    auto pk = ToByteVector(pqKey.GetPubKey());
    std::vector<unsigned char> emptySig{};

    CScript script = CScript() << emptySig << CScriptNum(0) << pk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA_NULLFAIL, CTransaction(BuildShellTx())));
}

// ---------------------------------------------------------------------------
// Group 4 — composition / mixed threshold
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(mixed_2_of_2_legacy_pq_threshold_passes)
{
    // Multi-CHECKSIGADD verify is tested via P2WSH because
    // SIGVERSION_WITNESS_V0 does not perform FindAndDelete. In
    // SIGVERSION_BASE each CHECKSIGADD would compute a different
    // scriptCode (post-FindAndDelete-of-its-own-sig), making the
    // chicken-and-egg of "sign the scriptCode that contains the sig
    // push you're producing" impossible. Real PQ multisig deployments
    // would always use witness v0 / AuthScript anyway.
    CKey legacyKey; legacyKey.MakeNewKey(true);
    const std::vector<unsigned char> seed = ParseHex(
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);

    auto pkLegacy = ToByteVector(legacyKey.GetPubKey());
    auto pkPq = ToByteVector(pqKey.GetPubKey());

    CScript witnessScript = CScript() << CScriptNum(0)
                                      << pkLegacy << OP_CHECKSIGADD
                                      << pkPq     << OP_CHECKSIGADD
                                      << CScriptNum(2) << OP_NUMEQUAL;

    auto [txCredit, txSpend] = BuildP2WSHCtx(witnessScript);
    const CAmount amount = txCredit.vout[0].nValue;

    auto sigLegacy = SignWitnessV0(legacyKey, witnessScript, txSpend, amount);
    auto sigPq     = SignWitnessV0(pqKey,     witnessScript, txSpend, amount);

    // Witness layout (deepest first; topmost consumed first by first CHECKSIGADD):
    //   [<sigPq>, <sigLegacy>, <witnessScript>]
    BOOST_CHECK(RunP2WSH(witnessScript, {sigPq, sigLegacy}, FLAGS_CSA_STRICT, txCredit, txSpend));
}

BOOST_AUTO_TEST_CASE(mixed_threshold_count_correct_with_one_invalid)
{
    // Two key positions, only one signed correctly; count must equal 1.
    // P2WSH path for the same FindAndDelete reason.
    CKey signKey;  signKey.MakeNewKey(true);
    CKey otherPk;  otherPk.MakeNewKey(true); // owner of pos 2 — not signed
    auto pk1 = ToByteVector(signKey.GetPubKey());
    auto pk2 = ToByteVector(otherPk.GetPubKey());

    CScript witnessScript = CScript() << CScriptNum(0)
                                      << pk1 << OP_CHECKSIGADD
                                      << pk2 << OP_CHECKSIGADD
                                      << CScriptNum(1) << OP_NUMEQUAL;

    auto [txCredit, txSpend] = BuildP2WSHCtx(witnessScript);
    const CAmount amount = txCredit.vout[0].nValue;
    auto sigGood = SignWitnessV0(signKey, witnessScript, txSpend, amount);
    std::vector<unsigned char> emptySig{}; // skips position 2 cleanly

    BOOST_CHECK(RunP2WSH(witnessScript, {emptySig, sigGood}, FLAGS_CSA_STRICT, txCredit, txSpend));
}

// ---------------------------------------------------------------------------
// Group 5 — sigop accounting
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(op_count_charges_per_executed_op)
{
    // Per-iteration cost (interpreter.cpp:590 increments by 1 for any
    // opcode > OP_16; OP_CHECKSIGADD handler then adds
    // CHECKSIGADD_PQ_SIGOP_COST = 8; OP_DROP also crosses OP_16 = +1):
    //
    //   <emptySig> push       0  (push opcode, no count)
    //   CScriptNum(0) -> OP_0 0  (<= OP_16, no count)
    //   <pk> push             0  (push opcode, no count)
    //   OP_CHECKSIGADD        9  (1 universal + 8 handler)
    //   OP_DROP               1
    //   ----------------------------
    //   per iter             10
    //
    // 20 iters = 200 ≤ MAX_OPS_PER_SCRIPT = 201 — accepted.
    // 21 iters = 210 > 201 — overflow → SCRIPT_ERR_OP_COUNT.
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());
    std::vector<unsigned char> emptySig{};

    auto build = [&](int n) {
        CScript s;
        for (int i = 0; i < n; ++i) {
            s << emptySig << CScriptNum(0) << pk << OP_CHECKSIGADD << OP_DROP;
        }
        s << OP_TRUE;
        return s;
    };

    // Boundary: 20 iters → 200 ops, just under the cap.
    CScript ok20 = build(20);
    BOOST_CHECK(RunBareScriptAndCheckTrue(ok20, FLAGS_CSA, CTransaction(BuildShellTx())));

    // 21 iters → overflow.
    CScript over21 = build(21);
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunBareScript(over21, FLAGS_CSA, CTransaction(BuildShellTx()), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OP_COUNT);
}

BOOST_AUTO_TEST_CASE(op_count_unexecuted_branch_does_not_charge_handler_surcharge)
{
    // Demonstrates that the per-handler +8 surcharge does NOT apply to
    // CHECKSIGADD invocations in an unexecuted OP_IF branch. The
    // universal +1 from interpreter.cpp:590 still applies because that
    // counter runs on every opcode read, but the +8 only fires inside
    // the handler.
    //
    // Without this distinction, 23 unexecuted CHECKSIGADDs would cost
    // 23 * 9 = 207 > 201 and fail; with it, each costs only 1, plus the
    // OP_DROPs (also +1 each) and the wrapping OP_IF/OP_ENDIF, which
    // stays well under the cap.
    CKey key; key.MakeNewKey(true);
    auto pk = ToByteVector(key.GetPubKey());
    std::vector<unsigned char> emptySig{};

    CScript inner;
    for (int i = 0; i < 23; ++i) {
        inner << emptySig << CScriptNum(0) << pk << OP_CHECKSIGADD << OP_DROP;
    }
    CScript script = (CScript() << CScriptNum(0) << OP_IF) + inner + (CScript() << OP_ENDIF << OP_TRUE);

    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA, CTransaction(BuildShellTx())));
}

// ---------------------------------------------------------------------------
// Group 6 — consensus per-element cap interaction
// ---------------------------------------------------------------------------
//
// These tests assert that SCRIPT_VERIFY_CHECKSIGADD ALONE widens the
// per-element cap, even with neither CSFS nor Merkle-inclusion active.
// They are the regression test for the EffectiveMaxScriptElementSize()
// mask change in interpreter.h and the lockstep MAX_STACK_BYTES gate in
// interpreter.cpp.

BOOST_AUTO_TEST_CASE(pq_pubkey_1313B_inline_push_accepted_under_checksigadd_only)
{
    // Inline push of a 1313-byte (1 + ML_DSA_44_PUBKEY_SIZE) pubkey.
    // Without SCRIPT_VERIFY_CHECKSIGADD this would fail at the per-element
    // cap. With it the push goes through, the PQ-pubkey shape check
    // accepts (canonical size), the CheckSig path returns false because
    // the sig is empty, count stays 0.
    const std::vector<unsigned char> seed = ParseHex(
        "11223344556677889900112233445566778899001122334455667788990011aa");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);
    auto pk = ToByteVector(pqKey.GetPubKey());
    BOOST_REQUIRE_EQUAL(pk.size(), 1U + ML_DSA_44_PUBKEY_SIZE);

    std::vector<unsigned char> emptySig{};
    CScript script = CScript() << emptySig << CScriptNum(0) << pk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA, CTransaction(BuildShellTx())));
}

BOOST_AUTO_TEST_CASE(pq_signature_2421B_pushed_inline_accepted_under_checksigadd_only)
{
    // Inline push of a 2421-byte (1 + ML_DSA_44_SIG_SIZE) blob in the
    // signature slot. We use a wrong-size... actually canonical-size
    // garbage value: under MANDATORY+CHECKSIGADD only (no STRICTENC) the
    // encoding helpers accept it; CheckSig fails, counter stays 0.
    std::vector<unsigned char> sigShape(1 + ML_DSA_44_SIG_SIZE, 0xab);
    sigShape.back() = SIGHASH_ALL;

    const std::vector<unsigned char> seed = ParseHex(
        "1122334455667788990011223344556677889900112233445566778899001122");
    CKey pqKey; pqKey.MakeNewKeyPQ(seed);
    auto pk = ToByteVector(pqKey.GetPubKey());

    CScript script = CScript() << sigShape << CScriptNum(0) << pk << OP_CHECKSIGADD
                              << CScriptNum(0) << OP_NUMEQUAL;

    BOOST_CHECK(RunBareScriptAndCheckTrue(script, FLAGS_CSA, CTransaction(BuildShellTx())));
}

BOOST_AUTO_TEST_SUITE_END()
