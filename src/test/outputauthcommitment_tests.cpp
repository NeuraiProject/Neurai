// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for NIP-023: OP_OUTPUTAUTHCOMMITMENT.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags OAC_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_OUTPUTAUTHCOMMITMENT;
static constexpr script_verify_flags OAC_FLAGS_DISCOURAGE =
    OAC_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags NO_OAC_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_OAC_FLAGS_DISCOURAGE =
    NO_OAC_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
// Combined flags for continuity-check covenant tests
// (OP_TXFIELD + OP_OUTPUTAUTHCOMMITMENT).
static constexpr script_verify_flags CONTINUITY_FLAGS =
    OAC_FLAGS | SCRIPT_VERIFY_TXFIELD;

namespace {

// A reproducible 32-byte AuthScript commitment fixture.
std::vector<unsigned char> FixtureCommitment(unsigned char fill)
{
    return std::vector<unsigned char>(32, fill);
}

// Build a scriptPubKey of the shape OP_1 0x20 <32B>, optionally followed by an
// OP_XNA_ASSET ... OP_DROP asset wrapper. The wrapper bytes are opaque to the
// opcode — what matters is that the 32 bytes after the OP_1 0x20 prefix are
// returned unchanged.
CScript BuildAuthScriptSPK(const std::vector<unsigned char>& commitment,
                           bool withAssetWrapper = false)
{
    // 34-byte prefix: OP_1 OP_PUSHBYTES_32 <32B>
    CScript spk;
    spk << OP_1 << commitment;

    if (withAssetWrapper) {
        // Anything parseable as an asset wrapper works for this test; the
        // opcode never reads past byte 33.
        std::vector<unsigned char> payload = { 'r','v','n','t', 0x00, 0x04,
                                                'F','A','K','E',
                                                0x10, 0x27, 0, 0, 0, 0, 0, 0 };
        spk << OP_XNA_ASSET << payload << OP_DROP;
    }

    return spk;
}

// Build a tx whose outputs cover several scriptPubKey shapes:
//   vout[0]: P2PKH (25 bytes) — must fail OP_OUTPUTAUTHCOMMITMENT.
//   vout[1]: witness v0 + 20B program (P2WPKH) — must fail.
//   vout[2]: witness v1 + 20B program — must fail.
//   vout[3]: AuthScript v1 bare (34 bytes).
//   vout[4]: AuthScript v1 with asset wrapper (variable length).
//   vout[5]: scriptPubKey of length < 34 — must fail.
CMutableTransaction BuildTx(const std::vector<unsigned char>& commitment3,
                            const std::vector<unsigned char>& commitment4)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    // vout[0]: P2PKH
    {
        CTxOut out;
        out.nValue = 1000;
        std::vector<unsigned char> h20(20, 0x11);
        out.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << h20
                                     << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(out);
    }

    // vout[1]: P2WPKH (OP_0 + 20B)
    {
        CTxOut out;
        out.nValue = 2000;
        std::vector<unsigned char> h20(20, 0x22);
        out.scriptPubKey = CScript() << OP_0 << h20;
        tx.vout.push_back(out);
    }

    // vout[2]: witness v1 + 20B program (PQ messaging address shape) — rejected
    {
        CTxOut out;
        out.nValue = 3000;
        std::vector<unsigned char> h20(20, 0x33);
        out.scriptPubKey = CScript() << OP_1 << h20;
        tx.vout.push_back(out);
    }

    // vout[3]: AuthScript v1 bare (34 bytes)
    {
        CTxOut out;
        out.nValue = 4000;
        out.scriptPubKey = BuildAuthScriptSPK(commitment3, /*withWrapper=*/false);
        tx.vout.push_back(out);
    }

    // vout[4]: AuthScript v1 + asset wrapper
    {
        CTxOut out;
        out.nValue = 5000;
        out.scriptPubKey = BuildAuthScriptSPK(commitment4, /*withWrapper=*/true);
        tx.vout.push_back(out);
    }

    // vout[5]: pathological — script of length 10 (< 34)
    {
        CTxOut out;
        out.nValue = 100;
        out.scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(8, 0xAA);
        tx.vout.push_back(out);
    }

    return tx;
}

bool RunScript(const CTransaction& tx, const CScript& script, script_verify_flags flags,
               std::vector<std::vector<unsigned char>>& resultStack, ScriptError* errOut = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

bool RunScriptWithSpentSPK(const CTransaction& tx, const CScript& script,
                           const CScript& spentSPK, CAmount spentAmount,
                           script_verify_flags flags,
                           std::vector<std::vector<unsigned char>>& resultStack,
                           ScriptError* errOut = nullptr)
{
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, spentAmount, txdata, spentSPK);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

bool DirectGetOutputAuthCommitment(const CTransaction& tx, unsigned int nOut,
                                   std::vector<unsigned char>& result)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    return checker.GetOutputAuthCommitment(nOut, result);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(outputauthcommitment_tests, BasicTestingSetup)

// --- Checker: direct byte extraction on each output shape ---

BOOST_AUTO_TEST_CASE(oac_returns_commitment_of_bare_authscript_output)
{
    std::vector<unsigned char> commitment = FixtureCommitment(0x44);
    CTransaction tx(BuildTx(commitment, FixtureCommitment(0x55)));

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetOutputAuthCommitment(tx, 3, result));
    BOOST_CHECK_EQUAL(result.size(), 32U);
    BOOST_CHECK(result == commitment);
}

BOOST_AUTO_TEST_CASE(oac_returns_commitment_of_wrapped_authscript_output)
{
    std::vector<unsigned char> commitment = FixtureCommitment(0x55);
    CTransaction tx(BuildTx(FixtureCommitment(0x44), commitment));

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetOutputAuthCommitment(tx, 4, result));
    // Asset wrapper bytes are ignored — only the 32 bytes after OP_1 0x20.
    BOOST_CHECK_EQUAL(result.size(), 32U);
    BOOST_CHECK(result == commitment);
}

BOOST_AUTO_TEST_CASE(oac_rejects_p2pkh_output)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetOutputAuthCommitment(tx, 0, result));
}

BOOST_AUTO_TEST_CASE(oac_rejects_bad_witness_version)
{
    // P2WPKH — witness v0 + 20B program
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetOutputAuthCommitment(tx, 1, result));
}

BOOST_AUTO_TEST_CASE(oac_rejects_bad_push_size)
{
    // Witness v1 + 20B program — commitment must always be 32 bytes.
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetOutputAuthCommitment(tx, 2, result));
}

BOOST_AUTO_TEST_CASE(oac_rejects_short_script)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetOutputAuthCommitment(tx, 5, result));
}

BOOST_AUTO_TEST_CASE(oac_rejects_out_of_range_index)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));

    std::vector<unsigned char> result;
    // tx has 6 outputs (indices 0..5)
    BOOST_CHECK(!DirectGetOutputAuthCommitment(tx, 6, result));
    BOOST_CHECK(!DirectGetOutputAuthCommitment(tx, 1000, result));
}

// --- EvalScript: opcode integration ---

BOOST_AUTO_TEST_CASE(oac_evalscript_pushes_bare_commitment)
{
    std::vector<unsigned char> commitment = FixtureCommitment(0x44);
    CTransaction tx(BuildTx(commitment, FixtureCommitment(0x55)));

    CScript script;
    script << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OAC_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK_EQUAL(result[0].size(), 32U);
    BOOST_CHECK(result[0] == commitment);
}

BOOST_AUTO_TEST_CASE(oac_evalscript_pushes_wrapped_commitment)
{
    std::vector<unsigned char> commitment = FixtureCommitment(0x55);
    CTransaction tx(BuildTx(FixtureCommitment(0x44), commitment));

    CScript script;
    script << CScriptNum(4) << OP_OUTPUTAUTHCOMMITMENT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OAC_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK_EQUAL(result[0].size(), 32U);
    BOOST_CHECK(result[0] == commitment);
}

BOOST_AUTO_TEST_CASE(oac_evalscript_pops_index_pushes_result)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    // Start with 3 elements on the stack; pop selector + push 32-byte result → 3 elements.
    script << OP_1 << OP_2 << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OAC_FLAGS, result));
    BOOST_CHECK_EQUAL(result.size(), 3U);
}

// --- Error cases via EvalScript ---

BOOST_AUTO_TEST_CASE(oac_empty_stack_fails)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    script << OP_OUTPUTAUTHCOMMITMENT;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, OAC_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(oac_negative_index_fails)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    script << CScriptNum(-1) << OP_OUTPUTAUTHCOMMITMENT;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, OAC_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);
}

BOOST_AUTO_TEST_CASE(oac_out_of_range_index_fails)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    script << CScriptNum(6) << OP_OUTPUTAUTHCOMMITMENT; // tx has 6 outputs (0..5)

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, OAC_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);
}

BOOST_AUTO_TEST_CASE(oac_non_authscript_output_fails)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    script << CScriptNum(0) << OP_OUTPUTAUTHCOMMITMENT; // vout[0] is P2PKH

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, OAC_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);
}

BOOST_AUTO_TEST_CASE(oac_short_script_fails)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    script << CScriptNum(5) << OP_OUTPUTAUTHCOMMITMENT; // vout[5] is < 34 bytes

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, OAC_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);
}

// --- Flag-gate behavior ---

BOOST_AUTO_TEST_CASE(oac_flag_off_is_nop_on_new_node)
{
    // With the flag off and DISCOURAGE_UPGRADABLE_NOPS off, the opcode
    // short-circuits to a NOP. The selector is *not* popped — this mirrors
    // the behavior of every other DePIN-branch opcode on a flag-off chain.
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    // Push 1 so the "true" on top of the stack survives whether or not the
    // opcode pops and pushes the result.
    script << OP_1 << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT << OP_DROP;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_OAC_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(oac_flag_off_with_discourage_nops_fails)
{
    CTransaction tx(BuildTx(FixtureCommitment(0x44), FixtureCommitment(0x55)));
    CScript script;
    script << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_OAC_FLAGS_DISCOURAGE, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// --- Continuity check (canonical covenant self-replication idiom) ---
//
// A covenant that wants "output[n] pays to the same covenant I came from" now
// writes:
//
//   <n> OP_OUTPUTAUTHCOMMITMENT   0x02 OP_TXFIELD   OP_EQUAL
//
// where 0x02 is TXFIELD_SPENT_AUTHCOMMITMENT — returns the 32 bytes of the
// spent covenant's commitment. The two pushes are byte-equal iff the output
// is locked to the same covenant, independently of any trailing asset
// wrapper. This is the primary use case of the NIP.

BOOST_AUTO_TEST_CASE(oac_continuity_match_with_spent_input)
{
    std::vector<unsigned char> commitment = FixtureCommitment(0xAB);

    // Spent scriptPubKey and vout[3] share the same commitment. vout[4] has
    // the same commitment but with an asset wrapper (different scriptPubKey
    // bytes) — the continuity check should still succeed because the opcode
    // strips the wrapper.
    CMutableTransaction mtx = BuildTx(commitment, commitment);
    CTransaction tx(mtx);

    // Spent UTXO is AuthScript v1 with the same commitment, bare (no wrapper).
    CScript spentSPK = BuildAuthScriptSPK(commitment, /*withWrapper=*/false);

    // Case 1: vout[3] bare AuthScript — continuity should hold.
    {
        CScript test;
        test << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT
             << std::vector<unsigned char>{0x02} << OP_TXFIELD
             << OP_EQUAL;
        std::vector<std::vector<unsigned char>> result;
        ScriptError err;
        bool ok = RunScriptWithSpentSPK(tx, test, spentSPK, 5000, CONTINUITY_FLAGS,
                                        result, &err);
        BOOST_CHECK(ok);
        BOOST_REQUIRE_EQUAL(result.size(), 1U);
        BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
    }

    // Case 2: vout[4] wrapped AuthScript — continuity should still hold.
    // This is the failure-mode-turned-success that motivates the NIP.
    {
        CScript test;
        test << CScriptNum(4) << OP_OUTPUTAUTHCOMMITMENT
             << std::vector<unsigned char>{0x02} << OP_TXFIELD
             << OP_EQUAL;
        std::vector<std::vector<unsigned char>> result;
        ScriptError err;
        bool ok = RunScriptWithSpentSPK(tx, test, spentSPK, 5000, CONTINUITY_FLAGS,
                                        result, &err);
        BOOST_CHECK(ok);
        BOOST_REQUIRE_EQUAL(result.size(), 1U);
        BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
    }
}

BOOST_AUTO_TEST_CASE(oac_continuity_mismatch_with_spent_input)
{
    // vout[3] has commitment A; spent input has commitment B. Continuity
    // check must evaluate to false.
    std::vector<unsigned char> commitmentOut = FixtureCommitment(0xAA);
    std::vector<unsigned char> commitmentIn  = FixtureCommitment(0xBB);

    CTransaction tx(BuildTx(commitmentOut, FixtureCommitment(0xCC)));

    CScript spentSPK = BuildAuthScriptSPK(commitmentIn, /*withWrapper=*/false);

    CScript test;
    test << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT
         << std::vector<unsigned char>{0x02} << OP_TXFIELD
         << OP_EQUAL;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScriptWithSpentSPK(tx, test, spentSPK, 5000, CONTINUITY_FLAGS,
                                    result, &err);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{}); // OP_EQUAL → false
}

// --- VerifyScript integration ---

BOOST_AUTO_TEST_CASE(oac_works_via_verifyscript)
{
    std::vector<unsigned char> commitment = FixtureCommitment(0xCD);
    CTransaction tx(BuildTx(commitment, FixtureCommitment(0x99)));

    CScript scriptSig;
    CScript scriptPubKey;
    // push 3 → OP_OUTPUTAUTHCOMMITMENT → push expected → OP_EQUAL
    scriptPubKey << CScriptNum(3) << OP_OUTPUTAUTHCOMMITMENT
                 << commitment << OP_EQUAL;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, nullptr, OAC_FLAGS,
                             TransactionSignatureChecker(&tx, 0, 0), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
