// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-041: AuthScript destination introspection.
//   OP_OUTPUTAUTHDEST (0xc2)            (nOut          -- version||commitment)
//   OP_TXFIELD        selector 0x04     (0x04          -- version||commitment)  spent input
//   OP_REFINPUTFIELD  selector 0x04     (nRef 0x04     -- version||commitment)  reference input
// 33 bytes: witness version (01 generic v1, 02 strict PQ, 03 strict ECDSA)
// followed by the 32-byte program in its original byte order.

#include "assets/assettypes.h"
#include "chainparams.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_neurai.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

static constexpr script_verify_flags BASE_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TXFIELD |
    SCRIPT_VERIFY_REFINPUTS | SCRIPT_VERIFY_OUTPUTAUTHCOMMITMENT;
static constexpr script_verify_flags ACTIVE_FLAGS =
    BASE_FLAGS | SCRIPT_VERIFY_AUTHSCRIPT_STRICT | SCRIPT_VERIFY_AUTHDEST;

struct AuthDestRegtestSetup : public BasicTestingSetup {
    AuthDestRegtestSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

// Asymmetric program 00 01 .. 1f: a byte-order slip cannot go unnoticed.
valtype AscendingProgram()
{
    valtype program(32);
    for (size_t i = 0; i < program.size(); i++) program[i] = (unsigned char)i;
    return program;
}

valtype Expected(unsigned char version, const valtype& program)
{
    valtype out{version};
    out.insert(out.end(), program.begin(), program.end());
    return out;
}

CScript Native(int version, const valtype& program)
{
    return CScript() << CScript::EncodeOP_N(version) << program;
}

CScript WithAsset(CScript prefix)
{
    CAssetTransfer("AUTHDEST", 5 * COIN).ConstructTransaction(prefix, AssetMarker::NEURAI_XNA);
    return prefix;
}

CMutableTransaction MakeTx(const std::vector<CScript>& outputs, size_t nRefInputs = 0)
{
    CMutableTransaction tx;
    tx.nVersion = nRefInputs ? 3 : 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("aa"), 0);
    for (size_t i = 0; i < nRefInputs; i++)
        tx.vrefin.push_back(COutPoint(uint256S("bb"), (uint32_t)i));
    for (const CScript& spk : outputs)
        tx.vout.push_back(CTxOut(1000, spk));
    return tx;
}

bool Run(const CTransaction& tx, const CScript& script, script_verify_flags flags,
         std::vector<valtype>& stack, ScriptError& err,
         const CScript& spentSPK = CScript(), const std::vector<CTxOut>* refOutputs = nullptr)
{
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata, spentSPK, nullptr, refOutputs);
    stack.clear();
    err = SCRIPT_ERR_OK;
    return EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &err);
}

// The three queries against one and the same scriptPubKey.
struct Queries {
    bool okOutput, okSpent, okRef;
    valtype output, spent, ref;
    ScriptError errOutput, errSpent, errRef;
};

Queries QueryAll(const CScript& spk, script_verify_flags flags)
{
    Queries q;
    const CTransaction tx(MakeTx({spk}, 1));
    const std::vector<CTxOut> refOutputs{CTxOut(1000, spk)};
    std::vector<valtype> stack;

    q.okOutput = Run(tx, CScript() << OP_0 << OP_OUTPUTAUTHDEST, flags, stack, q.errOutput);
    if (q.okOutput && !stack.empty()) q.output = stack.back();

    q.okSpent = Run(tx, CScript() << valtype{AUTHDEST_SELECTOR} << OP_TXFIELD, flags, stack, q.errSpent, spk);
    if (q.okSpent && !stack.empty()) q.spent = stack.back();

    q.okRef = Run(tx, CScript() << OP_0 << valtype{AUTHDEST_SELECTOR} << OP_REFINPUTFIELD, flags, stack, q.errRef, CScript(), &refOutputs);
    if (q.okRef && !stack.empty()) q.ref = stack.back();
    return q;
}

void CheckAllReturn(const CScript& spk, const valtype& expected, const char* what)
{
    const Queries q = QueryAll(spk, ACTIVE_FLAGS);
    BOOST_CHECK_MESSAGE(q.okOutput && q.output == expected, what << ": OP_OUTPUTAUTHDEST");
    BOOST_CHECK_MESSAGE(q.okSpent && q.spent == expected, what << ": OP_TXFIELD 0x04");
    BOOST_CHECK_MESSAGE(q.okRef && q.ref == expected, what << ": OP_REFINPUTFIELD 0x04");
}

void CheckAllFail(const CScript& spk, const char* what)
{
    const Queries q = QueryAll(spk, ACTIVE_FLAGS);
    BOOST_CHECK_MESSAGE(!q.okOutput && q.errOutput == SCRIPT_ERR_OUTPUTAUTHDEST, what << ": OP_OUTPUTAUTHDEST");
    BOOST_CHECK_MESSAGE(!q.okSpent && q.errSpent == SCRIPT_ERR_TXFIELD, what << ": OP_TXFIELD 0x04");
    BOOST_CHECK_MESSAGE(!q.okRef && q.errRef == SCRIPT_ERR_REFINPUTFIELD, what << ": OP_REFINPUTFIELD 0x04");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(authdest_tests, AuthDestRegtestSetup)

BOOST_AUTO_TEST_CASE(opcode_registry)
{
    BOOST_CHECK_EQUAL((int)OP_OUTPUTAUTHDEST, 0xc2);
    BOOST_CHECK(OP_OUTPUTAUTHDEST <= MAX_OPCODE);
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPUTAUTHDEST), "OP_OUTPUTAUTHDEST");
    BOOST_CHECK_EQUAL((int)AUTHDEST_SELECTOR, 0x04);
    // Outside the NIP-033 BLS reservation.
    BOOST_CHECK(OP_OUTPUTAUTHDEST < 0xd8 || OP_OUTPUTAUTHDEST > 0xdc);
}

// Fixed vectors: exactly version || program, program bytes in original order.
BOOST_AUTO_TEST_CASE(format_vectors_native)
{
    const valtype program = AscendingProgram();
    BOOST_CHECK_EQUAL(HexStr(Expected(2, program)),
                      "02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    for (int version : {1, 2, 3}) {
        CheckAllReturn(Native(version, program), Expected((unsigned char)version, program), "native");
    }
    const Queries q = QueryAll(Native(3, program), ACTIVE_FLAGS);
    BOOST_CHECK_EQUAL(q.output.size(), 33U);
    BOOST_CHECK_EQUAL(HexStr(q.output), "03000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

BOOST_AUTO_TEST_CASE(format_vectors_with_asset)
{
    const valtype program = AscendingProgram();
    for (int version : {1, 2, 3}) {
        CheckAllReturn(WithAsset(Native(version, program)), Expected((unsigned char)version, program), "asset-wrapped");
    }
}

BOOST_AUTO_TEST_CASE(invalid_versions_and_lengths)
{
    const valtype program = AscendingProgram();
    CheckAllFail(Native(0, program), "witness v0 32 bytes (P2WSH)");
    CheckAllFail(Native(4, program), "witness v4");
    CheckAllFail(Native(16, program), "witness v16");
    CheckAllFail(Native(2, valtype(20, 0x42)), "v2 with 20-byte program");
    CheckAllFail(Native(1, valtype(31, 0x42)), "v1 with 31-byte program");
    CheckAllFail(Native(3, valtype(33, 0x42)), "v3 with 33-byte program");
    CheckAllFail(Native(3, valtype(40, 0x42)), "v3 with 40-byte program");
    CheckAllFail(CScript() << OP_DUP << OP_HASH160 << valtype(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG, "P2PKH");
    CheckAllFail(CScript() << OP_HASH160 << valtype(20, 0x11) << OP_EQUAL, "P2SH");
    CheckAllFail(CScript(), "empty script");
    // A legacy P2PKH-prefixed asset output is an asset, but not an AuthScript destination.
    CheckAllFail(WithAsset(CScript() << OP_DUP << OP_HASH160 << valtype(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG), "P2PKH asset");
}

// The 34-byte prefix is NOT enough: extra instructions change how the output is spent.
BOOST_AUTO_TEST_CASE(trailing_garbage_and_malformed_wrappers)
{
    const valtype program = AscendingProgram();
    for (int version : {1, 2, 3}) {
        const CScript native = Native(version, program);

        CScript extraOp = native;       extraOp << OP_TRUE;
        CheckAllFail(extraOp, "native + trailing opcode");

        CScript extraDrop = native;     extraDrop << OP_DROP << OP_TRUE;
        CheckAllFail(extraDrop, "native + OP_DROP OP_TRUE");

        CScript extraPush = native;     extraPush << valtype(4, 0x99);
        CheckAllFail(extraPush, "native + trailing push");

        // Asset wrapper followed by more script.
        CScript assetThenMore = WithAsset(native);  assetThenMore << OP_TRUE;
        CheckAllFail(assetThenMore, "asset wrapper + trailing opcode");

        // Asset wrapper without the closing OP_DROP.
        CScript good = WithAsset(native);
        CScript noDrop(good.begin(), good.end() - 1);
        CheckAllFail(noDrop, "asset wrapper without OP_DROP");

        // Truncated payload: marker and type survive, the message does not deserialize.
        CScript truncated = native;
        truncated << OP_XNA_ASSET << valtype{'x', 'n', 'a', 't', 0x08, 'A', 'U'} << OP_DROP;
        CheckAllFail(truncated, "asset wrapper with truncated payload");

        // Unknown marker.
        CScript badMarker = native;
        badMarker << OP_XNA_ASSET << valtype{'z', 'z', 'z', 't', 0x01, 'A', 0, 0, 0, 0, 0, 0, 0, 0} << OP_DROP;
        CheckAllFail(badMarker, "asset wrapper with unknown marker");

        // OP_XNA_ASSET not right after the program.
        CScript misplaced = native;
        misplaced << OP_NOP << OP_XNA_ASSET << valtype{'x', 'n', 'a', 't'} << OP_DROP;
        CheckAllFail(misplaced, "OP_XNA_ASSET not at byte 34");
    }
}

BOOST_AUTO_TEST_CASE(output_index_handling)
{
    const valtype program = AscendingProgram();
    const CTransaction tx(MakeTx({Native(2, program), Native(3, valtype(32, 0x77))}));
    std::vector<valtype> stack;
    ScriptError err;

    BOOST_CHECK(Run(tx, CScript() << OP_1 << OP_OUTPUTAUTHDEST, ACTIVE_FLAGS, stack, err));
    BOOST_CHECK(stack.back() == Expected(3, valtype(32, 0x77)));

    BOOST_CHECK(!Run(tx, CScript() << OP_2 << OP_OUTPUTAUTHDEST, ACTIVE_FLAGS, stack, err));   // out of range
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHDEST);
    BOOST_CHECK(!Run(tx, CScript() << OP_1NEGATE << OP_OUTPUTAUTHDEST, ACTIVE_FLAGS, stack, err)); // negative
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHDEST);
    BOOST_CHECK(!Run(tx, CScript() << OP_OUTPUTAUTHDEST, ACTIVE_FLAGS, stack, err));           // empty stack
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    // A covenant: "output 0 must pay the strict PQ destination X".
    const CScript covenant = CScript() << OP_0 << OP_OUTPUTAUTHDEST << Expected(2, program) << OP_EQUAL;
    BOOST_CHECK(Run(tx, covenant, ACTIVE_FLAGS, stack, err));
    BOOST_CHECK(stack.size() == 1 && stack.back() == valtype{1});
    // Same 32 bytes under another version do NOT satisfy it.
    const CTransaction wrongVersion(MakeTx({Native(3, program)}));
    BOOST_CHECK(Run(wrongVersion, covenant, ACTIVE_FLAGS, stack, err));
    BOOST_CHECK(stack.size() == 1 && stack.back().empty());
    const CTransaction v1SameBytes(MakeTx({Native(1, program)}));
    BOOST_CHECK(Run(v1SameBytes, covenant, ACTIVE_FLAGS, stack, err));
    BOOST_CHECK(stack.size() == 1 && stack.back().empty());
}

// Before activation nothing new exists: 0xc2 is a bad opcode and 0x04 an unknown
// selector, with the very same errors as before NIP-041 - also for a v1 destination.
BOOST_AUTO_TEST_CASE(inactive_behaviour_is_unchanged)
{
    const valtype program = AscendingProgram();
    for (int version : {1, 2, 3}) {
        const Queries q = QueryAll(Native(version, program), BASE_FLAGS);
        BOOST_CHECK(!q.okOutput);
        BOOST_CHECK_EQUAL(q.errOutput, SCRIPT_ERR_BAD_OPCODE);
        BOOST_CHECK(!q.okSpent);
        BOOST_CHECK_EQUAL(q.errSpent, SCRIPT_ERR_TXFIELD);
        BOOST_CHECK(!q.okRef);
        BOOST_CHECK_EQUAL(q.errRef, SCRIPT_ERR_REFINPUTFIELD);
    }
    // The strict families alone do not enable it: the dedicated flag does.
    const Queries q = QueryAll(Native(2, program), BASE_FLAGS | SCRIPT_VERIFY_AUTHSCRIPT_STRICT);
    BOOST_CHECK(!q.okOutput && q.errOutput == SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!q.okSpent && !q.okRef);
    // An unexecuted branch never trips on the opcode, active or not.
    std::vector<valtype> stack;
    ScriptError err;
    const CTransaction tx(MakeTx({Native(2, program)}));
    BOOST_CHECK(Run(tx, CScript() << OP_0 << OP_IF << OP_OUTPUTAUTHDEST << OP_ENDIF << OP_1, ACTIVE_FLAGS, stack, err));
}

// The flag is derived from the strict AuthScript activation height: one schedule.
BOOST_AUTO_TEST_CASE(activation_follows_the_strict_height)
{
    const Consensus::Params& consensus = GetParams().GetConsensus();
    const script_verify_flags below = ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, consensus, false);
    const script_verify_flags above = ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, consensus, true);
    BOOST_CHECK((below & SCRIPT_VERIFY_AUTHDEST) == 0);
    BOOST_CHECK((below & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) == 0);
    BOOST_CHECK((above & SCRIPT_VERIFY_AUTHDEST) != 0);
    BOOST_CHECK((above & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) != 0);

    Consensus::Params custom = consensus;
    custom.nStrictAuthScriptHeight = 120;
    BOOST_CHECK((ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, custom, custom.IsStrictAuthScriptActive(119)) & SCRIPT_VERIFY_AUTHDEST) == 0);
    BOOST_CHECK((ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, custom, custom.IsStrictAuthScriptActive(120)) & SCRIPT_VERIFY_AUTHDEST) != 0);
}

// NIP-023 operations keep their exact behaviour, active or not: 32 bytes, v1 only,
// prefix peek (trailing bytes ignored), failure on v2/v3.
BOOST_AUTO_TEST_CASE(legacy_commitment_operations_are_untouched)
{
    const valtype program = AscendingProgram();
    for (script_verify_flags flags : {BASE_FLAGS, ACTIVE_FLAGS}) {
        std::vector<valtype> stack;
        ScriptError err;
        CScript v1Garbage = Native(1, program);
        v1Garbage << OP_TRUE;
        const std::vector<CScript> outs{Native(1, program), Native(2, program), Native(3, program), v1Garbage};
        const CTransaction tx(MakeTx(outs, 1));
        const std::vector<CTxOut> refV1{CTxOut(1000, Native(1, program))};
        const std::vector<CTxOut> refV2{CTxOut(1000, Native(2, program))};

        BOOST_CHECK(Run(tx, CScript() << OP_0 << OP_OUTPUTAUTHCOMMITMENT, flags, stack, err));
        BOOST_CHECK(stack.back() == program);
        BOOST_CHECK(Run(tx, CScript() << OP_3 << OP_OUTPUTAUTHCOMMITMENT, flags, stack, err)); // legacy prefix peek
        BOOST_CHECK(stack.back() == program);
        BOOST_CHECK(!Run(tx, CScript() << OP_1 << OP_OUTPUTAUTHCOMMITMENT, flags, stack, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);
        BOOST_CHECK(!Run(tx, CScript() << OP_2 << OP_OUTPUTAUTHCOMMITMENT, flags, stack, err));

        BOOST_CHECK(Run(tx, CScript() << valtype{0x02} << OP_TXFIELD, flags, stack, err, Native(1, program)));
        BOOST_CHECK(stack.back() == program);
        BOOST_CHECK(!Run(tx, CScript() << valtype{0x02} << OP_TXFIELD, flags, stack, err, Native(3, program)));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TXFIELD);

        BOOST_CHECK(Run(tx, CScript() << OP_0 << valtype{0x02} << OP_REFINPUTFIELD, flags, stack, err, CScript(), &refV1));
        BOOST_CHECK(stack.back() == program);
        BOOST_CHECK(!Run(tx, CScript() << OP_0 << valtype{0x02} << OP_REFINPUTFIELD, flags, stack, err, CScript(), &refV2));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
        // Selector 0x05 stays unknown in both operations.
        BOOST_CHECK(!Run(tx, CScript() << valtype{0x05} << OP_TXFIELD, flags, stack, err, Native(1, program)));
        BOOST_CHECK(!Run(tx, CScript() << OP_0 << valtype{0x05} << OP_REFINPUTFIELD, flags, stack, err, CScript(), &refV1));
    }
}

// The result never depends on the ambient activation context, only on the flags.
BOOST_AUTO_TEST_CASE(independent_of_ambient_context)
{
    const valtype program = AscendingProgram();
    const CScript spk = WithAsset(Native(3, program));
    {
        CStrictAuthScriptContext inactive(false);
        CheckAllReturn(spk, Expected(3, program), "ambient inactive");
    }
    {
        CStrictAuthScriptContext active(true);
        CheckAllReturn(spk, Expected(3, program), "ambient active");
    }
}

BOOST_AUTO_TEST_CASE(review_payload_must_not_consume_drop)
{
    for (int version : {1, 2, 3}) {
        CScript spk = Native(version, AscendingProgram());
        // Declares an 8-byte owner name but carries only seven bytes.
        // The old script-level parser reads OP_DROP (0x75) as byte eight.
        spk << OP_XNA_ASSET << valtype{'x','n','a','o',8,'A','B','C','D','E','F','G'} << OP_DROP;
        CheckAllFail(spk, "truncated owner payload must not borrow OP_DROP");
    }
}

// Evidence for the opcode compatibility review: the introspection opcodes that are
// expected NOT to care about the address family behave identically for generic v1,
// strict v2 and strict v3 scripts. They either return raw bytes/values or never look
// at a script's type, so a covenant written with them keeps working for any family.
BOOST_AUTO_TEST_CASE(other_introspection_opcodes_are_family_agnostic)
{
    static constexpr script_verify_flags FLAGS = ACTIVE_FLAGS |
        SCRIPT_VERIFY_OUTPUTVALUE | SCRIPT_VERIFY_OUTPUTSCRIPT | SCRIPT_VERIFY_OUTPUTASSETFIELD |
        SCRIPT_VERIFY_INPUTASSETFIELD | SCRIPT_VERIFY_INPUTOUTPUTCOUNT | SCRIPT_VERIFY_TXLOCKTIME |
        SCRIPT_VERIFY_TXHASH | SCRIPT_VERIFY_64BIT_INTEGERS;
    const valtype program = AscendingProgram();
    std::vector<valtype> stack;
    ScriptError err;
    std::vector<valtype> txhashes;

    for (int version : {1, 2, 3}) {
        for (bool withAsset : {false, true}) {
            const CScript spk = withAsset ? WithAsset(Native(version, program)) : Native(version, program);
            const CTransaction tx(MakeTx({spk}, 1));
            const std::vector<CTxOut> refOutputs{CTxOut(1000, spk)};
            const std::string what = strprintf("v%d%s", version, withAsset ? "+asset" : "");

            // Raw scriptPubKey, byte for byte, for the three sources.
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_0 << OP_OUTPUTSCRIPT, FLAGS, stack, err) &&
                                stack.back() == valtype(spk.begin(), spk.end()), what << ": OP_OUTPUTSCRIPT");
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << valtype{0x03} << OP_TXFIELD, FLAGS, stack, err, spk) &&
                                stack.back() == valtype(spk.begin(), spk.end()), what << ": OP_TXFIELD 0x03");
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_0 << valtype{0x03} << OP_REFINPUTFIELD, FLAGS, stack, err, CScript(), &refOutputs) &&
                                stack.back() == valtype(spk.begin(), spk.end()), what << ": OP_REFINPUTFIELD 0x03");

            // Values and counters.
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_0 << OP_OUTPUTVALUE << CScriptNum(1000) << OP_EQUAL, FLAGS, stack, err) &&
                                stack.back() == valtype{1}, what << ": OP_OUTPUTVALUE");
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_0 << valtype{0x01} << OP_REFINPUTFIELD << CScriptNum(1000) << OP_EQUAL, FLAGS, stack, err, CScript(), &refOutputs) &&
                                stack.back() == valtype{1}, what << ": OP_REFINPUTFIELD 0x01");
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_INPUTCOUNT << OP_1 << OP_EQUALVERIFY << OP_OUTPUTCOUNT << OP_1 << OP_EQUALVERIFY
                                                  << OP_REFINPUTCOUNT << OP_1 << OP_EQUAL, FLAGS, stack, err, CScript(), &refOutputs) &&
                                stack.back() == valtype{1}, what << ": input/output/refinput counts");
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_TXLOCKTIME, FLAGS, stack, err), what << ": OP_TXLOCKTIME");

            // OP_TXHASH over the outputs: succeeds for every family and commits to the exact script.
            BOOST_CHECK_MESSAGE(Run(tx, CScript() << valtype{0x10} << OP_TXHASH, FLAGS, stack, err) && stack.back().size() == 32,
                                what << ": OP_TXHASH (outputs)");
            if (!stack.empty()) txhashes.push_back(stack.back());

            // Asset name introspection reads the asset whatever prefix carries it.
            if (withAsset) {
                const valtype name{'A', 'U', 'T', 'H', 'D', 'E', 'S', 'T'};
                BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_0 << valtype{0x01} << OP_OUTPUTASSETFIELD, FLAGS, stack, err) &&
                                    stack.back() == name, what << ": OP_OUTPUTASSETFIELD name");
                BOOST_CHECK_MESSAGE(Run(tx, CScript() << OP_0 << valtype{0x01} << OP_REFINPUTASSETFIELD, FLAGS, stack, err, CScript(), &refOutputs) &&
                                    stack.back() == name, what << ": OP_REFINPUTASSETFIELD name");
            }
        }
    }
    // Six different scripts -> six different output hashes (the family is committed to).
    for (size_t i = 0; i < txhashes.size(); i++)
        for (size_t j = i + 1; j < txhashes.size(); j++)
            BOOST_CHECK(txhashes[i] != txhashes[j]);
}

BOOST_AUTO_TEST_SUITE_END()
