// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/assets.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_neurai.h"
#include "validation.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags INPUTASSETFIELD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_INPUTASSETFIELD;
static constexpr script_verify_flags INPUTASSETFIELD_FLAGS_DISCOURAGE =
    INPUTASSETFIELD_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags INPUTASSETFIELD_ARITH64_FLAGS =
    INPUTASSETFIELD_FLAGS | SCRIPT_VERIFY_64BIT_INTEGERS;
static constexpr script_verify_flags NO_INPUTASSETFIELD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_INPUTASSETFIELD_FLAGS_DISCOURAGE =
    NO_INPUTASSETFIELD_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

bool CheckInputs(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, script_verify_flags flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData &txdata, std::vector<CScriptCheck> *pvChecks = nullptr, std::shared_ptr<std::vector<CTxOut>> pRefOutputs = nullptr, ChainContext chainCtx = {}, bool* pfUsesChainContext = nullptr);

namespace {

std::vector<unsigned char> EncodeLE8(int64_t value)
{
    std::vector<unsigned char> out(8);
    memcpy(out.data(), &value, 8);
    return out;
}

std::vector<unsigned char> EncodeByte(unsigned char value)
{
    return std::vector<unsigned char>{value};
}

std::vector<CTxOut> BuildAssetPrevoutsForNetwork(const std::string& chain)
{
    SelectParams(chain);

    std::vector<CTxOut> prevouts;
    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());

    // Prevout 0: non-asset P2PKH.
    {
        CTxOut out;
        out.nValue = 1000;
        out.scriptPubKey = GetScriptForDestination(dest);
        prevouts.push_back(out);
    }

    // Prevout 1: transfer ROOT asset.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CAssetTransfer transfer("GOLD", 25 * COIN);
        transfer.ConstructTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    // Prevout 2: new asset with IPFS.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CNewAsset asset("NEWASSET", 100 * COIN, 2, 1, 1,
                        DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));
        asset.ConstructTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    // Prevout 3: reissue without hash, nUnits = -1.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CReissueAsset reissue("REISSUEASSET", 5 * COIN, -1, 0, "");
        reissue.ConstructTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    // Prevout 4: reissue with hash.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CReissueAsset reissue("HASHEDASSET", 7 * COIN, 0, 1,
                              DecodeAssetData("9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca"));
        reissue.ConstructTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    // Prevout 5: owner asset.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CNewAsset asset("OWNERROOT", COIN);
        asset.ConstructOwnerTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    // Prevout 6: qualifier null-data.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForNullAssetDataDestination(dest);
        CNullAssetTxData nullData("#TAGTEST", (int)QualifierType::ADD_QUALIFIER);
        nullData.ConstructTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    // Prevout 7: null verifier data.
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = CScript();
        CNullAssetTxVerifierString verifier("true");
        verifier.ConstructTransaction(out.scriptPubKey);
        prevouts.push_back(out);
    }

    return prevouts;
}

std::vector<CTxOut> BuildDEPINPrevoutsForNetwork(const std::string& chain)
{
    SelectParams(chain);

    std::vector<CTxOut> prevouts;
    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());

    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey = GetScriptForDestination(dest);
    CAssetTransfer transfer("&SENSOR", COIN);
    transfer.ConstructTransaction(out.scriptPubKey);
    prevouts.push_back(out);

    return prevouts;
}

CMutableTransaction BuildSpendingTx(size_t inputCount)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    for (size_t i = 0; i < inputCount; ++i) {
        CTxIn vin;
        vin.prevout.hash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
        vin.prevout.n = static_cast<uint32_t>(i);
        tx.vin.push_back(vin);
    }

    tx.vout.emplace_back(0, CScript() << OP_TRUE);
    return tx;
}

bool RunScriptWithPrevouts(const CTransaction& tx, const std::vector<CTxOut>& prevouts, const CScript& script, script_verify_flags flags,
                           std::vector<std::vector<unsigned char>>& resultStack, ScriptError* errOut = nullptr)
{
    const CScript spentScriptPubKey = prevouts.empty() ? CScript() : prevouts[0].scriptPubKey;
    const CAmount spentAmount = prevouts.empty() ? 0 : prevouts[0].nValue;
    TransactionSignatureChecker checker(&tx, 0, spentAmount, spentScriptPubKey, &prevouts);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

bool RunScriptWithoutPrevouts(const CTransaction& tx, const CScript& script, script_verify_flags flags,
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

bool DirectGetInputAssetField(const CTransaction& tx, const std::vector<CTxOut>& prevouts, unsigned int nInput, unsigned char selector, std::vector<unsigned char>& result)
{
    const CScript spentScriptPubKey = prevouts.empty() ? CScript() : prevouts[0].scriptPubKey;
    const CAmount spentAmount = prevouts.empty() ? 0 : prevouts[0].nValue;
    TransactionSignatureChecker checker(&tx, 0, spentAmount, spentScriptPubKey, &prevouts);
    return checker.GetInputAssetField(nInput, selector, result);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(inputassetfield_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(inputassetfield_disabled_treated_as_nop)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x01} << OP_INPUTASSETFIELD
           << OP_DROP << OP_DROP << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, script, NO_INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(inputassetfield_disabled_discourage_nops_fails)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x01} << OP_INPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, script, NO_INPUTASSETFIELD_FLAGS_DISCOURAGE, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(inputassetfield_error_cases)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(1) << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(-1) << std::vector<unsigned char>{0x01} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(99) << std::vector<unsigned char>{0x01} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x00} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x08} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x01, 0x02} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);

    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, CScript() << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);

    BOOST_CHECK(!RunScriptWithoutPrevouts(tx, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x01} << OP_INPUTASSETFIELD, INPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(inputassetfield_transfer_fields)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 1, 0x01, result));
    BOOST_CHECK(result == std::vector<unsigned char>({'G','O','L','D'}));

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 1, 0x02, result));
    BOOST_CHECK(result == EncodeLE8(25 * COIN));

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 1, 0x07, result));
    BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::ROOT)));

    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 1, 0x03, result));
    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 1, 0x04, result));
    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 1, 0x05, result));
    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 1, 0x06, result));
}

BOOST_AUTO_TEST_CASE(inputassetfield_new_reissue_and_owner_fields)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 2, 0x03, result));
    BOOST_CHECK(result == EncodeByte(2));
    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 2, 0x05, result));
    BOOST_CHECK(result == EncodeByte(1));
    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 2, 0x06, result));
    BOOST_CHECK(result == [](){ auto s = DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"); return std::vector<unsigned char>(s.begin(), s.end()); }());

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 3, 0x03, result));
    BOOST_CHECK(result == EncodeByte(0xff));
    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 3, 0x04, result));
    BOOST_CHECK(result == EncodeByte(0x00));
    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 3, 0x05, result));

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 4, 0x06, result));
    BOOST_CHECK(result == [](){ auto s = DecodeAssetData("9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca"); return std::vector<unsigned char>(s.begin(), s.end()); }());

    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 5, 0x01, result));
    BOOST_CHECK(result == std::vector<unsigned char>({'O','W','N','E','R','R','O','O','T','!'}));
    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 5, 0x02, result));
    BOOST_CHECK(result == EncodeLE8(OWNER_ASSET_AMOUNT));
    BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 5, 0x07, result));
    BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::OWNER)));
}

BOOST_AUTO_TEST_CASE(inputassetfield_null_data_inputs_fail)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    std::vector<unsigned char> result;

    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 6, 0x01, result));
    BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 7, 0x01, result));
}

BOOST_AUTO_TEST_CASE(inputassetfield_evalscript_and_verifyscript)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    std::vector<std::vector<unsigned char>> result;

    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x01}
           << OP_INPUTASSETFIELD << std::vector<unsigned char>({'G','O','L','D'}) << OP_EQUAL;

    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, script, INPUTASSETFIELD_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(CScript(), script, nullptr, INPUTASSETFIELD_FLAGS,
                             TransactionSignatureChecker(&tx, 0, prevouts[0].nValue, prevouts[0].scriptPubKey, &prevouts), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(inputassetfield_cross_input_and_64bit_integration)
{
    const std::vector<CTxOut> prevouts = BuildAssetPrevoutsForNetwork(CBaseChainParams::TESTNET);
    CTransaction tx(BuildSpendingTx(prevouts.size()));
    std::vector<std::vector<unsigned char>> result;

    CScript sameTypeScript;
    sameTypeScript << CScriptNum(1) << std::vector<unsigned char>{0x07} << OP_INPUTASSETFIELD
                   << CScriptNum(2) << std::vector<unsigned char>{0x07} << OP_INPUTASSETFIELD
                   << OP_EQUAL;

    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, sameTypeScript, INPUTASSETFIELD_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});

    CScript arithScript;
    arithScript << CScriptNum(1) << std::vector<unsigned char>{0x02} << OP_INPUTASSETFIELD
                << OP_2 << OP_MUL << CScriptNum(50 * COIN) << OP_EQUAL;

    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, arithScript, INPUTASSETFIELD_ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(inputassetfield_depin_type_network_matrix)
{
    std::vector<unsigned char> result;

    {
        const std::vector<CTxOut> prevouts = BuildDEPINPrevoutsForNetwork(CBaseChainParams::REGTEST);
        CTransaction tx(BuildSpendingTx(prevouts.size()));
        BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 0, 0x07, result));
        BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::DEPIN)));
    }

    {
        const std::vector<CTxOut> prevouts = BuildDEPINPrevoutsForNetwork(CBaseChainParams::TESTNET);
        CTransaction tx(BuildSpendingTx(prevouts.size()));
        BOOST_CHECK(DirectGetInputAssetField(tx, prevouts, 0, 0x07, result));
        BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::DEPIN)));
    }

    {
        const std::vector<CTxOut> prevouts = BuildDEPINPrevoutsForNetwork(CBaseChainParams::MAIN);
        CTransaction tx(BuildSpendingTx(prevouts.size()));
        BOOST_CHECK(!DirectGetInputAssetField(tx, prevouts, 0, 0x07, result));
    }
}

BOOST_AUTO_TEST_CASE(inputassetfield_checkinputs_enqueued_path_integration)
{
    SelectParams(CBaseChainParams::TESTNET);

    CCoinsView view;
    CCoinsViewCache coins(&view);

    CScript covenant;
    covenant << CScriptNum(1) << EncodeByte(0x01) << OP_INPUTASSETFIELD
             << std::vector<unsigned char>({'G','O','L','D'}) << OP_EQUAL;

    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());
    CTxOut covenantPrevout(0, covenant);
    CTxOut assetPrevout;
    assetPrevout.nValue = 0;
    assetPrevout.scriptPubKey = GetScriptForDestination(dest);
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(assetPrevout.scriptPubKey);

    const COutPoint prevout0(uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0);
    const COutPoint prevout1(uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 1);
    coins.AddCoin(prevout0, Coin(covenantPrevout, 10, false), true);
    coins.AddCoin(prevout1, Coin(assetPrevout, 10, false), true);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(prevout0, CScript());
    mtx.vin.emplace_back(prevout1, CScript());
    mtx.vout.emplace_back(0, CScript() << OP_TRUE);

    const CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx);
    CValidationState state;
    std::vector<CScriptCheck> checks;

    BOOST_CHECK(CheckInputs(tx, state, coins, true, INPUTASSETFIELD_FLAGS, true, false, txdata, &checks));
    BOOST_REQUIRE_EQUAL(checks.size(), tx.vin.size());
    BOOST_CHECK(checks[0]());
    BOOST_CHECK_EQUAL(checks[0].GetScriptError(), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
