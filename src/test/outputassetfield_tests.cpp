// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/assets.h"
#include "base58.h"
#include "chainparams.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

static const unsigned int OUTPUTASSETFIELD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_OUTPUTASSETFIELD;
static const unsigned int OUTPUTASSETFIELD_FLAGS_DISCOURAGE =
    OUTPUTASSETFIELD_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static const unsigned int NO_OUTPUTASSETFIELD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static const unsigned int NO_OUTPUTASSETFIELD_FLAGS_DISCOURAGE =
    NO_OUTPUTASSETFIELD_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

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

CMutableTransaction BuildAssetTxForNetwork(const std::string& chain)
{
    SelectParams(chain);

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());

    // Output 0: non-asset P2PKH
    {
        CTxOut out;
        out.nValue = 1000;
        out.scriptPubKey = GetScriptForDestination(dest);
        tx.vout.push_back(out);
    }

    // Output 1: transfer ROOT asset
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CAssetTransfer transfer("GOLD", 25 * COIN);
        transfer.ConstructTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    // Output 2: new asset with IPFS
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CNewAsset asset("NEWASSET", 100 * COIN, 2, 1, 1,
                        DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));
        asset.ConstructTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    // Output 3: reissue without hash, nUnits = -1, nReissuable = 0
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CReissueAsset reissue("REISSUEASSET", 5 * COIN, -1, 0, "");
        reissue.ConstructTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    // Output 4: reissue with hash
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CReissueAsset reissue("HASHEDASSET", 7 * COIN, 0, 1,
                              DecodeAssetData("9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca"));
        reissue.ConstructTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    // Output 5: owner asset
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CNewAsset asset("OWNERROOT", COIN);
        asset.ConstructOwnerTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    // Output 6: qualifier null-data
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForNullAssetDataDestination(dest);
        CNullAssetTxData nullData("#TAGTEST", (int)QualifierType::ADD_QUALIFIER);
        nullData.ConstructTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    // Output 7: null verifier data
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = CScript();
        CNullAssetTxVerifierString verifier("true");
        verifier.ConstructTransaction(out.scriptPubKey);
        tx.vout.push_back(out);
    }

    return tx;
}

CMutableTransaction BuildDEPINTxForNetwork(const std::string& chain)
{
    SelectParams(chain);

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());

    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey = GetScriptForDestination(dest);
    CAssetTransfer transfer("&SENSOR", COIN);
    transfer.ConstructTransaction(out.scriptPubKey);
    tx.vout.push_back(out);

    return tx;
}

bool RunScript(const CTransaction& tx, const CScript& script, unsigned int flags,
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

bool DirectGetOutputAssetField(const CTransaction& tx, unsigned int nOut, unsigned char selector, std::vector<unsigned char>& result)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    return checker.GetOutputAssetField(nOut, selector, result);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(outputassetfield_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(outputassetfield_disabled_treated_as_nop)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x01} << OP_OUTPUTASSETFIELD
           << OP_DROP << OP_DROP << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(RunScript(tx, script, NO_OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(outputassetfield_disabled_discourage_nops_fails)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x01} << OP_OUTPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, NO_OUTPUTASSETFIELD_FLAGS_DISCOURAGE, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(outputassetfield_error_cases)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;

    BOOST_CHECK(!RunScript(tx, CScript() << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(1) << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(-1) << std::vector<unsigned char>{0x01} << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTASSETFIELD);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(99) << std::vector<unsigned char>{0x01} << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTASSETFIELD);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x00} << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTASSETFIELD);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x08} << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTASSETFIELD);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(1) << std::vector<unsigned char>{0x01, 0x02} << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTASSETFIELD);

    BOOST_CHECK(!RunScript(tx, CScript() << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_OUTPUTASSETFIELD, OUTPUTASSETFIELD_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(outputassetfield_transfer_fields)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputAssetField(tx, 1, 0x01, result));
    BOOST_CHECK(result == std::vector<unsigned char>({'G','O','L','D'}));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 1, 0x02, result));
    BOOST_CHECK(result == EncodeLE8(25 * COIN));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 1, 0x07, result));
    BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::ROOT)));

    BOOST_CHECK(!DirectGetOutputAssetField(tx, 1, 0x03, result));
    BOOST_CHECK(!DirectGetOutputAssetField(tx, 1, 0x04, result));
    BOOST_CHECK(!DirectGetOutputAssetField(tx, 1, 0x05, result));
    BOOST_CHECK(!DirectGetOutputAssetField(tx, 1, 0x06, result));
}

BOOST_AUTO_TEST_CASE(outputassetfield_new_asset_fields)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x01, result));
    BOOST_CHECK(result == std::vector<unsigned char>({'N','E','W','A','S','S','E','T'}));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x02, result));
    BOOST_CHECK(result == EncodeLE8(100 * COIN));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x03, result));
    BOOST_CHECK(result == EncodeByte(2));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x04, result));
    BOOST_CHECK(result == EncodeByte(1));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x05, result));
    BOOST_CHECK(result == EncodeByte(1));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x06, result));
    BOOST_CHECK(result == DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 2, 0x07, result));
    BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::ROOT)));
}

BOOST_AUTO_TEST_CASE(outputassetfield_reissue_fields)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputAssetField(tx, 3, 0x01, result));
    BOOST_CHECK(result == std::vector<unsigned char>({'R','E','I','S','S','U','E','A','S','S','E','T'}));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 3, 0x02, result));
    BOOST_CHECK(result == EncodeLE8(5 * COIN));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 3, 0x03, result));
    BOOST_CHECK(result == EncodeByte(0xff));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 3, 0x04, result));
    BOOST_CHECK(result == EncodeByte(0x00));

    BOOST_CHECK(!DirectGetOutputAssetField(tx, 3, 0x05, result));
    BOOST_CHECK(!DirectGetOutputAssetField(tx, 3, 0x06, result));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 3, 0x07, result));
    BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::REISSUE)));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 4, 0x06, result));
    BOOST_CHECK(result == DecodeAssetData("9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca"));
}

BOOST_AUTO_TEST_CASE(outputassetfield_owner_fields)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputAssetField(tx, 5, 0x01, result));
    BOOST_CHECK(result == std::vector<unsigned char>({'O','W','N','E','R','R','O','O','T','!'}));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 5, 0x02, result));
    BOOST_CHECK(result == EncodeLE8(OWNER_ASSET_AMOUNT));

    BOOST_CHECK(DirectGetOutputAssetField(tx, 5, 0x07, result));
    BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::OWNER)));

    BOOST_CHECK(!DirectGetOutputAssetField(tx, 5, 0x03, result));
}

BOOST_AUTO_TEST_CASE(outputassetfield_null_data_outputs_fail)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<unsigned char> result;

    BOOST_CHECK(!DirectGetOutputAssetField(tx, 6, 0x01, result));
    BOOST_CHECK(!DirectGetOutputAssetField(tx, 7, 0x01, result));
}

BOOST_AUTO_TEST_CASE(outputassetfield_evalscript_equal_and_verifyscript)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<std::vector<unsigned char>> result;

    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x01}
           << OP_OUTPUTASSETFIELD << std::vector<unsigned char>({'G','O','L','D'}) << OP_EQUAL;

    BOOST_CHECK(RunScript(tx, script, OUTPUTASSETFIELD_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});

    CScript scriptSig;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(scriptSig, script, nullptr, OUTPUTASSETFIELD_FLAGS,
                             TransactionSignatureChecker(&tx, 0, 0), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(outputassetfield_type_confusion_reissue_vs_root)
{
    CTransaction tx(BuildAssetTxForNetwork(CBaseChainParams::TESTNET));
    std::vector<std::vector<unsigned char>> result;

    CScript script;
    script << CScriptNum(3) << std::vector<unsigned char>{0x07}
           << OP_OUTPUTASSETFIELD << EncodeByte((unsigned char)IntFromAssetType(AssetType::ROOT)) << OP_EQUAL;

    BOOST_CHECK(RunScript(tx, script, OUTPUTASSETFIELD_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{});
}

BOOST_AUTO_TEST_CASE(outputassetfield_depin_type_network_matrix)
{
    std::vector<unsigned char> result;

    {
        CTransaction tx(BuildDEPINTxForNetwork(CBaseChainParams::REGTEST));
        BOOST_CHECK(DirectGetOutputAssetField(tx, 0, 0x07, result));
        BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::DEPIN)));
    }

    {
        CTransaction tx(BuildDEPINTxForNetwork(CBaseChainParams::TESTNET));
        BOOST_CHECK(DirectGetOutputAssetField(tx, 0, 0x07, result));
        BOOST_CHECK(result == EncodeByte((unsigned char)IntFromAssetType(AssetType::DEPIN)));
    }

    {
        CTransaction tx(BuildDEPINTxForNetwork(CBaseChainParams::MAIN));
        BOOST_CHECK(!DirectGetOutputAssetField(tx, 0, 0x07, result));
    }
}

BOOST_AUTO_TEST_SUITE_END()
