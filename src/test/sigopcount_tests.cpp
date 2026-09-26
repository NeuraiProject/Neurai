// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "assets/assettypes.h"
#include "policy/policy.h"
#include "hash.h"
#include "consensus/validation.h"
#include "pubkey.h"
#include "key.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "test/test_neurai.h"

#include <vector>

#include <boost/test/unit_test.hpp>

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript &s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(sigopcount_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(GetSigOpCount_test)
    {
        BOOST_TEST_MESSAGE("Running get_sig_op_count Test");

        // Test CScript::get_sig_op_count()
        CScript s1;
        BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0U);
        BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0U);

        uint160 dummy;
        s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 2U);
        s1 << OP_IF << OP_CHECKSIG << OP_ENDIF;
        BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 3U);
        BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 21U);

        CScript p2sh = GetScriptForDestination(CScriptID(s1));
        CScript scriptSig;
        scriptSig << OP_0 << Serialize(s1);
        BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

        std::vector<CPubKey> keys;
        for (int i = 0; i < 3; i++)
        {
            CKey k;
            k.MakeNewKey(true);
            keys.push_back(k.GetPubKey());
        }
        CScript s2 = GetScriptForMultisig(1, keys);
        BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
        BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);

        p2sh = GetScriptForDestination(CScriptID(s2));
        BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(true), 0U);
        BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(false), 0U);
        CScript scriptSig2;
        scriptSig2 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << Serialize(s2);
        BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig2), 3U);
    }

    /**
     * Verifies script execution of the zeroth scriptPubKey of tx output and
     * zeroth scriptSig and witness of tx input.
     */
    ScriptError VerifyWithFlag(const CTransaction &output, const CMutableTransaction &input, script_verify_flags flags)
    {
        ScriptError error;
        CTransaction inputi(input);
        bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, &inputi.vin[0].scriptWitness, flags,
                                TransactionSignatureChecker(&inputi, 0, output.vout[0].nValue, output.vout[0].scriptPubKey), &error);
        BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

        return error;
    }

    /**
     * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
     * and witness such that spendingTx spends output zero of creationTx.
     * Also inserts creationTx's output into the coins view.
     */
    void BuildTxs(CMutableTransaction &spendingTx, CCoinsViewCache &coins, CMutableTransaction &creationTx, const CScript &scriptPubKey, const CScript &scriptSig, const CScriptWitness &witness)
    {
        creationTx.nVersion = 1;
        creationTx.vin.resize(1);
        creationTx.vin[0].prevout.SetNull();
        creationTx.vin[0].scriptSig = CScript();
        creationTx.vout.resize(1);
        creationTx.vout[0].nValue = 1;
        creationTx.vout[0].scriptPubKey = scriptPubKey;

        spendingTx.nVersion = 1;
        spendingTx.vin.resize(1);
        spendingTx.vin[0].prevout.hash = creationTx.GetHash();
        spendingTx.vin[0].prevout.n = 0;
        spendingTx.vin[0].scriptSig = scriptSig;
        spendingTx.vin[0].scriptWitness = witness;
        spendingTx.vout.resize(1);
        spendingTx.vout[0].nValue = 1;
        spendingTx.vout[0].scriptPubKey = CScript();

        AddCoins(coins, creationTx, 0, uint256());
    }

    BOOST_AUTO_TEST_CASE(GetTxSigOpCost_test)
    {
        BOOST_TEST_MESSAGE("Running GetTXSigOpCost Test");

        // Transaction creates outputs
        CMutableTransaction creationTx;
        // Transaction that spends outputs and whose
        // sig op cost is going to be tested
        CMutableTransaction spendingTx;

        // Create utxo set
        CCoinsView coinsDummy;
        CCoinsViewCache coins(&coinsDummy);
        // Create key
        CKey key;
        key.MakeNewKey(true);
        CPubKey pubkey = key.GetPubKey();
        // Default flags
        script_verify_flags flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;

        // Multisig script (legacy counting)
        {
            CScript scriptPubKey =
                    CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
            // Do not use a valid signature to avoid using wallet operations.
            CScript scriptSig = CScript() << OP_0 << OP_0;

            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
            // Legacy counting only includes signature operations in scriptSigs and scriptPubKeys
            // of a transaction and does not take the actual executed sig operations into account.
            // spendingTx in itself does not contain a signature operation.
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
            // creationTx contains two signature operations in its scriptPubKey, but legacy counting
            // is not accurate.
            assert(GetTransactionSigOpCost(CTransaction(creationTx), coins, flags) == MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR);
            // Sanity check: script verification fails because of an invalid signature.
            assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
        }

        // Multisig nested in P2SH
        {
            CScript redeemScript =
                    CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
            CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
            CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, CScriptWitness());
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2 * WITNESS_SCALE_FACTOR);
            assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
        }

        // P2WPKH witness program
        {
            CScript p2pk = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
            CScript scriptPubKey = GetScriptForWitness(p2pk);
            CScript scriptSig = CScript();
            CScriptWitness scriptWitness;
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));


            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
            // No signature operations if we don't verify the witness.
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
            assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);

            // The sig op cost for witness version != 0 is zero.
            assert(scriptPubKey[0] == 0x00);
            scriptPubKey[0] = 0x51;
            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
            scriptPubKey[0] = 0x00;
            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);

            // The witness of a coinbase transaction is not taken into account.
            spendingTx.vin[0].prevout.SetNull();
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        }

        // P2WPKH nested in P2SH
        {
            CScript p2pk = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
            CScript scriptSig = GetScriptForWitness(p2pk);
            CScript scriptPubKey = GetScriptForDestination(CScriptID(scriptSig));
            scriptSig = CScript() << ToByteVector(scriptSig);
            CScriptWitness scriptWitness;
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));

            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 1);
            assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_EQUALVERIFY);
        }

        // P2WSH witness program
        {
            CScript witnessScript =
                    CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
            CScript scriptPubKey = GetScriptForWitness(witnessScript);
            CScript scriptSig = CScript();
            CScriptWitness scriptWitness;
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));
            scriptWitness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags & ~SCRIPT_VERIFY_WITNESS) == 0);
            assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
        }

        // P2WSH nested in P2SH
        {
            CScript witnessScript =
                    CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
            CScript redeemScript = GetScriptForWitness(witnessScript);
            CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
            CScript scriptSig = CScript() << ToByteVector(redeemScript);
            CScriptWitness scriptWitness;
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));
            scriptWitness.stack.push_back(std::vector<unsigned char>(0));
            scriptWitness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

            BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig, scriptWitness);
            assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
            assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
        }
    }

BOOST_AUTO_TEST_CASE(optional_signature_cost_paths_and_activation)
{
    for (opcodetype opcode : {OP_CHECKSIGFROMSTACK, OP_CHECKSIGADD, OP_CHECKSIG_ED25519}) {
        const bool csfs = opcode == OP_CHECKSIGFROMSTACK;
        const bool csa = opcode == OP_CHECKSIGADD;
        const bool ed = opcode == OP_CHECKSIG_ED25519;
        const script_verify_flags activation = csfs ? SCRIPT_VERIFY_CHECKSIGFROMSTACK :
            (csa ? SCRIPT_VERIFY_CHECKSIGADD : SCRIPT_VERIFY_ED25519);
        const script_verify_flags inactive = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_AUTHSCRIPT;
        const script_verify_flags active = inactive | activation;
        // Static counting includes inactive branches, but never bytes inside pushes.
        const CScript script = CScript() << std::vector<unsigned char>{static_cast<unsigned char>(opcode)} << OP_DROP
            << OP_0 << OP_IF << opcode << OP_ENDIF << OP_TRUE;
        BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 0U);
        BOOST_CHECK_EQUAL(script.GetSigOpCount(true, csfs, csa, ed), 1U);
        // Other opcode flags must not accidentally activate this opcode's charge.
        const script_verify_flags otherFlags = inactive |
            ((SCRIPT_VERIFY_CHECKSIGFROMSTACK | SCRIPT_VERIFY_CHECKSIGADD | SCRIPT_VERIFY_ED25519) & ~activation);
        CCoinsView base;
        CCoinsViewCache coins(&base);
        CMutableTransaction creation, spending;
        CScriptWitness empty;
        BuildTxs(spending, coins, creation, script, CScript(), empty);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(creation), coins, inactive), 0);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(creation), coins, active), 4);
        // A bare script is charged when spent even if created before activation.
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, active), 4);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, inactive), 0);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, otherFlags), 0);
        // ScriptSig instructions are also part of the legacy static count.
        spending.vin[0].scriptSig = CScript() << opcode;
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, active), 8);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, inactive), 0);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, otherFlags), 0);

        const CScript p2sh = GetScriptForDestination(CScriptID(script));
        BuildTxs(spending, coins, creation, p2sh, CScript() << Serialize(script), empty);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, active), 4);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, inactive), 0);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, otherFlags), 0);

        uint256 scriptHash;
        CSHA256().Write(script.data(), script.size()).Finalize(scriptHash.begin());
        const CScript v0 = CScript() << OP_0 << ToByteVector(scriptHash);
        const CScript v1 = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, script));
        for (bool authscript : {false, true}) for (bool wrapped : {false, true}) {
            const CScript program = authscript ? v1 : v0;
            CScriptWitness witness;
            if (authscript) witness.stack.push_back({0});
            witness.stack.push_back(Serialize(script));
            const CScript output = wrapped ? GetScriptForDestination(CScriptID(program)) : program;
            const CScript scriptSig = wrapped ? CScript() << Serialize(program) : CScript();
            BuildTxs(spending, coins, creation, output, scriptSig, witness);
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, active), 1);
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, inactive), 0);
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, otherFlags), 0);
        }
        CScript asset = v1;
        CAssetTransfer("CSFSCOUNT", COIN).ConstructTransaction(asset, AssetMarker::NEURAI_XNA);
        CScriptWitness witness;
        witness.stack = {{0}, Serialize(script)};
        BuildTxs(spending, coins, creation, asset, CScript(), witness);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, active), 1);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, inactive), 0);
        BOOST_CHECK_EQUAL(GetTransactionSigOpCost(CTransaction(spending), coins, otherFlags), 0);

        // The P2SH per-input policy boundary includes the selected opcode when activated.
        for (int count : {15, 16}) {
            CScript redeem;
            for (int i = 0; i < count; ++i) redeem << opcode;
            BuildTxs(spending, coins, creation, GetScriptForDestination(CScriptID(redeem)), CScript() << Serialize(redeem), empty);
            const CTransaction tx(spending);
            BOOST_CHECK(AreInputsStandard(tx, coins));
            BOOST_CHECK_EQUAL(AreInputsStandard(tx, coins, csfs, csa, ed), count == 15);
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(tx, coins, active), count * 4);
            BOOST_CHECK_EQUAL(GetTransactionSigOpCost(tx, coins, inactive), 0);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
