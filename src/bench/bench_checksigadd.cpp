// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-039 §3.7 acceptance bench. Measures the cost of one executed
// OP_CHECKSIGADD against legacy ECDSA and PQ ML-DSA-44 keys, plus the
// empty-sig "skip" path. Results inform whether
// CHECKSIGADD_PQ_SIGOP_COST = 8 is correctly calibrated against
// real ML_DSA_44_Verify() versus secp256k1 ECDSA on the target hardware.
//
// Three regimes:
//   - CheckSigAddLegacyVerify : valid secp256k1 sig, real CheckSig path.
//   - CheckSigAddPQVerify     : valid ML-DSA-44 sig, real CheckSig path.
//                               Should dominate the legacy regime by the
//                               PQ-vs-ECDSA verify ratio (~50x on CI).
//   - CheckSigAddSkipped      : empty sig — bounds the cost of structural
//                               rejection (no verify is invoked).
//
// All three regimes use witness v0 (P2WSH) so SIGVERSION_WITNESS_V0
// applies and FindAndDelete does not run, matching the realistic
// deployment shape for OP_CHECKSIGADD.

#include "bench.h"
#include "hash.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "utilstrencodings.h"

#include <array>
#include <cassert>
#include <vector>

namespace {

constexpr script_verify_flags kFlags =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHECKSIGADD;

CMutableTransaction BuildCreditingTransaction(const CScript& scriptPubKey, CAmount nValue)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = nValue;
    return txCredit;
}

CMutableTransaction BuildSpendingTransaction(const CMutableTransaction& txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;
    return txSpend;
}

CScript P2WSHScriptPubKey(const CScript& witnessScript)
{
    uint256 wsHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(wsHash.begin());
    return CScript() << OP_0 << ToByteVector(wsHash);
}

// Deterministic 32-byte private key for the legacy regime (matches
// verify_script.cpp's key seed pattern).
const std::array<unsigned char, 32> kLegacyKeyBytes = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
}};

const std::vector<unsigned char> kPqSeed = ParseHex(
    "0011223344556677889900112233445566778899001122334455667788990011");

} // anonymous namespace

static void CheckSigAddLegacyVerify(benchmark::State& state)
{
    CKey key;
    key.Set(kLegacyKeyBytes.begin(), kLegacyKeyBytes.end(), /*fCompressed=*/true);
    auto pk = ToByteVector(key.GetPubKey());

    // Build the witnessScript that the bench will verify against, then
    // sign it under SIGVERSION_WITNESS_V0.
    CScript witnessScript = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD;
    CScript scriptPubKey = P2WSHScriptPubKey(witnessScript);
    CMutableTransaction txCredit = BuildCreditingTransaction(scriptPubKey, 1000);
    CMutableTransaction txSpend  = BuildSpendingTransaction(txCredit);

    uint256 hash = SignatureHash(witnessScript, txSpend, 0, SIGHASH_ALL,
                                 txCredit.vout[0].nValue, SIGVERSION_WITNESS_V0);
    std::vector<unsigned char> sig;
    bool signed_ok = key.Sign(hash, sig);
    assert(signed_ok); (void)signed_ok;
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    CScriptWitness witness;
    witness.stack.push_back(sig);
    witness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));
    txSpend.vin[0].scriptWitness = witness;

    while (state.KeepRunning()) {
        ScriptError err;
        // Note: success here means CHECKSIGADD pushed `1` (top-of-stack
        // is non-zero), which is what VerifyScript treats as success
        // when there is no trailing assertion.
        const bool ok = VerifyScript(
            txSpend.vin[0].scriptSig,
            scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            kFlags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue,
                                              scriptPubKey),
            &err);
        assert(ok && err == SCRIPT_ERR_OK);
        (void)ok;
    }
}

static void CheckSigAddPQVerify(benchmark::State& state)
{
    CKey pqKey;
    pqKey.MakeNewKeyPQ(kPqSeed);
    auto pk = ToByteVector(pqKey.GetPubKey());

    CScript witnessScript = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD;
    CScript scriptPubKey = P2WSHScriptPubKey(witnessScript);
    CMutableTransaction txCredit = BuildCreditingTransaction(scriptPubKey, 1000);
    CMutableTransaction txSpend  = BuildSpendingTransaction(txCredit);

    uint256 hash = SignatureHash(witnessScript, txSpend, 0, SIGHASH_ALL,
                                 txCredit.vout[0].nValue, SIGVERSION_WITNESS_V0);
    std::vector<unsigned char> sig;
    bool signed_ok = pqKey.Sign(hash, sig);
    assert(signed_ok); (void)signed_ok;
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    CScriptWitness witness;
    witness.stack.push_back(sig);
    witness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));
    txSpend.vin[0].scriptWitness = witness;

    while (state.KeepRunning()) {
        ScriptError err;
        const bool ok = VerifyScript(
            txSpend.vin[0].scriptSig,
            scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            kFlags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue,
                                              scriptPubKey),
            &err);
        assert(ok && err == SCRIPT_ERR_OK);
        (void)ok;
    }
}

static void CheckSigAddSkipped(benchmark::State& state)
{
    // Empty signature path: handler still executes (charges 9 sigops,
    // runs the PQ-pubkey shape check) but skips CheckSig entirely.
    // Bounds the cost of a skipped key position in a threshold script.
    CKey pqKey;
    pqKey.MakeNewKeyPQ(kPqSeed);
    auto pk = ToByteVector(pqKey.GetPubKey());

    // Trailing OP_NOT so an unincremented count (0) yields top-of-stack
    // true and the verify passes.
    CScript witnessScript = CScript() << CScriptNum(0) << pk << OP_CHECKSIGADD << OP_NOT;
    CScript scriptPubKey = P2WSHScriptPubKey(witnessScript);
    CMutableTransaction txCredit = BuildCreditingTransaction(scriptPubKey, 1000);
    CMutableTransaction txSpend  = BuildSpendingTransaction(txCredit);

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>{}); // empty sig
    witness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));
    txSpend.vin[0].scriptWitness = witness;

    while (state.KeepRunning()) {
        ScriptError err;
        const bool ok = VerifyScript(
            txSpend.vin[0].scriptSig,
            scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            kFlags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue,
                                              scriptPubKey),
            &err);
        assert(ok && err == SCRIPT_ERR_OK);
        (void)ok;
    }
}

BENCHMARK(CheckSigAddLegacyVerify);
BENCHMARK(CheckSigAddPQVerify);
BENCHMARK(CheckSigAddSkipped);
