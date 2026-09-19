// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Strict AuthScript families: witness v2 (post-quantum) and witness v3
// (classical ECDSA). Covers the versioned commitment, address encoding with
// canonical HRP/version pairs, script templates, consensus verification of
// the fixed [authType, sig, pubkey, OP_TRUE] witness, the sighash domain,
// sigops, asset-wrapped outputs and witness standardness / dust.

#include "assets/assettypes.h"
#include "base58.h"
#include "bech32.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "hash.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

static constexpr script_verify_flags STRICT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_AUTHSCRIPT |
    SCRIPT_VERIFY_AUTHSCRIPT_STRICT | SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
static constexpr script_verify_flags NO_STRICT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_AUTHSCRIPT;
static constexpr script_verify_flags NO_STRICT_DISCOURAGE =
    NO_STRICT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;

static const CAmount kAmount = 1 * COIN;
static const uint256 kPrevHash = uint256S(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

struct StrictAuthScriptRegtestSetup : public BasicTestingSetup {
    StrictAuthScriptRegtestSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

CKey MakeEcdsaKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

CKey MakePQKey()
{
    CKey key;
    key.MakeNewKeyPQ();
    return key;
}

WitnessStrictAuthScript StrictDest(const CKey& key)
{
    WitnessStrictAuthScript dest;
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(key.GetPubKey(), dest));
    return dest;
}

CMutableTransaction MakeSpendTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(kPrevHash, 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = kAmount - 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

// Register key + strict spend data in the keystore and sign input 0 of tx,
// which spends an output paying `spk` worth kAmount.
bool SignStrictInput(CBasicKeyStore& keystore, const CKey& key, const WitnessStrictAuthScript& dest,
                     const CScript& spk, CMutableTransaction& tx)
{
    keystore.AddKeyPubKey(key, key.GetPubKey());
    AuthScriptSpendData spendData;
    spendData.auth_type = StrictAuthScriptAuthType(dest.version);
    spendData.witnessScript = GetStrictAuthScriptTemplate();
    spendData.pubkey = key.GetPubKey();
    spendData.key_id = spendData.pubkey.GetID();
    spendData.is_default_template = true;
    keystore.AddAuthScriptSpendData(dest.version, dest.commitment, spendData);

    const CTransaction ctx(tx);
    TransactionSignatureCreator creator(&keystore, &ctx, 0, kAmount, SIGHASH_ALL);
    SignatureData sigdata;
    if (!ProduceSignature(creator, spk, sigdata)) {
        return false;
    }
    UpdateTransaction(tx, 0, sigdata);
    return true;
}

bool VerifyInput(const CMutableTransaction& tx, const CScript& spk, script_verify_flags flags, ScriptError* err)
{
    const CTransaction ctx(tx);
    return VerifyScript(ctx.vin[0].scriptSig, spk, &ctx.vin[0].scriptWitness, flags,
                        TransactionSignatureChecker(&ctx, 0, kAmount), err);
}

std::string EncodeWithHrp(const std::string& hrp, uint8_t version, const uint256& commitment)
{
    std::vector<uint8_t> data = {version};
    std::vector<uint8_t> bytes(commitment.begin(), commitment.end());
    std::vector<uint8_t> conv;
    BOOST_REQUIRE((bech32::ConvertBits<8, 5, true>(bytes, conv)));
    data.insert(data.end(), conv.begin(), conv.end());
    return bech32::Encode(hrp, data, bech32::Encoding::BECH32M);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(strict_authscript_tests, StrictAuthScriptRegtestSetup)

BOOST_AUTO_TEST_CASE(commitment_is_versioned)
{
    const CKey ecdsa = MakeEcdsaKey();
    const CKey pq = MakePQKey();
    const CPubKey ecdsaPub = ecdsa.GetPubKey();
    const CPubKey pqPub = pq.GetPubKey();
    const CScript tmpl = GetStrictAuthScriptTemplate();
    BOOST_CHECK(tmpl == (CScript() << OP_TRUE));

    // Same key + same script under different commitment versions differ.
    const uint256 v1ecdsa = GetAuthScriptCommitment(0x02, &ecdsaPub, tmpl);
    const uint256 v3ecdsa = GetAuthScriptCommitment(0x02, &ecdsaPub, tmpl, 3);
    BOOST_CHECK(!v1ecdsa.IsNull());
    BOOST_CHECK(!v3ecdsa.IsNull());
    BOOST_CHECK(v1ecdsa != v3ecdsa);

    const uint256 v1pq = GetAuthScriptCommitment(0x01, &pqPub, tmpl);
    const uint256 v2pq = GetAuthScriptCommitment(0x01, &pqPub, tmpl, 2);
    BOOST_CHECK(!v1pq.IsNull());
    BOOST_CHECK(!v2pq.IsNull());
    BOOST_CHECK(v1pq != v2pq);
    BOOST_CHECK(v2pq != v3ecdsa);

    // Default parameter is the historical v1 domain.
    BOOST_CHECK(GetAuthScriptCommitment(0x02, &ecdsaPub, tmpl, 1) == v1ecdsa);

    // Unknown commitment versions are not a defined domain.
    BOOST_CHECK(GetAuthScriptCommitment(0x02, &ecdsaPub, tmpl, 0).IsNull());
    BOOST_CHECK(GetAuthScriptCommitment(0x02, &ecdsaPub, tmpl, 4).IsNull());

    // Helpers bind versions and auth types both ways.
    BOOST_CHECK_EQUAL(StrictAuthScriptWitnessVersion(0x01), 2);
    BOOST_CHECK_EQUAL(StrictAuthScriptWitnessVersion(0x02), 3);
    BOOST_CHECK_EQUAL(StrictAuthScriptWitnessVersion(0x00), 0);
    BOOST_CHECK_EQUAL((int)StrictAuthScriptAuthType(2), 0x01);
    BOOST_CHECK_EQUAL((int)StrictAuthScriptAuthType(3), 0x02);
    BOOST_CHECK_EQUAL((int)StrictAuthScriptAuthType(1), 0x00);
}

BOOST_AUTO_TEST_CASE(strict_destination_for_pubkey)
{
    const CKey ecdsa = MakeEcdsaKey();
    const CKey pq = MakePQKey();

    WitnessStrictAuthScript d3;
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(ecdsa.GetPubKey(), d3));
    BOOST_CHECK_EQUAL((int)d3.version, 3);
    BOOST_CHECK(d3.IsECDSA());
    const CPubKey ecdsaPub = ecdsa.GetPubKey();
    BOOST_CHECK(d3.commitment == GetAuthScriptCommitment(0x02, &ecdsaPub, GetStrictAuthScriptTemplate(), 3));

    WitnessStrictAuthScript d2;
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(pq.GetPubKey(), d2));
    BOOST_CHECK_EQUAL((int)d2.version, 2);
    BOOST_CHECK(d2.IsPQ());

    // Uncompressed secp256k1 keys have no strict destination.
    CKey uncompressed;
    uncompressed.MakeNewKey(false);
    WitnessStrictAuthScript none;
    BOOST_CHECK(!GetStrictAuthScriptDestinationForPubKey(uncompressed.GetPubKey(), none));
}

BOOST_AUTO_TEST_CASE(address_encoding_canonical_pairs)
{
    const CKey ecdsa = MakeEcdsaKey();
    const CKey pq = MakePQKey();
    const WitnessStrictAuthScript d3 = StrictDest(ecdsa);
    const WitnessStrictAuthScript d2 = StrictDest(pq);
    const CPubKey pqPub = pq.GetPubKey();
    const WitnessV1AuthScript d1(GetAuthScriptCommitment(0x01, &pqPub, GetStrictAuthScriptTemplate()));

    const std::string a2 = EncodeDestination(d2);
    const std::string a3 = EncodeDestination(d3);
    const std::string a1 = EncodeDestination(d1);
    BOOST_CHECK_EQUAL(a2.substr(0, 5), "tpq1z");
    BOOST_CHECK_EQUAL(a3.substr(0, 5), "tnq1r");
    BOOST_CHECK_EQUAL(a1.substr(0, 5), "tnq1p");

    BOOST_CHECK(DecodeDestination(a2) == CTxDestination(d2));
    BOOST_CHECK(DecodeDestination(a3) == CTxDestination(d3));
    BOOST_CHECK(DecodeDestination(a1) == CTxDestination(d1));
    BOOST_CHECK(IsValidDestinationString(a2));
    BOOST_CHECK(IsValidDestinationString(a3));

    // Cross HRP/version combinations are rejected even with a valid checksum.
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeWithHrp("tnq", 2, d2.commitment))));
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeWithHrp("tpq", 3, d3.commitment))));
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeWithHrp("tpq", 1, d1))));
    // Other networks' HRPs are rejected on regtest.
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeWithHrp("pq", 2, d2.commitment))));
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeWithHrp("nq", 3, d3.commitment))));
    // Unknown witness versions are rejected.
    BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeWithHrp("tnq", 4, d3.commitment))));
}

BOOST_AUTO_TEST_CASE(script_templates_and_solver)
{
    const CKey ecdsa = MakeEcdsaKey();
    const CKey pq = MakePQKey();
    const WitnessStrictAuthScript d3 = StrictDest(ecdsa);
    const WitnessStrictAuthScript d2 = StrictDest(pq);

    const CScript spk3 = GetScriptForDestination(d3);
    const CScript spk2 = GetScriptForDestination(d2);
    BOOST_CHECK(spk3 == (CScript() << OP_3 << ToByteVector(d3.commitment)));
    BOOST_CHECK(spk2 == (CScript() << OP_2 << ToByteVector(d2.commitment)));

    txnouttype type;
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_REQUIRE(Solver(spk3, type, solutions));
    BOOST_CHECK_EQUAL(type, TX_WITNESS_V3_STRICT_ECDSA);
    BOOST_CHECK_EQUAL(GetTxnOutputType(type), "witness_v3_strict_ecdsa");
    BOOST_REQUIRE(Solver(spk2, type, solutions));
    BOOST_CHECK_EQUAL(type, TX_WITNESS_V2_STRICT_PQ);
    BOOST_CHECK_EQUAL(GetTxnOutputType(type), "witness_v2_strict_pq");

    CTxDestination back;
    BOOST_REQUIRE(ExtractDestination(spk3, back));
    BOOST_CHECK(back == CTxDestination(d3));
    BOOST_REQUIRE(ExtractDestination(spk2, back));
    BOOST_CHECK(back == CTxDestination(d2));

    // The same 32 bytes under another version are a different destination.
    const CScript crossed = CScript() << OP_2 << ToByteVector(d3.commitment);
    BOOST_REQUIRE(ExtractDestination(crossed, back));
    BOOST_CHECK(!(back == CTxDestination(d3)));
    BOOST_CHECK(EncodeDestination(back) != EncodeDestination(d3));

    // Index types keep versions apart as well.
    CDestinationIndexData idx2, idx3, idxCrossed;
    BOOST_REQUIRE(GetDestinationIndexData(d2, idx2));
    BOOST_REQUIRE(GetDestinationIndexData(d3, idx3));
    BOOST_REQUIRE(GetScriptDestinationIndexData(crossed, idxCrossed));
    BOOST_CHECK_EQUAL(idx2.type, DEST_INDEX_WITNESS_V2_STRICT_PQ);
    BOOST_CHECK_EQUAL(idx3.type, DEST_INDEX_WITNESS_V3_STRICT_ECDSA);
    BOOST_CHECK_EQUAL(idxCrossed.type, DEST_INDEX_WITNESS_V2_STRICT_PQ);
    BOOST_CHECK(idxCrossed.payload == idx3.payload);
    BOOST_CHECK(idxCrossed != idx3);
}

BOOST_AUTO_TEST_CASE(spend_v3_ecdsa)
{
    const CKey key = MakeEcdsaKey();
    const WitnessStrictAuthScript dest = StrictDest(key);
    const CScript spk = GetScriptForDestination(dest);

    CBasicKeyStore keystore;
    CMutableTransaction tx = MakeSpendTx();
    BOOST_REQUIRE(SignStrictInput(keystore, key, dest, spk, tx));

    const auto& stack = tx.vin[0].scriptWitness.stack;
    BOOST_REQUIRE_EQUAL(stack.size(), 4U);
    BOOST_CHECK(stack[0] == std::vector<unsigned char>{0x02});
    BOOST_CHECK(stack[2] == ToByteVector(key.GetPubKey()));
    BOOST_CHECK(stack[3] == std::vector<unsigned char>{OP_TRUE});

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyInput(tx, spk, STRICT_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Before activation the version is upgradable: accepted without the
    // flag, discouraged by policy.
    BOOST_CHECK(VerifyInput(tx, spk, NO_STRICT_FLAGS, &err));
    BOOST_CHECK(!VerifyInput(tx, spk, NO_STRICT_DISCOURAGE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);

    // authType must match the version.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[0] = {0x01};
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    // Exactly four items.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack.insert(bad.vin[0].scriptWitness.stack.begin() + 3, std::vector<unsigned char>{0x01});
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    // witnessScript must be exactly OP_TRUE.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[3] = {OP_2};
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    // Wrong key.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[2] = ToByteVector(MakeEcdsaKey().GetPubKey());
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    // Empty signature.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[1].clear();
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
    }
    // Corrupted signature.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[1][10] ^= 0x01;
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
    }
    // Same commitment bytes under witness v2: a different output, unspendable
    // with this witness (version/authType mismatch, versioned commitment).
    {
        const CScript crossed = CScript() << OP_2 << ToByteVector(dest.commitment);
        BOOST_CHECK(!VerifyInput(tx, crossed, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    // The generic v1 commitment for the same key is not spendable with the
    // strict witness (and vice versa: different commitment domain).
    {
        const CPubKey pub = key.GetPubKey();
        const CScript v1spk = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0x02, &pub, GetStrictAuthScriptTemplate()));
        BOOST_CHECK(!VerifyInput(tx, v1spk, STRICT_FLAGS, &err));
    }
}

BOOST_AUTO_TEST_CASE(spend_v2_pq)
{
    const CKey key = MakePQKey();
    const WitnessStrictAuthScript dest = StrictDest(key);
    const CScript spk = GetScriptForDestination(dest);

    CBasicKeyStore keystore;
    CMutableTransaction tx = MakeSpendTx();
    BOOST_REQUIRE(SignStrictInput(keystore, key, dest, spk, tx));

    const auto& stack = tx.vin[0].scriptWitness.stack;
    BOOST_REQUIRE_EQUAL(stack.size(), 4U);
    BOOST_CHECK(stack[0] == std::vector<unsigned char>{0x01});
    BOOST_CHECK_EQUAL(stack[1].size(), ML_DSA_44_SIG_SIZE + 1);
    BOOST_CHECK_EQUAL(stack[2].size(), 1 + ML_DSA_44_PUBKEY_SIZE);

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyInput(tx, spk, STRICT_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // A PQ witness can never satisfy witness v3 (ECDSA family).
    {
        const CScript crossed = CScript() << OP_3 << ToByteVector(dest.commitment);
        BOOST_CHECK(!VerifyInput(tx, crossed, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    // Corrupted PQ signature.
    {
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[1][100] ^= 0x01;
        BOOST_CHECK(!VerifyInput(bad, spk, STRICT_FLAGS, &err));
    }
    // An ECDSA key cannot be presented under witness v2, even if the output
    // commits to it with authType 0x01: the family requires a PQ key.
    {
        const CKey ecdsa = MakeEcdsaKey();
        const CPubKey ecdsaPub = ecdsa.GetPubKey();
        const CScript tmpl = GetStrictAuthScriptTemplate();
        const CScript spkEcdsaAsV2 = CScript() << OP_2 << ToByteVector(GetAuthScriptCommitment(0x01, &ecdsaPub, tmpl, 2));
        CMutableTransaction bad = MakeSpendTx();
        const CTransaction cbad(bad);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(ecdsa.Sign(SignatureHash(tmpl, cbad, 0, SIGHASH_ALL, kAmount, SIGVERSION_AUTHSCRIPT_STRICT, nullptr, 0x01), sig));
        sig.push_back(SIGHASH_ALL);
        bad.vin[0].scriptWitness.stack = {{0x01}, sig, ToByteVector(ecdsaPub), {OP_TRUE}};
        BOOST_CHECK(!VerifyInput(bad, spkEcdsaAsV2, STRICT_FLAGS, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
}

BOOST_AUTO_TEST_CASE(sighash_domains_differ)
{
    const CKey key = MakeEcdsaKey();
    CMutableTransaction tx = MakeSpendTx();
    const CTransaction ctx(tx);
    const CScript tmpl = GetStrictAuthScriptTemplate();

    const uint256 h1 = SignatureHash(tmpl, ctx, 0, SIGHASH_ALL, kAmount, SIGVERSION_AUTHSCRIPT, nullptr, 0x02);
    const uint256 h3 = SignatureHash(tmpl, ctx, 0, SIGHASH_ALL, kAmount, SIGVERSION_AUTHSCRIPT_STRICT, nullptr, 0x02);
    const uint256 h2 = SignatureHash(tmpl, ctx, 0, SIGHASH_ALL, kAmount, SIGVERSION_AUTHSCRIPT_STRICT, nullptr, 0x01);
    BOOST_CHECK(h1 != h3);
    BOOST_CHECK(h2 != h3);
    BOOST_CHECK(h1 != h2);

    // A signature produced for the v1 domain does not verify in the strict one.
    const WitnessStrictAuthScript dest = StrictDest(key);
    const CScript spk = GetScriptForDestination(dest);
    std::vector<unsigned char> v1sig;
    BOOST_REQUIRE(key.Sign(h1, v1sig));
    v1sig.push_back(SIGHASH_ALL);
    tx.vin[0].scriptWitness.stack = {{0x02}, v1sig, ToByteVector(key.GetPubKey()), {OP_TRUE}};
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!VerifyInput(tx, spk, STRICT_FLAGS, &err));

    std::vector<unsigned char> v3sig;
    BOOST_REQUIRE(key.Sign(h3, v3sig));
    v3sig.push_back(SIGHASH_ALL);
    tx.vin[0].scriptWitness.stack[1] = v3sig;
    BOOST_CHECK(VerifyInput(tx, spk, STRICT_FLAGS, &err));
}

BOOST_AUTO_TEST_CASE(sigops_are_charged)
{
    const CKey key = MakeEcdsaKey();
    const WitnessStrictAuthScript dest = StrictDest(key);
    const CScript spk = GetScriptForDestination(dest);
    CBasicKeyStore keystore;
    CMutableTransaction tx = MakeSpendTx();
    BOOST_REQUIRE(SignStrictInput(keystore, key, dest, spk, tx));

    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), spk, &tx.vin[0].scriptWitness, STRICT_FLAGS), 1U);
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), spk, &tx.vin[0].scriptWitness, NO_STRICT_FLAGS), 0U);

    const CKey pq = MakePQKey();
    const WitnessStrictAuthScript dest2 = StrictDest(pq);
    const CScript spk2 = GetScriptForDestination(dest2);
    CScriptWitness witness2;
    witness2.stack = {{0x01}, std::vector<unsigned char>(10, 0), ToByteVector(pq.GetPubKey()), {OP_TRUE}};
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), spk2, &witness2, STRICT_FLAGS), 1U);
}

BOOST_AUTO_TEST_CASE(asset_wrapped_strict_outputs)
{
    const CKey key = MakeEcdsaKey();
    const WitnessStrictAuthScript dest = StrictDest(key);

    CScript spk = GetScriptForDestination(dest);
    CAssetTransfer("STRICTTEST", 100 * COIN).ConstructTransaction(spk, AssetMarker::NEURAI_XNA);

    BOOST_CHECK(spk.IsAssetScript());
    BOOST_CHECK(!spk.IsAssetAuthScript()); // NIP-025 predicate stays v1-only

    txnouttype type;
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_REQUIRE(Solver(spk, type, solutions));
    BOOST_CHECK_EQUAL(type, TX_TRANSFER_ASSET);

    CTxDestination back;
    BOOST_REQUIRE(ExtractAssetDestination(spk, back));
    BOOST_CHECK(back == CTxDestination(dest));
    BOOST_REQUIRE(ExtractDestination(spk, back));
    BOOST_CHECK(back == CTxDestination(dest));

    int witnessversion = 0;
    std::vector<unsigned char> program, assetData;
    BOOST_REQUIRE(GetAssetScriptWitnessProgram(spk, witnessversion, program, &assetData));
    BOOST_CHECK_EQUAL(witnessversion, 3);
    BOOST_CHECK(uint256(program) == dest.commitment);
    BOOST_CHECK(!assetData.empty());

    // Spending an asset-wrapped strict output uses the same 4-item witness.
    CBasicKeyStore keystore;
    CMutableTransaction tx = MakeSpendTx();
    BOOST_REQUIRE(SignStrictInput(keystore, key, dest, spk, tx));
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyInput(tx, spk, STRICT_FLAGS, &err));
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), spk, &tx.vin[0].scriptWitness, STRICT_FLAGS), 1U);

    // v1 asset wrapper is still recognised by the NIP-025 predicate.
    CScript v1spk = CScript() << OP_1 << ToByteVector(dest.commitment);
    CAssetTransfer("STRICTTEST", 100 * COIN).ConstructTransaction(v1spk, AssetMarker::NEURAI_XNA);
    BOOST_CHECK(v1spk.IsAssetAuthScript());

    // Null-data asset script with a strict prefix (callers append the asset data).
    CScript nullData = GetScriptForNullAssetDataDestination(dest);
    BOOST_CHECK(nullData[1] == OP_3);
    nullData << std::vector<unsigned char>{0x01, 0x02, 0x03};
    BOOST_CHECK(nullData.IsNullAssetTxDataScript());
}

BOOST_AUTO_TEST_CASE(witness_standard_and_dust)
{
    const CKey pq = MakePQKey();
    const CKey ecdsa = MakeEcdsaKey();
    const WitnessStrictAuthScript d2 = StrictDest(pq);
    const WitnessStrictAuthScript d3 = StrictDest(ecdsa);
    const CScript spk2 = GetScriptForDestination(d2);
    const CScript spk3 = GetScriptForDestination(d3);

    CCoinsView base;
    CCoinsViewCache coins(&base);
    coins.AddCoin(COutPoint(kPrevHash, 0), Coin(CTxOut(kAmount, spk2), 1, false), false);

    CMutableTransaction tx = MakeSpendTx();
    tx.vin[0].scriptWitness.stack = {{0x01}, std::vector<unsigned char>(ML_DSA_44_SIG_SIZE + 1, 0),
                                     ToByteVector(pq.GetPubKey()), {OP_TRUE}};
    BOOST_CHECK(IsWitnessStandard(CTransaction(tx), coins, false));

    CMutableTransaction five = tx;
    five.vin[0].scriptWitness.stack.push_back({0x00});
    BOOST_CHECK(!IsWitnessStandard(CTransaction(five), coins, false));

    CMutableTransaction bigSig = tx;
    bigSig.vin[0].scriptWitness.stack[1].push_back(0x00);
    BOOST_CHECK(!IsWitnessStandard(CTransaction(bigSig), coins, false));

    // Dust: the PQ family needs a much larger witness than the ECDSA family.
    const CFeeRate feeRate(3000);
    const CAmount dust2 = GetDustThreshold(CTxOut(0, spk2), feeRate);
    const CAmount dust3 = GetDustThreshold(CTxOut(0, spk3), feeRate);
    BOOST_CHECK(dust3 > 0);
    BOOST_CHECK(dust2 > dust3);
}

BOOST_AUTO_TEST_CASE(message_signing)
{
    const CKey ecdsa = MakeEcdsaKey();
    const CKey pq = MakePQKey();
    const WitnessStrictAuthScript d3 = StrictDest(ecdsa);
    const WitnessStrictAuthScript d2 = StrictDest(pq);
    const uint256 hash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");

    std::vector<unsigned char> sig3, sig2;
    BOOST_REQUIRE(SignMessageHash(ecdsa, CTxDestination(d3), hash, sig3));
    BOOST_REQUIRE(SignMessageHash(pq, CTxDestination(d2), hash, sig2));
    BOOST_CHECK(VerifyMessageHash(CTxDestination(d3), hash, sig3));
    BOOST_CHECK(VerifyMessageHash(CTxDestination(d2), hash, sig2));

    // Signatures are bound to their destination family.
    BOOST_CHECK(!VerifyMessageHash(CTxDestination(d2), hash, sig3));
    BOOST_CHECK(!VerifyMessageHash(CTxDestination(d3), hash, sig2));
    BOOST_CHECK(!VerifyMessageHash(CTxDestination(WitnessStrictAuthScript(2, d3.commitment)), hash, sig3));
    // A key cannot sign for someone else's strict destination.
    std::vector<unsigned char> bad;
    BOOST_CHECK(!SignMessageHash(ecdsa, CTxDestination(d2), hash, bad));
    BOOST_CHECK(!SignMessageHash(ecdsa, CTxDestination(StrictDest(MakeEcdsaKey())), hash, bad));
}

// Review regressions: test inactive chains through the transaction validator,
// not just the placement helper or address decoder.
BOOST_AUTO_TEST_CASE(review_strict_assets_rejected_before_activation)
{
    struct RestoreNetwork {
        ~RestoreNetwork() { SelectParams(CBaseChainParams::REGTEST); }
    } restore;
    for (const auto& network : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET}) {
        SelectParams(network);
        BOOST_REQUIRE(!GetParams().GetConsensus().IsStrictAuthScriptActive(0));
        BOOST_REQUIRE(!IsStrictAuthScriptActiveInContext());
        for (int version : {2, 3}) {
            CScript spk = CScript() << CScript::EncodeOP_N(version)
                                   << std::vector<unsigned char>(32, 0x42);
            CAssetTransfer("STRICTTEST", COIN).ConstructTransaction(spk, AssetMarker::NEURAI_XNA);
            CMutableTransaction tx = MakeSpendTx();
            tx.vout[0] = CTxOut(0, spk);
            CValidationState state;
            BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(tx), state),
                "Inactive " << network << " accepted a witness v" << version << " asset output");
        }
    }
}

// Use the SAME key under its old and new destinations. Using unrelated PQ
// and ECDSA keys cannot establish message-domain separation.
BOOST_AUTO_TEST_CASE(review_message_signature_bound_to_destination_version)
{
    const uint256 hash = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    for (bool usePQ : {false, true}) {
        const CKey key = usePQ ? MakePQKey() : MakeEcdsaKey();
        const CPubKey pubkey = key.GetPubKey();
        const CTxDestination oldDest = usePQ
            ? CTxDestination(WitnessV1AuthScript(GetAuthScriptCommitment(0x01, &pubkey, GetStrictAuthScriptTemplate())))
            : CTxDestination(pubkey.GetID());
        const CTxDestination strictDest = StrictDest(key);
        std::vector<unsigned char> oldSignature, strictSignature;
        BOOST_REQUIRE(SignMessageHash(key, oldDest, hash, oldSignature));
        BOOST_REQUIRE(SignMessageHash(key, strictDest, hash, strictSignature));
        BOOST_CHECK(VerifyMessageHash(oldDest, hash, oldSignature));
        BOOST_CHECK(VerifyMessageHash(strictDest, hash, strictSignature));
        BOOST_CHECK_MESSAGE(!VerifyMessageHash(strictDest, hash, oldSignature),
                            "Old message signature accepted for strict destination");
        BOOST_CHECK_MESSAGE(!VerifyMessageHash(oldDest, hash, strictSignature),
                            "Strict message signature accepted for old destination");
    }
}

// Fixed vectors for the strict message-signing domain (external wallets must
// reproduce these bytes). Message "hola", commitment = 32 bytes 0x11.
BOOST_AUTO_TEST_CASE(message_hash_vectors)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << std::string("hola");
    const uint256 messageHash = ss.GetHash();
    BOOST_CHECK_EQUAL(HexStr(messageHash.begin(), messageHash.end()),
                      "cba3aa2c37996fdda56ab6304ec49ea428f66ac82a09afa92caef64d01c1a22a");

    const uint256 commitment(std::vector<unsigned char>(32, 0x11));
    const uint256 v2 = StrictAuthScriptMessageHash(WitnessStrictAuthScript(2, commitment), messageHash);
    const uint256 v3 = StrictAuthScriptMessageHash(WitnessStrictAuthScript(3, commitment), messageHash);
    BOOST_CHECK_EQUAL(HexStr(v2.begin(), v2.end()), "6ceeea6252013d1abadf49adb164764ecf46ad2e11e92a7e31c374adfd851bd3");
    BOOST_CHECK_EQUAL(HexStr(v3.begin(), v3.end()), "1833af5b07c57a8bac330e4fa0fc8bce8d29a440667ccea35dce1f5c6e076d6b");

    // Asymmetric commitment 00 01 .. 1f: catches an accidental reversal of the
    // commitment byte order, which a repeated-byte commitment cannot detect.
    std::vector<unsigned char> ascending(32);
    for (size_t i = 0; i < ascending.size(); i++) ascending[i] = (unsigned char)i;
    const uint256 commitmentAsc(ascending);
    const uint256 a2 = StrictAuthScriptMessageHash(WitnessStrictAuthScript(2, commitmentAsc), messageHash);
    const uint256 a3 = StrictAuthScriptMessageHash(WitnessStrictAuthScript(3, commitmentAsc), messageHash);
    BOOST_CHECK_EQUAL(HexStr(a2.begin(), a2.end()), "8979bb37993d0f86de41811dea81b40c55cccba5ab9a7e427817f541d7ad6158");
    BOOST_CHECK_EQUAL(HexStr(a3.begin(), a3.end()), "bedd906b07d08da2b89db5c8bf74e83d1ed8f525cbbff93cbbd6ebc993376152");
}

// Dust thresholds: fixed input size, fee rate and threshold per family, with
// values just below and exactly at the limit. Generic v1 is estimated as the
// wallet default template (PQ key + OP_TRUE), by policy choice.
BOOST_AUTO_TEST_CASE(dust_thresholds_are_pinned)
{
    const std::vector<unsigned char> program(32, 0x42);
    const CFeeRate feeRate(3000); // 3000 sat/kB
    // txout = 8 (value) + 1 (script len) + 34 (script) = 43 bytes
    // PQ input    = 41 + (1 + 2 + 2424 + 1316 + 2) / 4 = 41 + 936 = 977 vbytes -> 1020 total
    // ECDSA input = 41 + (1 + 2 + 74 + 34 + 2) / 4     = 41 + 28  = 69 vbytes  -> 112 total
    const CAmount pqDust = 3060;
    const CAmount ecdsaDust = 336;

    const CScript v1 = CScript() << OP_1 << program;
    const CScript v2 = CScript() << OP_2 << program;
    const CScript v3 = CScript() << OP_3 << program;
    BOOST_CHECK_EQUAL(GetDustThreshold(CTxOut(0, v1), feeRate), pqDust);
    BOOST_CHECK_EQUAL(GetDustThreshold(CTxOut(0, v2), feeRate), pqDust);
    BOOST_CHECK_EQUAL(GetDustThreshold(CTxOut(0, v3), feeRate), ecdsaDust);

    BOOST_CHECK(IsDust(CTxOut(pqDust - 1, v1), feeRate));
    BOOST_CHECK(!IsDust(CTxOut(pqDust, v1), feeRate));
    BOOST_CHECK(IsDust(CTxOut(pqDust - 1, v2), feeRate));
    BOOST_CHECK(!IsDust(CTxOut(pqDust, v2), feeRate));
    BOOST_CHECK(IsDust(CTxOut(ecdsaDust - 1, v3), feeRate));
    BOOST_CHECK(!IsDust(CTxOut(ecdsaDust, v3), feeRate));
}

// Activation is a per-block context, not a process-wide switch.
BOOST_AUTO_TEST_CASE(activation_context_is_scoped)
{
    const Consensus::Params& consensus = GetParams().GetConsensus();
    BOOST_CHECK(consensus.IsStrictAuthScriptActive(0)); // regtest default: from genesis
    BOOST_CHECK(IsStrictAuthScriptActiveInContext());

    CScript spk = CScript() << OP_2 << std::vector<unsigned char>(32, 0x42);
    CAssetTransfer("STRICTTEST", COIN).ConstructTransaction(spk, AssetMarker::NEURAI_XNA);
    CScript v1spk = CScript() << OP_1 << std::vector<unsigned char>(32, 0x42);
    CAssetTransfer("STRICTTEST", COIN).ConstructTransaction(v1spk, AssetMarker::NEURAI_XNA);
    CScript nullData = CScript() << OP_XNA_ASSET << OP_3 << std::vector<unsigned char>(32, 0x42) << std::vector<unsigned char>{1, 2, 3};

    int nType = 0, nStart = 0; bool fOwner = false; AssetMarker marker;
    // Explicit overloads ignore any ambient context.
    BOOST_CHECK(spk.IsAssetScript(nType, fOwner, nStart, marker, true));
    BOOST_CHECK(!spk.IsAssetScript(nType, fOwner, nStart, marker, false));
    BOOST_CHECK(v1spk.IsAssetScript(nType, fOwner, nStart, marker, false)); // v1 never depends on it
    BOOST_CHECK(nullData.IsNullAssetTxDataScript(true));
    BOOST_CHECK(!nullData.IsNullAssetTxDataScript(false));

    BOOST_CHECK(spk.IsAssetScript());
    {
        CStrictAuthScriptContext below(false); // e.g. a historical block under the activation height
        BOOST_CHECK(!IsStrictAuthScriptActiveInContext());
        BOOST_CHECK(!spk.IsAssetScript());
        BOOST_CHECK(v1spk.IsAssetScript());
        BOOST_CHECK(!nullData.IsNullAssetTxDataScript());
        txnouttype type; std::vector<std::vector<unsigned char>> solutions;
        BOOST_CHECK(!Solver(spk, type, solutions) || type != TX_TRANSFER_ASSET);
        CMutableTransaction tx = MakeSpendTx();
        tx.vout[0] = CTxOut(0, spk);
        CValidationState state;
        BOOST_CHECK(!CheckTransaction(CTransaction(tx), state));
        {
            CStrictAuthScriptContext above(true); // scopes nest and restore
            BOOST_CHECK(spk.IsAssetScript());
        }
        BOOST_CHECK(!spk.IsAssetScript());
        // Addresses of the strict families are not decodable below activation.
        BOOST_CHECK(!IsValidDestination(DecodeDestination(EncodeDestination(StrictDest(MakeEcdsaKey())))));
    }
    BOOST_CHECK(spk.IsAssetScript());
    BOOST_CHECK(IsValidDestination(DecodeDestination(EncodeDestination(StrictDest(MakeEcdsaKey())))));

    // The interpreter takes activation from its flags, never from the context.
    int witnessversion = 0; std::vector<unsigned char> program;
    {
        CStrictAuthScriptContext below(false);
        BOOST_CHECK(GetAssetScriptWitnessProgram(spk, witnessversion, program, nullptr, true));
        BOOST_CHECK(!GetAssetScriptWitnessProgram(spk, witnessversion, program, nullptr, false));
    }

    // The script flag follows the height passed by the caller.
    BOOST_CHECK((ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, consensus, true, 0) & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) != 0);
    BOOST_CHECK((ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, consensus, false, 0) & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) == 0);

    // Height semantics of the consensus parameter.
    Consensus::Params custom = consensus;
    custom.nStrictAuthScriptHeight = 150;
    BOOST_CHECK(!custom.IsStrictAuthScriptActive(149));
    BOOST_CHECK(custom.IsStrictAuthScriptActive(150));
}

// A v1 covenant can inspect an output paid to a strict asset destination.
// Identical script flags must give the same result when the caller's ambient
// context differs (e.g. script workers validating a block beyond the tip).
BOOST_AUTO_TEST_CASE(review_asset_introspection_uses_script_flags)
{
    CMutableTransaction tx = MakeSpendTx();
    CScript asset = CScript() << OP_3 << std::vector<unsigned char>(32, 0x42);
    CAssetTransfer("STRICTTEST", COIN).ConstructTransaction(asset, AssetMarker::NEURAI_XNA);
    tx.vout[0] = CTxOut(0, asset);

    const std::string name = "STRICTTEST";
    CScript covenant;
    covenant << OP_0 << std::vector<unsigned char>{0x01} << OP_OUTPUTASSETFIELD
             << std::vector<unsigned char>(name.begin(), name.end()) << OP_EQUAL;
    const CScript spent = CScript() << OP_1
        << ToByteVector(GetAuthScriptCommitment(0x00, nullptr, covenant));
    tx.vin[0].scriptWitness.stack = {{0x00},
        std::vector<unsigned char>(covenant.begin(), covenant.end())};
    const script_verify_flags flags = STRICT_FLAGS | SCRIPT_VERIFY_OUTPUTASSETFIELD;
    for (bool ambient : {true, false}) {
        CStrictAuthScriptContext context(ambient);
        ScriptError error = SCRIPT_ERR_OK;
        BOOST_CHECK_MESSAGE(VerifyInput(tx, spent, flags, &error),
            "Active strict-asset introspection failed with ambient=" << ambient
            << "; error=" << ScriptErrorString(error));
    }
}

BOOST_AUTO_TEST_CASE(p2sh_strict_real_signatures_and_template)
{
    for (bool pq : {false, true}) {
        const CKey key = pq ? MakePQKey() : MakeEcdsaKey();
        const auto dest = StrictDest(key);
        const CScript redeem = GetScriptForDestination(dest);
        const CScript p2sh = GetScriptForDestination(CScriptID(redeem));
        CBasicKeyStore keystore;
        keystore.AddCScript(redeem);
        auto tx = MakeSpendTx();
        BOOST_REQUIRE(SignStrictInput(keystore, key, dest, p2sh, tx));
        const CScript canonical = CScript() << ToByteVector(redeem);
        BOOST_CHECK(tx.vin[0].scriptSig == canonical);
        ScriptError error;
        BOOST_CHECK(VerifyInput(tx, p2sh, STRICT_FLAGS, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        auto malformed = tx;
        malformed.vin[0].scriptSig = CScript() << OP_0 << ToByteVector(redeem);
        BOOST_CHECK(!VerifyInput(malformed, p2sh, STRICT_FLAGS, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
        malformed = tx;
        malformed.vin[0].scriptWitness.stack.back() = {OP_TRUE, OP_NOP};
        BOOST_CHECK(!VerifyInput(malformed, p2sh, STRICT_FLAGS, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        malformed = tx;
        malformed.vin[0].scriptWitness.stack[1].clear();
        BOOST_CHECK(!VerifyInput(malformed, p2sh, STRICT_FLAGS, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        malformed = tx;
        malformed.vout[0].nValue -= 1;
        BOOST_CHECK(!VerifyInput(malformed, p2sh, STRICT_FLAGS, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        BOOST_CHECK(VerifyInput(tx, p2sh, NO_STRICT_FLAGS, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        BOOST_CHECK(!VerifyInput(tx, p2sh, NO_STRICT_DISCOURAGE, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    }
}

BOOST_AUTO_TEST_SUITE_END()
