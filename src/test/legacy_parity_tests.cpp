// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Below the unified fork, 2.0 must read every scriptPubKey exactly as 1.0.7
// does, or a block valid for one of them is invalid for the other while both
// run on mainnet. The functions in namespace legacy107 are copied verbatim
// from the 1.0.7 tag (src/script/script.cpp, src/script/standard.cpp and the
// OP_XNA_ASSET rule of CheckTransaction in src/consensus/tx_verify.cpp); only
// member calls are turned into free functions and the calls between them are
// qualified. Each generated script is read by both with the strict AuthScript
// context inactive, as on mainnet below the fork.

#include "assets/assets.h"
#include "base58.h"
#include "consensus/tx_verify.h"
#include "policy/policy.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <map>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace legacy107 {

typedef std::vector<unsigned char> valtype;

bool IsAssetScript(const CScript& script, int& nType, bool& fIsOwner, int& nStartingIndex)
{
    if (script.size() > 31) {
        if (script[25] == OP_XNA_ASSET) { // OP_XNA_ASSET is always in the 25 index of the script if it exists
            int index = -1;
            if (script[27] == XNA_R) { // Check to see if XNA starts at 27 ( this->size() < 105)
                if (script[28] == XNA_V)
                    if (script[29] == XNA_N)
                        index = 30;
            } else {
                if (script[28] == XNA_R) // Check to see if XNA starts at 28 ( this->size() >= 105)
                    if (script[29] == XNA_V)
                        if (script[30] == XNA_N)
                            index = 31;
            }

            if (index > 0) {
                nStartingIndex = index + 1; // Set the index where the asset data begins. Use to serialize the asset data into asset objects
                if (script[index] == XNA_T) { // Transfer first anticipating more transfers than other assets operations
                    nType = TX_TRANSFER_ASSET;
                    return true;
                } else if (script[index] == XNA_Q && script.size() > 39) {
                    nType = TX_NEW_ASSET;
                    fIsOwner = false;
                    return true;
                } else if (script[index] == XNA_O) {
                    nType = TX_NEW_ASSET;
                    fIsOwner = true;
                    return true;
                } else if (script[index] == XNA_R) {
                    nType = TX_REISSUE_ASSET;
                    return true;
                }
            }
        }
    }
    return false;
}

bool IsNullAssetTxDataScript(const CScript& script)
{
    return (script.size() > 23 &&
            script[0] == OP_XNA_ASSET &&
            script[1] == 0x14);
}

bool IsNullGlobalRestrictionAssetTxDataScript(const CScript& script)
{
    // 1 OP_XNA_ASSET followed by two OP_RESERVED + atleast 4 characters for the restricted name $ABC
    return (script.size() > 6 &&
            script[0] == OP_XNA_ASSET &&
            script[1] == OP_RESERVED &&
            script[2] == OP_RESERVED);
}

bool IsNullAssetVerifierTxDataScript(const CScript& script)
{
    // 1 OP_XNA_ASSET followed by one OP_RESERVED
    return (script.size() > 3 &&
            script[0] == OP_XNA_ASSET &&
            script[1] == OP_RESERVED &&
            script[2] != OP_RESERVED);
}

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    // Templates
    static std::multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(std::make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Neurai address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(std::make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));
    }

    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }
    /** XNA START */
    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    if (IsAssetScript(scriptPubKey, nType, fIsOwner, nStartingIndex)) {
        typeRet = (txnouttype)nType;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+3, scriptPubKey.begin()+23);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }
    /** XNA END */

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == 20) {
            typeRet = TX_WITNESS_V0_KEYHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            typeRet = TX_WITNESS_V0_SCRIPTHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        return false;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    // Provably prunable, asset data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first three
    // byte passes the IsPushOnly()
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_XNA_ASSET && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_RESTRICTED_ASSET_DATA;

        if (scriptPubKey.size() >= 23 && scriptPubKey[1] != OP_RESERVED) {
            std::vector<unsigned char> hashBytes(scriptPubKey.begin() + 2, scriptPubKey.begin() + 22);
            vSolutionsRet.push_back(hashBytes);
        }
        return true;
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    for (const std::pair<txnouttype, CScript>& tplate : mTemplates)
    {
        const CScript& script2 = tplate.second;
        vSolutionsRet.clear();

        opcodetype opcode1, opcode2;
        std::vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        while (true)
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                typeRet = tplate.first;
                if (typeRet == TX_MULTISIG)
                {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return false;
                }
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;

            // Template matching opcodes:
            if (opcode2 == OP_PUBKEYS)
            {
                while (vch1.size() >= 33 && vch1.size() <= 65)
                {
                    vSolutionsRet.push_back(vch1);
                    if (!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 65)
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_SMALLINTEGER)
            {   // Single-byte small integer pushed onto vSolutions
                if (opcode1 == OP_0 ||
                    (opcode1 >= OP_1 && opcode1 <= OP_16))
                {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(valtype(1, n));
                }
                else
                    break;
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                // Others must match exactly
                break;
            }
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!legacy107::Solver(scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    if (whichType == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
            return false;

        addressRet = pubKey.GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    /** XNA START */
    } else if (whichType == TX_NEW_ASSET || whichType == TX_REISSUE_ASSET || whichType == TX_TRANSFER_ASSET) {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TX_RESTRICTED_ASSET_DATA) {
        if (vSolutions.size()) {
            addressRet = CKeyID(uint160(vSolutions[0]));
            return true;
        }
    }
     /** XNA END */
    // Multisig txns have more than one address...
    return false;
}

// The rule CheckTransaction applies to each output of a transaction that
// issues or reissues nothing (its last branch).
std::string OutputRule(const CScript& script)
{
    int nType = 0;
    bool _isOwner = false;
    int nStartingIndex = 0;
    if (IsAssetScript(script, nType, _isOwner, nStartingIndex)) {
        if (nType != TX_TRANSFER_ASSET) {
            return "bad-txns-bad-asset-transaction";
        }
    } else {
        if (script.Find(OP_XNA_ASSET)) {
            if (script[0] != OP_XNA_ASSET) {
                return "bad-txns-op-xna-asset-not-in-right-script-location";
            }
        }
    }
    return "ok";
}

} // namespace legacy107

namespace {

typedef std::vector<unsigned char> valtype;

// The same rule as 2.0 applies it (CheckTransaction, last branch).
std::string OutputRule20(const CScript& script)
{
    int nType = 0;
    bool fIsOwner = false;
    if (script.IsAssetScript(nType, fIsOwner)) {
        if (nType != TX_TRANSFER_ASSET) {
            return "bad-txns-bad-asset-transaction";
        }
        return "ok";
    }
    if (script.IsNullAsset()) {
        return "ok";
    }
    switch (CheckXnaAssetOutputPlacement(script, /*strict=*/false)) {
    case XnaAssetPlacement::NotInRightLocation: return "bad-txns-op-xna-asset-not-in-right-script-location";
    case XnaAssetPlacement::BadAssetScript: return "bad-txns-bad-asset-script";
    case XnaAssetPlacement::Ok: break;
    }
    return "ok";
}

bool IsAssetOrDataType(txnouttype type)
{
    return type == TX_NEW_ASSET || type == TX_REISSUE_ASSET || type == TX_TRANSFER_ASSET ||
           type == TX_RESTRICTED_ASSET_DATA;
}

std::string Destination(bool fOk, const CTxDestination& dest)
{
    return fOk ? EncodeDestination(dest) : "none";
}

struct Counts {
    int scripts = 0;
    int assets = 0;
    int assetsWithoutP2PKH = 0;
    int nullData = 0;
    int dataDestinations = 0;
    int badLocation = 0;
};

// Compares one script and returns how 1.0.7 classified it.
void Compare(const CScript& script, Counts& counts)
{
    BOOST_TEST_CONTEXT("script=" << HexStr(script)) {
        counts.scripts++;

        int nType107 = -1, nStart107 = -1;
        bool fOwner107 = false;
        const bool fAsset107 = legacy107::IsAssetScript(script, nType107, fOwner107, nStart107);
        int nType20 = -1, nStart20 = -1;
        bool fOwner20 = false;
        const bool fAsset20 = script.IsAssetScript(nType20, fOwner20, nStart20);
        BOOST_CHECK_EQUAL(fAsset20, fAsset107);
        if (fAsset107 && fAsset20) {
            BOOST_CHECK_EQUAL(nType20, nType107);
            BOOST_CHECK_EQUAL(fOwner20, fOwner107);
            BOOST_CHECK_EQUAL(nStart20, nStart107);
            counts.assets++;
            if (script[0] != OP_DUP || script[24] != OP_CHECKSIG) counts.assetsWithoutP2PKH++;
        }

        BOOST_CHECK_EQUAL(script.IsNullAssetTxDataScript(), legacy107::IsNullAssetTxDataScript(script));
        BOOST_CHECK_EQUAL(script.IsNullGlobalRestrictionAssetTxDataScript(),
                          legacy107::IsNullGlobalRestrictionAssetTxDataScript(script));
        BOOST_CHECK_EQUAL(script.IsNullAssetVerifierTxDataScript(),
                          legacy107::IsNullAssetVerifierTxDataScript(script));
        if (legacy107::IsNullAssetTxDataScript(script)) counts.nullData++;

        // The destination of an asset, a tag or a burn. Other types (witness
        // programs, multisig) do not reach consensus through this function.
        txnouttype type107, type20;
        std::vector<valtype> solutions107, solutions20;
        const bool fSolved107 = legacy107::Solver(script, type107, solutions107);
        const bool fSolved20 = Solver(script, type20, solutions20);
        if ((fSolved107 && IsAssetOrDataType(type107)) || (fSolved20 && IsAssetOrDataType(type20))) {
            BOOST_CHECK_EQUAL(fSolved20, fSolved107);
            BOOST_CHECK_EQUAL(std::string(GetTxnOutputType(type20)), std::string(GetTxnOutputType(type107)));
            CTxDestination dest107, dest20;
            const bool fDest107 = legacy107::ExtractDestination(script, dest107);
            const bool fDest20 = ExtractDestination(script, dest20);
            BOOST_CHECK_EQUAL(Destination(fDest20, dest20), Destination(fDest107, dest107));
            if (fDest107 && type107 == TX_RESTRICTED_ASSET_DATA) counts.dataDestinations++;
        }

        const std::string rule107 = legacy107::OutputRule(script);
        BOOST_CHECK_EQUAL(OutputRule20(script), rule107);
        if (rule107 != "ok") counts.badLocation++;

        // An asset script is never a witness program below the fork.
        int witnessVersion = 0;
        valtype program;
        BOOST_CHECK(!GetAssetScriptWitnessProgram(script, witnessVersion, program, nullptr));
    }
}

valtype Push(const valtype& data)
{
    const CScript script = CScript() << data;
    return valtype(script.begin(), script.end());
}

valtype Bytes(const CScript& script)
{
    return valtype(script.begin(), script.end());
}

valtype Concat(std::initializer_list<valtype> parts)
{
    valtype out;
    for (const valtype& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

// Real shapes: the asset part after every prefix 1.0.7 or 2.0 may meet, with
// both markers, every operation and the push encodings of mainnet history.
std::vector<valtype> BaseScripts(FastRandomContext& rng)
{
    const valtype hash20 = rng.randbytes(20);
    const valtype commitment = rng.randbytes(32);
    const valtype p2pkh = Bytes(CScript() << OP_DUP << OP_HASH160 << hash20 << OP_EQUALVERIFY << OP_CHECKSIG);
    std::vector<valtype> prefixes{
        p2pkh,
        Concat({valtype(p2pkh.begin(), p2pkh.end() - 1), {OP_CHECKSIGVERIFY}}),
        Concat({{OP_RETURN, OP_RETURN, 0x14}, hash20, {OP_RETURN, OP_RETURN}}),
        Concat({{OP_HASH160, 0x14}, hash20, {OP_EQUAL, OP_NOP, OP_NOP}}),
        rng.randbytes(25),
        Bytes(CScript() << OP_1 << commitment),
        Bytes(CScript() << OP_2 << commitment),
        Bytes(CScript() << OP_3 << commitment),
        Bytes(CScript() << OP_0 << commitment),
        {},
    };
    // A prefix whose 25th byte is OP_XNA_ASSET with "rvn" right after it.
    valtype grind = Bytes(CScript() << OP_1 << commitment);
    grind[25] = OP_XNA_ASSET;
    grind[26] = 0x10;
    grind[27] = XNA_R;
    grind[28] = XNA_V;
    grind[29] = XNA_N;
    grind[30] = XNA_T;
    prefixes.push_back(grind);

    std::vector<valtype> payloads;
    for (const char* marker : {"rvn", "xna"}) {
        for (char op : {'t', 'q', 'o', 'r', 'x'}) {
            valtype message(marker, marker + 3);
            message.push_back(op);
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << std::string("PARITY") << int64_t(5 * COIN);
            if (op == 'q') ss << int8_t(0) << int8_t(1) << int8_t(0);
            message.insert(message.end(), ss.begin(), ss.end());
            payloads.push_back(message);
        }
    }

    std::vector<valtype> scripts;
    for (const valtype& prefix : prefixes) {
        for (const valtype& message : payloads) {
            // Direct push, doubled OP_XNA_ASSET and OP_PUSHDATA1, as on mainnet.
            scripts.push_back(Concat({prefix, {OP_XNA_ASSET}, Push(message), {OP_DROP}}));
            scripts.push_back(Concat({prefix, {OP_XNA_ASSET, OP_XNA_ASSET}, Push(message), {OP_DROP}}));
            scripts.push_back(Concat({prefix, {OP_XNA_ASSET, OP_PUSHDATA1, (unsigned char)message.size()}, message, {OP_DROP}}));
        }
    }

    // Asset data outputs: tags, global restrictions, verifiers, the AuthScript
    // form of the fork, and other pushes that 1.0.7 reads a destination from.
    CDataStream tag(SER_NETWORK, PROTOCOL_VERSION);
    tag << std::string("#TAG") << int8_t(1);
    const valtype tagData(tag.begin(), tag.end());
    scripts.push_back(Concat({{OP_XNA_ASSET, 0x14}, hash20, Push(tagData)}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_1, 0x20}, commitment, Push(tagData)}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_1, 0x20}, valtype(32, 0), Push({0x00})}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_1, 0x20}, valtype(32, 0), {0x00}}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_2, 0x20}, commitment, Push(tagData)}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_RESERVED, OP_RESERVED}, Push(tagData)}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_RESERVED}, Push(tagData)}));
    scripts.push_back(Concat({{OP_XNA_ASSET}, Push(Concat({hash20, {0x00}}))}));
    scripts.push_back(Concat({{OP_XNA_ASSET}, Push(rng.randbytes(40))}));
    scripts.push_back(Concat({{OP_XNA_ASSET, OP_16}, hash20, {0x01, 0x00}}));
    scripts.push_back({OP_XNA_ASSET});
    // Plain scripts of every template.
    scripts.push_back(p2pkh);
    scripts.push_back(Bytes(CScript() << OP_HASH160 << hash20 << OP_EQUAL));
    scripts.push_back(Bytes(CScript() << OP_0 << hash20));
    scripts.push_back(Bytes(CScript() << OP_0 << commitment));
    scripts.push_back(Bytes(CScript() << OP_1 << commitment));
    scripts.push_back(Bytes(CScript() << OP_RETURN << rng.randbytes(30)));
    return scripts;
}

valtype Mutate(FastRandomContext& rng, valtype script)
{
    static const unsigned char interesting[] = {
        OP_XNA_ASSET, XNA_R, XNA_V, XNA_N, XNA_T, XNA_Q, XNA_O, XNA_X, XNA_A, OP_DUP, OP_HASH160, 0x14,
        0x20, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_RESERVED, OP_1, OP_2, OP_3, OP_0, OP_DROP,
        OP_PUSHDATA1, OP_RETURN, 0x00, 0xff};
    const int edits = 1 + rng.randrange(3);
    for (int i = 0; i < edits; ++i) {
        const int kind = rng.randrange(10);
        // Most edits land on the bytes both parsers look at.
        const size_t span = script.empty() ? 1 : (rng.randbool() ? std::min<size_t>(script.size(), 41) : script.size());
        const size_t pos = rng.randrange(span);
        const unsigned char value = rng.randbool() ? interesting[rng.randrange(sizeof(interesting))] : (unsigned char)rng.randbits(8);
        if (kind < 6) {
            if (pos < script.size()) script[pos] = value;
        } else if (kind < 8) {
            script.insert(script.begin() + std::min(pos, script.size()), value);
        } else if (kind < 9) {
            if (pos < script.size()) script.erase(script.begin() + pos);
        } else {
            script.resize(rng.randrange(script.size() + 8));
        }
    }
    return script;
}

valtype RandomScript(FastRandomContext& rng)
{
    valtype script = rng.randbytes(rng.randrange(80));
    if (script.size() > 31 && rng.randrange(4) != 0) {
        script[25] = OP_XNA_ASSET;
        const size_t at = 27 + rng.randrange(2);
        const char* marker = rng.randbool() ? "rvn" : "xna";
        for (int i = 0; i < 3; ++i) script[at + i] = marker[i];
        static const unsigned char ops[] = {XNA_T, XNA_Q, XNA_O, XNA_R};
        script[at + 3] = ops[rng.randrange(4)];
    }
    if (!script.empty() && rng.randrange(4) == 0) script[0] = OP_XNA_ASSET;
    return script;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(legacy_parity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(below_the_fork_scripts_read_as_in_107)
{
    CStrictAuthScriptContext below(false);
    FastRandomContext rng(true);
    Counts counts;

    const std::vector<valtype> bases = BaseScripts(rng);
    for (const valtype& base : bases) {
        Compare(CScript(base.begin(), base.end()), counts);
    }
    for (int i = 0; i < 300000; ++i) {
        const valtype script = Mutate(rng, bases[rng.randrange(bases.size())]);
        Compare(CScript(script.begin(), script.end()), counts);
    }
    for (int i = 0; i < 300000; ++i) {
        const valtype script = RandomScript(rng);
        Compare(CScript(script.begin(), script.end()), counts);
    }

    BOOST_TEST_MESSAGE("scripts=" << counts.scripts << " assets=" << counts.assets
        << " without P2PKH=" << counts.assetsWithoutP2PKH << " tags=" << counts.nullData
        << " data destinations=" << counts.dataDestinations << " refused=" << counts.badLocation);
    // The comparison is not vacuous: every class appears many times.
    BOOST_CHECK_GT(counts.assets, 10000);
    BOOST_CHECK_GT(counts.assetsWithoutP2PKH, 1000);
    BOOST_CHECK_GT(counts.nullData, 500);
    BOOST_CHECK_GT(counts.dataDestinations, 1000);
    BOOST_CHECK_GT(counts.badLocation, 10000);
}

// The shapes the parity lab confirmed against a running 1.0.7 node.
BOOST_AUTO_TEST_CASE(confirmed_divergences_are_closed_below_the_fork)
{
    const valtype hash20(20, 0x42);
    const valtype commitment(32, 0x07);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << std::string("PARITY") << int64_t(COIN);
    valtype transfer{XNA_R, XNA_V, XNA_N, XNA_T};
    transfer.insert(transfer.end(), ss.begin(), ss.end());

    const CScript checksigverify = CScript() << OP_DUP << OP_HASH160 << hash20 << OP_EQUALVERIFY << OP_CHECKSIGVERIFY
                                             << OP_XNA_ASSET << transfer << OP_DROP;
    const CScript authscript = CScript() << OP_1 << commitment << OP_XNA_ASSET << transfer << OP_DROP;
    const CScript nullAuthScript = CScript() << OP_XNA_ASSET << OP_1 << commitment << valtype{0x00};
    valtype burnPush(hash20);
    burnPush.push_back(0x00);
    const CScript burn = CScript() << OP_XNA_ASSET << burnPush;

    int nType = 0, nStart = 0;
    bool fOwner = false;
    CTxDestination dest;
    {
        CStrictAuthScriptContext below(false);
        // A transfer after any 25 bytes is an asset of the holder in bytes 3..23.
        BOOST_CHECK(checksigverify.IsAssetScript(nType, fOwner, nStart));
        BOOST_CHECK(ExtractDestination(checksigverify, dest));
        BOOST_CHECK_EQUAL(EncodeDestination(dest), EncodeDestination(CKeyID(uint160(hash20))));
        // The AuthScript forms are not assets nor asset data.
        BOOST_CHECK(!authscript.IsAssetScript(nType, fOwner, nStart));
        BOOST_CHECK_EQUAL(OutputRule20(authscript), "bad-txns-op-xna-asset-not-in-right-script-location");
        BOOST_CHECK(!nullAuthScript.IsNullAssetTxDataScript());
        BOOST_CHECK(!nullAuthScript.IsNullAsset());
        // An asset data push other than 20 bytes still names a destination,
        // which the burn check of an issuance reads.
        BOOST_CHECK(ExtractDestination(burn, dest));
        BOOST_CHECK_EQUAL(EncodeDestination(dest), EncodeDestination(CKeyID(uint160(hash20))));
        // 2.0 does not relay an asset after another prefix. Asset data stays
        // standard in any encoding, as in 1.0.7; the mempool drops what changes
        // meaning when the fork activates.
        txnouttype type;
        BOOST_CHECK(!IsStandard(checksigverify, type, true));
        BOOST_CHECK(IsStandard(nullAuthScript, type, true));
        BOOST_CHECK(IsStandard(burn, type, true));
    }
    {
        // From the fork: the P2PKH layout is required and the AuthScript forms count.
        CStrictAuthScriptContext active(true);
        BOOST_CHECK(!checksigverify.IsAssetScript(nType, fOwner, nStart));
        BOOST_CHECK(authscript.IsAssetScript(nType, fOwner, nStart));
        BOOST_CHECK(nullAuthScript.IsNullAssetTxDataScript());
        BOOST_CHECK(!ExtractDestination(burn, dest));
    }
}

BOOST_AUTO_TEST_SUITE_END()
