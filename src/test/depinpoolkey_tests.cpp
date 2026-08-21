// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The DePIN pool key holder and the response transport layer
// (depinpoolkey.{h,cpp}): the owner's vouching signature, and "poolsig" over
// encrypted and plain responses.

#include "depinpoolkey.h"

// amount.h first: assets/assetdb.h declares CAmount parameters without
// including it, so it only compiles when the includer got there first.
#include "amount.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "depinchallenge.h"
#include "depinecies.h"
#include "key.h"
#include "pubkey.h"
#include "streams.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <univalue.h>

namespace {

const std::string TOKEN = "&TEST";

struct Holder {
    CKey key;
    CPubKey pubkey;
    std::string address;
};

Holder NewHolder()
{
    Holder h;
    h.key.MakeNewKey(true);
    h.pubkey = h.key.GetPubKey();
    h.address = EncodeDestination(h.pubkey.GetID());
    return h;
}

// REGTEST: DEPIN names only validate on testnet/regtest. The owner check reads
// the asset-address index, so the fixture provides in-memory asset databases.
struct DepinPoolKeySetup : public TestingSetup {
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;

    DepinPoolKeySetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssetIndex = fAssetIndex;
        prevPubKeyIndex = fPubKeyIndex;
        prevAssetsDb = passetsdb;
        prevAssetsCache = passetsCache;
        prevRestrictedDb = prestricteddb;
        fAssetIndex = true;
        fPubKeyIndex = true;
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);
        prestricteddb = new CRestrictedDB(1 << 20, true, true);
        ClearDepinPoolKey();
    }

    ~DepinPoolKeySetup()
    {
        ClearDepinPoolKey();
        delete prestricteddb;
        delete passetsCache;
        delete passetsdb;
        prestricteddb = prevRestrictedDb;
        passetsCache = prevAssetsCache;
        passetsdb = prevAssetsDb;
        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
    }
};

std::string OwnerSign(const Holder& owner, const std::string& token, const CPubKey& poolPub)
{
    std::string sig, error;
    BOOST_REQUIRE_MESSAGE(SignDepinChallengePreimage(owner.key, DepinPoolKeyOwnerPreimage(token, poolPub), sig, error), error);
    return sig;
}

std::string Decrypt(const UniValue& response, const Holder& client)
{
    BOOST_REQUIRE_MESSAGE(response.exists("encrypted"), response.write());
    CECIESEncryptedMessage ecies;
    CDataStream ss(ParseHex(response["encrypted"].get_str()), SER_NETWORK, PROTOCOL_VERSION);
    ss >> ecies;
    std::string plaintext, error;
    BOOST_REQUIRE_MESSAGE(ECIESDecryptMessage(ecies, client.key, client.address, plaintext, error), error);
    return plaintext;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depinpoolkey_tests, DepinPoolKeySetup)

BOOST_AUTO_TEST_CASE(pool_key_holder_roundtrip)
{
    CKey key, got;
    CPubKey pub;
    BOOST_CHECK(!HaveDepinPoolKey());
    BOOST_CHECK(!GetDepinPoolKey(got, pub));

    CKey poolKey;
    poolKey.MakeNewKey(true);
    SetDepinPoolKey(poolKey, "NXowner", "c2ln", "service.dat");
    BOOST_CHECK(HaveDepinPoolKey());
    BOOST_REQUIRE(GetDepinPoolKey(got, pub));
    BOOST_CHECK(got == poolKey);
    BOOST_CHECK(pub == poolKey.GetPubKey());
    BOOST_CHECK_EQUAL(GetDepinPoolKeyOwner(), "NXowner");
    BOOST_CHECK_EQUAL(GetDepinPoolKeySig(), "c2ln");
    BOOST_CHECK_EQUAL(GetDepinPoolKeyWalletName(), "service.dat");

    ClearDepinPoolKey();
    BOOST_CHECK(!HaveDepinPoolKey());
    BOOST_CHECK_EQUAL(GetDepinPoolKeyOwner(), "");
}

// (13) The owner's signature is verified by recovering the signer and asking
// the asset index whether it holds the owner token.
BOOST_AUTO_TEST_CASE(owner_signature_verified_against_owner)
{
    const Holder owner = NewHolder();
    const Holder holder = NewHolder(); // holds the token, not the owner token
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(TOKEN + OWNER_TAG, owner.address, 1));
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(TOKEN, holder.address, 10));

    CKey poolKey;
    poolKey.MakeNewKey(true);
    const CPubKey poolPub = poolKey.GetPubKey();
    CKey otherKey;
    otherKey.MakeNewKey(true);

    BOOST_CHECK_EQUAL(DepinPoolKeyOwnerPreimage(TOKEN, poolPub),
                      "DEPIN-POOLKEY|" + TOKEN + "|" + HexStr(poolPub.begin(), poolPub.end()));

    std::string ownerOut, error;
    BOOST_CHECK_MESSAGE(VerifyDepinPoolKeyOwnerSignature(TOKEN, poolPub, OwnerSign(owner, TOKEN, poolPub), ownerOut, error), error);
    BOOST_CHECK_EQUAL(ownerOut, owner.address);

    // A plain holder is not an owner.
    BOOST_CHECK(!VerifyDepinPoolKeyOwnerSignature(TOKEN, poolPub, OwnerSign(holder, TOKEN, poolPub), ownerOut, error));
    // The owner vouching for ANOTHER pubkey does not cover this one.
    BOOST_CHECK(!VerifyDepinPoolKeyOwnerSignature(TOKEN, poolPub, OwnerSign(owner, TOKEN, otherKey.GetPubKey()), ownerOut, error));
    // ...nor a signature for another token.
    BOOST_CHECK(!VerifyDepinPoolKeyOwnerSignature(TOKEN, poolPub, OwnerSign(owner, "&OTHER", poolPub), ownerOut, error));
    // Garbage.
    BOOST_CHECK(!VerifyDepinPoolKeyOwnerSignature(TOKEN, poolPub, "not-base64!", ownerOut, error));
    BOOST_CHECK(!VerifyDepinPoolKeyOwnerSignature(TOKEN, poolPub, "", ownerOut, error));
}

// (25) poolsig covers method, token, address, nonce and the exact body; the
// body is the ciphertext when the response is encrypted.
BOOST_AUTO_TEST_CASE(poolsig_covers_ciphertext_and_nonce)
{
    const Holder client = NewHolder();
    CKey poolKey;
    poolKey.MakeNewKey(true);
    const CPubKey poolPub = poolKey.GetPubKey();

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("a", 1));
    obj.push_back(Pair("b", "two"));
    const std::string nonce(64, 'f');

    // No key loaded: a DePIN response is never produced unsigned.
    BOOST_CHECK_THROW(FinishDepinResponse(obj, "depinreceivemsg", TOKEN, client.address, nonce, &client.pubkey), UniValue);

    SetDepinPoolKey(poolKey, "NXowner", "sig", "service.dat");

    // Encrypted: the plaintext never appears, the signature is over the blob.
    const UniValue enc = FinishDepinResponse(obj, "depinreceivemsg", TOKEN, client.address, nonce, &client.pubkey);
    BOOST_REQUIRE(enc.exists("encrypted"));
    BOOST_REQUIRE(enc.exists("poolsig"));
    BOOST_CHECK(!enc.exists("a"));
    const std::string body = enc["encrypted"].get_str();
    const std::string sig = enc["poolsig"].get_str();

    std::string error;
    BOOST_CHECK_MESSAGE(VerifyDepinResponseSignature(poolPub, "depinreceivemsg", TOKEN, client.address, nonce, body, sig, error), error);
    BOOST_CHECK_EQUAL(Decrypt(enc, client), obj.write());

    // Any change to what the signature binds invalidates it.
    std::string altered = body;
    altered[10] = (altered[10] == '0') ? '1' : '0';
    BOOST_CHECK(!VerifyDepinResponseSignature(poolPub, "depinreceivemsg", TOKEN, client.address, nonce, altered, sig, error));
    BOOST_CHECK(!VerifyDepinResponseSignature(poolPub, "depinreceivemsg", TOKEN, client.address, std::string(64, 'e'), body, sig, error));
    BOOST_CHECK(!VerifyDepinResponseSignature(poolPub, "depinsubmitmsg", TOKEN, client.address, nonce, body, sig, error));
    BOOST_CHECK(!VerifyDepinResponseSignature(poolPub, "depinreceivemsg", "&OTHER", client.address, nonce, body, sig, error));
    BOOST_CHECK(!VerifyDepinResponseSignature(poolPub, "depinreceivemsg", TOKEN, "NXsomeoneelse", nonce, body, sig, error));
    CKey otherPool;
    otherPool.MakeNewKey(true);
    BOOST_CHECK(!VerifyDepinResponseSignature(otherPool.GetPubKey(), "depinreceivemsg", TOKEN, client.address, nonce, body, sig, error));

    // Plain: an explicit canonical body (hex of the JSON) plus the signature
    // over that very string -- nothing to re-serialise on the client.
    const UniValue plain = FinishDepinResponse(obj, "depingetmsginfo", TOKEN, "", "", nullptr);
    BOOST_REQUIRE(plain.exists("body"));
    BOOST_CHECK(!plain.exists("encrypted"));
    BOOST_CHECK(!plain.exists("a"));
    const std::string plainBody = plain["body"].get_str();
    const std::string objJson = obj.write();
    BOOST_CHECK_EQUAL(plainBody, HexStr(objJson.begin(), objJson.end()));
    BOOST_CHECK(VerifyDepinResponseSignature(poolPub, "depingetmsginfo", TOKEN, "", "", plainBody, plain["poolsig"].get_str(), error));
    BOOST_CHECK(!VerifyDepinResponseSignature(poolPub, "depingetmsginfo", TOKEN, "", "", obj.write(), plain["poolsig"].get_str(), error));
    const UniValue decoded = DepinPlainBody(plain);
    BOOST_CHECK_EQUAL(decoded["a"].get_int(), 1);
    BOOST_CHECK_EQUAL(decoded["b"].get_str(), "two");

    // Any JSON value works as a body, arrays included.
    UniValue arr(UniValue::VARR);
    arr.push_back("x");
    const UniValue plainArr = FinishDepinResponse(arr, "depinlistsections", TOKEN, "", "", nullptr);
    BOOST_REQUIRE(DepinPlainBody(plainArr).isArray());
    BOOST_CHECK_EQUAL(DepinPlainBody(plainArr)[0].get_str(), "x");
    BOOST_CHECK(VerifyDepinResponseSignature(poolPub, "depinlistsections", TOKEN, "", "", plainArr["body"].get_str(), plainArr["poolsig"].get_str(), error));
    BOOST_CHECK_THROW(DepinPlainBody(enc), UniValue);

    // The preimage is what a client reconstructs; it is verifymessage-compatible
    // against the pool key's P2PKH address.
    BOOST_CHECK(VerifyDepinChallengeSignature(EncodeDestination(poolPub.GetID()), sig,
                                              DepinResponsePreimage("depinreceivemsg", TOKEN, client.address, nonce, body), error));
}

BOOST_AUTO_TEST_SUITE_END()
