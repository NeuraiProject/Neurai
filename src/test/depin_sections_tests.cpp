// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Hierarchical sections in DePIN messaging: sub-assets of the pool token act
// as chat sections with DOWNWARD visibility -- an active holder of "&TEST"
// participates in "&TEST/GENERAL"; a holder of only "&TEST/GENERAL" never
// reaches the root or a sibling.
//
// The tests drive the code through its real seams (passetsdb, prestricteddb,
// the pubkey index and the pool itself) rather than through issuance
// transactions, the same approach as depin_ancestor_recipients_tests.cpp:
// those databases are exactly what the section code reads, so writing them
// directly exercises it without a wallet, a miner or a chain.
//
// Two tests assert SHAPE rather than answers, and their asymmetry is
// deliberate:
//   - missing_dependencies_are_named_errors: passetsdb / prestricteddb /
//     fAssetIndex are dependencies that MUST fail with a named error when
//     absent (a missing restriction DB fails OPEN otherwise).
//   - authorization_requires_chainstate_cache: a missing connected-tip cache
//     must fail closed; reading only persisted balances is no longer enough.
//
// Runs on REGTEST: DEPIN names only validate on testnet/regtest.

#include "depinmsgpool.h"

#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "depinchallenge.h"
#include "depinecies.h"
#include "clientversion.h"
#include "dbwrapper.h"
#include <cstdlib>
#ifndef WIN32
#include <sys/statvfs.h>
#endif
#include "random.h"
#include "util.h"
#include "depinpoolkey.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "pubkeyindex.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_neurai.h"
#include "test/depin_test_utils.h"
#include "test/depin_rpc_test_client.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <univalue.h>
#include <vector>

namespace {

const std::string ROOT = "&TEST";
const std::string SECTION_A = "&TEST/GENERAL";
const std::string SECTION_B = "&TEST/OTHERS";
const std::string SECTION_A_SUB = "&TEST/GENERAL/SUB";

struct StateMetaFixture {
    uint32_t version = 2;
    uint256 stream;
    uint64_t high = 0;
    int64_t floor = 0;
    template <typename Stream> void Serialize(Stream& s) const {
        s << version << ROOT << stream << high << uint8_t(1) << floor << uint8_t(1);
    }
};
struct StateRecordFixture {
    uint64_t sequence;
    std::vector<unsigned char> bytes;
    template <typename Stream> void Serialize(Stream& s) const { s << sequence << bytes << CPubKey(); }
};

struct RawStateFixture {
    std::vector<unsigned char> bytes;
    template <typename Stream> void Serialize(Stream& stream) const {
        stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
};

struct Holder {
    CKey key;
    CPubKey pubkey;
    std::string address;
};

struct DepinSectionsSetup : public TestingSetup {
    ScopedDepinTestTipTime currentTip;
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;
    CKey poolKey;

    DepinSectionsSetup() : TestingSetup(CBaseChainParams::REGTEST)
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

        // Every DePIN response is signed with the pool key and depinsubmitmsg
        // only accepts envelopes for it.
        poolKey.MakeNewKey(true);
        SetDepinPoolKey(poolKey, "test");
        g_depinRateLimiter.Clear();
        g_depinRateLimiter.SetLimit(DEFAULT_DEPIN_RATE_LIMIT);

        gDepinAncestorRecipientsStats.Reset();
    }

    ~DepinSectionsSetup()
    {
        g_depinRateLimiter.Clear();
        g_depinRateLimiter.SetLimit(DEFAULT_DEPIN_RATE_LIMIT);
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

    void CreateAsset(const std::string& name)
    {
        CNewAsset asset(name, 1000 * COIN, DEPIN_ASSET_UNITS, 0, 0, "");
        BOOST_REQUIRE(passetsdb->WriteAssetData(asset, 1, uint256()));
    }

    void SetBalance(const std::string& assetName, const std::string& address, CAmount amount)
    {
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(assetName, address, amount));
    }

    void FreezeAddress(const std::string& assetName, const std::string& address)
    {
        BOOST_REQUIRE(prestricteddb->WriteRestrictedAddress(address, assetName));
    }

    void SelfRevoke(const std::string& assetName, const std::string& address)
    {
        BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(address, assetName));
    }

    void RevealPubKey(const std::string& address, const CPubKey& pubkey)
    {
        CTxDestination dest = DecodeDestination(address);
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));

        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(pubkey, 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    }

    Holder NewHolder(bool revealPubKey = true)
    {
        Holder holder;
        holder.key.MakeNewKey(true);
        holder.pubkey = holder.key.GetPubKey();
        holder.address = EncodeDestination(holder.pubkey.GetID());
        RememberDepinTestKey(holder.key);
        if (revealPubKey) {
            RevealPubKey(holder.address, holder.pubkey);
        }
        return holder;
    }
};

// RAII: null a global for the duration of a check and put it back afterwards.
template <typename T>
struct NullGuard {
    T*& slot;
    T* saved;
    explicit NullGuard(T*& slotIn) : slot(slotIn), saved(slotIn) { slot = nullptr; }
    ~NullGuard() { slot = saved; }
};

struct FlagGuard {
    bool& slot;
    bool saved;
    FlagGuard(bool& slotIn, bool value) : slot(slotIn), saved(slotIn) { slot = value; }
    ~FlagGuard() { slot = saved; }
};

// RAII: swap in a properly Initialize()d global pool, restore on exit.
struct ScopedInitializedPool {
    std::unique_ptr<CDepinMsgPool> previous;

    explicit ScopedInitializedPool(const std::string& token, unsigned int maxRecipients = 20)
        : previous(std::move(pDepinMsgPool))
    {
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(token, maxRecipients,
                                                DEFAULT_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                                DEFAULT_DEPIN_POOL_SIZE_MB));
    }

    ~ScopedInitializedPool()
    {
        pDepinMsgPool = std::move(previous);
    }
};

// A message whose payload is a real ECIES structure encrypted for `recipients`.
CDepinMessage MakeEciesMessage(const std::string& token, const Holder& sender,
                               const std::vector<Holder>& recipients, const std::string& text)
{
    std::map<std::string, CPubKey> keys;
    for (const Holder& holder : recipients) {
        keys[holder.address] = holder.pubkey;
    }

    CECIESEncryptedMessage ecies;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage(text, keys, ecies, error), error);

    CDepinMessage msg;
    msg.token = token;
    msg.senderAddress = sender.address;
    msg.timestamp = GetTime();
    msg.messageType = 0x02;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ecies;
    msg.encryptedPayload.assign(ss.begin(), ss.end());
    return msg;
}

bool TryDecrypt(const CDepinMessage& msg, const Holder& holder, std::string& plaintextOut)
{
    CECIESEncryptedMessage ecies;
    try {
        CDataStream ss(msg.encryptedPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> ecies;
    } catch (const std::exception&) {
        return false;
    }
    std::string error;
    return ECIESDecryptMessage(ecies, holder.key, holder.address, plaintextOut, error);
}

std::vector<const CDepinMessage*> Pointers(const std::vector<CDepinMessage>& messages)
{
    std::vector<const CDepinMessage*> out;
    for (const CDepinMessage& msg : messages) {
        out.push_back(&msg);
    }
    return out;
}

uint160 Hash160Of(const std::string& address)
{
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    BOOST_REQUIRE(keyID != nullptr);
    return uint160(*keyID);
}

// Sign a message the way depinsubmitmsg's VerifyDepinMessageSignature expects:
// the signed hash is the message identifier itself (GetHash).
void SignMessageWithKey(CDepinMessage& msg, const CKey& key)
{
    BOOST_REQUIRE(key.Sign(msg.GetHash(), msg.signature));
}

UniValue CallDepinRPC(const std::string& method, const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    request.fHelp = false;

    BOOST_REQUIRE(tableRPC[method]);
    return CallDepinTestRpc(method,params);
}

// What a client sends to depinsubmitmsg: the serialized message inside an
// ECIES envelope for the pool key.
UniValue WrapForPool(const std::string& sender, const CDepinMessage& msg)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << msg;
    const std::string hexMessage = HexStr(ss.begin(), ss.end());

    CKey poolKey;
    CPubKey poolPub;
    BOOST_REQUIRE(GetDepinPoolKey(poolKey, poolPub));
    std::map<std::string, CPubKey> keys;
    keys[EncodeDestination(poolPub.GetID())] = poolPub;

    CECIESEncryptedMessage ecies;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage(hexMessage, keys, ecies, error), error);
    CDataStream envelope(SER_NETWORK, PROTOCOL_VERSION);
    envelope << ecies;

    UniValue wrapped(UniValue::VOBJ);
    wrapped.push_back(Pair("sender", sender));
    wrapped.push_back(Pair("encrypted", HexStr(envelope.begin(), envelope.end())));
    return wrapped;
}

// Opens an encrypted DePIN response with the holder's key.
UniValue OpenResponse(const UniValue& response, const Holder& holder)
{
    BOOST_REQUIRE_MESSAGE(response.exists("encrypted"), response.write());
    BOOST_REQUIRE(response.exists("poolsig"));
    CECIESEncryptedMessage ecies;
    CDataStream ss(ParseHex(response["encrypted"].get_str()), SER_NETWORK, PROTOCOL_VERSION);
    ss >> ecies;
    std::string plaintext, error;
    BOOST_REQUIRE_MESSAGE(ECIESDecryptMessage(ecies, holder.key, holder.address, plaintext, error), error);
    UniValue inner;
    BOOST_REQUIRE(inner.read(plaintext));
    return inner;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_sections_tests, DepinSectionsSetup)

// ---------------------------------------------------------------------------
// Pure hierarchy helpers
// ---------------------------------------------------------------------------

// (1) The subtree predicate: root included, prefix traps excluded, never
// symmetric.
BOOST_AUTO_TEST_CASE(section_or_root_boundaries)
{
    BOOST_CHECK(IsDepinSectionOrRoot(ROOT, ROOT));
    BOOST_CHECK(IsDepinSectionOrRoot(SECTION_A, ROOT));
    BOOST_CHECK(IsDepinSectionOrRoot(SECTION_A_SUB, ROOT));
    BOOST_CHECK(IsDepinSectionOrRoot(SECTION_A_SUB, SECTION_A));

    // Sharing a prefix is not being inside the subtree: the character after
    // the root must be exactly '/'.
    BOOST_CHECK(!IsDepinSectionOrRoot("&TESTING", ROOT));
    BOOST_CHECK(!IsDepinSectionOrRoot("&TEST.FOO", ROOT));
    BOOST_CHECK(!IsDepinSectionOrRoot("&TES", ROOT));

    // Never symmetric: the root is not a section of its child.
    BOOST_CHECK(!IsDepinSectionOrRoot(ROOT, SECTION_A));
    BOOST_CHECK(!IsDepinSectionOrRoot(SECTION_B, SECTION_A));

    // Degenerate inputs.
    BOOST_CHECK(!IsDepinSectionOrRoot("", ROOT));
    BOOST_CHECK(!IsDepinSectionOrRoot(ROOT, ""));
}

// (2) Ancestor derivation: leaf -> root in order, root alone, foreign stop_at
// is an error.
BOOST_AUTO_TEST_CASE(ancestor_chain_derivation)
{
    std::vector<std::string> ancestors;
    std::string error;

    BOOST_REQUIRE_MESSAGE(DeriveDepinAncestors("&TEST/A/BBB", ROOT, ancestors, error), error);
    const std::vector<std::string> expected = {"&TEST/A/BBB", "&TEST/A", ROOT};
    BOOST_CHECK_EQUAL_COLLECTIONS(ancestors.begin(), ancestors.end(),
                                  expected.begin(), expected.end());

    BOOST_REQUIRE(DeriveDepinAncestors(ROOT, ROOT, ancestors, error));
    BOOST_REQUIRE_EQUAL(ancestors.size(), 1U);
    BOOST_CHECK_EQUAL(ancestors[0], ROOT);

    // Empty stopAt: up to the absolute root.
    BOOST_REQUIRE(DeriveDepinAncestors(SECTION_A_SUB, "", ancestors, error));
    BOOST_REQUIRE_EQUAL(ancestors.size(), 3U);
    BOOST_CHECK_EQUAL(ancestors.back(), ROOT);

    // A stopAt outside the branch is an error, not an empty answer.
    BOOST_CHECK(!DeriveDepinAncestors(SECTION_A, "&OTHER", ancestors, error));
    BOOST_CHECK(!error.empty());
}

// (3) UI labels relative to the pool root.
BOOST_AUTO_TEST_CASE(section_labels)
{
    BOOST_CHECK_EQUAL(GetDepinSectionLabel(ROOT, ROOT), "");
    BOOST_CHECK_EQUAL(GetDepinSectionLabel(SECTION_A, ROOT), "GENERAL");
    BOOST_CHECK_EQUAL(GetDepinSectionLabel(SECTION_A_SUB, ROOT), "GENERAL/SUB");
    // Outside the subtree the name comes back unchanged.
    BOOST_CHECK_EQUAL(GetDepinSectionLabel("&TESTING", ROOT), "&TESTING");
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// (4) Visibility is downward: the root holder reaches every section, the
// section holder never reaches the root or a sibling.
BOOST_AUTO_TEST_CASE(access_is_inherited_downward_never_upward)
{
    const Holder rootHolder = NewHolder(false);
    const Holder sectionHolder = NewHolder(false);

    SetBalance(ROOT, rootHolder.address, 10);
    SetBalance(SECTION_A, sectionHolder.address, 10);

    std::string error;
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(rootHolder.address, SECTION_A, ROOT, error), error);
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(rootHolder.address, SECTION_A_SUB, ROOT, error), error);
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(rootHolder.address, ROOT, ROOT, error), error);

    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(sectionHolder.address, SECTION_A, ROOT, error), error);
    BOOST_CHECK(!HasDepinSectionAccess(sectionHolder.address, ROOT, ROOT, error));
    BOOST_CHECK(!HasDepinSectionAccess(sectionHolder.address, SECTION_B, ROOT, error));
}

// (5) A restricted pair only excludes when NO ancestor pair remains active:
// the root keeps granting what a section-level revocation cannot take away.
BOOST_AUTO_TEST_CASE(restriction_excludes_only_without_active_ancestor)
{
    const Holder revoked = NewHolder(false);
    const Holder frozen = NewHolder(false);

    // Self-revoked in the section, holding nothing else: no access.
    SetBalance(SECTION_A, revoked.address, 10);
    SelfRevoke(SECTION_A, revoked.address);
    std::string error;
    BOOST_CHECK(!HasDepinSectionAccess(revoked.address, SECTION_A, ROOT, error));

    // The same address also holds the ACTIVE root: access restored -- the
    // root grants visibility regardless of the section-level revocation.
    SetBalance(ROOT, revoked.address, 5);
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(revoked.address, SECTION_A, ROOT, error), error);

    // Owner freeze behaves the same as self-revocation.
    SetBalance(SECTION_B, frozen.address, 10);
    FreezeAddress(SECTION_B, frozen.address);
    BOOST_CHECK(!HasDepinSectionAccess(frozen.address, SECTION_B, ROOT, error));
}

// (6) Missing dependencies are NAMED errors, never "no access for lack of
// balance": denying with a false reason misleads exactly like granting too
// much. All three variants in one test.
BOOST_AUTO_TEST_CASE(missing_dependencies_are_named_errors)
{
    const Holder holder = NewHolder(false);
    SetBalance(SECTION_A, holder.address, 10);

    // Sanity: with everything present, access is granted.
    std::string error;
    BOOST_REQUIRE_MESSAGE(HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error), error);

    {
        FlagGuard guard(fAssetIndex, false);
        error.clear();
        BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
        BOOST_CHECK_MESSAGE(error.find("-assetindex") != std::string::npos, error);
    }
    {
        NullGuard<CAssetsDB> guard(passetsdb);
        error.clear();
        BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
        BOOST_CHECK_MESSAGE(error.find("Asset database") != std::string::npos, error);
    }
    {
        NullGuard<CRestrictedDB> guard(prestricteddb);
        error.clear();
        BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
        BOOST_CHECK_MESSAGE(error.find("Restricted asset database") != std::string::npos, error);
        // Specifically NOT the no-balance denial.
        BOOST_CHECK_MESSAGE(error.find("no active balance") == std::string::npos, error);
    }

    // And everything restored works again.
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error), error);
}

// (7) Chainstate absence must be a named error even when disk has a balance.
BOOST_AUTO_TEST_CASE(authorization_requires_chainstate_cache)
{
    const Holder active = NewHolder(false);
    SetBalance(SECTION_A, active.address, 10);
    std::string error;
    {
        NullGuard<CAssetsCache> assetsGuard(passets);
        BOOST_CHECK(!HasDepinSectionAccess(active.address, SECTION_A, ROOT, error));
        BOOST_CHECK(error.find("chainstate cache") != std::string::npos);
        BOOST_CHECK(!HasDepinSectionOwnerAccess(active.address, SECTION_A, ROOT, error));
    }
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(active.address, SECTION_A, ROOT, error), error);
}

// (8) Owner authority follows the BASE-name chain with '!' re-appended per
// level: the root owner controls every section, a section owner controls its
// subtree and nothing above or beside it.
BOOST_AUTO_TEST_CASE(owner_access_follows_base_name_chain)
{
    const Holder rootOwner = NewHolder(false);
    const Holder sectionOwner = NewHolder(false);

    SetBalance(ROOT + OWNER_TAG, rootOwner.address, 1 * COIN);
    SetBalance(SECTION_A + OWNER_TAG, sectionOwner.address, 1 * COIN);

    std::string error;
    BOOST_CHECK_MESSAGE(HasDepinSectionOwnerAccess(rootOwner.address, ROOT, ROOT, error), error);
    BOOST_CHECK_MESSAGE(HasDepinSectionOwnerAccess(rootOwner.address, SECTION_A, ROOT, error), error);
    BOOST_CHECK_MESSAGE(HasDepinSectionOwnerAccess(rootOwner.address, SECTION_A_SUB, ROOT, error), error);

    BOOST_CHECK_MESSAGE(HasDepinSectionOwnerAccess(sectionOwner.address, SECTION_A, ROOT, error), error);
    BOOST_CHECK_MESSAGE(HasDepinSectionOwnerAccess(sectionOwner.address, SECTION_A_SUB, ROOT, error), error);
    BOOST_CHECK(!HasDepinSectionOwnerAccess(sectionOwner.address, ROOT, ROOT, error));
    BOOST_CHECK(!HasDepinSectionOwnerAccess(sectionOwner.address, SECTION_B, ROOT, error));
}

// ---------------------------------------------------------------------------
// Delivery and scope
// ---------------------------------------------------------------------------

// (9) THE central property: a root message encrypted only for the root holder
// is neither delivered to nor decryptable by the section holder; a section
// message addressed to both reaches and decrypts for both.
BOOST_AUTO_TEST_CASE(root_message_is_unreachable_for_section_holder)
{
    const Holder rootHolder = NewHolder(false);
    const Holder sectionHolder = NewHolder(false);
    const Holder sender = NewHolder(false);

    const CDepinMessage rootMsg =
        MakeEciesMessage(ROOT, sender, {rootHolder}, "root only");
    const CDepinMessage sectionMsg =
        MakeEciesMessage(SECTION_A, sender, {rootHolder, sectionHolder}, "section for both");

    const uint160 rootHash = Hash160Of(rootHolder.address);
    const uint160 sectionHash = Hash160Of(sectionHolder.address);

    // Delivery: the root message never reaches the section holder.
    BOOST_CHECK(ShouldDeliverDepinMessageToAddress(rootMsg, rootHolder.address, &rootHash));
    BOOST_CHECK(!ShouldDeliverDepinMessageToAddress(rootMsg, sectionHolder.address, &sectionHash));

    // The section message reaches both (the root sees its whole branch).
    BOOST_CHECK(ShouldDeliverDepinMessageToAddress(sectionMsg, rootHolder.address, &rootHash));
    BOOST_CHECK(ShouldDeliverDepinMessageToAddress(sectionMsg, sectionHolder.address, &sectionHash));

    // Cryptography agrees with delivery: the section holder cannot decrypt the
    // root message even given the bytes.
    std::string plaintext;
    BOOST_CHECK(!TryDecrypt(rootMsg, sectionHolder, plaintext));
    BOOST_REQUIRE(TryDecrypt(rootMsg, rootHolder, plaintext));
    BOOST_CHECK_EQUAL(plaintext, "root only");

    BOOST_REQUIRE(TryDecrypt(sectionMsg, sectionHolder, plaintext));
    BOOST_CHECK_EQUAL(plaintext, "section for both");
    BOOST_REQUIRE(TryDecrypt(sectionMsg, rootHolder, plaintext));
    BOOST_CHECK_EQUAL(plaintext, "section for both");
}

// (10) The scope separates tabs and runs BEFORE the sender shortcut: a
// sender's own message from another section must not leak into this tab.
BOOST_AUTO_TEST_CASE(scope_filter_separates_tabs_and_runs_before_sender_shortcut)
{
    const Holder holder = NewHolder(false);
    const Holder sender = NewHolder(false);

    std::vector<CDepinMessage> messages;
    messages.push_back(MakeEciesMessage(ROOT, sender, {holder}, "at root"));
    messages.push_back(MakeEciesMessage(SECTION_A, sender, {holder}, "in A"));
    messages.push_back(MakeEciesMessage(SECTION_B, sender, {holder}, "in B"));

    const uint160 holderHash = Hash160Of(holder.address);

    // Scope A shows only A's subtree.
    std::vector<CDepinMessage> scoped =
        FilterDepinMessagesForAddress(Pointers(messages), holder.address, &holderHash, SECTION_A);
    BOOST_REQUIRE_EQUAL(scoped.size(), 1U);
    BOOST_CHECK_EQUAL(scoped[0].token, SECTION_A);

    // Root scope shows the whole pool.
    scoped = FilterDepinMessagesForAddress(Pointers(messages), holder.address, &holderHash, ROOT);
    BOOST_CHECK_EQUAL(scoped.size(), 3U);

    // Sender shortcut ordering: the SENDER asking for tab A must not see their
    // own message from B. If the shortcut ran first, it would leak through.
    const uint160 senderHash = Hash160Of(sender.address);
    scoped = FilterDepinMessagesForAddress(Pointers(messages), sender.address, &senderHash, SECTION_A);
    BOOST_REQUIRE_EQUAL(scoped.size(), 1U);
    BOOST_CHECK_EQUAL(scoped[0].token, SECTION_A);
}

// (11) Empty scope is byte-compatible with the pre-sections behavior.
BOOST_AUTO_TEST_CASE(empty_scope_is_byte_compatible)
{
    const Holder holder = NewHolder(false);
    const Holder sender = NewHolder(false);

    std::vector<CDepinMessage> messages;
    messages.push_back(MakeEciesMessage(ROOT, sender, {holder}, "one"));
    messages.push_back(MakeEciesMessage(SECTION_A, sender, {holder}, "two"));

    const uint160 holderHash = Hash160Of(holder.address);

    const std::vector<CDepinMessage> unscoped =
        FilterDepinMessagesForAddress(Pointers(messages), holder.address, &holderHash);
    const std::vector<CDepinMessage> emptyScope =
        FilterDepinMessagesForAddress(Pointers(messages), holder.address, &holderHash, "");

    BOOST_REQUIRE_EQUAL(unscoped.size(), emptyScope.size());
    BOOST_CHECK_EQUAL(unscoped.size(), 2U);
    for (size_t i = 0; i < unscoped.size(); ++i) {
        BOOST_CHECK(unscoped[i].GetHash() == emptyScope[i].GetHash());
    }
}

// ---------------------------------------------------------------------------
// Pool write path
// ---------------------------------------------------------------------------

// (12) AddMessage is the authoritative write check: a section sender may
// publish in their section, never at the root (the old code checked ownership
// of activeToken, which also made section publishing impossible), never in a
// foreign token, and not while revoked.
BOOST_AUTO_TEST_CASE(pool_accepts_section_and_rejects_unauthorized)
{
    ScopedInitializedPool pool(ROOT);

    const Holder sectionSender = NewHolder(false);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(SECTION_A, sectionSender.address, 10);

    std::string error;

    // Section sender publishing in their section: accepted.
    CDepinMessage sectionMsg = MakeEciesMessage(SECTION_A, sectionSender, {audience}, "hello A");
    BOOST_CHECK_MESSAGE(pDepinMsgPool->AddMessage(sectionMsg, error, true), error);

    // The same sender at the ROOT: rejected -- inherited access flows down,
    // never up.
    CDepinMessage rootMsg = MakeEciesMessage(ROOT, sectionSender, {audience}, "hello root");
    error.clear();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(rootMsg, error, true));
    BOOST_CHECK_MESSAGE(error.find("no active balance") != std::string::npos, error);

    // A token outside the subtree: rejected by the subtree gate.
    CDepinMessage foreignMsg = MakeEciesMessage("&TESTING", sectionSender, {audience}, "wrong pool");
    error.clear();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(foreignMsg, error, true));
    BOOST_CHECK_MESSAGE(error.find("not active token") != std::string::npos, error);

    // Self-revoked in the only pair they hold: rejected. A balance check alone
    // would have let this through.
    SelfRevoke(SECTION_A, sectionSender.address);
    CDepinMessage revokedMsg = MakeEciesMessage(SECTION_A, sectionSender, {audience}, "after revoke");
    error.clear();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(revokedMsg, error, true));
}

// (13) Guard: accepting a message performs NO resolver flush. The authorization
// path reads through a local cache without flushing global state.
BOOST_AUTO_TEST_CASE(addmessage_does_not_flush)
{
    ScopedInitializedPool pool(ROOT);

    const Holder sender = NewHolder(false);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(ROOT, sender.address, 10);

    gDepinAncestorRecipientsStats.Reset();

    CDepinMessage msg = MakeEciesMessage(SECTION_A, sender, {audience}, "no flush");
    std::string error;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(msg, error, true), error);

    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
}

// (14) Hardening independent of sections: recipientKeys is a sender-chosen
// snapshot, so the count itself is capped, not only the byte size.
BOOST_AUTO_TEST_CASE(addmessage_caps_recipient_count)
{
    ScopedInitializedPool pool(ROOT, /* maxRecipients = */ 2);

    const Holder sender = NewHolder(false);
    SetBalance(ROOT, sender.address, 10);

    const Holder r1 = NewHolder(false);
    const Holder r2 = NewHolder(false);
    const Holder r3 = NewHolder(false);
    for (const Holder& h : {r1, r2, r3}) SetBalance(ROOT, h.address, 10);

    std::string error;

    CDepinMessage okMsg = MakeEciesMessage(ROOT, sender, {r1, r2}, "two is fine");
    BOOST_CHECK_MESSAGE(pDepinMsgPool->AddMessage(okMsg, error, true), error);

    CDepinMessage overMsg = MakeEciesMessage(ROOT, sender, {r1, r2, r3}, "three is too many");
    error.clear();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(overMsg, error, true));
    BOOST_CHECK_MESSAGE(error.find("recipients") != std::string::npos, error);
}

// (15) depinsubmitmsg accepts a section message end to end (envelope for the
// pool key, subtree gate, inherited-access pre-check, real signature), replies
// encrypted for the sender, and still rejects foreign tokens and the bare
// (unwrapped) form before anything else.
BOOST_AUTO_TEST_CASE(reject_malformed_ecies_locally_and_through_submit_rpc)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(SECTION_A, sender.address, 10);
    const CDepinMessage valid = MakeEciesMessage(SECTION_A, sender, {audience}, "valid ECIES");
    std::string error;

    // A valid outer privacy envelope and signature must not disguise a broken
    // inner ECIES structure. Truncate both its header and its final key entry.
    for (size_t length : {size_t(1), valid.encryptedPayload.size() - 1}) {
        CDepinMessage invalid = valid;
        invalid.encryptedPayload.resize(length);
        SignMessageWithKey(invalid, sender.key);
        BOOST_CHECK(!pDepinMsgPool->AddMessage(invalid, error));
        BOOST_CHECK(error.find("Invalid ECIES message payload") != std::string::npos);
        UniValue params(UniValue::VARR);
        params.push_back(WrapForPool(sender.address, invalid));
        try {
            CallDepinRPC("depinsubmitmsg", params);
            BOOST_FAIL("Malformed inner ECIES was admitted");
        } catch (const UniValue& rpcError) {
            BOOST_CHECK(rpcError["message"].get_str().find("Invalid ECIES message payload") != std::string::npos);
        }
        BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 0U);
    }

    CDepinMessage signedValid = valid;
    SignMessageWithKey(signedValid, sender.key);
    UniValue params(UniValue::VARR);
    params.push_back(WrapForPool(sender.address, signedValid));
    const UniValue reply = OpenResponse(CallDepinRPC("depinsubmitmsg", params), sender);
    BOOST_CHECK_EQUAL(reply["result"].get_str(), "success");
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
}

BOOST_AUTO_TEST_CASE(depinsubmitmsg_accepts_section)
{
    ScopedInitializedPool pool(ROOT);

    // The sender needs a REVEALED pubkey (signature verification reads the
    // index, and the reply is encrypted for it) and an active section balance.
    const Holder sender = NewHolder(true);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(SECTION_A, sender.address, 10);

    CDepinMessage msg = MakeEciesMessage(SECTION_A, sender, {audience}, "via rpc");
    SignMessageWithKey(msg, sender.key);

    UniValue params(UniValue::VARR);
    params.push_back(WrapForPool(sender.address, msg));

    const UniValue response = CallDepinRPC("depinsubmitmsg", params);
    const UniValue result = OpenResponse(response, sender);
    BOOST_CHECK_EQUAL(result["result"].get_str(), "success");
    BOOST_CHECK_EQUAL(result["hash"].get_str(), msg.GetHash().ToString());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);

    // The bare hex form no longer exists.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << msg;
    UniValue bareParams(UniValue::VARR);
    bareParams.push_back(HexStr(ss.begin(), ss.end()));
    BOOST_CHECK_THROW(CallDepinRPC("depinsubmitmsg", bareParams), UniValue);

    // An envelope whose sender is not the signer is refused.
    UniValue mismatched(UniValue::VARR);
    mismatched.push_back(WrapForPool(audience.address, msg));
    BOOST_CHECK_THROW(CallDepinRPC("depinsubmitmsg", mismatched), UniValue);

    // A foreign token is rejected up front with the subtree error.
    CDepinMessage foreign = MakeEciesMessage("&TESTING", sender, {audience}, "wrong");
    SignMessageWithKey(foreign, sender.key);
    UniValue foreignParams(UniValue::VARR);
    foreignParams.push_back(WrapForPool(sender.address, foreign));
    BOOST_CHECK_THROW(CallDepinRPC("depinsubmitmsg", foreignParams), UniValue);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
}

// (15c) Submissions are limited per sender and minute; other senders are
// unaffected.
BOOST_AUTO_TEST_CASE(depinsubmitmsg_is_rate_limited_per_sender)
{
    ScopedInitializedPool pool(ROOT);
    g_depinRateLimiter.SetLimit(2);

    const Holder sender = NewHolder(true);
    const Holder other = NewHolder(true);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(SECTION_A, sender.address, 10);
    SetBalance(SECTION_A, other.address, 10);

    auto submit = [&](const Holder& from, const std::string& text) {
        CDepinMessage msg = MakeEciesMessage(SECTION_A, from, {audience}, text);
        SignMessageWithKey(msg, from.key);
        UniValue params(UniValue::VARR);
        params.push_back(WrapForPool(from.address, msg));
        return CallDepinRPC("depinsubmitmsg", params);
    };
    submit(sender, "uno");
    submit(sender, "dos");
    BOOST_CHECK_THROW(submit(sender, "tres"), UniValue);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 2U);
    submit(other, "otro");
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 3U);
}

// (15d) The quota belongs to whoever can actually sign for the address.
// Anyone can build an envelope for the pool key that names a victim as
// sender, so a submission that fails verification -- wrong signature, or a
// signer without access -- must not count against the address it names.
BOOST_AUTO_TEST_CASE(depinsubmitmsg_invalid_signature_does_not_consume_sender_quota)
{
    ScopedInitializedPool pool(ROOT);
    g_depinRateLimiter.SetLimit(2);

    const Holder victim = NewHolder(true);
    const Holder attacker = NewHolder(true);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(SECTION_A, victim.address, 10);

    auto submit = [&](const Holder& from, const CKey& signWith, const std::string& text) {
        CDepinMessage msg = MakeEciesMessage(SECTION_A, from, {audience}, text);
        SignMessageWithKey(msg, signWith);
        UniValue params(UniValue::VARR);
        params.push_back(WrapForPool(from.address, msg));
        return CallDepinRPC("depinsubmitmsg", params);
    };
    auto errorCode = [&](const Holder& from, const CKey& signWith, const std::string& text) {
        try {
            submit(from, signWith, text);
        } catch (const UniValue& e) {
            return find_value(e, "code").get_int();
        }
        return 0;
    };

    // Forged in the victim's name, signed by the attacker: refused on the
    // signature, never on the rate limit.
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK_EQUAL(errorCode(victim, attacker.key, "forged"), RPC_VERIFY_ERROR);
    }
    // Properly signed by an address with no access: refused on access.
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK_EQUAL(errorCode(attacker, attacker.key, "stranger"), RPC_VERIFY_ERROR);
    }
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 0U);

    // The victim's quota is intact: the limit's worth of real messages is
    // accepted, and only then does the limiter bite.
    submit(victim, victim.key, "uno");
    submit(victim, victim.key, "dos");
    BOOST_CHECK_EQUAL(errorCode(victim, victim.key, "tres"), RPC_MISC_ERROR);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 2U);
}

// (15b) A sender without a revealed public key is refused with
// RPC_INVALID_ADDRESS_OR_KEY before anything is stored: the reply would have
// nothing to be encrypted for, and no plaintext fallback exists. Valid
// message, valid signature, valid envelope -- only the key is missing.
BOOST_AUTO_TEST_CASE(depinsubmitmsg_requires_revealed_sender_key)
{
    ScopedInitializedPool pool(ROOT);

    const Holder sender = NewHolder(false);
    const Holder audience = NewHolder(false);
    SetBalance(ROOT, audience.address, 10);
    SetBalance(SECTION_A, sender.address, 10);

    CDepinMessage msg = MakeEciesMessage(SECTION_A, sender, {audience}, "sin clave");
    SignMessageWithKey(msg, sender.key);
    UniValue params(UniValue::VARR);
    params.push_back(WrapForPool(sender.address, msg));

    int code = 0;
    try {
        CallDepinRPC("depinsubmitmsg", params);
    } catch (const UniValue& e) {
        code = find_value(e, "code").get_int();
    }
    BOOST_CHECK_EQUAL(code, RPC_INVALID_ADDRESS_OR_KEY);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 0U);
}

// ---------------------------------------------------------------------------
// Sections snapshot and what must NOT be cached
// ---------------------------------------------------------------------------

// (16) The section list is cached per tip (a same-tip change to the asset DB
// is deliberately not visible until the tip moves -- that is what "snapshot"
// means), while authorization is NEVER cached: a restriction written now is
// enforced now.
BOOST_AUTO_TEST_CASE(sections_cached_per_tip_and_authorization_uncached)
{
    ScopedInitializedPool pool(ROOT);
    BOOST_REQUIRE(chainActive.Tip() != nullptr);

    CreateAsset(ROOT);
    CreateAsset(SECTION_A);

    std::vector<std::string> sections;
    std::string error;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->GetSections(sections, error), error);
    const std::vector<std::string> expected = {ROOT, SECTION_A};
    BOOST_CHECK_EQUAL_COLLECTIONS(sections.begin(), sections.end(),
                                  expected.begin(), expected.end());

    // New section in the DB but the tip has not moved: the snapshot answers.
    CreateAsset(SECTION_B);
    BOOST_REQUIRE(pDepinMsgPool->GetSections(sections, error));
    BOOST_CHECK_EQUAL_COLLECTIONS(sections.begin(), sections.end(),
                                  expected.begin(), expected.end());

    // Authorization, by contrast, reflects a restriction IMMEDIATELY -- caching
    // it would let a just-frozen holder keep publishing until the next block.
    const Holder holder = NewHolder(false);
    SetBalance(SECTION_A, holder.address, 10);
    BOOST_REQUIRE_MESSAGE(HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error), error);
    SelfRevoke(SECTION_A, holder.address);
    BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
}

// (18) A pool with maxRecipients == 0 can never carry a message (the payload
// cap multiplies by it, the recipientKeys count check rejects >= 1), so
// Initialize() must refuse it instead of booting a pool that silently drops
// everything -- which is also what lets every consumer drop its 0-fallback.
BOOST_AUTO_TEST_CASE(pool_initialize_rejects_zero_max_recipients)
{
    CDepinMsgPool pool;
    BOOST_CHECK(!pool.Initialize(ROOT, /*maxRecipients=*/0,
                                 DEFAULT_DEPIN_MESSAGE_SIZE,
                                 DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                 DEFAULT_DEPIN_POOL_SIZE_MB));
    BOOST_CHECK(!pool.IsEnabled());

    // The boundary value is fine.
    CDepinMsgPool poolOne;
    BOOST_CHECK(poolOne.Initialize(ROOT, /*maxRecipients=*/1,
                                   DEFAULT_DEPIN_MESSAGE_SIZE,
                                   DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                   DEFAULT_DEPIN_POOL_SIZE_MB));
    BOOST_CHECK_EQUAL(poolOne.GetMaxRecipients(), 1U);
}

// (17) The remote-send leak scenario, at the resolver level: a pool serves
// "&TEST/GENERAL" and a message goes to "&TEST/GENERAL/SUB". The "&TEST"
// holder is OUTSIDE that pool; with stopAt = pool root it must NOT be in the
// recipient set, while absolute-root derivation (what a remote send used
// before querying INFO) would include it -- and every recipientKeys entry is a
// reader, because the pool's port exposes raw payloads.
BOOST_AUTO_TEST_CASE(branch_resolution_stops_at_pool_root)
{
    CreateAsset(ROOT);
    CreateAsset(SECTION_A);
    CreateAsset(SECTION_A_SUB);

    const Holder rootHolder = NewHolder();      // pubkeys revealed: the resolver
    const Holder sectionHolder = NewHolder();   // filters key-less holders out
    const Holder leafHolder = NewHolder();

    SetBalance(ROOT, rootHolder.address, 1);
    SetBalance(SECTION_A, sectionHolder.address, 1);
    SetBalance(SECTION_A_SUB, leafHolder.address, 1);

    auto contains = [](const CDepinAncestorRecipients& result, const std::string& address) {
        for (const CDepinRecipient& recipient : result.recipients) {
            if (recipient.address == address) return true;
        }
        return false;
    };

    // Scoped to the pool root: exactly the pool's audience.
    CDepinAncestorRecipients scoped;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(SECTION_A_SUB, 50, scoped, error, SECTION_A),
                          error);
    const std::vector<std::string> expectedAncestors = {SECTION_A_SUB, SECTION_A};
    BOOST_CHECK_EQUAL_COLLECTIONS(scoped.ancestors.begin(), scoped.ancestors.end(),
                                  expectedAncestors.begin(), expectedAncestors.end());
    BOOST_CHECK(contains(scoped, leafHolder.address));
    BOOST_CHECK(contains(scoped, sectionHolder.address));
    BOOST_CHECK(!contains(scoped, rootHolder.address));

    // Absolute root: the difference IS the leak the stopAt closes.
    CDepinAncestorRecipients absolute;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(SECTION_A_SUB, 50, absolute, error, ""), error);
    BOOST_CHECK(contains(absolute, rootHolder.address));
}

BOOST_AUTO_TEST_CASE(new_messages_require_enabled_recipients_and_allow_private_subsets)
{
    ScopedInitializedPool pool(ROOT);
    CreateAsset(ROOT);
    CreateAsset(SECTION_A);
    const Holder sender = NewHolder(true);
    const Holder receiver = NewHolder(true);
    const Holder stranger = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    SetBalance(SECTION_A, receiver.address, 10);
    SetBalance(SECTION_B, stranger.address, 10);
    std::string error, plaintext;
    CDepinMessage good = MakeEciesMessage(SECTION_A, sender, {receiver}, "private subset");
    good.messageType = 0x01;
    SignMessageWithKey(good, sender.key);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(good, error), error);
    BOOST_REQUIRE(TryDecrypt(good, receiver, plaintext));
    BOOST_CHECK_EQUAL(plaintext, "private subset");
    Holder poolHolder;
    poolHolder.key = poolKey;
    poolHolder.pubkey = poolKey.GetPubKey();
    poolHolder.address = EncodeDestination(poolHolder.pubkey.GetID());
    BOOST_CHECK(!TryDecrypt(good, poolHolder, plaintext));

    CDepinMessage bad = MakeEciesMessage(SECTION_A, sender, {receiver, stranger}, "sibling is not eligible");
    SignMessageWithKey(bad, sender.key);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(bad, error));
    BOOST_CHECK(error.find("Recipient not authorized") != std::string::npos);
    UniValue params(UniValue::VARR);
    params.push_back(WrapForPool(sender.address, bad));
    try {
        CallDepinRPC("depinsubmitmsg", params);
        BOOST_FAIL("Unauthorized recipient admitted through RPC");
    } catch (const UniValue& rpcError) {
        BOOST_CHECK_EQUAL(rpcError["code"].get_int(), RPC_VERIFY_REJECTED);
        BOOST_CHECK(rpcError["message"].get_str().find("Recipient not authorized:") != std::string::npos);
    }
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
    CDepinAncestorRecipients beforeFreeze;
    BOOST_REQUIRE(GetDepinAncestorRecipients(SECTION_A, 20, beforeFreeze, error, ROOT));
    BOOST_CHECK(std::any_of(beforeFreeze.recipients.begin(), beforeFreeze.recipients.end(),
        [&](const CDepinRecipient& r) { return r.address == receiver.address; }));
    // A once-valid directory/ciphertext must fail admission after revocation.
    FreezeAddress(SECTION_A, receiver.address);
    bad = MakeEciesMessage(SECTION_A, sender, {receiver}, "frozen recipient");
    SignMessageWithKey(bad, sender.key);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(bad, error));
    SetBalance(ROOT, receiver.address, 10); // Active ancestor still grants access.
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(bad, error), error);
    SelfRevoke(ROOT, receiver.address); // No remaining active ancestor.
    bad = MakeEciesMessage(SECTION_A, sender, {receiver}, "self-revoked recipient");
    SignMessageWithKey(bad, sender.key);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(bad, error));
    BOOST_CHECK(error.find("Recipient not authorized:") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(cache_permissions_override_disk_without_growing_global_balances)
{
    const Holder holder = NewHolder(true);
    SetBalance(SECTION_A, holder.address, 10);
    SetBalance(ROOT + OWNER_TAG, holder.address, COIN);
    LOCK(cs_main);
    const size_t oldSize = passets->mapAssetsAddressAmount.size();
    const uint64_t oldFlushes = nFullStateFlushes.load();
    std::string error;
    BOOST_REQUIRE(HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
    BOOST_CHECK_EQUAL(passets->mapAssetsAddressAmount.size(), oldSize);
    const auto pair = std::make_pair(SECTION_A, holder.address);
    passets->mapAssetsAddressAmount[pair] = 0;
    BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
    passets->mapAssetsAddressAmount.erase(pair);
    BOOST_CHECK(HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
    passets->setNewRestrictedAddressToAdd.insert(CAssetCacheRestrictedAddress(
        SECTION_A, holder.address, RestrictedType::FREEZE_ADDRESS));
    BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
    passets->setNewRestrictedAddressToAdd.clear();
    SelfRevoke(SECTION_A, holder.address);
    BOOST_CHECK(!HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
    passets->setNewSelfRestrictionToAdd.insert(CAssetCacheSelfRestriction(SECTION_A, holder.address, false));
    BOOST_CHECK(HasDepinSectionAccess(holder.address, SECTION_A, ROOT, error));
    passets->mapAssetsAddressAmount[std::make_pair(ROOT + OWNER_TAG, holder.address)] = 0;
    BOOST_CHECK(!HasDepinSectionOwnerAccess(holder.address, SECTION_A, ROOT, error));
    passets->mapAssetsAddressAmount.clear();
    BOOST_CHECK(HasDepinSectionOwnerAccess(holder.address, SECTION_A, ROOT, error));
    BOOST_CHECK_EQUAL(nFullStateFlushes.load(), oldFlushes);
}

BOOST_AUTO_TEST_CASE(restoration_keeps_history_after_sender_and_recipient_revoke)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    const Holder revoked = NewHolder(true);
    const Holder remaining = NewHolder(true);
    for (const Holder& h : {sender, revoked, remaining}) SetBalance(SECTION_A, h.address, 10);
    CDepinMessage msg = MakeEciesMessage(SECTION_A, sender, {revoked, remaining}, "historical message");
    SignMessageWithKey(msg, sender.key);
    std::string error, plaintext;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(msg, error), error);
    BOOST_REQUIRE(pDepinMsgPool->SaveToDisk());
    pDepinMsgPool->Clear();
    FreezeAddress(SECTION_A, revoked.address);
    SelfRevoke(SECTION_A, sender.address);
    BOOST_REQUIRE(pDepinMsgPool->LoadFromDisk());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
    const auto history = pDepinMsgPool->GetMessagesForAddress(remaining.address, SECTION_A);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_REQUIRE(TryDecrypt(history[0], remaining, plaintext));
    BOOST_CHECK_EQUAL(plaintext, "historical message");
    BOOST_CHECK(!HasDepinSectionAccess(revoked.address, SECTION_A, ROOT, error));
    BOOST_CHECK(!pDepinMsgPool->AddMessage(msg, error)); // No public restoration bypass.

    // Restoration still verifies signatures, even though it ignores membership.
    pDepinMsgPool->Clear();
    CDepinMessage unsignedMessage = MakeEciesMessage(SECTION_A, remaining, {remaining}, "bad signature");
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(unsignedMessage, error, true));
    BOOST_REQUIRE(pDepinMsgPool->SaveToDisk());
    pDepinMsgPool->Clear();
    BOOST_REQUIRE(pDepinMsgPool->LoadFromDisk());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 0U);

    // A valid signature cannot make an invalid section name restorable.
    CDepinMessage invalidName = msg;
    invalidName.token = ROOT + "/X";
    SignMessageWithKey(invalidName, sender.key);
    CDataStream disk(SER_DISK, CLIENT_VERSION);
    disk << DEPINPOOL_MAGIC_BYTES << DEPINPOOL_FILE_VERSION << GetTime() << uint64_t(1) << invalidName;
    {
        std::ofstream file((GetDataDir() / "depinpool.dat").string(), std::ios::binary);
        file.write(disk.data(), disk.size());
        BOOST_REQUIRE(file.good());
    }
    BOOST_REQUIRE(pDepinMsgPool->LoadFromDisk());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 0U);
}

BOOST_AUTO_TEST_CASE(directory_merges_pending_balances_and_restrictions_without_flush)
{
    CreateAsset(ROOT);
    const Holder oldHolder = NewHolder(true);
    const Holder newHolder = NewHolder(true);
    SetBalance(ROOT, oldHolder.address, 10);
    LOCK(cs_main);
    passets->mapAssetsAddressAmount[std::make_pair(ROOT, oldHolder.address)] = 0;
    passets->mapAssetsAddressAmount[std::make_pair(ROOT, newHolder.address)] = 10;
    const size_t size = passets->mapAssetsAddressAmount.size();
    const uint64_t flushes = nFullStateFlushes.load();
    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(ROOT, 20, result, error, ROOT), error);
    BOOST_REQUIRE_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK_EQUAL(result.recipients[0].address, newHolder.address);
    passets->setNewRestrictedAddressToAdd.insert(CAssetCacheRestrictedAddress(
        ROOT, newHolder.address, RestrictedType::FREEZE_ADDRESS));
    BOOST_REQUIRE(GetDepinAncestorRecipients(ROOT, 20, result, error, ROOT));
    BOOST_CHECK(result.recipients.empty());
    BOOST_CHECK_EQUAL(passets->mapAssetsAddressAmount.size(), size);
    BOOST_CHECK_EQUAL(nFullStateFlushes.load(), flushes);
}

BOOST_AUTO_TEST_CASE(section_directory_merges_tip_metadata_without_flush)
{
    ScopedInitializedPool pool(ROOT);
    CreateAsset(SECTION_A);
    LOCK(cs_main);
    CNewAsset removed(SECTION_A, 10, DEPIN_ASSET_UNITS, 0, 0, "");
    CNewAsset added(SECTION_B, 10, DEPIN_ASSET_UNITS, 0, 0, "");
    passets->setNewAssetsToRemove.insert(CAssetCacheNewAsset(removed, "", 1, uint256()));
    passets->setNewAssetsToAdd.insert(CAssetCacheNewAsset(added, "", 2, uint256()));
    const uint64_t flushes = nFullStateFlushes.load();
    std::vector<std::string> sections;
    std::string error;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->GetSections(sections, error), error);
    BOOST_REQUIRE_EQUAL(sections.size(), 2U);
    BOOST_CHECK_EQUAL(sections[0], ROOT);
    BOOST_CHECK_EQUAL(sections[1], SECTION_B);
    BOOST_CHECK_EQUAL(nFullStateFlushes.load(), flushes);
}

BOOST_AUTO_TEST_CASE(admission_cost_and_concurrent_pool_readers)
{
    for (unsigned int count : {20U, 50U}) {
        for (int depth : {1, 4, 12}) {
            ScopedInitializedPool pool(ROOT, count);
            std::string token = ROOT;
            CreateAsset(token);
            for (int level = 1; level < depth; ++level) {
                token += "/SUB";
                CreateAsset(token);
            }
            const Holder sender = NewHolder(true);
            SetBalance(ROOT, sender.address, 10);
            std::vector<Holder> audience;
            for (unsigned int i = 0; i < count; ++i) {
                const Holder receiver = NewHolder(true);
                SetBalance(ROOT, receiver.address, 10);
                audience.push_back(receiver);
            }
            const uint64_t oldFlushes = nFullStateFlushes.load();
            gDepinAdmissionStats.Reset();
            std::atomic<bool> stop{false};
            std::atomic<uint64_t> reads{0}, maxReadMicros{0};
            std::thread reader([&] {
                while (!stop.load()) {
                    const int64_t start = GetTimeMicros();
                    pDepinMsgPool->GetAllMessages();
                    const uint64_t elapsed = GetTimeMicros() - start;
                    uint64_t previous = maxReadMicros.load();
                    while (previous < elapsed && !maxReadMicros.compare_exchange_weak(previous, elapsed)) {}
                    reads++;
                    std::this_thread::yield();
                }
            });
            while (reads.load() == 0) std::this_thread::yield();
            bool accepted = true;
            std::string error;
            const int iterations = 8;
            const int64_t start = GetTimeMicros();
            for (int i = 0; i < iterations; ++i) {
                CDepinMessage msg = MakeEciesMessage(token, sender, audience, "admission benchmark");
                SignMessageWithKey(msg, sender.key);
                if (!pDepinMsgPool->AddMessage(msg, error)) {
                    accepted = false;
                    break;
                }
            }
            const int64_t total = GetTimeMicros() - start;
            stop = true;
            reader.join();
            BOOST_REQUIRE_MESSAGE(accepted, error);
            BOOST_CHECK_EQUAL(gDepinAdmissionStats.admitted.load(), iterations);
            BOOST_CHECK_EQUAL(gDepinAdmissionStats.balanceQueries.load(), uint64_t(iterations) * (count + 1) * depth);
            BOOST_CHECK_EQUAL(nFullStateFlushes.load(), oldFlushes);
            BOOST_TEST_MESSAGE("DEPIN_BENCH recipients=" << count << " depth=" << depth
                << " iterations=" << iterations << " total_us=" << total
                << " permission_us=" << gDepinAdmissionStats.permissionMicros.load()
                << " pool_hold_us=" << gDepinAdmissionStats.poolHoldMicros.load()
                << " pool_wait_us=" << gDepinAdmissionStats.poolWaitMicros.load()
                << " reader_max_us=" << maxReadMicros.load() << " reads=" << reads.load());
        }
    }
}

BOOST_AUTO_TEST_CASE(sequence_pages_survive_anchor_deletion_and_late_timestamps)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true), receiver = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    SetBalance(ROOT, receiver.address, 10);
    std::string error;
    CDepinMessage first = MakeEciesMessage(ROOT, sender, {receiver}, "first");
    SignMessageWithKey(first, sender.key);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(first, error));
    const auto stream = pDepinMsgPool->GetStreamId();
    CDepinSequencePage page;
    BOOST_REQUIRE(pDepinMsgPool->GetSequencePage(receiver.address, ROOT, stream, 0, 1, 0, page, error));
    BOOST_CHECK_EQUAL(page.after, 1U);
    BOOST_CHECK(!page.hasMore);
    size_t removed = 0;
    BOOST_REQUIRE(pDepinMsgPool->Purge(ROOT, GetTime(), true, 0, removed, error));
    BOOST_CHECK_EQUAL(removed, 1U);
    CDepinMessage late = MakeEciesMessage(ROOT, sender, {receiver}, "late clock");
    late.timestamp -= 60;
    SignMessageWithKey(late, sender.key);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(late, error));
    BOOST_REQUIRE(pDepinMsgPool->GetSequencePage(receiver.address, ROOT, stream, page.after, 1, 0, page, error));
    BOOST_REQUIRE_EQUAL(page.messages.size(), 1U);
    BOOST_CHECK(page.messages[0].message.GetHash() == late.GetHash());
    BOOST_CHECK_EQUAL(page.messages[0].sequence, 2U);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(first, error));
    BOOST_CHECK(error.find("administratively deleted") != std::string::npos);
    BOOST_CHECK(!pDepinMsgPool->GetSequencePage(receiver.address, ROOT, GetRandHash(), 0, 1, 0, page, error));
    BOOST_CHECK(!pDepinMsgPool->GetSequencePage(receiver.address, ROOT, stream, 3, 1, 0, page, error));
}

BOOST_AUTO_TEST_CASE(durable_sequences_and_marks_with_message_persistence_toggle)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true), receiver = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    SetBalance(ROOT, receiver.address, 10);
    std::string error;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
    CDepinMessage first = MakeEciesMessage(ROOT, sender, {receiver}, "retained first");
    CDepinMessage second = MakeEciesMessage(ROOT, sender, {receiver}, "retained second");
    SignMessageWithKey(first, sender.key);
    SignMessageWithKey(second, sender.key);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(first, error));
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(second, error));
    const auto stream = pDepinMsgPool->GetStreamId();
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error)); // crash-safe admission, no shutdown save
    BOOST_CHECK(pDepinMsgPool->GetStreamId() == stream);
    CDepinSequencePage page;
    BOOST_REQUIRE(pDepinMsgPool->GetSequencePage(receiver.address, ROOT, stream, 1, 1, 0, page, error));
    BOOST_REQUIRE_EQUAL(page.messages.size(), 1U);
    BOOST_CHECK(page.messages[0].message.GetHash() == second.GetHash());
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    const auto volatileStream = pDepinMsgPool->GetStreamId();
    BOOST_CHECK(volatileStream != stream);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(first, error));
    size_t removed = 0;
    BOOST_REQUIRE(pDepinMsgPool->Purge(ROOT, GetTime(), true, 0, removed, error));
    BOOST_CHECK_EQUAL(removed, 2U); // includes the inactive retained checkpoint
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    BOOST_CHECK(pDepinMsgPool->GetStreamId() != volatileStream);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetTombstoneCount(), 2U);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(first, error));
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    BOOST_CHECK(pDepinMsgPool->GetStreamId() != stream);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(second, error));
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetHighWater(), 2U);
}

BOOST_AUTO_TEST_CASE(tombstone_capacity_and_expiry_never_silently_drop_live_marks)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true), receiver = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    SetBalance(ROOT, receiver.address, 10);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error, 1));
    CDepinMessage first = MakeEciesMessage(ROOT, sender, {receiver}, "capacity first");
    CDepinMessage second = MakeEciesMessage(ROOT, sender, {receiver}, "capacity second");
    SignMessageWithKey(first, sender.key);
    SignMessageWithKey(second, sender.key);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(first, error));
    size_t removed = 0;
    BOOST_REQUIRE(pDepinMsgPool->Purge(ROOT, GetTime(), true, 0, removed, error));
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(second, error));
    BOOST_CHECK(!pDepinMsgPool->Purge(ROOT, GetTime(), true, 0, removed, error));
    BOOST_CHECK_EQUAL(removed, 0U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U);
    BOOST_CHECK(pDepinMsgPool->StorageHealthy()); // capacity exhaustion is recoverable
    BOOST_CHECK(!pDepinMsgPool->AddMessage(first, error));
    SetMockTime(GetTime() + int64_t(MAX_DEPIN_MESSAGE_EXPIRY_HOURS) * 3600);
    RefreshDepinTestTipTime();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(first, error));
    SetMockTime(GetTime() + 1);
    RefreshDepinTestTipTime();
    BOOST_REQUIRE(pDepinMsgPool->Purge(ROOT, GetTime(), false, pDepinMsgPool->GetMessageExpiryTime(), removed, error));
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetTombstoneCount(), 0U);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(first, error)); // date now rejects it, not its old mark
    SetMockTime(0);
    RefreshDepinTestTipTime();
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    BOOST_CHECK(!pDepinMsgPool->AddMessage(first, error)); // no replay after the wall clock rolls back
}

BOOST_AUTO_TEST_CASE(durable_purge_respects_scope_age_and_inactive_checkpoint)
{
    ScopedInitializedPool pool(ROOT);
    const auto now = GetTime();
    SetMockTime(now);
    const Holder sender = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    std::vector<CDepinMessage> messages;
    const std::vector<std::pair<std::string, int64_t>> samples{
        {ROOT, now - 7201}, {SECTION_A, now - 3601}, {SECTION_A, now - 3600},
        {SECTION_A, now + 1}, {SECTION_B, now - 7201}};
    for (const auto& sample : samples) {
        auto message = MakeEciesMessage(sample.first, sender, {sender}, "scope/age");
        message.timestamp = sample.second;
        SignMessageWithKey(message, sender.key);
        BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(message, error), error);
        messages.push_back(message);
    }
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    size_t removed = 0;
    BOOST_REQUIRE(pDepinMsgPool->Purge(SECTION_A, now, false, 3600, removed, error));
    BOOST_CHECK_EQUAL(removed, 1U); // strictly older: equality survives
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 4U);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(messages[1], error));
    BOOST_REQUIRE(pDepinMsgPool->Purge(SECTION_A, now, false, 0, removed, error));
    BOOST_CHECK_EQUAL(removed, 1U); // 0 hours is not "all": future survives
    BOOST_REQUIRE(pDepinMsgPool->Purge(SECTION_A, now, true, 0, removed, error));
    BOOST_CHECK_EQUAL(removed, 1U);
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 2U); // parent and sibling untouched
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetHighWater(), 5U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetTombstoneCount(), 3U);
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(v1_migration_preserves_original_and_rejects_truncation)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    CDepinMessage message = MakeEciesMessage(ROOT, sender, {sender}, "legacy");
    SignMessageWithKey(message, sender.key);
    CDataStream data(SER_DISK, CLIENT_VERSION);
    data << DEPINPOOL_MAGIC_BYTES << uint32_t(1) << GetTime() << uint64_t(1) << message;
    const auto path = GetDataDir() / "depinpool.dat";
    {
        std::ofstream file(path.string(), std::ios::binary);
        file.write(data.data(), data.size() - 1);
    }
    std::string error;
    BOOST_CHECK(!pDepinMsgPool->InitializeStorage(true, error));
    BOOST_CHECK(!pDepinMsgPool->StorageHealthy());
    BOOST_CHECK_EQUAL(fs::file_size(path), data.size() - 1);
    {
        std::ofstream file(path.string(), std::ios::binary);
        file.write(data.data(), data.size());
    }
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U); // historical sender no longer needs holdings
    BOOST_CHECK(fs::exists(path.string() + ".v1.bak"));
    BOOST_CHECK_EQUAL(fs::file_size(path), data.size());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetHighWater(), 1U);
}

BOOST_AUTO_TEST_CASE(legacy_import_can_be_enabled_after_a_volatile_start)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    auto message = MakeEciesMessage(ROOT, sender, {sender}, "deferred migration");
    SignMessageWithKey(message, sender.key);
    CDataStream data(SER_DISK, CLIENT_VERSION);
    data << DEPINPOOL_MAGIC_BYTES << uint32_t(1) << GetTime() << uint64_t(1) << message;
    {
        std::ofstream file((GetDataDir() / "depinpool.dat").string(), std::ios::binary);
        file.write(data.data(), data.size());
    }
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 1U);
    // Saved verification metadata remains valid if the chain loses key reveal.
    CDestinationIndexData addressData;
    BOOST_REQUIRE(GetDestinationIndexData(DecodeDestination(sender.address), addressData));
    BOOST_REQUIRE(pblocktree->ErasePubKeyIndex({CPubKeyIndexKey(addressData)}));
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U);
}

BOOST_AUTO_TEST_CASE(legacy_complete_invalid_records_are_skipped_but_bad_framing_is_fatal)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    auto valid = MakeEciesMessage(ROOT, sender, {sender}, "valid after invalid");
    SignMessageWithKey(valid, sender.key);
    auto invalid = valid;
    // Larger than the new wire limit but inside the old payload bound. Its
    // record is complete, so the migration must still find the next message.
    invalid.encryptedPayload.resize(MAX_DEPIN_MESSAGE_WIRE_BYTES + 1);
    CDataStream records(SER_DISK, CLIENT_VERSION);
    records << invalid << valid;
    auto write = [&](uint32_t magic, uint32_t version, bool trailing) {
        CDataStream data(SER_DISK, CLIENT_VERSION);
        data << magic << version << GetTime() << uint64_t(2);
        data.write(records.data(), records.size());
        if (trailing) data << uint8_t(42);
        std::ofstream file((GetDataDir() / "depinpool.dat").string(), std::ios::binary);
        file.write(data.data(), data.size());
    };
    std::string error;
    write(0, 1, false);
    BOOST_CHECK(!pDepinMsgPool->InitializeStorage(true, error));
    write(DEPINPOOL_MAGIC_BYTES, 99, false);
    BOOST_CHECK(!pDepinMsgPool->InitializeStorage(true, error));
    write(DEPINPOOL_MAGIC_BYTES, 1, true);
    BOOST_CHECK(!pDepinMsgPool->InitializeStorage(true, error));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
    write(DEPINPOOL_MAGIC_BYTES, 1, false);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 1U);
    BOOST_CHECK(pDepinMsgPool->GetAllMessages()[0].GetHash() == valid.GetHash());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetHighWater(), 1U);
}

BOOST_AUTO_TEST_CASE(corrupt_tombstone_fails_closed_without_erasing_evidence)
{
    ScopedInitializedPool pool(ROOT);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    const uint256 hash = GetRandHash();
    CHashWriter directory(SER_GETHASH, 0);
    directory << ROOT;
    const auto path = GetDataDir() / "depinstate-v2" / directory.GetHash().ToString();
    pDepinMsgPool.reset();
    {
        CDBWrapper db(path, 1 << 20);
        BOOST_REQUIRE(db.Write(std::make_pair('T', hash), std::vector<unsigned char>{1}, true));
    }
    pDepinMsgPool.reset(new CDepinMsgPool());
    BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE, DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS, DEFAULT_DEPIN_POOL_SIZE_MB));
    BOOST_CHECK(!pDepinMsgPool->InitializeStorage(false, error));
    BOOST_CHECK(error.find("corrupt tombstone") != std::string::npos);
    BOOST_CHECK(!pDepinMsgPool->StorageHealthy());
    pDepinMsgPool.reset();
    {
        CDBWrapper db(path, 1 << 20);
        BOOST_CHECK(db.Exists(std::make_pair('T', hash)));
    }
}

BOOST_AUTO_TEST_CASE(critical_metadata_and_sequence_exhaustion_fail_explicitly)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    const auto stream = pDepinMsgPool->GetStreamId();
    CHashWriter directory(SER_GETHASH, 0);
    directory << ROOT;
    const auto path = GetDataDir() / "depinstate-v2" / directory.GetHash().ToString();
    pDepinMsgPool.reset();
    for (int scenario = 0; scenario < 4; ++scenario) {
        StateMetaFixture meta;
        meta.stream = stream;
        if (scenario == 0) meta.version = 99;
        if (scenario == 1) meta.high = std::numeric_limits<uint64_t>::max();
        if (scenario == 2) meta.floor = -1;
        if (scenario == 3) meta.high = std::numeric_limits<int64_t>::max();
        {
            CDBWrapper db(path, 1 << 20);
            BOOST_REQUIRE(db.Write('V', meta, true));
        }
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE, DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS, DEFAULT_DEPIN_POOL_SIZE_MB));
        if (scenario < 3) {
            BOOST_CHECK(!pDepinMsgPool->InitializeStorage(true, error));
            BOOST_CHECK(!pDepinMsgPool->StorageHealthy());
        } else {
            BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
            auto message = MakeEciesMessage(ROOT, sender, {sender}, "exhausted sequence");
            SignMessageWithKey(message, sender.key);
            BOOST_CHECK(!pDepinMsgPool->AddMessage(message, error));
            BOOST_CHECK(error.find("exhausted") != std::string::npos);
            BOOST_CHECK_EQUAL(pDepinMsgPool->GetHighWater(), uint64_t(std::numeric_limits<int64_t>::max()));
        }
        pDepinMsgPool.reset();
    }
}

BOOST_AUTO_TEST_CASE(complete_invalid_v2_record_is_quarantined_and_rotates_stream)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    auto first = MakeEciesMessage(ROOT, sender, {sender}, "invalidated record");
    auto second = MakeEciesMessage(ROOT, sender, {sender}, "valid record");
    SignMessageWithKey(first, sender.key);
    SignMessageWithKey(second, sender.key);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(first, error));
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(second, error));
    const auto stream = pDepinMsgPool->GetStreamId();
    CHashWriter directory(SER_GETHASH, 0);
    directory << ROOT;
    const auto path = GetDataDir() / "depinstate-v2" / directory.GetHash().ToString();
    pDepinMsgPool.reset();
    {
        CDBWrapper db(path, 1 << 20);
        BOOST_REQUIRE(db.Write(std::make_pair('M', first.GetHash()), StateRecordFixture{1, {1}}, true));
    }
    pDepinMsgPool.reset(new CDepinMsgPool());
    BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE, DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS, DEFAULT_DEPIN_POOL_SIZE_MB));
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(true, error), error);
    BOOST_CHECK(pDepinMsgPool->GetStreamId() != stream);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetHighWater(), 2U);
    CDepinSequencePage page;
    BOOST_CHECK(!pDepinMsgPool->GetSequencePage(sender.address, ROOT, stream, 0, 10, 0, page, error));
    BOOST_REQUIRE(pDepinMsgPool->GetSequencePage(sender.address, ROOT, pDepinMsgPool->GetStreamId(), 0, 10, 0, page, error));
    BOOST_CHECK_EQUAL(page.messages[0].sequence, 2U);
    pDepinMsgPool.reset();
    {
        CDBWrapper db(path, 1 << 20);
        BOOST_CHECK(db.Exists(std::make_pair('Q', first.GetHash())));
        BOOST_CHECK(!db.Exists(std::make_pair('M', first.GetHash())));
    }
}

BOOST_AUTO_TEST_CASE(v2_bad_framing_missing_metadata_and_duplicate_sequences_fail_closed)
{
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(true, error));
    auto first = MakeEciesMessage(ROOT, sender, {sender}, "first framed record");
    auto second = MakeEciesMessage(ROOT, sender, {sender}, "second framed record");
    SignMessageWithKey(first, sender.key);
    SignMessageWithKey(second, sender.key);
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(first, error));
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(second, error));
    StateMetaFixture meta;
    meta.stream = pDepinMsgPool->GetStreamId();
    meta.high = 2;
    CHashWriter directory(SER_GETHASH, 0);
    directory << ROOT;
    const auto path = GetDataDir() / "depinstate-v2" / directory.GetHash().ToString();
    pDepinMsgPool.reset();
    for (int scenario = 0; scenario < 4; ++scenario) {
        CDataStream record(SER_DISK, CLIENT_VERSION);
        record << uint64_t(scenario == 2 ? 2 : 1);
        if (scenario == 0) record << uint8_t(10) << uint8_t(1); // incomplete vector
        else if (scenario == 1) WriteCompactSize(record, uint64_t(32) * 1024 * 1024);
        else record << std::vector<unsigned char>{1} << CPubKey();
        {
            CDBWrapper db(path, 1 << 20);
            BOOST_REQUIRE(db.Write('V', meta, true));
            BOOST_REQUIRE(db.Write(std::make_pair('M', first.GetHash()),
                RawStateFixture{std::vector<unsigned char>(record.begin(), record.end())}, true));
            if (scenario == 3) BOOST_REQUIRE(db.Erase('V', true));
        }
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE, DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS, DEFAULT_DEPIN_POOL_SIZE_MB));
        BOOST_CHECK(!pDepinMsgPool->InitializeStorage(true, error));
        BOOST_CHECK(!pDepinMsgPool->StorageHealthy());
        BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
        pDepinMsgPool.reset();
        CDBWrapper db(path, 1 << 20);
        BOOST_CHECK(db.Exists(std::make_pair('M', first.GetHash())));
        BOOST_CHECK(db.Exists(std::make_pair('M', second.GetHash())));
        BOOST_CHECK(!db.Exists(std::make_pair('Q', first.GetHash()))); // no partial recovery commit
    }
}

BOOST_AUTO_TEST_CASE(wal_checksum_corruption_fails_without_resetting_state)
{
    ScopedInitializedPool pool(ROOT);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    CHashWriter directory(SER_GETHASH, 0);
    directory << ROOT;
    const auto path = GetDataDir() / "depinstate-v2" / directory.GetHash().ToString();
    pDepinMsgPool.reset();
    bool damaged = false;
    for (const auto& entry : fs::directory_iterator(path)) {
        if (entry.path().extension() != ".log" || fs::file_size(entry.path()) < 8) continue;
        std::fstream file(entry.path().string(), std::ios::binary | std::ios::in | std::ios::out);
        char byte;
        BOOST_REQUIRE(bool(file.get(byte)));
        byte ^= 1; // damage CRC, without replacing the record through LevelDB
        file.seekp(0);
        file.put(byte);
        BOOST_REQUIRE(bool(file));
        damaged = true;
        break;
    }
    BOOST_REQUIRE(damaged);
    pDepinMsgPool.reset(new CDepinMsgPool());
    BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE, DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS, DEFAULT_DEPIN_POOL_SIZE_MB));
    BOOST_CHECK(!pDepinMsgPool->InitializeStorage(false, error));
    BOOST_CHECK(!pDepinMsgPool->StorageHealthy());
    BOOST_CHECK(fs::exists(path));
}

BOOST_AUTO_TEST_CASE(real_disk_full_does_not_acknowledge_or_partially_apply_deletion)
{
#ifdef WIN32
    BOOST_CHECK(true);
#else
    if (!std::getenv("DEPIN_DISK_FULL_TEST")) { BOOST_CHECK(true); return; }
    struct statvfs capacity;
    BOOST_REQUIRE(statvfs(GetDataDir().string().c_str(), &capacity) == 0);
    BOOST_REQUIRE(uint64_t(capacity.f_blocks) * capacity.f_frsize <= uint64_t(1024) * 1024 * 1024);
    ScopedInitializedPool pool(ROOT);
    const Holder sender = NewHolder(true);
    SetBalance(ROOT, sender.address, 10);
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false, error));
    auto message = MakeEciesMessage(ROOT, sender, {sender}, "disk full");
    const int64_t submittedAt = GetTime();
    for (int i = 0; i < 5000; ++i) {
        message.timestamp = submittedAt - i;
        BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(message, error, true), error);
    }
    const auto filler = GetDataDir() / "test-disk-filler";
    {
        std::ofstream file(filler.string(), std::ios::binary);
        std::string chunk(128 * 1024, 'x');
        while (file.good()) file.write(chunk.data(), chunk.size());
    }
    size_t removed = 0;
    const bool deleted = pDepinMsgPool->Purge(ROOT, GetTime(), true, 0, removed, error);
    fs::remove(filler);
    BOOST_CHECK(!deleted);
    BOOST_CHECK(!pDepinMsgPool->StorageHealthy());
    BOOST_CHECK_EQUAL(removed, 0U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 5000U);
    BOOST_CHECK(!pDepinMsgPool->AddMessage(message, error, true));
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->InitializeStorage(false, error), error);
    // A sync error has an uncertain outcome; a whole committed batch or none
    // is recoverable, but an acknowledged partial deletion is never allowed.
    BOOST_CHECK(pDepinMsgPool->GetTombstoneCount() == 0 || pDepinMsgPool->GetTombstoneCount() == 5000);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
