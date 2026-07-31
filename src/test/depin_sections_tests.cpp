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
//   - authorization_touches_no_cs_main_state: passets / passetsRestrictionCache
//     are caches that must NOT be needed at all -- authorization runs under
//     cs_depinmsgpool, where CAssetsCache methods would race with block
//     validation. Reintroducing CheckForDEPINRestriction() in the access path
//     makes this test crash rather than pass silently.
//
// Runs on REGTEST: DEPIN names only validate on testnet/regtest.

#include "depinmsgpool.h"

#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "depinecies.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "pubkeyindex.h"
#include "rpc/client.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string ROOT = "&TEST";
const std::string SECTION_A = "&TEST/GENERAL";
const std::string SECTION_B = "&TEST/OTHERS";
const std::string SECTION_A_SUB = "&TEST/GENERAL/SUB";

struct Holder {
    CKey key;
    CPubKey pubkey;
    std::string address;
};

struct DepinSectionsSetup : public TestingSetup {
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;

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

        gDepinAncestorRecipientsStats.Reset();
    }

    ~DepinSectionsSetup()
    {
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
        BOOST_REQUIRE(pDepinMsgPool->Initialize(token, DEFAULT_DEPIN_MSG_PORT, maxRecipients,
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
    return (*tableRPC[method]->actor)(request);
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

// (7) Proof BY CONSTRUCTION that authorization reads no cs_main-domain state:
// with passets and passetsRestrictionCache null it still answers correctly.
// CheckForDEPINRestriction() dereferences passets' dirty sets unconditionally,
// so reintroducing it here crashes this test instead of passing silently.
// (Deliberate asymmetry with the previous test: passetsdb/prestricteddb must
// error when absent; passets/passetsRestrictionCache must not be needed.)
BOOST_AUTO_TEST_CASE(authorization_touches_no_cs_main_state)
{
    const Holder active = NewHolder(false);
    const Holder revoked = NewHolder(false);

    SetBalance(SECTION_A, active.address, 10);
    SetBalance(SECTION_A, revoked.address, 10);
    SelfRevoke(SECTION_A, revoked.address);

    NullGuard<CAssetsCache> assetsGuard(passets);
    NullGuard<CLRUCache<std::string, int8_t> > cacheGuard(passetsRestrictionCache);

    std::string error;
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(active.address, SECTION_A, ROOT, error), error);
    BOOST_CHECK(!HasDepinSectionAccess(revoked.address, SECTION_A, ROOT, error));

    // Owner variant runs under the same constraint.
    const Holder owner = NewHolder(false);
    SetBalance(ROOT + OWNER_TAG, owner.address, 1 * COIN);
    BOOST_CHECK_MESSAGE(HasDepinSectionOwnerAccess(owner.address, SECTION_A, ROOT, error), error);
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
// path must stay direct-reads-only; wiring GetDepinAncestorRecipients (or any
// flushing helper) into AddMessage turns this red.
BOOST_AUTO_TEST_CASE(addmessage_does_not_flush)
{
    ScopedInitializedPool pool(ROOT);

    const Holder sender = NewHolder(false);
    const Holder audience = NewHolder(false);
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

    std::string error;

    CDepinMessage okMsg = MakeEciesMessage(ROOT, sender, {r1, r2}, "two is fine");
    BOOST_CHECK_MESSAGE(pDepinMsgPool->AddMessage(okMsg, error, true), error);

    CDepinMessage overMsg = MakeEciesMessage(ROOT, sender, {r1, r2, r3}, "three is too many");
    error.clear();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(overMsg, error, true));
    BOOST_CHECK_MESSAGE(error.find("recipients") != std::string::npos, error);
}

// (15) depinsubmitmsg accepts a section message end to end (subtree gate plus
// inherited-access pre-check, real signature) and still rejects foreign
// tokens before anything else.
BOOST_AUTO_TEST_CASE(depinsubmitmsg_accepts_section)
{
    ScopedInitializedPool pool(ROOT);

    // The sender needs a REVEALED pubkey (signature verification reads the
    // index) and an active section balance.
    const Holder sender = NewHolder(true);
    const Holder audience = NewHolder(false);
    SetBalance(SECTION_A, sender.address, 10);

    CDepinMessage msg = MakeEciesMessage(SECTION_A, sender, {audience}, "via rpc");
    SignMessageWithKey(msg, sender.key);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << msg;

    UniValue params(UniValue::VARR);
    params.push_back(HexStr(ss.begin(), ss.end()));

    const UniValue result = CallDepinRPC("depinsubmitmsg", params);
    BOOST_CHECK_EQUAL(result["result"].get_str(), "success");
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);

    // A foreign token is rejected up front with the subtree error.
    CDepinMessage foreign = MakeEciesMessage("&TESTING", sender, {audience}, "wrong");
    SignMessageWithKey(foreign, sender.key);
    CDataStream ssForeign(SER_NETWORK, PROTOCOL_VERSION);
    ssForeign << foreign;
    UniValue foreignParams(UniValue::VARR);
    foreignParams.push_back(HexStr(ssForeign.begin(), ssForeign.end()));

    BOOST_CHECK_THROW(CallDepinRPC("depinsubmitmsg", foreignParams), UniValue);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
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
    BOOST_CHECK(!pool.Initialize(ROOT, DEFAULT_DEPIN_MSG_PORT, /*maxRecipients=*/0,
                                 DEFAULT_DEPIN_MESSAGE_SIZE,
                                 DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                 DEFAULT_DEPIN_POOL_SIZE_MB));
    BOOST_CHECK(!pool.IsEnabled());

    // The boundary value is fine.
    CDepinMsgPool poolOne;
    BOOST_CHECK(poolOne.Initialize(ROOT, DEFAULT_DEPIN_MSG_PORT, /*maxRecipients=*/1,
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

BOOST_AUTO_TEST_SUITE_END()
