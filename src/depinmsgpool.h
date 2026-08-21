// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINMSGPOOL_H
#define NEURAI_DEPINMSGPOOL_H

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include "sync.h"
#include "uint256.h"
#include "serialize.h"
#include "amount.h"
// CDepinRecipient holds a CPubKey by value, so the full definition is needed
// here; a forward declaration would not do.
#include "pubkey.h"
#include "depinchallenge.h"

#ifdef ENABLE_WALLET
class CWallet;
#endif

// Configuration defaults
static const unsigned int DEFAULT_MAX_DEPIN_RECIPIENTS = 20;
static const unsigned int DEFAULT_DEPIN_MESSAGE_SIZE = 1024;  // 1KB
static const unsigned int DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS = 168;  // 7 days
static const unsigned int DEFAULT_DEPIN_POOL_SIZE_MB = 100;  // 100 MB

// Hard limits (maximum allowed values)
static const unsigned int MAX_DEPIN_RECIPIENTS = 50;
static const unsigned int MAX_DEPIN_MESSAGE_SIZE = 10240;  // 10KB max
static const unsigned int MAX_DEPIN_MESSAGE_EXPIRY_HOURS = 720;  // 30 days max
static const unsigned int MAX_DEPIN_POOL_SIZE_MB = 1000;  // 1GB max

// DePIN pool persistence
static const bool DEFAULT_DEPINPOOL_PERSIST = false;
static const uint32_t DEPINPOOL_MAGIC_BYTES = 0xD0D1D2D3;
static const uint32_t DEPINPOOL_FILE_VERSION = 1;

// Ancestor-recipient queries (GetDepinAncestorRecipients, below).
// These are query limits, NOT messaging limits: they have nothing to do with
// MAX_DEPIN_RECIPIENTS / -depinmsgmaxusers and never decide whether a message
// can be sent.
static const size_t DEFAULT_DEPIN_ANCESTOR_RECIPIENTS_LIMIT = 1000;
static const size_t MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP = 10000;

// Bound on the WORKING SET, distinct from maxResults: the order of the result
// is fixed before truncation, so every positive-balance row has to be collected
// and sorted before anything can be cut. Expressed in (asset, address) rows
// because that is what AssetAddressDirMulti counts; unique addresses can never
// exceed that number, so it bounds memory just as well.
static const size_t MAX_DEPIN_ANCESTOR_SCAN_ROWS = 100000;

// Termination guard for ancestor derivation. Names are far shorter than this
// allows (121 characters on testnet, >= 3 per component, so ~30 levels), and
// the derivation loop shrinks the name every step anyway; the cap just keeps a
// corrupted input from producing an unbounded vector.
static const size_t MAX_DEPIN_ANCESTOR_DEPTH = 64;

// Primary chat message structure with ECIES hybrid encryption
// Uses a single CECIESEncryptedMessage shared by all recipients
// The ECIES structure contains:
//   - encryptedPayload: message encrypted ONCE with AES-256-CBC
//   - recipientKeys: map of (address_hash160 -> encrypted_AES_key)
// Each recipient can decrypt the AES key with their private key,
// then decrypt the shared payload.
class CDepinMessage {
public:
    std::string token;                      // Required token
    std::string senderAddress;              // Sender address
    int64_t timestamp;                      // UNIX time
    uint8_t messageType;                    // Message type: 0x01 = private, 0x02 = group
    std::vector<unsigned char> signature;   // Sender signature

    // ECIES encrypted message (serialized CECIESEncryptedMessage)
    // Shared by all recipients - each can decrypt with their private key
    std::vector<unsigned char> encryptedPayload;

    CDepinMessage() {
        SetNull();
    }

    void SetNull() {
        token = "";
        senderAddress = "";
        timestamp = 0;
        messageType = 0x02;  // Default: group (for backward compatibility)
        signature.clear();
        encryptedPayload.clear();
    }

    // Helper methods to check message type
    bool IsPrivateMessage() const { return messageType == 0x01; }
    bool IsGroupMessage() const { return messageType == 0x02; }

    uint256 GetHash() const;
    bool IsExpired(int64_t currentTime, int64_t expiryTimeSeconds) const;
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(token);
        READWRITE(senderAddress);
        READWRITE(timestamp);
        READWRITE(messageType);
        READWRITE(encryptedPayload);
        READWRITE(signature);
    }
};

// Chat message mempool
class CDepinMsgPool {
private:
    // Lets unit tests enable a pool without Initialize()'s
    // fAssetIndex/fPubKeyIndex/passetsdb preconditions.
    friend struct DepinServerTester;

    mutable CCriticalSection cs_depinmsgpool;

    std::string activeToken;                    // Token active in this pool
    std::map<uint256, CDepinMessage> mapMessages; // Hash -> Message
    std::multimap<int64_t, uint256> mapByTime;  // Timestamp -> Hash (for expiry)

    bool fEnabled;
    unsigned int nMaxRecipients;
    unsigned int nMaxMessageSize;       // Maximum message size in bytes
    unsigned int nMessageExpiryHours;   // Message expiry time in hours
    unsigned int nMaxPoolSizeMB;        // Maximum pool size in MB

    // Per-tip snapshot of the sections under activeToken (see GetSections()).
    // Its own lock, never cs_depinmsgpool: rebuilding is a full asset-directory
    // scan and must not stall message delivery.
    mutable CCriticalSection cs_sectionCache;
    uint256 sectionSnapshotTip;
    std::vector<std::string> sectionSnapshot;

    // Erase `hashes` from both indexes. Caller holds cs_depinmsgpool.
    void EraseMessages(const std::vector<uint256>& hashes);

public:
    CDepinMsgPool();

    // Configuration
    bool Initialize(const std::string& token, unsigned int maxRecipients,
                   unsigned int maxMessageSize, unsigned int messageExpiryHours, unsigned int maxPoolSizeMB);
    bool IsEnabled() const { return fEnabled; }
    std::string GetActiveToken() const { return activeToken; }
    // Encryption used by the pool for message payloads.
    // Kept as a dedicated getter so future algorithms can be switched centrally.
    std::string GetEncryptionCipher() const { return "AES-256-GCM"; }
    unsigned int GetMaxRecipients() const { return nMaxRecipients; }
    unsigned int GetMaxMessageSize() const { return nMaxMessageSize; }
    unsigned int GetMessageExpiryHours() const { return nMessageExpiryHours; }
    unsigned int GetMaxPoolSizeMB() const { return nMaxPoolSizeMB; }
    int64_t GetMessageExpiryTime() const { return nMessageExpiryHours * 3600; }  // Convert to seconds

    // Message handling
    bool AddMessage(const CDepinMessage& message, std::string& error, bool skipSignatureCheck = false);
    bool GetDepinMessage(const uint256& hash, CDepinMessage& message) const;
    // scopeToken "" keeps the historical behavior (every message); otherwise
    // only messages whose token is scopeToken or a section inside it are
    // considered. The scope is a TAB filter, not access control: delivery is
    // still decided by recipientKeys membership.
    std::vector<CDepinMessage> GetMessagesForAddress(const std::string& address,
                                                     const std::string& scopeToken = "") const;
    std::vector<CDepinMessage> GetAllMessages() const;
    size_t GetMessageCount() const;
    size_t CountMessagesInScope(const std::string& scopeToken) const;

    // Cleanup. scopeToken "" keeps the historical pool-wide behavior; otherwise
    // only messages inside that subtree are touched -- the owner of a section
    // may purge what it controls, never parents or siblings.
    void RemoveExpiredMessages(int64_t currentTime, const std::string& scopeToken = "");
    void RemoveMessagesOlderThan(int64_t currentTime, int64_t ageThresholdSeconds,
                                 const std::string& scopeToken = "");
    void Clear();
    size_t ClearScope(const std::string& scopeToken);

    // Sub-assets of the active token at the current chain tip, activeToken
    // itself first. Backed by a per-tip snapshot with its OWN lock
    // (cs_sectionCache) so the underlying asset-directory scan never blocks
    // message delivery; invalidation is lazy on tip change, so reorgs need no
    // hook. Lock order: cs_main -> cs_sectionCache; this method never takes
    // cs_depinmsgpool. Authorization is deliberately NOT cached anywhere.
    bool GetSections(std::vector<std::string>& sections, std::string& error);

    // Stats
    size_t Size() const;
    size_t DynamicMemoryUsage() const;
    int64_t GetOldestMessageTime() const;
    int64_t GetNewestMessageTime() const;

    // Persistence
    bool SaveToDisk();
    bool LoadFromDisk();
};

// Global chat mempool instance
extern std::unique_ptr<CDepinMsgPool> pDepinMsgPool;

// Helper functions

// Validate that `token` is both a well-formed asset name AND specifically a
// DEPIN (soulbound "&TOKEN" / "&TOKEN/SUB") asset. DePIN messaging is
// intentionally restricted to DEPIN-typed tokens; other otherwise-valid
// asset types (ROOT, SUB, QUALIFIER, RESTRICTED, MSGCHANNEL, UNIQUE, ...)
// are rejected here even though IsAssetNameValid() alone would accept them.
// Does not require fAssetIndex/fPubKeyIndex/passetsdb.
bool IsValidDepinMessagingToken(const std::string& token, std::string& error);

// ---------------------------------------------------------------------------
// Section hierarchy helpers. All three are pure string derivation -- no
// database, no locks -- which is what makes them usable both from the hot
// read path (scope filtering) and from authorization.
// ---------------------------------------------------------------------------

// Ancestors of `token`, itself first, up to `stopAt` (inclusive) or up to the
// absolute root when stopAt is empty. Errors if stopAt is neither `token` nor
// one of its '/'-separated ancestors, or if the depth guard
// (MAX_DEPIN_ANCESTOR_DEPTH) is exceeded. This is THE ancestor derivation of
// the messaging layer; GetDepinAncestorRecipients() and HasDepinSectionAccess()
// both call it, so there is exactly one notion of "parent of" in the code.
bool DeriveDepinAncestors(const std::string& token, const std::string& stopAt,
                          std::vector<std::string>& ancestors, std::string& error);

// True iff `name` is `root` itself or lives inside root's '/'-subtree: the
// character after the root prefix must be exactly '/'. "&TESTING" and
// "&TEST.FOO" are NOT inside "&TEST"; "&TEST/GENERAL" and "&TEST/A/B" are.
bool IsDepinSectionOrRoot(const std::string& name, const std::string& root);

// UI label of `name` relative to `root`: "" for the root itself,
// "GENERAL" for "&TEST/GENERAL" under "&TEST", "A/B" for "&TEST/A/B".
// Returns `name` unchanged when it is not inside root's subtree.
std::string GetDepinSectionLabel(const std::string& name, const std::string& root);

// ---------------------------------------------------------------------------
// Section authorization: may `address` read/write in section `sectionToken` of
// the pool rooted at `root`? True iff the address holds an ACTIVE pair
// (positive balance, no owner-freeze 'R', no self-revocation 'S') of
// sectionToken or of any ancestor up to `root` -- holding the root grants the
// whole branch, so a section-level revocation does not withdraw it.
//
// Lock and freshness contract (deliberate, see the sections NIP): this runs
// inside AddMessage() under cs_depinmsgpool, where calling
// GetDepinAncestorRecipients() is forbidden (it takes cs_main and flushes) and
// where CAssetsCache methods such as CheckForDEPINRestriction() would race --
// they read passets' dirty sets and write passetsRestrictionCache, state that
// mutates during block validation under cs_main. So this function performs
// ONLY direct database reads (ReadAssetAddressQuantity, ReadRestrictedAddress,
// ReadSelfRestriction), which LevelDB serves concurrently without a lock. Its
// freshness is therefore the flushed state -- the same the pool's ownership
// check has always had -- with balance and restrictions read at the SAME level
// rather than mixing disk balances with half-connected in-memory restrictions.
//
// Preconditions, each a named error BEFORE any read: fAssetIndex (without the
// index "no balance" would be indistinguishable from "cannot answer"),
// passetsdb, prestricteddb (restrictions read from a null pointer would fail
// OPEN and let frozen/revoked holders publish). Denying with a false reason is
// as misleading as granting too much, so a missing dependency is an error,
// never "no access".
bool HasDepinSectionAccess(const std::string& address, const std::string& sectionToken,
                           const std::string& root, std::string& error);

// Same relation for owner tokens: the owner of a section controls its subtree,
// the owner of the root controls everything. Ancestors are derived over the
// BASE names and OWNER_TAG is re-appended per level -- "&TEST/GENERAL!" is not
// a component of anything. Owner tokens cannot be frozen or self-revoked, so
// "active" reduces to positive balance and prestricteddb is not required.
bool HasDepinSectionOwnerAccess(const std::string& address, const std::string& sectionToken,
                                const std::string& root, std::string& error);

bool VerifyDepinMessageSignature(const CDepinMessage& message);
bool SignDepinMessage(CDepinMessage& message, const std::string& senderAddress);
bool CheckTokenOwnership(const std::string& address, const std::string& token, std::string& error);
bool CheckAddressHasPublicKey(const std::string& address, CPubKey& pubkey, std::string& error);
std::vector<std::string> GetTokenHolders(const std::string& token, unsigned int maxHolders, std::string& error);

// One active holder of a DEPIN branch, with the key needed to encrypt for it.
struct CDepinRecipient {
    std::string address;
    CPubKey pubkey;
};

// Result of GetDepinAncestorRecipients(). Purely informational: it carries no
// notion of whether the set fits in a message.
struct CDepinAncestorRecipients {
    std::string token;                      // token the query was made for
    std::string stopAt;                     // where derivation stopped ("" = absolute root)
    std::vector<std::string> ancestors;     // token first, then each ancestor up to stopAt/root
    std::vector<CDepinRecipient> recipients;

    // Addresses examined and dropped. With truncated == false these counts
    // cover the whole query; with truncated == true they only cover the
    // addresses examined before the extra eligible recipient was found, which
    // is what the *Complete flags say (both are simply !truncated).
    size_t skippedNoPubKey;
    bool skippedNoPubKeyComplete;
    size_t skippedRestricted;
    bool skippedRestrictedComplete;

    size_t maxResults;
    bool truncated;

    CDepinAncestorRecipients()
        : skippedNoPubKey(0), skippedNoPubKeyComplete(true),
          skippedRestricted(0), skippedRestrictedComplete(true),
          maxResults(0), truncated(false) {}
};

// Access-pattern instrumentation for GetDepinAncestorRecipients().
//
// These counters exist so the tests can assert the *shape* of the query rather
// than only its result: one flush per call, restrictions resolved once per
// address instead of once per (asset, address) pair, and no pubkey lookup for
// an address already dropped by restriction. Those are the regressions that are
// easy to introduce here and invisible to a functional test -- the answer stays
// correct while the cost explodes.
//
// Counting is confined to GetDepinAncestorRecipients(); the flush counter in
// particular only sees the flush that function performs. A helper that grew its
// own raw FlushStateToDisk() call would not be counted here, which is why
// AssetAddressDirMulti() and GetAddressDepinRestrictions() are additionally
// tested with a null pcoinsTip -- flushing then crashes rather than passing.
struct CDepinAncestorRecipientsStats {
    std::atomic<uint64_t> flushCalls;
    std::atomic<uint64_t> restrictionQueries;
    std::atomic<uint64_t> pubkeyQueries;

    CDepinAncestorRecipientsStats() : flushCalls(0), restrictionQueries(0), pubkeyQueries(0) {}

    void Reset() {
        flushCalls = 0;
        restrictionQueries = 0;
        pubkeyQueries = 0;
    }
};
extern CDepinAncestorRecipientsStats gDepinAncestorRecipientsStats;

// Active holders of a DEPIN branch: the deduplicated union of the holders of
// `token` and of every one of its '/'-separated ancestors, each with the public
// key revealed on chain. "Active" means positive balance, revealed public key,
// and not blocked by owner-freeze or self-revocation.
//
// The query is exact at every step: `token` must be a DEPIN asset that exists,
// ancestors are derived by stripping one component at a time, and each one is
// validated and required to exist. Holders are read with exact name equality,
// never by prefix -- querying "&TEST" does not reach "&TEST/APPLE", "&TESTING"
// or "&TEST.FOO".
//
// stopAt must be `token` itself or one of its ancestors; derivation then stops
// there, inclusive. Empty (the default) derives up to the absolute root.
//
// Restriction is per (asset, address): an address is eligible if it is active in
// at least ONE of the ancestors where it holds a balance. Holding the root
// already grants visibility over the branch, so revoking in a section does not
// take that away.
//
// maxResults is a query limit, not a messaging limit. If more eligible
// recipients exist, the first maxResults in address order are returned and
// truncated is set -- the order is fixed before any cut, so a restricted or
// key-less address never displaces a valid one later in the ordering.
//
// The function takes cs_main and flushes once itself; that contract belongs to
// it, not to the caller. Taking cs_main beforehand is harmless (it is a
// recursive mutex), but it must NOT be called while holding a lock that is
// elsewhere acquired after cs_main -- cs_depinmsgpool, for instance.
//
// Requires fAssetIndex, fPubKeyIndex, passetsdb, pblocktree, pcoinsTip and
// prestricteddb; a missing one is a named error, never an empty result.
bool GetDepinAncestorRecipients(const std::string& token,
                                size_t maxResults,
                                CDepinAncestorRecipients& result,
                                std::string& error,
                                const std::string& stopAt = "");

// Decide whether a given address should receive this message from the pool.
// Sender always sees their own message; otherwise checks recipientKeys
// membership by hash160 (no decryption attempted, no private key needed).
// addressHash160 must be pre-decoded once by the caller (see GetMessagesForAddress).
//
// scopeToken "" is byte-for-byte the historical behavior. Non-empty, the
// message's token must be scopeToken or a section inside it; the check runs
// BEFORE the sender shortcut (a sender's own message from another section must
// not leak into the wrong tab) and before the ECIES deserialization (the
// expensive part). The scope separates tabs; it is NOT access control -- what
// an address can decrypt is still fixed by recipientKeys.
bool ShouldDeliverDepinMessageToAddress(const CDepinMessage& msg, const std::string& address,
                                         const uint160* addressHash160,
                                         const std::string& scopeToken = "");

// Apply ShouldDeliverDepinMessageToAddress over a collection, preserving order.
// Split out from GetMessagesForAddress so the delivery policy can be tested on a
// whole message set without a live CDepinMsgPool/passetsdb.
// Takes pointers so callers holding the pool lock never have to copy the whole
// pool (up to 1 GB of payloads) just to filter it; only delivered messages are
// copied into the result. Null entries are skipped.
std::vector<CDepinMessage> FilterDepinMessagesForAddress(const std::vector<const CDepinMessage*>& messages,
                                                         const std::string& address,
                                                         const uint160* addressHash160,
                                                         const std::string& scopeToken = "");

// Encrypt message for ALL recipients at once (ECIES hybrid encryption)
// Creates a single CECIESEncryptedMessage with:
//   - Message encrypted once with AES
//   - AES key encrypted for each recipient
bool EncryptMessageForAllRecipients(const std::string& message,
                                     const std::vector<std::string>& recipientAddresses,
                                     std::vector<unsigned char>& encryptedData,
                                     std::string& error);

// Decrypt message for a specific address
// Extracts the recipient's encrypted AES key from CECIESEncryptedMessage,
// decrypts it with private key, then decrypts the shared payload
bool DecryptMessageForAddress(const std::vector<unsigned char>& encryptedData,
                               const std::string& address,
                               std::string& decryptedMessage,
                               std::string& error);

#ifdef ENABLE_WALLET
// Signs a DePIN challenge preimage (DepinChallengePreimage) with the wallet
// key of `address`. The wallet-side half of the challenge/response flow; the
// node verifies with VerifyDepinChallengeSignature over the same preimage.
bool SignDepinChallenge(CWallet* pwallet,
                        const std::string& address,
                        const std::string& token,
                        const std::string& challenge,
                        std::string& signature,
                        std::string& error,
                        DepinChallengeType type = DepinChallengeType::RECEIVE);
#endif

#endif // NEURAI_DEPINMSGPOOL_H
