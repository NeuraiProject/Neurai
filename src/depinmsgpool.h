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
#include <memory>
#include <set>
#include "sync.h"
#include "uint256.h"
#include "serialize.h"
#include "amount.h"
// CDepinRecipient holds a CPubKey by value, so the full definition is needed
// here; a forward declaration would not do.
#include "pubkey.h"
#include "depinchallenge.h"
#include "depinserialization.h"

#ifdef ENABLE_WALLET
class CWallet;
#endif

class CDBWrapper;

// Configuration defaults
static const unsigned int DEFAULT_MAX_DEPIN_RECIPIENTS = 20;
static const unsigned int DEFAULT_DEPIN_MESSAGE_SIZE = 1024;  // 1KB
static const unsigned int DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS = 168;  // 7 days
static const int64_t DEFAULT_DEPIN_MAX_TIP_AGE = 3600;
static const int64_t DEFAULT_DEPIN_MAX_HEADER_LAG = 2;

struct CDepinServiceStatus {
    bool ready = false;
    std::string reason;
    int height = -1;
    int headers = -1;
    int64_t tipAge = 0;
};

// Chain-dependent operations hold cs_main from this check through their
// final permission check and effect. Diagnostics may call this at any time.
CDepinServiceStatus GetDepinServiceStatus();
bool CheckDepinServiceReady(std::string& error);

struct CDepinAdmissionStats {
    std::atomic<uint64_t> balanceQueries{0};
    std::atomic<uint64_t> permissionMicros{0};
    std::atomic<uint64_t> poolWaitMicros{0};
    std::atomic<uint64_t> poolHoldMicros{0};
    std::atomic<uint64_t> admitted{0};
    void Reset() { balanceQueries = 0; permissionMicros = 0; poolWaitMicros = 0; poolHoldMicros = 0; admitted = 0; }
};
extern CDepinAdmissionStats gDepinAdmissionStats;
static const unsigned int DEFAULT_DEPIN_POOL_SIZE_MB = 100;  // 100 MB

// Hard limits (maximum allowed values)
static const unsigned int MAX_DEPIN_RECIPIENTS = 50;
static const unsigned int MAX_DEPIN_MESSAGE_SIZE = 10240;  // 10KB max
static const unsigned int MAX_DEPIN_MESSAGE_EXPIRY_HOURS = 720;  // 30 days max
static const unsigned int MAX_DEPIN_POOL_SIZE_MB = 1000;  // 1GB max

// DePIN pool persistence
static const bool DEFAULT_DEPINPOOL_PERSIST = false;
static const uint32_t DEPINPOOL_MAGIC_BYTES = 0xD0D1D2D3;
// Legacy flat file only; current transactional state is version 2.
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
//   - encryptedPayload: AES-256-GCM [nonce (12) || ciphertext || tag (16)]
//   - recipientKeys: address_hash160 -> GCM-wrapped AES key (60 bytes:
//     nonce (12) || encrypted_AES_key (32) || tag (16))
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
        verifiedSenderKey = CPubKey();
    }

    // Verified sender key retained only as service metadata, never serialized
    // into the user's signed wire message. Allows historical verification after
    // a reorg removes the original key-reveal transaction from the index.
    CPubKey verifiedSenderKey;

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

// The serialized user message remains unchanged. Only its decoder is bounded.
static const size_t MAX_DEPIN_MESSAGE_WIRE_BYTES = 16384;
template <typename Stream>
void ReadDepinMessageBounded(Stream& stream, CDepinMessage& message,
                             size_t maxPayload = MAX_DEPIN_MESSAGE_WIRE_BYTES)
{
    message.token = ReadDepinString(stream, 128);
    message.senderAddress = ReadDepinString(stream, 64);
    stream >> message.timestamp >> message.messageType;
    message.encryptedPayload = ReadDepinBytes(stream, maxPayload);
    message.signature = ReadDepinBytes(stream, 80);
}
bool DecodeDepinMessage(const std::vector<unsigned char>& bytes, CDepinMessage& message, std::string& error);

enum class DepinAdmissionError { NONE, RECIPIENT_NOT_AUTHORIZED };

static const size_t DEFAULT_DEPIN_TOMBSTONE_LIMIT = 100000;
static const size_t MAX_DEPIN_TOMBSTONE_LIMIT = 1000000;
struct CDepinSequenceMessage {
    uint64_t sequence;
    CDepinMessage message;
};
struct CDepinSequencePage {
    uint256 stream;
    uint64_t after = 0;
    bool hasMore = false;
    std::vector<CDepinSequenceMessage> messages;
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

    std::map<uint64_t, uint256> mapBySequence;
    std::map<uint256, uint64_t> sequenceByHash;
    uint256 streamId;
    uint64_t highWater = 0;
    int64_t minimumTimestamp = 0;
    uint256 checkpointStream;
    uint64_t checkpointHigh = 0;
    bool checkpointKeep = false;
    bool legacyImported = false;
    std::map<uint256, int64_t> tombstones;
    std::unique_ptr<CDBWrapper> store;
    bool persistMessages = false;
    bool storageFault = false;
    size_t tombstoneLimit = DEFAULT_DEPIN_TOMBSTONE_LIMIT;
    bool CommitAdmission(const CDepinMessage& message, uint64_t sequence, std::string& error);
    bool CommitErase(const std::vector<uint256>& hashes, bool moderation, int64_t now, std::string& error,
                     const std::map<uint256, int64_t>* retainedTimestamps = nullptr);
    void ApplyErase(const std::vector<uint256>& hashes);
    bool FailStorage(const std::string& reason, std::string& error);

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

    // Erase `hashes` durably, then from all four indexes. Caller holds pool lock.
    void EraseMessages(const std::vector<uint256>& hashes);

    // Only LoadFromDisk may restore an already stored message without applying
    // today's membership to its historical sender and recipients. All other
    // validations, including the signature, still apply to restoration.
    bool AddMessageInternal(const CDepinMessage& message, std::string& error,
                            bool skipSignatureCheck, bool restoring,
                            DepinAdmissionError* admissionError = nullptr, uint64_t restoreSequence = 0);

public:
    CDepinMsgPool();
    ~CDepinMsgPool();
    bool InitializeStorage(bool keepMessages, std::string& error, size_t maxTombstones = DEFAULT_DEPIN_TOMBSTONE_LIMIT);
    bool StorageHealthy() const;
    uint256 GetStreamId() const;
    uint64_t GetHighWater() const;
    size_t GetTombstoneCount() const;
    bool Purge(const std::string& scope, int64_t now, bool all, int64_t olderThan,
               size_t& removed, std::string& error);
    bool GetLegacyPage(const std::string& address, const std::string& scope, int64_t from,
                       const std::string& anchor, size_t limit, std::vector<CDepinMessage>& messages,
                       bool& hasMore, std::string& error) const;
    bool GetSequencePage(const std::string& address, const std::string& scope,
                         const uint256& stream, uint64_t after, size_t limit, int64_t fromTimestamp,
                         CDepinSequencePage& page, std::string& error) const;

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
    bool AddMessage(const CDepinMessage& message, std::string& error, bool skipSignatureCheck = false,
                    DepinAdmissionError* admissionError = nullptr);
    bool GetDepinMessage(const uint256& hash, CDepinMessage& message) const;
    // Returns only unexpired messages, including for the sender. scopeToken
    // "" considers every token; otherwise
    // only messages whose token is scopeToken or a section inside it are
    // considered. The scope is a TAB filter, not access control: delivery is
    // still decided by recipientKeys membership.
    std::vector<CDepinMessage> GetMessagesForAddress(const std::string& address,
                                                     const std::string& scopeToken = "") const;
    // Physical snapshot by default, for storage statistics and maintenance.
    // Delivery callers must pass false to exclude expired entries using one
    // reference time for the whole snapshot, without waiting for cleanup.
    std::vector<CDepinMessage> GetAllMessages(bool includeExpired = true) const;
    size_t GetMessageCount() const;
    // Unexpired count for section listings; share the RPC's reference time.
    size_t CountMessagesInScope(const std::string& scopeToken, int64_t now) const;

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
    // raw pool reads; permission-dependent RPCs still serialize under cs_main.
    // Invalidation is lazy on tip change, so reorgs need no
    // hook. Lock order: cs_main -> cs_sectionCache; this method never takes
    // cs_depinmsgpool. Authorization is deliberately NOT cached anywhere.
    bool GetSections(std::vector<std::string>& sections, std::string& error);

    // Stats
    size_t Size() const;
    size_t DynamicMemoryUsage() const;
    int64_t GetOldestMessageTime() const;
    int64_t GetNewestMessageTime() const;

    // State v2 uses synchronous LevelDB batches for retained admissions and
    // moderation. SaveToDisk is a shutdown checkpoint, not the durability
    // boundary. LoadFromDisk is the retained-storage initialization facade.
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
// Takes cs_main and reads the connected chainstate: dirty asset balances and
// restrictions override the persisted indexes. A fresh local CAssetsCache
// receives balance read-throughs, so queries never fill the global balance map
// or force a full UTXO flush. No mempool permissions are used.
//
// Callers performing an operation must hold cs_main from CheckDepinServiceReady
// through authorization and selection/mutation. Lock order is cs_main before
// pool, section-cache, challenge and wallet locks; never call under a pool lock.
// These reusable permission helpers do not enforce node freshness themselves.
// Missing indexes, chainstate cache or databases are named errors. In particular
// a missing restriction database must fail closed.
bool HasDepinSectionAccess(const std::string& address, const std::string& sectionToken,
                           const std::string& root, std::string& error);

// Same relation for owner tokens: the owner of a section controls its subtree,
// the owner of the root controls everything. Ancestors are derived over the
// BASE names and OWNER_TAG is re-appended per level -- "&TEST/GENERAL!" is not
// a component of anything. Owner tokens cannot be frozen or self-revoked, so
// "active" reduces to positive balance and prestricteddb is not required.
bool HasDepinSectionOwnerAccess(const std::string& address, const std::string& sectionToken,
                                const std::string& root, std::string& error);

bool VerifyDepinMessageSignature(const CDepinMessage& message, CPubKey* verifiedKey = nullptr);
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

// Access-pattern instrumentation for GetDepinAncestorRecipients(). flushCalls
// remains zero for compatibility with earlier tests; nFullStateFlushes checks
// the actual validation path. restrictionQueries counts addresses evaluated,
// not low-level database reads; multiple ancestor pairs may be checked for one
// address. Public keys are only queried after an active pair has been found.
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
// Takes cs_main, checks service freshness and merges the persisted directory
// with connected-tip balances and restrictions without flushing. Callers may
// already hold cs_main, but must not hold a lock ordered after it (pool, etc.).
// Requires fAssetIndex, fPubKeyIndex, passets, passetsCache, passetsdb,
// pblocktree, pcoinsTip and prestricteddb; absence is a named error.
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



#endif // NEURAI_DEPINMSGPOOL_H
