// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_NET_PROCESSING_H
#define NEURAI_NET_PROCESSING_H

#include "net.h"
#include "validationinterface.h"
#include "consensus/params.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

class CBlockHeader;
class CChainParams;

/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
/** Expiration time for orphan transactions in seconds */
static const int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60;
/** Minimum time between orphan transactions expire time checks in seconds */
static const int64_t ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60;
/** Default number of orphan and recently rejected txn to keep around for block reconstruction */
static const unsigned int DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100;
/** Headers download timeout expressed in microseconds
 *  Timeout = base + per_header * (expected number of headers) */
static constexpr int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE = 15 * 60 * 1000000; // 15 minutes
static constexpr int64_t HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER = 1000; // 1ms/header
/** Protect at least this many outbound peers from disconnection due to slow/
 * behind headers chain.
 */
static constexpr int32_t MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT = 4;
/** Timeout for (unprotected) outbound peers to sync to our chainwork, in seconds */
static constexpr int64_t CHAIN_SYNC_TIMEOUT = 20 * 60; // 20 minutes
/** How frequently to check for stale tips, in seconds */
static constexpr int64_t STALE_CHECK_INTERVAL = 10 * 60; // 10 minutes
/** How frequently to check for extra outbound peers and disconnect, in seconds */
static constexpr int64_t EXTRA_PEER_CHECK_INTERVAL = 45;
/** Minimum time an outbound-peer-eviction candidate must be connected for, in order to evict, in seconds */
static constexpr int64_t MINIMUM_CONNECT_TIME = 30;

class PeerLogicValidation final: public CValidationInterface, public NetEventsInterface {
private:
    CConnman* const connman;

public:
    explicit PeerLogicValidation(CConnman* connman, CScheduler &scheduler);

    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected, const std::vector<CTransactionRef>& vtxConflicted) override;
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    void BlockChecked(const CBlock& block, const CValidationState& state) override;
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) override;


    void InitializeNode(CNode* pnode) override;
    void FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime) override;
    /** Process protocol messages received from a given node */
    bool ProcessMessages(CNode* pfrom, std::atomic<bool>& interrupt) override;
    /**
    * Send queued protocol messages to be sent to a give node.
    *
    * @param[in]   pto             The node which we are sending messages to.
    * @param[in]   interrupt       Interrupt condition for processing threads
    * @return                      True if there is more work to be done
    */
    bool SendMessages(CNode* pto, std::atomic<bool>& interrupt) override;

    void ConsiderEviction(CNode *pto, int64_t time_in_seconds);
    void CheckForStaleTipAndEvictPeers(const Consensus::Params &consensusParams);
    void EvictExtraOutboundPeers(int64_t time_in_seconds);

private:
    int64_t m_stale_tip_check_time; //!< Next time to check for stale tip
};

struct CNodeStateStats {
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};

/** Header-sync timing collected since process start.
 *
 * request_to_response_us includes the peer response time and local queueing;
 * it is intentionally not presented as a raw network RTT.
 */
struct HeaderSyncPeerStats {
    NodeId node_id{0};
    int request_start_height{-1};
    uint64_t batches{0};
    uint64_t headers{0};
    int last_batch_headers{0};
    int64_t last_request_to_response_us{0};
    int64_t last_validation_us{0};
    int64_t average_request_to_response_us{0};
    int64_t average_validation_us{0};
};

struct HeaderSyncStats {
    uint64_t batches{0};
    uint64_t headers{0};
    uint64_t unsolicited_responses{0};
    int64_t average_request_to_response_us{0};
    int64_t average_validation_us{0};
    std::vector<HeaderSyncPeerStats> peers;
};

/** Return header-sync timing collected since process start. */
HeaderSyncStats GetHeaderSyncStats();

/** Process a decoded header batch. Original wire length controls follow-up
 * requests even when an authenticated prefix is trimmed. Takes cs_main internally.
 */
bool ProcessHeadersMessage(CNode* peer, CConnman* connman, std::vector<CBlockHeader> headers,
                           const CChainParams& params, bool punish_duplicate_invalid);

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch);

/** Bounds the admission CPU spent on transactions that peers send and that are
 *  then rejected, which no fee pays for (CPU review, 16-11-2026).
 *
 *  - Per address (IPv4 address, IPv6 /48), so that reconnecting does not
 *    reset it: a credit of PER_ADDRESS_MAX microseconds, refilled at
 *    PER_ADDRESS_REFILL per minute. An address that uses it up is ignored for
 *    IGNORE_SECONDS. Whitelisted peers have no per-address credit.
 *  - In total, three buckets refilled every second: one for inbound peers
 *    (INBOUND_PER_MINUTE, holding at most INBOUND_BURST), one reserved for
 *    outbound and whitelisted peers (RESERVED_PER_MINUTE, RESERVED_BURST)
 *    and a shared one with the sum of both. Admission checks the shared
 *    bucket and the one of its group before each transaction and charges
 *    both after it; a bucket may go below zero, and nothing more is admitted
 *    from it until refills pay that back. Admissions of peer transactions run
 *    one at a time, so in any 60 seconds they spend at most 15 s in total
 *    (10 s inbound, 5 s reserved) plus the one admission in progress, without
 *    bursts that would hold cs_main for seconds.
 *  Times are GetTime() seconds (mockable); charges are thread CPU microseconds.
 */
class TxAdmissionBudget
{
public:
    static constexpr int64_t PER_ADDRESS_MAX = 3000000;
    static constexpr int64_t PER_ADDRESS_REFILL = 1000000;
    static constexpr int64_t IGNORE_SECONDS = 10 * 60;
    static constexpr int64_t INBOUND_PER_MINUTE = 9000000;
    static constexpr int64_t INBOUND_BURST = 1000000;
    static constexpr int64_t RESERVED_PER_MINUTE = 4000000;
    static constexpr int64_t RESERVED_BURST = 1000000;
    static constexpr size_t MAX_ADDRESSES = 10000;

    /** The account an address belongs to. */
    static std::string Key(const CNetAddr& addr);
    /** Whether transactions from this address are ignored now. */
    bool IsIgnored(const std::string& key, bool fWhitelisted, int64_t now);
    /** Whether the buckets of a group have room for another admission now. */
    bool HasRoom(bool fReserved, int64_t now);
    /** Whether a transaction from this account may be admitted now. */
    bool MayAdmit(const std::string& key, bool fReserved, bool fWhitelisted, int64_t now);
    /** When this address was last charged for a rejection; 0 if never (or
     *  since its account was dropped from the table). */
    int64_t LastCharge(const std::string& key);
    /** Charge the CPU time of an admission that ended in a rejection. */
    void ChargeRejected(const std::string& key, bool fReserved, bool fWhitelisted, int64_t cpuMicros, int64_t now);

private:
    struct Account {
        int64_t credit;
        int64_t updated;
        int64_t ignoredUntil;
        int64_t lastCharge;
    };
    struct Bucket {
        const int64_t perMinute;
        const int64_t burst;
        int64_t level;
        int64_t updated;
        void Refill(int64_t now);
    };
    CCriticalSection cs;
    std::map<std::string, Account> accounts;
    Bucket inbound{INBOUND_PER_MINUTE, INBOUND_BURST, INBOUND_BURST, 0};
    Bucket reserved{RESERVED_PER_MINUTE, RESERVED_BURST, RESERVED_BURST, 0};
    Bucket shared{INBOUND_PER_MINUTE + RESERVED_PER_MINUTE, INBOUND_BURST + RESERVED_BURST,
                  INBOUND_BURST + RESERVED_BURST, 0};

    Account& Get(const std::string& key, int64_t now);
};

#endif // NEURAI_NET_PROCESSING_H
