// Copyright (c) 2025 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINMCPWORKER_H
#define NEURAI_DEPINMCPWORKER_H

#include "depinmcpclient.h"
#include "uint256.h"
#include "sync.h"
#include "fs.h"

#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <set>
#include <map>
#include <deque>
#include <vector>
#include <utility>
#include <condition_variable>
#include <mutex>

struct CDepinMessage;

// Defaults for MCP worker tuning
static const int DEFAULT_DEPIN_MCP_TIMEOUT = 120;        // HTTP timeout seconds
static const int DEFAULT_DEPIN_MCP_CONCURRENCY = 2;      // parallel AI requests
static const int DEFAULT_DEPIN_MCP_CONTEXT = 6;          // history entries per sender (3 turns), 0 = off
static const int DEFAULT_DEPIN_MCP_FRAG_SIZE = 1500;     // plaintext chars per response fragment
static const int DEFAULT_DEPIN_MCP_MAX_FRAGMENTS = 5;    // max fragments per response
static const size_t MCP_MAX_PROCESSED_CACHE = 10000;     // processed-hash cache cap
static const size_t MCP_MAX_TASK_QUEUE = 256;            // pending task queue cap
static const size_t MCP_MAX_COMMAND_CHARS = 4000;        // max chars of a single incoming command
static const int64_t MCP_CONTEXT_IDLE_TTL = 60 * 60;     // drop idle conversation context after 1h

/**
 * CDepinMCPWorker - Background worker for DePIN MCP integration
 *
 * Architecture:
 * 1. A single poller thread (WorkerLoop) sweeps the DePIN message pool every N seconds,
 *    validates messages with the command prefix (e.g. "/ai"), decrypts them once and hands
 *    them to a bounded queue.
 * 2. A pool of task threads (TaskLoop) consume the queue and run the (slow, blocking) AI
 *    requests concurrently, so one slow prompt no longer stalls every other user.
 * 3. Responses are encrypted (ECIES) for all token holders, signed and published back to the
 *    channel, fragmented across several messages when too long.
 *
 * The worker keeps a FIFO cache of processed message hashes to avoid duplicates, per-sender
 * and global rate limiting, and an in-memory short conversation history per sender.
 */
// Test-only accessor (defined in test/depinmcpworker_tests.cpp).
struct DepinMCPWorkerTester;

class CDepinMCPWorker
{
    friend struct DepinMCPWorkerTester;

private:
    // Poller thread
    std::thread workerThread;
    std::atomic<bool> running;
    std::atomic<bool> shouldStop;

    // Task pool (concurrent AI requests)
    // One queued command. `token` is the token the incoming message carried
    // (the monitored token or a section inside it); every reply goes back to
    // that same token -- answering a section's question at the root would leak
    // the conversation to the whole root audience.
    struct MCPTask {
        std::string sender;
        std::string decrypted;
        std::string token;
    };
    std::vector<std::thread> taskPool;
    std::deque<MCPTask> taskQueue;
    std::mutex taskMutex;
    std::condition_variable taskCv;
    std::atomic<int> tasksInFlight;
    int concurrency;

    // MCP client
    std::unique_ptr<CDepinMCPClient> mcpClient;

    // Configuration
    std::string mcpUrl;
    std::string mcpEndpoint;
    std::string commandKey;         // e.g., "/ai"
    std::string nodeAddress;        // Address for signing responses
    std::string depinToken;         // Token to monitor
    int pollInterval;               // Seconds between polls
    std::string responsePrefix;     // e.g., "[BOT]:"
    int rateLimitPerMinute;         // per-sender (0 = unlimited)
    int globalRateLimitPerMinute;   // global across all senders (0 = unlimited)
    int contextSize;                // conversation history entries per sender (0 = disabled)
    int fragmentSize;               // plaintext chars per response fragment
    int maxFragments;               // max fragments per response
    std::string poolHost;           // DePIN pool host (localhost = local pool)
    int poolPort;                   // DePIN pool port

    // Processed-message dedup (FIFO eviction)
    std::set<uint256> processedMessages;
    std::deque<uint256> processedOrder;
    bool processedDirty;
    CCriticalSection cs_processed;

    // Per-sender rate limiting: address -> deque of timestamps
    std::map<std::string, std::deque<int64_t>> rateLimitMap;
    CCriticalSection cs_rateLimit;

    // Global rate limiting
    std::deque<int64_t> globalRateTimestamps;
    CCriticalSection cs_globalRate;

    // Conversation context (in-memory only): sender -> last K messages (alternating user/assistant)
    std::map<std::string, std::deque<std::string>> contextMap;
    std::map<std::string, int64_t> contextLastSeen;
    CCriticalSection cs_context;

    // Statistics
    std::atomic<uint64_t> totalCommandsProcessed;
    std::atomic<uint64_t> totalErrors;
    std::atomic<uint64_t> totalRateLimited;
    std::atomic<int64_t> lastPollTime;

    /** Poller thread entry point. */
    void WorkerLoop();

    /** Task pool thread entry point. */
    void TaskLoop();

    /** Enqueue a decrypted command for a task thread. Blocks while the queue is full.
     *  @return false if the worker is shutting down (caller should not mark it processed). */
    bool EnqueueTask(const std::string& sender, const std::string& decryptedMessage,
                     const std::string& msgToken);

    /** Run a single command end-to-end (rate limit, AI request, response). */
    void ProcessTask(const std::string& sender, const std::string& decryptedMessage,
                     const std::string& msgToken);

    /** Validate a message and, on success, return its decrypted text (single decrypt). */
    bool ValidateMessage(const CDepinMessage& msg, std::string& decryptedOut);

    /** Extract the command text after the command prefix. */
    bool ExtractCommand(const std::string& message, std::string& command);

    bool IsMessageProcessed(const uint256& hash);
    void MarkAsProcessed(const uint256& hash);

    bool CheckRateLimit(const std::string& address);
    bool CheckGlobalRateLimit();

    /** Drop stale rate-limit / context entries to bound memory. Called once per poll cycle. */
    void CleanupStaleState();

    // Conversation context helpers
    std::vector<std::string> GetContext(const std::string& sender);
    void AppendContext(const std::string& sender, const std::string& prompt, const std::string& response);
    void ResetContext(const std::string& sender);

    bool LoadProcessedMessages();
    bool SaveProcessedMessages();
    void FlushProcessedIfDirty();
    fs::path GetProcessedMessagesPath() const;

    /** Encrypt+sign+publish a single pooled message under `msgToken` for `holders`. */
    bool SendPooledMessage(const std::string& text, const std::vector<std::string>& holders,
                           const std::string& msgToken);

    /** Send an AI response back to the section it was asked in, fragmenting it
     *  if too long. Recipients are the active holders of msgToken and of its
     *  ancestors up to the monitored token. */
    bool SendResponse(const std::string& response, const std::string& originalSender,
                      const std::string& msgToken);

public:
    CDepinMCPWorker();
    ~CDepinMCPWorker();

    /**
     * Initialize worker with configuration. Extended params have sensible defaults so the
     * existing call sites keep working.
     */
    bool Initialize(const std::string& url, const std::string& endpoint,
                   const std::string& apiKey, const std::string& key,
                   const std::string& address, const std::string& token,
                   int interval, const std::string& prefix,
                   int timeout, int rateLimit,
                   const std::string& poolHost = "localhost", int poolPort = 19002,
                   int maxTokens = DEFAULT_DEPIN_MCP_MAX_TOKENS,
                   double temperature = DEFAULT_DEPIN_MCP_TEMPERATURE,
                   int concurrency = DEFAULT_DEPIN_MCP_CONCURRENCY,
                   int contextSize = DEFAULT_DEPIN_MCP_CONTEXT,
                   int globalRateLimit = 0,
                   int fragmentSize = DEFAULT_DEPIN_MCP_FRAG_SIZE,
                   int maxFragments = DEFAULT_DEPIN_MCP_MAX_FRAGMENTS);

    bool Start();
    void Stop();
    bool IsRunning() const { return running.load(); }

    // Getters for statistics and configuration
    uint64_t GetCommandsProcessed() const { return totalCommandsProcessed.load(); }
    uint64_t GetTotalErrors() const { return totalErrors.load(); }
    uint64_t GetRateLimited() const { return totalRateLimited.load(); }
    int GetTasksInFlight() const { return tasksInFlight.load(); }
    int64_t GetLastPollTime() const { return lastPollTime.load(); }
    std::string GetMCPUrl() const { return mcpUrl; }
    std::string GetCommandKey() const { return commandKey; }
    std::string GetDepinToken() const { return depinToken; }
    std::string GetNodeAddress() const { return nodeAddress; }
    int GetPollInterval() const { return pollInterval; }
    int GetConcurrency() const { return concurrency; }
    std::string GetPoolHost() const { return poolHost; }
    int GetPoolPort() const { return poolPort; }
    bool IsUsingRemotePool() const { return poolHost != "localhost" && poolHost != "127.0.0.1"; }
    size_t GetProcessedCacheSize();
    size_t GetContextSessions();
    std::string GetModelName() const;
};

// Global instance
extern std::unique_ptr<CDepinMCPWorker> g_depinMCPWorker;

#endif // NEURAI_DEPINMCPWORKER_H
