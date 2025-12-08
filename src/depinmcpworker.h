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

struct CDepinMessage;

/**
 * CDepinMCPWorker - Background worker for DePIN MCP integration
 *
 * This class runs a background thread that:
 * 1. Polls the DePIN message pool every N seconds
 * 2. Filters messages with the configured command prefix (e.g., "/ai")
 * 3. Sends prompts to the MCP server (AI model)
 * 4. Sends AI responses back to the DePIN channel
 *
 * The worker maintains a cache of processed messages to avoid duplicates
 * and implements rate limiting per sender address.
 */
class CDepinMCPWorker
{
private:
    // Thread management
    std::thread workerThread;
    std::atomic<bool> running;
    std::atomic<bool> shouldStop;

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
    int rateLimitPerMinute;
    std::string poolHost;           // DePIN pool host (localhost = local pool)
    int poolPort;                   // DePIN pool port

    // Message processing
    std::set<uint256> processedMessages;
    CCriticalSection cs_processed;

    // Rate limiting: address -> deque of timestamps
    std::map<std::string, std::deque<int64_t>> rateLimitMap;
    CCriticalSection cs_rateLimit;

    // Statistics
    std::atomic<uint64_t> totalCommandsProcessed;
    std::atomic<uint64_t> totalErrors;
    std::atomic<int64_t> lastPollTime;

    /**
     * Main worker loop - runs in background thread
     */
    void WorkerLoop();

    /**
     * Process a single DePIN message
     * @param msg Message to process
     * @return true if processed successfully
     */
    bool ProcessMessage(const CDepinMessage& msg);

    /**
     * Validate message before processing
     * @param msg Message to validate
     * @return true if message is valid and should be processed
     */
    bool ValidateMessage(const CDepinMessage& msg);

    /**
     * Extract command from message content
     * @param message Full message text
     * @param command Output parameter for extracted command
     * @return true if command was successfully extracted
     */
    bool ExtractCommand(const std::string& message, std::string& command);

    /**
     * Check if message has already been processed
     * @param hash Message hash
     * @return true if already processed
     */
    bool IsMessageProcessed(const uint256& hash);

    /**
     * Mark message as processed
     * @param hash Message hash to mark
     */
    void MarkAsProcessed(const uint256& hash);

    /**
     * Check rate limit for sender address
     * @param address Sender's address
     * @return true if within rate limit, false if exceeded
     */
    bool CheckRateLimit(const std::string& address);

    /**
     * Load processed messages from disk
     * @return true if loaded successfully (or file doesn't exist)
     */
    bool LoadProcessedMessages();

    /**
     * Save processed messages to disk
     * @return true if saved successfully
     */
    bool SaveProcessedMessages();

    /**
     * Get path to processed messages file
     */
    fs::path GetProcessedMessagesPath() const;

    /**
     * Send AI response back to DePIN channel
     * @param response Response text from AI
     * @param originalSender Address of original message sender
     * @return true if sent successfully
     */
    bool SendResponse(const std::string& response, const std::string& originalSender);

public:
    CDepinMCPWorker();
    ~CDepinMCPWorker();

    /**
     * Initialize worker with configuration
     * @param url MCP server base URL
     * @param endpoint MCP API endpoint
     * @param apiKey Optional API key
     * @param key Command prefix (e.g., "/ai")
     * @param address Node address for signing
     * @param token DePIN token to monitor
     * @param interval Poll interval in seconds
     * @param prefix Response prefix (e.g., "[BOT]:")
     * @param timeout HTTP timeout in seconds
     * @param rateLimit Rate limit per minute (0 = no limit)
     * @param poolHost DePIN pool host (localhost = local pool)
     * @param poolPort DePIN pool port
     * @return true if initialization succeeded
     */
    bool Initialize(const std::string& url, const std::string& endpoint,
                   const std::string& apiKey, const std::string& key,
                   const std::string& address, const std::string& token,
                   int interval, const std::string& prefix,
                   int timeout, int rateLimit,
                   const std::string& poolHost = "localhost", int poolPort = 19002);

    /**
     * Start the worker thread
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop the worker thread
     */
    void Stop();

    /**
     * Check if worker is running
     * @return true if worker thread is active
     */
    bool IsRunning() const { return running.load(); }

    // Getters for statistics and configuration
    uint64_t GetCommandsProcessed() const { return totalCommandsProcessed.load(); }
    uint64_t GetTotalErrors() const { return totalErrors.load(); }
    int64_t GetLastPollTime() const { return lastPollTime.load(); }
    std::string GetMCPUrl() const { return mcpUrl; }
    std::string GetCommandKey() const { return commandKey; }
    std::string GetDepinToken() const { return depinToken; }
    std::string GetNodeAddress() const { return nodeAddress; }
    int GetPollInterval() const { return pollInterval; }
    std::string GetPoolHost() const { return poolHost; }
    int GetPoolPort() const { return poolPort; }
    bool IsUsingRemotePool() const { return poolHost != "localhost" && poolHost != "127.0.0.1"; }
    std::string GetModelName() const;
};

// Global instance
extern std::unique_ptr<CDepinMCPWorker> g_depinMCPWorker;

#endif // NEURAI_DEPINMCPWORKER_H
