// Copyright (c) 2025 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmcpworker.h"
#include "depinmsgpool.h"
#include "util.h"
#include "utiltime.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "key.h"
#include "wallet/rpcwallet.h"
#include "validation.h"
#include "script/standard.h"

#include <algorithm>

// External declarations
extern std::vector<CWalletRef> vpwallets;

// Global instance
std::unique_ptr<CDepinMCPWorker> g_depinMCPWorker = nullptr;

CDepinMCPWorker::CDepinMCPWorker()
    : running(false),
      shouldStop(false),
      pollInterval(10),
      rateLimitPerMinute(0),
      totalCommandsProcessed(0),
      totalErrors(0),
      lastPollTime(0)
{
}

CDepinMCPWorker::~CDepinMCPWorker()
{
    Stop();
}

bool CDepinMCPWorker::Initialize(const std::string& url, const std::string& endpoint,
                                 const std::string& apiKey, const std::string& key,
                                 const std::string& address, const std::string& token,
                                 int interval, const std::string& prefix,
                                 int timeout, int rateLimit,
                                 const std::string& pHost, int pPort)
{
    LogPrintf("MCPWorker: Initializing with URL=%s, endpoint=%s, key=%s, token=%s\n",
              url, endpoint, key, token);

    // Validate parameters
    if (url.empty()) {
        LogPrintf("MCPWorker: MCP URL cannot be empty\n");
        return false;
    }

    if (endpoint.empty()) {
        LogPrintf("MCPWorker: MCP endpoint cannot be empty\n");
        return false;
    }

    if (key.empty()) {
        LogPrintf("MCPWorker: Command key cannot be empty\n");
        return false;
    }

    if (token.empty()) {
        LogPrintf("MCPWorker: DePIN token cannot be empty\n");
        return false;
    }

    if (address.empty()) {
        LogPrintf("MCPWorker: Node address cannot be empty\n");
        return false;
    }

    if (interval < 1) {
        LogPrintf("MCPWorker: Poll interval must be at least 1 second\n");
        return false;
    }

    // Store configuration
    mcpUrl = url;
    mcpEndpoint = endpoint;
    commandKey = key;
    nodeAddress = address;
    depinToken = token;
    pollInterval = interval;
    responsePrefix = prefix;
    rateLimitPerMinute = rateLimit;
    poolHost = pHost;
    poolPort = pPort;

    // Log pool source
    if (poolHost == "localhost" || poolHost == "127.0.0.1") {
        LogPrintf("MCPWorker: Using LOCAL DePIN message pool\n");
    } else {
        LogPrintf("MCPWorker: Using REMOTE DePIN message pool at %s:%d\n", poolHost, poolPort);
    }

    // Create MCP client
    mcpClient = std::make_unique<CDepinMCPClient>(url, endpoint, apiKey, timeout);

    // Test connection to MCP server
    LogPrintf("MCPWorker: Testing connection to MCP server...\n");
    if (!mcpClient->TestConnection()) {
        LogPrintf("MCPWorker: WARNING - Failed to connect to MCP server. Worker will continue but commands may fail.\n");
        // Don't return false - allow worker to start and retry later
    } else {
        LogPrintf("MCPWorker: Successfully connected to MCP server\n");
    }

    LogPrintf("MCPWorker: Initialization complete\n");
    return true;
}

bool CDepinMCPWorker::Start()
{
    if (running.load()) {
        LogPrintf("MCPWorker: Already running\n");
        return false;
    }

    LogPrintf("MCPWorker: Starting worker thread...\n");

    shouldStop.store(false);
    running.store(true);

    workerThread = std::thread(&CDepinMCPWorker::WorkerLoop, this);

    LogPrintf("MCPWorker: Worker thread started\n");
    return true;
}

void CDepinMCPWorker::Stop()
{
    if (!running.load()) {
        return;
    }

    LogPrintf("MCPWorker: Stopping worker thread...\n");

    shouldStop.store(true);

    if (workerThread.joinable()) {
        workerThread.join();
    }

    running.store(false);

    LogPrintf("MCPWorker: Worker thread stopped\n");
}

void CDepinMCPWorker::WorkerLoop()
{
    LogPrintf("MCPWorker: Worker loop started (interval=%d seconds)\n", pollInterval);

    bool useRemotePool = (poolHost != "localhost" && poolHost != "127.0.0.1");

    while (!shouldStop.load()) {
        try {
            lastPollTime.store(GetTime());

            LogPrintf("MCPWorker: Polling for new messages (token=%s, key=%s, source=%s)...\n",
                     depinToken, commandKey, useRemotePool ? poolHost : "local");

            std::vector<CDepinMessage> messages;

            if (useRemotePool) {
                // Query remote DePIN message pool
                if (vpwallets.empty() || !vpwallets[0]) {
                    LogPrintf("MCPWorker: No wallet available for remote pool query\n");
                    std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
                    continue;
                }

                std::vector<std::string> addressList;
                addressList.push_back(nodeAddress);

                std::string error;
                if (!QueryRemoteDepinMsgPool(vpwallets[0], poolHost, poolPort, depinToken,
                                            addressList, messages, error)) {
                    LogPrintf("MCPWorker: Failed to query remote pool: %s\n", error);
                    std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
                    continue;
                }
            } else {
                // Use local pool
                if (!pDepinMsgPool) {
                    LogPrintf("MCPWorker: DePIN message pool not initialized\n");
                    std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
                    continue;
                }
                messages = pDepinMsgPool->GetAllMessages();
            }

            LogPrintf("MCPWorker: Found %d total messages in pool\n", messages.size());

            int processedThisCycle = 0;

            // Process each message
            for (const auto& msg : messages) {
                if (shouldStop.load()) {
                    break;
                }

                // Get message hash for deduplication
                uint256 hash = msg.GetHash();

                // Skip if already processed
                if (IsMessageProcessed(hash)) {
                    continue;
                }

                // Validate and process message
                if (ValidateMessage(msg)) {
                    if (ProcessMessage(msg)) {
                        MarkAsProcessed(hash);
                        totalCommandsProcessed++;
                        processedThisCycle++;
                    } else {
                        totalErrors++;
                    }
                }
            }

            if (processedThisCycle > 0) {
                LogPrintf("MCPWorker: Processed %d new commands this cycle\n", processedThisCycle);
            }

        } catch (const std::exception& e) {
            LogPrintf("MCPWorker: Exception in worker loop: %s\n", e.what());
            totalErrors++;
        }

        // Sleep until next poll
        std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
    }

    LogPrintf("MCPWorker: Worker loop exited\n");
}

bool CDepinMCPWorker::ValidateMessage(const CDepinMessage& msg)
{
    // Check if message is for our token
    if (msg.token != depinToken) {
        LogPrintf("MCPWorker: Message token '%s' != our token '%s', skipping\n", msg.token, depinToken);
        return false;
    }

    // Check if message is recent (within last 24 hours)
    int64_t now = GetTime();
    int64_t maxAge = 24 * 60 * 60; // 24 hours
    if (now - msg.timestamp > maxAge) {
        LogPrintf("MCPWorker: Skipping old message (age=%d seconds)\n",
                 now - msg.timestamp);
        return false;
    }

    // Don't process our own messages (from the bot)
    if (msg.senderAddress == nodeAddress) {
        LogPrintf("MCPWorker: Skipping own message from %s\n", msg.senderAddress);
        return false;
    }

    LogPrintf("MCPWorker: Checking message from %s (token=%s)\n", msg.senderAddress, msg.token);

    // Try to decrypt the message to check if it starts with command key
    // We need to decrypt it here to validate, then decrypt again in ProcessMessage
    // This is necessary because messages are stored encrypted
    std::string decryptedMessage;
    std::string error;

    if (!DecryptMessageForAddress(msg.encryptedPayload, nodeAddress, decryptedMessage, error)) {
        LogPrintf("MCPWorker: Could not decrypt message from %s: %s\n", msg.senderAddress, error);
        return false;
    }

    LogPrintf("MCPWorker: Decrypted message: '%s'\n", decryptedMessage);

    // Check if message starts with command key
    if (decryptedMessage.find(commandKey) != 0) {
        LogPrintf("MCPWorker: Message does not start with command key '%s'\n", commandKey);
        return false;
    }

    LogPrintf("MCPWorker: Valid AI command from %s: %s\n",
             msg.senderAddress, decryptedMessage);

    return true;
}

bool CDepinMCPWorker::ExtractCommand(const std::string& message, std::string& command)
{
    // Remove command key prefix
    if (message.find(commandKey) != 0) {
        return false;
    }

    // Extract text after command key
    command = message.substr(commandKey.length());

    // Trim leading/trailing whitespace
    size_t start = command.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        command = "";
        return false;
    }

    size_t end = command.find_last_not_of(" \t\r\n");
    command = command.substr(start, end - start + 1);

    // Validate command length
    if (command.empty()) {
        return false;
    }

    if (command.length() > 1000) {
        LogPrintf("MCPWorker: Command too long (%d characters), truncating\n", command.length());
        command = command.substr(0, 1000);
    }

    LogPrint(BCLog::NET, "MCPWorker: Extracted command: %s\n", command);

    return true;
}

bool CDepinMCPWorker::ProcessMessage(const CDepinMessage& msg)
{
    LogPrintf("MCPWorker: Processing message from %s\n", msg.senderAddress);

    // Check rate limit
    if (!CheckRateLimit(msg.senderAddress)) {
        LogPrintf("MCPWorker: Rate limit exceeded for %s\n", msg.senderAddress);

        // Send rate limit message
        std::string rateLimitMsg = "Rate limit exceeded. Please wait before sending more commands.";
        SendResponse(rateLimitMsg, msg.senderAddress);

        return false;
    }

    // Decrypt message first
    std::string decryptedMessage;
    std::string error;

    if (!DecryptMessageForAddress(msg.encryptedPayload, nodeAddress, decryptedMessage, error)) {
        LogPrintf("MCPWorker: Failed to decrypt message: %s\n", error);
        return false;
    }

    // Extract command
    std::string command;
    if (!ExtractCommand(decryptedMessage, command)) {
        LogPrintf("MCPWorker: Failed to extract command from message\n");
        return false;
    }

    // Send to MCP server
    std::string response;
    if (!mcpClient->SendPrompt(command, response)) {
        LogPrintf("MCPWorker: Failed to get response from MCP server\n");

        // Send error message
        std::string errorMsg = "Error: Failed to get response from AI server. Please try again later.";
        SendResponse(errorMsg, msg.senderAddress);

        return false;
    }

    LogPrintf("MCPWorker: Received response from MCP (%d bytes)\n", response.length());

    // Send response back to channel
    if (!SendResponse(response, msg.senderAddress)) {
        LogPrintf("MCPWorker: Failed to send response to channel\n");
        return false;
    }

    LogPrintf("MCPWorker: Successfully processed command and sent response\n");
    return true;
}

bool CDepinMCPWorker::SendResponse(const std::string& response, const std::string& originalSender)
{
    try {
        // Add prefix if configured
        std::string finalResponse = response;
        if (!responsePrefix.empty()) {
            finalResponse = responsePrefix + " " + response;
        }

        // Limit response length
        if (finalResponse.length() > 2000) {
            LogPrintf("MCPWorker: Response too long (%d characters), truncating\n", finalResponse.length());
            finalResponse = finalResponse.substr(0, 1997) + "...";
        }

        LogPrintf("MCPWorker: Sending response to channel (length=%d)\n", finalResponse.length());

        // Get wallet
        if (vpwallets.empty() || !vpwallets[0]) {
            LogPrintf("MCPWorker: No wallet available\n");
            return false;
        }

        CWallet* pwallet = vpwallets[0];

        // Validate node address
        CTxDestination dest = DecodeDestination(nodeAddress);
        if (!IsValidDestination(dest)) {
            LogPrintf("MCPWorker: Invalid node address: %s\n", nodeAddress);
            return false;
        }

        // Get token holders for encryption
        std::string error;
        std::vector<std::string> holders = GetTokenHolders(depinToken, MAX_DEPIN_RECIPIENTS, error);

        if (holders.empty()) {
            LogPrintf("MCPWorker: Failed to get token holders: %s\n", error);
            return false;
        }

        // Create message
        CDepinMessage newMsg;
        newMsg.token = depinToken;
        newMsg.senderAddress = nodeAddress;
        newMsg.timestamp = GetTime();

        // Encrypt message for all token holders
        if (!EncryptMessageForAllRecipients(finalResponse, holders, newMsg.encryptedPayload, error)) {
            LogPrintf("MCPWorker: Failed to encrypt message: %s\n", error);
            return false;
        }

        LogPrintf("MCPWorker: Encrypted message for %d recipients, size: %d bytes\n",
                  holders.size(), newMsg.encryptedPayload.size());

        // Sign message using wallet
        if (!SignDepinMessage(newMsg, nodeAddress)) {
            LogPrintf("MCPWorker: Failed to sign message\n");
            return false;
        }

        // Add to pool (requires 3 parameters)
        std::string addError;
        if (!pDepinMsgPool->AddMessage(newMsg, addError, false)) {
            LogPrintf("MCPWorker: Failed to add message to pool: %s\n", addError);
            return false;
        }

        LogPrintf("MCPWorker: Response sent successfully\n");
        return true;

    } catch (const std::exception& e) {
        LogPrintf("MCPWorker: Exception sending response: %s\n", e.what());
        return false;
    }
}

bool CDepinMCPWorker::IsMessageProcessed(const uint256& hash)
{
    LOCK(cs_processed);
    return processedMessages.count(hash) > 0;
}

void CDepinMCPWorker::MarkAsProcessed(const uint256& hash)
{
    LOCK(cs_processed);
    processedMessages.insert(hash);

    // Limit cache size to prevent memory growth
    // Keep only the most recent 1000 entries
    if (processedMessages.size() > 1000) {
        // Remove oldest entry (first in set)
        auto it = processedMessages.begin();
        processedMessages.erase(it);
    }
}

bool CDepinMCPWorker::CheckRateLimit(const std::string& address)
{
    // If rate limiting is disabled, always allow
    if (rateLimitPerMinute == 0) {
        return true;
    }

    LOCK(cs_rateLimit);

    int64_t now = GetTime();
    int64_t windowStart = now - 60; // Last 60 seconds

    auto& timestamps = rateLimitMap[address];

    // Remove timestamps outside the window
    while (!timestamps.empty() && timestamps.front() < windowStart) {
        timestamps.pop_front();
    }

    // Check if limit exceeded
    if (timestamps.size() >= static_cast<size_t>(rateLimitPerMinute)) {
        LogPrint(BCLog::NET, "MCPWorker: Rate limit exceeded for %s (%d/%d)\n",
                 address, timestamps.size(), rateLimitPerMinute);
        return false;
    }

    // Add current timestamp
    timestamps.push_back(now);

    return true;
}
