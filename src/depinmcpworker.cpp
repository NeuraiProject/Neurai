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
#include "streams.h"
#include "clientversion.h"

#include <algorithm>
#include <chrono>
#include <fstream>

// External declarations
extern std::vector<CWalletRef> vpwallets;

// Global instance
std::unique_ptr<CDepinMCPWorker> g_depinMCPWorker = nullptr;

CDepinMCPWorker::CDepinMCPWorker()
    : running(false),
      shouldStop(false),
      tasksInFlight(0),
      concurrency(DEFAULT_DEPIN_MCP_CONCURRENCY),
      pollInterval(10),
      rateLimitPerMinute(0),
      globalRateLimitPerMinute(0),
      contextSize(DEFAULT_DEPIN_MCP_CONTEXT),
      fragmentSize(DEFAULT_DEPIN_MCP_FRAG_SIZE),
      maxFragments(DEFAULT_DEPIN_MCP_MAX_FRAGMENTS),
      poolPort(19002),
      processedDirty(false),
      totalCommandsProcessed(0),
      totalErrors(0),
      totalRateLimited(0),
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
                                 const std::string& pHost, int pPort,
                                 int maxTokens, double temperature,
                                 int conc, int ctxSize,
                                 int globalRateLimit,
                                 int fragSize, int maxFrags)
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
    globalRateLimitPerMinute = globalRateLimit;
    contextSize = ctxSize < 0 ? 0 : ctxSize;
    // Conversation context works in user/assistant pairs; keep it even.
    if (contextSize % 2 != 0) contextSize += 1;
    fragmentSize = fragSize > 0 ? fragSize : DEFAULT_DEPIN_MCP_FRAG_SIZE;
    maxFragments = maxFrags > 0 ? maxFrags : DEFAULT_DEPIN_MCP_MAX_FRAGMENTS;
    concurrency = conc > 0 ? conc : 1;
    poolHost = pHost;
    poolPort = pPort;

    if (poolHost == "localhost" || poolHost == "127.0.0.1") {
        LogPrintf("MCPWorker: Using LOCAL DePIN message pool\n");
    } else {
        LogPrintf("MCPWorker: Using REMOTE DePIN message pool at %s:%d\n", poolHost, poolPort);
    }

    // Create MCP client
    mcpClient = std::make_unique<CDepinMCPClient>(url, endpoint, apiKey, timeout,
                                                  maxTokens, temperature);

    // Fetch model name from MCP server
    LogPrintf("MCPWorker: Fetching model information from MCP server...\n");
    if (mcpClient->FetchModelName()) {
        LogPrintf("MCPWorker: AI Model loaded: %s\n", mcpClient->GetModelName());
    } else {
        LogPrintf("MCPWorker: WARNING - Could not fetch model name. Will try to get it from responses.\n");
    }

    // Test connection to MCP server
    LogPrintf("MCPWorker: Testing connection to MCP server...\n");
    if (!mcpClient->TestConnection()) {
        LogPrintf("MCPWorker: WARNING - Failed to connect to MCP server. Worker will continue but commands may fail.\n");
        // Don't return false - allow worker to start and retry later
    } else {
        LogPrintf("MCPWorker: Successfully connected to MCP server\n");
    }

    LogPrintf("MCPWorker: Initialization complete (concurrency=%d, context=%d, globalRateLimit=%d)\n",
              concurrency, contextSize, globalRateLimitPerMinute);

    // Load previously processed messages from disk
    if (!LoadProcessedMessages()) {
        LogPrintf("MCPWorker: WARNING - Could not load processed messages from disk\n");
    }

    return true;
}

bool CDepinMCPWorker::Start()
{
    if (running.load()) {
        LogPrintf("MCPWorker: Already running\n");
        return false;
    }

    LogPrintf("MCPWorker: Starting worker (%d task threads)...\n", concurrency);

    shouldStop.store(false);
    running.store(true);

    // Spawn task pool first so the queue has consumers, then the poller.
    for (int i = 0; i < concurrency; i++) {
        taskPool.emplace_back(&CDepinMCPWorker::TaskLoop, this);
    }
    workerThread = std::thread(&CDepinMCPWorker::WorkerLoop, this);

    LogPrintf("MCPWorker: Worker started\n");
    return true;
}

void CDepinMCPWorker::Stop()
{
    if (!running.load()) {
        return;
    }

    LogPrintf("MCPWorker: Stopping worker...\n");

    shouldStop.store(true);
    taskCv.notify_all();

    if (workerThread.joinable()) {
        workerThread.join();
    }

    taskCv.notify_all();
    for (auto& t : taskPool) {
        if (t.joinable()) t.join();
    }
    taskPool.clear();

    running.store(false);

    // Save processed messages before exiting
    FlushProcessedIfDirty();

    LogPrintf("MCPWorker: Worker stopped\n");
}

void CDepinMCPWorker::WorkerLoop()
{
    LogPrintf("MCPWorker: Poller loop started (interval=%d seconds)\n", pollInterval);

    bool useRemotePool = (poolHost != "localhost" && poolHost != "127.0.0.1");

    while (!shouldStop.load()) {
        try {
            lastPollTime.store(GetTime());

            LogPrintf("MCPWorker: Polling for new messages (token=%s, key=%s, source=%s)...\n",
                     depinToken, commandKey, useRemotePool ? poolHost : "local");

            std::vector<CDepinMessage> messages;

#ifdef ENABLE_DEPIN_GATEWAY
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
#else
            if (useRemotePool) {
                // Should be unreachable: init.cpp refuses to start with a remote pool host
                // when the gateway is not compiled in. Guard anyway.
                LogPrintf("MCPWorker: Remote pool query is disabled in this build (requires ENABLE_DEPIN_GATEWAY)\n");
                std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
                continue;
            } else {
#endif
                // Use local pool
                if (!pDepinMsgPool) {
                    LogPrintf("MCPWorker: DePIN message pool not initialized\n");
                    std::this_thread::sleep_for(std::chrono::seconds(pollInterval));
                    continue;
                }
                messages = pDepinMsgPool->GetAllMessages();
            }

            LogPrintf("MCPWorker: Found %d total messages in pool\n", messages.size());

            int enqueuedThisCycle = 0;

            // Validate each message and hand the new ones to the task pool.
            for (const auto& msg : messages) {
                if (shouldStop.load()) {
                    break;
                }

                uint256 hash = msg.GetHash();
                if (IsMessageProcessed(hash)) {
                    continue;
                }

                std::string decrypted;
                if (ValidateMessage(msg, decrypted)) {
                    // Mark only after a successful enqueue so dropped/aborted messages retry.
                    if (EnqueueTask(msg.senderAddress, decrypted)) {
                        MarkAsProcessed(hash);
                        enqueuedThisCycle++;
                    }
                }
            }

            if (enqueuedThisCycle > 0) {
                LogPrintf("MCPWorker: Enqueued %d new commands this cycle\n", enqueuedThisCycle);
            }

            // Bound memory and persist the dedup cache at most once per cycle.
            CleanupStaleState();
            FlushProcessedIfDirty();

        } catch (const std::exception& e) {
            LogPrintf("MCPWorker: Exception in poller loop: %s\n", e.what());
            totalErrors++;
        }

        // Interruptible sleep until next poll
        for (int slept = 0; slept < pollInterval * 5 && !shouldStop.load(); slept++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    LogPrintf("MCPWorker: Poller loop exited\n");
}

void CDepinMCPWorker::TaskLoop()
{
    while (true) {
        std::pair<std::string, std::string> task;
        {
            std::unique_lock<std::mutex> lk(taskMutex);
            taskCv.wait(lk, [this] { return shouldStop.load() || !taskQueue.empty(); });
            if (shouldStop.load() && taskQueue.empty()) {
                return;
            }
            if (taskQueue.empty()) {
                continue;
            }
            task = taskQueue.front();
            taskQueue.pop_front();
        }
        // Wake any producer waiting for queue space.
        taskCv.notify_all();

        tasksInFlight++;
        try {
            ProcessTask(task.first, task.second);
        } catch (const std::exception& e) {
            LogPrintf("MCPWorker: Exception processing task: %s\n", e.what());
            totalErrors++;
        }
        tasksInFlight--;
    }
}

bool CDepinMCPWorker::EnqueueTask(const std::string& sender, const std::string& decryptedMessage)
{
    std::unique_lock<std::mutex> lk(taskMutex);
    taskCv.wait(lk, [this] { return shouldStop.load() || taskQueue.size() < MCP_MAX_TASK_QUEUE; });
    if (shouldStop.load()) {
        return false;
    }
    taskQueue.emplace_back(sender, decryptedMessage);
    lk.unlock();
    taskCv.notify_all();
    return true;
}

void CDepinMCPWorker::ProcessTask(const std::string& sender, const std::string& decryptedMessage)
{
    LogPrintf("MCPWorker: Processing command from %s\n", sender);

    // Rate limiting: global first (cheaper to reject), then per-sender.
    if (!CheckGlobalRateLimit() || !CheckRateLimit(sender)) {
        LogPrintf("MCPWorker: Rate limit exceeded for %s\n", sender);
        totalRateLimited++;
        SendResponse("Rate limit exceeded. Please wait before sending more commands.", sender);
        return;
    }

    // Extract command (text after the prefix)
    std::string command;
    if (!ExtractCommand(decryptedMessage, command)) {
        LogPrintf("MCPWorker: Failed to extract command from message\n");
        totalErrors++;
        return;
    }

    // Special command: clear this sender's conversation context.
    if (contextSize > 0 && command == "reset") {
        ResetContext(sender);
        SendResponse("Conversation context cleared.", sender);
        totalCommandsProcessed++;
        return;
    }

    // Send to MCP server, with conversation context when enabled.
    std::string response;
    std::vector<std::string> context;
    if (contextSize > 0) {
        context = GetContext(sender);
    }

    if (!mcpClient->SendWithContext(command, context, response)) {
        LogPrintf("MCPWorker: Failed to get response from MCP server\n");
        totalErrors++;
        SendResponse("Error: Failed to get response from AI server. Please try again later.", sender);
        return;
    }

    LogPrintf("MCPWorker: Received response from MCP (%d bytes)\n", response.length());

    if (contextSize > 0) {
        AppendContext(sender, command, response);
    }

    if (SendResponse(response, sender)) {
        LogPrintf("MCPWorker: Successfully processed command and sent response\n");
        totalCommandsProcessed++;
    } else {
        LogPrintf("MCPWorker: Failed to send response to channel\n");
        totalErrors++;
    }
}

bool CDepinMCPWorker::ValidateMessage(const CDepinMessage& msg, std::string& decryptedOut)
{
    // Check if message is for our token
    if (msg.token != depinToken) {
        return false;
    }

    // Check if message is recent (within last 24 hours)
    int64_t now = GetTime();
    int64_t maxAge = 24 * 60 * 60; // 24 hours
    if (now - msg.timestamp > maxAge) {
        return false;
    }

    // Don't process our own messages (from the bot)
    if (msg.senderAddress == nodeAddress) {
        return false;
    }

    // Decrypt the message ONCE here; the decrypted text is reused by the task thread.
    std::string error;
    if (!DecryptMessageForAddress(msg.encryptedPayload, nodeAddress, decryptedOut, error)) {
        LogPrint(BCLog::NET, "MCPWorker: Could not decrypt message from %s: %s\n", msg.senderAddress, error);
        return false;
    }

    // Check if message starts with command key
    if (decryptedOut.find(commandKey) != 0) {
        return false;
    }

    LogPrintf("MCPWorker: Accepted command from %s\n", msg.senderAddress);
    return true;
}

bool CDepinMCPWorker::ExtractCommand(const std::string& message, std::string& command)
{
    if (message.find(commandKey) != 0) {
        return false;
    }

    command = message.substr(commandKey.length());

    // Trim surrounding whitespace
    size_t start = command.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        command.clear();
        return true; // empty command is allowed (e.g. just "/ai")
    }
    size_t end = command.find_last_not_of(" \t\r\n");
    command = command.substr(start, end - start + 1);

    // Cap input length to keep request payloads bounded.
    if (command.length() > MCP_MAX_COMMAND_CHARS) {
        LogPrintf("MCPWorker: Command too long (%d chars), truncating to %d\n",
                  command.length(), (int)MCP_MAX_COMMAND_CHARS);
        command = command.substr(0, MCP_MAX_COMMAND_CHARS);
    }

    LogPrint(BCLog::NET, "MCPWorker: Extracted command: %s\n", command);
    return true;
}

bool CDepinMCPWorker::SendPooledMessage(const std::string& text, const std::vector<std::string>& holders)
{
    if (vpwallets.empty() || !vpwallets[0]) {
        LogPrintf("MCPWorker: No wallet available\n");
        return false;
    }

    // Validate node address
    CTxDestination dest = DecodeDestination(nodeAddress);
    if (!IsValidDestination(dest)) {
        LogPrintf("MCPWorker: Invalid node address: %s\n", nodeAddress);
        return false;
    }

    CDepinMessage newMsg;
    newMsg.token = depinToken;
    newMsg.senderAddress = nodeAddress;
    newMsg.timestamp = GetTime();

    std::string error;
    if (!EncryptMessageForAllRecipients(text, holders, newMsg.encryptedPayload, error)) {
        LogPrintf("MCPWorker: Failed to encrypt message: %s\n", error);
        return false;
    }

    if (!SignDepinMessage(newMsg, nodeAddress)) {
        LogPrintf("MCPWorker: Failed to sign message\n");
        return false;
    }

    std::string addError;
    if (!pDepinMsgPool->AddMessage(newMsg, addError, false)) {
        LogPrintf("MCPWorker: Failed to add message to pool: %s\n", addError);
        return false;
    }

    return true;
}

bool CDepinMCPWorker::SendResponse(const std::string& response, const std::string& originalSender)
{
    try {
        // Build the response prefix (only prepended to the first fragment).
        std::string prefixPart;
        if (!responsePrefix.empty()) {
            std::string modelInfo = mcpClient ? mcpClient->GetModelName() : "unknown";
            prefixPart = responsePrefix + " [" + modelInfo + "] ";
        }

        // Fetch token holders once for all fragments.
        std::string error;
        std::vector<std::string> holders = GetTokenHolders(depinToken, MAX_DEPIN_RECIPIENTS, error);
        if (holders.empty()) {
            LogPrintf("MCPWorker: Failed to get token holders: %s\n", error);
            return false;
        }

        // Split the response into fragments instead of hard-truncating.
        int fsize = fragmentSize > 0 ? fragmentSize : DEFAULT_DEPIN_MCP_FRAG_SIZE;
        std::vector<std::string> chunks;
        size_t pos = 0;
        while (pos < response.size() && (int)chunks.size() < maxFragments) {
            chunks.push_back(response.substr(pos, fsize));
            pos += fsize;
        }
        if (chunks.empty()) {
            chunks.push_back(""); // edge case: empty AI response
        }
        bool truncated = pos < response.size();
        int n = (int)chunks.size();

        if (truncated) {
            LogPrintf("MCPWorker: Response exceeds %d fragments of %d chars, truncating tail\n",
                      maxFragments, fsize);
        }

        bool ok = true;
        for (int i = 0; i < n; i++) {
            std::string text;
            if (n > 1) {
                text += "(" + std::to_string(i + 1) + "/" + std::to_string(n) + ") ";
            }
            if (i == 0) {
                text += prefixPart;
            }
            text += chunks[i];
            if (i == n - 1 && truncated) {
                text += " [...]";
            }

            if (!SendPooledMessage(text, holders)) {
                ok = false;
                break;
            }
        }

        if (ok) {
            LogPrintf("MCPWorker: Response sent successfully in %d fragment(s) to %d recipients\n",
                      n, (int)holders.size());
        }
        return ok;

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
    if (processedMessages.insert(hash).second) {
        processedOrder.push_back(hash);
        processedDirty = true;

        // FIFO eviction: drop the oldest entries first (insertion order),
        // not the lowest hash value.
        while (processedOrder.size() > MCP_MAX_PROCESSED_CACHE) {
            const uint256& oldest = processedOrder.front();
            processedMessages.erase(oldest);
            processedOrder.pop_front();
        }
    }
}

bool CDepinMCPWorker::CheckRateLimit(const std::string& address)
{
    if (rateLimitPerMinute == 0) {
        return true;
    }

    LOCK(cs_rateLimit);

    int64_t now = GetTime();
    int64_t windowStart = now - 60; // Last 60 seconds

    auto& timestamps = rateLimitMap[address];

    while (!timestamps.empty() && timestamps.front() < windowStart) {
        timestamps.pop_front();
    }

    if (timestamps.size() >= static_cast<size_t>(rateLimitPerMinute)) {
        LogPrint(BCLog::NET, "MCPWorker: Per-sender rate limit exceeded for %s (%d/%d)\n",
                 address, timestamps.size(), rateLimitPerMinute);
        return false;
    }

    timestamps.push_back(now);
    return true;
}

bool CDepinMCPWorker::CheckGlobalRateLimit()
{
    if (globalRateLimitPerMinute == 0) {
        return true;
    }

    LOCK(cs_globalRate);

    int64_t now = GetTime();
    int64_t windowStart = now - 60;

    while (!globalRateTimestamps.empty() && globalRateTimestamps.front() < windowStart) {
        globalRateTimestamps.pop_front();
    }

    if (globalRateTimestamps.size() >= static_cast<size_t>(globalRateLimitPerMinute)) {
        LogPrint(BCLog::NET, "MCPWorker: Global rate limit exceeded (%d/%d)\n",
                 globalRateTimestamps.size(), globalRateLimitPerMinute);
        return false;
    }

    globalRateTimestamps.push_back(now);
    return true;
}

void CDepinMCPWorker::CleanupStaleState()
{
    int64_t now = GetTime();

    // Drop empty / fully-expired per-sender rate-limit buckets.
    {
        LOCK(cs_rateLimit);
        for (auto it = rateLimitMap.begin(); it != rateLimitMap.end();) {
            auto& dq = it->second;
            while (!dq.empty() && dq.front() < now - 60) {
                dq.pop_front();
            }
            if (dq.empty()) {
                it = rateLimitMap.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Trim the global window.
    {
        LOCK(cs_globalRate);
        while (!globalRateTimestamps.empty() && globalRateTimestamps.front() < now - 60) {
            globalRateTimestamps.pop_front();
        }
    }

    // Drop idle conversation contexts.
    if (contextSize > 0) {
        LOCK(cs_context);
        for (auto it = contextLastSeen.begin(); it != contextLastSeen.end();) {
            if (now - it->second > MCP_CONTEXT_IDLE_TTL) {
                contextMap.erase(it->first);
                it = contextLastSeen.erase(it);
            } else {
                ++it;
            }
        }
    }
}

std::vector<std::string> CDepinMCPWorker::GetContext(const std::string& sender)
{
    LOCK(cs_context);
    auto it = contextMap.find(sender);
    if (it == contextMap.end()) {
        return std::vector<std::string>();
    }
    return std::vector<std::string>(it->second.begin(), it->second.end());
}

void CDepinMCPWorker::AppendContext(const std::string& sender, const std::string& prompt, const std::string& response)
{
    LOCK(cs_context);
    auto& dq = contextMap[sender];
    dq.push_back(prompt);
    dq.push_back(response);
    while ((int)dq.size() > contextSize) {
        dq.pop_front();
    }
    contextLastSeen[sender] = GetTime();
}

void CDepinMCPWorker::ResetContext(const std::string& sender)
{
    LOCK(cs_context);
    contextMap.erase(sender);
    contextLastSeen.erase(sender);
}

fs::path CDepinMCPWorker::GetProcessedMessagesPath() const
{
    return GetDataDir() / "mcp_processed.dat";
}

bool CDepinMCPWorker::LoadProcessedMessages()
{
    fs::path path = GetProcessedMessagesPath();

    if (!fs::exists(path)) {
        LogPrintf("MCPWorker: No processed messages file found (first run)\n");
        return true;
    }

    try {
        std::ifstream file(path.string(), std::ios::binary);
        if (!file.is_open()) {
            LogPrintf("MCPWorker: Could not open processed messages file\n");
            return false;
        }

        uint32_t version = 0;
        file.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != 1) {
            LogPrintf("MCPWorker: Unknown processed messages file version: %u\n", version);
            return false;
        }

        uint32_t count = 0;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));

        if (count > 100000) {
            LogPrintf("MCPWorker: Processed messages file has too many entries: %u\n", count);
            return false;
        }

        LOCK(cs_processed);
        processedMessages.clear();
        processedOrder.clear();

        for (uint32_t i = 0; i < count; i++) {
            uint256 hash;
            file.read(reinterpret_cast<char*>(hash.begin()), 32);
            if (!file.good()) {
                LogPrintf("MCPWorker: Error reading processed messages file at entry %u\n", i);
                return false;
            }
            if (processedMessages.insert(hash).second) {
                processedOrder.push_back(hash); // preserve on-disk (FIFO) order
            }
        }

        file.close();
        processedDirty = false;
        LogPrintf("MCPWorker: Loaded %u processed message hashes from disk\n", count);
        return true;

    } catch (const std::exception& e) {
        LogPrintf("MCPWorker: Exception loading processed messages: %s\n", e.what());
        return false;
    }
}

bool CDepinMCPWorker::SaveProcessedMessages()
{
    fs::path path = GetProcessedMessagesPath();

    try {
        fs::path tempPath = path.string() + ".tmp";

        std::ofstream file(tempPath.string(), std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            LogPrintf("MCPWorker: Could not open temp file for saving\n");
            return false;
        }

        LOCK(cs_processed);

        uint32_t version = 1;
        file.write(reinterpret_cast<const char*>(&version), sizeof(version));

        uint32_t count = processedOrder.size();
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));

        // Write in FIFO order so load reconstructs eviction order.
        for (const uint256& hash : processedOrder) {
            file.write(reinterpret_cast<const char*>(hash.begin()), 32);
        }

        file.close();

        if (fs::exists(path)) {
            fs::remove(path);
        }
        fs::rename(tempPath, path);

        LogPrint(BCLog::NET, "MCPWorker: Saved %u processed message hashes to disk\n", count);
        return true;

    } catch (const std::exception& e) {
        LogPrintf("MCPWorker: Exception saving processed messages: %s\n", e.what());
        return false;
    }
}

void CDepinMCPWorker::FlushProcessedIfDirty()
{
    {
        LOCK(cs_processed);
        if (!processedDirty) {
            return;
        }
        processedDirty = false; // optimistic; restored below on failure
    }

    if (!SaveProcessedMessages()) {
        LOCK(cs_processed);
        processedDirty = true;
    }
}

size_t CDepinMCPWorker::GetProcessedCacheSize()
{
    LOCK(cs_processed);
    return processedMessages.size();
}

size_t CDepinMCPWorker::GetContextSessions()
{
    LOCK(cs_context);
    return contextMap.size();
}

std::string CDepinMCPWorker::GetModelName() const
{
    if (mcpClient) {
        return mcpClient->GetModelName();
    }
    return "unknown";
}
