// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpoolnet.h"
#include "depinmsgpool.h"
#include "rpc/server.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"
#include "streams.h"
#include "version.h"
#include "random.h"
#include "base58.h"
#include "validation.h"
#include "utiltime.h"
#include "txdb.h"
#include "assets/assets.h"   // OWNER_TAG (NIP revision 005b)

#include <cstring>
#include <sstream>

// Forward declarations of RPC functions
#ifdef ENABLE_DEPIN_GATEWAY
UniValue depinsendmsg(const JSONRPCRequest& request);
UniValue depingetmsg(const JSONRPCRequest& request);
#endif
UniValue depinreceivemsg(const JSONRPCRequest& request);
UniValue depingetmsginfo(const JSONRPCRequest& request);
UniValue depingetpoolcontent(const JSONRPCRequest& request);
UniValue depinpoolstats(const JSONRPCRequest& request);
UniValue depinmcpstatus(const JSONRPCRequest& request);
UniValue depinclearmsg(const JSONRPCRequest& request);
UniValue depinpoolpkey(const JSONRPCRequest& request);
UniValue depinsubmitmsg(const JSONRPCRequest& request);
UniValue depinlistsections(const JSONRPCRequest& request);
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
extern std::vector<CWalletRef> vpwallets;
bool DeriveDepinPoolKeys(CWallet* pwallet, CKey& privKey, CPubKey& pubkey, std::string& derivationPath, std::string& error);
#endif
#include <cstdlib>
#include <algorithm>
#include <cctype>

// Platform-specific socket headers
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// Windows socket compatibility
typedef int socklen_t;
#define close closesocket
#define SHUT_RDWR SD_BOTH
inline std::string GetSocketErrorMsg() {
    int err = WSAGetLastError();
    char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, 0, buf, sizeof(buf), NULL);
    return std::string(buf);
}
inline int GetSocketError() { return WSAGetLastError(); }
// Helper to check specific socket errors
inline bool IsSocketErrorInterrupt(int err) { return err == WSAEINTR; }
inline bool IsSocketErrorWouldBlock(int err) { return err == WSAEWOULDBLOCK; }
inline bool IsSocketErrorInProgress(int err) { return err == WSAEINPROGRESS; }
// inet_ntop compatibility for older Windows
inline const char* InetNtopCompat(int af, const void* src, char* dst, socklen_t size) {
    if (af == AF_INET) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof(struct in_addr));
        DWORD len = size;
        if (WSAAddressToStringA((struct sockaddr*)&in, sizeof(in), NULL, dst, &len) == 0) {
            return dst;
        }
    }
    return NULL;
}
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
inline std::string GetSocketErrorMsg() {
    return std::string(strerror(errno));
}
inline int GetSocketError() { return errno; }
inline bool IsSocketErrorInterrupt(int err) { return err == EINTR; }
inline bool IsSocketErrorWouldBlock(int err) { return err == EWOULDBLOCK; }
inline bool IsSocketErrorInProgress(int err) { return err == EINPROGRESS; }
inline const char* InetNtopCompat(int af, const void* src, char* dst, socklen_t size) {
    return inet_ntop(af, src, dst, size);
}
#endif

std::unique_ptr<CDepinMsgPoolServer> pDepinMsgPoolServer;

#ifdef ENABLE_WALLET
#ifdef ENABLE_DEPIN_GATEWAY
extern UniValue depinsendmsg(const JSONRPCRequest& request);
extern UniValue depingetmsg(const JSONRPCRequest& request);
#endif
extern UniValue depinreceivemsg(const JSONRPCRequest& request);
extern UniValue depingetmsginfo(const JSONRPCRequest& request);
extern UniValue depingetpoolcontent(const JSONRPCRequest& request);
extern UniValue depinpoolstats(const JSONRPCRequest& request);
extern UniValue depinmcpstatus(const JSONRPCRequest& request);
extern UniValue depinclearmsg(const JSONRPCRequest& request);
extern UniValue depinpoolpkey(const JSONRPCRequest& request);
#endif

// ===== Servidor =====

CDepinMsgPoolServer::CDepinMsgPoolServer()
    : fRunning(false), serverSocket(-1), port(0), activeClients(0),
      maxClients(DEFAULT_DEPIN_MAX_CONNECTIONS) {
}

CDepinMsgPoolServer::~CDepinMsgPoolServer() {
    Stop();
}

bool CDepinMsgPoolServer::Start(int listenPort) {
    LOCK(cs_server);

    if (fRunning) {
        LogPrintf("Chat mempool server already running\n");
        return false;
    }

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        LogPrintf("ERROR: Failed to create chat mempool server socket: %s\n", GetSocketErrorMsg().c_str());
        return false;
    }

    // Allow address reuse
    int opt = 1;
#ifdef WIN32
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
#else
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
#endif
        LogPrintf("WARNING: Failed to set SO_REUSEADDR on chat mempool socket\n");
    }

    // Configure address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    // NIP revision 005b: public by default (0.0.0.0) — the DePIN port is a
    // messaging gateway meant for remote access. -depinmsgbind lets an operator
    // restrict it to a specific interface (e.g. 127.0.0.1 for local-only use).
    std::string bindAddr = gArgs.GetArg("-depinmsgbind", "0.0.0.0");
    if (bindAddr == "0.0.0.0") {
        serverAddr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, bindAddr.c_str(), &serverAddr.sin_addr) != 1) {
        LogPrintf("ERROR: invalid -depinmsgbind address '%s'\n", bindAddr.c_str());
        close(serverSocket);
        serverSocket = -1;
        return false;
    }
    serverAddr.sin_port = htons(listenPort);

    // Bind socket
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        LogPrintf("ERROR: Failed to bind chat mempool server socket to port %d: %s\n",
                  listenPort, GetSocketErrorMsg().c_str());
        close(serverSocket);
        serverSocket = -1;
        return false;
    }

    // Listen for connections
    if (listen(serverSocket, 10) < 0) {
        LogPrintf("ERROR: Failed to listen on chat mempool server socket: %s\n", GetSocketErrorMsg().c_str());
        close(serverSocket);
        serverSocket = -1;
        return false;
    }

    port = listenPort;
    maxClients = (unsigned int)std::max<int64_t>(
        1, gArgs.GetArg("-depinmaxconnections", DEFAULT_DEPIN_MAX_CONNECTIONS));
    fRunning = true;

    // Start server thread. fRunning must be true before the thread exists
    // (the accept loop runs while fRunning), so roll it back if creation fails
    // instead of letting the exception escape with the listener still open.
    try {
        serverThread = std::thread(&CDepinMsgPoolServer::ThreadServerHandler, this);
    } catch (const std::exception& e) {
        LogPrintf("ERROR: Failed to start chat mempool server thread: %s\n", e.what());
        fRunning = false;
        close(serverSocket);
        serverSocket = -1;
        return false;
    }

    LogPrintf("Chat mempool server started on port %d\n", port);
    return true;
}

void CDepinMsgPoolServer::Stop() {
    // Idempotent: only the first caller performs the teardown.
    bool expected = true;
    if (!fRunning.compare_exchange_strong(expected, false))
        return;

    // Unblock select()/accept() in the accept loop. shutdown() only: the fd
    // must stay open (and the member unchanged) until the accept loop is
    // joined — closing it here would let the loop select()/accept() on a
    // closed, possibly kernel-reused fd, or FD_SET(-1) after the reset below.
    if (serverSocket >= 0) {
        shutdown(serverSocket, SHUT_RDWR);
    }

    // Wait for the accept loop to finish. Even if shutdown() does not wake
    // accept on some platforms, the loop's 1s select() timeout bounds this.
    if (serverThread.joinable()) {
        serverThread.join();
    }

    // No one references the listener fd anymore: safe to close and reset it
    if (serverSocket >= 0) {
        close(serverSocket);
        serverSocket = -1;
    }

    // Unblock in-flight handlers stuck in recv()/send(), then wait for all of
    // them. After this point no handler can touch shared node state.
    ShutdownClientSockets();
    JoinClientThreads();

    LogPrintf("Chat mempool server stopped\n");
}

void CDepinMsgPoolServer::ShutdownClientSockets() {
    LOCK(cs_clients);
    for (int fd : clientSockets) {
        // shutdown() only: unblocks the handler's recv()/send(). The handler
        // owns the fd and is the only one that close()s it; closing here could
        // race with the handler and hit an fd already reused by the kernel.
        shutdown(fd, SHUT_RDWR);
    }
}

void CDepinMsgPoolServer::JoinClientThreads() {
    // Move the threads out of the lock before joining: a handler needs
    // cs_clients to deregister itself from clientSockets.
    std::vector<std::thread> threads;
    {
        LOCK(cs_clients);
        for (auto& client : clientThreads) {
            if (client.thread.joinable())
                threads.push_back(std::move(client.thread));
        }
        clientThreads.clear();
    }

    for (auto& t : threads) {
        if (t.joinable())
            t.join();
    }
}

void CDepinMsgPoolServer::ReapFinishedClientThreads() {
    // Join and drop handlers that already finished, so clientThreads does not
    // grow without bound under many short-lived connections.
    std::vector<std::thread> finished;
    {
        LOCK(cs_clients);
        for (auto it = clientThreads.begin(); it != clientThreads.end();) {
            if (it->done && it->done->load()) {
                if (it->thread.joinable())
                    finished.push_back(std::move(it->thread));
                it = clientThreads.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& t : finished) {
        if (t.joinable())
            t.join();
    }
}

void CDepinMsgPoolServer::ThreadServerHandler() {
    LogPrint(BCLog::NET, "Chat mempool server thread started\n");

    while (fRunning) {
        // Reap finished handlers on every iteration (runs at least once per
        // select() timeout) to keep clientThreads bounded.
        ReapFinishedClientThreads();

        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);

        // Configure timeout for accept
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;  // 1 second timeout
        tv.tv_usec = 0;

        int activity = select(serverSocket + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0 && !IsSocketErrorInterrupt(GetSocketError())) {
            if (fRunning) {
                LogPrintf("ERROR: select() failed in chat mempool server: %s\n", GetSocketErrorMsg().c_str());
            }
            break;
        }

        if (activity == 0) {
            // Timeout, continue loop
            continue;
        }

        // Accept connection
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            int err = GetSocketError();
            if (!IsSocketErrorInterrupt(err) && !IsSocketErrorWouldBlock(err)) {
                LogPrint(BCLog::NET, "ERROR: accept() failed: %s\n", GetSocketErrorMsg().c_str());
            }
            continue;
        }

        // Reject connections accepted while the server is shutting down
        if (!fRunning) {
            close(clientSocket);
            continue;
        }

        // Limit concurrent handlers (DoS surface)
        if (activeClients.load() >= maxClients) {
            std::string busy = "ERROR|Server busy\n";
            send(clientSocket, busy.c_str(), busy.size(), 0);
            close(clientSocket);
            continue;
        }

        // Log connection
        char clientIP[INET_ADDRSTRLEN];
        InetNtopCompat(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        LogPrint(BCLog::NET, "Chat mempool: Accepted connection from %s:%d\n",
                clientIP, ntohs(clientAddr.sin_port));

        // Handle client in a managed (joinable) thread, registered so Stop()
        // can unblock and join it before node teardown.
        auto done = std::make_shared<std::atomic_bool>(false);
        std::string ip(clientIP);

        bool registered = false;
        bool counted = false;
        bool slotCreated = false;

        try {
            LOCK(cs_clients);
            clientSockets.insert(clientSocket);
            registered = true;
            activeClients.fetch_add(1);
            counted = true;

            // Create an empty slot first: if the vector throws here, no thread
            // exists yet. Do NOT construct the thread inside a temporary passed
            // to push_back — if the vector throws after the temporary thread is
            // created, the destructor of a joinable std::thread aborts.
            clientThreads.emplace_back();
            slotCreated = true;
            CDepinClientThread& client = clientThreads.back();
            client.done = done;
            client.thread = std::thread([this, clientSocket, ip, done]() {
                HandleClient(clientSocket, ip);
                done->store(true);
            });
        } catch (...) {
            // Roll back registration so no counter/fd is left without a handler
            {
                LOCK(cs_clients);
                if (slotCreated && !clientThreads.empty() && clientThreads.back().done == done)
                    clientThreads.pop_back();
                if (registered)
                    clientSockets.erase(clientSocket);
            }
            if (counted)
                activeClients.fetch_sub(1);
            close(clientSocket);
            LogPrintf("ERROR: Failed to start DePIN client handler thread\n");
            continue;
        }
    }

    LogPrint(BCLog::NET, "Chat mempool server thread terminated\n");
}

void CDepinMsgPoolServer::HandleClient(int clientSocket, std::string clientIP) {
    try {
        // Configure timeout
        struct timeval tv;
        tv.tv_sec = DEPIN_SOCKET_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

        // Read request
        std::string request;
        char buffer[4096];
        ssize_t bytesRead;
        bool fValid = true;

        while ((bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytesRead] = '\0';
            request += buffer;

            // Look for end of message (newline)
            size_t pos = request.find('\n');
            if (pos != std::string::npos) {
                request = request.substr(0, pos);
                break;
            }

            // Size limit
            if (request.size() > DEPIN_MAX_PROTOCOL_SIZE) {
                std::string error = "ERROR|Request too large\n";
                send(clientSocket, error.c_str(), error.size(), 0);
                fValid = false;
                break;
            }
        }

        if (fValid && bytesRead < 0) {
            LogPrint(BCLog::NET, "ERROR: recv() failed: %s\n", GetSocketErrorMsg().c_str());
            fValid = false;
        }

        // Do not start new work while the server is shutting down
        if (fValid && fRunning) {
            std::string response = ProcessRequest(request, clientIP);
            response += "\n";
            send(clientSocket, response.c_str(), response.size(), 0);
        }
    } catch (const std::exception& e) {
        LogPrintf("ERROR: DePIN client handler exception: %s\n", e.what());
    } catch (...) {
        LogPrintf("ERROR: DePIN client handler unknown exception\n");
    }

    // Deregister the fd BEFORE closing it: with close-then-erase, Stop() could
    // see the fd still in the set and shutdown() an fd already closed and
    // possibly reused by the kernel. The handler owns the fd: only close here.
    {
        LOCK(cs_clients);
        clientSockets.erase(clientSocket);
    }
    close(clientSocket);
    activeClients.fetch_sub(1);
}

std::string CDepinMsgPoolServer::ProcessRequest(const std::string& request, const std::string& clientIP) {
#ifdef ENABLE_DEPIN_GATEWAY
    CleanupExpiredChallenges();
#endif
    std::string jsonResponse;
    if (TryProcessJsonRpc(request, jsonResponse, clientIP)) {
        return jsonResponse;
    }

    LogPrint(BCLog::NET, "Chat mempool: Processing request: %s\n", request);

    // Parse: CMD|param1|param2|...
    std::vector<std::string> parts;
    std::stringstream ss(request);
    std::string part;

    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.empty()) {
        return "ERROR|Invalid request format";
    }

    std::string cmd = parts[0];

    // AUTH - request challenge
#ifdef ENABLE_DEPIN_GATEWAY
    if (cmd == DEPIN_CMD_AUTH) {
        if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
            return "ERROR|Chat mempool not enabled";
        }

        if (parts.size() < 3) {
            return "ERROR|Invalid AUTH format. Expected: AUTH|token|address[|SEND]";
        }

        std::string token = parts[1];
        std::string address = parts[2];
        std::string mode = parts.size() >= 4 ? parts[3] : "GET";
        std::string modeUpper = mode;
        std::transform(modeUpper.begin(), modeUpper.end(), modeUpper.begin(), ::toupper);

        // NIP revision 005b: map the mode explicitly and reject unknown modes,
        // instead of defaulting anything != SEND to RECEIVE (which would turn
        // an ADMIN request into a RECEIVE challenge).
        DepinChallengeType challengeType;
        if (modeUpper == "SEND")
            challengeType = DepinChallengeType::SEND;
        else if (modeUpper == "GET" || modeUpper == "RECEIVE")
            challengeType = DepinChallengeType::RECEIVE;
        else if (modeUpper == "ADMIN")
            challengeType = DepinChallengeType::ADMIN;
        else
            return "ERROR|Unknown AUTH mode";

        std::string error;
        std::string challenge = IssueChallenge(token, address, clientIP, challengeType, error);
        if (challenge.empty()) {
            return "ERROR|" + error;
        }

        return strprintf("CHALLENGE|%s|%d", challenge, DEPIN_CHALLENGE_TIMEOUT);
    }
#else
    if (cmd == DEPIN_CMD_AUTH) {
        return "ERROR|AUTH command is disabled in this build";
    }
#endif

    // PING
    if (cmd == DEPIN_CMD_PING) {
        return "OK|PONG";
    }

    // INFO
    if (cmd == DEPIN_CMD_INFO) {
        if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
            return "ERROR|Chat mempool not enabled";
        }

        std::string token = pDepinMsgPool->GetActiveToken();
        int port = (int)pDepinMsgPool->GetPort();
        std::string cipher = pDepinMsgPool->GetEncryptionCipher();
        int maxRecipients = (int)pDepinMsgPool->GetMaxRecipients();
        int maxMessageSize = (int)pDepinMsgPool->GetMaxMessageSize();
        int messageExpiryHours = (int)pDepinMsgPool->GetMessageExpiryHours();
        int maxPoolSizeMB = (int)pDepinMsgPool->GetMaxPoolSizeMB();
        int messageCount = (int)pDepinMsgPool->Size();
        size_t memoryUsage = pDepinMsgPool->DynamicMemoryUsage();

        int64_t oldest = pDepinMsgPool->GetOldestMessageTime();
        int64_t newest = pDepinMsgPool->GetNewestMessageTime();

        std::string oldestStr = (oldest > 0) ? DateTimeStrFormat("%Y-%m-%d %H:%M:%S", oldest) : "N/A";
        std::string newestStr = (newest > 0) ? DateTimeStrFormat("%Y-%m-%d %H:%M:%S", newest) : "N/A";

        // depinpoolpkey integration
        std::string poolPKey = "0";
#ifdef ENABLE_WALLET
        if (!vpwallets.empty() && vpwallets[0] && !vpwallets[0]->IsCrypted()) {
            CPubKey pubkey;
            CKey privKey;
            std::string derivationPath;
            std::string error;
            if (DeriveDepinPoolKeys(vpwallets[0], privKey, pubkey, derivationPath, error)) {
                poolPKey = HexStr(pubkey.begin(), pubkey.end());
            }
        }
#endif

        return strprintf("OK|%s|%d|%s|%d|%d|%d|%d|%d|%d|%s|%s|%s",
                        token, port, cipher, maxRecipients, maxMessageSize,
                        messageExpiryHours, maxPoolSizeMB, messageCount,
                        (int)memoryUsage, oldestStr, newestStr, poolPKey);
    }

    // GETMESSAGES
#ifdef ENABLE_DEPIN_GATEWAY
    if (cmd == DEPIN_CMD_GETMESSAGES) {
        if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
            return "ERROR|Chat mempool not enabled";
        }

        if (parts.size() < 6) {
            return "ERROR|Authentication required. Use AUTH command first";
        }

        std::string token = parts[1];
        std::string addressesStr = parts[2];
        std::string authAddress = parts[3];
        std::string signature = parts[4];
        std::string challenge = parts[5];

        std::string error;

        if (!ValidateChallenge(token, authAddress, clientIP, challenge, DepinChallengeType::RECEIVE, error)) {
            return "ERROR|" + error;
        }

        std::string messageToSign = strprintf("DEPIN-GET|%s|%s|%s", token, authAddress, challenge);
        if (!VerifyChallengeSignature(authAddress, signature, messageToSign, error)) {
            return "ERROR|" + error;
        }

        // Verify token: the active token or a section inside its subtree. The
        // challenge above was bound to this same token at issue time, so a
        // section challenge cannot be replayed against the root.
        if (!IsDepinSectionOrRoot(token, pDepinMsgPool->GetActiveToken())) {
            return strprintf("ERROR|Token mismatch. Server has: %s", pDepinMsgPool->GetActiveToken());
        }

        // Only a single address is ever accepted (see the check below), so
        // reject anything that cannot be one before splitting: the request as a
        // whole may be up to DEPIN_MAX_PROTOCOL_SIZE (10 MB), and splitting a
        // multi-megabyte comma list just to reject it afterwards is free work
        // for an attacker, done while holding cs_depinmsgpool downstream.
        if (addressesStr.size() > MAX_DEPIN_ADDRESS_FIELD_SIZE) {
            return "ERROR|Address field too large";
        }

        // Parse addresses
        std::vector<std::string> addresses;
        std::stringstream addrSS(addressesStr);
        std::string addr;
        while (std::getline(addrSS, addr, ',')) {
            addresses.push_back(addr);
        }

        if (addresses.empty()) {
            return "ERROR|No addresses provided";
        }

        // The challenge/signature above only proves control of authAddress, so
        // the request may not ask for anything else: previously it was enough
        // for authAddress to appear somewhere in the list, and every listed
        // address was then served, letting any authenticated holder pull the
        // encrypted payloads addressed to someone else. Exactly one address,
        // and it must be the authenticated one.
        if (addresses.size() != 1 || addresses[0] != authAddress) {
            return "ERROR|Only the authenticated address may be queried";
        }

        try {
            // The requested token is the scope: a section query returns only
            // that section's subtree, the root returns the whole pool.
            std::vector<CDepinMessage> messages = pDepinMsgPool->GetMessagesForAddress(authAddress, token);

            // Serialize messages with exception handling
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << messages;

            // Convert to hex
            std::string hex = HexStr(ss.begin(), ss.end());

            LogPrint(BCLog::NET, "GETMESSAGES: Successfully serialized %d messages for %s\n",
                    messages.size(), authAddress);

            return "OK|" + hex;
        } catch (const std::exception& e) {
            LogPrintf("ERROR: Failed to serialize messages for GETMESSAGES: %s\n", e.what());
            return strprintf("ERROR|Failed to serialize messages: %s", e.what());
        }
    }
#else
    if (cmd == DEPIN_CMD_GETMESSAGES) {
        return "ERROR|GETMESSAGES command is disabled in this build";
    }
#endif

    return "ERROR|Unknown command: " + cmd;
}

bool CDepinMsgPoolServer::TryProcessJsonRpc(const std::string& request, std::string& response, const std::string& clientIP) {
    UniValue valRequest;
    if (!valRequest.read(request)) {
        return false;
    }

    if (!valRequest.isObject() || !valRequest.exists("method")) {
        return false;
    }

    try {
        response = ProcessJsonRpcRequest(valRequest, clientIP);
    } catch (const std::exception& e) {
        UniValue error = JSONRPCError(RPC_PARSE_ERROR, e.what());
        UniValue reply = JSONRPCReplyObj(NullUniValue, error,
                                         valRequest.exists("id") ? valRequest["id"] : NullUniValue);
        response = reply.write();
    }

    return true;
}

std::string CDepinMsgPoolServer::ProcessJsonRpcRequest(const UniValue& valRequest, const std::string& clientIP) {
    UniValue id = valRequest.exists("id") ? valRequest["id"] : NullUniValue;

    const UniValue& methodVal = valRequest["method"];
    if (!methodVal.isStr()) {
        UniValue reply = JSONRPCReplyObj(NullUniValue,
                                         JSONRPCError(RPC_INVALID_REQUEST, "'method' must be a string"),
                                         id);
        return reply.write();
    }

    JSONRPCRequest jsonRequest;
    jsonRequest.strMethod = methodVal.get_str();
    jsonRequest.fHelp = false;
    jsonRequest.URI = "/";
    jsonRequest.authUser = "depin-port";

    if (valRequest.exists("params")) {
        jsonRequest.params = valRequest["params"];
    } else {
        jsonRequest.params.setArray();
    }

    // Check if it's a DePIN command
    if (jsonRequest.strMethod.find("depin") != 0) {
        return JSONRPCReply(NullUniValue, JSONRPCError(RPC_METHOD_NOT_FOUND, "Only DePIN commands are allowed on this port"), id);
    }

#ifndef ENABLE_DEPIN_GATEWAY
    // NIP revision 005b: without the gateway (challenge/signature) compiled in,
    // depinclearmsg cannot be authenticated over the DePIN port. Fail closed;
    // the operator can still run it via the authenticated node RPC.
    if (jsonRequest.strMethod == "depinclearmsg") {
        return JSONRPCReply(NullUniValue,
            JSONRPCError(RPC_INVALID_REQUEST,
                "depinclearmsg is not available over the DePIN port in this build; use node RPC"), id);
    }
#endif

    // 1. Mandatory Pre-auth for Legacy/Gateway commands
#ifdef ENABLE_DEPIN_GATEWAY
    if (jsonRequest.strMethod == "depinsendmsg" || jsonRequest.strMethod == "depingetmsg") {
        size_t paramCount = jsonRequest.params.size();
        if (paramCount < 4) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, "Insufficient parameters for remote call"),
                                             id);
            return reply.write();
        }

        if (!jsonRequest.params[3].isStr()) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, "fromaddress is required for remote call"),
                                             id);
            return reply.write();
        }

        std::string token = jsonRequest.params[0].get_str();
        std::string fromAddress = jsonRequest.params[3].get_str();
        std::string challenge = jsonRequest.params[paramCount - 2].get_str();
        std::string signature = jsonRequest.params[paramCount - 1].get_str();

        if (challenge.empty() || signature.empty()) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, "Challenge and signature cannot be empty"),
                                             id);
            return reply.write();
        }

        std::string authError;
        DepinChallengeType challengeType = (jsonRequest.strMethod == "depinsendmsg") ? DepinChallengeType::SEND : DepinChallengeType::RECEIVE;
        if (!ValidateChallenge(token, fromAddress, clientIP, challenge, challengeType, authError)) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, authError),
                                             id);
            return reply.write();
        }

        std::string messageToSign = strprintf("DEPIN-%s|%s|%s|%s",
                                              (jsonRequest.strMethod == "depinsendmsg" ? "SEND" : "GET"),
                                              token, fromAddress, challenge);
        if (!VerifyChallengeSignature(fromAddress, signature, messageToSign, authError)) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, authError),
                                             id);
            return reply.write();
        }

        // Trim challenge and signature from params for the actual RPC call
        UniValue trimmed(UniValue::VARR);
        for (size_t i = 0; i < paramCount - 2; ++i) {
            trimmed.push_back(jsonRequest.params[i]);
        }
        jsonRequest.params = trimmed;
        jsonRequest.fSkipWalletCheck = true; // Skip wallet check for authenticated gateway calls
    }

    // NIP revision 005b: depinclearmsg is a destructive operation. Over the
    // DePIN port it requires a challenge-signature from an OWNER. The node-RPC
    // path is unchanged (the operator is already authenticated by
    // rpcuser/rpcpassword).
    // Remote params, two accepted shapes:
    //   [ mode_or_null, admin_address, challenge, signature ]           (pool-wide)
    //   [ mode_or_null, scope, admin_address, challenge, signature ]    (one subtree)
    // With a scope, the ADMIN challenge must have been issued FOR that scope
    // token, and owner authority is inherited: the owner of the section or of
    // any ancestor up to the pool root. Purging a subtree never touches
    // parents or siblings -- the same shape of authority as reading and
    // writing there, and purging upward would be an escalation.
    if (jsonRequest.strMethod == "depinclearmsg") {
        if (jsonRequest.params.size() != 4 && jsonRequest.params.size() != 5) {
            return JSONRPCReply(NullUniValue,
                JSONRPCError(RPC_INVALID_PARAMETER,
                    "depinclearmsg over the DePIN port expects [mode, address, challenge, signature] "
                    "or [mode, scope, address, challenge, signature]"), id);
        }

        const bool hasScope = (jsonRequest.params.size() == 5);
        const size_t base = hasScope ? 2 : 1;

        // Validate types before get_str() to return a clean error.
        for (size_t i = base; i < base + 3; ++i) {
            if (!jsonRequest.params[i].isStr()) {
                return JSONRPCReply(NullUniValue,
                    JSONRPCError(RPC_INVALID_PARAMETER, "address, challenge and signature must be strings"), id);
            }
        }
        if (hasScope && !jsonRequest.params[1].isStr()) {
            return JSONRPCReply(NullUniValue,
                JSONRPCError(RPC_INVALID_PARAMETER, "scope must be a string"), id);
        }

        const UniValue modeParam = jsonRequest.params[0];
        std::string scope     = hasScope ? jsonRequest.params[1].get_str() : "";
        std::string address   = jsonRequest.params[base].get_str();
        std::string challenge = jsonRequest.params[base + 1].get_str();
        std::string signature = jsonRequest.params[base + 2].get_str();
        const std::string activeToken = pDepinMsgPool ? pDepinMsgPool->GetActiveToken() : "";
        const std::string authToken = scope.empty() ? activeToken : scope;

        std::string authError;
        if (!scope.empty() && !IsDepinSectionOrRoot(scope, activeToken)) {
            return JSONRPCReply(NullUniValue,
                JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Scope '%s' is not configured token '%s' or a section inside it",
                              scope, activeToken)), id);
        }

        // 1) The challenge (issued only to an owner, see IssueChallenge/ADMIN)
        //    was issued for authToken and is signed by 'address'.
        std::string messageToSign = strprintf("DEPIN-CLEAR|%s|%s|%s", authToken, address, challenge);
        if (!ValidateChallenge(authToken, address, clientIP, challenge, DepinChallengeType::ADMIN, authError) ||
            !VerifyChallengeSignature(address, signature, messageToSign, authError)) {
            return JSONRPCReply(NullUniValue, JSONRPCError(RPC_INVALID_REQUEST, authError), id);
        }
        // 2) Defense in depth: 'address' holds the owner token of authToken or
        //    of one of its ancestors up to the pool root.
        if (!HasDepinSectionOwnerAccess(address, authToken, activeToken, authError)) {
            return JSONRPCReply(NullUniValue,
                JSONRPCError(RPC_INVALID_REQUEST, "depinclearmsg requires an owner of the token or an ancestor"), id);
        }

        // Rebuild params for the real RPC (accepts <= 2 params):
        //   [mode?] or [mode_or_null, scope]
        UniValue clearParams(UniValue::VARR);
        const bool modeGiven = !(modeParam.isNull() || (modeParam.isStr() && modeParam.get_str().empty()));
        if (scope.empty()) {
            if (modeGiven) {
                clearParams.push_back(modeParam);
            }
        } else {
            clearParams.push_back(modeGiven ? modeParam : NullUniValue);
            clearParams.push_back(UniValue(scope));
        }
        jsonRequest.params = clearParams;
        jsonRequest.fSkipWalletCheck = true;
    }
#endif

    // Sections: over the DePIN port, depinlistsections serves NAMES only.
    // Its address mode reports access and per-section message counters, and
    // this port is unauthenticated -- honoring the parameter here would hand
    // any caller another address's tab metadata, which is exactly what the
    // counters-only-with-access rule exists to prevent. The full mode stays
    // available on node RPC (operator-authenticated); a holder can prove
    // access to a section's messages through AUTH+GETMESSAGES instead.
    if (jsonRequest.strMethod == "depinlistsections" &&
        jsonRequest.params.size() > 0 && !jsonRequest.params[0].isNull() &&
        !(jsonRequest.params[0].isStr() && jsonRequest.params[0].get_str().empty())) {
        return JSONRPCReply(NullUniValue,
            JSONRPCError(RPC_INVALID_PARAMETER,
                "depinlistsections over the DePIN port lists section names only; "
                "the address mode requires node RPC"), id);
    }

    UniValue result = NullUniValue;
    UniValue error = NullUniValue;

    try {
        if (jsonRequest.strMethod == "depinsubmitmsg") {
            result = depinsubmitmsg(jsonRequest);
        } else if (jsonRequest.strMethod == "depinreceivemsg") {
            result = depinreceivemsg(jsonRequest);
        } else if (jsonRequest.strMethod == "depingetmsginfo") {
            result = depingetmsginfo(jsonRequest);
        } else if (jsonRequest.strMethod == "depingetpoolcontent") {
            result = depingetpoolcontent(jsonRequest);
        } else if (jsonRequest.strMethod == "depinpoolstats") {
            result = depinpoolstats(jsonRequest);
        } else if (jsonRequest.strMethod == "depinmcpstatus") {
            result = depinmcpstatus(jsonRequest);
        } else if (jsonRequest.strMethod == "depinlistsections") {
            result = depinlistsections(jsonRequest);
        }
#ifdef ENABLE_WALLET
        else if (jsonRequest.strMethod == "depinclearmsg") {
            result = depinclearmsg(jsonRequest);
        } else if (jsonRequest.strMethod == "depinpoolpkey") {
            result = depinpoolpkey(jsonRequest);
        }
#ifdef ENABLE_DEPIN_GATEWAY
        else if (jsonRequest.strMethod == "depinsendmsg") {
            result = depinsendmsg(jsonRequest);
        } else if (jsonRequest.strMethod == "depingetmsg") {
            result = depingetmsg(jsonRequest);
        }
#endif
#endif
        else {
            if (jsonRequest.strMethod == "depinsendmsg" || jsonRequest.strMethod == "depingetmsg") {
#ifndef ENABLE_DEPIN_GATEWAY
                throw JSONRPCError(RPC_METHOD_NOT_FOUND, "DePIN gateway commands are disabled in this build");
#else
                throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Wallet RPC not available in this build");
#endif
            } else if (jsonRequest.strMethod == "depinclearmsg" || jsonRequest.strMethod == "depinpoolpkey") {
                throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Wallet RPC not available in this build");
            } else {
                throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not allowed on DePIN port");
            }
        }
    } catch (const UniValue& e) {
        error = e;
    } catch (const std::exception& e) {
        error = JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    UniValue reply = JSONRPCReplyObj(error.isNull() ? result : NullUniValue,
                                     error,
                                     id);
    return reply.write();
}

// Helper to issue a challenge with rate limiting and verification
#ifdef ENABLE_DEPIN_GATEWAY
std::string CDepinMsgPoolServer::IssueChallenge(const std::string& token, const std::string& address,
                                                const std::string& clientIP, DepinChallengeType type,
                                                std::string& error) {
    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        error = "Chat mempool not enabled";
        return "";
    }

    // The requested token may be a section inside the served subtree. The
    // challenge stores the token it was issued for and ValidateChallenge()
    // compares it, so a challenge for a section can never be replayed against
    // the root or a sibling.
    if (!IsDepinSectionOrRoot(token, pDepinMsgPool->GetActiveToken())) {
        error = strprintf("Token mismatch. Server has: %s", pDepinMsgPool->GetActiveToken());
        return "";
    }

    if (address.empty()) {
        error = "Address is required";
        return "";
    }

    if (!IsValidDestinationString(address)) {
        error = "Invalid address format";
        return "";
    }

    // Verify access BEFORE issuing challenge (prevents DoS). Inherited and
    // ACTIVE: holding the token or any ancestor up to the pool root grants the
    // section, frozen and self-revoked pairs do not count.
    // NIP revision 005b: an ADMIN challenge (for depinclearmsg) is only issued
    // to an OWNER -- of the requested section or of any ancestor up to the
    // root -- not to any holder.
    if (type == DepinChallengeType::ADMIN) {
        if (!HasDepinSectionOwnerAccess(address, token, pDepinMsgPool->GetActiveToken(), error)) {
            return "";
        }
    } else {
        if (!HasDepinSectionAccess(address, token, pDepinMsgPool->GetActiveToken(), error)) {
            return "";
        }
    }

    // Verify that address has public key registered in blockchain (prevents DoS from non-spending addresses)
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Address is not a P2PKH address";
        return "";
    }

    CDestinationIndexData addressData;
    if (!GetDestinationIndexData(dest, addressData)) {
        error = "Failed to derive address index data";
        return "";
    }

    CPubKeyIndexValue pubKeyValue;
    if (!pblocktree->ReadPubKeyIndex(addressData, pubKeyValue)) {
        error = "Address has no public key registered in blockchain. Address must spend coins first to reveal public key.";
        return "";
    }

    if (!pubKeyValue.pubkey.IsValid() || !pubKeyValue.pubkey.IsFullyValid()) {
        error = "Invalid public key in blockchain index";
        return "";
    }

    // Verify that the pubkey corresponds to the address
    if (pubKeyValue.pubkey.GetID() != *keyID) {
        error = "Public key does not match address";
        return "";
    }

    unsigned char randBytes[32];
    GetRandBytes(randBytes, sizeof(randBytes));
    std::string nonce = HexStr(randBytes, randBytes + sizeof(randBytes));

    CDepinChallenge challenge;
    challenge.token = token;
    challenge.address = address;
    challenge.nonce = nonce;
    challenge.clientIP = clientIP;
    challenge.expiry = GetTime() + DEPIN_CHALLENGE_TIMEOUT;
    challenge.type = type;

    {
        LOCK(cs_challenges);
        mapChallenges[nonce] = challenge;
    }

    return nonce;
}

void CDepinMsgPoolServer::CleanupExpiredChallenges() {
    int64_t now = GetTime();
    LOCK(cs_challenges);
    for (auto it = mapChallenges.begin(); it != mapChallenges.end();) {
        if (it->second.expiry <= now) {
            it = mapChallenges.erase(it);
        } else {
            ++it;
        }
    }
}

bool CDepinMsgPoolServer::ValidateChallenge(const std::string& token, const std::string& address,
                                            const std::string& clientIP, const std::string& nonce,
                                            DepinChallengeType expectedType,
                                            std::string& error) {
    int64_t now = GetTime();
    LOCK(cs_challenges);
    auto it = mapChallenges.find(nonce);
    if (it == mapChallenges.end()) {
        error = "Challenge not found";
        return false;
    }

    const CDepinChallenge& entry = it->second;
    if (entry.expiry <= now) {
        error = "Challenge expired";
        mapChallenges.erase(it);
        return false;
    }

    if (entry.token != token || entry.address != address) {
        error = "Challenge does not match token/address";
        mapChallenges.erase(it);
        return false;
    }

    if (!entry.clientIP.empty() && entry.clientIP != clientIP) {
        error = "Challenge IP mismatch";
        mapChallenges.erase(it);
        return false;
    }

    if (entry.type != expectedType) {
        error = "Challenge type mismatch";
        mapChallenges.erase(it);
        return false;
    }

    mapChallenges.erase(it);
    return true;
}

bool CDepinMsgPoolServer::VerifyChallengeSignature(const std::string& address,
                                                   const std::string& signature,
                                                   const std::string& message,
                                                   std::string& error) const {
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        error = "Invalid address";
        return false;
    }

    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Address does not refer to a key";
        return false;
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(signature.c_str(), &fInvalid);
    if (fInvalid || vchSig.empty()) {
        error = "Malformed signature";
        return false;
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << message;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
        error = "Failed to recover public key from signature";
        return false;
    }

    if (pubkey.GetID() != *keyID) {
        error = "Signature does not match address";
        return false;
    }

    return true;
}
#endif

// ===== Cliente =====

#ifdef ENABLE_DEPIN_GATEWAY
bool CDepinMsgPoolClient::RequestChallenge(const std::string& host, int port,
                                           const std::string& token,
                                           const std::string& address,
                                           std::string& challenge,
                                           int& expiresIn,
                                           std::string& error,
                                           bool forSend) {
    std::string request = strprintf("%s|%s|%s%s",
                                    DEPIN_CMD_AUTH,
                                    token,
                                    address,
                                    forSend ? "|SEND" : "");
    std::string response;

    if (!SendRequest(host, port, request, response, error)) {
        return false;
    }

    std::vector<std::string> parts;
    std::stringstream ss(response);
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.empty()) {
        error = "Invalid challenge response";
        return false;
    }

    if (parts[0] == DEPIN_RESP_ERROR) {
        error = parts.size() > 1 ? parts[1] : "Challenge rejected";
        return false;
    }

    if (parts.size() != 3 || parts[0] != "CHALLENGE") {
        error = "Unexpected challenge response: " + response;
        return false;
    }

    challenge = parts[1];
    expiresIn = atoi(parts[2].c_str());
    return true;
}

bool CDepinMsgPoolClient::QueryMessages(const std::string& host, int port,
                                       const std::string& token,
                                       const std::vector<std::string>& addresses,
                                       const std::string& authAddress,
                                       const std::string& signature,
                                       const std::string& challenge,
                                       std::vector<CDepinMessage>& messages,
                                       std::string& error) {
    // Build address list
    std::string addressList;
    for (size_t i = 0; i < addresses.size(); i++) {
        if (i > 0) addressList += ",";
        addressList += addresses[i];
    }

    // Build request
    std::string request = strprintf("%s|%s|%s|%s|%s|%s",
                                   DEPIN_CMD_GETMESSAGES,
                                   token,
                                   addressList,
                                   authAddress,
                                   signature,
                                   challenge);

    // Send request
    std::string response;
    if (!SendRequest(host, port, request, response, error)) {
        return false;
    }

    // Parse response: OK|hex_data or ERROR|message
    size_t pos = response.find('|');
    if (pos == std::string::npos) {
        error = "Invalid response format";
        return false;
    }

    std::string status = response.substr(0, pos);
    std::string data = response.substr(pos + 1);

    if (status != "OK") {
        error = "Server error: " + data;
        return false;
    }

    // Deserialize messages from hex
    std::vector<unsigned char> vData = ParseHex(data);
    CDataStream ss(vData, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ss >> messages;
    } catch (const std::exception& e) {
        error = strprintf("Failed to deserialize messages: %s", e.what());
        return false;
    }

    return true;
}

bool CDepinMsgPoolClient::SubmitRemoteMessage(const std::string& host, int port,
                                    const std::string& token,
                                    const std::string& destination,
                                    int destinationPort,
                                    const std::string& message,
                                    const std::string& fromAddress,
                                    const std::string& challenge,
                                    const std::string& signature,
                                    UniValue& result,
                                    std::string& error) {
    UniValue request(UniValue::VOBJ);
    request.push_back(Pair("jsonrpc", "2.0"));
    request.push_back(Pair("id", 1));
    request.push_back(Pair("method", "depinsendmsg"));

    UniValue params(UniValue::VARR);
    params.push_back(token);
    params.push_back(destination);
    params.push_back(message);
    params.push_back(fromAddress);
    if (destinationPort != DEFAULT_DEPIN_MSG_PORT) {
        params.push_back(destinationPort);
    }
    params.push_back(challenge);
    params.push_back(signature);

    request.push_back(Pair("params", params));

    std::string response;
    if (!SendRequest(host, port, request.write(), response, error)) {
        return false;
    }

    UniValue reply;
    if (!reply.read(response)) {
        error = "Invalid JSON response";
        return false;
    }

    const UniValue& errVal = reply["error"];
    if (!errVal.isNull()) {
        if (errVal.isObject() && errVal.exists("message")) {
            error = errVal["message"].get_str();
        } else {
            error = "Remote node returned an error";
        }
        return false;
    }

    result = reply["result"];
    return true;
}
#endif

bool CDepinMsgPoolClient::SubmitSerializedMessage(const std::string& host, int port,
                                                   const std::string& hexMessage,
                                                   UniValue& result,
                                                   std::string& error) {
    // Create JSON-RPC request for the new "depinsubmitmsg" method
    UniValue request(UniValue::VOBJ);
    request.push_back(Pair("jsonrpc", "2.0"));
    request.push_back(Pair("id", 1));
    request.push_back(Pair("method", "depinsubmitmsg"));

    UniValue params(UniValue::VARR);
    params.push_back(hexMessage);  // Hex-encoded serialized CDepinMessage
    request.push_back(Pair("params", params));

    std::string response;
    if (!SendRequest(host, port, request.write(), response, error)) {
        return false;
    }

    UniValue reply;
    if (!reply.read(response)) {
        error = "Invalid JSON response";
        return false;
    }

    const UniValue& errVal = reply["error"];
    if (!errVal.isNull()) {
        if (errVal.isObject() && errVal.exists("message")) {
            error = errVal["message"].get_str();
        } else {
            error = "Remote node returned an error";
        }
        return false;
    }

    result = reply["result"];
    return true;
}

bool CDepinMsgPoolClient::Ping(const std::string& host, int port, std::string& error) {
    std::string request = DEPIN_CMD_PING;
    std::string response;

    if (!SendRequest(host, port, request, response, error)) {
        return false;
    }

    if (response != "OK|PONG") {
        error = "Unexpected ping response: " + response;
        return false;
    }

    return true;
}

bool CDepinMsgPoolClient::GetRemoteServerInfo(const std::string& host, int port,
                                              CDepinRemoteServerInfo& info,
                                              std::string& error) {
    // Use INFO command to get server configuration
    std::string request = DEPIN_CMD_INFO;
    std::string response;

    if (!SendRequest(host, port, request, response, error)) {
        return false;
    }

    // The server answers
    //   OK|token|port|cipher|maxRecipients|maxMessageSize|expiryHours|maxPoolSizeMB|...
    // (ProcessRequest, INFO). The previous parser here assumed an old
    // OK|token|count|expiry layout and read the CIPHER field as the expiry, so
    // it failed on every current server with stoi("AES-256-GCM"). Split all
    // fields and index them by position instead.
    std::vector<std::string> fields;
    std::stringstream ss(response);
    std::string field;
    while (std::getline(ss, field, '|')) {
        fields.push_back(field);
    }

    if (fields.empty() || fields[0] != "OK") {
        error = "Server error: " + response;
        return false;
    }
    if (fields.size() < 7) {
        error = "Server INFO response has too few fields (old version)";
        return false;
    }

    try {
        info.token = fields[1];
        info.port = std::stoi(fields[2]);
        info.cipher = fields[3];
        info.maxRecipients = (unsigned int)std::stoul(fields[4]);
        info.maxMessageSize = (unsigned int)std::stoul(fields[5]);
        info.messageExpiryHours = std::stoll(fields[6]);
    } catch (const std::exception& e) {
        error = strprintf("Failed to parse INFO response: %s", e.what());
        return false;
    }

    if (info.token.empty()) {
        error = "Server INFO response carries no token";
        return false;
    }

    // Defense in depth: Initialize() refuses maxRecipients == 0, so no honest
    // server announces it. Failing here keeps every consumer (depinsendmsg's
    // scope decision above all) from turning a nonsensical limit into a
    // default instead of an error.
    if (info.maxRecipients == 0) {
        error = "Server INFO announces maxRecipients=0; a pool that accepts no "
                "recipients cannot carry a message";
        return false;
    }

    return true;
}

bool CDepinMsgPoolClient::GetRemoteServerInfo(const std::string& host, int port,
                                              int64_t& messageExpiryHours,
                                              std::string& error) {
    CDepinRemoteServerInfo info;
    if (!GetRemoteServerInfo(host, port, info, error)) {
        return false;
    }
    messageExpiryHours = info.messageExpiryHours;
    return true;
}

bool CDepinMsgPoolClient::SendRequest(const std::string& host, int port,
                                     const std::string& request,
                                     std::string& response,
                                     std::string& error) {
    // Crear socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        error = strprintf("Failed to create socket: %s", GetSocketErrorMsg());
        return false;
    }

    // Configurar timeout
    struct timeval tv;
    tv.tv_sec = DEPIN_SOCKET_TIMEOUT;
    tv.tv_usec = 0;
#ifdef WIN32
    DWORD timeout = DEPIN_SOCKET_TIMEOUT * 1000; // milliseconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif

    // Resolver hostname
    struct hostent* server = gethostbyname(host.c_str());
    if (server == NULL) {
        error = strprintf("Could not resolve hostname: %s", host);
        close(sock);
        return false;
    }

    // Configurar dirección del servidor
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    memcpy(&serverAddr.sin_addr.s_addr, server->h_addr, server->h_length);
    serverAddr.sin_port = htons(port);

    // Conectar
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        error = strprintf("Failed to connect to %s:%d: %s", host, port, GetSocketErrorMsg());
        close(sock);
        return false;
    }

    // Send request
    std::string fullRequest = request + "\n";
    ssize_t sent = send(sock, fullRequest.c_str(), fullRequest.size(), 0);
    if (sent < 0) {
        error = strprintf("Failed to send request: %s", GetSocketErrorMsg());
        close(sock);
        return false;
    }

    // Receive response
    response.clear();
    char buffer[4096];
    ssize_t bytesRead;

    while ((bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;

        // Look for end of message
        size_t pos = response.find('\n');
        if (pos != std::string::npos) {
            response = response.substr(0, pos);
            break;
        }

        // Límite de tamaño
        if (response.size() > DEPIN_MAX_PROTOCOL_SIZE) {
            error = "Response too large";
            close(sock);
            return false;
        }
    }

    if (bytesRead < 0) {
        error = strprintf("Failed to receive response: %s", GetSocketErrorMsg());
        close(sock);
        return false;
    }

    close(sock);
    return true;
}
