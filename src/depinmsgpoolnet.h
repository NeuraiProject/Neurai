// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINMSGPOOLNET_H
#define NEURAI_DEPINMSGPOOLNET_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <univalue.h>
#include "depinmsgpool.h"
#include "sync.h"

// Protocolo simple para DePIN messaging
// Formato de mensajes:
// Request:  CMD|token|addresses (separados por coma)
// Response: STATUS|data

// Comandos
static const std::string DEPIN_CMD_GETMESSAGES = "GETMESSAGES";
static const std::string DEPIN_CMD_PING = "PING";
static const std::string DEPIN_CMD_INFO = "INFO";
static const std::string DEPIN_CMD_AUTH = "AUTH";

// Respuestas
static const std::string DEPIN_RESP_OK = "OK";
static const std::string DEPIN_RESP_ERROR = "ERROR";

// Configuración
static const int DEPIN_SOCKET_TIMEOUT = 30; // segundos
static const size_t DEPIN_MAX_PROTOCOL_SIZE = 10 * 1024 * 1024; // 10MB
static const int DEPIN_CHALLENGE_TIMEOUT = 30; // segundos

enum class DepinChallengeType {
    RECEIVE,
    SEND
};

struct CDepinChallenge {
    std::string token;
    std::string address;
    std::string nonce;
    std::string clientIP;
    int64_t expiry;
    DepinChallengeType type;
};

// Servidor de DePIN messaging
class CDepinMsgPoolServer {
private:
    std::atomic<bool> fRunning;
    std::thread serverThread;
    int serverSocket;
    int port;
    mutable CCriticalSection cs_server;

    void ThreadServerHandler();
    void HandleClient(int clientSocket, std::string clientIP);
    std::string ProcessRequest(const std::string& request, const std::string& clientIP);
    bool TryProcessJsonRpc(const std::string& request, std::string& response, const std::string& clientIP);
    std::string ProcessJsonRpcRequest(const UniValue& valRequest, const std::string& clientIP);
    std::string IssueChallenge(const std::string& token, const std::string& address,
                               const std::string& clientIP, DepinChallengeType type,
                               std::string& error);
    bool ValidateChallenge(const std::string& token, const std::string& address,
                           const std::string& clientIP, const std::string& nonce,
                           DepinChallengeType expectedType,
                           std::string& error);
    bool VerifyChallengeSignature(const std::string& address, const std::string& signature,
                                  const std::string& message, std::string& error) const;
    void CleanupExpiredChallenges();

    std::map<std::string, CDepinChallenge> mapChallenges;
    mutable CCriticalSection cs_challenges;

public:
    CDepinMsgPoolServer();
    ~CDepinMsgPoolServer();

    bool Start(int listenPort);
    void Stop();
    bool IsRunning() const { return fRunning; }
    int GetPort() const { return port; }
};

// Cliente de chat mempool
class CDepinMsgPoolClient {
public:
    static bool RequestChallenge(const std::string& host, int port,
                                 const std::string& token,
                                 const std::string& address,
                                 std::string& challenge,
                                 int& expiresIn,
                                 std::string& error,
                                 bool forSend = false);

    static bool QueryMessages(const std::string& host, int port,
                             const std::string& token,
                              const std::vector<std::string>& addresses,
                             const std::string& authAddress,
                             const std::string& signature,
                             const std::string& challenge,
                             std::vector<CDepinMessage>& messages,
                             std::string& error);

    static bool SubmitRemoteMessage(const std::string& host, int port,
                                    const std::string& token,
                                    const std::string& destination,
                                    int destinationPort,
                                    const std::string& message,
                                    const std::string& fromAddress,
                                    const std::string& challenge,
                                    const std::string& signature,
                                    UniValue& result,
                                    std::string& error);

    // Submit pre-encrypted and signed message (new secure protocol)
    // hexMessage: hex-encoded serialized CDepinMessage (already encrypted & signed)
    static bool SubmitSerializedMessage(const std::string& host, int port,
                                        const std::string& hexMessage,
                                        UniValue& result,
                                        std::string& error);

    static bool Ping(const std::string& host, int port, std::string& error);

    static bool GetInfo(const std::string& host, int port,
                       std::string& token, int& messageCount,
                       std::string& error);

    // Get remote server configuration (JSON-RPC depingetmsginfo)
    static bool GetRemoteServerInfo(const std::string& host, int port,
                                   int64_t& messageExpiryHours,
                                   std::string& error);

private:
    static bool SendRequest(const std::string& host, int port,
                          const std::string& request,
                          std::string& response,
                          std::string& error);
};

// Global server instance
extern std::unique_ptr<CDepinMsgPoolServer> pDepinMsgPoolServer;

#endif // NEURAI_DEPINMSGPOOLNET_H
