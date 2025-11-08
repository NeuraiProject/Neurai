// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINMSGPOOLNET_H
#define NEURAI_DEPINMSGPOOLNET_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
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

// Respuestas
static const std::string DEPIN_RESP_OK = "OK";
static const std::string DEPIN_RESP_ERROR = "ERROR";

// Configuración
static const int DEPIN_SOCKET_TIMEOUT = 30; // segundos
static const size_t DEPIN_MAX_PROTOCOL_SIZE = 10 * 1024 * 1024; // 10MB

// Servidor de DePIN messaging
class CDepinMsgPoolServer {
private:
    std::atomic<bool> fRunning;
    std::thread serverThread;
    int serverSocket;
    int port;
    mutable CCriticalSection cs_server;

    void ThreadServerHandler();
    void HandleClient(int clientSocket);
    std::string ProcessRequest(const std::string& request);

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
    static bool QueryMessages(const std::string& host, int port,
                             const std::string& token,
                             const std::vector<std::string>& addresses,
                             std::vector<CDepinMessage>& messages,
                             std::string& error);

    static bool Ping(const std::string& host, int port, std::string& error);

    static bool GetInfo(const std::string& host, int port,
                       std::string& token, int& messageCount,
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
