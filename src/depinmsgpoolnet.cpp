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

#include <cstring>
#include <sstream>

// Forward declarations of RPC functions
UniValue depinsendmsg(const JSONRPCRequest& request);
UniValue depingetmsg(const JSONRPCRequest& request);
UniValue depinsubmitmsg(const JSONRPCRequest& request);
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
extern UniValue depinsendmsg(const JSONRPCRequest& request);
extern UniValue depingetmsg(const JSONRPCRequest& request);
#endif

// ===== Servidor =====

CDepinMsgPoolServer::CDepinMsgPoolServer()
    : fRunning(false), serverSocket(-1), port(0) {
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

    // Crear socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        LogPrintf("ERROR: Failed to create chat mempool server socket: %s\n", GetSocketErrorMsg().c_str());
        return false;
    }

    // Permitir reutilizar dirección
    int opt = 1;
#ifdef WIN32
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
#else
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
#endif
        LogPrintf("WARNING: Failed to set SO_REUSEADDR on chat mempool socket\n");
    }

    // Configurar dirección
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(listenPort);

    // Bind
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        LogPrintf("ERROR: Failed to bind chat mempool server socket to port %d: %s\n",
                  listenPort, GetSocketErrorMsg().c_str());
        close(serverSocket);
        serverSocket = -1;
        return false;
    }

    // Listen
    if (listen(serverSocket, 10) < 0) {
        LogPrintf("ERROR: Failed to listen on chat mempool server socket: %s\n", GetSocketErrorMsg().c_str());
        close(serverSocket);
        serverSocket = -1;
        return false;
    }

    port = listenPort;
    fRunning = true;

    // Iniciar thread del servidor
    serverThread = std::thread(&CDepinMsgPoolServer::ThreadServerHandler, this);

    LogPrintf("Chat mempool server started on port %d\n", port);
    return true;
}

void CDepinMsgPoolServer::Stop() {
    if (!fRunning)
        return;

    fRunning = false;

    // Cerrar socket
    if (serverSocket >= 0) {
        shutdown(serverSocket, SHUT_RDWR);
        close(serverSocket);
        serverSocket = -1;
    }

    // Esperar a que termine el thread
    if (serverThread.joinable()) {
        serverThread.join();
    }

    LogPrintf("Chat mempool server stopped\n");
}

void CDepinMsgPoolServer::ThreadServerHandler() {
    LogPrint(BCLog::NET, "Chat mempool server thread started\n");

    while (fRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);

        // Configurar timeout para accept
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;  // 1 segundo de timeout
        tv.tv_usec = 0;

        int activity = select(serverSocket + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0 && !IsSocketErrorInterrupt(GetSocketError())) {
            if (fRunning) {
                LogPrintf("ERROR: select() failed in chat mempool server: %s\n", GetSocketErrorMsg().c_str());
            }
            break;
        }

        if (activity == 0) {
            // Timeout, continuar loop
            continue;
        }

        // Aceptar conexión
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            int err = GetSocketError();
            if (!IsSocketErrorInterrupt(err) && !IsSocketErrorWouldBlock(err)) {
                LogPrint(BCLog::NET, "ERROR: accept() failed: %s\n", GetSocketErrorMsg().c_str());
            }
            continue;
        }

        // Log de conexión
        char clientIP[INET_ADDRSTRLEN];
        InetNtopCompat(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        LogPrint(BCLog::NET, "Chat mempool: Accepted connection from %s:%d\n",
                clientIP, ntohs(clientAddr.sin_port));

        // Manejar cliente en thread separado (o inline para simplicidad)
        std::thread clientThread(&CDepinMsgPoolServer::HandleClient, this, clientSocket, std::string(clientIP));
        clientThread.detach();
    }

    LogPrint(BCLog::NET, "Chat mempool server thread terminated\n");
}

void CDepinMsgPoolServer::HandleClient(int clientSocket, std::string clientIP) {
    // Configurar timeout
    struct timeval tv;
    tv.tv_sec = DEPIN_SOCKET_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    // Leer request
    std::string request;
    char buffer[4096];
    ssize_t bytesRead;

    while ((bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        request += buffer;

        // Buscar fin de mensaje (newline)
        size_t pos = request.find('\n');
        if (pos != std::string::npos) {
            request = request.substr(0, pos);
            break;
        }

        // Límite de tamaño
        if (request.size() > DEPIN_MAX_PROTOCOL_SIZE) {
            std::string error = "ERROR|Request too large\n";
            send(clientSocket, error.c_str(), error.size(), 0);
            close(clientSocket);
            return;
        }
    }

    if (bytesRead < 0) {
        LogPrint(BCLog::NET, "ERROR: recv() failed: %s\n", GetSocketErrorMsg().c_str());
        close(clientSocket);
        return;
    }

    // Procesar request
    std::string response = ProcessRequest(request, clientIP);

    // Enviar respuesta
    response += "\n";
    send(clientSocket, response.c_str(), response.size(), 0);

    // Cerrar conexión
    close(clientSocket);
}

std::string CDepinMsgPoolServer::ProcessRequest(const std::string& request, const std::string& clientIP) {
    CleanupExpiredChallenges();
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
        DepinChallengeType challengeType = (modeUpper == "SEND") ? DepinChallengeType::SEND : DepinChallengeType::RECEIVE;

        std::string error;
        std::string challenge = IssueChallenge(token, address, clientIP, challengeType, error);
        if (challenge.empty()) {
            return "ERROR|" + error;
        }

        return strprintf("CHALLENGE|%s|%d", challenge, DEPIN_CHALLENGE_TIMEOUT);
    }

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
        size_t messageCount = pDepinMsgPool->Size();

        return strprintf("OK|%s|%d", token, messageCount);
    }

    // GETMESSAGES
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

        // Verificar token
        if (token != pDepinMsgPool->GetActiveToken()) {
            return strprintf("ERROR|Token mismatch. Server has: %s", pDepinMsgPool->GetActiveToken());
        }

        // Parse direcciones
        std::vector<std::string> addresses;
        std::stringstream addrSS(addressesStr);
        std::string addr;
        while (std::getline(addrSS, addr, ',')) {
            addresses.push_back(addr);
        }

        if (addresses.empty()) {
            return "ERROR|No addresses provided";
        }

        bool authFound = false;
        for (const auto& addr : addresses) {
            if (addr == authAddress) {
                authFound = true;
                break;
            }
        }

        if (!authFound) {
            return "ERROR|Authenticated address not present in request";
        }

        // Obtener mensajes para esas direcciones
        std::vector<CDepinMessage> messages;

        try {
            for (const std::string& address : addresses) {
                std::vector<CDepinMessage> addrMessages = pDepinMsgPool->GetMessagesForAddress(address);
                messages.insert(messages.end(), addrMessages.begin(), addrMessages.end());
            }

            // Serializar mensajes con manejo de excepciones
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << messages;

            // Convertir a hex
            std::string hex = HexStr(ss.begin(), ss.end());

            LogPrint(BCLog::NET, "GETMESSAGES: Successfully serialized %d messages for %d addresses\n",
                    messages.size(), addresses.size());

            return "OK|" + hex;
        } catch (const std::exception& e) {
            LogPrintf("ERROR: Failed to serialize messages for GETMESSAGES: %s\n", e.what());
            return strprintf("ERROR|Failed to serialize messages: %s", e.what());
        }
    }

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

    if (jsonRequest.params.isNull()) {
        jsonRequest.params.setArray();
    }

    if (!jsonRequest.params.isArray()) {
        UniValue reply = JSONRPCReplyObj(NullUniValue,
                                         JSONRPCError(RPC_INVALID_REQUEST, "Parameters must be an array"),
                                         id);
        return reply.write();
    }

    if (jsonRequest.strMethod == "depinsendmsg") {
        size_t paramCount = jsonRequest.params.size();
        if (paramCount < 6) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER,
                                                          "Remote depinsendmsg requires fromaddress, challenge and signature"),
                                             id);
            return reply.write();
        }

        if (!jsonRequest.params[0].isStr()) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, "Token must be a string"),
                                             id);
            return reply.write();
        }

        if (!jsonRequest.params[3].isStr()) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER,
                                                          "fromaddress is required for remote depinsendmsg"),
                                             id);
            return reply.write();
        }

        std::string token = jsonRequest.params[0].get_str();
        std::string fromAddress = jsonRequest.params[3].get_str();
        std::string challenge = jsonRequest.params[paramCount - 2].get_str();
        std::string signature = jsonRequest.params[paramCount - 1].get_str();

        if (challenge.empty() || signature.empty()) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER,
                                                          "Challenge and signature cannot be empty"),
                                             id);
            return reply.write();
        }

        std::string authError;
        if (!ValidateChallenge(token, fromAddress, clientIP, challenge, DepinChallengeType::SEND, authError)) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, authError),
                                             id);
            return reply.write();
        }

        std::string messageToSign = strprintf("DEPIN-SEND|%s|%s|%s", token, fromAddress, challenge);
        if (!VerifyChallengeSignature(fromAddress, signature, messageToSign, authError)) {
            UniValue reply = JSONRPCReplyObj(NullUniValue,
                                             JSONRPCError(RPC_INVALID_PARAMETER, authError),
                                             id);
            return reply.write();
        }

        UniValue trimmed(UniValue::VARR);
        for (size_t i = 0; i < paramCount - 2; ++i) {
            trimmed.push_back(jsonRequest.params[i]);
        }
        jsonRequest.params = trimmed;
    }

    UniValue result = NullUniValue;
    UniValue error = NullUniValue;

    try {
#ifdef ENABLE_WALLET
        if (jsonRequest.strMethod == "depinsubmitmsg") {
            // NEW SECURE PROTOCOL: Receives pre-encrypted and signed messages
            // Message signature is ALWAYS verified in depinsubmitmsg
            result = depinsubmitmsg(jsonRequest);
        } else if (jsonRequest.strMethod == "depinsendmsg") {
            // LEGACY PROTOCOL: Server encrypts and signs (less secure, deprecated)
            // Mark request as pre-authenticated by DePIN server
            // This skips wallet ownership check since signature was already verified
            jsonRequest.fSkipWalletCheck = true;
            result = depinsendmsg(jsonRequest);
        } else if (jsonRequest.strMethod == "depingetmsg") {
            result = depingetmsg(jsonRequest);
        } else {
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not allowed on DePIN port");
        }
#else
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Wallet RPC not available in this build");
#endif
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

std::string CDepinMsgPoolServer::IssueChallenge(const std::string& token, const std::string& address,
                                                const std::string& clientIP, DepinChallengeType type,
                                                std::string& error) {
    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        error = "Chat mempool not enabled";
        return "";
    }

    if (token != pDepinMsgPool->GetActiveToken()) {
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

    // Verify token ownership BEFORE issuing challenge (prevents DoS)
    if (!CheckTokenOwnership(address, token, error)) {
        return "";
    }

    // Verify that address has public key registered in blockchain (prevents DoS from non-spending addresses)
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Address is not a P2PKH address";
        return "";
    }

    CPubKeyIndexValue pubKeyValue;
    if (!pblocktree->ReadPubKeyIndex(uint160(*keyID), pubKeyValue)) {
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

// ===== Cliente =====

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
    // Construir lista de direcciones
    std::string addressList;
    for (size_t i = 0; i < addresses.size(); i++) {
        if (i > 0) addressList += ",";
        addressList += addresses[i];
    }

    // Construir request
    std::string request = strprintf("%s|%s|%s|%s|%s|%s",
                                   DEPIN_CMD_GETMESSAGES,
                                   token,
                                   addressList,
                                   authAddress,
                                   signature,
                                   challenge);

    // Enviar request
    std::string response;
    if (!SendRequest(host, port, request, response, error)) {
        return false;
    }

    // Parse response: OK|hex_data o ERROR|mensaje
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

    // Deserializar mensajes desde hex
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

bool CDepinMsgPoolClient::GetInfo(const std::string& host, int port,
                                 std::string& token, int& messageCount,
                                 std::string& error) {
    std::string request = DEPIN_CMD_INFO;
    std::string response;

    if (!SendRequest(host, port, request, response, error)) {
        return false;
    }

    // Parse: OK|token|count
    size_t pos1 = response.find('|');
    if (pos1 == std::string::npos) {
        error = "Invalid INFO response format";
        return false;
    }

    size_t pos2 = response.find('|', pos1 + 1);
    if (pos2 == std::string::npos) {
        error = "Invalid INFO response format";
        return false;
    }

    std::string status = response.substr(0, pos1);
    if (status != "OK") {
        error = "Server error: " + response.substr(pos1 + 1);
        return false;
    }

    token = response.substr(pos1 + 1, pos2 - pos1 - 1);
    messageCount = std::stoi(response.substr(pos2 + 1));

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

    // Enviar request
    std::string fullRequest = request + "\n";
    ssize_t sent = send(sock, fullRequest.c_str(), fullRequest.size(), 0);
    if (sent < 0) {
        error = strprintf("Failed to send request: %s", GetSocketErrorMsg());
        close(sock);
        return false;
    }

    // Recibir respuesta
    response.clear();
    char buffer[4096];
    ssize_t bytesRead;

    while ((bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;

        // Buscar fin de mensaje
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
