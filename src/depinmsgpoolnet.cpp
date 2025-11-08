// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpoolnet.h"
#include "depinmsgpool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "streams.h"
#include "version.h"

#include <cstring>
#include <sstream>

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
        std::thread clientThread(&CDepinMsgPoolServer::HandleClient, this, clientSocket);
        clientThread.detach();
    }

    LogPrint(BCLog::NET, "Chat mempool server thread terminated\n");
}

void CDepinMsgPoolServer::HandleClient(int clientSocket) {
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
    std::string response = ProcessRequest(request);

    // Enviar respuesta
    response += "\n";
    send(clientSocket, response.c_str(), response.size(), 0);

    // Cerrar conexión
    close(clientSocket);
}

std::string CDepinMsgPoolServer::ProcessRequest(const std::string& request) {
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

        if (parts.size() < 3) {
            return "ERROR|Invalid GETMESSAGES format. Expected: GETMESSAGES|token|address1,address2,...";
        }

        std::string token = parts[1];
        std::string addressesStr = parts[2];

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

        // Obtener mensajes para esas direcciones
        std::vector<CDepinMessage> messages;

        for (const std::string& address : addresses) {
            std::vector<CDepinMessage> addrMessages = pDepinMsgPool->GetMessagesForAddress(address);
            messages.insert(messages.end(), addrMessages.begin(), addrMessages.end());
        }

        // Serializar mensajes
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << messages;

        // Convertir a hex
        std::string hex = HexStr(ss.begin(), ss.end());

        return "OK|" + hex;
    }

    return "ERROR|Unknown command: " + cmd;
}

// ===== Cliente =====

bool CDepinMsgPoolClient::QueryMessages(const std::string& host, int port,
                                       const std::string& token,
                                       const std::vector<std::string>& addresses,
                                       std::vector<CDepinMessage>& messages,
                                       std::string& error) {
    // Construir lista de direcciones
    std::string addressList;
    for (size_t i = 0; i < addresses.size(); i++) {
        if (i > 0) addressList += ",";
        addressList += addresses[i];
    }

    // Construir request
    std::string request = strprintf("%s|%s|%s",
                                   DEPIN_CMD_GETMESSAGES,
                                   token,
                                   addressList);

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
