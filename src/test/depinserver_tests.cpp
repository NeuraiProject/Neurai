// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Lifecycle tests for CDepinMsgPoolServer: bounded-time Stop() with idle
// clients, concurrent-connection limit and basic request round-trip.

#include "depinmsgpoolnet.h"
#include "util.h"
#include "utiltime.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

#ifndef WIN32

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

// Start the server on the first free port of a private range
int StartServerOnFreePort(CDepinMsgPoolServer& server)
{
    for (int port = 34611; port < 34641; ++port) {
        if (server.Start(port)) return port;
    }
    return -1;
}

// Connect a test client to the local server with a short socket timeout,
// so a broken implementation fails the test instead of hanging it
int ConnectClient(int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

std::string ReadLine(int sock)
{
    std::string data;
    char c;
    while (recv(sock, &c, 1, 0) == 1) {
        if (c == '\n') break;
        data += c;
    }
    return data;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depinserver_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(depinserver_ping_roundtrip)
{
    CDepinMsgPoolServer server;
    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);
    BOOST_CHECK(server.IsRunning());

    int sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    std::string req = "PING\n";
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    BOOST_CHECK_EQUAL(ReadLine(sock), "OK|PONG");
    close(sock);

    server.Stop();
    BOOST_CHECK(!server.IsRunning());
}

BOOST_AUTO_TEST_CASE(depinserver_stop_with_idle_clients_is_bounded)
{
    CDepinMsgPoolServer server;
    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    // Open idle connections whose handlers stay blocked in recv()
    std::vector<int> clients;
    for (int i = 0; i < 3; ++i) {
        int sock = ConnectClient(port);
        BOOST_REQUIRE(sock >= 0);
        clients.push_back(sock);
    }

    // Give the accept loop time to register the handlers
    MilliSleep(200);

    int64_t t0 = GetTimeMillis();
    server.Stop();
    int64_t elapsed = GetTimeMillis() - t0;

    BOOST_CHECK(!server.IsRunning());
    // Stop() must unblock handlers via shutdown(), well below the 30s socket timeout
    BOOST_CHECK_MESSAGE(elapsed < 10000, strprintf("Stop() took %d ms", elapsed));

    // Stop() is idempotent
    server.Stop();
    BOOST_CHECK(!server.IsRunning());

    for (int sock : clients) close(sock);
}

BOOST_AUTO_TEST_CASE(depinserver_busy_limit)
{
    gArgs.ForceSetArg("-depinmaxconnections", "1");

    CDepinMsgPoolServer server;
    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    // First client occupies the single slot (handler blocked in recv())
    int busySock = ConnectClient(port);
    BOOST_REQUIRE(busySock >= 0);
    MilliSleep(200); // let the accept loop register it

    // Second client must be rejected without spawning a handler
    int rejectedSock = ConnectClient(port);
    BOOST_REQUIRE(rejectedSock >= 0);
    BOOST_CHECK_EQUAL(ReadLine(rejectedSock), "ERROR|Server busy");

    close(rejectedSock);
    close(busySock);
    server.Stop();
    BOOST_CHECK(!server.IsRunning());

    gArgs.ForceSetArg("-depinmaxconnections",
                      strprintf("%u", DEFAULT_DEPIN_MAX_CONNECTIONS));
}

BOOST_AUTO_TEST_SUITE_END()

#endif // !WIN32
