// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Lifecycle tests for CDepinMsgPoolServer: bounded-time Stop() with idle
// clients, concurrent-connection limit and basic request round-trip.

#include "depinmsgpoolnet.h"
#include "depinmsgpool.h"
#include "util.h"
#include "utiltime.h"
#include "test/test_neurai.h"
#include "base58.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "validation.h" // strMessageMagic

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

#ifdef ENABLE_DEPIN_GATEWAY
// Test accessor (friend of both classes): lets us stand up an enabled pool and a
// pre-validated challenge without Initialize()'s passetsdb/index preconditions
// or IssueChallenge()'s on-chain token-ownership lookup. Same approach as
// DepinMCPWorkerTester in depinmcpworker_tests.cpp.
struct DepinServerTester {
    static void EnablePool(CDepinMsgPool& pool, const std::string& token)
    {
        pool.fEnabled = true;
        pool.activeToken = token;
    }

    // Only reachable this way: Initialize() rejects maxRecipients == 0, so a
    // zero can only come from a hostile or broken server. The tester plays
    // that server.
    static void SetMaxRecipients(CDepinMsgPool& pool, unsigned int n)
    {
        pool.nMaxRecipients = n;
    }

    static void InjectChallenge(CDepinMsgPoolServer& server, const CDepinChallenge& challenge)
    {
        LOCK(server.cs_challenges);
        server.mapChallenges[challenge.nonce] = challenge;
    }
};

namespace {

// RAII: swaps in a fresh enabled pool and restores the previous global on the
// way out, including when a BOOST_REQUIRE throws mid-test. Also stops the
// server it owns, so a failure cannot leak a listening socket or an enabled
// pool into later test cases.
struct ScopedGatewayPool {
    std::unique_ptr<CDepinMsgPool> previous;
    CDepinMsgPoolServer& server;

    ScopedGatewayPool(CDepinMsgPoolServer& serverIn, const std::string& token)
        : previous(std::move(pDepinMsgPool)), server(serverIn)
    {
        pDepinMsgPool.reset(new CDepinMsgPool());
        DepinServerTester::EnablePool(*pDepinMsgPool, token);
    }

    ~ScopedGatewayPool()
    {
        server.Stop();
        pDepinMsgPool = std::move(previous);
    }
};

std::string SignChallengeMessage(const CKey& key, const std::string& message)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << message;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) return "";
    return EncodeBase64(vchSig.data(), vchSig.size());
}

} // namespace
#endif // ENABLE_DEPIN_GATEWAY

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

#ifdef ENABLE_DEPIN_GATEWAY
// Security regression: the challenge only proves control of authAddress, so
// GETMESSAGES must refuse to serve any other address. Before the fix it was
// enough for authAddress to appear somewhere in the list and every listed
// address was served, letting an authenticated holder pull another holder's
// encrypted payloads.
BOOST_AUTO_TEST_CASE(depinserver_getmessages_rejects_foreign_address)
{
    const std::string token = "&TESTTOKEN";

    CDepinMsgPoolServer server;
    // Restores the global pool and stops the server even if a check below throws.
    ScopedGatewayPool scopedPool(server, token);

    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    // A authenticates; B is a third party whose messages A must not receive.
    CKey keyA;
    keyA.MakeNewKey(true);
    const std::string addressA = EncodeDestination(keyA.GetPubKey().GetID());

    CKey keyB;
    keyB.MakeNewKey(true);
    const std::string addressB = EncodeDestination(keyB.GetPubKey().GetID());

    // Inject a challenge that is already valid for A. Empty clientIP so
    // ValidateChallenge() skips the IP match.
    CDepinChallenge challenge;
    challenge.token = token;
    challenge.address = addressA;
    challenge.nonce = "testnonce0123456789";
    challenge.clientIP = "";
    challenge.expiry = GetTime() + DEPIN_CHALLENGE_TIMEOUT;
    challenge.type = DepinChallengeType::RECEIVE;

    const std::string toSign = strprintf("DEPIN-GET|%s|%s|%s", token, addressA, challenge.nonce);
    const std::string signature = SignChallengeMessage(keyA, toSign);
    BOOST_REQUIRE(!signature.empty());

    // Authenticated as A but asking for "A,B" -> must be refused outright.
    DepinServerTester::InjectChallenge(server, challenge);
    int sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    std::string req = strprintf("GETMESSAGES|%s|%s,%s|%s|%s|%s\n",
                                token, addressA, addressB, addressA, signature, challenge.nonce);
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    std::string response = ReadLine(sock);
    close(sock);
    BOOST_CHECK_MESSAGE(response.find("ERROR|") == 0,
                        "expected refusal, got: " + response);

    // Sanity check that the refusal above is about the extra address and not a
    // broken handshake: the same credentials asking only for A must succeed.
    DepinServerTester::InjectChallenge(server, challenge);
    sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    req = strprintf("GETMESSAGES|%s|%s|%s|%s|%s\n",
                    token, addressA, addressA, signature, challenge.nonce);
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    response = ReadLine(sock);
    close(sock);
    BOOST_CHECK_MESSAGE(response.find("OK|") == 0,
                        "expected success for own address, got: " + response);
}

// Sections: a challenge is bound to the token it was issued for. One issued
// for a section must not authenticate a query for the root (or vice versa) --
// ValidateChallenge() compares the stored token, so no server change was
// needed for this property, but it must not regress.
BOOST_AUTO_TEST_CASE(depinserver_section_challenge_is_bound_to_its_token)
{
    const std::string rootToken = "&TESTTOKEN";
    const std::string sectionToken = "&TESTTOKEN/GENERAL";

    CDepinMsgPoolServer server;
    ScopedGatewayPool scopedPool(server, rootToken);

    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    CKey keyA;
    keyA.MakeNewKey(true);
    const std::string addressA = EncodeDestination(keyA.GetPubKey().GetID());

    CDepinChallenge challenge;
    challenge.token = sectionToken;
    challenge.address = addressA;
    challenge.nonce = "sectionnonce0123456789";
    challenge.clientIP = "";
    challenge.expiry = GetTime() + DEPIN_CHALLENGE_TIMEOUT;
    challenge.type = DepinChallengeType::RECEIVE;

    // Replay attempt: challenge issued for the SECTION, used against the ROOT.
    // The signature is made over the root form so only the stored token can
    // reject it.
    const std::string toSignRoot = strprintf("DEPIN-GET|%s|%s|%s", rootToken, addressA, challenge.nonce);
    const std::string rootSignature = SignChallengeMessage(keyA, toSignRoot);
    BOOST_REQUIRE(!rootSignature.empty());

    DepinServerTester::InjectChallenge(server, challenge);
    int sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    std::string req = strprintf("GETMESSAGES|%s|%s|%s|%s|%s\n",
                                rootToken, addressA, addressA, rootSignature, challenge.nonce);
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    std::string response = ReadLine(sock);
    close(sock);
    BOOST_CHECK_MESSAGE(response.find("ERROR|") == 0,
                        "section challenge must not serve the root, got: " + response);

    // The same challenge used for the token it was issued for: accepted.
    const std::string toSignSection = strprintf("DEPIN-GET|%s|%s|%s", sectionToken, addressA, challenge.nonce);
    const std::string sectionSignature = SignChallengeMessage(keyA, toSignSection);
    BOOST_REQUIRE(!sectionSignature.empty());

    DepinServerTester::InjectChallenge(server, challenge);
    sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    req = strprintf("GETMESSAGES|%s|%s|%s|%s|%s\n",
                    sectionToken, addressA, addressA, sectionSignature, challenge.nonce);
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    response = ReadLine(sock);
    close(sock);
    BOOST_CHECK_MESSAGE(response.find("OK|") == 0,
                        "expected success for the challenge's own token, got: " + response);
}

// GetRemoteServerInfo against a live server: the INFO reply's fields land on
// the right names. The previous parser assumed an old OK|token|count|expiry
// layout and read the CIPHER field as the expiry, failing on every current
// server with stoi("AES-256-GCM") -- which is what fed depinsendmsg the wrong
// recipient scope for remote sends.
BOOST_AUTO_TEST_CASE(depinserver_remote_info_parses_current_format)
{
    const std::string token = "&TESTTOKEN/APPLE";

    CDepinMsgPoolServer server;
    ScopedGatewayPool scopedPool(server, token);
    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    CDepinMsgPoolClient::CDepinRemoteServerInfo info;
    std::string error;
    BOOST_REQUIRE_MESSAGE(CDepinMsgPoolClient::GetRemoteServerInfo("127.0.0.1", port, info, error),
                          error);
    BOOST_CHECK_EQUAL(info.token, token);
    BOOST_CHECK_EQUAL(info.maxRecipients, DEFAULT_MAX_DEPIN_RECIPIENTS);
    BOOST_CHECK_EQUAL(info.maxMessageSize, DEFAULT_DEPIN_MESSAGE_SIZE);
    BOOST_CHECK_EQUAL(info.messageExpiryHours, (int64_t)DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS);
    BOOST_CHECK_EQUAL(info.cipher, "AES-256-GCM");

    // The back-compat wrapper reports the same expiry (depingetmsg relies on it).
    int64_t expiry = 0;
    BOOST_REQUIRE_MESSAGE(CDepinMsgPoolClient::GetRemoteServerInfo("127.0.0.1", port, expiry, error),
                          error);
    BOOST_CHECK_EQUAL(expiry, (int64_t)DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS);
}

// A server announcing maxRecipients == 0 is broken or hostile (Initialize()
// refuses that configuration): the client must return a named error, never
// hand the zero to a consumer that would quietly turn it into a default.
// depinsendmsg fails closed through this same path.
BOOST_AUTO_TEST_CASE(depinserver_remote_info_rejects_zero_max_recipients)
{
    CDepinMsgPoolServer server;
    ScopedGatewayPool scopedPool(server, "&TESTTOKEN");
    DepinServerTester::SetMaxRecipients(*pDepinMsgPool, 0);
    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    CDepinMsgPoolClient::CDepinRemoteServerInfo info;
    std::string error;
    BOOST_CHECK(!CDepinMsgPoolClient::GetRemoteServerInfo("127.0.0.1", port, info, error));
    BOOST_CHECK_MESSAGE(error.find("maxRecipients=0") != std::string::npos, error);
}

// Sections: over the unauthenticated DePIN port, depinlistsections serves
// names only. The address mode reports access and per-section counters for
// ANY address the caller names, so honoring it here would hand out another
// holder's tab metadata without a challenge.
BOOST_AUTO_TEST_CASE(depinserver_port_listsections_is_names_only)
{
    CDepinMsgPoolServer server;
    ScopedGatewayPool scopedPool(server, "&TESTTOKEN");
    int port = StartServerOnFreePort(server);
    BOOST_REQUIRE(port > 0);

    // Address mode: refused at the port, before the RPC ever runs.
    int sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    std::string req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"depinlistsections\","
                      "\"params\":[\"NSomeAddress\"]}\n";
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    std::string response = ReadLine(sock);
    close(sock);
    BOOST_CHECK_MESSAGE(response.find("lists section names only") != std::string::npos,
                        "expected the names-only refusal, got: " + response);

    // The bare form passes the gate (whatever it then returns, it is not the
    // gate's refusal -- this fixture has no asset DB, so the RPC itself may
    // error, which is fine: the property under test is the gate).
    sock = ConnectClient(port);
    BOOST_REQUIRE(sock >= 0);
    req = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"depinlistsections\",\"params\":[]}\n";
    BOOST_REQUIRE(send(sock, req.c_str(), req.size(), 0) == (ssize_t)req.size());
    response = ReadLine(sock);
    close(sock);
    BOOST_CHECK_MESSAGE(response.find("lists section names only") == std::string::npos,
                        "the bare form must not hit the names-only gate: " + response);
}
#endif // ENABLE_DEPIN_GATEWAY

BOOST_AUTO_TEST_SUITE_END()

#endif // !WIN32
