// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for denial-of-service detection/prevention code

#include "chainparams.h"
#include "keystore.h"
#include "net.h"
#include "netbase.h"
#include "net_processing.h"
#include "pow.h"
#include "script/sign.h"
#include "serialize.h"
#include "util.h"
#include "validation.h"

#include "test/test_neurai.h"

#include <stdint.h>

#include <boost/test/unit_test.hpp>

// Tests these internal-to-net_processing.cpp methods:
extern bool AddOrphanTx(const CTransactionRef &tx, NodeId peer);

extern void EraseOrphansFor(NodeId peer);

extern unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans);

struct COrphanTx
{
    CTransactionRef tx;
    NodeId fromPeer;
    int64_t nTimeExpire;
};
extern std::map<uint256, COrphanTx> mapOrphanTransactions;

CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), GetParams().GetDefaultPort());
}

static NodeId id = 0;

BOOST_FIXTURE_TEST_SUITE(DoS_tests, TestingSetup)

// Test eviction of an outbound peer whose chain never advances
// Mock a node connection, and use mocktime to simulate a peer
// which never sends any headers messages.  PeerLogic should
// decide to evict that outbound peer, after the appropriate timeouts.
// Note that we protect 4 outbound nodes from being subject to
// this logic; this test takes advantage of that protection only
// being applied to nodes which send headers with sufficient
// work.
    BOOST_AUTO_TEST_CASE(outbound_slow_chain_eviction_test)
    {
        BOOST_TEST_MESSAGE("Running Outbound Slow Chain Eviction Test");

        std::atomic<bool> interruptDummy(false);

        // Mock an outbound peer
        CAddress addr1(ip(0xa0b0c001), NODE_NONE);
        CNode dummyNode1(id++, ServiceFlags(NODE_NETWORK | NODE_WITNESS), 0, INVALID_SOCKET, addr1, 0, 0, CAddress(), "", /*fInboundIn=*/ false);
        dummyNode1.SetSendVersion(PROTOCOL_VERSION);

        peerLogic->InitializeNode(&dummyNode1);
        dummyNode1.nVersion = 1;
        dummyNode1.fSuccessfullyConnected = true;

        // This test requires that we have a chain with non-zero work.
        BOOST_CHECK(chainActive.Tip() != nullptr);
        BOOST_CHECK(chainActive.Tip()->nChainWork > 0);

        // Test starts here
        peerLogic->SendMessages(&dummyNode1, interruptDummy); // should result in getheaders
        BOOST_CHECK(dummyNode1.vSendMsg.size() > 0);
        dummyNode1.vSendMsg.clear();

        int64_t nStartTime = GetTime();
        // Wait 21 minutes
        SetMockTime(nStartTime + 21 * 60);
        peerLogic->SendMessages(&dummyNode1, interruptDummy); // should result in getheaders
        BOOST_CHECK(dummyNode1.vSendMsg.size() > 0);
        // Wait 3 more minutes
        SetMockTime(nStartTime + 24 * 60);
        peerLogic->SendMessages(&dummyNode1, interruptDummy); // should result in disconnect
        BOOST_CHECK(dummyNode1.fDisconnect == true);
        SetMockTime(0);

        bool dummy;
        peerLogic->FinalizeNode(dummyNode1.GetId(), dummy);
    }

    BOOST_AUTO_TEST_CASE(DoS_banning_test)
    {
        BOOST_TEST_MESSAGE("Running DoS Banning Test");

        std::atomic<bool> interruptDummy(false);

        connman->ClearBanned();
        CAddress addr1(ip(0xa0b0c001), NODE_NONE);
        CNode dummyNode1(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr1, 0, 0, CAddress(), "", true);
        dummyNode1.SetSendVersion(PROTOCOL_VERSION);
        peerLogic->InitializeNode(&dummyNode1);
        dummyNode1.nVersion = 1;
        dummyNode1.fSuccessfullyConnected = true;
        Misbehaving(dummyNode1.GetId(), 100); // Should get banned
        peerLogic->SendMessages(&dummyNode1, interruptDummy);
        BOOST_CHECK(connman->IsBanned(addr1));
        BOOST_CHECK(!connman->IsBanned(ip(0xa0b0c001 | 0x0000ff00))); // Different IP, not banned

        CAddress addr2(ip(0xa0b0c002), NODE_NONE);
        CNode dummyNode2(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr2, 1, 1, CAddress(), "", true);
        dummyNode2.SetSendVersion(PROTOCOL_VERSION);
        peerLogic->InitializeNode(&dummyNode2);
        dummyNode2.nVersion = 1;
        dummyNode2.fSuccessfullyConnected = true;
        Misbehaving(dummyNode2.GetId(), 50);
        peerLogic->SendMessages(&dummyNode2, interruptDummy);
        BOOST_CHECK(!connman->IsBanned(addr2)); // 2 not banned yet...
        BOOST_CHECK(connman->IsBanned(addr1));  // ... but 1 still should be
        Misbehaving(dummyNode2.GetId(), 50);
        peerLogic->SendMessages(&dummyNode2, interruptDummy);
        BOOST_CHECK(connman->IsBanned(addr2));

        bool dummy;
        peerLogic->FinalizeNode(dummyNode1.GetId(), dummy);
        peerLogic->FinalizeNode(dummyNode2.GetId(), dummy);
    }

    BOOST_AUTO_TEST_CASE(DoS_banscore_test)
    {
        BOOST_TEST_MESSAGE("Running DoS Banscore Test Test");

        std::atomic<bool> interruptDummy(false);

        connman->ClearBanned();
        gArgs.ForceSetArg("-banscore", "111"); // because 11 is my favorite number
        CAddress addr1(ip(0xa0b0c001), NODE_NONE);
        CNode dummyNode1(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr1, 3, 1, CAddress(), "", true);
        dummyNode1.SetSendVersion(PROTOCOL_VERSION);
        peerLogic->InitializeNode(&dummyNode1);
        dummyNode1.nVersion = 1;
        dummyNode1.fSuccessfullyConnected = true;
        Misbehaving(dummyNode1.GetId(), 100);
        peerLogic->SendMessages(&dummyNode1, interruptDummy);
        BOOST_CHECK(!connman->IsBanned(addr1));
        Misbehaving(dummyNode1.GetId(), 10);
        peerLogic->SendMessages(&dummyNode1, interruptDummy);
        BOOST_CHECK(!connman->IsBanned(addr1));
        Misbehaving(dummyNode1.GetId(), 1);
        peerLogic->SendMessages(&dummyNode1, interruptDummy);
        BOOST_CHECK(connman->IsBanned(addr1));
        gArgs.ForceSetArg("-banscore", std::to_string(DEFAULT_BANSCORE_THRESHOLD));

        bool dummy;
        peerLogic->FinalizeNode(dummyNode1.GetId(), dummy);
    }

    BOOST_AUTO_TEST_CASE(DoS_bantime_test)
    {
        BOOST_TEST_MESSAGE("Running DoS Bantime Test");

        std::atomic<bool> interruptDummy(false);

        connman->ClearBanned();
        int64_t nStartTime = GetTime();
        SetMockTime(nStartTime); // Overrides future calls to GetTime()

        CAddress addr(ip(0xa0b0c001), NODE_NONE);
        CNode dummyNode(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr, 4, 4, CAddress(), "", true);
        dummyNode.SetSendVersion(PROTOCOL_VERSION);
        peerLogic->InitializeNode(&dummyNode);
        dummyNode.nVersion = 1;
        dummyNode.fSuccessfullyConnected = true;

        Misbehaving(dummyNode.GetId(), 100);
        peerLogic->SendMessages(&dummyNode, interruptDummy);
        BOOST_CHECK(connman->IsBanned(addr));

        SetMockTime(nStartTime + 60 * 60);
        BOOST_CHECK(connman->IsBanned(addr));

        SetMockTime(nStartTime + 60 * 60 * 24 + 1);
        BOOST_CHECK(!connman->IsBanned(addr));

        bool dummy;
        peerLogic->FinalizeNode(dummyNode.GetId(), dummy);
    }

    CTransactionRef RandomOrphan()
    {
        std::map<uint256, COrphanTx>::iterator it;
        it = mapOrphanTransactions.lower_bound(InsecureRand256());
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        return it->second.tx;
    }

    BOOST_AUTO_TEST_CASE(DoS_maporphans_test)
    {
        BOOST_TEST_MESSAGE("Running DoS MapOrphans Test");

        CKey key;
        key.MakeNewKey(true);
        CBasicKeyStore keystore;
        keystore.AddKey(key);

        // 50 orphan transactions:
        for (int i = 0; i < 50; i++)
        {
            CMutableTransaction tx;
            tx.vin.resize(1);
            tx.vin[0].prevout.n = 0;
            tx.vin[0].prevout.hash = InsecureRand256();
            tx.vin[0].scriptSig << OP_1;
            tx.vout.resize(1);
            tx.vout[0].nValue = 1 * CENT;
            tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

            AddOrphanTx(MakeTransactionRef(tx), i);
        }

        // ... and 50 that depend on other orphans:
        for (int i = 0; i < 50; i++)
        {
            CTransactionRef txPrev = RandomOrphan();

            CMutableTransaction tx;
            tx.vin.resize(1);
            tx.vin[0].prevout.n = 0;
            tx.vin[0].prevout.hash = txPrev->GetHash();
            tx.vout.resize(1);
            tx.vout[0].nValue = 1 * CENT;
            tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
            SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL);

            AddOrphanTx(MakeTransactionRef(tx), i);
        }

        // This really-big orphan should be ignored:
        for (int i = 0; i < 10; i++)
        {
            CTransactionRef txPrev = RandomOrphan();

            CMutableTransaction tx;
            tx.vout.resize(1);
            tx.vout[0].nValue = 1 * CENT;
            tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
            tx.vin.resize(2777);
            for (unsigned int j = 0; j < tx.vin.size(); j++)
            {
                tx.vin[j].prevout.n = j;
                tx.vin[j].prevout.hash = txPrev->GetHash();
            }
            SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL);
            // Re-use same signature for other inputs
            // (they don't have to be valid for this test)
            for (unsigned int j = 1; j < tx.vin.size(); j++)
                tx.vin[j].scriptSig = tx.vin[0].scriptSig;

            BOOST_CHECK(!AddOrphanTx(MakeTransactionRef(tx), i));
        }

        // Test EraseOrphansFor:
        for (NodeId i = 0; i < 3; i++)
        {
            size_t sizeBefore = mapOrphanTransactions.size();
            EraseOrphansFor(i);
            BOOST_CHECK(mapOrphanTransactions.size() < sizeBefore);
        }

        // Test LimitOrphanTxSize() function:
        LimitOrphanTxSize(40);
        BOOST_CHECK(mapOrphanTransactions.size() <= 40);
        LimitOrphanTxSize(10);
        BOOST_CHECK(mapOrphanTransactions.size() <= 10);
        LimitOrphanTxSize(0);
        BOOST_CHECK(mapOrphanTransactions.empty());
    }

// Admission CPU of rejected transactions: a credit per address that refills
// and, once used up, ignores the address for a while; shared, inbound and
// reserved accounts per one-minute window, exceeded at most by one admission.
BOOST_AUTO_TEST_CASE(tx_admission_budget)
{
    using Budget = TxAdmissionBudget;
    const int64_t t = 1000000;

    {
        // 3 s of credit per address, refilled at 1 s per minute; using it up
        // ignores the address for 10 minutes. Checks are 30 s or more apart,
        // so the shared buckets have refilled.
        Budget budget;
        BOOST_CHECK(budget.MayAdmit("a", false, false, t));
        budget.ChargeRejected("a", false, false, 2000000, t);           // 1 s left
        BOOST_CHECK(budget.MayAdmit("a", false, false, t + 30));         // 1.5 s
        budget.ChargeRejected("a", false, false, 1600000, t + 30);      // used up
        BOOST_CHECK(!budget.MayAdmit("a", false, false, t + 60));
        BOOST_CHECK(budget.MayAdmit("b", false, false, t + 60));
        BOOST_CHECK(!budget.MayAdmit("a", false, false, t + 30 + Budget::IGNORE_SECONDS - 1));
        BOOST_CHECK(budget.MayAdmit("a", false, false, t + 30 + Budget::IGNORE_SECONDS));
    }
    {
        // The credit refills up to 3 s at most.
        Budget budget;
        budget.ChargeRejected("a", false, false, 2500000, t);           // 0.5 s
        budget.ChargeRejected("a", false, false, 2400000, t + 120);     // 2.5 s - 2.4 s
        BOOST_CHECK(budget.MayAdmit("a", false, false, t + 180));        // 1.1 s
        budget.ChargeRejected("a", false, false, 1200000, t + 180);
        BOOST_CHECK(!budget.MayAdmit("a", false, false, t + 240));
        BOOST_CHECK(budget.MayAdmit("b", false, false, t + 240));
    }
    {
        Budget budget;
        budget.ChargeRejected("c", false, false, 2900000, t);
        budget.ChargeRejected("c", false, false, 3000000, t + 3600);    // refilled to 3 s at most
        BOOST_CHECK(!budget.MayAdmit("c", false, false, t + 3700));
        BOOST_CHECK(budget.MayAdmit("d", false, false, t + 3700));
    }
    {
        // Inbound peers share a bucket of 1 s refilled at 9 s per minute. It
        // may go below zero by the admission in progress, and then waits for
        // refills to pay that back.
        Budget budget;
        BOOST_CHECK(budget.MayAdmit("i1", false, false, t));
        budget.ChargeRejected("i1", false, false, 600000, t);           // inbound 0.4 s
        BOOST_CHECK(budget.MayAdmit("i2", false, false, t));
        budget.ChargeRejected("i2", false, false, 700000, t);           // inbound -0.3 s
        BOOST_CHECK(!budget.MayAdmit("i3", false, false, t));
        // Outbound and whitelisted peers keep their own bucket.
        BOOST_CHECK(budget.MayAdmit("o1", true, false, t));
        BOOST_CHECK(budget.MayAdmit("w", true, true, t));
        BOOST_CHECK(!budget.MayAdmit("i3", false, false, t + 2));        // 0.15 s per second: 0
        BOOST_CHECK(budget.MayAdmit("i3", false, false, t + 3));         // 0.15 s
    }
    {
        // The shared bucket (2 s, 13 s per minute) lets one admission run
        // past it in total, not one per group.
        Budget budget;
        budget.ChargeRejected("i1", false, false, 900000, t);           // inbound 0.1 s, shared 1.1 s
        budget.ChargeRejected("o1", true, false, 900000, t);            // reserved 0.1 s, shared 0.2 s
        BOOST_CHECK(budget.MayAdmit("o2", true, false, t));
        budget.ChargeRejected("o2", true, false, 500000, t);            // shared -0.3 s
        BOOST_CHECK(!budget.MayAdmit("i2", false, false, t));            // inbound has 0.1 s left
        BOOST_CHECK(!budget.MayAdmit("o3", true, false, t));
        BOOST_CHECK(!budget.MayAdmit("w", true, true, t));
        BOOST_CHECK(budget.MayAdmit("i2", false, false, t + 2));
    }
    {
        // Sustained load from fresh addresses of both groups, 0.4 s per
        // admission: over 60 s, at most 10 s inbound, 5 s reserved and 15 s
        // in total, each plus the admission in progress, and the rates are
        // actually available.
        Budget budget;
        int64_t usedInbound = 0, usedReserved = 0;
        for (int64_t second = 0; second < 60; ++second) {
            for (int k = 0; k < 10; ++k) {
                const std::string key = "s" + std::to_string(second * 10 + k);
                if (budget.MayAdmit(key, false, false, t + second)) {
                    budget.ChargeRejected(key, false, false, 400000, t + second);
                    usedInbound += 400000;
                }
                if (budget.MayAdmit(key + "o", true, false, t + second)) {
                    budget.ChargeRejected(key + "o", true, false, 400000, t + second);
                    usedReserved += 400000;
                }
            }
        }
        BOOST_CHECK(usedInbound <= 10000000 + 400000);
        BOOST_CHECK(usedReserved <= 5000000 + 400000);
        BOOST_CHECK(usedInbound + usedReserved <= 15000000 + 400000);
        BOOST_CHECK(usedInbound >= 9000000);
        BOOST_CHECK(usedReserved >= 4000000);
    }
    {
        // Whitelisted peers have no per-address credit.
        Budget budget;
        budget.ChargeRejected("w", true, true, 4000000, t);
        budget.ChargeRejected("x", true, false, 4000000, t);
        BOOST_CHECK(!budget.MayAdmit("w", true, true, t));               // the buckets are empty
        BOOST_CHECK(budget.MayAdmit("w", true, true, t + 180));
        BOOST_CHECK(!budget.MayAdmit("x", true, false, t + 180));
    }
    {
        // What the queue of waiting transactions asks: whether an address is
        // ignored, whether a group has room, when an address was last charged.
        Budget budget;
        BOOST_CHECK_EQUAL(budget.LastCharge("a"), 0);
        BOOST_CHECK(!budget.IsIgnored("a", false, t));
        BOOST_CHECK(budget.HasRoom(false, t));
        budget.ChargeRejected("a", false, false, 1500000, t);           // 1.5 s left
        BOOST_CHECK_EQUAL(budget.LastCharge("a"), t);
        BOOST_CHECK(!budget.HasRoom(false, t));                           // inbound -0.5 s
        BOOST_CHECK(budget.HasRoom(true, t));                             // reserved 1 s, shared 0.5 s
        BOOST_CHECK(!budget.IsIgnored("a", false, t));
        budget.ChargeRejected("a", false, false, 1700000, t + 10);      // 1.67 s - 1.7 s
        BOOST_CHECK(budget.IsIgnored("a", false, t + 10));
        BOOST_CHECK(!budget.IsIgnored("a", true, t + 10));                // whitelisted: never
        BOOST_CHECK_EQUAL(budget.LastCharge("a"), t + 10);
        BOOST_CHECK(!budget.IsIgnored("a", false, t + 10 + Budget::IGNORE_SECONDS));
    }
    {
        // One account per IPv4 address and per IPv6 /48.
        CNetAddr a4, b4, a6, b6, c6;
        BOOST_REQUIRE(LookupHost("192.0.2.1", a4, false));
        BOOST_REQUIRE(LookupHost("192.0.2.2", b4, false));
        BOOST_REQUIRE(LookupHost("2001:db8:1:2::1", a6, false));
        BOOST_REQUIRE(LookupHost("2001:db8:1:ff00::9", b6, false));
        BOOST_REQUIRE(LookupHost("2001:db8:2::1", c6, false));
        BOOST_CHECK(Budget::Key(a4) != Budget::Key(b4));
        BOOST_CHECK_EQUAL(Budget::Key(a6), Budget::Key(b6));
        BOOST_CHECK(Budget::Key(a6) != Budget::Key(c6));
    }
    {
        // The table is bounded: past MAX_ADDRESSES the oldest account goes.
        Budget budget;
        budget.ChargeRejected("first", false, false, 3000000, t);
        BOOST_CHECK(!budget.MayAdmit("first", false, false, t + 60));
        for (size_t i = 0; i < Budget::MAX_ADDRESSES; ++i) {
            budget.ChargeRejected("x" + std::to_string(i), false, false, 1, t + 61);
        }
        BOOST_CHECK(budget.MayAdmit("first", false, false, t + 62));
    }
}

BOOST_AUTO_TEST_SUITE_END()
