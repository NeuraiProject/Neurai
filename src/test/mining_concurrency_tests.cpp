// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include <amount.h>
#include <assets/assetdb.h>
#include <base58.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <crypto/ethash/helpers.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <hash.h>
#include <miner.h>
#include <pow.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <test/epoch_context_cache_test_access.h>
#include <test/test_neurai.h>
#include <util.h>
#include <utiltime.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>
#include <array>
#include <atomic>
#include <future>

extern std::map<std::string, CBlock> mapXNAKAWBlockTemplates;

namespace {
using Context = EpochContextCache::Context;

UniValue RPC(const std::string& method, const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    // Unlike CallRPC, this helper makes no Boost assertions from worker threads.
    return tableRPC[method]->actor(request);
}

std::string SubmitError(const std::string& header, const std::string& mix = std::string(64, '0'), const std::string& nonce = "0")
{
    UniValue params(UniValue::VARR);
    params.push_back(header); params.push_back(mix); params.push_back(nonce);
    try { return RPC("pprpcsb", params).write(); }
    catch (const UniValue& error) { return find_value(error, "message").get_str(); }
}

struct MiningSetup : TestingSetup {
    CCoinsViewDB* savedCoins{::pcoinsdbview};
    CAssetsDB* savedAssets{passetsdb};
    int64_t savedTime{GetMockTime()};
    std::string savedAddress{gArgs.GetArg("-miningaddress", "")};
    std::string savedBypass{gArgs.GetArg("-bypassdownload", "0")};

    MiningSetup() : TestingSetup(CBaseChainParams::MAIN)
    {
        ::pcoinsdbview = pcoinsdbview;
        passetsdb = new CAssetsDB(1 << 20, true, true);
        gArgs.ForceSetArg("-bypassdownload", "1");
        uint160 id;
        id.SetHex("1234");
        gArgs.ForceSetArg("-miningaddress", EncodeDestination(CKeyID(id)));
    }
    ~MiningSetup()
    {
        GetMainSignals().FlushBackgroundCallbacks();
        gArgs.ForceSetArg("-miningaddress", savedAddress);
        gArgs.ForceSetArg("-bypassdownload", savedBypass);
        SetMockTime(savedTime);
        delete passetsdb;
        passetsdb = savedAssets;
        ::pcoinsdbview = savedCoins;
    }
    void NewTip()
    {
        auto block = BlockAssembler(GetParams()).CreateNewBlock(CScript() << OP_TRUE)->block;
        block.hashMerkleRoot = BlockMerkleRoot(block);
        do { ++block.nNonce64; }
        while (!CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
        BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr));
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
    }
    std::string Template()
    {
        UniValue params(UniValue::VARR);
        params.push_back(UniValue(UniValue::VOBJ));
        return find_value(RPC("getblocktemplate", params), "pprpcheader").get_str();
    }
    std::string Refresh()
    {
        SetMockTime(GetTime() + 31);
        mempool.AddTransactionsUpdated(1);
        return Template();
    }
    CBlock Copy(const std::string& header)
    {
        LOCK(cs_main);
        return mapXNAKAWBlockTemplates.at(header);
    }
};
}

BOOST_FIXTURE_TEST_SUITE(mining_concurrency_tests, MiningSetup)

BOOST_AUTO_TEST_CASE(rpc_and_validation_hash_correctly_during_concurrent_epoch_eviction)
{
    std::array<Context, 3> contexts;
    std::array<CBlockHeader, 3> headers;
    std::array<ethash::result, 3> expected;
    for (int epoch = 0; epoch < 3; ++epoch) {
        contexts[epoch] = Context(ethash::create_epoch_context(epoch));
        auto& header = headers[epoch];
        header.nHeight = epoch * ETHASH_EPOCH_LENGTH;
        header.nTime = nKAWPOWActivationTime + 1;
        header.nNonce64 = 17 + epoch;
        expected[epoch] = progpow::hash(*contexts[epoch], header.nHeight,
            to_hash256(header.GetKAWPOWHeaderHash().GetHex()), header.nNonce64);
    }
    std::atomic<int> validationBuilds{0}, rpcBuilds{0};
    EpochContextCacheTestAccess::FactoryOverride validation(KawpowValidationCache(), [&](int epoch) {
        ++validationBuilds; return contexts.at(epoch);
    });
    EpochContextCacheTestAccess::FactoryOverride rpc(KawpowRpcCache(), [&](int epoch) {
        ++rpcBuilds; return contexts.at(epoch);
    });
    // Only RPC height admission uses this synthetic tip. No validation or chain
    // updates run until all workers join and the real tip has been restored.
    struct TipGuard {
        CBlockIndex* saved;
        CBlockIndex tip;
        TipGuard() {
            LOCK(cs_main);
            saved = chainActive.Tip();
            tip.nHeight = 3 * ETHASH_EPOCH_LENGTH;
            tip.pprev = saved;
            chainActive.SetTip(&tip);
        }
        ~TipGuard() { LOCK(cs_main); chainActive.SetTip(saved); }
    } tip;
    std::promise<void> start;
    const auto gate = start.get_future().share();
    std::vector<std::future<bool>> workers;
    for (int worker = 0; worker < 8; ++worker) {
        workers.push_back(std::async(std::launch::async, [&, worker] {
            gate.wait();
            for (int i = 0; i < 30; ++i) {
                const int epoch = (i + worker) % 3;
                const auto& header = headers[epoch];
                if (worker % 2) {
                    uint256 mix;
                    const auto digest = header.GetHashFull(mix);
                    if (digest.GetHex() != to_hex(expected[epoch].final_hash) ||
                        mix.GetHex() != to_hex(expected[epoch].mix_hash)) return false;
                } else {
                    UniValue params(UniValue::VARR);
                    params.push_back(header.GetKAWPOWHeaderHash().GetHex());
                    params.push_back(to_hex(expected[epoch].mix_hash));
                    params.push_back(strprintf("%x", header.nNonce64));
                    params.push_back(static_cast<int>(header.nHeight));
                    const auto result = RPC("getkawpowhash", params);
                    if (find_value(result, "digest").get_str() != to_hex(expected[epoch].final_hash) ||
                        find_value(result, "result").get_str() != "true") return false;
                }
            }
            return true;
        }));
    }
    start.set_value();
    for (auto& worker : workers) BOOST_CHECK(worker.get());
    BOOST_CHECK_GT(validationBuilds.load(), 3);
    BOOST_CHECK_GT(rpcBuilds.load(), 3);
}

BOOST_AUTO_TEST_CASE(rpc_cache_failures_are_retryable_and_do_not_evict_validation)
{
    int attempts = 0;
    const auto held = KawpowValidationCache().Get(0);
    EpochContextCacheTestAccess::FactoryOverride rpc(KawpowRpcCache(), [&](int epoch) -> Context {
        if (++attempts == 1) return {};
        return Context(ethash::create_epoch_context(epoch));
    });
    UniValue params(UniValue::VARR);
    params.push_back(std::string(64, '0')); params.push_back(std::string(64, '0'));
    params.push_back("0"); params.push_back(0);
    BOOST_CHECK_EXCEPTION(RPC("getkawpowhash", params), UniValue, [](const UniValue& e) {
        return find_value(e, "message").get_str().find("KAWPOW context unavailable") == 0;
    });
    BOOST_CHECK_NO_THROW(RPC("getkawpowhash", params));
    BOOST_CHECK_EQUAL(attempts, 2);
    for (int epoch : {1, 2, 3}) KawpowRpcCache().Get(epoch);
    BOOST_CHECK(KawpowValidationCache().Get(0) == held);
}

BOOST_AUTO_TEST_CASE(refreshed_templates_keep_previous_work_submittable)
{
    NewTip();
    const auto first = Template();
    auto block = Copy(first);
    const auto second = Refresh();
    BOOST_REQUIRE(first != second);
    BOOST_CHECK(Copy(first).GetKAWPOWHeaderHash() == block.GetKAWPOWHeaderHash());
    do { ++block.nNonce64; }
    while (!CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(SubmitError(first, block.mix_hash.GetHex(), strprintf("%x", block.nNonce64)), "true");
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    Template();
    BOOST_CHECK_EQUAL(SubmitError(second), "Block header hash not found in block data");
}

BOOST_AUTO_TEST_CASE(template_retention_is_bounded_and_reuse_does_not_evict)
{
    NewTip();
    std::vector<std::string> issued{Template()};
    for (size_t i = 1; i < MAX_KAWPOW_BLOCK_TEMPLATES; ++i) issued.push_back(Refresh());
    for (int i = 0; i < 30; ++i) BOOST_CHECK_EQUAL(Template(), issued.back());
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapXNAKAWBlockTemplates.size(), MAX_KAWPOW_BLOCK_TEMPLATES);
        for (const auto& header : issued) BOOST_CHECK_EQUAL(mapXNAKAWBlockTemplates.count(header), 1U);
    }
    const auto last = Refresh();
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(mapXNAKAWBlockTemplates.size(), MAX_KAWPOW_BLOCK_TEMPLATES);
    BOOST_CHECK_EQUAL(mapXNAKAWBlockTemplates.count(issued.front()), 0U);
    BOOST_CHECK_EQUAL(mapXNAKAWBlockTemplates.count(issued[1]), 1U);
    BOOST_CHECK_EQUAL(mapXNAKAWBlockTemplates.count(last), 1U);
}

BOOST_AUTO_TEST_CASE(submission_copies_under_lock_and_hashes_after_releasing_it)
{
    NewTip();
    const auto header = Template();
    {
        LOCK(cs_main);
        mapXNAKAWBlockTemplates.at(header).nBits = 0; // Fail after the context rendezvous.
    }
    const auto context = Context(ethash::create_epoch_context(0));
    std::promise<void> hashing, release;
    const auto resume = release.get_future().share();
    auto entered = hashing.get_future();
    EpochContextCacheTestAccess::FactoryOverride validation(KawpowValidationCache(), [&](int) {
        hashing.set_value(); resume.wait(); return context;
    });
    auto submit = std::async(std::launch::async, [&] { return SubmitError(header); });
    const bool entered_hash = entered.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    auto writer = std::async(std::launch::async, [&] {
        LOCK(cs_main);
        mapXNAKAWBlockTemplates.at(header).vtx.clear();
        mapXNAKAWBlockTemplates.erase(header);
    });
    const bool unlocked = writer.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    release.set_value(); // Always release workers, including on assertion failures.
    writer.get();
    BOOST_CHECK(entered_hash && unlocked);
    BOOST_CHECK_EQUAL(submit.get(), "Block does not solve the boundary");
}

BOOST_AUTO_TEST_CASE(missing_template_lookup_waits_for_the_writer)
{
    std::promise<void> started;
    auto ready = started.get_future();
    std::future<std::string> submit;
    bool waiting;
    {
        LOCK(cs_main);
        submit = std::async(std::launch::async, [&] {
            started.set_value();
            return SubmitError(std::string(64, 'f'));
        });
        ready.wait();
        waiting = submit.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout;
    }
    BOOST_CHECK(waiting);
    BOOST_CHECK_EQUAL(submit.get(), "Block header hash not found in block data");
}

BOOST_AUTO_TEST_CASE(concurrent_duplicate_submissions_keep_independent_results)
{
    NewTip();
    const auto header = Template();
    auto block = Copy(header);
    // A real template with an intentionally incorrect mix. Every worker checks
    // the same block hash, so each result listener can run on other RPC threads.
    block.mix_hash.SetNull();
    CDataStream bytes(SER_NETWORK, PROTOCOL_VERSION);
    bytes << block;
    const auto encoded = HexStr(bytes.begin(), bytes.end());
    std::promise<void> start;
    const auto gate = start.get_future().share();
    std::vector<std::future<bool>> workers;
    for (int worker = 0; worker < 8; ++worker) {
        workers.push_back(std::async(std::launch::async, [&, worker] {
            gate.wait();
            for (int i = 0; i < 15; ++i) {
                if (worker % 2) {
                    if (SubmitError(header) != "\"invalid-mix-hash\"") return false;
                } else {
                    UniValue params(UniValue::VARR);
                    params.push_back(encoded);
                    if (RPC("submitblock", params).get_str() != "invalid-mix-hash") return false;
                }
            }
            return true;
        }));
    }
    start.set_value();
    for (auto& worker : workers) BOOST_CHECK(worker.get());
    BOOST_CHECK_EQUAL(chainActive.Height(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
