// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include <amount.h>
#include <assets/assetdb.h>
#include <base58.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <crypto/ethash/helpers.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <crypto/ethash/progpow_test_vectors.hpp>
#include <hash.h>
#include <miner.h>
#include <pow.h>
#include <rpc/server.h>
#include <test/epoch_context_cache_test_access.h>
#include <test/test_neurai.h>
#include <util.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

extern std::map<std::string, CBlock> mapXNAKAWBlockTemplates;

namespace {
std::string Upper(std::string text, bool mixed = false)
{
    for (size_t i = 0; i < text.size(); ++i) {
        if ((!mixed || i % 2) && text[i] >= 'a' && text[i] <= 'f') text[i] -= 'a' - 'A';
    }
    return text;
}

std::vector<std::string> BadHashes()
{
    std::vector<std::string> result{"", "0x" + std::string(62, '0')};
    for (size_t size : {1, 32, 63, 65, 66, 200}) result.emplace_back(size, '0');
    for (char c : {'/', ':', 'g', 'G', ' ', '\t', '\n', '+', '-', '\0', char(0xff)}) {
        for (size_t pos : {0, 1, 62, 63}) {
            std::string text(64, 'a');
            text[pos] = c;
            result.push_back(text);
        }
    }
    return result;
}

UniValue RPC(const std::string& method, const std::vector<UniValue>& values)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = UniValue(UniValue::VARR);
    for (const auto& value : values) request.params.push_back(value);
    return tableRPC[method]->actor(request);
}

std::vector<UniValue> Params(const std::string& method)
{
    std::vector<UniValue> values{std::string(64, '0'), std::string(64, '0'), "0"};
    if (method == "getkawpowhash") { values.emplace_back(0); values.emplace_back(std::string(64, 'f')); }
    return values;
}

void ExpectError(const std::string& method, const std::vector<UniValue>& params, int code,
                 const std::string& message = "")
{
    try { RPC(method, params); BOOST_ERROR("Malformed mining parameters were accepted"); }
    catch (const UniValue& error) {
        BOOST_CHECK_EQUAL(find_value(error, "code").get_int(), code);
        BOOST_CHECK_EQUAL(find_value(error, "message").get_str().find(message), 0U);
    }
}

// Every malformed call must fail before even requesting an epoch context.
struct NoContexts {
    int builds{0};
    EpochContextCacheTestAccess::FactoryOverride rpc{KawpowRpcCache(), [this](int) {
        ++builds; return EpochContextCache::Context{};
    }};
    EpochContextCacheTestAccess::FactoryOverride validation{KawpowValidationCache(), [this](int) {
        ++builds; return EpochContextCache::Context{};
    }};
};

struct MiningHexSetup : TestingSetup {
    CCoinsViewDB* savedCoins{::pcoinsdbview};
    CAssetsDB* savedAssets{passetsdb};
    std::string savedAddress{gArgs.GetArg("-miningaddress", "")};
    std::string savedBypass{gArgs.GetArg("-bypassdownload", "0")};

    MiningHexSetup() : TestingSetup(CBaseChainParams::MAIN)
    {
        ::pcoinsdbview = pcoinsdbview;
        passetsdb = new CAssetsDB(1 << 20, true, true);
        gArgs.ForceSetArg("-bypassdownload", "1");
        uint160 id;
        id.SetHex("1234");
        gArgs.ForceSetArg("-miningaddress", EncodeDestination(CKeyID(id)));
    }
    ~MiningHexSetup()
    {
        GetMainSignals().FlushBackgroundCallbacks();
        gArgs.ForceSetArg("-miningaddress", savedAddress);
        gArgs.ForceSetArg("-bypassdownload", savedBypass);
        delete passetsdb;
        passetsdb = savedAssets;
        ::pcoinsdbview = savedCoins;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(hash256_hex_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hex_conversion_preserves_textual_byte_order)
{
    const std::string input = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff";
    const uint8_t expected[32] = {1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    // Use a non-palindromic sequence so an internal uint256 byte copy fails.
    for (const auto& variant : {input, Upper(input), Upper(input, true)}) {
        const auto hash = to_hash256(variant);
        BOOST_CHECK_EQUAL_COLLECTIONS(hash.bytes, hash.bytes + 32, expected, expected + 32);
        BOOST_CHECK_EQUAL(to_hex(hash), input);
    }
}

BOOST_AUTO_TEST_CASE(hex_conversion_rejects_wrong_lengths_and_digits)
{
    for (const auto& text : BadHashes()) BOOST_CHECK_THROW(to_hash256(text), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mining_rpc_hex_tests, MiningHexSetup)

BOOST_AUTO_TEST_CASE(hash_fields_are_validated_before_lookup_or_hashing)
{
    NoContexts contexts;
    for (const std::string method : {"getkawpowhash", "pprpcsb"}) {
        for (size_t field : {0, 1, 4}) {
            if (field == 4 && method == "pprpcsb") continue;
            const std::string name = field == 0 ? "header_hash" : field == 1 ? "mix_hash" : "target";
            for (const auto& text : BadHashes()) {
                auto params = Params(method);
                params[field] = UniValue(text);
                ExpectError(method, params, RPC_INVALID_PARAMETER, name);
            }
        }
    }
    BOOST_CHECK_EQUAL(contexts.builds, 0);
}

BOOST_AUTO_TEST_CASE(nonces_reject_signs_overflow_and_non_hex)
{
    NoContexts contexts;
    const std::vector<std::string> invalid{"", "0x", "0X", "+1", "-1", " 1", "1 ", "1\n", "g",
        "0xg", "0x+1", "10000000000000000", "00000000000000000", "0x10000000000000000",
        std::string("1\0f", 3), std::string(1, char(0xff))};
    for (const std::string method : {"getkawpowhash", "pprpcsb"}) {
        for (const auto& nonce : invalid) {
            auto params = Params(method);
            params[2] = UniValue(nonce);
            ExpectError(method, params, RPC_INVALID_PARAMS,
                method == "pprpcsb" ? "Invalid hex nonce" : "Invalid nonce hex string");
        }
    }
    BOOST_CHECK_EQUAL(contexts.builds, 0);
}

BOOST_AUTO_TEST_CASE(types_height_and_argument_count_are_checked)
{
    NoContexts contexts;
    for (const std::string method : {"getkawpowhash", "pprpcsb"}) {
        const auto good = Params(method);
        for (size_t field = 0; field < good.size(); ++field) {
            for (const auto& wrong : {UniValue(), UniValue(UniValue::VOBJ), UniValue(UniValue::VARR),
                                      UniValue(true), field == 3 ? UniValue("0") : UniValue(0)}) {
                auto params = good;
                params[field] = wrong;
                ExpectError(method, params, RPC_TYPE_ERROR);
            }
        }
        for (size_t size = 0; size <= 6; ++size) {
            if (size == good.size() || (method == "getkawpowhash" && size == 4)) continue;
            auto params = good;
            params.resize(size);
            BOOST_CHECK_THROW(RPC(method, params), std::runtime_error);
        }
    }
    for (const std::string value : {"-1", "1.5", "4294967296", "1e100"}) {
        auto params = Params("getkawpowhash");
        BOOST_REQUIRE(params[3].setNumStr(value));
        ExpectError("getkawpowhash", params, RPC_INVALID_PARAMETER, "height");
    }
    for (const uint64_t height : {11ULL, 0xffffffffULL}) {
        auto params = Params("getkawpowhash");
        params[3] = UniValue(height);
        ExpectError("getkawpowhash", params, RPC_DESERIALIZATION_ERROR, "Block height is too large");
    }
    BOOST_CHECK_EQUAL(contexts.builds, 0);
}

BOOST_AUTO_TEST_CASE(known_vector_survives_case_normalization_and_target_boundaries)
{
    // No chain validation occurs while this synthetic tip admits vector height 49.
    struct TipGuard {
        CBlockIndex* saved;
        CBlockIndex tip;
        TipGuard() {
            LOCK(cs_main);
            saved = chainActive.Tip();
            tip.nHeight = 49;
            tip.pprev = saved;
            chainActive.SetTip(&tip);
        }
        ~TipGuard() { LOCK(cs_main); chainActive.SetTip(saved); }
    } tip;
    const auto& vector = progpow_hash_test_cases[1];
    std::string lowerTarget = vector.final_hash_hex;
    lowerTarget.back() = '2'; // The published digest ends in 3.
    for (int style = 0; style < 3; ++style) {
        const auto hex = [style](const std::string& text) { return style ? Upper(text, style == 2) : text; };
        for (const auto& target : {std::string(vector.final_hash_hex), lowerTarget, std::string(64, 'f'), std::string(64, '0')}) {
            const auto result = RPC("getkawpowhash", {hex(vector.header_hash_hex), hex(vector.mix_hash_hex),
                std::string("0X") + hex(vector.nonce_hex), vector.block_number, hex(target)});
            BOOST_CHECK_EQUAL(find_value(result, "digest").get_str(), vector.final_hash_hex);
            BOOST_CHECK_EQUAL(find_value(result, "mix_hash").get_str(), vector.mix_hash_hex);
            BOOST_CHECK_EQUAL(find_value(result, "result").get_str(), "true");
            BOOST_CHECK_EQUAL(find_value(result, "meets_target").get_str(),
                target == lowerTarget || target == std::string(64, '0') ? "false" : "true");
        }
    }
    const auto result = RPC("getkawpowhash", {vector.header_hash_hex, std::string(64, '0'), vector.nonce_hex, vector.block_number});
    BOOST_CHECK_EQUAL(find_value(result, "result").get_str(), "false");
    BOOST_CHECK_EQUAL(find_value(result, "digest").get_str(), vector.final_hash_hex);
    BOOST_CHECK(find_value(result, "meets_target").isNull());
}

BOOST_AUTO_TEST_CASE(nonce_formats_preserve_all_64_bits)
{
    const auto context = KawpowValidationCache().Get(0);
    const std::vector<std::pair<std::string, uint64_t>> nonces{{"0", 0}, {"aBc", 0xabc}, {"0xAbC", 0xabc},
        {"0XABC", 0xabc}, {"0000000000000001", 1}, {"fFfFfFfFfFfFfFfF", UINT64_MAX},
        {"0xFFFFFFFFFFFFFFFF", UINT64_MAX}};
    for (const auto& nonce : nonces) {
        const auto expected = progpow::hash(*context, 0, {}, nonce.second);
        const auto result = RPC("getkawpowhash", {std::string(64, '0'), to_hex(expected.mix_hash), nonce.first, 0});
        BOOST_CHECK_EQUAL(find_value(result, "result").get_str(), "true");
        BOOST_CHECK_EQUAL(find_value(result, "digest").get_str(), to_hex(expected.final_hash));
    }
}

BOOST_AUTO_TEST_CASE(submit_accepts_lower_upper_and_mixed_case)
{
    auto first = BlockAssembler(GetParams()).CreateNewBlock(CScript() << OP_TRUE)->block;
    first.hashMerkleRoot = BlockMerkleRoot(first);
    do { ++first.nNonce64; }
    while (!CheckProofOfWork(first.GetHashFull(first.mix_hash), first.nBits, GetParams().GetConsensus()));
    BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(first), true, nullptr));
    for (int style = 0; style < 3; ++style) {
        const auto work = RPC("getblocktemplate", {UniValue(UniValue::VOBJ)});
        const auto header = find_value(work, "pprpcheader").get_str();
        CBlock block;
        { LOCK(cs_main); block = mapXNAKAWBlockTemplates.at(header); }
        do { ++block.nNonce64; }
        while (!CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
        const auto hex = [style](const std::string& text) { return style ? Upper(text, style == 2) : text; };
        const auto result = RPC("pprpcsb", {hex(header), hex(block.mix_hash.GetHex()), "0X" + hex(strprintf("%x", block.nNonce64))});
        BOOST_CHECK(result.isBool() && result.get_bool());
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()
