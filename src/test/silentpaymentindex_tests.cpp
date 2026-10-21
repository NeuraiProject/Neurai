// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047 light client index (silentpaymentindex.h): canonical format against
// the independent vectors, equivalence with the wallet scanner, records
// written by ConnectBlock, startup verification and repair, and range
// queries. Runs without the wallet.

#include "silentpaymentindex.h"
#include "silentpayments.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "data/silentpayment_index_vectors.json.h"
#include "keystore.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>
#include <univalue.h>

using namespace silentpayments;

namespace {

UniValue ReadVectors()
{
    UniValue v;
    const std::string s(json_tests::silentpayment_index_vectors,
                        json_tests::silentpayment_index_vectors + sizeof(json_tests::silentpayment_index_vectors));
    BOOST_REQUIRE(v.read(s));
    return v;
}

uint256 FromHex(const std::string& hex) { return uint256S(hex); }

uint256 RawHash(const std::string& hex)
{
    const std::vector<unsigned char> v = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(v.size(), 32U);
    return uint256(v);
}

IndexBlock BlockFromJSON(const UniValue& b)
{
    IndexBlock block;
    block.height = b["height"].get_int64();
    block.hash = FromHex(b["hash"].get_str());
    block.prev = FromHex(b["prev"].get_str());
    for (const UniValue& e : b["entries"].getValues()) {
        IndexEntry entry;
        entry.txid = FromHex(e["txid"].get_str());
        const std::vector<unsigned char> tweak = ParseHex(e["tweak"].get_str());
        entry.tweak.Set(tweak.begin(), tweak.end());
        for (const UniValue& o : e["outputs"].getValues()) {
            IndexOutput output;
            output.vout = o["vout"].get_int64();
            output.commitment = RawHash(o["commitment"].get_str());
            output.value = std::stoll(o["value_sat"].get_str());
            entry.outputs.push_back(output);
        }
        block.entries.push_back(entry);
    }
    for (const UniValue& s : b["spent"].getValues()) {
        block.spent.emplace_back(FromHex(s["txid"].get_str()), s["vout"].get_int64());
    }
    return block;
}

std::vector<unsigned char> Bytes(const IndexBlock& block)
{
    std::vector<unsigned char> out;
    SerializeIndexBlock(block, out);
    return out;
}

/** A transaction spending native v3 outputs of `keys` with the strict
 *  witness shape (signatures are not checked here), and the spent outputs. */
CMutableTransaction ShapedSpend(const std::vector<CKey>& keys, std::vector<CTxOut>& spent, std::vector<COutPoint>& outpoints)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    for (size_t i = 0; i < keys.size(); ++i) {
        const COutPoint outpoint(InsecureRand256(), InsecureRandRange(5));
        CTxIn in(outpoint);
        const CPubKey pub = keys[i].GetPubKey();
        in.scriptWitness.stack = {{0x02}, std::vector<unsigned char>(71, 0x30), std::vector<unsigned char>(pub.begin(), pub.end()), {OP_TRUE}};
        tx.vin.push_back(in);
        spent.emplace_back(COIN, PaymentScript(pub));
        outpoints.push_back(outpoint);
    }
    return tx;
}

struct SilentPaymentIndexSetup : public TestChain100Setup {
    CKey scanKey, spendKey;
    PaymentCode code;
    std::vector<unsigned char> context;

    SilentPaymentIndexSetup()
    {
        scanKey.MakeNewKey(true);
        spendKey.MakeNewKey(true);
        code = PaymentCode{LocalNetworkId(), scanKey.GetPubKey(), spendKey.GetPubKey()};
        context = LocalContext();
    }

    ~SilentPaymentIndexSetup()
    {
        fSilentPaymentIndex = false;
        fHavePruned = false;
        nIndexBatchBytes = DEFAULT_INDEX_BATCH_BYTES;
        ResetIndex();
    }

    static void AddStrictKey(CBasicKeyStore& keystore, const CKey& key)
    {
        keystore.AddKey(key);
        WitnessStrictAuthScript strict;
        BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(key.GetPubKey(), strict));
        AuthScriptSpendData spendData;
        spendData.auth_type = StrictAuthScriptAuthType(strict.version);
        spendData.witnessScript = GetStrictAuthScriptTemplate();
        spendData.pubkey = key.GetPubKey();
        spendData.key_id = key.GetPubKey().GetID();
        spendData.is_default_template = true;
        BOOST_REQUIRE(keystore.AddAuthScriptSpendData(strict.version, strict.commitment, spendData));
    }

    /** Coinbase (P2PK) -> one strict v3 output of `key`. */
    CMutableTransaction FundV3(const CTransaction& coinbase, const CKey& key)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(coinbase.GetHash(), 0)));
        tx.vout.push_back(CTxOut(coinbase.vout[0].nValue - COIN, PaymentScript(key.GetPubKey())));
        CBasicKeyStore keystore;
        keystore.AddKey(coinbaseKey);
        BOOST_REQUIRE(SignSignature(keystore, coinbase.vout[0].scriptPubKey, tx, 0, coinbase.vout[0].nValue, SIGHASH_ALL));
        return tx;
    }

    /** Strict v3 output -> silent payment to `code`, signed. */
    CMutableTransaction Pay(const CMutableTransaction& funding, const CKey& key, CAmount fee = COIN)
    {
        const COutPoint outpoint(funding.GetHash(), 0);
        std::vector<CTxOut> outputs;
        std::string error;
        BOOST_REQUIRE_MESSAGE(CreateOutputs(context, {key}, {outpoint}, {{code, funding.vout[0].nValue - fee}}, outputs, error), error);
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(outpoint));
        tx.vout = outputs;
        CBasicKeyStore keystore;
        AddStrictKey(keystore, key);
        BOOST_REQUIRE(SignSignature(keystore, funding.vout[0].scriptPubKey, tx, 0, funding.vout[0].nValue, SIGHASH_ALL));
        return tx;
    }

    CScript CoinbaseScript() const { return CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG; }

    void Init(int checkDepth = DEFAULT_CHECKSILENTPAYMENTINDEX)
    {
        std::string error;
        BOOST_REQUIRE_MESSAGE(InitIndex(GetParams(), checkDepth, error), error);
    }

    void Enable(int checkDepth = DEFAULT_CHECKSILENTPAYMENTINDEX)
    {
        fSilentPaymentIndex = true;
        Init(checkDepth);
    }

    std::vector<unsigned char> Value(const uint256& hash)
    {
        std::vector<unsigned char> value;
        BOOST_REQUIRE(pblocktree->ReadSilentPaymentRecord(hash, value));
        return value;
    }

    void Put(const uint256& hash, const std::vector<unsigned char>& value)
    {
        BOOST_REQUIRE(pblocktree->WriteSilentPaymentRecords({{hash, value}}, true));
    }

    IndexBlock Record(const uint256& hash)
    {
        IndexBlock block;
        std::vector<unsigned char> bytes;
        BOOST_REQUIRE(ReadIndexRecord(hash, block, bytes));
        return block;
    }

    std::vector<std::vector<unsigned char>> AllValues()
    {
        LOCK(cs_main);
        std::vector<std::vector<unsigned char>> values;
        for (int h = IndexStartHeight(GetParams().GetConsensus()); h <= chainActive.Height(); ++h) {
            values.push_back(Value(chainActive[h]->GetBlockHash()));
        }
        return values;
    }

    const CBlockIndex* At(int height)
    {
        LOCK(cs_main);
        return chainActive[height];
    }

    /** Payment to `code` and a spend of it in the same block, plus a mixed
     *  (not eligible) spend of a v3 output; returns the paying transaction. */
    CMutableTransaction MakeIndexedBlocks()
    {
        CKey k1, k2;
        k1.MakeNewKey(true);
        k2.MakeNewKey(true);
        const CMutableTransaction fund1 = FundV3(coinbaseTxns[0], k1);
        const CMutableTransaction fund2 = FundV3(coinbaseTxns[1], k2);
        CreateAndProcessBlock({}, CoinbaseScript()); // the second coinbase matures
        CreateAndProcessBlock({fund1, fund2}, CoinbaseScript());
        const CMutableTransaction pay = Pay(fund1, k1);
        CreateAndProcessBlock({pay}, CoinbaseScript());
        return pay;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(silentpaymentindex_tests, SilentPaymentIndexSetup)

BOOST_AUTO_TEST_CASE(format_matches_the_vectors)
{
    const UniValue v = ReadVectors();
    const std::vector<unsigned char> ctx = ParseHex(v["context"].get_str());
    BOOST_REQUIRE_EQUAL(ctx.size(), 35U);
    std::vector<std::vector<unsigned char>> raw;
    for (const UniValue& item : v["blocks"].getValues()) {
        const IndexBlock block = BlockFromJSON(item["block"]);
        const std::vector<unsigned char> bytes = Bytes(block);
        BOOST_CHECK_EQUAL(HexStr(bytes), item["bytes"].get_str());
        BOOST_CHECK_EQUAL(HexStr(IndexBlockDigest(ctx, bytes)), item["digest"].get_str());
        size_t pos = 0;
        IndexBlock decoded;
        std::string error;
        BOOST_REQUIRE_MESSAGE(DeserializeIndexBlock(bytes, pos, decoded, error), error);
        BOOST_CHECK_EQUAL(pos, bytes.size());
        BOOST_CHECK(decoded == block);
        raw.push_back(bytes);
    }

    std::vector<unsigned char> message;
    SerializeIndexBlockMessage(ctx, raw[v["messages"]["block"]["block_index"].get_int()], message);
    BOOST_CHECK_EQUAL(HexStr(message), v["messages"]["block"]["hex"].get_str());

    const UniValue& range = v["messages"]["range"];
    IndexRangeHeader header;
    header.snapshotHeight = range["header"]["snapshot_height"].get_int64();
    header.snapshotHash = FromHex(range["header"]["snapshot_hash"].get_str());
    header.syncedHeight = range["header"]["synced_height"].get_int64();
    header.nextHeight = range["header"]["next_height"].get_int64();
    header.status = range["header"]["status"].get_int();
    std::vector<std::vector<unsigned char>> blocks;
    for (const UniValue& i : range["block_indexes"].getValues()) blocks.push_back(raw[i.get_int()]);
    message.clear();
    SerializeIndexRangeMessage(ctx, header, blocks, message);
    BOOST_CHECK_EQUAL(HexStr(message), range["hex"].get_str());
}

BOOST_AUTO_TEST_CASE(decoder_rejects_the_invalid_vectors)
{
    const UniValue v = ReadVectors();
    for (const UniValue& item : v["invalid"].getValues()) {
        const std::vector<unsigned char> bytes = ParseHex(item["bytes"].get_str());
        const std::string expected = item["error"].get_str();
        size_t pos = 0;
        IndexBlock block;
        std::string error;
        const bool ok = DeserializeIndexBlock(bytes, pos, block, error);
        if (expected == "trailing bytes") {
            // The block decodes; whoever reads a whole record or message must
            // reject what is left.
            BOOST_CHECK(ok && pos + 1 == bytes.size());
        } else {
            BOOST_CHECK_MESSAGE(!ok && error == expected, item["description"].get_str() + ": got \"" + error + "\"");
        }
    }
    // Every strict prefix of a valid block is truncated.
    const std::vector<unsigned char> full = ParseHex(v["blocks"][1]["bytes"].get_str());
    for (size_t size = 0; size < full.size(); ++size) {
        const std::vector<unsigned char> prefix(full.begin(), full.begin() + size);
        size_t pos = 0;
        IndexBlock block;
        std::string error;
        BOOST_CHECK(!DeserializeIndexBlock(prefix, pos, block, error));
    }
}

BOOST_AUTO_TEST_CASE(index_entries_find_what_the_wallet_scanner_finds)
{
    for (int round = 0; round < 40; ++round) {
        std::vector<CKey> keys(1 + InsecureRandRange(4));
        for (CKey& key : keys) key.MakeNewKey(true);
        std::vector<CTxOut> spent;
        std::vector<COutPoint> outpoints;
        CMutableTransaction tx = ShapedSpend(keys, spent, outpoints);

        // Two payments to the code, one to another code, change and a P2PKH output.
        CKey otherScan, otherSpend;
        otherScan.MakeNewKey(true);
        otherSpend.MakeNewKey(true);
        const PaymentCode other{LocalNetworkId(), otherScan.GetPubKey(), otherSpend.GetPubKey()};
        std::vector<CTxOut> outputs;
        std::string error;
        BOOST_REQUIRE_MESSAGE(CreateOutputs(context, keys, outpoints, {{code, 5 * COIN}, {other, 2 * COIN}, {code, COIN}}, outputs, error), error);
        CKey change;
        change.MakeNewKey(true);
        tx.vout = outputs;
        tx.vout.emplace_back(3 * COIN, PaymentScript(change.GetPubKey()));
        tx.vout.emplace_back(COIN, GetScriptForDestination(change.GetPubKey().GetID()));
        for (size_t i = tx.vout.size() - 1; i > 0; --i) std::swap(tx.vout[i], tx.vout[InsecureRandRange(i + 1)]);
        const CTransaction ctx(tx);

        IndexEntry entry;
        BOOST_REQUIRE(BuildIndexEntry(context, ctx, spent, entry));
        BOOST_CHECK(entry.txid == ctx.GetHash());
        BOOST_CHECK_EQUAL(entry.outputs.size(), 4U); // every native v3 output, the change included

        std::vector<CPubKey> pubkeys;
        std::vector<COutPoint> eligible;
        BOOST_REQUIRE(GetEligibleInputs(ctx, spent, pubkeys, eligible));
        const std::vector<Match> fromTx = ScanTransaction(context, ctx, pubkeys, eligible, scanKey, spendKey.GetPubKey());
        const std::vector<Match> fromIndex = ScanIndexEntry(context, entry, scanKey, spendKey.GetPubKey());
        BOOST_REQUIRE_EQUAL(fromTx.size(), 2U);
        BOOST_REQUIRE_EQUAL(fromIndex.size(), fromTx.size());
        for (size_t i = 0; i < fromTx.size(); ++i) {
            BOOST_CHECK_EQUAL(fromIndex[i].vout, fromTx[i].vout);
            BOOST_CHECK_EQUAL(fromIndex[i].k, fromTx[i].k);
            BOOST_CHECK(fromIndex[i].key == fromTx[i].key);
            BOOST_CHECK(fromIndex[i].tweak == fromTx[i].tweak);
        }
        BOOST_CHECK_EQUAL(ScanIndexEntry(context, entry, otherScan, otherSpend.GetPubKey()).size(), 1U);
    }
}

BOOST_AUTO_TEST_CASE(non_candidates_have_no_entry)
{
    CKey key, payee;
    key.MakeNewKey(true);
    payee.MakeNewKey(true);
    std::vector<CTxOut> spent;
    std::vector<COutPoint> outpoints;
    const CMutableTransaction base = [&] {
        CMutableTransaction tx = ShapedSpend({key}, spent, outpoints);
        tx.vout.emplace_back(COIN, PaymentScript(payee.GetPubKey()));
        return tx;
    }();
    IndexEntry entry;
    BOOST_CHECK(BuildIndexEntry(context, CTransaction(base), spent, entry));

    CMutableTransaction v1 = base;
    v1.nVersion = 1;
    BOOST_CHECK(!BuildIndexEntry(context, CTransaction(v1), spent, entry));

    CMutableTransaction noV3 = base;
    noV3.vout[0].scriptPubKey = GetScriptForDestination(payee.GetPubKey().GetID());
    BOOST_CHECK(!BuildIndexEntry(context, CTransaction(noV3), spent, entry));

    // Same witness shape spending a generic AuthScript (v1) output.
    std::vector<CTxOut> v1Spent = spent;
    v1Spent[0].scriptPubKey = CScript() << OP_1 << ToByteVector(uint256());
    BOOST_CHECK(!BuildIndexEntry(context, CTransaction(base), v1Spent, entry));

    // A v3 output of another key.
    std::vector<CTxOut> otherKey = spent;
    otherKey[0].scriptPubKey = PaymentScript(payee.GetPubKey());
    BOOST_CHECK(!BuildIndexEntry(context, CTransaction(base), otherKey, entry));
}

BOOST_AUTO_TEST_CASE(connect_block_writes_the_records)
{
    Enable();
    CKey k1, k2;
    k1.MakeNewKey(true);
    k2.MakeNewKey(true);
    const CMutableTransaction fund1 = FundV3(coinbaseTxns[0], k1);
    const CMutableTransaction fund2 = FundV3(coinbaseTxns[1], k2);
    CreateAndProcessBlock({}, CoinbaseScript()); // the second coinbase matures
    const CBlock fundBlock = CreateAndProcessBlock({fund1, fund2}, CoinbaseScript());
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == fundBlock.GetHash());
    const IndexBlock fundRecord = Record(fundBlock.GetHash());
    BOOST_CHECK(fundRecord.entries.empty()); // inputs are P2PK
    BOOST_CHECK(fundRecord.spent.empty());

    // A payment and the spend of that payment in the same block.
    const CMutableTransaction pay = Pay(fund1, k1);
    std::vector<CPubKey> pubkeys{k1.GetPubKey()};
    std::vector<COutPoint> outpoints{COutPoint(fund1.GetHash(), 0)};
    const std::vector<Match> found = ScanTransaction(context, CTransaction(pay), pubkeys, outpoints, scanKey, spendKey.GetPubKey());
    BOOST_REQUIRE_EQUAL(found.size(), 1U);
    CKey dk;
    BOOST_REQUIRE(PaymentPrivateKey(spendKey, found[0].tweak, dk));
    CMutableTransaction spend;
    spend.nVersion = 2;
    spend.vin.push_back(CTxIn(COutPoint(pay.GetHash(), 0)));
    spend.vout.push_back(CTxOut(pay.vout[0].nValue - COIN, GetScriptForDestination(k2.GetPubKey().GetID())));
    {
        CBasicKeyStore keystore;
        AddStrictKey(keystore, dk);
        BOOST_REQUIRE(SignSignature(keystore, pay.vout[0].scriptPubKey, spend, 0, pay.vout[0].nValue, SIGHASH_ALL));
    }

    // A v3 output spent together with a P2PK coinbase: not eligible, but the
    // v3 spend is listed.
    CMutableTransaction mixed;
    mixed.nVersion = 2;
    mixed.vin.push_back(CTxIn(COutPoint(fund2.GetHash(), 0)));
    mixed.vin.push_back(CTxIn(COutPoint(coinbaseTxns[2].GetHash(), 0)));
    mixed.vout.push_back(CTxOut(fund2.vout[0].nValue, PaymentScript(k1.GetPubKey())));
    {
        CBasicKeyStore strict, legacy;
        AddStrictKey(strict, k2);
        legacy.AddKey(coinbaseKey);
        BOOST_REQUIRE(SignSignature(strict, fund2.vout[0].scriptPubKey, mixed, 0, fund2.vout[0].nValue, SIGHASH_ALL));
        BOOST_REQUIRE(SignSignature(legacy, coinbaseTxns[2].vout[0].scriptPubKey, mixed, 1, coinbaseTxns[2].vout[0].nValue, SIGHASH_ALL));
    }
    const CBlock block = CreateAndProcessBlock({pay, spend, mixed}, CoinbaseScript());
    BOOST_REQUIRE(At(chainActive.Height())->GetBlockHash() == block.GetHash());

    const IndexBlock record = Record(block.GetHash());
    BOOST_CHECK_EQUAL(record.height, (uint32_t)chainActive.Height());
    BOOST_CHECK(record.prev == block.hashPrevBlock);
    BOOST_REQUIRE_EQUAL(record.entries.size(), 1U); // spend pays P2PKH, mixed is not eligible
    const IndexEntry& entry = record.entries[0];
    BOOST_CHECK(entry.txid == pay.GetHash());
    BOOST_REQUIRE_EQUAL(entry.outputs.size(), 1U);
    BOOST_CHECK_EQUAL(entry.outputs[0].value, pay.vout[0].nValue);
    const std::vector<Match> fromIndex = ScanIndexEntry(context, entry, scanKey, spendKey.GetPubKey());
    BOOST_REQUIRE_EQUAL(fromIndex.size(), 1U);
    BOOST_CHECK(fromIndex[0].key == found[0].key && fromIndex[0].tweak == found[0].tweak);

    // Spent: fund1 (by pay), pay (by spend, same block) and fund2 (by mixed);
    // never the P2PK coinbase.
    const std::vector<COutPoint> expected{COutPoint(fund1.GetHash(), 0), COutPoint(pay.GetHash(), 0), COutPoint(fund2.GetHash(), 0)};
    BOOST_CHECK(record.spent == expected);

    // Durability: the records wait for the next flush, which empties the list.
    BOOST_CHECK(PendingIndexRecords() >= 2U);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(PendingIndexRecords(), 0U);

    const IndexStatus status = GetIndexStatus();
    BOOST_CHECK(status.complete);
    BOOST_CHECK_EQUAL(status.syncedHeight, chainActive.Height());
}

BOOST_AUTO_TEST_CASE(startup_fill_equals_connect_block)
{
    Enable(); // fills the 100 blocks of the fixture from block and undo data
    MakeIndexedBlocks();
    const std::vector<std::vector<unsigned char>> connected = AllValues();
    BOOST_REQUIRE_EQUAL(connected.size(), (size_t)chainActive.Height());

    BOOST_REQUIRE(pblocktree->EraseSilentPaymentRecords());
    BOOST_REQUIRE(pblocktree->EraseSilentPaymentMeta());
    std::vector<unsigned char> value;
    BOOST_CHECK(!pblocktree->ReadSilentPaymentRecord(chainActive.Tip()->GetBlockHash(), value));
    Init(0);
    BOOST_CHECK(AllValues() == connected);
    BOOST_CHECK(GetIndexStatus().complete);
}

BOOST_AUTO_TEST_CASE(records_in_memory_are_bounded_by_bytes)
{
    Enable();
    // Every record is over the limit: each one is written synchronously at once.
    nIndexBatchBytes = 1;
    MakeIndexedBlocks();
    BOOST_CHECK_EQUAL(PendingIndexRecords(), 0U);
    BOOST_CHECK_EQUAL(PendingIndexBytes(), 0U);

    // A limit of a few records: they accumulate, and never past the limit.
    nIndexBatchBytes = 300;
    size_t most = 0;
    for (int i = 0; i < 10; ++i) {
        CreateAndProcessBlock({}, CoinbaseScript());
        BOOST_CHECK(PendingIndexBytes() <= nIndexBatchBytes);
        most = std::max(most, PendingIndexBytes());
    }
    BOOST_CHECK(most > 0);

    // The startup fill in batches of a few records writes the same records.
    const std::vector<std::vector<unsigned char>> connected = AllValues();
    BOOST_REQUIRE(pblocktree->EraseSilentPaymentRecords());
    BOOST_REQUIRE(pblocktree->EraseSilentPaymentMeta());
    nIndexBatchBytes = 200;
    Init(0);
    BOOST_CHECK(AllValues() == connected);
    BOOST_CHECK(GetIndexStatus().complete);
}

BOOST_AUTO_TEST_CASE(startup_repairs_absent_and_corrupt_records)
{
    Enable();
    const CMutableTransaction pay = MakeIndexedBlocks();
    const std::vector<std::vector<unsigned char>> good = AllValues();
    const int start = IndexStartHeight(GetParams().GetConsensus());

    // An old block (outside any recent window) and the block with the payment.
    for (int height : {5, chainActive.Height()}) {
        const CBlockIndex* pindex = At(height);
        const uint256 hash = pindex->GetBlockHash();
        const std::vector<unsigned char> original = Value(hash);
        IndexBlock block = Record(hash);

        std::vector<std::vector<unsigned char>> variants;
        variants.emplace_back(original.begin(), original.end() - 1);              // truncated
        variants.push_back(original);
        variants.back()[0] = INDEX_SCHEMA + 1;                                    // another schema
        variants.push_back(original);
        variants.back().push_back(0);                                             // trailing byte
        {
            std::vector<unsigned char> v(original.begin(), original.begin() + 1 + 68);
            v.push_back(0xfd);                                                    // non-minimal count
            v.push_back(original[1 + 68]);
            v.push_back(0);
            v.insert(v.end(), original.begin() + 1 + 69, original.end());
            variants.push_back(v);
        }
        for (int field = 0; field < 3; ++field) {
            IndexBlock wrong = block;
            if (field == 0) wrong.hash = At(height - 1)->GetBlockHash();          // another hash
            if (field == 1) wrong.height += 1;                                    // another height
            if (field == 2) wrong.prev = uint256S("01");                          // another parent
            std::vector<unsigned char> v{INDEX_SCHEMA};
            SerializeIndexBlock(wrong, v);
            variants.push_back(v);
        }
        variants.emplace_back(); // empty value

        for (const std::vector<unsigned char>& variant : variants) {
            Put(hash, variant);
            Init(0);
            BOOST_CHECK(Value(hash) == original);
            BOOST_CHECK(GetIndexStatus().complete);
        }
        // Deleted.
        BOOST_REQUIRE(pblocktree->Erase(std::make_pair('S', hash), true));
        Init(0);
        BOOST_CHECK(Value(hash) == original);
    }
    BOOST_CHECK(AllValues() == good);
    BOOST_CHECK_EQUAL(start, 1);

    // A well formed record with wrong content: only the deep check sees it.
    const uint256 tip = chainActive.Tip()->GetBlockHash();
    IndexBlock altered = Record(tip);
    BOOST_REQUIRE_EQUAL(altered.entries.size(), 1U);
    BOOST_REQUIRE(altered.entries[0].txid == pay.GetHash());
    const std::vector<unsigned char> g = ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    altered.entries[0].tweak.Set(g.begin(), g.end());
    std::vector<unsigned char> alteredValue{INDEX_SCHEMA};
    SerializeIndexBlock(altered, alteredValue);
    Put(tip, alteredValue);
    Init(0);
    BOOST_CHECK(Value(tip) == alteredValue);
    Init(1);
    BOOST_CHECK(Value(tip) == good.back());
}

BOOST_AUTO_TEST_CASE(missing_data_makes_the_index_incomplete)
{
    Enable();
    const int height = 10;
    const CBlockIndex* pindex = At(height);
    const uint256 hash = pindex->GetBlockHash();
    const std::vector<unsigned char> original = Value(hash);
    BOOST_REQUIRE(pblocktree->Erase(std::make_pair('S', hash), true));
    {
        LOCK(cs_main);
        const_cast<CBlockIndex*>(pindex)->nStatus &= ~BLOCK_HAVE_DATA; // as if pruned
    }
    Init(0);
    IndexStatus status = GetIndexStatus();
    BOOST_CHECK(!status.complete);
    BOOST_REQUIRE_EQUAL(status.missing.size(), 1U);
    BOOST_CHECK(status.missing[0] == std::make_pair(height, height));
    BOOST_CHECK_EQUAL(status.syncedHeight, height - 1);

    // Ranges stop before the gap and say why; beyond it they fail.
    RangeRequest request;
    request.startHeight = 5;
    request.count = 100;
    RangeResult result;
    std::string error;
    BOOST_REQUIRE(QueryRange(request, result, error) == RangeError::NONE);
    BOOST_CHECK_EQUAL(result.blocks.size(), 5U);
    BOOST_CHECK_EQUAL(result.header.nextHeight, (uint32_t)height);
    BOOST_CHECK_EQUAL(result.header.status, INDEX_RANGE_INCOMPLETE);
    request.startHeight = height;
    BOOST_CHECK(QueryRange(request, result, error) == RangeError::INCOMPLETE);

    {
        LOCK(cs_main);
        const_cast<CBlockIndex*>(pindex)->nStatus |= BLOCK_HAVE_DATA;
    }
    Init(0);
    BOOST_CHECK(GetIndexStatus().complete);
    BOOST_CHECK(Value(hash) == original);
}

BOOST_AUTO_TEST_CASE(disabling_erases_and_pruned_nodes_refuse_to_enable)
{
    Enable();
    const uint256 hash = At(50)->GetBlockHash();
    std::vector<unsigned char> value, meta;
    BOOST_CHECK(pblocktree->ReadSilentPaymentRecord(hash, value));

    fSilentPaymentIndex = false;
    Init();
    BOOST_CHECK(!pblocktree->ReadSilentPaymentRecord(hash, value));
    BOOST_CHECK(!pblocktree->ReadSilentPaymentMeta(meta));
    BOOST_CHECK(!GetIndexStatus().enabled);

    // A node that has deleted block files cannot build the history.
    fHavePruned = true;
    fSilentPaymentIndex = true;
    std::string error;
    BOOST_CHECK(!InitIndex(GetParams(), DEFAULT_CHECKSILENTPAYMENTINDEX, error));
    BOOST_CHECK(error.find("-reindex") != std::string::npos);
    BOOST_CHECK(!pblocktree->ReadSilentPaymentMeta(meta));

    fHavePruned = false;
    Init();
    BOOST_CHECK(pblocktree->ReadSilentPaymentRecord(hash, value));
    BOOST_CHECK(GetIndexStatus().complete);
}

BOOST_AUTO_TEST_CASE(range_queries_follow_the_contract)
{
    Enable();
    const int tip = chainActive.Height();
    RangeResult result;
    std::string error;
    auto query = [&](int start, int64_t count, const uint256* anchor = nullptr, size_t maxBytes = INDEX_RANGE_MAX_BYTES,
                     unsigned int maxBlocks = INDEX_RANGE_MAX_BLOCKS) {
        RangeRequest request;
        request.startHeight = start;
        request.count = count;
        request.maxBytes = maxBytes;
        request.maxBlocks = maxBlocks;
        if (anchor) {
            request.hasAnchor = true;
            request.anchor = *anchor;
        }
        return QueryRange(request, result, error);
    };

    BOOST_CHECK(query(0, 1) == RangeError::INVALID_PARAMETER);
    BOOST_CHECK(query(tip + 2, 1) == RangeError::INVALID_PARAMETER);
    BOOST_CHECK(query(1, 0) == RangeError::INVALID_PARAMETER);

    BOOST_REQUIRE(query(tip + 1, 10) == RangeError::NONE);
    BOOST_CHECK(result.blocks.empty());
    BOOST_CHECK_EQUAL(result.header.status, INDEX_RANGE_TIP);
    BOOST_CHECK_EQUAL(result.header.nextHeight, (uint32_t)tip + 1);

    BOOST_REQUIRE(query(1, 10) == RangeError::NONE);
    BOOST_CHECK_EQUAL(result.blocks.size(), 10U);
    BOOST_CHECK_EQUAL(result.header.nextHeight, 11U);
    BOOST_CHECK_EQUAL(result.header.status, INDEX_RANGE_MORE);
    BOOST_CHECK_EQUAL(result.header.snapshotHeight, (uint32_t)tip);
    BOOST_CHECK(result.header.snapshotHash == chainActive.Tip()->GetBlockHash());
    for (size_t i = 0; i < result.blocks.size(); ++i) {
        BOOST_CHECK_EQUAL(result.blocks[i].height, 1 + i);
        BOOST_CHECK(result.blocks[i].hash == At(1 + i)->GetBlockHash());
    }

    BOOST_REQUIRE(query(tip - 2, 10) == RangeError::NONE);
    BOOST_CHECK_EQUAL(result.blocks.size(), 3U);
    BOOST_CHECK_EQUAL(result.header.status, INDEX_RANGE_TIP);

    BOOST_REQUIRE(query(1, 5000, nullptr, INDEX_RANGE_MAX_BYTES, 20) == RangeError::NONE);
    BOOST_CHECK_EQUAL(result.blocks.size(), 20U);
    BOOST_CHECK_EQUAL(result.header.status, INDEX_RANGE_MORE);

    // Never a truncated block: one block even if it alone is over the limit.
    BOOST_REQUIRE(query(1, 10, nullptr, 1) == RangeError::NONE);
    BOOST_CHECK_EQUAL(result.blocks.size(), 1U);
    BOOST_CHECK_EQUAL(result.header.status, INDEX_RANGE_MORE);
    const size_t one = result.bytes[0].size();
    BOOST_REQUIRE(query(1, 10, nullptr, 2 * one) == RangeError::NONE);
    BOOST_CHECK_EQUAL(result.blocks.size(), 2U);

    // Anchors.
    uint256 anchor = At(9)->GetBlockHash();
    BOOST_CHECK(query(10, 5, &anchor) == RangeError::NONE && !result.reorg && result.blocks.size() == 5);
    BOOST_CHECK(query(11, 5, &anchor) == RangeError::INVALID_PARAMETER);
    uint256 unknown = uint256S("1234");
    BOOST_CHECK(query(10, 5, &unknown) == RangeError::ANCHOR_NOT_FOUND);

    // The anchor leaves the active chain.
    const uint256 oldTip = chainActive.Tip()->GetBlockHash();
    {
        CValidationState state;
        LOCK(cs_main);
        BOOST_REQUIRE(InvalidateBlock(state, GetParams(), chainActive.Tip()));
        BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
    }
    CreateAndProcessBlock({}, CScript() << OP_TRUE);
    CreateAndProcessBlock({}, CScript() << OP_TRUE);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), tip + 1);
    BOOST_REQUIRE(query(tip + 1, 5, &oldTip) == RangeError::NONE);
    BOOST_CHECK(result.reorg);
    BOOST_CHECK_EQUAL(result.forkHeight, tip - 1);

    // The records of the abandoned block remain and stay correct for its hash.
    IndexBlock stale;
    std::vector<unsigned char> bytes;
    BOOST_CHECK(ReadIndexRecord(oldTip, stale, bytes) && stale.height == (uint32_t)tip);
    BOOST_CHECK(GetIndexStatus().complete);
}

BOOST_AUTO_TEST_CASE(disabled_index_writes_nothing)
{
    BOOST_REQUIRE(!fSilentPaymentIndex);
    Init();
    CreateAndProcessBlock({}, CoinbaseScript());
    std::vector<unsigned char> value;
    BOOST_CHECK(!pblocktree->ReadSilentPaymentRecord(chainActive.Tip()->GetBlockHash(), value));
    RangeRequest request;
    request.startHeight = 1;
    request.count = 1;
    RangeResult result;
    std::string error;
    BOOST_CHECK(QueryRange(request, result, error) == RangeError::DISABLED);
}

BOOST_AUTO_TEST_SUITE_END()
