// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047 wallet scanner over real blocks and undo data: pruned history,
// cursor behaviour and reorganisations.

#include "silentpayments.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "keystore.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/bip39.h"
#include "wallet/db.h"
#include "wallet/walletdb.h"
#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

namespace {

struct SilentPaymentsWalletSetup : public TestChain100Setup {
    CKey scanKey, spendKey;
    silentpayments::PaymentCode code;

    SilentPaymentsWalletSetup()
    {
        bitdb.MakeMock();
        scanKey.MakeNewKey(true);
        spendKey.MakeNewKey(true);
        code = silentpayments::PaymentCode{silentpayments::LocalNetworkId(), scanKey.GetPubKey(), spendKey.GetPubKey()};
    }

    ~SilentPaymentsWalletSetup()
    {
        bitdb.Flush(true);
        bitdb.Reset();
    }

    std::unique_ptr<CWallet> ViewWallet(const std::string& name)
    {
        std::unique_ptr<CWallet> wallet(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, name))));
        bool firstRun;
        wallet->LoadWallet(firstRun);
        LOCK2(cs_main, wallet->cs_wallet);
        std::string error;
        BOOST_REQUIRE_MESSAGE(wallet->ImportSilentPaymentViewKey(scanKey, spendKey.GetPubKey(), error), error);
        return wallet;
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
        tx.vout.push_back(CTxOut(coinbase.vout[0].nValue - COIN, silentpayments::PaymentScript(key.GetPubKey())));
        CBasicKeyStore keystore;
        keystore.AddKey(coinbaseKey);
        BOOST_REQUIRE(SignSignature(keystore, coinbase.vout[0].scriptPubKey, tx, 0, coinbase.vout[0].nValue, SIGHASH_ALL));
        return tx;
    }

    /** Strict v3 output -> silent payment to `to` (default: `code`), signed SIGHASH_ALL. */
    CMutableTransaction Pay(const CMutableTransaction& funding, const CKey& key, const silentpayments::PaymentCode* to = nullptr,
                            CAmount fee = COIN)
    {
        const COutPoint outpoint(funding.GetHash(), 0);
        std::vector<CTxOut> outputs;
        std::string error;
        const std::vector<silentpayments::Recipient> recipients{{to ? *to : code, funding.vout[0].nValue - fee}};
        BOOST_REQUIRE_MESSAGE(silentpayments::CreateOutputs(silentpayments::LocalContext(), {key}, {outpoint}, recipients, outputs, error), error);
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

    /** Strict ECDSA BIP44 wallet with a fixed test seed (the same on every
     *  load of `name`); `own` gets the keys of its silent payment identity. */
    std::unique_ptr<CWallet> SeedWallet(const std::string& name, silentpayments::AccountKeys& own)
    {
        SecureVector seed;
        CMnemonic::ToSeed(SecureString("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
                          SecureString("SP-LAB-R disposable"), seed);
        BOOST_REQUIRE(silentpayments::DeriveAccountKeys(seed, silentpayments::LocalNetworkId(), own));
        std::unique_ptr<CWallet> wallet(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, name))));
        bool firstRun;
        wallet->LoadWallet(firstRun);
        LOCK(wallet->cs_wallet);
        CHDChain chain(wallet.get());
        chain.seed_id = CKeyID(uint160(std::vector<unsigned char>(20, 0x42)));
        chain.bUse_bip44 = true;
        wallet->SetHDChain(chain, true);
        wallet->LoadAddressType(static_cast<uint8_t>(WalletAddressType::ECDSA));
        wallet->LoadVchSeed(std::vector<unsigned char>(seed.begin(), seed.end()));
        return wallet;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(silentpayments_wallet_tests, SilentPaymentsWalletSetup)

BOOST_AUTO_TEST_CASE(scan_stops_at_pruned_blocks_and_follows_reorgs)
{
    CKey k1, k2;
    k1.MakeNewKey(true);
    k2.MakeNewKey(true);

    // Payment 1 in the first block file.
    const CMutableTransaction fund1 = FundV3(coinbaseTxns[0], k1);
    CreateAndProcessBlock({fund1}, CoinbaseScript());
    const CMutableTransaction pay1 = Pay(fund1, k1);
    CreateAndProcessBlock({pay1}, CoinbaseScript());
    const int height1 = chainActive.Height();

    // Payment 2 in a new block file, parent and child in the same block (its
    // prevout only exists in that block's undo data).
    {
        LOCK(cs_main);
        GetBlockFileInfo(chainActive.Tip()->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    }
    const CMutableTransaction fund2 = FundV3(coinbaseTxns[1], k2);
    const CMutableTransaction pay2 = Pay(fund2, k2);
    CreateAndProcessBlock({fund2, pay2}, CoinbaseScript());
    const CBlockIndex* block2 = chainActive.Tip();
    BOOST_REQUIRE(block2->GetBlockPos().nFile != chainActive[height1]->GetBlockPos().nFile);

    const COutPoint out1(pay1.GetHash(), 0), out2(pay2.GetHash(), 0);

    // A view wallet finds both payments from blocks and undo data.
    std::unique_ptr<CWallet> full = ViewWallet("sp_full.dat");
    {
        LOCK2(cs_main, full->cs_wallet);
        int found = 0;
        std::string error;
        BOOST_REQUIRE_MESSAGE(full->RescanSilentPayments(0, found, error), error);
        BOOST_CHECK_EQUAL(found, 2);
        BOOST_CHECK_EQUAL(full->GetSilentPaymentCursor(), chainActive.Height());
        BOOST_REQUIRE(full->mapSilentPayments.count(out1) && full->mapSilentPayments.count(out2));
        BOOST_CHECK_EQUAL(full->mapSilentPayments[out1].height, height1);
        BOOST_CHECK_EQUAL(full->mapSilentPayments[out2].height, block2->nHeight);
        BOOST_CHECK(full->mapSilentPayments[out1].viewOnly);
        // The transactions reach the wallet as watch-only.
        BOOST_CHECK(full->mapWallet.count(pay1.GetHash()) && full->mapWallet.count(pay2.GetHash()));
        BOOST_CHECK(full->IsMine(CTransaction(pay2).vout[0]) == ISMINE_WATCH_UNSOLVABLE ||
                    full->IsMine(CTransaction(pay2).vout[0]) == ISMINE_WATCH_SOLVABLE);
        // Scanning again neither duplicates nor counts again.
        BOOST_REQUIRE(full->RescanSilentPayments(0, found = 0, error));
        BOOST_CHECK_EQUAL(found, 0);
        BOOST_CHECK_EQUAL(full->mapSilentPayments.size(), 2U);
    }

    // Reorganisation: block2 is replaced by two blocks holding the same
    // transactions; the cursor leaves the stale branch and the payment is
    // confirmed again in its new block, once.
    {
        CValidationState state;
        LOCK(cs_main);
        BOOST_REQUIRE(InvalidateBlock(state, GetParams(), const_cast<CBlockIndex*>(block2)));
        BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
    }
    CreateAndProcessBlock({fund2}, CoinbaseScript());
    CreateAndProcessBlock({pay2}, CoinbaseScript());
    {
        LOCK2(cs_main, full->cs_wallet);
        BOOST_REQUIRE(full->SyncSilentPayments(chainActive.Tip()));
        BOOST_CHECK_EQUAL(full->GetSilentPaymentCursor(), chainActive.Height());
        BOOST_CHECK_EQUAL(full->mapSilentPayments.size(), 2U);
        BOOST_CHECK_EQUAL(full->mapSilentPayments[out2].height, chainActive.Height());
        BOOST_CHECK(full->mapSilentPayments[out2].blockHash == chainActive.Tip()->GetBlockHash());
        BOOST_CHECK_EQUAL(full->mapSilentPayments[out1].height, height1);
    }

    // Disconnect notification: the cursor steps back and the payment of the
    // disconnected block becomes unconfirmed until it is connected again.
    {
        LOCK2(cs_main, full->cs_wallet);
        const CBlockIndex* tip = chainActive.Tip();
        std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
        BOOST_REQUIRE(ReadBlockFromDisk(*block, tip, GetParams().GetConsensus()));
        full->BlockDisconnected(block);
        BOOST_CHECK_EQUAL(full->GetSilentPaymentCursor(), tip->nHeight - 1);
        BOOST_CHECK_EQUAL(full->mapSilentPayments[out2].height, -1);
        BOOST_REQUIRE(full->SyncSilentPayments(tip, block.get()));
        BOOST_CHECK_EQUAL(full->mapSilentPayments[out2].height, tip->nHeight);
    }

    // Pruned history: the scan stops at the first missing block, does not
    // advance the cursor past it and says which block is missing.
    const int firstFile = chainActive[height1]->GetBlockPos().nFile;
    {
        LOCK(cs_main);
        PruneOneBlockFile(firstFile);
        UnlinkPrunedFiles({firstFile});
    }
    std::unique_ptr<CWallet> pruned = ViewWallet("sp_pruned.dat");
    {
        LOCK2(cs_main, pruned->cs_wallet);
        int found = 0;
        std::string error;
        BOOST_CHECK(!pruned->RescanSilentPayments(0, found, error));
        BOOST_CHECK_MESSAGE(error.find("is not available") != std::string::npos, error);
        BOOST_CHECK_EQUAL(pruned->GetSilentPaymentCursor(), -1);
        BOOST_CHECK(!pruned->GetSilentPaymentError().empty());
        BOOST_CHECK(pruned->mapSilentPayments.empty());
        // A sync triggered by a new tip does not jump the gap either.
        BOOST_CHECK(!pruned->SyncSilentPayments(chainActive.Tip()));
        BOOST_CHECK_EQUAL(pruned->GetSilentPaymentCursor(), -1);
        // Starting after the pruned range finds the payment that remains.
        found = 0;
        BOOST_REQUIRE_MESSAGE(pruned->RescanSilentPayments(chainActive.Height() - 1, found, error), error);
        BOOST_CHECK_EQUAL(found, 1);
        BOOST_CHECK(pruned->mapSilentPayments.count(out2) && !pruned->mapSilentPayments.count(out1));
        BOOST_CHECK(pruned->GetSilentPaymentError().empty());
    }
}

BOOST_AUTO_TEST_CASE(view_key_rules)
{
    std::unique_ptr<CWallet> wallet = ViewWallet("sp_view.dat");
    LOCK2(cs_main, wallet->cs_wallet);
    std::string error;
    // One identity per wallet, and a watch wallet stays unencrypted.
    BOOST_CHECK(!wallet->ImportSilentPaymentViewKey(scanKey, spendKey.GetPubKey(), error));
    BOOST_CHECK(!wallet->EncryptWallet(SecureString("passphrase")));
    BOOST_CHECK(!wallet->IsCrypted());
    silentpayments::PaymentCode shown;
    BOOST_REQUIRE(wallet->GetSilentPaymentCode(shown, error));
    BOOST_CHECK(shown.scanKey == code.scanKey && shown.spendKey == code.spendKey);
    BOOST_CHECK(!wallet->SilentPaymentsPaused());

    // A view wallet cannot send.
    CWalletTx wtx;
    CReserveKey reservekey(wallet.get());
    CAmount fee;
    std::vector<unsigned int> positions;
    CCoinControl coinControl;
    BOOST_CHECK(!wallet->CreateSilentPaymentTransaction({{code, COIN}}, wtx, reservekey, fee, positions, error, coinControl));

    // Scan key equal to +-spend key is refused.
    std::unique_ptr<CWallet> other(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "sp_bad.dat"))));
    bool firstRun;
    other->LoadWallet(firstRun);
    LOCK(other->cs_wallet);
    BOOST_CHECK(!other->ImportSilentPaymentViewKey(scanKey, scanKey.GetPubKey(), error));
}

BOOST_AUTO_TEST_CASE(rescan_rebuilds_known_payments_and_chunks_agree)
{
    // AUD-02: the specific rescan restores a wallet transaction that was
    // removed while its silent payment record stayed.
    CKey k1;
    k1.MakeNewKey(true);
    const CMutableTransaction fund = FundV3(coinbaseTxns[0], k1);
    CreateAndProcessBlock({fund}, CoinbaseScript());
    const CMutableTransaction pay = Pay(fund, k1);
    CreateAndProcessBlock({pay}, CoinbaseScript());
    const COutPoint out(pay.GetHash(), 0);

    std::unique_ptr<CWallet> wallet = ViewWallet("sp_rebuild.dat");
    int found = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(wallet->RescanSilentPayments(0, found, error), error);
    BOOST_CHECK_EQUAL(found, 1);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_REQUIRE(wallet->mapWallet.count(pay.GetHash()));
        std::vector<uint256> zapIn{pay.GetHash()}, zapOut;
        BOOST_REQUIRE(wallet->ZapSelectTx(zapIn, zapOut) == DB_LOAD_OK);
        BOOST_CHECK(!wallet->mapWallet.count(pay.GetHash()));
        BOOST_CHECK(wallet->mapSilentPayments.count(out));
        int depth;
        BOOST_CHECK_EQUAL(wallet->GetSilentPaymentStatus(out, wallet->mapSilentPayments[out], depth), "unknown");
    }
    found = 0;
    BOOST_REQUIRE_MESSAGE(wallet->RescanSilentPayments(0, found, error), error);
    BOOST_CHECK_EQUAL(found, 0); // known record, not a new payment
    {
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK(wallet->mapWallet.count(pay.GetHash()));
        int depth;
        BOOST_CHECK_EQUAL(wallet->GetSilentPaymentStatus(out, wallet->mapSilentPayments[out], depth), "confirmed");
    }

    // B1: scanning in chunks of one block gives the same records.
    std::unique_ptr<CWallet> chunked = ViewWallet("sp_chunked.dat");
    found = 0;
    BOOST_REQUIRE_MESSAGE(chunked->RescanSilentPayments(0, found, error, 1), error);
    BOOST_CHECK_EQUAL(found, 1);
    LOCK2(cs_main, chunked->cs_wallet);
    BOOST_CHECK_EQUAL(chunked->GetSilentPaymentCursor(), chainActive.Height());
    BOOST_CHECK(chunked->mapSilentPayments.count(out) && chunked->mapSilentPayments[out].height == chainActive.Height());
}

BOOST_AUTO_TEST_CASE(write_failures_stop_the_scan)
{
    // K-13: a record that cannot be written stops the scan without moving the
    // cursor past the payment, and the scan resumes once writes work again.
    struct BudgetGuard {
        ~BudgetGuard() { SetSilentPaymentWriteBudgetForTesting(-1); }
    } guard;
    CKey k1;
    k1.MakeNewKey(true);
    const CMutableTransaction fund = FundV3(coinbaseTxns[0], k1);
    CreateAndProcessBlock({fund}, CoinbaseScript());
    const CMutableTransaction pay = Pay(fund, k1);
    CreateAndProcessBlock({pay}, CoinbaseScript());
    const int payHeight = chainActive.Height();

    std::unique_ptr<CWallet> wallet = ViewWallet("sp_writefail.dat");
    for (int budget : {0, 1, 2}) {
        SetSilentPaymentWriteBudgetForTesting(budget);
        int found = 0;
        std::string error;
        BOOST_CHECK(!wallet->RescanSilentPayments(0, found, error));
        BOOST_CHECK_MESSAGE(!error.empty(), "budget " << budget);
        // With two writes allowed (cursor rewind and first block), the payment itself fails.
        if (budget == 2) BOOST_CHECK_MESSAGE(error.find("storing a payment") != std::string::npos, error);
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->mapSilentPayments.empty());
        BOOST_CHECK(wallet->GetSilentPaymentCursor() < payHeight);
    }
    SetSilentPaymentWriteBudgetForTesting(-1);
    int found = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(wallet->RescanSilentPayments(0, found, error), error);
    BOOST_CHECK_EQUAL(found, 1);
}

BOOST_AUTO_TEST_CASE(damaged_identities_fail_closed)
{
    // AUD-07: an invalid stored view key is a visible, damaged identity.
    {
        std::unique_ptr<CWallet> wallet(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "sp_badview.dat"))));
        bool firstRun;
        wallet->LoadWallet(firstRun);
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK(!wallet->LoadSilentPaymentViewKey(std::vector<unsigned char>(32, 0), spendKey.GetPubKey()));
        BOOST_CHECK(wallet->HasSilentPaymentIdentity());
        BOOST_CHECK(!wallet->GetSilentPaymentIdentityError().empty());
        silentpayments::PaymentCode shown;
        std::string error;
        BOOST_CHECK(!wallet->GetSilentPaymentCode(shown, error));
        BOOST_CHECK(!wallet->SyncSilentPayments(chainActive.Tip()));
        // A valid view key replaces the damaged one.
        BOOST_REQUIRE_MESSAGE(wallet->ImportSilentPaymentViewKey(scanKey, spendKey.GetPubKey(), error), error);
        BOOST_CHECK(wallet->GetSilentPaymentIdentityError().empty());
        BOOST_CHECK(wallet->GetSilentPaymentCode(shown, error) && shown.scanKey == scanKey.GetPubKey());
    }

    // AUD-01: a stored code that does not match the seed is never shown
    // again, survives a reload and is only cleared by an explicit repair.
    silentpayments::AccountKeys own;
    auto ownWallet = [&](const std::string& name) { return SeedWallet(name, own); };
    {
        std::unique_ptr<CWallet> wallet = ownWallet("sp_owncode.dat");
        LOCK2(cs_main, wallet->cs_wallet);
        // Public record substituted offline with another identity's keys.
        BOOST_REQUIRE(CWalletDB(wallet->GetDBHandle()).WriteSilentPaymentCode(scanKey.GetPubKey(), spendKey.GetPubKey()));
        wallet->LoadSilentPaymentCode(scanKey.GetPubKey(), spendKey.GetPubKey());
        silentpayments::PaymentCode shown;
        std::string error;
        bool verified = true;
        BOOST_CHECK(!wallet->GetSilentPaymentCode(shown, error, &verified));
        BOOST_CHECK_MESSAGE(error.find("does not match the wallet seed") != std::string::npos, error);
        BOOST_CHECK(!wallet->GetSilentPaymentCode(shown, error));
        BOOST_CHECK(!wallet->SyncSilentPayments(chainActive.Tip()));
    }
    {
        // Reloaded: the failure record keeps the identity closed.
        std::unique_ptr<CWallet> wallet = ownWallet("sp_owncode.dat");
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK(!wallet->GetSilentPaymentIdentityError().empty());
        silentpayments::PaymentCode shown, previous, repaired;
        std::string error;
        BOOST_CHECK(!wallet->GetSilentPaymentCode(shown, error));
        BOOST_REQUIRE_MESSAGE(wallet->RepairSilentPaymentIdentity(previous, repaired, error), error);
        BOOST_CHECK(previous.scanKey == scanKey.GetPubKey());
        BOOST_CHECK(repaired.scanKey == own.scanPub && repaired.spendKey == own.spendPub);
        bool verified = false;
        BOOST_REQUIRE(wallet->GetSilentPaymentCode(shown, error, &verified));
        BOOST_CHECK(verified && shown.scanKey == own.scanPub);
    }
    {
        std::unique_ptr<CWallet> wallet = ownWallet("sp_owncode.dat");
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->GetSilentPaymentIdentityError().empty());
    }
}

BOOST_AUTO_TEST_CASE(records_of_another_chain)
{
    // K-12: a record confirmed in a block unknown here is shown as such.
    std::unique_ptr<CWallet> wallet = ViewWallet("sp_otherchain.dat");
    LOCK2(cs_main, wallet->cs_wallet);
    silentpayments::PaymentRecord record;
    record.key = spendKey.GetPubKey();
    record.blockHash = GetRandHash();
    record.height = 5;
    const COutPoint outpoint(GetRandHash(), 0);
    int depth;
    BOOST_CHECK_EQUAL(wallet->GetSilentPaymentStatus(outpoint, record, depth), "other_chain");
    record.blockHash.SetNull();
    record.height = -1;
    BOOST_CHECK_EQUAL(wallet->GetSilentPaymentStatus(outpoint, record, depth), "unknown");
}

BOOST_AUTO_TEST_CASE(only_own_transactions_are_rebroadcast)
{
    // AUD-05 (047c D1): the rebroadcast only announces transactions that
    // spend this wallet's coins, never a payment it merely received.
    CKey k1;
    k1.MakeNewKey(true);
    const CMutableTransaction received = FundV3(coinbaseTxns[0], k1); // spends a coin of another wallet
    const CMutableTransaction sent = Pay(received, k1);               // spends the received coin
    std::unique_ptr<CWallet> wallet(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "sp_resend.dat"))));
    bool firstRun;
    wallet->LoadWallet(firstRun);
    wallet->SetBroadcastTransactions(true);
    LOCK2(cs_main, wallet->cs_wallet);
    AddStrictKey(*wallet, k1);
    for (const CMutableTransaction& tx : {received, sent}) {
        BOOST_REQUIRE(wallet->AddToWallet(CWalletTx(wallet.get(), MakeTransactionRef(tx))));
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(wallet->mapWallet.at(tx.GetHash()).AcceptToMemoryPool(maxTxFee, state), state.GetRejectReason());
    }
    BOOST_CHECK(!wallet->mapWallet.at(received.GetHash()).IsFromMe(ISMINE_ALL));
    const std::vector<uint256> relayed = wallet->ResendWalletTransactionsBefore(GetTime() + 60, connman);
    BOOST_CHECK(relayed == std::vector<uint256>{sent.GetHash()});
}

BOOST_AUTO_TEST_CASE(received_payment_keys_and_coins_stay_apart)
{
    // A seed wallet holding an ordinary strict v3 coin and two silent
    // payments of different amounts to its own code.
    silentpayments::AccountKeys own;
    std::unique_ptr<CWallet> wallet = SeedWallet("sp_apart.dat", own);
    const silentpayments::PaymentCode ownCode{silentpayments::LocalNetworkId(), own.scanPub, own.spendPub};
    CKey ordinaryKey, payerKey;
    ordinaryKey.MakeNewKey(true);
    payerKey.MakeNewKey(true);
    const CMutableTransaction ordinary = FundV3(coinbaseTxns[0], ordinaryKey);
    const CMutableTransaction fund = FundV3(coinbaseTxns[1], payerKey);
    const CMutableTransaction fund2 = FundV3(coinbaseTxns[2], payerKey);
    CreateAndProcessBlock({}, CoinbaseScript()); // the second coinbase matures
    CreateAndProcessBlock({ordinary, fund}, CoinbaseScript());
    const CMutableTransaction pay = Pay(fund, payerKey, &ownCode);
    CreateAndProcessBlock({pay, fund2}, CoinbaseScript());
    const CMutableTransaction pay2 = Pay(fund2, payerKey, &ownCode, 2 * COIN); // smaller than pay
    CreateAndProcessBlock({pay2}, CoinbaseScript());
    BOOST_REQUIRE_EQUAL(chainActive.Height(), COINBASE_MATURITY + 4); // no block was rejected
    const COutPoint ordinaryOut(ordinary.GetHash(), 0), received(pay.GetHash(), 0), received2(pay2.GetHash(), 0);
    {
        LOCK(wallet->cs_wallet);
        AddStrictKey(*wallet, ordinaryKey);
    }
    int found = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(wallet->RescanSilentPayments(0, found, error), error);
    BOOST_CHECK_EQUAL(found, 2);
    wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

    // AUD-04 (047c D3): d_k is stored in its own record, never as an
    // ordinary "key", so a client without NIP-047 does not load it.
    CPubKey paymentKey;
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->mapSilentPayments.count(received));
        paymentKey = wallet->mapSilentPayments.at(received).key;
        BOOST_CHECK(wallet->IsSilentPaymentKey(paymentKey.GetID()));
        BOOST_CHECK(!wallet->IsSilentPaymentKey(ordinaryKey.GetPubKey().GetID()));
    }
    {
        CDB batch(wallet->GetDBHandle(), "r");
        BOOST_CHECK(batch.Exists(std::make_pair(std::string("spkey"), paymentKey)));
        BOOST_CHECK(!batch.Exists(std::make_pair(std::string("key"), paymentKey)));
        BOOST_CHECK(!batch.Exists(std::make_pair(std::string("keymeta"), paymentKey)));
        BOOST_CHECK(batch.Exists(std::make_pair(std::string("key"), ordinaryKey.GetPubKey())));
    }
    wallet.reset();
    wallet = SeedWallet("sp_apart.dat", own);
    LOCK2(cs_main, wallet->cs_wallet);
    CKey loaded;
    BOOST_CHECK(wallet->IsSilentPaymentKey(paymentKey.GetID()));
    BOOST_CHECK(wallet->GetKey(paymentKey.GetID(), loaded) && loaded.GetPubKey() == paymentKey);
    BOOST_CHECK(wallet->mapWallet.count(pay.GetHash()) && wallet->mapWallet.count(ordinary.GetHash()));

    // AUD-06 (047c D2): automatic selection never combines a received
    // payment with another payment or with other coins.
    using Groups = std::vector<std::vector<size_t>>;
    std::vector<COutput> available;
    wallet->AvailableCoins(available);
    std::set<COutPoint> spendable;
    for (const COutput& out : available) spendable.emplace(out.tx->GetHash(), out.i);
    BOOST_CHECK(spendable.count(ordinaryOut) && spendable.count(received) && spendable.count(received2));
    const std::vector<COutPoint> coins{ordinaryOut, received, received2};
    // Other coins together, then each payment on its own, smallest first.
    BOOST_CHECK(wallet->SilentPaymentSelectionGroups(coins, {}) == (Groups{{0}, {2}, {1}}));
    // A chosen payment is not completed with anything; chosen ordinary coins
    // only with ordinary ones.
    BOOST_CHECK(wallet->SilentPaymentSelectionGroups({ordinaryOut, received2}, {received}) == (Groups{{}}));
    BOOST_CHECK(wallet->SilentPaymentSelectionGroups({received, received2}, {ordinaryOut}) == (Groups{{}}));
    // No payment involved, or a single one: nothing to keep apart.
    BOOST_CHECK(wallet->SilentPaymentSelectionGroups({ordinaryOut}, {}) == (Groups{{0}}));
    BOOST_CHECK(wallet->SilentPaymentSelectionGroups({received}, {}) == (Groups{{0}}));
    // -mixsilentpayments adds everything together, as a last resort.
    gArgs.ForceSetArg("-mixsilentpayments", "1");
    BOOST_CHECK(wallet->SilentPaymentSelectionGroups(coins, {}) == (Groups{{0}, {2}, {1}, {0, 1, 2}}));
    gArgs.ForceSetArg("-mixsilentpayments", "0");
}

BOOST_AUTO_TEST_SUITE_END()
