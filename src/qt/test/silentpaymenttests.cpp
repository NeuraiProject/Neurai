// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "silentpaymenttests.h"

#include "qt/callback.h"
#include "qt/coincontroldialog.h"
#include "qt/guiutil.h"
#include "qt/neuraiunits.h"
#include "qt/overviewpage.h"
#include "qt/neuraiamountfield.h"
#include "qt/optionsmodel.h"
#include "qt/platformstyle.h"
#include "qt/qvalidatedlineedit.h"
#include "qt/receivecoinsdialog.h"
#include "qt/receiverequestdialog.h"
#include "qt/sendcoinsdialog.h"
#include "qt/sendcoinsentry.h"
#include "qt/walletmodel.h"
#include "test/test_neurai.h"
#include "validation.h"
#include "assets/myassetsdb.h"
#include "wallet/bip39.h"
#include "wallet/silentpayments.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <QAbstractButton>
#include <QApplication>
#include <QFrame>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QVBoxLayout>

#if defined(HAVE_CONFIG_H)
#include "config/neurai-config.h" /* for USE_QRCODE */
#endif

namespace
{
//! Press "Yes" in the modal send confirmation dialog.
void ConfirmSend()
{
    QTimer::singleShot(0, makeCallback([](Callback* callback) {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                SendConfirmationDialog* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                QAbstractButton* button = dialog->button(QMessageBox::Yes);
                button->setEnabled(true);
                button->click();
            }
        }
        delete callback;
    }), SLOT(call()));
}

void FillEntry(SendCoinsDialog& dialog, const QString& to, CAmount amount)
{
    QVBoxLayout* entries = dialog.findChild<QVBoxLayout*>("entries");
    SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(to);
    entry->findChild<NeuraiAmountField*>("payAmount")->setValue(amount);
}

bool Emitted(const QSignalSpy& spy, const QString& text)
{
    for (const QList<QVariant>& args : spy) {
        if (args.value(1).toString().contains(text)) return true;
    }
    return false;
}

void TestSilentPaymentsGUI()
{
    TestChain100Setup test;
    bitdb.MakeMock();
    // WalletModel's restricted-asset table reads this database at construction.
    std::unique_ptr<CMyRestrictedDB> myRestricted(new CMyRestrictedDB(1 << 20, true, true));
    pmyrestricteddb = myRestricted.get();
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    OptionsModel optionsModel;

    CKey scan, spend;
    scan.MakeNewKey(true);
    spend.MakeNewKey(true);
    const silentpayments::PaymentCode recipient{silentpayments::LocalNetworkId(), scan.GetPubKey(), spend.GetPubKey()};
    const QString code = QString::fromStdString(silentpayments::EncodeCode(recipient));
    const QString otherNetwork = QString::fromStdString(silentpayments::EncodeCode(
        silentpayments::PaymentCode{silentpayments::TESTNET, scan.GetPubKey(), spend.GetPubKey()}));

    // Legacy wallet: sending to a code is refused with a clear reason, a code
    // of another network is named as such, and there is no code button.
    CWallet legacy(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "sp_qt_legacy.dat")));
    bool firstRun;
    legacy.LoadWallet(firstRun);
    {
        LOCK(legacy.cs_wallet);
        legacy.AddKeyPubKey(test.coinbaseKey, test.coinbaseKey.GetPubKey());
    }
    legacy.ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
    {
        WalletModel model(platformStyle.get(), &legacy, &optionsModel);
        SendCoinsDialog dialog(platformStyle.get());
        dialog.setModel(&model);
        QSignalSpy modelMessages(&model, SIGNAL(message(QString,QString,unsigned int)));
        FillEntry(dialog, code, COIN);
        QMetaObject::invokeMethod(&dialog, "on_sendButton_clicked");
        QVERIFY(Emitted(modelMessages, "strict ECDSA wallet"));

        QSignalSpy dialogMessages(&dialog, SIGNAL(message(QString,QString,unsigned int)));
        FillEntry(dialog, otherNetwork, COIN);
        QMetaObject::invokeMethod(&dialog, "on_sendButton_clicked");
        QVERIFY(Emitted(dialogMessages, "another network"));

        ReceiveCoinsDialog receive(platformStyle.get());
        receive.setModel(&model);
        QVERIFY(receive.findChild<QPushButton*>("silentCodeButton")->isHidden());
    }

    // Strict ECDSA wallet with v3 coins: the form pays the code and the
    // recipient finds exactly that payment.
    SecureVector seed;
    CMnemonic::ToSeed(SecureString("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
                      SecureString("SP-QT-TEST disposable"), seed);
    silentpayments::AccountKeys own;
    QVERIFY(silentpayments::DeriveAccountKeys(seed, silentpayments::LocalNetworkId(), own));
    CWallet wallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "sp_qt_ecdsa.dat")));
    wallet.LoadWallet(firstRun);
    CPubKey coinbasePub;
    {
        LOCK(wallet.cs_wallet);
        CHDChain chain(&wallet);
        chain.seed_id = CKeyID(uint160(std::vector<unsigned char>(20, 0x5a)));
        chain.bUse_bip44 = true;
        wallet.SetHDChain(chain, true);
        wallet.LoadAddressType(static_cast<uint8_t>(WalletAddressType::ECDSA));
        wallet.LoadVchSeed(std::vector<unsigned char>(seed.begin(), seed.end()));
        CWalletDB walletdb(wallet.GetDBHandle());
        coinbasePub = wallet.GenerateNewStrictEcdsaKey(walletdb, false);
        wallet.TopUpStrictEcdsaKeyPool(5);
    }
    for (int i = 0; i < 2; ++i) {
        test.CreateAndProcessBlock({}, silentpayments::PaymentScript(coinbasePub));
    }
    for (int i = 0; i < COINBASE_MATURITY; ++i) {
        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    }
    wallet.ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
    wallet.SetBroadcastTransactions(true);

    WalletModel model(platformStyle.get(), &wallet, &optionsModel);
    SendCoinsDialog dialog(platformStyle.get());
    dialog.setModel(&model);
    uint256 txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](CWallet*, const uint256& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    FillEntry(dialog, code, 2 * COIN);
    ConfirmSend();
    QMetaObject::invokeMethod(&dialog, "on_sendButton_clicked");
    QVERIFY(!txid.IsNull());
    {
        LOCK2(cs_main, wallet.cs_wallet);
        const CTransaction& tx = *wallet.mapWallet.at(txid).tx;
        QCOMPARE(tx.nVersion, 2);
        std::vector<CTxOut> spent;
        for (const CTxIn& in : tx.vin) spent.push_back(wallet.mapWallet.at(in.prevout.hash).tx->vout[in.prevout.n]);
        for (const CTxOut& out : tx.vout) QVERIFY(silentpayments::IsNativeV3Script(out.scriptPubKey));
        std::vector<CPubKey> pubkeys;
        std::vector<COutPoint> outpoints;
        QVERIFY(silentpayments::GetEligibleInputs(tx, spent, pubkeys, outpoints));
        std::vector<silentpayments::Match> matches =
            silentpayments::ScanTransaction(silentpayments::LocalContext(), tx, pubkeys, outpoints, scan, spend.GetPubKey());
        QCOMPARE(matches.size(), size_t(1));
        QCOMPARE(tx.vout[matches[0].vout].nValue, 2 * COIN);
    }

    // The form also pays this wallet's own code; the payment shows apart
    // from the XNA balance and is tagged in coin control.
    const QString ownCode = QString::fromStdString(silentpayments::EncodeCode(
        silentpayments::PaymentCode{silentpayments::LocalNetworkId(), own.scanPub, own.spendPub}));
    auto mine = [&](const uint256& hash) {
        CMutableTransaction tx;
        {
            LOCK(wallet.cs_wallet);
            tx = CMutableTransaction(*wallet.mapWallet.at(hash).tx);
        }
        test.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        wallet.ScanForWalletTransactions(chainActive.Tip(), nullptr, true);
    };
    mine(txid);
    txid.SetNull();
    FillEntry(dialog, ownCode, 3 * COIN);
    ConfirmSend();
    QMetaObject::invokeMethod(&dialog, "on_sendButton_clicked");
    QVERIFY(!txid.IsNull());
    mine(txid);
    int found = 0;
    std::string error;
    QVERIFY(wallet.RescanSilentPayments(0, found, error));
    QCOMPARE(found, 1);

    OverviewPage overview(platformStyle.get());
    overview.setWalletModel(&model);
    const int unit = optionsModel.getDisplayUnit();
    QFrame* silentCard = overview.findChild<QFrame*>("silentPaymentsFrame");
    QVERIFY(silentCard && !silentCard->isHidden());
    QCOMPARE(overview.findChild<QLabel*>("labelSilentAvailable")->text(),
             NeuraiUnits::formatWithUnit(unit, 3 * COIN, false, NeuraiUnits::separatorAlways));
    QCOMPARE(overview.findChild<QLabel*>("labelSilentCount")->text(), QString("1"));
    QCOMPARE(overview.findChild<QLabel*>("labelBalance")->text(),
             NeuraiUnits::formatWithUnit(unit, model.getBalance() - 3 * COIN, false, NeuraiUnits::separatorAlways));

    CoinControlDialog coinControl(platformStyle.get());
    coinControl.setModel(&model);
    int tagged = 0;
    for (QTreeWidgetItemIterator it(coinControl.findChild<QTreeWidget*>("treeWidget")); *it; ++it) {
        for (int column = 0; column < (*it)->columnCount(); ++column) {
            if ((*it)->text(column) == "Silent payment" && (*it)->childCount() == 0) ++tagged;
        }
    }
    QCOMPARE(tagged, 1);

    // The receive page opens and closes a card with this wallet's own code.
    ReceiveCoinsDialog receive(platformStyle.get());
    receive.setModel(&model);
    QPushButton* button = receive.findChild<QPushButton*>("silentCodeButton");
    QFrame* codeCard = receive.findChild<QFrame*>("silentCodeFrame");
    QVERIFY(!button->isHidden() && codeCard && codeCard->isHidden());
    button->click();
    QVERIFY(!codeCard->isHidden());
    QCOMPARE(receive.findChild<QPlainTextEdit*>("silentCodeText")->toPlainText(), ownCode);
    QVERIFY(!receive.findChild<QLabel*>("silentCodeStatus")->text().isEmpty());
#ifdef USE_QRCODE
    QVERIFY(GUIUtil::HasPixmap(receive.findChild<QLabel*>("silentCodeQR")));
#endif
    button->click();
    QVERIFY(codeCard->isHidden());

    bitdb.Flush(true);
    bitdb.Reset();
    pmyrestricteddb = nullptr;
}
} // namespace

void SilentPaymentTests::silentPaymentTests()
{
    TestSilentPaymentsGUI();
}
