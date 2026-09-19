// Standalone GUI review harness. Built as test_main.cpp in an isolated Qt build.
#include "test/test_neurai.h"
#include "wallet/wallet.h"
#include "wallet/coincontrol.h"
#include "assets/myassetsdb.h"
#include "assets/assetdb.h"
#include "validation.h"
#include "qt/walletmodel.h"
#include "qt/optionsmodel.h"
#include "qt/platformstyle.h"
#include "qt/signverifymessagedialog.h"
#include "qt/receiverequestdialog.h"
#include "qt/sendcoinsdialog.h"
#include "qt/sendcoinsentry.h"
#include "qt/neuraiamountfield.h"
#include "qt/coincontroldialog.h"
#include "qt/assetcontroldialog.h"
#include <QApplication>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QTimer>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QAbstractButton>
#include <QDir>
#include <QClipboard>
#include <QComboBox>
#include <QStringListModel>
#include <iostream>

static int checks = 0;
static void Check(bool ok, const std::string& label) {
    std::cout << (ok ? "PASS " : "FAIL ") << label << std::endl;
    if (!ok) throw std::runtime_error(label);
    ++checks;
}
template<typename T> T* Field(QObject& parent, const char* name) {
    T* field = parent.findChild<T*>(name);
    if (!field) throw std::runtime_error(std::string("Missing widget: ") + name);
    return field;
}
int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    app.setApplicationName("Neurai-point6-review");
    QTimer watchdog;
    QObject::connect(&watchdog, &QTimer::timeout, [] { std::cerr << "GUI timeout" << std::endl; std::exit(2); });
    watchdog.start(60000);
    try {
        std::unique_ptr<CMyRestrictedDB> restricted;
        std::unique_ptr<CAssetsDB> assetsDB;
        TestChain100Setup chain;
        restricted.reset(new CMyRestrictedDB(1 << 20, true));
        assetsDB.reset(new CAssetsDB(1 << 20, true));
        pmyrestricteddb = restricted.get();
        passetsdb = assetsDB.get();
        for (int i = 0; i < 10; ++i) chain.CreateAndProcessBlock({}, GetScriptForRawPubKey(chain.coinbaseKey.GetPubKey()));
        bitdb.MakeMock();
        auto db = std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "point6.dat"));
        CWallet wallet(std::move(db));
        bool first;
        wallet.LoadWallet(first);
        wallet.AddKeyPubKey(chain.coinbaseKey, chain.coinbaseKey.GetPubKey());
        wallet.ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
        wallet.SetBroadcastTransactions(true);
        CStrictAuthScriptContext active(true);
        CKey pq, ec;
        pq.MakeNewKeyPQ(); ec.MakeNewKey(true);
        wallet.AddKeyPubKey(pq, pq.GetPubKey());
        wallet.AddKeyPubKey(ec, ec.GetPubKey());
        std::vector<CTxDestination> destinations(4);
        destinations[0] = ec.GetPubKey().GetID();
        Check(wallet.GetDefaultAuthScriptDestination(pq.GetPubKey(), destinations[1]), "register/v1");
        Check(wallet.GetStrictAuthScriptDestination(pq.GetPubKey(), destinations[2]), "register/v2");
        Check(wallet.GetStrictAuthScriptDestination(ec.GetPubKey(), destinations[3]), "register/v3");
        std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
        OptionsModel options;
        WalletModel model(style.get(), &wallet, &options);
        for (size_t v = 0; v < destinations.size(); ++v) {
            const auto label = "v" + std::to_string(v);
            QString address = QString::fromStdString(EncodeDestination(destinations[v]));
            Check(model.validateAddress(address), label + "/validate");
            ReceiveRequestDialog receive;
            receive.setModel(&options);
            receive.setInfo(SendCoinsRecipient(address, "review", COIN, "point6"));
            receive.show(); app.processEvents();
            QMetaObject::invokeMethod(&receive, "on_btnCopyAddress_clicked");
            Check(QApplication::clipboard()->text() == address, label + "/receive-address");
            // Rendering also exercises layout and address presentation.
            Check(receive.grab().save(QString::fromStdString(label + "-receive.png")), label + "/receive-render");
            receive.hide();
            SignVerifyMessageDialog sign(style.get(), nullptr);
            sign.setModel(&model);
            Field<QLineEdit>(sign, "addressIn_SM")->setText(address);
            Field<QPlainTextEdit>(sign, "messageIn_SM")->setPlainText("point6 mensaje");
            QMetaObject::invokeMethod(&sign, "on_signMessageButton_SM_clicked");
            QString signature = Field<QLineEdit>(sign, "signatureOut_SM")->text();
            Check(!signature.isEmpty(), label + "/sign");
            Field<QLineEdit>(sign, "addressIn_VM")->setText(address);
            Field<QPlainTextEdit>(sign, "messageIn_VM")->setPlainText("point6 mensaje");
            Field<QLineEdit>(sign, "signatureIn_VM")->setText(signature);
            QMetaObject::invokeMethod(&sign, "on_verifyMessageButton_VM_clicked");
            Check(Field<QLabel>(sign, "statusLabel_VM")->text().contains("verified"), label + "/verify");
            Field<QPlainTextEdit>(sign, "messageIn_VM")->setPlainText("otro mensaje");
            QMetaObject::invokeMethod(&sign, "on_verifyMessageButton_VM_clicked");
            Check(Field<QLabel>(sign, "statusLabel_VM")->text().contains("did not match"), label + "/wrong-message");
            SendCoinsDialog send(style.get()); send.setModel(&model);
            auto entries = Field<QVBoxLayout>(send, "entries");
            auto entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
            Check(entry != nullptr, label + "/send-entry");
            Field<QLineEdit>(*entry, "payTo")->setText(address);
            Field<NeuraiAmountField>(*entry, "payAmount")->setValue(COIN);
            uint256 txid;
            boost::signals2::scoped_connection connection(wallet.NotifyTransactionChanged.connect(
                [&txid](CWallet*, const uint256& hash, ChangeType status) { if (status == CT_NEW) txid = hash; }));
            QString unexpected;
            QTimer confirm;
            QObject::connect(&confirm, &QTimer::timeout, [&] {
                for (auto widget : QApplication::topLevelWidgets()) {
                    if (auto box = qobject_cast<QMessageBox*>(widget)) {
                        if (widget->inherits("SendConfirmationDialog")) {
                            box->button(QMessageBox::Yes)->setEnabled(true);
                            box->button(QMessageBox::Yes)->click();
                        } else { unexpected = box->text(); box->accept(); }
                    }
                }
            });
            confirm.start(100);
            QMetaObject::invokeMethod(&send, "on_sendButton_clicked");
            confirm.stop();
            Check(!txid.IsNull(), label + "/send " + unexpected.toStdString());
            auto wtx = wallet.GetWalletTx(txid);
            Check(wtx && std::any_of(wtx->tx->vout.begin(), wtx->tx->vout.end(), [&](const CTxOut& out) {
                return out.nValue == COIN && out.scriptPubKey == GetScriptForDestination(destinations[v]);
            }), label + "/actual-output");
            connection.disconnect(); // Coinbase notifications must not replace the payment txid.
            chain.CreateAndProcessBlock({CMutableTransaction(*wtx->tx)}, GetScriptForRawPubKey(chain.coinbaseKey.GetPubKey()));
            wallet.ScanForWalletTransactions(chainActive.Tip(), nullptr, true);
            Check(wallet.GetWalletTx(txid)->GetDepthInMainChain() == 1, label + "/send-mined");
            unsigned int index = 0;
            while (wtx->tx->vout[index].scriptPubKey != GetScriptForDestination(destinations[v])) ++index;
            CoinControlDialog control(style.get()); control.setModel(&model);
            CoinControlDialog::coinControl->UnSelectAll();
            CoinControlDialog::coinControl->Select(COutPoint(txid, index));
            CoinControlDialog::payAmounts = {COIN / 2};
            CoinControlDialog::updateLabels(&model, &control);
            const int expected = v == 0 ? 226 : v == 3 ? 148 : 1056;
            auto text = Field<QLabel>(control, "labelCoinControlBytes")->text();
            Check(text.contains(QString::number(expected)), label + "/coin-control-bytes " + text.toStdString());
            CoinControlDialog::coinControl->UnSelectAll();
            CoinControlDialog::payAmounts.clear();
        }
        CoinControlDialog coins(style.get()); coins.setModel(&model);
        AssetControlDialog assets(style.get()); assets.setModel(&model);
        coins.show(); assets.show(); app.processEvents();
        Check(coins.grab().save("coin-control.png"), "coin-control/render");
        Check(assets.grab().save("asset-control.png"), "asset-control/render");
        auto combo = Field<QComboBox>(assets, "assetList");
        auto choices = new QStringListModel({"REVIEW_A", "REVIEW_B"}, combo);
        combo->setModel(choices);
        combo->setCurrentIndex(0);
        QMetaObject::invokeMethod(&assets, "onAssetSelected", Q_ARG(QString, "REVIEW_A"));
        AssetControlDialog::assetControl->SelectAsset(COutPoint(uint256S("01"), 0));
        QMetaObject::invokeMethod(&assets, "onAssetSelected", Q_ARG(QString, "REVIEW_A"));
        Check(!AssetControlDialog::assetControl->HasAssetSelected(), "asset-selector/direct-slot-clears-selection");
        AssetControlDialog::assetControl->SelectAsset(COutPoint(uint256S("01"), 0));
        combo->setCurrentIndex(1);
        app.processEvents();
        Check(!AssetControlDialog::assetControl->HasAssetSelected(), "asset-selector/changing-asset-clears-selection");
        std::cout << "RESULT " << checks << " passed" << std::endl;
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << std::endl;
        return 1;
    }
    return 0;
}
