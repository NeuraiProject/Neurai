// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletview.h"

#include "addressbookpage.h"
#include "askpassphrasedialog.h"
#include "neuraigui.h"
#include "clientmodel.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "overviewpage.h"
#include "platformstyle.h"
#include "privacypage.h"
#include "receivecoinsdialog.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "transactiontablemodel.h"
#include "assettablemodel.h"
#include "transactionview.h"
#include "walletmodel.h"
#include "assetsdialog.h"
#include "createassetdialog.h"
#include "reissueassetdialog.h"
#include "restrictedassetsdialog.h"
#include <validation.h>

#include "ui_interface.h"

#include <algorithm>

#include <QAction>
#include <QActionGroup>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QScrollBar>
#include <QScreen>
#include <QProgressDialog>
#include <QPushButton>
#include <QVBoxLayout>


WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(0),
    walletModel(0),
    platformStyle(_platformStyle)
{
    // Create tabs
    overviewPage = new OverviewPage(platformStyle);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);
    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    sendCoinsPage = new SendCoinsDialog(platformStyle);

    assetsPage = new AssetsDialog(platformStyle);
    createAssetsPage = new CreateAssetDialog(platformStyle);
    manageAssetsPage = new ReissueAssetDialog(platformStyle);
    restrictedAssetsPage = new RestrictedAssetsDialog(platformStyle, this, RestrictedAssetsDialog::PageMode::RestrictedOnly);
    depinAssetsPage = new RestrictedAssetsDialog(platformStyle, this, RestrictedAssetsDialog::PageMode::DepinOnly);
    privacyPage = new PrivacyPage(platformStyle, this);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);

    addPage(overviewPage);
    addPage(transactionsPage);
    addPage(receiveCoinsPage);
    addPage(sendCoinsPage);

    /** XNA START */
    addPage(assetsPage);
    addPage(createAssetsPage);
    addPage(manageAssetsPage);
    addPage(restrictedAssetsPage);
    addPage(depinAssetsPage);
    addPage(privacyPage);
    /** XNA END */

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));
    connect(overviewPage, SIGNAL(outOfSyncWarningClicked()), this, SLOT(requestedSyncWarningInfo()));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, SIGNAL(clicked()), transactionView, SLOT(exportClicked()));

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    // Pass through messages from transactionView
    connect(transactionView, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));

    /** XNA START */
    connect(assetsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    connect(createAssetsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    connect(manageAssetsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    connect(restrictedAssetsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    connect(depinAssetsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    connect(privacyPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    connect(overviewPage, SIGNAL(assetSendClicked(QModelIndex)), assetsPage, SLOT(focusAsset(QModelIndex)));
    connect(overviewPage, SIGNAL(assetIssueSubClicked(QModelIndex)), createAssetsPage, SLOT(focusSubAsset(QModelIndex)));
    connect(overviewPage, SIGNAL(assetIssueUniqueClicked(QModelIndex)), createAssetsPage, SLOT(focusUniqueAsset(QModelIndex)));
    connect(overviewPage, SIGNAL(assetReissueClicked(QModelIndex)), manageAssetsPage, SLOT(focusReissueAsset(QModelIndex)));
    /** RNV END */
}

WalletView::~WalletView()
{
}

namespace {
/** Scroll area for a wallet page. Its minimum width is the page's, so the window
 *  cannot get narrower than the forms; only on screens too small for that does
 *  the page scroll horizontally. Vertically it scrolls whenever needed. */
class PageScrollArea : public QScrollArea
{
public:
    using QScrollArea::QScrollArea;

    QSize minimumSizeHint() const override
    {
        QSize hint = QScrollArea::minimumSizeHint();
        if (const QWidget *page = widget()) {
            int width = std::max(page->minimumWidth(), page->minimumSizeHint().width()) + verticalScrollBar()->sizeHint().width();
            if (screen())
                width = std::min(width, screen()->availableGeometry().width() - 80);
            hint.setWidth(width);
        }
        return hint;
    }
};
} // namespace

void WalletView::addPage(QWidget *page)
{
    // Fixed minimum heights from the forms can be below what their contents need
    // (larger fonts, display scaling); let the layouts decide so nothing is squeezed.
    QList<QWidget*> containers = page->findChildren<QWidget*>();
    containers.prepend(page);
    for (QWidget *container : containers) {
        if (container->layout() && container->minimumHeight() > 0)
            container->setMinimumHeight(0);
    }

    QScrollArea *scroll = new PageScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setObjectName("walletPageScroll");
    scroll->setStyleSheet("QScrollArea#walletPageScroll { background: transparent; border: none; }");
    scroll->viewport()->setAutoFillBackground(false);
    scroll->setWidget(page);
    addWidget(scroll);
}

void WalletView::showPage(QWidget *page)
{
    // The page lives in the viewport of its scroll area
    for (QWidget *w = page; w; w = w->parentWidget()) {
        if (w->parentWidget() == this) {
            setCurrentWidget(w);
            return;
        }
    }
}

void WalletView::setNeuraiGUI(NeuraiGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), gui, SLOT(gotoHistoryPage()));

        // Clicking on a asset menu item Send
        connect(overviewPage, SIGNAL(assetSendClicked(QModelIndex)), gui, SLOT(gotoAssetsPage()));

        // Clicking on a asset menu item Issue Sub
        connect(overviewPage, SIGNAL(assetIssueSubClicked(QModelIndex)), gui, SLOT(gotoCreateAssetsPage()));

        // Clicking on a asset menu item Issue Unique
        connect(overviewPage, SIGNAL(assetIssueUniqueClicked(QModelIndex)), gui, SLOT(gotoCreateAssetsPage()));

        // Clicking on a asset menu item Reissue
        connect(overviewPage, SIGNAL(assetReissueClicked(QModelIndex)), gui, SLOT(gotoManageAssetsPage()));

        // Quick actions of the overview page
        connect(overviewPage, SIGNAL(sendCoinsClicked()), gui, SLOT(gotoSendCoinsPage()));
        connect(overviewPage, SIGNAL(receiveCoinsClicked()), gui, SLOT(gotoReceiveCoinsPage()));
        connect(overviewPage, SIGNAL(createAssetClicked()), gui, SLOT(gotoCreateAssetsPage()));

        // Receive and report messages
        connect(this, SIGNAL(message(QString,QString,unsigned int)), gui, SLOT(message(QString,QString,unsigned int)));

        // Pass through encryption status changed signals
        connect(this, SIGNAL(encryptionStatusChanged(int)), gui, SLOT(setEncryptionStatus(int)));

        // Pass through transaction notifications
        connect(this, SIGNAL(incomingTransaction(QString,int,CAmount,QString,QString,QString,QString)), gui, SLOT(incomingTransaction(QString,int,CAmount,QString,QString,QString,QString)));

        // Connect HD enabled state signal 
        connect(this, SIGNAL(hdEnabledStatusChanged(int)), gui, SLOT(setHDStatus(int)));

        // Pass through checkAssets calls to the GUI
        connect(this, SIGNAL(checkAssets()), gui, SLOT(checkAssets()));
    }
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
    assetsPage->setClientModel(_clientModel);
    createAssetsPage->setClientModel(_clientModel);
    manageAssetsPage->setClientModel(_clientModel);
    restrictedAssetsPage->setClientModel(_clientModel);
    depinAssetsPage->setClientModel(_clientModel);
    privacyPage->setClientModel(_clientModel);
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    // Put transaction list in tabs
    transactionView->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    sendCoinsPage->setModel(_walletModel);
    usedReceivingAddressesPage->setModel(_walletModel ? _walletModel->getAddressTableModel() : nullptr);
    usedSendingAddressesPage->setModel(_walletModel ? _walletModel->getAddressTableModel() : nullptr);

    /** XNA START */
    assetsPage->setModel(_walletModel);
    createAssetsPage->setModel(_walletModel);
    manageAssetsPage->setModel(_walletModel);
    restrictedAssetsPage->setModel(_walletModel);
    depinAssetsPage->setModel(_walletModel);
    privacyPage->setWalletModel(_walletModel);

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));

        // Handle changes in encryption status
        connect(_walletModel, SIGNAL(encryptionStatusChanged(int)), this, SIGNAL(encryptionStatusChanged(int)));
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged(_walletModel->hd44Enabled() ? NeuraiGUI::HD44_ENABLED : _walletModel->hdEnabled() ? NeuraiGUI::HD_ENABLED : NeuraiGUI::HD_DISABLED);

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(processNewTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(_walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));

        // Show progress dialog
        connect(_walletModel, SIGNAL(showProgress(QString,int)), this, SLOT(showProgress(QString,int)));
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int end)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->inInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    /** XNA START */
    // With the addition of asset transactions, there can be multiple transaction that need notifications
    // so we need to loop through all new transaction that were added to the transaction table and display
    // notifications for each individual transaction
    QString assetName = "";
    for (int i = start; i <= end; i++) {
        QString date = ttm->index(i, TransactionTableModel::Date, parent).data().toString();
        qint64 amount = ttm->index(i, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
        QString type = ttm->index(i, TransactionTableModel::Type, parent).data().toString();
        QModelIndex index = ttm->index(i, 0, parent);
        QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
        QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();
        assetName = ttm->data(index, TransactionTableModel::AssetNameRole).toString();

        Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label,
                                   assetName);
    }
    /** XNA END */

    /** Everytime we get an new transaction. We should check to see if assets are enabled or not */
    overviewPage->showAssets();
    transactionView->showAssets();
    Q_EMIT checkAssets();

    assetsPage->processNewTransaction();
    createAssetsPage->updateAssetList();
    manageAssetsPage->updateAssetsList();

}

void WalletView::gotoOverviewPage()
{
    showPage(overviewPage);
    Q_EMIT checkAssets();
}

void WalletView::gotoHistoryPage()
{
    showPage(transactionsPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    showPage(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    showPage(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged(walletModel->getEncryptionStatus());
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->backupWallet(filename)) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}
void WalletView::getMyWords()
{
    // Create the box and set the default text.
    QMessageBox box;
    box.setWindowTitle(tr("Recovery information. (Will close after 5 min)"));
    box.setText(tr("No words available."));
    box.setStandardButtons(QMessageBox::Close);
    box.button(QMessageBox::Close)->animateClick(); // Qt6: msec param removed

    // Check for HD-wallet and set text if not HD-wallet.
    if(!walletModel->hd44Enabled())
        box.setText(tr("This wallet is not a HD wallet, words not supported."));

    // Unlock wallet requested by wallet model
    WalletView::unlockWallet();

    // Make sure wallet is unlocked before trying to fetch the words.
    // When unlocked, set the text to 12words and passphrase.
    if (walletModel->getEncryptionStatus() != WalletModel::Locked)
        box.setText(walletModel->getMyWords());

    // Show the box
    box.exec();
}

void WalletView::usedSendingAddresses()
{
    if(!walletModel)
        return;

    usedSendingAddressesPage->show();
    usedSendingAddressesPage->raise();
    usedSendingAddressesPage->activateWindow();
}

void WalletView::usedReceivingAddresses()
{
    if(!walletModel)
        return;

    usedReceivingAddressesPage->show();
    usedReceivingAddressesPage->raise();
    usedReceivingAddressesPage->activateWindow();
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setCancelButton(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog)
        progressDialog->setValue(nProgress);
}

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}

bool fFirstVisit = true;
/** XNA START */
void WalletView::gotoAssetsPage()
{
    if (fFirstVisit){
        fFirstVisit = false;
        assetsPage->handleFirstSelection();
    }
    showPage(assetsPage);
    assetsPage->focusAssetListBox();
}

void WalletView::gotoCreateAssetsPage()
{
    showPage(createAssetsPage);
}

void WalletView::gotoManageAssetsPage()
{
    showPage(manageAssetsPage);
}

void WalletView::gotoRestrictedAssetsPage()
{
    showPage(restrictedAssetsPage);
}

void WalletView::gotoDepinAssetsPage()
{
    showPage(depinAssetsPage);
}

void WalletView::gotoPrivacyPage()
{
    showPage(privacyPage);
}
/** XNA END */
