// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_OVERVIEWPAGE_H
#define NEURAI_QT_OVERVIEWPAGE_H

#include "amount.h"

#include <QSortFilterProxyModel>
#include <QWidget>
#include <QMenu>
#include <memory>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;
class AssetFilterProxy;

class AssetViewDelegate;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QFrame;
class QLabel;
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void showOutOfSyncWarning(bool fShow);
    void showAssets();

    bool eventFilter(QObject *object, QEvent *event);
    void openIPFSForAsset(const QModelIndex &index);

public Q_SLOTS:
            void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                            const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);

    Q_SIGNALS:
            void transactionClicked(const QModelIndex &index);
    void assetSendClicked(const QModelIndex &index);
    void assetIssueSubClicked(const QModelIndex &index);
    void assetIssueUniqueClicked(const QModelIndex &index);
    void assetReissueClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();
    void sendCoinsClicked();
    void receiveCoinsClicked();
    void createAssetClicked();

private:
    Ui::OverviewPage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;

    //! NIP-047: received silent payments, in their own card under the XNA
    //! balance and only while the wallet has any.
    QFrame *silentFrame;
    QLabel *silentTitle;
    QLabel *silentAvailable;
    QLabel *silentPending;
    QLabel *silentCount;
    QLabel *silentTotal;
    void setupSilentPaymentsCard();

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;
    std::unique_ptr<AssetFilterProxy> assetFilter;

    AssetViewDelegate *assetdelegate;
    QMenu *contextMenu;
    QAction *sendAction;
    QAction *issueSub;
    QAction *issueUnique;
    QAction *reissue;
    QAction *openURL;
    QAction *copyHashAction;


private Q_SLOTS:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void handleAssetRightClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void handleOutOfSyncWarningClicks();
    void assetSearchChanged();
};

#endif // NEURAI_QT_OVERVIEWPAGE_H
