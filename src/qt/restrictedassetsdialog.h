// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_RESTRICTEDASSETSDIALOG_H
#define NEURAI_QT_RESTRICTEDASSETSDIALOG_H

#include "walletmodel.h"

#include <QMessageBox>
#include <QString>
#include <QWidget>

class ClientModel;
class PlatformStyle;
class SendAssetsEntry;
class SendCoinsRecipient;
class AssetFilterProxy;
class AssignQualifier;
class MyRestrictedAssetsTableModel;
class MyRestrictedAssetsFilterProxy;
class QSortFilterProxyModel;
class QWidget;
class QComboBox;
class QLabel;
class QCheckBox;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QValidatedLineEdit;


namespace Ui {
    class RestrictedAssetsDialog;
}

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending neurais */
class RestrictedAssetsDialog : public QWidget
{
    Q_OBJECT

public:
    enum class PageMode {
        RestrictedOnly,
        DepinOnly
    };

    explicit RestrictedAssetsDialog(const PlatformStyle *platformStyle, QWidget *parent = 0, PageMode mode = PageMode::RestrictedOnly);
    ~RestrictedAssetsDialog();

    void setClientModel(ClientModel *clientModel);
    void setModel(WalletModel *model);
    void setupStyling(const PlatformStyle *platformStyle);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);
public Q_SLOTS:
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                    const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);


private:
    Ui::RestrictedAssetsDialog *ui;
    ClientModel *clientModel;
    WalletModel *model;
    const PlatformStyle *platformStyle;
    PageMode pageMode;
    AssetFilterProxy *assetFilterProxy;
    AssetFilterProxy *depinAssetFilterProxy;
    QSortFilterProxyModel *myRestrictedAssetsFilterProxy;

    MyRestrictedAssetsTableModel *myRestrictedAssetsModel;
    QWidget *depinTab;
    QComboBox *depinAssetComboBox;
    QLabel *depinAssetLabel;
    QLabel *depinAddressLabel;
    QValidatedLineEdit *depinAddressEdit;
    QCheckBox *depinChangeAddressCheckBox;
    QLineEdit *depinChangeAddressEdit;
    QLabel *depinWarningLabel;
    QPushButton *depinCheckButton;
    QPushButton *depinClearButton;
    QPushButton *depinSubmitButton;
    QRadioButton *depinFreezeAddressRadio;
    QRadioButton *depinUnfreezeAddressRadio;
    QRadioButton *depinSelfRevokeRadio;

    void createDepinTab();
    void setDepinWarning(const QString &message, bool failure = true);
    void clearDepinWarning();
    void enableDepinSubmit(const QString &message);
    bool findDepinHolderAddress(const std::string& assetName, std::string& holderAddress, bool& foundOwnerControlledHolding) const;

private Q_SLOTS:
    void updateDisplayUnit();
    void assignQualifierClicked();
    void freezeAddressClicked();
    void depinClicked();
    void depinCheck();
    void depinDataChanged();
    void depinChangeAddressChanged(int state);
    void depinActionChanged();
    void clearDepinForm();


    Q_SIGNALS:
            // Fired when a message should be reported to the user
            void message(const QString &title, const QString &message, unsigned int style);
};

#endif // NEURAI_QT_RESTRICTEDASSETSSDIALOG_H
