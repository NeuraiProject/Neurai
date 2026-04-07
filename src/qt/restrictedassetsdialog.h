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
#include <map>

class ClientModel;
class PlatformStyle;
class SendAssetsEntry;
class SendCoinsRecipient;
class AssetFilterProxy;
class AssignQualifier;
class CNewAsset;
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
class QDoubleSpinBox;
class QButtonGroup;
class QFrame;
class QValueComboBox;
class NeuraiAmountField;
class QPlainTextEdit;
class QStandardItemModel;
class QModelIndex;


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
    QSortFilterProxyModel *depinSummaryFilterProxy;
    QSortFilterProxyModel *depinAddressFilterProxy;

    MyRestrictedAssetsTableModel *myRestrictedAssetsModel;
    QStandardItemModel *depinSummaryModel;
    QStandardItemModel *depinAddressModel;
    QWidget *depinTab;
    QWidget *depinCreateTab;
    QWidget *depinTransferTab;
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
    QComboBox *depinCreateAssetComboBox;
    QLineEdit *depinCreateAddressEdit;
    QDoubleSpinBox *depinCreateQuantitySpinBox;
    QCheckBox *depinCreateReissuableCheckBox;
    QLabel *depinCreateUnitsLabel;
    QCheckBox *depinCreateChangeAddressCheckBox;
    QValidatedLineEdit *depinCreateChangeAddressEdit;
    QLabel *depinCreateWarningLabel;
    QPushButton *depinCreateButton;
    QPushButton *depinCreateClearButton;
    QButtonGroup *depinCreateFeeGroup;
    QRadioButton *depinCreateSmartFeeRadio;
    QRadioButton *depinCreateCustomFeeRadio;
    QComboBox *depinCreateConfTargetSelector;
    QLabel *depinCreateSmartFeeLabel;
    QLabel *depinCreateFeeEstimationLabel;
    QCheckBox *depinCreateMinimumFeeCheckBox;
    NeuraiAmountField *depinCreateCustomFee;
    QComboBox *depinTransferAssetComboBox;
    QCheckBox *depinTransferBatchCheckBox;
    QValidatedLineEdit *depinTransferAddressEdit;
    QPlainTextEdit *depinTransferBatchEdit;
    QLabel *depinTransferBatchHelpLabel;
    QLabel *depinTransferWarningLabel;
    QPushButton *depinTransferButton;
    QPushButton *depinTransferClearButton;

    void createDepinTab();
    void createDepinCreateTab();
    void createDepinTransferTab();
    void setDepinWarning(const QString &message, bool failure = true);
    void clearDepinWarning();
    void enableDepinSubmit(const QString &message);
    bool getDepinAssetMetadata(const std::string& assetName, CNewAsset& assetData) const;
    bool getWalletAssetBalancesByAddress(const std::string& assetName, std::map<std::string, CAmount>* balances) const;
    bool getWalletAssetOutputsAtAddress(const std::string& assetName, const std::string& address, std::vector<COutput>* outputs, CAmount* totalAmount = nullptr) const;
    bool getDepinOwnerControlledOutputs(const std::string& assetName, std::string& ownerAddress, std::vector<COutput>* outputs, CAmount* totalAmount = nullptr) const;
    bool findDepinHolderAddress(const std::string& assetName, std::string& holderAddress, bool& foundOwnerControlledHolding) const;
    bool findDepinOwnerAddress(const std::string& assetName, std::string& ownerAddress) const;
    void updateDepinOverview();
    void updateDepinAddressOverview(const QString& assetName);
    void syncDepinSelection(const QString& assetName);
    void updateDepinCreateAssets();
    void updateDepinCreateSelectedAsset();
    void updateDepinTransferAssets();
    void clearDepinCreateWarning();
    void setDepinCreateWarning(const QString &message, bool failure = true);
    void updateDepinCreateMinFeeLabel();
    bool validateDepinCreateForm(QString *errorMessage = nullptr);
    void updateDepinCreateCoinControlState(CCoinControl& ctrl) const;
    void clearDepinTransferWarning();
    void setDepinTransferWarning(const QString &message, bool failure = true);
    bool validateDepinTransferForm(QString *errorMessage = nullptr);
    QStringList depinTransferRecipients() const;

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
    void depinCreateDataChanged();
    void depinCreateChangeAddressChanged(int state);
    void depinCreateAssetChanged(int index);
    void clearDepinCreateForm();
    void depinCreateClicked();
    void depinCreateFeeFeatureChanged(bool enabled);
    void depinCreateSetMinimumFee();
    void updateDepinCreateFeeSectionControls();
    void updateDepinCreateSmartFeeLabel();
    void depinTransferDataChanged();
    void depinTransferBatchModeChanged(int state);
    void clearDepinTransferForm();
    void depinTransferClicked();
    void depinAssetSummarySelectionChanged(const QModelIndex &current, const QModelIndex &previous);
    void depinAssetSearchChanged(const QString &text);
    void depinAddressSearchChanged(const QString &text);


    Q_SIGNALS:
            // Fired when a message should be reported to the user
            void message(const QString &title, const QString &message, unsigned int style);
};

#endif // NEURAI_QT_RESTRICTEDASSETSSDIALOG_H
