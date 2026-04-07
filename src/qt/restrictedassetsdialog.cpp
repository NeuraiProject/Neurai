// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "restrictedassetsdialog.h"
#include "ui_restrictedassetsdialog.h"

#include "neuraiunits.h"
#include "clientmodel.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"
#include "assettablemodel.h"
#include "assetfilterproxy.h"

#include "base58.h"
#include "chainparams.h"
#include "validation.h" // mempool and minRelayTxFee
#include "ui_interface.h"
#include "txmempool.h"
#include "policy/fees.h"
#include "wallet/fees.h"
#include "guiconstants.h"
#include "restrictedassignqualifier.h"
#include "ui_restrictedassignqualifier.h"
#include "restrictedfreezeaddress.h"
#include "ui_restrictedfreezeaddress.h"
#include "sendcoinsdialog.h"
#include "myrestrictedassettablemodel.h"
#include "qvalidatedlineedit.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGraphicsDropShadowEffect>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QFontMetrics>
#include <QMessageBox>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>
#include <QDebug>
#include <QMessageBox>

#include <policy/policy.h>
#include <core_io.h>
#include <rpc/mining.h>
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>

RestrictedAssetsDialog::RestrictedAssetsDialog(const PlatformStyle *_platformStyle, QWidget *parent, PageMode mode) :
        QDialog(parent),
        ui(new Ui::RestrictedAssetsDialog),
        clientModel(0),
        model(0),
        platformStyle(_platformStyle),
        pageMode(mode),
        assetFilterProxy(0),
        depinAssetFilterProxy(0),
        myRestrictedAssetsFilterProxy(0),
        myRestrictedAssetsModel(0),
        depinTab(0),
        depinAssetComboBox(0),
        depinAssetLabel(0),
        depinAddressLabel(0),
        depinAddressEdit(0),
        depinChangeAddressCheckBox(0),
        depinChangeAddressEdit(0),
        depinWarningLabel(0),
        depinCheckButton(0),
        depinClearButton(0),
        depinSubmitButton(0),
        depinFreezeAddressRadio(0),
        depinUnfreezeAddressRadio(0),
        depinSelfRevokeRadio(0)
{

    ui->setupUi(this);
    setWindowTitle(pageMode == PageMode::DepinOnly ? "DePIN" : "Manage Restricted Assets");
    setupStyling(_platformStyle);
}

void RestrictedAssetsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
}

void RestrictedAssetsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel()) {
        setBalance(_model->getBalance(), _model->getUnconfirmedBalance(), _model->getImmatureBalance(),
                   _model->getWatchBalance(), _model->getWatchUnconfirmedBalance(), _model->getWatchImmatureBalance());
        connect(_model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
                SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
        connect(_model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();


        assetFilterProxy = new AssetFilterProxy(this);
        assetFilterProxy->setSourceModel(_model->getAssetTableModel());
        assetFilterProxy->setDynamicSortFilter(true);
        assetFilterProxy->setAssetNamePrefix("$");
        assetFilterProxy->setSortCaseSensitivity(Qt::CaseInsensitive);
        assetFilterProxy->setFilterCaseSensitivity(Qt::CaseInsensitive);

        depinAssetFilterProxy = new AssetFilterProxy(this);
        depinAssetFilterProxy->setSourceModel(_model->getAssetTableModel());
        depinAssetFilterProxy->setDynamicSortFilter(true);
        depinAssetFilterProxy->setAssetNamePrefix("&");
        depinAssetFilterProxy->setSortCaseSensitivity(Qt::CaseInsensitive);
        depinAssetFilterProxy->setFilterCaseSensitivity(Qt::CaseInsensitive);

        myRestrictedAssetsFilterProxy = new QSortFilterProxyModel(this);
        myRestrictedAssetsFilterProxy->setSourceModel(_model->getMyRestrictedAssetsTableModel());
        myRestrictedAssetsFilterProxy->setDynamicSortFilter(true);
        myRestrictedAssetsFilterProxy->setSortCaseSensitivity(Qt::CaseInsensitive);
        myRestrictedAssetsFilterProxy->setFilterCaseSensitivity(Qt::CaseInsensitive);

        myRestrictedAssetsFilterProxy->setSortRole(Qt::EditRole);

        ui->myAddressList->setModel(myRestrictedAssetsFilterProxy);
        ui->myAddressList->horizontalHeader()->setStretchLastSection(true);
        ui->myAddressList->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        ui->myAddressList->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        ui->myAddressList->setAlternatingRowColors(true);
        ui->myAddressList->setSortingEnabled(true);
        ui->myAddressList->verticalHeader()->hide();

        ui->listAssets->setModel(pageMode == PageMode::DepinOnly ? depinAssetFilterProxy : assetFilterProxy);
        ui->listAssets->horizontalHeader()->setStretchLastSection(true);
        ui->listAssets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        ui->listAssets->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        ui->listAssets->setAlternatingRowColors(true);
        ui->listAssets->verticalHeader()->hide();

        if (pageMode == PageMode::DepinOnly) {
            ui->frameAddressList->hide();
            ui->labelAssetBalance->setText(tr("DEPIN Balances"));
            if (!depinTab) {
                createDepinTab();
            }
        } else {
            AssignQualifier *assignQualifier = new AssignQualifier(platformStyle, this);
            assignQualifier->setWalletModel(_model);
            assignQualifier->setObjectName("tab_assign_qualifier");
            connect(assignQualifier->getUI()->buttonSubmit, SIGNAL(clicked()), this, SLOT(assignQualifierClicked()));
            ui->tabWidget->addTab(assignQualifier, "Assign/Remove Qualifier");

            FreezeAddress *freezeAddress = new FreezeAddress(platformStyle, this);
            freezeAddress->setWalletModel(_model);
            freezeAddress->setObjectName("tab_freeze_address");
            connect(freezeAddress->getUI()->buttonSubmit, SIGNAL(clicked()), this, SLOT(freezeAddressClicked()));
            ui->tabWidget->addTab(freezeAddress, "Restrict Addresses/Global");
        }
    }
}

RestrictedAssetsDialog::~RestrictedAssetsDialog()
{
    QSettings settings;
    delete ui;
}

void RestrictedAssetsDialog::createDepinTab()
{
    depinTab = new QWidget(this);
    depinTab->setObjectName("tab_depin_management");

    QVBoxLayout *mainLayout = new QVBoxLayout(depinTab);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    QFormLayout *formLayout = new QFormLayout();
    formLayout->setHorizontalSpacing(10);
    formLayout->setVerticalSpacing(10);

    depinAssetLabel = new QLabel(tr("DEPIN Asset:"), depinTab);
    depinAssetLabel->setStyleSheet(STRING_LABEL_COLOR);
    depinAssetLabel->setFont(GUIUtil::getTopLabelFont());
    depinAssetComboBox = new QComboBox(depinTab);
    depinAssetComboBox->setModel(depinAssetFilterProxy);
    formLayout->addRow(depinAssetLabel, depinAssetComboBox);

    depinAddressLabel = new QLabel(tr("Address:"), depinTab);
    depinAddressLabel->setStyleSheet(STRING_LABEL_COLOR);
    depinAddressLabel->setFont(GUIUtil::getTopLabelFont());
    depinAddressEdit = new QValidatedLineEdit(depinTab);
    depinAddressEdit->setMaxLength(50);
    formLayout->addRow(depinAddressLabel, depinAddressEdit);

    depinChangeAddressCheckBox = new QCheckBox(tr("Custom Change Address"), depinTab);
    depinChangeAddressCheckBox->setStyleSheet(QString(".QCheckBox{ %1; }").arg(STRING_LABEL_COLOR));
    depinChangeAddressEdit = new QLineEdit(depinTab);
    depinChangeAddressEdit->setEnabled(false);
    depinChangeAddressEdit->setMaxLength(50);
    depinChangeAddressEdit->hide();
    formLayout->addRow(depinChangeAddressCheckBox, depinChangeAddressEdit);

    mainLayout->addLayout(formLayout);

    QLabel *actionLabel = new QLabel(tr("DEPIN Options"), depinTab);
    actionLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(actionLabel);

    QGroupBox *optionsGroup = new QGroupBox(depinTab);
    QVBoxLayout *optionsLayout = new QVBoxLayout(optionsGroup);
    depinFreezeAddressRadio = new QRadioButton(tr("Freeze this address for the selected DEPIN asset"), depinTab);
    depinUnfreezeAddressRadio = new QRadioButton(tr("Unfreeze or restore this address for the selected DEPIN asset"), depinTab);
    depinSelfRevokeRadio = new QRadioButton(tr("Self-revoke the selected DEPIN asset held in this wallet"), depinTab);
    depinFreezeAddressRadio->setChecked(true);
    optionsLayout->addWidget(depinFreezeAddressRadio);
    optionsLayout->addWidget(depinUnfreezeAddressRadio);
    optionsLayout->addWidget(depinSelfRevokeRadio);
    mainLayout->addWidget(optionsGroup);

    depinWarningLabel = new QLabel(depinTab);
    depinWarningLabel->hide();
    mainLayout->addWidget(depinWarningLabel);

    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    depinCheckButton = new QPushButton(tr("Check"), depinTab);
    depinClearButton = new QPushButton(tr("Clear"), depinTab);
    depinSubmitButton = new QPushButton(tr("Submit"), depinTab);
    depinSubmitButton->setDisabled(true);
    buttonsLayout->addWidget(depinCheckButton);
    buttonsLayout->addStretch();
    buttonsLayout->addWidget(depinClearButton);
    buttonsLayout->addWidget(depinSubmitButton);
    mainLayout->addLayout(buttonsLayout);

    connect(depinCheckButton, SIGNAL(clicked()), this, SLOT(depinCheck()));
    connect(depinClearButton, SIGNAL(clicked()), this, SLOT(clearDepinForm()));
    connect(depinSubmitButton, SIGNAL(clicked()), this, SLOT(depinClicked()));
    connect(depinAssetComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(depinDataChanged()));
    connect(depinAddressEdit, SIGNAL(textChanged(QString)), this, SLOT(depinDataChanged()));
    connect(depinChangeAddressEdit, SIGNAL(textChanged(QString)), this, SLOT(depinDataChanged()));
    connect(depinChangeAddressCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinChangeAddressChanged(int)));
    connect(depinChangeAddressCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinDataChanged()));
    connect(depinFreezeAddressRadio, SIGNAL(clicked()), this, SLOT(depinActionChanged()));
    connect(depinUnfreezeAddressRadio, SIGNAL(clicked()), this, SLOT(depinActionChanged()));
    connect(depinSelfRevokeRadio, SIGNAL(clicked()), this, SLOT(depinActionChanged()));

    ui->tabWidget->addTab(depinTab, tr("DEPIN"));
    depinActionChanged();
}

void RestrictedAssetsDialog::setDepinWarning(const QString &message, bool failure)
{
    if (!depinWarningLabel) {
        return;
    }

    depinWarningLabel->setStyleSheet(failure ? STRING_LABEL_COLOR_WARNING : "");
    depinWarningLabel->setText(message);
    depinWarningLabel->show();
}

void RestrictedAssetsDialog::clearDepinWarning()
{
    if (!depinWarningLabel) {
        return;
    }

    depinWarningLabel->clear();
    depinWarningLabel->hide();
}

void RestrictedAssetsDialog::enableDepinSubmit(const QString &message)
{
    setDepinWarning(message, false);
    depinSubmitButton->setEnabled(true);
}

void RestrictedAssetsDialog::clearDepinForm()
{
    if (!depinTab) {
        return;
    }

    depinAddressEdit->clear();
    depinChangeAddressEdit->clear();
    depinAddressEdit->setStyleSheet(STYLE_VALID);
    depinChangeAddressEdit->setStyleSheet(STYLE_VALID);
    depinFreezeAddressRadio->setChecked(true);
    depinChangeAddressCheckBox->setChecked(false);
    depinSubmitButton->setDisabled(true);
    clearDepinWarning();
    depinActionChanged();
}

bool RestrictedAssetsDialog::findDepinHolderAddress(const std::string& assetName, std::string& holderAddress, bool& foundOwnerControlledHolding) const
{
    holderAddress.clear();
    foundOwnerControlledHolding = false;

    if (!model || !model->getWallet()) {
        return false;
    }

    LOCK2(cs_main, model->getWallet()->cs_wallet);

    std::set<CTxDestination> destinations;
    for (const auto& entry : model->getWallet()->mapWallet) {
        const CWalletTx& wtx = entry.second;
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            CTxDestination dest;
            if (ExtractDestination(wtx.tx->vout[i].scriptPubKey, dest)) {
                destinations.insert(dest);
            }
        }
    }

    for (const auto& dest : destinations) {
        std::string address = EncodeDestination(dest);
        if (!AddressHasAssetToken(*passets, assetName, address)) {
            continue;
        }

        if (AddressHasDEPINOwnerToken(*passets, assetName, address)) {
            foundOwnerControlledHolding = true;
            continue;
        }

        holderAddress = address;
        return true;
    }

    return false;
}

void RestrictedAssetsDialog::setupStyling(const PlatformStyle *platformStyle)
{
    /** Update the restrictedassets frame */
    ui->frameAssetBalance->setStyleSheet(QString(".QFrame {background-color: %1; padding-top: 10px; padding-right: 5px; border: none;}").arg(platformStyle->WidgetBackGroundColor().name()));
    ui->frameAddressList->setStyleSheet(QString(".QFrame {background-color: %1; padding-top: 10px; padding-right: 5px; border: none;}").arg(platformStyle->WidgetBackGroundColor().name()));

    ui->tabFrame->setStyleSheet(QString(".QFrame {background-color: %1; padding-top: 10px; padding-right: 5px; border: none;}").arg(platformStyle->WidgetBackGroundColor().name()));

    /** Create the shadow effects on the frames */
    ui->frameAssetBalance->setGraphicsEffect(GUIUtil::getShadowEffect());
    ui->frameAddressList->setGraphicsEffect(GUIUtil::getShadowEffect());
    ui->tabFrame->setGraphicsEffect(GUIUtil::getShadowEffect());

    /** Add label color and font */
    ui->labelAssetBalance->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelAssetBalance->setFont(GUIUtil::getTopLabelFont());

    ui->labelAddressList->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelAddressList->setFont(GUIUtil::getTopLabelFont());
}



QWidget *RestrictedAssetsDialog::setupTabChain(QWidget *prev)
{
//    QWidget::setTabOrder(prev, ui->sendButton);
//    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
//    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return prev;
}

void RestrictedAssetsDialog::depinDataChanged()
{
    if (!depinSubmitButton) {
        return;
    }

    depinSubmitButton->setDisabled(true);
    clearDepinWarning();
    if (depinAddressEdit) {
        depinAddressEdit->setStyleSheet(STYLE_VALID);
    }
    if (depinChangeAddressEdit) {
        depinChangeAddressEdit->setStyleSheet(STYLE_VALID);
    }
}

void RestrictedAssetsDialog::depinChangeAddressChanged(int state)
{
    if (!depinChangeAddressEdit) {
        return;
    }

    bool fChecked = state == Qt::CheckState::Checked;
    depinChangeAddressEdit->setEnabled(fChecked);
    depinChangeAddressEdit->setVisible(fChecked);
    depinDataChanged();
}

void RestrictedAssetsDialog::depinActionChanged()
{
    if (!depinAddressLabel || !depinAddressEdit) {
        return;
    }

    bool fSelfRevoke = depinSelfRevokeRadio && depinSelfRevokeRadio->isChecked();
    depinAddressLabel->setVisible(!fSelfRevoke);
    depinAddressEdit->setVisible(!fSelfRevoke);
    depinAddressEdit->setEnabled(!fSelfRevoke);

    depinDataChanged();
}

void RestrictedAssetsDialog::depinCheck()
{
    if (!model || !passets || !depinAssetComboBox) {
        setDepinWarning(tr("Unable to perform action at this time"));
        return;
    }

    QString assetName = depinAssetComboBox->currentData(AssetTableModel::RoleIndex::AssetNameRole).toString();
    if (assetName.endsWith("!")) {
        assetName.chop(1);
    }
    const bool fAdministrator = depinAssetComboBox->currentData(AssetTableModel::RoleIndex::AdministratorRole).toBool();
    const bool fFreezeAddress = depinFreezeAddressRadio->isChecked();
    const bool fUnfreezeAddress = depinUnfreezeAddressRadio->isChecked();
    const bool fSelfRevoke = depinSelfRevokeRadio->isChecked();
    const QString address = depinAddressEdit->text();
    const QString changeAddress = depinChangeAddressCheckBox->isChecked() ? depinChangeAddressEdit->text() : "";

    bool failed = false;
    if (!IsAssetNameADEPIN(assetName.toStdString())) {
        setDepinWarning(tr("Must have a DEPIN asset selected"));
        return;
    }

    if (depinChangeAddressCheckBox->isChecked() && !changeAddress.isEmpty()) {
        CTxDestination changeDest = DecodeDestination(changeAddress.toStdString());
        if (!IsValidDestination(changeDest)) {
            depinChangeAddressEdit->setStyleSheet(STYLE_INVALID);
            failed = true;
        }
    }

    if (fSelfRevoke) {
        std::string holderAddress;
        bool foundOwnerControlledHolding = false;
        if (!findDepinHolderAddress(assetName.toStdString(), holderAddress, foundOwnerControlledHolding)) {
            if (foundOwnerControlledHolding) {
                setDepinWarning(tr("The address holding the DEPIN owner token cannot self-revoke"));
            } else {
                setDepinWarning(tr("This wallet does not hold the selected DEPIN asset"));
            }
            return;
        }

        if (passets->CheckForDEPINRestriction(assetName.toStdString(), holderAddress, true)) {
            setDepinWarning(tr("This DEPIN asset is already revoked or frozen for the holder address"));
            return;
        }

        if (failed) {
            return;
        }

        enableDepinSubmit(tr("Data has been validated, you can now submit the DEPIN self-revoke transaction"));
        return;
    }

    if (!fAdministrator) {
        setDepinWarning(tr("You need the owner token (&ASSET!) in this wallet to manage address restrictions for this DEPIN asset"));
        return;
    }

    CTxDestination dest = DecodeDestination(address.toStdString());
    if (!IsValidDestination(dest)) {
        depinAddressEdit->setStyleSheet(STYLE_INVALID);
        failed = true;
    }

    if (!failed && AddressHasDEPINOwnerToken(*passets, assetName.toStdString(), address.toStdString())) {
        setDepinWarning(tr("The address holding the DEPIN owner token cannot be frozen or revoked"));
        return;
    }

    if (!failed && depinChangeAddressCheckBox->isChecked() && !changeAddress.isEmpty() && changeAddress == address) {
        depinChangeAddressEdit->setStyleSheet(STYLE_INVALID);
        failed = true;
    }

    if (failed) {
        return;
    }

    const bool fOwnerFrozen = passets->CheckForAddressRestriction(assetName.toStdString(), address.toStdString(), true);
    const bool fSelfRevoked = passets->CheckForDEPINSelfRestriction(assetName.toStdString(), address.toStdString(), true);

    if (fFreezeAddress && fOwnerFrozen) {
        setDepinWarning(tr("Address is already frozen by the DEPIN owner"));
    } else if (fUnfreezeAddress && !fOwnerFrozen && !fSelfRevoked) {
        setDepinWarning(tr("Address is already active"));
    } else {
        enableDepinSubmit(tr("Data has been validated, you can now submit the DEPIN transaction"));
    }
}

void RestrictedAssetsDialog::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                                 const CAmount& watchBalance, const CAmount& watchUnconfirmedBalance, const CAmount& watchImmatureBalance)
{
    Q_UNUSED(unconfirmedBalance);
    Q_UNUSED(immatureBalance);
    Q_UNUSED(watchBalance);
    Q_UNUSED(watchUnconfirmedBalance);
    Q_UNUSED(watchImmatureBalance);

    ui->labelBalance->setFont(GUIUtil::getSubLabelFont());
    ui->label->setFont(GUIUtil::getSubLabelFont());

    if(model && model->getOptionsModel())
    {
        ui->labelBalance->setText(NeuraiUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
    }
}

void RestrictedAssetsDialog::updateDisplayUnit()
{
    setBalance(model->getBalance(), 0, 0, 0, 0, 0);
}

void RestrictedAssetsDialog::freezeAddressClicked()
{
    // Check wallet unlock status
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    // Get the widget belonging to the freeze address tab
    FreezeAddress* widget = ui->tabWidget->findChild<FreezeAddress *>("tab_freeze_address");

    std::string asset_name = widget->getUI()->assetComboBox->currentData(AssetTableModel::RoleIndex::AssetNameRole).toString().toStdString();
    std::string address = widget->getUI()->lineEditAddress->text().toStdString();
    std::string change_address = widget->getUI()->checkBoxChangeAddress->isChecked() ? widget->getUI()->lineEditChangeAddress->text().toStdString(): "";
    std::string decodedAssetData = DecodeAssetData(widget->getUI()->lineEditAssetData->text().toStdString());

    // Get the single address options
    bool fFreezeAddress = widget->getUI()->radioButtonFreezeAddress->isChecked();
    bool fUnfreezeAddress = widget->getUI()->radioButtonUnfreezeAddress->isChecked();

    // Get the global options
    bool fFreezeGlobal = widget->getUI()->radioButtonGlobalFreeze->isChecked();
    bool fUnfreezeGlobal = widget->getUI()->radioButtonGlobalUnfreeze->isChecked();

    // Create parameters for transaction construction
    CReserveKey reservekey(model->getWallet());
    CWalletTx transaction;
    CAmount nRequiredFee;
    CCoinControl ctrl;

    // If the optional change address wasn't given create a new change address for this wallet
    if (change_address == "") {
        CTxDestination change_dest;
        std::string strFailReason;
        if (!model->getWallet()->CreateNewChangeAddress(reservekey, change_dest, strFailReason)) {
            QMessageBox changeAddressBox;
            changeAddressBox.setText(tr("Failed to create a change address"));
            changeAddressBox.exec();
            return;
        }

        change_address = EncodeDestination(change_dest);
    }

    ctrl.destChange = DecodeDestination(change_address);

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    // Create the pointers which is passed to the CreateTransferAssetTransaction function
    std::vector< std::pair<CNullAssetTxData, std::string> > vecFreezeAddressTxData;
    std::vector<CNullAssetTxData> vecFreezeGlobalTxData;

    // We have to send the owner token for the asset in order to perform a restriction
    std::string asset_owner_token = RestrictedNameToOwnerName(asset_name);

    vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_owner_token, 1 * COIN, decodedAssetData), change_address));

    int flag = -1;
    if (fFreezeAddress || fUnfreezeAddress) {
        flag = fFreezeAddress ? 1 : 0;
        vecFreezeAddressTxData.push_back(std::make_pair(CNullAssetTxData(asset_name, flag), address));
    } else if (fFreezeGlobal || fUnfreezeGlobal) {
        flag = fFreezeGlobal ? 1 : 0;
        vecFreezeGlobalTxData.push_back(CNullAssetTxData(asset_name, flag));
    }

    if (flag == -1) {
        QMessageBox failMsgBox;
        failMsgBox.setText(tr("Failed to generate the correct transaction. Please try again"));
        failMsgBox.exec();
        return;
    }

    if (IsInitialBlockDownload()) {
        GUIUtil::SyncWarningMessage syncWarning(this);
        bool sendTransaction = syncWarning.showTransactionSyncWarningMessage();
        if (!sendTransaction)
            return;
    }

    // Create the Transaction
    if (!CreateTransferAssetTransaction(model->getWallet(), ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee, &vecFreezeAddressTxData, &vecFreezeGlobalTxData)) {
        QMessageBox createTransactionBox;
        createTransactionBox.setText(QString::fromStdString(error.second));
        createTransactionBox.exec();
        return;
    }

    QString freezingAddress = tr("Freezing all trading of the restricted asset <b>%1</b> from address <b>%2</b><br>").arg(QString::fromStdString(asset_name), QString::fromStdString(address));
    QString unfreezingAddress = tr("Unfreezing trading of the restricted asset <b>%1</b> from address <b>%2</b><br>").arg(QString::fromStdString(asset_name), QString::fromStdString(address));
    QString freezingGlobal = tr("Freezing all trading of the restricted asset <b>%1</b> from all addresses<br>").arg(QString::fromStdString(asset_name));
    QString unfreezingGlobal = tr("Opening / Unfreezing all trading of the restricted asset <b>%1</b> from all addresses<br>").arg(QString::fromStdString(asset_name));

    QString questionString;
    // Format confirmation message

    if (fFreezeAddress || fUnfreezeAddress) {
        questionString.append(flag ? freezingAddress : unfreezingAddress);
    } else if (fFreezeGlobal || fUnfreezeGlobal) {
        questionString.append(flag ? freezingGlobal : unfreezingGlobal);
    }

    if(nRequiredFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#e82121;'>");
        questionString.append(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), nRequiredFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number((double)GetVirtualTransactionSize(transaction) / 1000) + " kB)");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount =  nRequiredFee;
    QStringList alternativeUnits;
    for (NeuraiUnits::Unit u : NeuraiUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(NeuraiUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
                                  .arg(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
                                  .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    QString addString = tr("Confirm adding restriction");
    QString removingString = tr("Confirm removing resetricton");
    SendConfirmationDialog confirmationDialog(flag ? addString : removingString,
                                              questionString, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(model->getWallet(), transaction, reservekey, error, txid)) {
        QMessageBox sendTransactionBox;
        sendTransactionBox.setText(QString::fromStdString(error.second));
        sendTransactionBox.exec();
    }

    QMessageBox txidMsgBox;
    std::string sentMsg = _("Sent new transaction to the network");
    std::string totalMsg = strprintf("%s: %s",sentMsg, txid);
    txidMsgBox.setText(QString::fromStdString(totalMsg));
    txidMsgBox.exec();

    widget->clear();
}

void RestrictedAssetsDialog::depinClicked()
{
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        return;
    }

    QString qAssetName = depinAssetComboBox->currentData(AssetTableModel::RoleIndex::AssetNameRole).toString();
    if (qAssetName.endsWith("!")) {
        qAssetName.chop(1);
    }
    const std::string asset_name = qAssetName.toStdString();
    const bool fFreezeAddress = depinFreezeAddressRadio->isChecked();
    const bool fUnfreezeAddress = depinUnfreezeAddressRadio->isChecked();
    const bool fSelfRevoke = depinSelfRevokeRadio->isChecked();
    std::string address = depinAddressEdit->text().toStdString();
    std::string change_address = depinChangeAddressCheckBox->isChecked() ? depinChangeAddressEdit->text().toStdString() : "";

    CReserveKey reservekey(model->getWallet());
    CWalletTx transaction;
    CAmount nRequiredFee;
    CCoinControl ctrl;

    if (change_address.empty()) {
        CTxDestination change_dest;
        std::string strFailReason;
        if (!model->getWallet()->CreateNewChangeAddress(reservekey, change_dest, strFailReason)) {
            QMessageBox changeAddressBox;
            changeAddressBox.setText(tr("Failed to create a change address"));
            changeAddressBox.exec();
            return;
        }

        change_address = EncodeDestination(change_dest);
    }

    std::pair<int, std::string> error;
    std::vector<std::pair<CAssetTransfer, std::string>> vTransfers;
    std::vector<std::pair<CNullAssetTxData, std::string>> vecAssetData;

    int flag = -1;
    if (fSelfRevoke) {
        std::string holderAddress;
        bool foundOwnerControlledHolding = false;
        if (!findDepinHolderAddress(asset_name, holderAddress, foundOwnerControlledHolding)) {
            QMessageBox failMsgBox;
            failMsgBox.setText(foundOwnerControlledHolding ? tr("The address holding the DEPIN owner token cannot self-revoke")
                                                           : tr("This wallet does not hold the selected DEPIN asset"));
            failMsgBox.exec();
            return;
        }

        address = holderAddress;
        flag = 1;
        vecAssetData.push_back(std::make_pair(CNullAssetTxData(asset_name, flag), address));
    } else if (fFreezeAddress || fUnfreezeAddress) {
        if (address == change_address) {
            QMessageBox failMsgBox;
            failMsgBox.setText(tr("The DEPIN owner token change address cannot be the same address being managed"));
            failMsgBox.exec();
            return;
        }

        flag = fFreezeAddress ? 1 : 0;
        vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_name + OWNER_TAG, OWNER_ASSET_AMOUNT), change_address));
        vecAssetData.push_back(std::make_pair(CNullAssetTxData(asset_name, flag), address));
    }

    if (flag == -1) {
        QMessageBox failMsgBox;
        failMsgBox.setText(tr("Failed to generate the correct DEPIN transaction. Please try again"));
        failMsgBox.exec();
        return;
    }

    ctrl.destChange = DecodeDestination(change_address);

    if (IsInitialBlockDownload()) {
        GUIUtil::SyncWarningMessage syncWarning(this);
        bool sendTransaction = syncWarning.showTransactionSyncWarningMessage();
        if (!sendTransaction)
            return;
    }

    if (!CreateTransferAssetTransaction(model->getWallet(), ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee, &vecAssetData)) {
        QMessageBox createTransactionBox;
        createTransactionBox.setText(QString::fromStdString(error.second));
        createTransactionBox.exec();
        return;
    }

    QString questionString;
    if (fSelfRevoke) {
        questionString.append(tr("Self-revoking DEPIN asset <b>%1</b> for address <b>%2</b><br>")
                                  .arg(QString::fromStdString(asset_name), QString::fromStdString(address)));
    } else if (fFreezeAddress) {
        questionString.append(tr("Freezing DEPIN asset <b>%1</b> for address <b>%2</b><br>")
                                  .arg(QString::fromStdString(asset_name), QString::fromStdString(address)));
    } else {
        questionString.append(tr("Restoring DEPIN asset <b>%1</b> for address <b>%2</b><br>")
                                  .arg(QString::fromStdString(asset_name), QString::fromStdString(address)));
    }

    if(nRequiredFee > 0)
    {
        questionString.append("<hr /><span style='color:#e82121;'>");
        questionString.append(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), nRequiredFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));
        questionString.append(" (" + QString::number((double)GetVirtualTransactionSize(transaction) / 1000) + " kB)");
    }

    questionString.append("<hr />");
    CAmount totalAmount = nRequiredFee;
    QStringList alternativeUnits;
    for (NeuraiUnits::Unit u : NeuraiUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(NeuraiUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
                                  .arg(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
                                  .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    QString title;
    if (fSelfRevoke) {
        title = tr("Confirm self-revoking DEPIN asset");
    } else if (fFreezeAddress) {
        title = tr("Confirm freezing DEPIN asset");
    } else {
        title = tr("Confirm restoring DEPIN asset");
    }

    SendConfirmationDialog confirmationDialog(title, questionString, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    std::string txid;
    if (!SendAssetTransaction(model->getWallet(), transaction, reservekey, error, txid)) {
        QMessageBox sendTransactionBox;
        sendTransactionBox.setText(QString::fromStdString(error.second));
        sendTransactionBox.exec();
        return;
    }

    QMessageBox txidMsgBox;
    std::string sentMsg = _("Sent new transaction to the network");
    std::string totalMsg = strprintf("%s: %s",sentMsg, txid);
    txidMsgBox.setText(QString::fromStdString(totalMsg));
    txidMsgBox.exec();

    clearDepinForm();
}

void RestrictedAssetsDialog::assignQualifierClicked()
{
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    AssignQualifier* widget = ui->tabWidget->findChild<AssignQualifier *>("tab_assign_qualifier");

    std::string address = widget->getUI()->lineEditAddress->text().toStdString();
    std::string asset_name = widget->getUI()->assetComboBox->currentData(AssetTableModel::RoleIndex::AssetNameRole).toString().toStdString();
    std::string change_address = widget->getUI()->checkBoxChangeAddress->isChecked() ? widget->getUI()->lineEditChangeAddress->text().toStdString(): "";
    std::string decodedAssetData = DecodeAssetData(widget->getUI()->lineEditAssetData->text().toStdString());

    int flag = widget->getUI()->assignTypeComboBox->currentIndex() ? 0 : 1;

    CReserveKey reservekey(model->getWallet());
    CWalletTx transaction;
    CAmount nRequiredFee;
    CCoinControl ctrl;

    // If the optional change address wasn't given create a new change address for this wallet
    if (change_address == "") {
        CTxDestination change_dest;
        std::string strFailReason;
        if (!model->getWallet()->CreateNewChangeAddress(reservekey, change_dest, strFailReason)) {
            QMessageBox changeAddressBox;
            changeAddressBox.setText(tr("Failed to create a change address"));
            changeAddressBox.exec();
            return;
        }

        change_address = EncodeDestination(change_dest);
    }

    ctrl.destChange = DecodeDestination(change_address);

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    // Always transfer 1 of the qualifier tokens to the change address
    vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_name, 1 * COIN, decodedAssetData), change_address));

    // Add the asset data with the flag to remove or add the tag 1 = Add, 0 = Remove
    std::vector< std::pair<CNullAssetTxData, std::string> > vecAssetData;
    vecAssetData.push_back(std::make_pair(CNullAssetTxData(asset_name, flag), address));

    // Create the Transaction
    if (!CreateTransferAssetTransaction(model->getWallet(), ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee, &vecAssetData)) {
        QMessageBox createTransactionBox;
        createTransactionBox.setText(QString::fromStdString(error.second));
        createTransactionBox.exec();
        return;
    }

    QString addingQualifier = tr("Adding qualifier <b>%1</b> to address <b>%2</b><br>").arg(QString::fromStdString(asset_name), QString::fromStdString(address));
    QString removingQualifier = tr("Removing qualifier <b>%1</b> from address <b>%2</b><br>").arg(QString::fromStdString(asset_name), QString::fromStdString(address));

    QString questionString;
    // Format confirmation message

    questionString.append(flag ? addingQualifier : removingQualifier);
    if(nRequiredFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#e82121;'>");
        questionString.append(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), nRequiredFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number((double)GetVirtualTransactionSize(transaction) / 1000) + " kB)");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount =  nRequiredFee;
    QStringList alternativeUnits;
    for (NeuraiUnits::Unit u : NeuraiUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(NeuraiUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
                                  .arg(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
                                  .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    QString addString = tr("Confirm adding qualifier");
    QString removingString = tr("Confirm removing qualifier");
    SendConfirmationDialog confirmationDialog(flag ? addString : removingString,
                                              questionString, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(model->getWallet(), transaction, reservekey, error, txid)) {
        QMessageBox sendTransactionBox;
        sendTransactionBox.setText(QString::fromStdString(error.second));
        sendTransactionBox.exec();
    }

    QMessageBox txidMsgBox;
    std::string sentMsg = _("Sent new transaction to the network");
    std::string totalMsg = strprintf("%s: %s",sentMsg, txid);
    txidMsgBox.setText(QString::fromStdString(totalMsg));
    txidMsgBox.exec();

    widget->clear();
}
