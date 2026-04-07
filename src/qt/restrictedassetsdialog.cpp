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
#include "neuraiamountfield.h"
#include "qvalidatedlineedit.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QGraphicsDropShadowEffect>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QFontMetrics>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>
#include <QDebug>
#include <QMessageBox>
#include <algorithm>
#include <set>

#include <policy/policy.h>
#include <core_io.h>
#include <rpc/mining.h>
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>

RestrictedAssetsDialog::RestrictedAssetsDialog(const PlatformStyle *_platformStyle, QWidget *parent, PageMode mode) :
        QWidget(parent),
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
        depinCreateTab(0),
        depinTransferTab(0),
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
        depinSelfRevokeRadio(0),
        depinCreateAssetComboBox(0),
        depinCreateAddressEdit(0),
        depinCreateQuantitySpinBox(0),
        depinCreateReissuableCheckBox(0),
        depinCreateUnitsLabel(0),
        depinCreateChangeAddressCheckBox(0),
        depinCreateChangeAddressEdit(0),
        depinCreateWarningLabel(0),
        depinCreateButton(0),
        depinCreateClearButton(0),
        depinCreateFeeGroup(0),
        depinCreateSmartFeeRadio(0),
        depinCreateCustomFeeRadio(0),
        depinCreateConfTargetSelector(0),
        depinCreateSmartFeeLabel(0),
        depinCreateFeeEstimationLabel(0),
        depinCreateMinimumFeeCheckBox(0),
        depinCreateCustomFee(0),
        depinTransferAssetComboBox(0),
        depinTransferBatchCheckBox(0),
        depinTransferAddressEdit(0),
        depinTransferBatchEdit(0),
        depinTransferBatchHelpLabel(0),
        depinTransferWarningLabel(0),
        depinTransferButton(0),
        depinTransferClearButton(0)
{

    ui->setupUi(this);
    setWindowTitle(pageMode == PageMode::DepinOnly ? "DePIN" : "Manage Restricted Assets");
    setupStyling(_platformStyle);
}

void RestrictedAssetsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel && pageMode == PageMode::DepinOnly) {
        connect(_clientModel, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)), this, SLOT(updateDepinCreateSmartFeeLabel()));
    }
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
            if (!depinCreateTab) {
                createDepinCreateTab();
            }
            if (!depinTransferTab) {
                createDepinTransferTab();
            }
            if (depinCreateCustomFee) {
                depinCreateCustomFee->setDisplayUnit(_model->getOptionsModel()->getDisplayUnit());
            }
            connect(_model->getOptionsModel(), SIGNAL(customFeeFeaturesChanged(bool)), this, SLOT(depinCreateFeeFeatureChanged(bool)));
            depinCreateFeeFeatureChanged(_model->getOptionsModel()->getCustomFeeFeatures());
            updateDepinCreateAssets();
            updateDepinTransferAssets();
            updateDepinCreateMinFeeLabel();
            updateDepinCreateFeeSectionControls();
            updateDepinCreateSmartFeeLabel();
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

void RestrictedAssetsDialog::createDepinCreateTab()
{
    depinCreateTab = new QWidget(this);
    depinCreateTab->setObjectName("tab_depin_create");

    QVBoxLayout *mainLayout = new QVBoxLayout(depinCreateTab);
    mainLayout->setSpacing(12);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    QFormLayout *formLayout = new QFormLayout();
    formLayout->setHorizontalSpacing(10);
    formLayout->setVerticalSpacing(10);

    QLabel *assetLabel = new QLabel(tr("DEPIN Asset:"), depinCreateTab);
    assetLabel->setStyleSheet(STRING_LABEL_COLOR);
    assetLabel->setFont(GUIUtil::getTopLabelFont());
    depinCreateAssetComboBox = new QComboBox(depinCreateTab);
    formLayout->addRow(assetLabel, depinCreateAssetComboBox);

    QLabel *addressLabel = new QLabel(tr("Recipient Address:"), depinCreateTab);
    addressLabel->setStyleSheet(STRING_LABEL_COLOR);
    addressLabel->setFont(GUIUtil::getTopLabelFont());
    depinCreateAddressEdit = new QLineEdit(depinCreateTab);
    depinCreateAddressEdit->setReadOnly(true);
    formLayout->addRow(addressLabel, depinCreateAddressEdit);

    QLabel *quantityLabel = new QLabel(tr("Quantity:"), depinCreateTab);
    quantityLabel->setStyleSheet(STRING_LABEL_COLOR);
    quantityLabel->setFont(GUIUtil::getTopLabelFont());
    depinCreateQuantitySpinBox = new QDoubleSpinBox(depinCreateTab);
    depinCreateQuantitySpinBox->setDecimals(0);
    depinCreateQuantitySpinBox->setMinimum(0);
    depinCreateQuantitySpinBox->setMaximum(21000000000.0);
    depinCreateQuantitySpinBox->setSingleStep(1.0);
    formLayout->addRow(quantityLabel, depinCreateQuantitySpinBox);

    QLabel *unitsLabel = new QLabel(tr("Units:"), depinCreateTab);
    unitsLabel->setStyleSheet(STRING_LABEL_COLOR);
    unitsLabel->setFont(GUIUtil::getTopLabelFont());
    depinCreateUnitsLabel = new QLabel(tr("0 (fixed for DEPIN)"), depinCreateTab);
    depinCreateUnitsLabel->setFont(GUIUtil::getSubLabelFont());
    formLayout->addRow(unitsLabel, depinCreateUnitsLabel);

    depinCreateReissuableCheckBox = new QCheckBox(tr("Can Reissue"), depinCreateTab);
    depinCreateReissuableCheckBox->setStyleSheet(QString(".QCheckBox{ %1; }").arg(STRING_LABEL_COLOR));
    formLayout->addRow(QString(), depinCreateReissuableCheckBox);

    depinCreateChangeAddressCheckBox = new QCheckBox(tr("Custom Change Address"), depinCreateTab);
    depinCreateChangeAddressCheckBox->setStyleSheet(QString(".QCheckBox{ %1; }").arg(STRING_LABEL_COLOR));
    depinCreateChangeAddressEdit = new QValidatedLineEdit(depinCreateTab);
    GUIUtil::setupAddressWidget(depinCreateChangeAddressEdit, this);
    depinCreateChangeAddressEdit->setEnabled(false);
    depinCreateChangeAddressEdit->hide();
    formLayout->addRow(depinCreateChangeAddressCheckBox, depinCreateChangeAddressEdit);

    mainLayout->addLayout(formLayout);

    QGroupBox *feeGroup = new QGroupBox(tr("Transaction Fee"), depinCreateTab);
    QVBoxLayout *feeLayout = new QVBoxLayout(feeGroup);

    depinCreateFeeGroup = new QButtonGroup(feeGroup);
    depinCreateSmartFeeRadio = new QRadioButton(tr("Recommended"), feeGroup);
    depinCreateCustomFeeRadio = new QRadioButton(tr("Custom"), feeGroup);
    depinCreateFeeGroup->addButton(depinCreateSmartFeeRadio, 0);
    depinCreateFeeGroup->addButton(depinCreateCustomFeeRadio, 1);
    depinCreateSmartFeeRadio->setChecked(true);

    QHBoxLayout *feeModeLayout = new QHBoxLayout();
    feeModeLayout->addWidget(depinCreateSmartFeeRadio);
    feeModeLayout->addWidget(depinCreateCustomFeeRadio);
    feeModeLayout->addStretch();
    feeLayout->addLayout(feeModeLayout);

    QHBoxLayout *smartFeeLayout = new QHBoxLayout();
    QLabel *targetLabel = new QLabel(tr("Confirmation target:"), feeGroup);
    smartFeeLayout->addWidget(targetLabel);
    depinCreateConfTargetSelector = new QComboBox(feeGroup);
    smartFeeLayout->addWidget(depinCreateConfTargetSelector, 1);
    depinCreateSmartFeeLabel = new QLabel(feeGroup);
    smartFeeLayout->addWidget(depinCreateSmartFeeLabel);
    feeLayout->addLayout(smartFeeLayout);

    depinCreateFeeEstimationLabel = new QLabel(feeGroup);
    depinCreateFeeEstimationLabel->setWordWrap(true);
    feeLayout->addWidget(depinCreateFeeEstimationLabel);

    QHBoxLayout *customFeeLayout = new QHBoxLayout();
    depinCreateMinimumFeeCheckBox = new QCheckBox(feeGroup);
    depinCreateMinimumFeeCheckBox->setStyleSheet(QString(".QCheckBox{ %1; }").arg(STRING_LABEL_COLOR));
    customFeeLayout->addWidget(depinCreateMinimumFeeCheckBox);
    depinCreateCustomFee = new NeuraiAmountField(feeGroup);
    customFeeLayout->addWidget(depinCreateCustomFee);
    feeLayout->addLayout(customFeeLayout);

    QSettings settings;
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0);
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_TRANSACTION_FEE);
    if (!settings.contains("fPayOnlyMinFee"))
        settings.setValue("fPayOnlyMinFee", false);
    if (!settings.contains("nConfTarget"))
        settings.setValue("nConfTarget", model ? model->getDefaultConfirmTarget() : confTargets.front());

    for (const int &n : confTargets) {
        depinCreateConfTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n * GetParams().GetConsensus().nPowTargetSpacing)).arg(n));
    }

    if (settings.value("nFeeRadio").toInt() == 1) {
        depinCreateCustomFeeRadio->setChecked(true);
    } else {
        depinCreateSmartFeeRadio->setChecked(true);
    }

    depinCreateCustomFee->setValue(settings.value("nTransactionFee").toLongLong());
    depinCreateCustomFee->setSingleStep(GetRequiredFee(1000));
    depinCreateMinimumFeeCheckBox->setChecked(settings.value("fPayOnlyMinFee").toBool());
    depinCreateConfTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));

    mainLayout->addWidget(feeGroup);

    depinCreateWarningLabel = new QLabel(depinCreateTab);
    depinCreateWarningLabel->hide();
    depinCreateWarningLabel->setWordWrap(true);
    mainLayout->addWidget(depinCreateWarningLabel);

    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    depinCreateClearButton = new QPushButton(tr("Clear"), depinCreateTab);
    depinCreateButton = new QPushButton(tr("Reissue"), depinCreateTab);
    depinCreateButton->setDisabled(true);
    buttonsLayout->addStretch();
    buttonsLayout->addWidget(depinCreateClearButton);
    buttonsLayout->addWidget(depinCreateButton);
    mainLayout->addLayout(buttonsLayout);

    connect(depinCreateAssetComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(depinCreateAssetChanged(int)));
    connect(depinCreateQuantitySpinBox, SIGNAL(valueChanged(double)), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateReissuableCheckBox, SIGNAL(clicked()), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateChangeAddressCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinCreateChangeAddressChanged(int)));
    connect(depinCreateChangeAddressCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateChangeAddressEdit, SIGNAL(textChanged(QString)), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateClearButton, SIGNAL(clicked()), this, SLOT(clearDepinCreateForm()));
    connect(depinCreateButton, SIGNAL(clicked()), this, SLOT(depinCreateClicked()));
    connect(depinCreateSmartFeeRadio, SIGNAL(clicked()), this, SLOT(updateDepinCreateFeeSectionControls()));
    connect(depinCreateCustomFeeRadio, SIGNAL(clicked()), this, SLOT(updateDepinCreateFeeSectionControls()));
    connect(depinCreateSmartFeeRadio, SIGNAL(clicked()), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateCustomFeeRadio, SIGNAL(clicked()), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateConfTargetSelector, SIGNAL(currentIndexChanged(int)), this, SLOT(updateDepinCreateSmartFeeLabel()));
    connect(depinCreateConfTargetSelector, SIGNAL(currentIndexChanged(int)), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateMinimumFeeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinCreateSetMinimumFee()));
    connect(depinCreateMinimumFeeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(updateDepinCreateFeeSectionControls()));
    connect(depinCreateMinimumFeeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinCreateDataChanged()));
    connect(depinCreateCustomFee, SIGNAL(valueChanged()), this, SLOT(depinCreateDataChanged()));

    ui->tabWidget->addTab(depinCreateTab, tr("Create"));
}

void RestrictedAssetsDialog::createDepinTransferTab()
{
    depinTransferTab = new QWidget(this);
    depinTransferTab->setObjectName("tab_depin_transfer");

    QVBoxLayout *mainLayout = new QVBoxLayout(depinTransferTab);
    mainLayout->setSpacing(12);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    QFormLayout *formLayout = new QFormLayout();
    formLayout->setHorizontalSpacing(10);
    formLayout->setVerticalSpacing(10);

    QLabel *assetLabel = new QLabel(tr("DEPIN Asset:"), depinTransferTab);
    assetLabel->setStyleSheet(STRING_LABEL_COLOR);
    assetLabel->setFont(GUIUtil::getTopLabelFont());
    depinTransferAssetComboBox = new QComboBox(depinTransferTab);
    formLayout->addRow(assetLabel, depinTransferAssetComboBox);

    depinTransferBatchCheckBox = new QCheckBox(tr("Batch mode"), depinTransferTab);
    depinTransferBatchCheckBox->setStyleSheet(QString(".QCheckBox{ %1; }").arg(STRING_LABEL_COLOR));
    formLayout->addRow(QString(), depinTransferBatchCheckBox);

    QLabel *addressLabel = new QLabel(tr("Destination Address:"), depinTransferTab);
    addressLabel->setStyleSheet(STRING_LABEL_COLOR);
    addressLabel->setFont(GUIUtil::getTopLabelFont());
    depinTransferAddressEdit = new QValidatedLineEdit(depinTransferTab);
    GUIUtil::setupAddressWidget(depinTransferAddressEdit, this);
    formLayout->addRow(addressLabel, depinTransferAddressEdit);

    QLabel *batchLabel = new QLabel(tr("Batch Addresses:"), depinTransferTab);
    batchLabel->setStyleSheet(STRING_LABEL_COLOR);
    batchLabel->setFont(GUIUtil::getTopLabelFont());
    depinTransferBatchEdit = new QPlainTextEdit(depinTransferTab);
    depinTransferBatchEdit->setPlaceholderText(tr("One Neurai address per line"));
    depinTransferBatchEdit->hide();
    formLayout->addRow(batchLabel, depinTransferBatchEdit);

    depinTransferBatchHelpLabel = new QLabel(tr("Batch mode sends exactly 1 DEPIN asset per address. Maximum 20 addresses."), depinTransferTab);
    depinTransferBatchHelpLabel->setWordWrap(true);
    depinTransferBatchHelpLabel->hide();
    formLayout->addRow(QString(), depinTransferBatchHelpLabel);

    mainLayout->addLayout(formLayout);

    depinTransferWarningLabel = new QLabel(depinTransferTab);
    depinTransferWarningLabel->hide();
    depinTransferWarningLabel->setWordWrap(true);
    mainLayout->addWidget(depinTransferWarningLabel);

    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    depinTransferClearButton = new QPushButton(tr("Clear"), depinTransferTab);
    depinTransferButton = new QPushButton(tr("Transfer"), depinTransferTab);
    depinTransferButton->setDisabled(true);
    buttonsLayout->addStretch();
    buttonsLayout->addWidget(depinTransferClearButton);
    buttonsLayout->addWidget(depinTransferButton);
    mainLayout->addLayout(buttonsLayout);

    connect(depinTransferAssetComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(depinTransferDataChanged()));
    connect(depinTransferBatchCheckBox, SIGNAL(stateChanged(int)), this, SLOT(depinTransferBatchModeChanged(int)));
    connect(depinTransferAddressEdit, SIGNAL(textChanged(QString)), this, SLOT(depinTransferDataChanged()));
    connect(depinTransferBatchEdit, SIGNAL(textChanged()), this, SLOT(depinTransferDataChanged()));
    connect(depinTransferClearButton, SIGNAL(clicked()), this, SLOT(clearDepinTransferForm()));
    connect(depinTransferButton, SIGNAL(clicked()), this, SLOT(depinTransferClicked()));

    ui->tabWidget->addTab(depinTransferTab, tr("Transfer"));
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

void RestrictedAssetsDialog::depinCreateDataChanged()
{
    if (!depinCreateButton) {
        return;
    }

    depinCreateButton->setDisabled(true);
    clearDepinCreateWarning();

    if (validateDepinCreateForm()) {
        depinCreateButton->setEnabled(true);
    }
}

void RestrictedAssetsDialog::depinCreateChangeAddressChanged(int state)
{
    if (!depinCreateChangeAddressEdit) {
        return;
    }

    const bool checked = state == Qt::Checked;
    depinCreateChangeAddressEdit->setEnabled(checked);
    depinCreateChangeAddressEdit->setVisible(checked);
    depinCreateDataChanged();
}

void RestrictedAssetsDialog::depinCreateAssetChanged(int)
{
    updateDepinCreateSelectedAsset();
}

void RestrictedAssetsDialog::clearDepinCreateForm()
{
    if (!depinCreateTab) {
        return;
    }

    depinCreateAssetComboBox->setCurrentIndex(0);
    depinCreateAddressEdit->clear();
    depinCreateQuantitySpinBox->setValue(0);
    depinCreateReissuableCheckBox->setChecked(true);
    depinCreateChangeAddressCheckBox->setChecked(false);
    depinCreateChangeAddressEdit->clear();
    depinCreateButton->setDisabled(true);
    clearDepinCreateWarning();
}

void RestrictedAssetsDialog::depinCreateClicked()
{
    QString validationError;
    if (!validateDepinCreateForm(&validationError)) {
        setDepinCreateWarning(validationError);
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        return;
    }

    const QString qAssetName = depinCreateAssetComboBox->currentData().toString();
    const QString qAddress = depinCreateAddressEdit->text();
    const CAmount quantity = static_cast<CAmount>(depinCreateQuantitySpinBox->value()) * COIN;
    const bool reissuable = depinCreateReissuableCheckBox->isChecked();

    CReissueAsset reissueAsset(qAssetName.toStdString(), quantity, -1, reissuable ? 1 : 0, "");
    CCoinControl coinControl;
    updateDepinCreateCoinControlState(coinControl);

    CWalletTx transaction;
    CReserveKey reservekey(model->getWallet());
    std::pair<int, std::string> error;
    CAmount nRequiredFee;

    if (IsInitialBlockDownload()) {
        GUIUtil::SyncWarningMessage syncWarning(this);
        bool sendTransaction = syncWarning.showTransactionSyncWarningMessage();
        if (!sendTransaction)
            return;
    }

    if (!CreateReissueAssetTransaction(model->getWallet(), coinControl, reissueAsset, qAddress.toStdString(), error, transaction, reservekey, nRequiredFee)) {
        setDepinCreateWarning(QString::fromStdString(error.second));
        return;
    }

    std::string strError;
    if (!ContextualCheckReissueAsset(passets, reissueAsset, strError, *transaction.tx.get())) {
        setDepinCreateWarning(QString::fromStdString(strError));
        return;
    }

    QString questionString = tr("Reissuing DEPIN asset <b>%1</b> to address <b>%2</b><br>")
                                 .arg(qAssetName, qAddress);

    if(nRequiredFee > 0)
    {
        questionString.append("<hr /><span style='color:#e82121;'>");
        questionString.append(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), nRequiredFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));
        questionString.append(" (" + tr("virtual size: %1 kVB").arg(QString::number((double)GetVirtualTransactionSize(transaction) / 1000, 'f', 3)) + ")");
    }

    questionString.append("<hr />");
    const CAmount totalAmount = GetReissueAssetBurnAmount() + nRequiredFee;
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

    SendConfirmationDialog confirmationDialog(tr("Confirm DEPIN reissue"),
                                              questionString, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    std::string txid;
    if (!SendAssetTransaction(model->getWallet(), transaction, reservekey, error, txid)) {
        setDepinCreateWarning(QString::fromStdString(error.second));
        return;
    }

    QMessageBox txidMsgBox;
    std::string sentMsg = _("Sent new transaction to the network");
    std::string totalMsg = strprintf("%s: %s", sentMsg, txid);
    txidMsgBox.setText(QString::fromStdString(totalMsg));
    txidMsgBox.exec();

    clearDepinCreateForm();
    updateDepinCreateAssets();
}

void RestrictedAssetsDialog::depinCreateFeeFeatureChanged(bool enabled)
{
    if (!depinCreateCustomFeeRadio || !depinCreateSmartFeeRadio || !depinCreateMinimumFeeCheckBox || !depinCreateCustomFee) {
        return;
    }

    if (!enabled) {
        depinCreateSmartFeeRadio->setChecked(true);
    }

    depinCreateCustomFeeRadio->setEnabled(enabled);
    depinCreateMinimumFeeCheckBox->setEnabled(enabled && depinCreateCustomFeeRadio->isChecked());
    depinCreateCustomFee->setEnabled(enabled && depinCreateCustomFeeRadio->isChecked() && !depinCreateMinimumFeeCheckBox->isChecked());
    updateDepinCreateFeeSectionControls();
}

void RestrictedAssetsDialog::depinCreateSetMinimumFee()
{
    if (!depinCreateCustomFee) {
        return;
    }

    depinCreateCustomFee->setValue(GetRequiredFee(1000));
}

void RestrictedAssetsDialog::depinTransferDataChanged()
{
    if (!depinTransferButton) {
        return;
    }

    depinTransferButton->setDisabled(true);
    clearDepinTransferWarning();

    if (validateDepinTransferForm()) {
        depinTransferButton->setEnabled(true);
    }
}

void RestrictedAssetsDialog::depinTransferBatchModeChanged(int state)
{
    const bool batchMode = state == Qt::Checked;
    if (depinTransferAddressEdit) {
        depinTransferAddressEdit->setVisible(!batchMode);
        depinTransferAddressEdit->setEnabled(!batchMode);
    }
    if (depinTransferBatchEdit) {
        depinTransferBatchEdit->setVisible(batchMode);
        depinTransferBatchEdit->setEnabled(batchMode);
    }
    if (depinTransferBatchHelpLabel) {
        depinTransferBatchHelpLabel->setVisible(batchMode);
    }

    depinTransferDataChanged();
}

void RestrictedAssetsDialog::clearDepinTransferForm()
{
    if (!depinTransferTab) {
        return;
    }

    depinTransferAssetComboBox->setCurrentIndex(0);
    depinTransferBatchCheckBox->setChecked(false);
    depinTransferAddressEdit->clear();
    depinTransferBatchEdit->clear();
    depinTransferButton->setDisabled(true);
    clearDepinTransferWarning();
}

void RestrictedAssetsDialog::depinTransferClicked()
{
    QString validationError;
    if (!validateDepinTransferForm(&validationError)) {
        setDepinTransferWarning(validationError);
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        return;
    }

    const QString qAssetName = depinTransferAssetComboBox->currentData().toString();
    const QStringList recipients = depinTransferRecipients();

    std::vector<std::pair<CAssetTransfer, std::string>> vTransfers;
    for (const QString& recipient : recipients) {
        vTransfers.emplace_back(std::make_pair(CAssetTransfer(qAssetName.toStdString(), 1 * COIN), recipient.toStdString()));
    }

    CCoinControl ctrl;
    std::string ownerAddress;
    std::vector<COutput> ownerControlledOutputs;
    CAmount ownerControlledAmount = 0;
    if (!getDepinOwnerControlledOutputs(qAssetName.toStdString(), ownerAddress, &ownerControlledOutputs, &ownerControlledAmount)) {
        setDepinTransferWarning(tr("Unable to find owner-controlled inputs for the selected DEPIN asset"));
        return;
    }

    ctrl.assetDestChange = DecodeDestination(ownerAddress);
    ctrl.strAssetSelected = qAssetName.toStdString();

    CAmount selectedAmount = 0;
    const CAmount requiredAmount = recipients.size() * COIN;
    for (const auto& output : ownerControlledOutputs) {
        ctrl.SelectAsset(COutPoint(output.tx->GetHash(), output.i));

        CAssetOutputEntry outputData;
        if (GetAssetData(output.tx->tx->vout[output.i].scriptPubKey, outputData)) {
            selectedAmount += outputData.nAmount;
        }

        if (selectedAmount >= requiredAmount) {
            break;
        }
    }

    if (selectedAmount < requiredAmount) {
        setDepinTransferWarning(tr("Not enough owner-controlled inputs are available for the selected DEPIN asset"));
        return;
    }

    CWalletTx transaction;
    CReserveKey reservekey(model->getWallet());
    std::pair<int, std::string> error;
    CAmount nRequiredFee;

    if (IsInitialBlockDownload()) {
        GUIUtil::SyncWarningMessage syncWarning(this);
        bool sendTransaction = syncWarning.showTransactionSyncWarningMessage();
        if (!sendTransaction)
            return;
    }

    if (!CreateTransferAssetTransaction(model->getWallet(), ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee)) {
        setDepinTransferWarning(QString::fromStdString(error.second));
        return;
    }

    QStringList formatted;
    for (const QString& recipient : recipients) {
        const QString amount = "<b>1 " + qAssetName + "</b>";
        const QString address = "<span style='font-family: monospace;'>" + recipient + "</span>";
        formatted.append(tr("%1 to %2").arg(amount, address));
    }

    QString questionString = tr("Confirm DEPIN transfer");
    questionString.append("<br /><br />%1");

    if(nRequiredFee > 0)
    {
        questionString.append("<hr /><span style='color:#e82121;'>");
        questionString.append(NeuraiUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), nRequiredFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));
        questionString.append(" (" + tr("virtual size: %1 kVB").arg(QString::number((double)GetVirtualTransactionSize(transaction) / 1000, 'f', 3)) + ")");
    }

    SendConfirmationDialog confirmationDialog(tr("Confirm DEPIN transfer"),
                                              questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    std::string txid;
    if (!SendAssetTransaction(model->getWallet(), transaction, reservekey, error, txid)) {
        setDepinTransferWarning(QString::fromStdString(error.second));
        return;
    }

    QMessageBox txidMsgBox;
    std::string sentMsg = _("Sent new transaction to the network");
    std::string totalMsg = strprintf("%s: %s", sentMsg, txid);
    txidMsgBox.setText(QString::fromStdString(totalMsg));
    txidMsgBox.exec();

    clearDepinTransferForm();
    updateDepinTransferAssets();
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

bool RestrictedAssetsDialog::findDepinOwnerAddress(const std::string& assetName, std::string& ownerAddress) const
{
    ownerAddress.clear();

    if (!model || !model->getWallet()) {
        return false;
    }

    const std::string ownerTokenName = assetName + OWNER_TAG;
    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    model->getWallet()->AvailableAssets(mapAssetCoins, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, 0);

    const auto it = mapAssetCoins.find(ownerTokenName);
    if (it == mapAssetCoins.end()) {
        return false;
    }

    for (const auto& output : it->second) {
        if (!output.tx || !output.tx->tx || output.i >= output.tx->tx->vout.size()) {
            continue;
        }

        const CScript& script = output.tx->tx->vout[output.i].scriptPubKey;
        std::string parsedOwnerName;
        std::string parsedOwnerAddress;
        if (OwnerAssetFromScript(script, parsedOwnerName, parsedOwnerAddress) &&
            parsedOwnerName == ownerTokenName) {
            ownerAddress = parsedOwnerAddress;
            return true;
        }

        CAssetTransfer transfer;
        if (TransferAssetFromScript(script, transfer, parsedOwnerAddress) &&
            transfer.strName == ownerTokenName) {
            ownerAddress = parsedOwnerAddress;
            return true;
        }
    }

    return false;
}

bool RestrictedAssetsDialog::getDepinAssetMetadata(const std::string& assetName, CNewAsset& assetData) const
{
    if (passets && passets->GetAssetMetaDataIfExists(assetName, assetData)) {
        return true;
    }

    if (!model || !model->getWallet()) {
        return false;
    }

    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    model->getWallet()->AvailableAssets(mapAssetCoins, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, 0);

    const auto it = mapAssetCoins.find(assetName);
    if (it == mapAssetCoins.end()) {
        return false;
    }

    for (const auto& output : it->second) {
        if (!output.tx || !output.tx->tx || output.i >= output.tx->tx->vout.size()) {
            continue;
        }

        std::string address;
        if (AssetFromScript(output.tx->tx->vout[output.i].scriptPubKey, assetData, address) &&
            assetData.strName == assetName) {
            return true;
        }
    }

    return false;
}

bool RestrictedAssetsDialog::getDepinOwnerControlledOutputs(const std::string& assetName, std::string& ownerAddress, std::vector<COutput>* outputs, CAmount* totalAmount) const
{
    if (outputs) {
        outputs->clear();
    }
    if (totalAmount) {
        *totalAmount = 0;
    }

    if (!findDepinOwnerAddress(assetName, ownerAddress) || !model || !model->getWallet()) {
        return false;
    }

    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    model->getWallet()->AvailableAssets(mapAssetCoins, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, 0);

    const auto it = mapAssetCoins.find(assetName);
    if (it == mapAssetCoins.end()) {
        return false;
    }

    CAmount ownerControlledAmount = 0;
    for (const auto& output : it->second) {
        if (!output.tx || !output.tx->tx || output.i >= output.tx->tx->vout.size()) {
            continue;
        }

        CAssetOutputEntry outputData;
        if (!GetAssetData(output.tx->tx->vout[output.i].scriptPubKey, outputData) ||
            outputData.assetName != assetName) {
            continue;
        }

        if (EncodeDestination(outputData.destination) != ownerAddress) {
            continue;
        }

        ownerControlledAmount += outputData.nAmount;
        if (outputs) {
            outputs->push_back(output);
        }
    }

    if (totalAmount) {
        *totalAmount = ownerControlledAmount;
    }

    return ownerControlledAmount > 0;
}

void RestrictedAssetsDialog::updateDepinCreateAssets()
{
    if (!depinCreateAssetComboBox || !model || !model->getWallet() || !passets) {
        return;
    }

    const QString currentAsset = depinCreateAssetComboBox->currentData().toString();

    std::vector<std::string> walletAssets;
    GetAllMyAssets(model->getWallet(), walletAssets, 0, true, false);

    depinCreateAssetComboBox->clear();
    depinCreateAssetComboBox->addItem(QString(), QString());

    std::set<std::string> inserted;
    for (const auto& item : walletAssets) {
        std::string assetName;
        if (IsAssetNameADEPIN(item)) {
            assetName = item;
        } else if (IsAssetNameAnOwner(item) && !item.empty() && item.front() == '&') {
            assetName = item.substr(0, item.size() - 1);
        } else {
            continue;
        }

        if (inserted.count(assetName)) {
            continue;
        }

        CNewAsset assetData;
        std::string ownerAddress;
        if (!getDepinAssetMetadata(assetName, assetData) || !assetData.nReissuable || !findDepinOwnerAddress(assetName, ownerAddress)) {
            continue;
        }

        inserted.insert(assetName);
        depinCreateAssetComboBox->addItem(QString::fromStdString(assetName), QString::fromStdString(assetName));
    }

    const int existingIndex = depinCreateAssetComboBox->findData(currentAsset);
    depinCreateAssetComboBox->setCurrentIndex(existingIndex >= 0 ? existingIndex : 0);
    updateDepinCreateSelectedAsset();
}

void RestrictedAssetsDialog::updateDepinCreateSelectedAsset()
{
    if (!depinCreateAssetComboBox || !depinCreateAddressEdit || !depinCreateQuantitySpinBox) {
        return;
    }

    const QString qAssetName = depinCreateAssetComboBox->currentData().toString();
    if (qAssetName.isEmpty()) {
        depinCreateAddressEdit->clear();
        depinCreateQuantitySpinBox->setMaximum(21000000000.0);
        depinCreateQuantitySpinBox->setValue(0);
        depinCreateReissuableCheckBox->setChecked(true);
        depinCreateDataChanged();
        return;
    }

    std::string ownerAddress;
    if (!findDepinOwnerAddress(qAssetName.toStdString(), ownerAddress)) {
        depinCreateAddressEdit->clear();
        depinCreateQuantitySpinBox->setValue(0);
        setDepinCreateWarning(tr("Unable to find the owner address for the selected DEPIN asset"));
        depinCreateButton->setDisabled(true);
        return;
    }

    depinCreateAddressEdit->setText(QString::fromStdString(ownerAddress));

    CNewAsset assetData;
    if (getDepinAssetMetadata(qAssetName.toStdString(), assetData)) {
        const double currentAmount = static_cast<double>(assetData.nAmount / COIN);
        depinCreateQuantitySpinBox->setMaximum(std::max(0.0, 21000000000.0 - currentAmount));
        depinCreateReissuableCheckBox->setChecked(assetData.nReissuable);
    } else {
        depinCreateQuantitySpinBox->setMaximum(21000000000.0);
        depinCreateReissuableCheckBox->setChecked(true);
    }

    depinCreateQuantitySpinBox->setValue(0);
    depinCreateDataChanged();
}

void RestrictedAssetsDialog::updateDepinTransferAssets()
{
    if (!depinTransferAssetComboBox || !model || !model->getWallet()) {
        return;
    }

    const QString currentAsset = depinTransferAssetComboBox->currentData().toString();

    std::vector<std::string> walletAssets;
    GetAllMyAssets(model->getWallet(), walletAssets, 0, true, false);

    depinTransferAssetComboBox->clear();
    depinTransferAssetComboBox->addItem(QString(), QString());

    std::set<std::string> inserted;
    for (const auto& item : walletAssets) {
        if (!IsAssetNameADEPIN(item) || inserted.count(item)) {
            continue;
        }

        std::string ownerAddress;
        CAmount ownerControlledAmount = 0;
        if (getDepinOwnerControlledOutputs(item, ownerAddress, nullptr, &ownerControlledAmount) && ownerControlledAmount >= 1 * COIN) {
            inserted.insert(item);
            depinTransferAssetComboBox->addItem(QString::fromStdString(item), QString::fromStdString(item));
        }
    }

    const int existingIndex = depinTransferAssetComboBox->findData(currentAsset);
    depinTransferAssetComboBox->setCurrentIndex(existingIndex >= 0 ? existingIndex : 0);
    depinTransferDataChanged();
}

void RestrictedAssetsDialog::clearDepinCreateWarning()
{
    if (!depinCreateWarningLabel) {
        return;
    }

    depinCreateWarningLabel->clear();
    depinCreateWarningLabel->hide();
}

void RestrictedAssetsDialog::setDepinCreateWarning(const QString &message, bool failure)
{
    if (!depinCreateWarningLabel) {
        return;
    }

    depinCreateWarningLabel->setStyleSheet(failure ? STRING_LABEL_COLOR_WARNING : "");
    depinCreateWarningLabel->setText(message);
    depinCreateWarningLabel->show();
}

void RestrictedAssetsDialog::clearDepinTransferWarning()
{
    if (!depinTransferWarningLabel) {
        return;
    }

    depinTransferWarningLabel->clear();
    depinTransferWarningLabel->hide();
}

void RestrictedAssetsDialog::setDepinTransferWarning(const QString &message, bool failure)
{
    if (!depinTransferWarningLabel) {
        return;
    }

    depinTransferWarningLabel->setStyleSheet(failure ? STRING_LABEL_COLOR_WARNING : "");
    depinTransferWarningLabel->setText(message);
    depinTransferWarningLabel->show();
}

void RestrictedAssetsDialog::updateDepinCreateFeeSectionControls()
{
    if (!depinCreateSmartFeeRadio || !depinCreateCustomFeeRadio || !depinCreateConfTargetSelector ||
        !depinCreateCustomFee || !depinCreateMinimumFeeCheckBox) {
        return;
    }

    depinCreateConfTargetSelector->setEnabled(depinCreateSmartFeeRadio->isChecked());
    depinCreateSmartFeeLabel->setEnabled(depinCreateSmartFeeRadio->isChecked());
    depinCreateFeeEstimationLabel->setEnabled(depinCreateSmartFeeRadio->isChecked());
    depinCreateMinimumFeeCheckBox->setEnabled(depinCreateCustomFeeRadio->isChecked());
    depinCreateCustomFee->setEnabled(depinCreateCustomFeeRadio->isChecked() && !depinCreateMinimumFeeCheckBox->isChecked());
}

void RestrictedAssetsDialog::updateDepinCreateSmartFeeLabel()
{
    if (!model || !model->getOptionsModel() || !depinCreateSmartFeeLabel || !depinCreateFeeEstimationLabel) {
        return;
    }

    CCoinControl coinControl;
    updateDepinCreateCoinControlState(coinControl);
    coinControl.m_feerate.reset();

    FeeCalculation feeCalc;
    const CFeeRate feeRate = CFeeRate(GetMinimumFee(1000, coinControl, ::mempool, ::feeEstimator, &feeCalc));

    depinCreateSmartFeeLabel->setText(NeuraiUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK()) + "/kB");

    if (feeCalc.reason == FeeReason::FALLBACK) {
        depinCreateFeeEstimationLabel->setText(tr("Smart fee not initialized yet. This usually takes a few blocks."));
    } else {
        depinCreateFeeEstimationLabel->setText(tr("Estimated to begin confirmation within %n block(s).", "", feeCalc.returnedTarget));
    }
}

void RestrictedAssetsDialog::updateDepinCreateMinFeeLabel()
{
    if (!model || !model->getOptionsModel() || !depinCreateMinimumFeeCheckBox) {
        return;
    }

    depinCreateMinimumFeeCheckBox->setText(tr("Pay only the required fee of %1").arg(
            NeuraiUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), GetRequiredFee(1000)) + "/kB"));
}

bool RestrictedAssetsDialog::validateDepinCreateForm(QString *errorMessage)
{
    if (!model || !passets || !depinCreateAssetComboBox || !depinCreateAddressEdit || !depinCreateQuantitySpinBox) {
        if (errorMessage) {
            *errorMessage = tr("Unable to perform action at this time");
        }
        return false;
    }

    const QString qAssetName = depinCreateAssetComboBox->currentData().toString();
    if (qAssetName.isEmpty()) {
        if (errorMessage) {
            *errorMessage = tr("Must have a DEPIN asset selected");
        }
        return false;
    }

    if (!IsAssetNameADEPIN(qAssetName.toStdString())) {
        if (errorMessage) {
            *errorMessage = tr("Selected asset is not a valid DEPIN asset");
        }
        return false;
    }

    std::string ownerAddress;
    if (!findDepinOwnerAddress(qAssetName.toStdString(), ownerAddress)) {
        if (errorMessage) {
            *errorMessage = tr("The selected DEPIN owner token is not held by this wallet");
        }
        return false;
    }

    if (depinCreateAddressEdit->text() != QString::fromStdString(ownerAddress)) {
        if (errorMessage) {
            *errorMessage = tr("The DEPIN reissue recipient must be the address holding the owner token");
        }
        return false;
    }

    if (depinCreateQuantitySpinBox->value() <= 0) {
        if (errorMessage) {
            *errorMessage = tr("Quantity must be greater than zero");
        }
        return false;
    }

    CNewAsset assetData;
    if (!getDepinAssetMetadata(qAssetName.toStdString(), assetData)) {
        if (errorMessage) {
            *errorMessage = tr("Asset data couldn't be found");
        }
        return false;
    }

    const CAmount quantity = static_cast<CAmount>(depinCreateQuantitySpinBox->value()) * COIN;
    if (assetData.nAmount + quantity > MAX_MONEY) {
        if (errorMessage) {
            *errorMessage = tr("Quantity is to large. Max is 21,000,000,000");
        }
        return false;
    }

    if (depinCreateChangeAddressCheckBox && depinCreateChangeAddressCheckBox->isChecked()) {
        const QString qChangeAddress = depinCreateChangeAddressEdit->text();
        if (qChangeAddress.isEmpty()) {
            if (errorMessage) {
                *errorMessage = tr("Custom change address is required");
            }
            return false;
        }

        const CTxDestination dest = DecodeDestination(qChangeAddress.toStdString());
        if (!IsValidDestination(dest)) {
            if (errorMessage) {
                *errorMessage = tr("Invalid Neurai change address");
            }
            return false;
        }
    }

    bool validCustomFee = true;
    if (depinCreateCustomFee && depinCreateCustomFeeRadio && depinCreateCustomFeeRadio->isChecked()) {
        validCustomFee = depinCreateCustomFee->validate();
    }

    if (!validCustomFee) {
        if (errorMessage) {
            *errorMessage = tr("Invalid custom fee amount");
        }
        return false;
    }

    return true;
}

QStringList RestrictedAssetsDialog::depinTransferRecipients() const
{
    QStringList recipients;

    if (!depinTransferBatchCheckBox || !depinTransferBatchCheckBox->isChecked()) {
        if (depinTransferAddressEdit) {
            const QString address = depinTransferAddressEdit->text().trimmed();
            if (!address.isEmpty()) {
                recipients << address;
            }
        }
        return recipients;
    }

    if (!depinTransferBatchEdit) {
        return recipients;
    }

    const QStringList lines = depinTransferBatchEdit->toPlainText().split('\n');
    for (const QString& line : lines) {
        const QString address = line.trimmed();
        if (!address.isEmpty()) {
            recipients << address;
        }
    }

    return recipients;
}

bool RestrictedAssetsDialog::validateDepinTransferForm(QString *errorMessage)
{
    if (!model || !depinTransferAssetComboBox) {
        if (errorMessage) {
            *errorMessage = tr("Unable to perform action at this time");
        }
        return false;
    }

    const QString qAssetName = depinTransferAssetComboBox->currentData().toString();
    if (qAssetName.isEmpty()) {
        if (errorMessage) {
            *errorMessage = tr("Must have a DEPIN asset selected");
        }
        return false;
    }

    if (!IsAssetNameADEPIN(qAssetName.toStdString())) {
        if (errorMessage) {
            *errorMessage = tr("Selected asset is not a valid DEPIN asset");
        }
        return false;
    }

    const QStringList recipients = depinTransferRecipients();
    if (recipients.isEmpty()) {
        if (errorMessage) {
            *errorMessage = tr("At least one destination address is required");
        }
        return false;
    }

    if (depinTransferBatchCheckBox && depinTransferBatchCheckBox->isChecked() && recipients.size() > 20) {
        if (errorMessage) {
            *errorMessage = tr("Batch mode supports a maximum of 20 addresses");
        }
        return false;
    }

    for (const QString& recipient : recipients) {
        if (!model->validateAddress(recipient)) {
            if (errorMessage) {
                *errorMessage = tr("Invalid Neurai destination address: %1").arg(recipient);
            }
            return false;
        }
    }

    const CAmount requiredAmount = recipients.size() * COIN;
    std::string ownerAddress;
    CAmount ownerControlledAmount = 0;
    if (!getDepinOwnerControlledOutputs(qAssetName.toStdString(), ownerAddress, nullptr, &ownerControlledAmount) ||
        ownerControlledAmount < requiredAmount) {
        if (errorMessage) {
            *errorMessage = tr("Not enough owner-controlled %1 balance to send 1 unit to each destination").arg(qAssetName);
        }
        return false;
    }

    return true;
}

void RestrictedAssetsDialog::updateDepinCreateCoinControlState(CCoinControl& ctrl) const
{
    if (depinCreateCustomFeeRadio && depinCreateCustomFeeRadio->isChecked() && depinCreateCustomFee) {
        ctrl.m_feerate = CFeeRate(depinCreateCustomFee->value());
    } else {
        ctrl.m_feerate.reset();
    }

    if (depinCreateConfTargetSelector) {
        ctrl.m_confirm_target = getConfTargetForIndex(depinCreateConfTargetSelector->currentIndex());
    }

    ctrl.destChange = CNoDestination();
    if (depinCreateChangeAddressCheckBox && depinCreateChangeAddressCheckBox->isChecked() && depinCreateChangeAddressEdit) {
        const CTxDestination dest = DecodeDestination(depinCreateChangeAddressEdit->text().toStdString());
        if (IsValidDestination(dest)) {
            ctrl.destChange = dest;
        }
    }
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

    if (model && model->getOptionsModel() && depinCreateCustomFee) {
        depinCreateCustomFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        updateDepinCreateMinFeeLabel();
        updateDepinCreateSmartFeeLabel();
    }
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
