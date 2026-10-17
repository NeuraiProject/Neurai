// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "neuraiunits.h"
#include "guiutil.h"
#include "guitheme.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "guiconstants.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveCoinsDialog),
    model(0),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
    ui->receiveButton->setProperty("primary", true);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->clearButton->setIcon(QIcon());
        ui->receiveButton->setIcon(QIcon());
        ui->showRequestButton->setIcon(QIcon());
        ui->removeRequestButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->receiveButton->setIcon(_platformStyle->SingleColorIcon(":/icons/receiving_addresses"));
        ui->showRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/edit"));
        ui->removeRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
    }

    // context menu actions
    QAction *copyURIAction = new QAction(tr("Copy URI"), this);
    QAction *copyLabelAction = new QAction(tr("Copy label"), this);
    QAction *copyMessageAction = new QAction(tr("Copy message"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyURIAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // context menu signals
    connect(ui->recentRequestsView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    connect(copyURIAction, SIGNAL(triggered()), this, SLOT(copyURI()));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(copyLabel()));
    connect(copyMessageAction, SIGNAL(triggered()), this, SLOT(copyMessage()));
    connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));

    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    setupRequestFrame(platformStyle);
    setupHistoryFrame(platformStyle);
    setupSilentCodeFrame();
}

void ReceiveCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        _model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(_model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();

        QTableView* tableView = ui->recentRequestsView;

        tableView->verticalHeader()->hide();
        tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setModel(_model->getRecentRequestsTableModel());
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);

        connect(tableView->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this,
            SLOT(recentRequestsView_selectionChanged(QItemSelection, QItemSelection)));

        tableView->show();
    }
    // NIP-047: only wallets with a silent payment identity have a code. The
    // card says whether the code was checked against the seed, which changes
    // with the lock state.
    ui->silentCodeButton->setVisible(_model && _model->hasSilentPaymentIdentity());
    if (_model)
        connect(_model, SIGNAL(encryptionStatusChanged(int)), this, SLOT(refreshSilentCodeFrame()));
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    ui->reqLabel->setText("");
    ui->reqMessage->setText("");
    ui->reuseAddress->setChecked(false);
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::setupRequestFrame(const PlatformStyle *platformStyle)
{
    /** Update the coincontrol frame */
    GUITheme::makeCard(ui->frame2, "padding: 6px;");
    /** Create the shadow effects on the frames */

    ui->frame2->setGraphicsEffect(GUIUtil::getShadowEffect());

    ui->label_5->setStyleSheet(STRING_LABEL_COLOR);

    ui->label_2->setStyleSheet(STRING_LABEL_COLOR);
    ui->label_2->setFont(GUIUtil::getSubLabelFont());

    ui->label->setStyleSheet(STRING_LABEL_COLOR);
    ui->label->setFont(GUIUtil::getSubLabelFont());

    ui->label_3->setStyleSheet(STRING_LABEL_COLOR);
    ui->label_3->setFont(GUIUtil::getSubLabelFont());

    ui->label_4->setStyleSheet(STRING_LABEL_COLOR);
    ui->label_4->setFont(GUIUtil::getSubLabelFont());

    ui->label_7->setStyleSheet(STRING_LABEL_COLOR);
    ui->label_7->setFont(GUIUtil::getSubLabelFont());

    ui->reuseAddress->setStyleSheet(QString(".QCheckBox{ %1; }").arg(STRING_LABEL_COLOR));
    ui->reqLabel->setFont(GUIUtil::getSubLabelFont());
    ui->reqAmount->setFont(GUIUtil::getSubLabelFont());
    ui->reqMessage->setFont(GUIUtil::getSubLabelFont());
    ui->receiveButton->setFont(GUIUtil::getSubLabelFont());
    ui->clearButton->setFont(GUIUtil::getSubLabelFont());
    ui->silentCodeButton->setFont(GUIUtil::getSubLabelFont());
    ui->recentRequestsView->setFont(GUIUtil::getSubLabelFont());
    ui->showRequestButton->setFont(GUIUtil::getSubLabelFont());
    ui->removeRequestButton->setFont(GUIUtil::getSubLabelFont());
    ui->label_5->setFont(GUIUtil::getSubLabelFont());

    ui->label_6->setFont(GUIUtil::getSubLabelFontBolded());
}

void ReceiveCoinsDialog::setupHistoryFrame(const PlatformStyle *platformStyle)
{
    /** Update the coincontrol frame */
    GUITheme::makeCard(ui->frame, "padding: 6px;");
    /** Create the shadow effects on the frames */

    ui->frame->setGraphicsEffect(GUIUtil::getShadowEffect());

    ui->label_6->setStyleSheet(STRING_LABEL_COLOR);

    contextMenu->setFont(GUIUtil::getSubLabelFont());

}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if(!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    QString address;
    QString label = ui->reqLabel->text();
    if(ui->reuseAddress->isChecked())
    {
        /* Choose existing receiving address */
        AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
        dlg.setModel(model->getAddressTableModel());
        if(dlg.exec())
        {
            address = dlg.getReturnValue();
            if(label.isEmpty()) /* If no label provided, use the previously used label */
            {
                label = model->getAddressTableModel()->labelForAddress(address);
            }
        } else {
            return;
        }
    } else {
        /* Generate new receiving address */
        address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "");
    }
    if (address.isEmpty()) {
        QMessageBox::warning(this, tr("Receive"), tr("Could not generate a receiving address. Check that the wallet is available and unlocked."));
        return;
    }
    SendCoinsRecipient info(address, label,
        ui->reqAmount->value(), ui->reqMessage->text());
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(info);
    dialog->show();
    clear();

    /* Store request for later reference */
    model->getRecentRequestsTableModel()->addNewRequest(info);
}

void ReceiveCoinsDialog::setupSilentCodeFrame()
{
    silentCodeFrame = new QFrame(this);
    silentCodeFrame->setObjectName("silentCodeFrame");
    QHBoxLayout* layout = new QHBoxLayout(silentCodeFrame);
    layout->setSpacing(16);

    silentCodeQR = new QRImageWidget(silentCodeFrame);
    silentCodeQR->setObjectName("silentCodeQR");
    silentCodeQR->setAlignment(Qt::AlignCenter);
    silentCodeQR->setToolTip(tr("Drag the image, or right-click to save or copy it."));
    layout->addWidget(silentCodeQR, 0, Qt::AlignTop);

    QVBoxLayout* info = new QVBoxLayout();
    QLabel* title = new QLabel(tr("Silent payment code"), silentCodeFrame);
    title->setFont(GUIUtil::getSubLabelFontBolded());
    title->setStyleSheet(STRING_LABEL_COLOR);
    info->addWidget(title);

    silentCodeStatus = new QLabel(silentCodeFrame);
    silentCodeStatus->setObjectName("silentCodeStatus");
    silentCodeStatus->setWordWrap(true);
    silentCodeStatus->setFont(GUIUtil::getSubLabelFont());
    silentCodeStatus->setStyleSheet(STRING_LABEL_COLOR);
    info->addWidget(silentCodeStatus);

    // The code has no spaces: a read-only text box wraps it anywhere and
    // copies it whole.
    silentCodeText = new QPlainTextEdit(silentCodeFrame);
    silentCodeText->setObjectName("silentCodeText");
    silentCodeText->setReadOnly(true);
    silentCodeText->setWordWrapMode(QTextOption::WrapAnywhere);
    silentCodeText->setFont(GUIUtil::fixedPitchFont());
    silentCodeText->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    silentCodeText->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    silentCodeText->setTabChangesFocus(true);
    silentCodeText->setFixedHeight(silentCodeText->fontMetrics().lineSpacing() * 3 + 12);
    info->addWidget(silentCodeText);

    QLabel* help = new QLabel(tr("Share this code instead of an address. It can be reused: every payment to it arrives at a new "
                                 "address that only this wallet links to the code. The sender needs a wallet that supports "
                                 "silent payments."), silentCodeFrame);
    help->setWordWrap(true);
    help->setFont(GUIUtil::getSubLabelFont());
    help->setStyleSheet(STRING_LABEL_COLOR);
    info->addWidget(help);

    QHBoxLayout* buttons = new QHBoxLayout();
    QPushButton* copyCode = new QPushButton(tr("Copy code"), silentCodeFrame);
    copyCode->setObjectName("silentCodeCopy");
    QPushButton* copyURI = new QPushButton(tr("Copy URI"), silentCodeFrame);
    QPushButton* saveImage = new QPushButton(tr("Save image..."), silentCodeFrame);
    for (QPushButton* button : {copyCode, copyURI, saveImage}) {
        button->setFont(GUIUtil::getSubLabelFont());
        button->setAutoDefault(false);
        buttons->addWidget(button);
    }
    buttons->addStretch();
    info->addLayout(buttons);
    info->addStretch();
    layout->addLayout(info, 1);

    connect(copyCode, &QPushButton::clicked, this, [this]() { GUIUtil::setClipboard(silentCode); });
    connect(copyURI, &QPushButton::clicked, this, [this]() { GUIUtil::setClipboard(silentCodeURI()); });
    connect(saveImage, &QPushButton::clicked, silentCodeQR, &QRImageWidget::saveImage);

    GUITheme::makeCard(silentCodeFrame, "padding: 6px;");
    silentCodeFrame->setGraphicsEffect(GUIUtil::getShadowEffect());
    ui->verticalLayout_5->insertWidget(ui->verticalLayout_5->indexOf(ui->frame2) + 1, silentCodeFrame);
    silentCodeFrame->hide();
    ui->silentCodeButton->setCheckable(true);
}

QString ReceiveCoinsDialog::silentCodeURI() const
{
    return GUIUtil::formatNeuraiURI(SendCoinsRecipient(silentCode, QString(), 0, QString()));
}

bool ReceiveCoinsDialog::fillSilentCodeFrame(bool warn)
{
    if (!model || !model->getOptionsModel())
        return false;
    QString code, error;
    bool ok = model->getSilentPaymentCode(code, error);
    if (!ok && warn && model->getEncryptionStatus() == WalletModel::Locked) {
        // 047c D8: the code is shown only once checked against the seed in
        // this session; an encrypted wallet asks for its passphrase once.
        WalletModel::UnlockContext ctx(model->requestUnlock());
        if (!ctx.isValid())
            return false;
        ok = model->getSilentPaymentCode(code, error);
    }
    if (!ok) {
        if (warn) {
            QMessageBox::warning(this, tr("Silent payment code"),
                tr("The silent payment code is not available: %1").arg(error));
        }
        return false;
    }
    silentCode = code;
    silentCodeText->setPlainText(code);
    silentCodeStatus->setText(tr("Checked against this wallet's seed."));
    QString qrError;
    const QImage image = MakeQRCodeImage(silentCodeURI(), code, qrError, 240);
    if (image.isNull()) {
        silentCodeQR->setText(qrError);
    } else {
        silentCodeQR->setPixmap(QPixmap::fromImage(image));
    }
    return true;
}

void ReceiveCoinsDialog::on_silentCodeButton_clicked()
{
    // The button is checkable: checked opens the card, unchecked closes it.
    const bool open = ui->silentCodeButton->isChecked() && fillSilentCodeFrame(true);
    ui->silentCodeButton->setChecked(open);
    ui->silentCodeButton->setText(open ? tr("Hide silent payment &code") : tr("Silent payment &code"));
    silentCodeFrame->setVisible(open);
}

void ReceiveCoinsDialog::refreshSilentCodeFrame()
{
    if (silentCodeFrame->isHidden())
        return;
    if (!fillSilentCodeFrame(false)) {
        ui->silentCodeButton->setChecked(false);
        on_silentCodeButton_clicked();
    }
}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex &index)
{
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(submodel->entry(index.row()).recipient);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    ui->showRequestButton->setEnabled(enable);
    ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_showRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

    for (const QModelIndex& index : selection) {
        on_recentRequestsView_doubleClicked(index);
    }
}

void ReceiveCoinsDialog::on_removeRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), selection.length(), firstIndex.parent());
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Return)
    {
        // press return -> submit form
        if (ui->reqLabel->hasFocus() || ui->reqAmount->hasFocus() || ui->reqMessage->hasFocus())
        {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

QModelIndex ReceiveCoinsDialog::selectedRow()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }
    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->data(firstIndex.model()->index(firstIndex.row(), column), Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint &point)
{
    if (!selectedRow().isValid()) {
        return;
    }
    contextMenu->exec(QCursor::pos());
}

// context menu action: copy URI
void ReceiveCoinsDialog::copyURI()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    const RecentRequestsTableModel * const submodel = model->getRecentRequestsTableModel();
    const QString uri = GUIUtil::formatNeuraiURI(submodel->entry(sel.row()).recipient);
    GUIUtil::setClipboard(uri);
}

// context menu action: copy label
void ReceiveCoinsDialog::copyLabel()
{
    copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    copyColumnToClipboard(RecentRequestsTableModel::Amount);
}
