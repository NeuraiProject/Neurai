// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "neuraiunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "assetfilterproxy.h"
#include "assettablemodel.h"
#include "walletmodel.h"
#include "assetrecord.h"
#include "assets/assets.h"

#include <QAbstractItemDelegate>
#include <QDateTime>
#include <QPainter>
#include <QDesktopServices>
#include <QMouseEvent>
#include <validation.h>
#include <utiltime.h>

#define DECORATION_SIZE 54
#define NUM_ITEMS 8

#include <QDebug>
#include <QTimer>
#include <QPainterPath>
#include <QGraphicsDropShadowEffect>
#include <QScrollBar>
#include <QUrl>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(NeuraiUnits::XNA),
        platformStyle(_platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);

        const GUITheme::Tokens& theme = GUITheme::tokens();
        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect.adjusted(4, 0, -4, 0);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QString assetName = index.data(TransactionTableModel::AssetNameRole).toString();

        // Tinted badge with the transaction type icon
        QColor accent = !confirmed ? theme.textMuted : (amount < 0 ? theme.error : theme.success);
        QColor badgeColor = accent;
        badgeColor.setAlpha(darkModeEnabled ? 60 : 36);
        const int badgeSize = 34;
        QRect badgeRect(mainRect.left(), mainRect.center().y() - badgeSize / 2 + 1, badgeSize, badgeSize);
        QPainterPath badge;
        badge.addRoundedRect(badgeRect, 8, 8);
        painter->fillPath(badge, badgeColor);
        platformStyle->SingleColorIcon(icon, accent).paint(painter, badgeRect.adjusted(7, 7, -7, -7));

        int xspace = badgeSize + 12;
        int ypad = 9;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect topRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect bottomRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);

        QString amountText = index.data(TransactionTableModel::FormattedAmountRole).toString();
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        else if (amount > 0)
        {
            amountText = QString("+") + amountText;
        }

        // First line: address or label on the left, amount on the right
        QFont titleFont = GUIUtil::getSubLabelFontBolded();
        painter->setFont(titleFont);
        int amountWidth = painter->fontMetrics().horizontalAdvance(amountText);
        GUIUtil::concatenate(painter, address, amountWidth, topRect.left(), topRect.right() - 12);
        painter->setPen(theme.text);
        QRect boundingRect;
        painter->drawText(topRect, Qt::AlignLeft|Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, topRect.top(), 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        painter->setPen(!confirmed ? theme.textMuted : (amount < 0 ? theme.error : theme.success));
        painter->drawText(topRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        // Second line: date on the left, asset name on the right
        QFont subFont = GUIUtil::getSubLabelFont();
        subFont.setPixelSize(12);
        painter->setFont(subFont);
        painter->setPen(theme.textMuted);
        QString dateText = GUIUtil::dateTimeStr(date);
        GUIUtil::concatenate(painter, assetName, painter->fontMetrics().horizontalAdvance(dateText), bottomRect.left(), bottomRect.right());
        painter->drawText(bottomRect, Qt::AlignLeft|Qt::AlignVCenter, dateText);
        painter->drawText(bottomRect, Qt::AlignRight|Qt::AlignVCenter, assetName);

        // Divider between rows
        if (index.row() + 1 < index.model()->rowCount()) {
            painter->setPen(theme.border);
            painter->drawLine(mainRect.left(), option.rect.bottom(), mainRect.right(), option.rect.bottom());
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};

class AssetViewDelegate : public QAbstractItemDelegate
{
Q_OBJECT
public:
    explicit AssetViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
            QAbstractItemDelegate(parent), unit(NeuraiUnits::XNA),
            platformStyle(_platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);

        const GUITheme::Tokens& theme = GUITheme::tokens();
        QPixmap ipfspixmap = qvariant_cast<QPixmap>(index.data(AssetTableModel::AssetIPFSHashDecorationRole));
        bool admin = index.data(AssetTableModel::AdministratorRole).toBool();
        QString name = index.data(AssetTableModel::AssetNameRole).toString();
        QString amountText = index.data(AssetTableModel::FormattedAmountRole).toString();
        bool fDepinAsset = IsAssetNameADEPIN(name.toStdString());

        QRect mainRect = option.rect.adjusted(4, 0, -12, 0);

        // Round badge with the first letter of the asset; the colour tells the asset kind
        QColor badgeText = fDepinAsset ? theme.success : (admin ? theme.primary : theme.textMuted);
        QColor badgeFill = badgeText;
        badgeFill.setAlpha(darkModeEnabled ? 60 : 30);
        const int badgeSize = 34;
        QRect badgeRect(mainRect.left(), mainRect.center().y() - badgeSize / 2 + 1, badgeSize, badgeSize);
        painter->setPen(Qt::NoPen);
        painter->setBrush(badgeFill);
        painter->drawEllipse(badgeRect);
        QFont badgeFont = GUIUtil::getSubLabelFontBolded();
        badgeFont.setPixelSize(14);
        painter->setFont(badgeFont);
        painter->setPen(badgeText);
        QString initial = name.left(1).toUpper();
        if (initial == "$" || initial == "#" || initial == "&")
            initial = name.mid(1, 1).toUpper();
        painter->drawText(badgeRect, Qt::AlignCenter, initial);

        int xspace = badgeSize + 12;
        int ypad = 8;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        int ipfsSpace = ipfspixmap.isNull() ? 0 : 24;
        QRect topRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace - ipfsSpace, halfheight);
        QRect bottomRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace - ipfsSpace, halfheight);

        if (ipfsSpace) {
            QRect ipfsLinkRect(mainRect.right() - 16, mainRect.center().y() - 8, 16, 16);
            painter->drawPixmap(ipfsLinkRect, ipfspixmap);
        }

        // Asset name and amount
        QFont nameFont = GUIUtil::getSubLabelFontBolded();
        nameFont.setPixelSize(14);
        painter->setFont(nameFont);
        int amountWidth = painter->fontMetrics().horizontalAdvance(amountText);
        GUIUtil::concatenate(painter, name, amountWidth, topRect.left(), topRect.right() - 12);
        painter->setPen(theme.text);
        painter->drawText(topRect, Qt::AlignLeft|Qt::AlignVCenter, name);
        painter->drawText(topRect.adjusted(0, 0, 0, halfheight), Qt::AlignRight|Qt::AlignVCenter, amountText);

        // Asset kind under the name
        QFont subFont = GUIUtil::getSubLabelFont();
        subFont.setPixelSize(12);
        painter->setFont(subFont);
        painter->setPen(theme.textMuted);
        QString subtitle = fDepinAsset ? tr("DePIN asset") : (admin ? tr("Administrator") : tr("Asset"));
        painter->drawText(bottomRect, Qt::AlignLeft|Qt::AlignVCenter, subtitle);

        // Divider between rows
        if (index.row() + 1 < index.model()->rowCount()) {
            painter->setPen(theme.border);
            painter->drawLine(mainRect.left(), option.rect.bottom(), option.rect.right() - 12, option.rect.bottom());
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(52, 52);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include "overviewpage.moc"
#include "neuraigui.h"
#include <QFontDatabase>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    currentBalance(-1),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    currentWatchOnlyBalance(-1),
    currentWatchUnconfBalance(-1),
    currentWatchImmatureBalance(-1),
    silentFrame(nullptr),
    silentTitle(nullptr),
    silentAvailable(nullptr),
    silentPending(nullptr),
    silentCount(nullptr),
    silentTotal(nullptr),
    txdelegate(new TxViewDelegate(platformStyle, this)),
    assetdelegate(new AssetViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = platformStyle->SingleColorIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64,64), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);
    ui->labelAssetStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(3 * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    /** Create the list of assets */
    ui->listAssets->setItemDelegate(assetdelegate);
    ui->listAssets->setIconSize(QSize(42, 42));
    ui->listAssets->setMinimumHeight(2 * 52);
    ui->listAssets->viewport()->setAutoFillBackground(false);

    // Delay before filtering assetes in ms
    static const int input_filter_delay = 200;

    QTimer *asset_typing_delay;
    asset_typing_delay = new QTimer(this);
    asset_typing_delay->setSingleShot(true);
    asset_typing_delay->setInterval(input_filter_delay);
    connect(ui->assetSearch, SIGNAL(textChanged(QString)), asset_typing_delay, SLOT(start()));
    connect(asset_typing_delay, SIGNAL(timeout()), this, SLOT(assetSearchChanged()));

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));
    ui->listAssets->viewport()->installEventFilter(this);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));
    connect(ui->labelAssetStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));
    connect(ui->labelTransactionsStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));

    /** Cards for the balance, asset and transaction sections */
    for (QFrame* card : {ui->frame, ui->assetFrame, ui->frame_2}) {
        GUITheme::makeCard(card, "padding: 8px 6px 4px 6px;");
        card->setGraphicsEffect(GUIUtil::getShadowEffect());
    }
    for (QListView* list : {ui->listTransactions, ui->listAssets}) {
        list->setStyleSheet(".QListView { border: none; background: transparent; }");
    }
    ui->line_3->hide();
    ui->verticalLayout_2->setSpacing(20);

    /** Quick actions under the balance, as in the web wallet */
    QPushButton* sendButton = new QPushButton(tr("Send"), ui->frame);
    sendButton->setProperty("primary", true);
    QPushButton* receiveButton = new QPushButton(tr("Receive"), ui->frame);
    QPushButton* createAssetButton = new QPushButton(tr("Create asset"), ui->frame);
    QHBoxLayout* quickActions = new QHBoxLayout();
    quickActions->setSpacing(8);
    quickActions->setContentsMargins(0, 4, 0, 6);
    quickActions->addWidget(sendButton);
    quickActions->addWidget(receiveButton);
    quickActions->addWidget(createAssetButton);
    quickActions->addStretch();
    ui->verticalLayout_4->addLayout(quickActions);
    connect(sendButton, &QPushButton::clicked, this, &OverviewPage::sendCoinsClicked);
    connect(receiveButton, &QPushButton::clicked, this, &OverviewPage::receiveCoinsClicked);
    connect(createAssetButton, &QPushButton::clicked, this, &OverviewPage::createAssetClicked);

    /** Update the labels colors */
    ui->assetBalanceLabel->setStyleSheet(STRING_LABEL_COLOR);
    ui->xnaBalancesLabel->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelBalanceText->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelPendingText->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelImmatureText->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelTotalText->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelSpendable->setStyleSheet(STRING_LABEL_COLOR);
    ui->labelWatchonly->setStyleSheet(STRING_LABEL_COLOR);
    ui->recentTransactionsLabel->setStyleSheet(STRING_LABEL_COLOR);

    /** Update the labels font */
    ui->xnaBalancesLabel->setFont(GUIUtil::getTopLabelFont());
    ui->assetBalanceLabel->setFont(GUIUtil::getTopLabelFont());
    ui->recentTransactionsLabel->setFont(GUIUtil::getTopLabelFont());

    /** Update the sub labels font */
    ui->labelBalanceText->setFont(GUIUtil::getSubLabelFont());
    ui->labelPendingText->setFont(GUIUtil::getSubLabelFont());
    ui->labelImmatureText->setFont(GUIUtil::getSubLabelFont());
    ui->labelSpendable->setFont(GUIUtil::getSubLabelFont());
    ui->labelWatchonly->setFont(GUIUtil::getSubLabelFont());
    ui->labelBalance->setFont(GUIUtil::getSubLabelFont());
    ui->labelUnconfirmed->setFont(GUIUtil::getSubLabelFont());
    ui->labelImmature->setFont(GUIUtil::getSubLabelFont());
    ui->labelWatchAvailable->setFont(GUIUtil::getSubLabelFont());
    ui->labelWatchPending->setFont(GUIUtil::getSubLabelFont());
    ui->labelWatchImmature->setFont(GUIUtil::getSubLabelFont());
    ui->labelTotalText->setFont(GUIUtil::getSubLabelFont());
    ui->labelTotal->setFont(GUIUtil::getTopLabelFont(QFont::Weight::Bold, 26));
    ui->labelWatchTotal->setFont(GUIUtil::getTopLabelFont(QFont::Weight::Bold, 26));

    /** Card for received silent payments (built after the fonts it copies) */
    setupSilentPaymentsCard();

    /** Create the search bar for assets */
    ui->assetSearch->setAttribute(Qt::WA_MacShowFocusRect, 0);
    ui->assetSearch->setAlignment(Qt::AlignVCenter);
    ui->assetSearch->setFont(GUIUtil::getSubLabelFont());

    // Trigger the call to show the assets table if assets are active
    showAssets();

    // context menu actions
    sendAction = new QAction(tr("Send Asset"), this);
    QAction *copyAmountAction = new QAction(tr("Copy Amount"), this);
    QAction *copyNameAction = new QAction(tr("Copy Name"), this);
    copyHashAction = new QAction(tr("Copy Hash"), this);
    issueSub = new QAction(tr("Issue Sub Asset"), this);
    issueUnique = new QAction(tr("Issue Unique Asset"), this);
    reissue = new QAction(tr("Reissue Asset"), this);
    openURL = new QAction(tr("Open IPFS in Browser"), this);

    sendAction->setObjectName("Send");
    issueSub->setObjectName("Sub");
    issueUnique->setObjectName("Unique");
    reissue->setObjectName("Reissue");
    copyNameAction->setObjectName("Copy Name");
    copyAmountAction->setObjectName("Copy Amount");
    copyHashAction->setObjectName("Copy Hash");
    openURL->setObjectName("Browse");

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(sendAction);
    contextMenu->addAction(issueSub);
    contextMenu->addAction(issueUnique);
    contextMenu->addAction(reissue);
    contextMenu->addSeparator();
    contextMenu->addAction(openURL);
    contextMenu->addAction(copyHashAction);
    contextMenu->addSeparator();
    contextMenu->addAction(copyNameAction);
    contextMenu->addAction(copyAmountAction);
    // context menu signals
}

bool OverviewPage::eventFilter(QObject *object, QEvent *event)
{
    // If the asset viewport is being clicked
    if (object == ui->listAssets->viewport() && event->type() == QEvent::MouseButtonPress) {

        // Grab the mouse event
        QMouseEvent * mouseEv = static_cast<QMouseEvent*>(event);

        // Select the current index at the mouse location
        QModelIndex currentIndex = ui->listAssets->indexAt(mouseEv->pos());

        // Open the menu on right click, direct url on left click
        if (mouseEv->buttons() & Qt::RightButton ) {
            handleAssetRightClicked(currentIndex);
        } else if (mouseEv->buttons() & Qt::LeftButton) {
            openIPFSForAsset(currentIndex);
        }
    }

    return QWidget::eventFilter(object, event);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::handleAssetRightClicked(const QModelIndex &index)
{
    if(assetFilter) {
        // Grab the data elements from the index that we need to disable and enable menu items
        QString name = index.data(AssetTableModel::AssetNameRole).toString();
        QString ipfshash = index.data(AssetTableModel::AssetIPFSHashRole).toString();
        QString ipfsbrowser = walletModel->getOptionsModel()->getIpfsUrl();

        if (IsAssetNameAnOwner(name.toStdString())) {
            name = name.left(name.size() - 1);
            sendAction->setDisabled(true);
        } else {
            sendAction->setDisabled(false);
        }

        // If the ipfs hash isn't there or doesn't start with Qm, disable the action item
        if (ipfshash.count() > 0 && ipfshash.indexOf("Qm") == 0 && ipfsbrowser.indexOf("http") == 0 ) {
            openURL->setDisabled(false);
        } else {
            openURL->setDisabled(true);
        }

        if (ipfshash.count() > 0) {
            copyHashAction->setDisabled(false);
        } else {
            copyHashAction->setDisabled(true);
        }

        if (!index.data(AssetTableModel::AdministratorRole).toBool()) {
            issueSub->setDisabled(true);
            issueUnique->setDisabled(true);
            reissue->setDisabled(true);
        } else {
            issueSub->setDisabled(false);
            issueUnique->setDisabled(false);
            reissue->setDisabled(true);
            CNewAsset asset;
            auto currentActiveAssetCache = GetCurrentAssetCache();
            if (currentActiveAssetCache && currentActiveAssetCache->GetAssetMetaDataIfExists(name.toStdString(), asset))
                if (asset.nReissuable)
                    reissue->setDisabled(false);

        }

        QAction* action = contextMenu->exec(QCursor::pos());

        if (action) {
            if (action->objectName() == "Send")
                Q_EMIT assetSendClicked(assetFilter->mapToSource(index));
            else if (action->objectName() == "Sub")
                Q_EMIT assetIssueSubClicked(assetFilter->mapToSource(index));
            else if (action->objectName() == "Unique")
                Q_EMIT assetIssueUniqueClicked(assetFilter->mapToSource(index));
            else if (action->objectName() == "Reissue")
                Q_EMIT assetReissueClicked(assetFilter->mapToSource(index));
            else if (action->objectName() == "Copy Name")
                GUIUtil::setClipboard(index.data(AssetTableModel::AssetNameRole).toString());
            else if (action->objectName() == "Copy Amount")
                GUIUtil::setClipboard(index.data(AssetTableModel::FormattedAmountRole).toString());
            else if (action->objectName() == "Copy Hash")
                GUIUtil::setClipboard(ipfshash);
            else if (action->objectName() == "Browse") {
                QDesktopServices::openUrl(QUrl::fromUserInput(ipfsbrowser.replace("%s", ipfshash)));
            }
        }
    }
}

void OverviewPage::handleOutOfSyncWarningClicks()
{
    Q_EMIT outOfSyncWarningClicked();
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(const CAmount& walletBalance, const CAmount& walletUnconfirmedBalance, const CAmount& immatureBalance, const CAmount& walletWatchOnlyBalance, const CAmount& walletWatchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = walletBalance;
    currentUnconfirmedBalance = walletUnconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = walletWatchOnlyBalance;
    currentWatchUnconfBalance = walletWatchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;

    // NIP-047: received silent payments have their own card; the XNA card
    // shows the other coins.
    CAmount silentAvailableAmount = 0, silentPendingAmount = 0;
    bool silentWatchOnly = false;
    int silentUnspent = 0;
    const bool hasSilent = walletModel->getSilentPaymentBalance(silentAvailableAmount, silentPendingAmount, silentWatchOnly, &silentUnspent);
    CAmount balance = currentBalance, unconfirmedBalance = currentUnconfirmedBalance;
    CAmount watchOnlyBalance = currentWatchOnlyBalance, watchUnconfBalance = currentWatchUnconfBalance;
    (silentWatchOnly ? watchOnlyBalance : balance) -= silentAvailableAmount;
    (silentWatchOnly ? watchUnconfBalance : unconfirmedBalance) -= silentPendingAmount;
    silentFrame->setVisible(hasSilent);
    silentTitle->setText(silentWatchOnly ? tr("Silent Payments (watch-only)") : tr("Silent Payments"));
    silentAvailable->setText(NeuraiUnits::formatWithUnit(unit, silentAvailableAmount, false, NeuraiUnits::separatorAlways));
    silentPending->setText(NeuraiUnits::formatWithUnit(unit, silentPendingAmount, false, NeuraiUnits::separatorAlways));
    silentCount->setText(QString::number(silentUnspent));
    const CAmount silentTotalAmount = silentAvailableAmount + silentPendingAmount;
    silentTotal->setText(NeuraiUnits::formatWithUnitTruncated(unit, silentTotalAmount, 2, NeuraiUnits::separatorAlways));
    silentTotal->setToolTip(NeuraiUnits::formatWithUnit(unit, silentTotalAmount, false, NeuraiUnits::separatorAlways));

    ui->labelBalance->setText(NeuraiUnits::formatWithUnit(unit, balance, false, NeuraiUnits::separatorAlways));
    ui->labelUnconfirmed->setText(NeuraiUnits::formatWithUnit(unit, unconfirmedBalance, false, NeuraiUnits::separatorAlways));
    ui->labelImmature->setText(NeuraiUnits::formatWithUnit(unit, immatureBalance, false, NeuraiUnits::separatorAlways));
    // The large total keeps two decimals so that it fits up to the maximum supply; the exact value is in the tooltip
    const CAmount total = balance + unconfirmedBalance + immatureBalance;
    ui->labelTotal->setText(NeuraiUnits::formatWithUnitTruncated(unit, total, 2, NeuraiUnits::separatorAlways));
    ui->labelTotal->setToolTip(NeuraiUnits::formatWithUnit(unit, total, false, NeuraiUnits::separatorAlways));
    ui->labelWatchAvailable->setText(NeuraiUnits::formatWithUnit(unit, watchOnlyBalance, false, NeuraiUnits::separatorAlways));
    ui->labelWatchPending->setText(NeuraiUnits::formatWithUnit(unit, watchUnconfBalance, false, NeuraiUnits::separatorAlways));
    ui->labelWatchImmature->setText(NeuraiUnits::formatWithUnit(unit, watchImmatureBalance, false, NeuraiUnits::separatorAlways));
    const CAmount watchTotal = watchOnlyBalance + watchUnconfBalance + watchImmatureBalance;
    ui->labelWatchTotal->setText(NeuraiUnits::formatWithUnitTruncated(unit, watchTotal, 2, NeuraiUnits::separatorAlways));
    ui->labelWatchTotal->setToolTip(NeuraiUnits::formatWithUnit(unit, watchTotal, false, NeuraiUnits::separatorAlways));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance
}

void OverviewPage::setupSilentPaymentsCard()
{
    silentFrame = new QFrame(this);
    silentFrame->setObjectName("silentPaymentsFrame");
    QVBoxLayout* layout = new QVBoxLayout(silentFrame);

    silentTitle = new QLabel(tr("Silent Payments"), silentFrame);
    silentTitle->setObjectName("silentPaymentsLabel");
    silentTitle->setFont(GUIUtil::getTopLabelFont());
    silentTitle->setStyleSheet(STRING_LABEL_COLOR);
    layout->addWidget(silentTitle);

    QFrame* line = new QFrame(silentFrame);
    line->setFrameShape(ui->line_2->frameShape());
    line->setFrameShadow(ui->line_2->frameShadow());
    line->setStyleSheet(ui->line_2->styleSheet());
    layout->addWidget(line);

    // Same grid as the XNA card: values next to their captions, a line and
    // the total underneath.
    QGridLayout* grid = new QGridLayout();
    grid->setSpacing(ui->gridLayout->spacing());
    grid->setContentsMargins(ui->gridLayout->contentsMargins());
    auto addRow = [&](int row, const QString& text, const QString& name) {
        QLabel* caption = new QLabel(text, silentFrame);
        caption->setFont(GUIUtil::getSubLabelFont());
        caption->setStyleSheet(STRING_LABEL_COLOR);
        QLabel* value = new QLabel(silentFrame);
        value->setObjectName(name);
        value->setFont(GUIUtil::getSubLabelFont());
        value->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        value->setCursor(Qt::IBeamCursor);
        grid->addWidget(caption, row, 0);
        grid->addWidget(value, row, 1);
        return value;
    };
    silentAvailable = addRow(0, tr("Available:"), "labelSilentAvailable");
    silentPending = addRow(1, tr("Pending:"), "labelSilentPending");
    silentCount = addRow(2, tr("Payments:"), "labelSilentCount");
    silentCount->setToolTip(tr("Received payments not spent yet. Each one is a separate coin."));
    QFrame* totalLine = new QFrame(silentFrame);
    totalLine->setFrameShape(ui->line->frameShape());
    totalLine->setFrameShadow(ui->line->frameShadow());
    totalLine->setStyleSheet(ui->line->styleSheet());
    grid->addWidget(totalLine, 3, 0, 1, 2);
    silentTotal = addRow(4, tr("Total:"), "labelSilentTotal");
    silentTotal->setFont(ui->labelTotal->font());
    grid->setColumnStretch(2, 1);
    layout->addLayout(grid);

    GUITheme::makeCard(silentFrame, "padding: 8px 6px 4px 6px;");
    silentFrame->setGraphicsEffect(GUIUtil::getShadowEffect());
    ui->verticalLayout_2->insertWidget(ui->verticalLayout_2->indexOf(ui->frame) + 1, silentFrame);
    silentFrame->hide();
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        assetFilter.reset(new AssetFilterProxy());
        assetFilter->setSourceModel(model->getAssetTableModel());
        assetFilter->sort(AssetTableModel::AssetNameRole, Qt::DescendingOrder);
        ui->listAssets->setModel(assetFilter.get());
        ui->listAssets->setAutoFillBackground(false);

        ui->assetVerticalSpaceWidget->setStyleSheet("background-color: transparent");
        ui->assetVerticalSpaceWidget2->setStyleSheet("background-color: transparent");


        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance(),
                   model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)), this, SLOT(setBalance(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
    }

    // update the display unit, to not use the default ("XNA")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if(currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance,
                       currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
    if (AreAssetsDeployed()) {
        ui->labelAssetStatus->setVisible(fShow);
    }
}

void OverviewPage::showAssets()
{
    if (AreAssetsDeployed()) {
        ui->assetFrame->show();
        ui->assetBalanceLabel->show();
        ui->labelAssetStatus->show();

        // Disable the vertical space so that listAssets goes to the bottom of the screen
        ui->assetVerticalSpaceWidget->hide();
        ui->assetVerticalSpaceWidget2->hide();
    } else {
        ui->assetFrame->hide();
        ui->assetBalanceLabel->hide();
        ui->labelAssetStatus->hide();

        // This keeps the XNA balance grid from expanding and looking terrible when asset balance is hidden
        ui->assetVerticalSpaceWidget->show();
        ui->assetVerticalSpaceWidget2->show();
    }
}

void OverviewPage::assetSearchChanged()
{
    if (!assetFilter)
        return;
    assetFilter->setAssetNameContains(ui->assetSearch->text());
}

void OverviewPage::openIPFSForAsset(const QModelIndex &index)
{
    // Get the ipfs hash of the asset clicked
    QString ipfshash = index.data(AssetTableModel::AssetIPFSHashRole).toString();
    QString ipfsbrowser = walletModel->getOptionsModel()->getIpfsUrl();

    // If the ipfs hash isn't there or doesn't start with Qm, disable the action item
    if (ipfshash.count() > 0 && ipfshash.indexOf("Qm") == 0 && ipfsbrowser.indexOf("http") == 0)
    {
        QUrl ipfsurl = QUrl::fromUserInput(ipfsbrowser.replace("%s", ipfshash));

        // Create the box with everything.
        if(QMessageBox::Yes == QMessageBox::question(this,
                                                        tr("Open IPFS content?"),
                                                        tr("Open the following IPFS content in your default browser?\n")
                                                        + ipfsurl.toString()
                                                    ))
        {
        QDesktopServices::openUrl(ipfsurl);
        }
    }
}
