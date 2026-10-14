// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/privacypage.h"

#include "qt/clientmodel.h"
#include "qt/guitheme.h"
#include "qt/guiutil.h"
#include "qt/neuraiunits.h"
#include "qt/optionsmodel.h"
#include "qt/platformstyle.h"
#include "qt/privacypoolmodel.h"
#include "qt/walletmodel.h"

#include "config/neurai-config.h" /* for USE_QRCODE */
#include "ui_interface.h"

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

#include <QButtonGroup>
#include <QComboBox>
#include <QFontMetrics>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QLinearGradient>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QResizeEvent>
#include <QTableWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>

namespace {

constexpr CAmount QUANTUM = 100 * COIN;
constexpr int QR_SIZE = 140;

/** QR of a private address drawn like NeuraiWallet's: high error correction, a
 *  navy gradient, rounded finder patterns and the Neurai logo in the middle. */
QPixmap AddressQr(const QString& text, int size, qreal dpr)
{
#ifdef USE_QRCODE
    QRcode* code = QRcode_encodeString(text.toUtf8().constData(), 0, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (!code) return QPixmap();
    const int n = code->width;
    std::vector<bool> dark(static_cast<size_t>(n) * n);
    for (size_t i = 0; i < dark.size(); ++i) dark[i] = code->data[i] & 1;
    QRcode_free(code);

    // Drawn in device pixels so that modules land on whole pixels and stay sharp.
    const int pixels = qRound(size * dpr);
    QImage image(pixels, pixels, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::white);
    QPainter painter(&image);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);

    // One quiet cell around the symbol; the logo clears an odd, centred square.
    const qreal cell = qreal(pixels) / (n + 2);
    const qreal logoSize = pixels * 0.3;
    int logoCells = static_cast<int>(std::ceil((logoSize + cell) / cell));
    if (logoCells % 2 == 0) ++logoCells;
    logoCells = std::min(logoCells, n);
    const int logoStart = (n - logoCells) / 2, logoEnd = logoStart + logoCells;
    const int finders[3][2] = {{0, 0}, {0, n - 7}, {n - 7, 0}};
    auto inFinder = [&](int r, int c) {
        for (const auto& f : finders) {
            if (r >= f[0] && r < f[0] + 7 && c >= f[1] && c < f[1] + 7) return true;
        }
        return false;
    };

    QLinearGradient gradient(0, 0, pixels, pixels);
    gradient.setColorAt(0, QColor("#0c2550"));
    gradient.setColorAt(1, QColor("#1e3a8a"));
    QPainterPath cells;
    cells.setFillRule(Qt::WindingFill);
    for (int r = 0; r < n; ++r) {
        for (int c = 0; c < n; ++c) {
            if (!dark[static_cast<size_t>(r) * n + c] || inFinder(r, c)) continue;
            if (r >= logoStart && r < logoEnd && c >= logoStart && c < logoEnd) continue;
            const int x0 = qRound((c + 1) * cell), y0 = qRound((r + 1) * cell);
            cells.addRect(x0, y0, qRound((c + 2) * cell) - x0, qRound((r + 2) * cell) - y0);
        }
    }
    painter.fillPath(cells, gradient);
    painter.setRenderHint(QPainter::Antialiasing);
    for (const auto& f : finders) {
        const qreal x = (f[1] + 1) * cell, y = (f[0] + 1) * cell;
        QPainterPath frame, hole, dot;
        frame.addRoundedRect(x, y, 7 * cell, 7 * cell, 2 * cell, 2 * cell);
        hole.addRoundedRect(x + cell, y + cell, 5 * cell, 5 * cell, 1.25 * cell, 1.25 * cell);
        dot.addRoundedRect(x + 2 * cell, y + 2 * cell, 3 * cell, 3 * cell, 0.9 * cell, 0.9 * cell);
        painter.fillPath(frame, gradient);
        painter.fillPath(hole, Qt::white);
        painter.fillPath(dot, gradient);
    }
    QPainterPath backdrop;
    backdrop.addRoundedRect((logoStart + 1) * cell, (logoStart + 1) * cell, logoCells * cell, logoCells * cell, 0.5 * cell, 0.5 * cell);
    painter.fillPath(backdrop, Qt::white);
    const QRectF logo(pixels / 2.0 - logoSize / 2, pixels / 2.0 - logoSize / 2, logoSize, logoSize);
    painter.drawImage(logo, QImage(":/icons/qr_logo"));
    painter.end();
    image.setDevicePixelRatio(dpr);
    return QPixmap::fromImage(image);
#else
    Q_UNUSED(text);
    Q_UNUSED(size);
    Q_UNUSED(dpr);
    return QPixmap();
#endif
}

QString Css(const QColor& color) { return color.name(); }

/** "0.0669 XNA" rather than "0.06690000 XNA". */
QString CompactXna(CAmount amount)
{
    QString text = NeuraiUnits::format(NeuraiUnits::XNA, amount, false, NeuraiUnits::separatorNever);
    while (text.contains('.') && (text.endsWith('0') || text.endsWith('.'))) text.chop(1);
    return text + " XNA";
}

/** An icon recoloured to one colour (the icons are drawn black). */
QIcon TintedIcon(const QString& file, const QColor& color)
{
    QImage image(file);
    image = image.convertToFormat(QImage::Format_ARGB32);
    for (int y = 0; y < image.height(); ++y) {
        QRgb* line = reinterpret_cast<QRgb*>(image.scanLine(y));
        for (int x = 0; x < image.width(); ++x) line[x] = qRgba(color.red(), color.green(), color.blue(), qAlpha(line[x]));
    }
    return QIcon(QPixmap::fromImage(image));
}

QLabel* Heading(const QString& text, int size = 14)
{
    QLabel* label = new QLabel(text);
    QFont font = label->font();
    font.setPixelSize(size);
    font.setBold(true);
    label->setFont(font);
    return label;
}

QLabel* Muted(const QString& text = QString())
{
    QLabel* label = new QLabel(text);
    label->setWordWrap(true);
    label->setStyleSheet(QString("color: %1;").arg(GUITheme::tokens().textMuted.name()));
    return label;
}

/** A card with the same border, radius and shadow as the other pages. */
QFrame* Card(QLayout* layout)
{
    QFrame* card = new QFrame;
    card->setLayout(layout);
    layout->setContentsMargins(18, 16, 18, 16);
    layout->setSpacing(10);
    GUITheme::makeCard(card);
    card->setGraphicsEffect(GUIUtil::getShadowEffect());
    return card;
}

QPushButton* Primary(const QString& text)
{
    QPushButton* button = new QPushButton(text);
    button->setProperty("primary", true);
    button->setAutoDefault(false);
    return button;
}

} // namespace

BalancedTextLabel::BalancedTextLabel(QWidget* parent) : QLabel(parent)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
}

void BalancedTextLabel::setFullText(const QString& text)
{
    if (text == m_full) return;
    m_full = text;
    relayout();
}

void BalancedTextLabel::fitTo(int width)
{
    if (width == m_available) return;
    m_available = width;
    relayout();
}

void BalancedTextLabel::relayout()
{
    const QFontMetrics metrics(font());
    const int width = std::max(1, m_available);
    const int length = m_full.size();
    int lines = 1;
    while (lines < length && metrics.horizontalAdvance(m_full.left((length + lines - 1) / lines)) > width) ++lines;
    // Same number of characters on every line (the last one is shorter only for odd lengths).
    const int perLine = std::max(1, (length + lines - 1) / lines);
    QStringList parts;
    for (int at = 0; at < length; at += perLine) parts << m_full.mid(at, perLine);
    const QString text = parts.join('\n');
    if (text != QLabel::text()) QLabel::setText(text);
    setFixedWidth(metrics.horizontalAdvance(m_full.left(perLine)) + 2);
}

PrivacyPage::PrivacyPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent), m_platformStyle(platformStyle)
{
    QVBoxLayout* page = new QVBoxLayout(this);
    page->setContentsMargins(30, 28, 30, 20);
    page->setSpacing(14);
    const GUITheme::Tokens& t = GUITheme::tokens();
    setStyleSheet(QString(
        "QPushButton[chip=\"true\"] { border-radius: 12px; padding: 4px 12px; min-height: 16px; max-height: 24px; background-color: %1;"
        " border: 1px solid %2; color: %3; font-weight: 500; }"
        "QPushButton[chip=\"true\"]:hover { border-color: %4; }"
        "QPushButton[chip=\"true\"]:checked { background-color: %5; border-color: %4; color: %4; font-weight: 600; }"
        "QPushButton[chip=\"true\"]:disabled { color: %6; }")
        .arg(Css(t.surface), Css(t.fieldBorder), Css(t.text), Css(t.primary), Css(t.accent), Css(t.textMuted)));

    // Title
    QHBoxLayout* titleRow = new QHBoxLayout;
    titleRow->addWidget(Heading(tr("Privacy pool"), 20));
    m_poolChip = Muted();
    m_poolChip->setWordWrap(false);
    titleRow->addWidget(m_poolChip);
    titleRow->addStretch();
    page->addLayout(titleRow);
    page->addWidget(Muted(tr("Deposit XNA into private notes, send them to other private addresses and withdraw them to any "
                             "address. Deposits and withdrawals show their amounts on chain; private transfers, which notes "
                             "are yours and your private balance do not.")));

    // Unavailable
    QVBoxLayout* unavailable = new QVBoxLayout;
    unavailable->addWidget(Heading(tr("Not available")));
    m_unavailableText = Muted();
    unavailable->addWidget(m_unavailableText);
    m_unavailableCard = Card(unavailable);
    page->addWidget(m_unavailableCard);

    // Open
    QVBoxLayout* open = new QVBoxLayout;
    open->addWidget(Heading(tr("Open your private wallet")));
    open->addWidget(Muted(tr("Your private wallet is derived from this wallet's recovery words, the same way NeuraiWallet "
                             "derives it, so both show the same notes. A ZK passphrase gives a separate private wallet; "
                             "leave it empty if you did not set one.")));
    QHBoxLayout* openRow = new QHBoxLayout;
    m_zkPassphrase = new QLineEdit;
    m_zkPassphrase->setEchoMode(QLineEdit::Password);
    m_zkPassphrase->setPlaceholderText(tr("ZK passphrase (optional)"));
    m_openButton = Primary(tr("Open private wallet"));
    openRow->addWidget(m_zkPassphrase, 1);
    openRow->addWidget(m_openButton);
    open->addLayout(openRow);
    m_openStatus = Muted();
    open->addWidget(m_openStatus);
    m_openCard = Card(open);
    page->addWidget(m_openCard);

    // Balance card and, beside it, a card with the QR of the private address
    m_balanceCard = new QWidget;
    QHBoxLayout* topRow = new QHBoxLayout(m_balanceCard);
    topRow->setContentsMargins(0, 0, 0, 0);
    topRow->setSpacing(14);
    QVBoxLayout* details = new QVBoxLayout;
    details->setSpacing(6);
    QHBoxLayout* balanceTitle = new QHBoxLayout;
    balanceTitle->addWidget(Muted(tr("Private balance")));
    balanceTitle->addStretch();
    m_closeButton = new QPushButton(tr("Close"));
    m_closeButton->setAutoDefault(false);
    m_closeButton->setToolTip(tr("Forget the private keys until the private wallet is opened again"));
    balanceTitle->addWidget(m_closeButton);
    details->addLayout(balanceTitle);
    m_balance = Heading(QString(), 24);
    details->addWidget(m_balance);
    m_spendable = Muted();
    details->addWidget(m_spendable);
    m_status = Muted();
    details->addWidget(m_status);
    details->addSpacing(6);
    details->addWidget(Muted(tr("Private receiving address")));
    // The address, and right after it a copy icon as tall as the address (one line or two).
    m_addressRow = new QWidget;
    QHBoxLayout* addressRow = new QHBoxLayout(m_addressRow);
    addressRow->setContentsMargins(0, 0, 0, 0);
    addressRow->setSpacing(10);
    m_address = new BalancedTextLabel;
    m_address->setFont(GUIUtil::fixedPitchFont());
    m_address->setTextInteractionFlags(Qt::TextSelectableByMouse);
    addressRow->addWidget(m_address);
    QPushButton* copyIcon = new QPushButton;
    m_copyIcon = copyIcon;
    copyIcon->setIcon(TintedIcon(":/icons/ui_copy", t.text));
    copyIcon->setIconSize(QSize(16, 16));
    copyIcon->setToolTip(tr("Copy the private receiving address"));
    copyIcon->setAutoDefault(false);
    copyIcon->setCursor(Qt::PointingHandCursor);
    copyIcon->setFixedWidth(36);
    copyIcon->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    copyIcon->setStyleSheet(QString("QPushButton { padding: 0px; min-height: 28px; border-radius: 8px; background-color: %1; border: 1px solid %2; }"
                                    "QPushButton:hover { border-color: %3; }")
                                .arg(Css(t.surfaceAlt), Css(t.fieldBorder), Css(t.primary)));
    addressRow->addWidget(copyIcon);
    addressRow->addStretch();
    m_addressRow->setMinimumWidth(160);
    m_addressRow->installEventFilter(this);
    details->addWidget(m_addressRow);
    details->addStretch();
    topRow->addWidget(Card(details), 1);

    QVBoxLayout* qrColumn = new QVBoxLayout;
    qrColumn->setSpacing(10);
    qrColumn->addStretch();
    m_qr = new QLabel;
    m_qr->setFixedSize(QR_SIZE, QR_SIZE);
    m_qr->setToolTip(tr("Scan to send private XNA to this wallet"));
    qrColumn->addWidget(m_qr, 0, Qt::AlignHCenter);
    QPushButton* copy = new QPushButton(tr("Copy"));
    copy->setAutoDefault(false);
    copy->setToolTip(tr("Copy the private receiving address"));
    qrColumn->addWidget(copy);
    qrColumn->addStretch();
    QFrame* qrCard = Card(qrColumn);
    qrCard->setFixedWidth(QR_SIZE + 36);
    topRow->addWidget(qrCard);
    page->addWidget(m_balanceCard);

    // Deposit and withdraw, side by side
    m_operations = new QWidget;
    QHBoxLayout* operations = new QHBoxLayout(m_operations);
    operations->setContentsMargins(0, 0, 0, 0);
    operations->setSpacing(14);

    QGridLayout* deposit = new QGridLayout;
    deposit->addWidget(Heading(tr("Deposit")), 0, 0, 1, 2);
    deposit->addWidget(Muted(tr("Multiples of 100 XNA, in two steps: the wallet sends itself one coin of exactly the amount "
                                "plus the pool fee, and once it confirms that coin moves into the pool.")), 1, 0, 1, 2);
    QHBoxLayout* steps = new QHBoxLayout;
    steps->setSpacing(8);
    for (int i = 0; i < 2; ++i) {
        m_stepDot[i] = new QLabel;
        m_stepDot[i]->setFixedSize(26, 26);
        m_stepDot[i]->setAlignment(Qt::AlignCenter);
        m_stepText[i] = new QLabel;
        m_stepText[i]->setTextFormat(Qt::RichText);
        steps->addWidget(m_stepDot[i]);
        steps->addWidget(m_stepText[i]);
        if (i == 0) {
            m_stepLine = new QFrame;
            m_stepLine->setFixedHeight(2);
            m_stepLine->setMinimumWidth(24);
            steps->addWidget(m_stepLine, 1);
        }
    }
    deposit->addLayout(steps, 2, 0, 1, 2);
    deposit->addWidget(new QLabel(tr("Amount (XNA)")), 3, 0);
    m_depositAmount = new QLineEdit;
    m_depositAmount->setPlaceholderText("100");
    deposit->addWidget(m_depositAmount, 3, 1);
    m_quickAmounts = makeChips(false);
    for (int value : {100, 200, 500}) addChip(m_quickAmounts, QString("%1 XNA").arg(value), value, false);
    deposit->addWidget(m_quickAmounts.widget, 4, 1);
    deposit->addWidget(new QLabel(tr("Pool fee")), 5, 0);
    m_depositFee = makeChips(true);
    deposit->addWidget(m_depositFee.widget, 5, 1);
    m_depositFeeHint = Muted();
    deposit->addWidget(m_depositFeeHint, 6, 1);
    m_fundingStatus = Muted();
    deposit->addWidget(m_fundingStatus, 7, 0, 1, 2);
    deposit->setRowStretch(8, 1);
    m_depositButton = Primary(tr("1/2 · Prepare funding coin"));
    deposit->addWidget(m_depositButton, 9, 0, 1, 2, Qt::AlignRight);
    deposit->setColumnStretch(1, 1);
    operations->addWidget(Card(deposit), 1);

    QGridLayout* withdraw = new QGridLayout;
    withdraw->addWidget(Heading(tr("Withdraw")), 0, 0, 1, 3);
    withdraw->addWidget(Muted(tr("Multiples of 100 XNA, the rest stays in a private change note. Below 100 XNA the whole "
                                 "note is withdrawn: amount plus fee must equal the note.")), 1, 0, 1, 3);
    withdraw->addWidget(new QLabel(tr("Note")), 2, 0);
    m_withdrawNote = new QComboBox;
    withdraw->addWidget(m_withdrawNote, 2, 1, 1, 2);
    withdraw->addWidget(new QLabel(tr("Amount (XNA)")), 3, 0);
    m_withdrawAmount = new QLineEdit;
    withdraw->addWidget(m_withdrawAmount, 3, 1);
    QPushButton* max = new QPushButton(tr("Max"));
    max->setAutoDefault(false);
    withdraw->addWidget(max, 3, 2);
    withdraw->addWidget(new QLabel(tr("To address")), 4, 0);
    m_withdrawAddress = new QLineEdit;
    m_withdrawAddress->setPlaceholderText(tr("Transparent XNA address"));
    withdraw->addWidget(m_withdrawAddress, 4, 1);
    QPushButton* own = new QPushButton(tr("My address"));
    own->setAutoDefault(false);
    own->setToolTip(tr("Use a new receiving address of this wallet"));
    withdraw->addWidget(own, 4, 2);
    withdraw->addWidget(new QLabel(tr("Pool fee")), 5, 0);
    m_withdrawFee = makeChips(true);
    withdraw->addWidget(m_withdrawFee.widget, 5, 1, 1, 2);
    m_withdrawFeeHint = Muted();
    withdraw->addWidget(m_withdrawFeeHint, 6, 1, 1, 2);
    withdraw->setRowStretch(7, 1);
    m_withdrawButton = Primary(tr("Withdraw"));
    withdraw->addWidget(m_withdrawButton, 8, 0, 1, 3, Qt::AlignRight);
    withdraw->setColumnStretch(1, 1);
    operations->addWidget(Card(withdraw), 1);
    page->addWidget(m_operations);

    // Private transfer
    QVBoxLayout* transfer = new QVBoxLayout;
    transfer->addWidget(Heading(tr("Private transfer")));
    transfer->addWidget(Muted(tr("Send part of a note to private (tnzk…) addresses, such as the receiving address of another "
                                 "Neurai wallet. Each amount is a multiple of 100 XNA; the rest of the note, minus the pool "
                                 "fee, comes back to you as a new private note. At most three outputs, change included.")));
    QHBoxLayout* noteRow = new QHBoxLayout;
    noteRow->addWidget(new QLabel(tr("Note")));
    m_transferNote = new QComboBox;
    noteRow->addWidget(m_transferNote, 1);
    noteRow->addSpacing(12);
    noteRow->addWidget(new QLabel(tr("Pool fee")));
    m_transferFee = makeChips(true);
    noteRow->addWidget(m_transferFee.widget);
    transfer->addLayout(noteRow);
    m_transferFeeHint = Muted();
    m_transferFeeHint->setAlignment(Qt::AlignRight);
    transfer->addWidget(m_transferFeeHint);
    m_recipientLayout = new QVBoxLayout;
    m_recipientLayout->setSpacing(8);
    transfer->addLayout(m_recipientLayout);
    QHBoxLayout* transferActions = new QHBoxLayout;
    m_addRecipient = new QPushButton(tr("Add recipient"));
    m_addRecipient->setAutoDefault(false);
    transferActions->addWidget(m_addRecipient);
    m_transferSummary = Muted();
    transferActions->addWidget(m_transferSummary, 1);
    m_transferButton = Primary(tr("Send privately"));
    transferActions->addWidget(m_transferButton);
    transfer->addLayout(transferActions);
    m_transferCard = Card(transfer);
    page->addWidget(m_transferCard);
    addRecipient();

    // Notes
    QVBoxLayout* notes = new QVBoxLayout;
    notes->addWidget(Heading(tr("Private notes")));
    m_notes = new QTableWidget(0, 4);
    m_notes->setHorizontalHeaderLabels({tr("Note"), tr("Amount"), tr("Status"), tr("Block")});
    m_notes->verticalHeader()->setVisible(false);
    m_notes->horizontalHeader()->setStretchLastSection(true);
    m_notes->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_notes->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_notes->setSelectionMode(QAbstractItemView::NoSelection);
    m_notes->setFocusPolicy(Qt::NoFocus);
    m_notes->setShowGrid(false);
    m_notes->setMinimumHeight(140);
    notes->addWidget(m_notes);
    m_notesCard = Card(notes);
    page->addWidget(m_notesCard);
    page->addStretch();

    connect(m_openButton, &QPushButton::clicked, this, &PrivacyPage::openClicked);
    connect(m_zkPassphrase, &QLineEdit::returnPressed, this, &PrivacyPage::openClicked);
    connect(m_closeButton, &QPushButton::clicked, this, [this] { if (m_pool) m_pool->close(); });
    connect(copy, &QPushButton::clicked, this, &PrivacyPage::copyAddressClicked);
    connect(copyIcon, &QPushButton::clicked, this, &PrivacyPage::copyAddressClicked);
    connect(m_depositButton, &QPushButton::clicked, this, &PrivacyPage::depositClicked);
    connect(m_withdrawButton, &QPushButton::clicked, this, &PrivacyPage::withdrawClicked);
    connect(max, &QPushButton::clicked, this, &PrivacyPage::maxClicked);
    connect(own, &QPushButton::clicked, this, &PrivacyPage::ownAddressClicked);
    connect(m_depositAmount, &QLineEdit::textChanged, this, &PrivacyPage::updateFunding);
    connect(m_addRecipient, &QPushButton::clicked, this, &PrivacyPage::addRecipient);
    connect(m_transferButton, &QPushButton::clicked, this, &PrivacyPage::transferClicked);
    connect(m_transferNote, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &PrivacyPage::updateTransfer);
    connect(m_transferFee.group, &QButtonGroup::buttonToggled, this, [this](QAbstractButton*, bool checked) { if (checked) updateTransfer(); });
    connect(m_depositFee.group, &QButtonGroup::buttonToggled, this, [this](QAbstractButton*, bool checked) { if (checked) updateFunding(); });
    connect(m_quickAmounts.group, &QButtonGroup::buttonClicked, this, [this](QAbstractButton* button) {
        m_depositAmount->setText(QString::number(button->property("value").toLongLong()));
    });
    connect(m_depositAmount, &QLineEdit::textChanged, this, [this](const QString& text) {
        for (QAbstractButton* chip : m_quickAmounts.group->buttons()) {
            chip->setChecked(text.trimmed() == QString::number(chip->property("value").toLongLong()));
        }
    });

    setDepositStep(1, false);
    updateView();
}

bool PrivacyPage::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_addressRow && event->type() == QEvent::Resize) fitAddress();
    return QWidget::eventFilter(watched, event);
}

void PrivacyPage::fitAddress()
{
    const int spacing = m_addressRow->layout()->spacing();
    m_address->fitTo(m_addressRow->width() - m_copyIcon->width() - spacing);
}

void PrivacyPage::setClientModel(ClientModel* clientModel)
{
    m_clientModel = clientModel;
    if (m_pool) m_pool->setClientModel(clientModel);
    if (clientModel) {
        connect(clientModel, &ClientModel::numBlocksChanged, this,
                [this](int, const QDateTime&, double, bool header) { if (!header) updateFunding(); });
    }
}

void PrivacyPage::setWalletModel(WalletModel* walletModel)
{
    m_walletModel = walletModel;
    if (!walletModel) return;
    m_pool = new PrivacyPoolModel(walletModel, this);
    if (m_clientModel) m_pool->setClientModel(m_clientModel);
    connect(m_pool, &PrivacyPoolModel::changed, this, &PrivacyPage::updateView);
    connect(m_pool, &PrivacyPoolModel::operationFinished, this, &PrivacyPage::operationFinished);
    fillFees(m_depositFee);
    fillFees(m_withdrawFee);
    fillFees(m_transferFee);
    updateView();
    updateFunding();
}

QString PrivacyPage::formatAmount(CAmount amount) const
{
    const int unit = m_walletModel ? m_walletModel->getOptionsModel()->getDisplayUnit() : NeuraiUnits::XNA;
    return NeuraiUnits::formatWithUnit(unit, amount, false, NeuraiUnits::separatorAlways);
}

bool PrivacyPage::parseAmount(const QLineEdit* field, CAmount& amount) const
{
    return NeuraiUnits::parse(NeuraiUnits::XNA, field->text().trimmed(), &amount) && amount > 0;
}

PrivacyPage::Chips PrivacyPage::makeChips(bool exclusive)
{
    Chips chips;
    chips.widget = new QWidget;
    QHBoxLayout* layout = new QHBoxLayout(chips.widget);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    layout->addStretch();
    chips.group = new QButtonGroup(chips.widget);
    chips.group->setExclusive(exclusive);
    return chips;
}

void PrivacyPage::addChip(Chips& chips, const QString& text, qlonglong value, bool checked)
{
    QPushButton* chip = new QPushButton(text);
    chip->setProperty("chip", true);
    chip->setProperty("value", value);
    chip->setCheckable(true);
    chip->setAutoDefault(false);
    chip->setCursor(Qt::PointingHandCursor);
    QHBoxLayout* layout = static_cast<QHBoxLayout*>(chips.widget->layout());
    layout->insertWidget(layout->count() - 1, chip);
    chips.group->addButton(chip);
    chip->setChecked(checked);
}

CAmount PrivacyPage::selectedFee(const Chips& chips) const
{
    const QAbstractButton* chip = chips.group->checkedButton();
    return chip ? chip->property("value").toLongLong() : 0;
}

void PrivacyPage::fillFees(Chips& chips)
{
    if (!m_pool || !chips.group->buttons().isEmpty()) return;
    const QList<CAmount> levels = m_pool->feeLevels("D");
    for (int i = 0; i < levels.size(); ++i) {
        QString text = NeuraiUnits::format(NeuraiUnits::XNA, levels[i], false, NeuraiUnits::separatorNever);
        while (text.contains('.') && (text.endsWith('0') || text.endsWith('.'))) text.chop(1);
        addChip(chips, text + " XNA", levels[i], i == 0);
    }
}

void PrivacyPage::setDepositStep(int step, bool waiting)
{
    const GUITheme::Tokens& t = GUITheme::tokens();
    const QString base = "border-radius: 13px; font-weight: 700;";
    const QString active = QString("background-color: %1; color: %2; border: 1px solid %1;").arg(Css(t.primary), Css(t.primaryText));
    const QString pending = QString("background-color: %1; color: %2; border: 2px solid %3;").arg(Css(t.accent), Css(t.primary), Css(t.primary));
    const QString done = QString("background-color: %1; color: white; border: 1px solid %1;").arg(Css(t.success));
    const QString todo = QString("background-color: %1; color: %2; border: 1px solid %3;").arg(Css(t.surfaceAlt), Css(t.textMuted), Css(t.fieldBorder));
    const QString muted = Css(t.textMuted);
    auto text = [&](const QString& title, const QString& detail, bool current) {
        return QString("<span style='font-weight:%1;'>%2</span><br><span style='color:%3;'>%4</span>")
            .arg(current ? "700" : "600", title.toHtmlEscaped(), muted, detail.toHtmlEscaped());
    };
    if (step <= 1) {
        m_stepDot[0]->setText("1");
        m_stepDot[0]->setStyleSheet(base + (waiting ? pending : active));
        m_stepText[0]->setText(text(tr("Funding coin"), waiting ? tr("Waiting for confirmation…") : tr("Amount + fee, to yourself"), true));
        m_stepDot[1]->setStyleSheet(base + todo);
    } else {
        m_stepDot[0]->setText(QString::fromUtf8("\u2713"));
        m_stepDot[0]->setStyleSheet(base + done);
        m_stepText[0]->setText(text(tr("Funding coin"), tr("Confirmed"), false));
        m_stepDot[1]->setStyleSheet(base + active);
    }
    m_stepDot[1]->setText("2");
    m_stepText[1]->setText(text(tr("Deposit"), tr("Proof and pool transaction"), step >= 2));
    m_stepLine->setStyleSheet(QString("background-color: %1; border: none;").arg(Css(step >= 2 ? t.success : t.border)));
}

void PrivacyPage::updateQr(const QString& address)
{
    if (address == m_qrAddress) return;
    m_qrAddress = address;
    const QPixmap qr = address.isEmpty() ? QPixmap() : AddressQr(address, QR_SIZE, devicePixelRatioF());
    m_qr->setPixmap(qr);
    m_qr->setVisible(!qr.isNull());
}

void PrivacyPage::updateView()
{
    using State = PrivacyPoolModel::State;
    const State state = m_pool ? m_pool->state() : State::Unavailable;
    const bool busy = m_pool && m_pool->busy();
    m_poolChip->setText(m_pool && !m_pool->poolName().isEmpty() ? tr("C6 XNA · %1 · testnet").arg(m_pool->poolName()) : QString());
    m_unavailableCard->setVisible(state == State::Unavailable);
    m_unavailableText->setText(m_pool ? m_pool->unavailableReason() : tr("Open a wallet first."));
    m_openCard->setVisible(state == State::Closed || state == State::Opening);
    m_openButton->setEnabled(state == State::Closed && !busy);
    m_openButton->setText(state == State::Opening ? tr("Opening…") : tr("Open private wallet"));
    const bool ready = state == State::Ready;
    m_balanceCard->setVisible(ready);
    m_operations->setVisible(ready);
    m_transferCard->setVisible(ready);
    m_notesCard->setVisible(ready);
    if (!m_pool) return;

    const QString activity = m_pool->activity();
    m_openStatus->setText(state == State::Opening ? activity : QString());
    m_openStatus->setVisible(state == State::Opening);
    if (!ready) return;

    const PrivacySnapshot& snapshot = m_pool->snapshot();
    m_balance->setText(formatAmount(snapshot.balance));
    const int count = snapshot.notes.size();
    m_spendable->setText(tr("Spendable now: %1 · %2").arg(formatAmount(snapshot.spendable),
                                                         count == 1 ? tr("1 note") : tr("%1 notes").arg(count)));
    QString status = activity;
    if (status.isEmpty()) {
        status = snapshot.height >= 0 ? tr("Scanned up to block %1 · pool reserve %2").arg(snapshot.height).arg(formatAmount(snapshot.poolReserve))
                                      : tr("Not scanned yet");
        if (!snapshot.pending.isEmpty()) {
            status += " · " + (snapshot.pending.size() == 1 ? tr("1 operation waiting for confirmation")
                                                            : tr("%1 operations waiting for confirmation").arg(snapshot.pending.size()));
        }
    }
    m_status->setText(status);
    m_address->setFullText(snapshot.receiveAddress);
    fitAddress();
    updateQr(snapshot.receiveAddress);
    m_closeButton->setEnabled(!busy);
    m_depositButton->setEnabled(!busy && m_depositEnabled);
    m_withdrawButton->setEnabled(!busy);
    m_transferButton->setEnabled(!busy);

    // Notes table and the notes that withdrawals and transfers can spend
    const quint32 selected = m_withdrawNote->currentData().toUInt();
    const QVariant transferSelected = m_transferNote->currentData();
    m_withdrawNote->clear();
    m_transferNote->blockSignals(true);
    m_transferNote->clear();
    m_notes->setRowCount(snapshot.notes.size());
    for (int row = 0; row < snapshot.notes.size(); ++row) {
        const PrivacyNoteRow& note = snapshot.notes[row];
        const QString state = note.reserved ? tr("Spend pending") : note.spendable ? tr("Spendable") : tr("Confirming");
        const QStringList cells = {QString("#%1").arg(note.index), formatAmount(note.amount), state, QString::number(note.height)};
        for (int column = 0; column < cells.size(); ++column) {
            QTableWidgetItem* item = new QTableWidgetItem(cells[column]);
            item->setTextAlignment(column == 1 ? Qt::AlignRight | Qt::AlignVCenter : Qt::AlignLeft | Qt::AlignVCenter);
            m_notes->setItem(row, column, item);
        }
        if (note.spendable) {
            const QString label = tr("#%1 · %2").arg(note.index).arg(formatAmount(note.amount));
            m_withdrawNote->addItem(label, note.index);
            if (note.index == selected) m_withdrawNote->setCurrentIndex(m_withdrawNote->count() - 1);
            m_transferNote->addItem(label, note.index);
            if (transferSelected.isValid() && note.index == transferSelected.toUInt()) m_transferNote->setCurrentIndex(m_transferNote->count() - 1);
        }
    }
    if (m_withdrawNote->count() == 0) m_withdrawNote->addItem(tr("No spendable notes"));
    m_withdrawNote->setEnabled(m_withdrawNote->currentData().isValid());
    if (m_transferNote->count() == 0) m_transferNote->addItem(tr("No spendable notes"));
    m_transferNote->setEnabled(m_transferNote->currentData().isValid());
    m_transferNote->blockSignals(false);
    updateFeeLevels(m_withdrawFee, m_withdrawFeeHint, "W");
    updateTransfer();
    updateFunding();
}

void PrivacyPage::updateFeeLevels(Chips& chips, QLabel* hint, const QString& operation)
{
    if (!m_pool || m_pool->state() != PrivacyPoolModel::State::Ready) return;
    // Rounded up to 0.0001 XNA, which is also how it is shown.
    const CAmount step = 10000;
    const CAmount needed = (m_pool->requiredPoolFee(operation) + step - 1) / step * step;
    QAbstractButton* cheapest = nullptr;
    // Chips are in ascending order of fee.
    for (QAbstractButton* chip : chips.group->buttons()) {
        const bool enough = chip->property("value").toLongLong() >= needed;
        chip->setEnabled(enough);
        chip->setToolTip(enough ? QString() : tr("Below the network fee the node asks for now (%1)").arg(CompactXna(needed)));
        if (enough && !cheapest) cheapest = chip;
    }
    QAbstractButton* current = chips.group->checkedButton();
    if (cheapest && (!current || !current->isEnabled())) cheapest->setChecked(true);
    hint->setText(cheapest ? tr("Network fee now about %1 (10% margin included)").arg(CompactXna(needed))
                           : tr("The network asks for about %1, more than the highest pool fee: wait for less congestion.").arg(CompactXna(needed)));
}

void PrivacyPage::updateFunding()
{
    if (!m_pool || m_pool->state() != PrivacyPoolModel::State::Ready) return;
    updateFeeLevels(m_depositFee, m_depositFeeHint, "D");
    const bool busy = m_pool->busy();
    auto show = [&](int step, bool waiting, const QString& button, const QString& status, bool enabled) {
        setDepositStep(step, waiting);
        m_depositButton->setText(button);
        m_fundingStatus->setText(status);
        m_depositEnabled = enabled;
        m_depositButton->setEnabled(enabled && !busy);
    };
    const QString prepare = tr("1/2 · Prepare funding coin");
    CAmount amount;
    if (!parseAmount(m_depositAmount, amount)) {
        show(1, false, prepare, QString(), false);
        return;
    }
    if (amount % QUANTUM) {
        show(1, false, prepare, tr("Use multiples of 100 XNA."), false);
        return;
    }
    const CAmount value = amount + selectedFee(m_depositFee);
    switch (m_pool->fundingState(value)) {
    case PrivacyPoolModel::Funding::Ready:
        show(2, false, tr("2/2 · Deposit"), tr("Funding coin of %1 confirmed: ready to deposit.").arg(formatAmount(value)), true);
        break;
    case PrivacyPoolModel::Funding::Unconfirmed:
        show(1, true, tr("Waiting for confirmation…"),
             tr("Funding coin of %1 sent. The deposit continues after one confirmation.").arg(formatAmount(value)), false);
        break;
    case PrivacyPoolModel::Funding::None:
        show(1, false, prepare, tr("The wallet will send %1 to one of its own addresses.").arg(formatAmount(value)), true);
        break;
    }
}

void PrivacyPage::openClicked()
{
    if (m_pool) m_pool->open(m_zkPassphrase->text());
    m_zkPassphrase->clear();
}

void PrivacyPage::depositClicked()
{
    if (!m_pool) return;
    CAmount amount;
    if (!parseAmount(m_depositAmount, amount) || amount % QUANTUM) {
        Q_EMIT message(tr("Deposit"), tr("Enter an amount that is a multiple of 100 XNA."), CClientUIInterface::MSG_WARNING);
        return;
    }
    const CAmount fee = selectedFee(m_depositFee);
    switch (m_pool->fundingState(amount + fee)) {
    case PrivacyPoolModel::Funding::None: {
        if (QMessageBox::question(this, tr("Prepare funding"),
                tr("The wallet will send %1 (deposit %2 + pool fee %3) to one of its own addresses, plus a network fee of "
                   "about %4 (the node's fee rate + 10%). When that coin has one confirmation, press Deposit again to move it "
                   "into the pool.")
                    .arg(formatAmount(amount + fee), formatAmount(amount), formatAmount(fee),
                         CompactXna(m_pool->networkFeeRate().GetFee(250))),
                QMessageBox::Ok | QMessageBox::Cancel) != QMessageBox::Ok) {
            return;
        }
        QString error;
        if (m_pool->prepareFunding(amount, fee, error)) {
            Q_EMIT message(tr("Deposit"), tr("Funding coin sent. Press Deposit again after it confirms."), CClientUIInterface::MSG_INFORMATION);
        } else {
            Q_EMIT message(tr("Deposit"), error, CClientUIInterface::MSG_ERROR);
        }
        updateFunding();
        return;
    }
    case PrivacyPoolModel::Funding::Unconfirmed:
        Q_EMIT message(tr("Deposit"), tr("The funding coin needs one confirmation first."), CClientUIInterface::MSG_WARNING);
        return;
    case PrivacyPoolModel::Funding::Ready:
        break;
    }
    if (QMessageBox::question(this, tr("Confirm deposit"),
            tr("Deposit %1 into the privacy pool? The pool fee is %2. The proof is computed on this computer and the "
               "transaction is checked by the node before it is broadcast.").arg(formatAmount(amount), formatAmount(fee)),
            QMessageBox::Ok | QMessageBox::Cancel) != QMessageBox::Ok) {
        return;
    }
    m_pool->deposit(amount, fee);
}

void PrivacyPage::withdrawClicked()
{
    if (!m_pool) return;
    const QVariant noteData = m_withdrawNote->currentData();
    if (!noteData.isValid()) {
        Q_EMIT message(tr("Withdraw"), tr("There is no spendable note."), CClientUIInterface::MSG_WARNING);
        return;
    }
    const quint32 index = noteData.toUInt();
    CAmount noteAmount = 0;
    for (const PrivacyNoteRow& note : m_pool->snapshot().notes) {
        if (note.index == index) noteAmount = note.amount;
    }
    CAmount amount;
    const CAmount fee = selectedFee(m_withdrawFee);
    if (!parseAmount(m_withdrawAmount, amount)) {
        Q_EMIT message(tr("Withdraw"), tr("Enter the amount to withdraw."), CClientUIInterface::MSG_WARNING);
        return;
    }
    if (amount + fee > noteAmount) {
        Q_EMIT message(tr("Withdraw"), tr("Amount plus fee exceeds the note (%1).").arg(formatAmount(noteAmount)), CClientUIInterface::MSG_WARNING);
        return;
    }
    if (amount >= QUANTUM ? amount % QUANTUM != 0 : amount + fee != noteAmount) {
        Q_EMIT message(tr("Withdraw"), tr("Withdraw a multiple of 100 XNA, or below 100 XNA the whole note: amount plus fee equal to %1.")
                                           .arg(formatAmount(noteAmount)), CClientUIInterface::MSG_WARNING);
        return;
    }
    const QString address = m_withdrawAddress->text().trimmed();
    if (address.isEmpty() || !m_walletModel->validateAddress(address)) {
        Q_EMIT message(tr("Withdraw"), tr("Enter a valid destination address."), CClientUIInterface::MSG_WARNING);
        return;
    }
    const CAmount change = noteAmount - amount - fee;
    if (QMessageBox::question(this, tr("Confirm withdrawal"),
            tr("Withdraw %1 from note #%2 to %3? Pool fee %4.").arg(formatAmount(amount)).arg(index).arg(address, formatAmount(fee)) +
                (change ? tr(" %1 stays in a new private note.").arg(formatAmount(change)) : QString()),
            QMessageBox::Ok | QMessageBox::Cancel) != QMessageBox::Ok) {
        return;
    }
    m_pool->withdraw(index, amount, fee, address);
}

void PrivacyPage::maxClicked()
{
    if (!m_pool) return;
    const quint32 index = m_withdrawNote->currentData().toUInt();
    for (const PrivacyNoteRow& note : m_pool->snapshot().notes) {
        if (note.index != index) continue;
        const CAmount available = note.amount - selectedFee(m_withdrawFee);
        if (available <= 0) return;
        const CAmount amount = available < QUANTUM ? available : available / QUANTUM * QUANTUM;
        m_withdrawAmount->setText(NeuraiUnits::format(NeuraiUnits::XNA, amount, false, NeuraiUnits::separatorNever));
    }
}

void PrivacyPage::ownAddressClicked()
{
    if (!m_pool) return;
    QString error;
    const QString address = m_pool->newWalletAddress(error);
    if (address.isEmpty()) {
        Q_EMIT message(tr("Withdraw"), error, CClientUIInterface::MSG_ERROR);
        return;
    }
    m_withdrawAddress->setText(address);
}

void PrivacyPage::copyAddressClicked()
{
    GUIUtil::setClipboard(m_address->fullText());
}

void PrivacyPage::operationFinished(bool success, const QString& text)
{
    if (text.isEmpty()) return;
    Q_EMIT message(tr("Privacy pool"), text, success ? CClientUIInterface::MSG_INFORMATION : CClientUIInterface::MSG_ERROR);
    if (success) {
        m_depositAmount->clear();
        m_withdrawAmount->clear();
        for (const RecipientRow& row : m_recipients) {
            row.address->clear();
            row.amount->clear();
        }
    }
    updateFunding();
}

CAmount PrivacyPage::noteAmount(quint32 index) const
{
    if (!m_pool) return 0;
    for (const PrivacyNoteRow& note : m_pool->snapshot().notes) {
        if (note.index == index) return note.amount;
    }
    return 0;
}

void PrivacyPage::addRecipient()
{
    if (m_recipients.size() >= 3) return;
    RecipientRow row;
    row.widget = new QWidget;
    QHBoxLayout* layout = new QHBoxLayout(row.widget);
    layout->setContentsMargins(0, 0, 0, 0);
    row.address = new QLineEdit;
    row.address->setPlaceholderText(tr("Private address (tnzk1…)"));
    row.address->setFont(GUIUtil::fixedPitchFont());
    row.amount = new QLineEdit;
    row.amount->setPlaceholderText(tr("Amount (XNA)"));
    row.amount->setMaximumWidth(160);
    QPushButton* remove = new QPushButton(tr("Remove"));
    remove->setAutoDefault(false);
    layout->addWidget(row.address, 1);
    layout->addWidget(row.amount);
    layout->addWidget(remove);
    m_recipientLayout->addWidget(row.widget);
    m_recipients.push_back(row);
    QWidget* widget = row.widget;
    connect(remove, &QPushButton::clicked, this, [this, widget] {
        if (m_recipients.size() <= 1) {
            m_recipients[0].address->clear();
            m_recipients[0].amount->clear();
            return;
        }
        for (auto it = m_recipients.begin(); it != m_recipients.end(); ++it) {
            if (it->widget == widget) {
                m_recipients.erase(it);
                break;
            }
        }
        widget->deleteLater();
        updateTransfer();
    });
    connect(row.address, &QLineEdit::textChanged, this, &PrivacyPage::updateTransfer);
    connect(row.amount, &QLineEdit::textChanged, this, &PrivacyPage::updateTransfer);
    updateTransfer();
}

bool PrivacyPage::transferRecipients(QList<QPair<QString, CAmount>>& recipients, QString& reason) const
{
    recipients.clear();
    for (const RecipientRow& row : m_recipients) {
        const QString address = row.address->text().trimmed();
        if (address.isEmpty() && row.amount->text().trimmed().isEmpty()) continue;
        QString error;
        if (!m_pool || !m_pool->validatePrivateAddress(address, error)) {
            reason = address.isEmpty() ? tr("Enter the private address of each recipient.") : tr("Invalid private address: %1").arg(error);
            return false;
        }
        CAmount amount;
        if (!parseAmount(row.amount, amount) || amount % QUANTUM) {
            reason = tr("Each amount must be a multiple of 100 XNA.");
            return false;
        }
        recipients.append({address, amount});
    }
    if (recipients.isEmpty()) {
        reason = tr("Add at least one recipient.");
        return false;
    }
    return true;
}

void PrivacyPage::updateTransfer()
{
    m_addRecipient->setEnabled(m_recipients.size() < 3);
    if (!m_pool || m_pool->state() != PrivacyPoolModel::State::Ready) return;
    // Outputs: the recipient rows plus (usually) the change; the exact size is checked before proving.
    updateFeeLevels(m_transferFee, m_transferFeeHint, QString("T%1").arg(std::min<int>(3, m_recipients.size() + 1)));
    const QVariant noteData = m_transferNote->currentData();
    QList<QPair<QString, CAmount>> recipients;
    QString reason;
    if (!noteData.isValid()) {
        m_transferSummary->setText(tr("No spendable note."));
        return;
    }
    if (!transferRecipients(recipients, reason)) {
        m_transferSummary->setText(reason);
        return;
    }
    CAmount total = selectedFee(m_transferFee);
    for (const auto& recipient : recipients) total += recipient.second;
    const CAmount available = noteAmount(noteData.toUInt());
    if (total > available) {
        m_transferSummary->setText(tr("The note (%1) cannot cover the amounts plus the fee.").arg(formatAmount(available)));
        return;
    }
    const CAmount change = available - total;
    const int outputs = recipients.size() + (change > 0 ? 1 : 0);
    if (outputs > 3) {
        m_transferSummary->setText(tr("Too many outputs: with change, at most two recipients."));
        return;
    }
    m_transferSummary->setText(change > 0 ? tr("Change back to you: %1 · form T%2").arg(formatAmount(change)).arg(outputs)
                                          : tr("No change · form T%1").arg(outputs));
}

void PrivacyPage::transferClicked()
{
    if (!m_pool) return;
    const QVariant noteData = m_transferNote->currentData();
    if (!noteData.isValid()) {
        Q_EMIT message(tr("Private transfer"), tr("There is no spendable note."), CClientUIInterface::MSG_WARNING);
        return;
    }
    QList<QPair<QString, CAmount>> recipients;
    QString reason;
    if (!transferRecipients(recipients, reason)) {
        Q_EMIT message(tr("Private transfer"), reason, CClientUIInterface::MSG_WARNING);
        return;
    }
    const quint32 index = noteData.toUInt();
    const CAmount fee = selectedFee(m_transferFee);
    CAmount total = fee;
    QString lines;
    for (const auto& recipient : recipients) {
        total += recipient.second;
        lines += tr("%1 to %2").arg(formatAmount(recipient.second), recipient.first.left(20) + "…" + recipient.first.right(8)) + "\n";
    }
    const CAmount available = noteAmount(index);
    if (total > available) {
        Q_EMIT message(tr("Private transfer"), tr("The note (%1) cannot cover the amounts plus the fee.").arg(formatAmount(available)),
                       CClientUIInterface::MSG_WARNING);
        return;
    }
    const CAmount change = available - total;
    if (recipients.size() + (change > 0 ? 1 : 0) > 3) {
        Q_EMIT message(tr("Private transfer"), tr("Too many outputs: with change, at most two recipients."), CClientUIInterface::MSG_WARNING);
        return;
    }
    if (QMessageBox::question(this, tr("Confirm private transfer"),
            tr("Send from note #%1:").arg(index) + "\n\n" + lines + "\n" + tr("Pool fee %1.").arg(formatAmount(fee)) +
                (change ? " " + tr("%1 comes back to you as a new private note.").arg(formatAmount(change)) : QString()),
            QMessageBox::Ok | QMessageBox::Cancel) != QMessageBox::Ok) {
        return;
    }
    m_pool->transfer(index, recipients, fee);
}

