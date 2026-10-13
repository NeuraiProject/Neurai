// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/neurai-config.h"
#endif

#include "splashscreen.h"

#include "guitheme.h"
#include "networkstyle.h"

#include "clientversion.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "version.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <QApplication>
#include <QCloseEvent>
#include <QPainter>
#include <QFontMetrics>
#include <QScreen>

// Fixing Boost 1.73 compile errors
#include <boost/bind/bind.hpp>

#include <algorithm>
using namespace boost::placeholders;

SplashScreen::SplashScreen(const NetworkStyle* networkStyle)
    : QWidget(), curAlignment(0)
{
    // The splash is a fixed-size bitmap, so its text is sized in pixels and
    // does not follow the system text scale; long lines are shrunk to fit.
    const int splashWidth = 480;
    const int splashHeight = 320;
    float devicePixelRatio = ((QGuiApplication*)QCoreApplication::instance())->devicePixelRatio();

    // define text to place
    QString titleText       = tr(PACKAGE_NAME);
    QString versionText     = QString("Version %1").arg(QString::fromStdString(FormatFullVersion()));
    QString copyrightText   = QString::fromUtf8(CopyrightHolders(strprintf("\xc2\xA9 %u-%u ", 2009, COPYRIGHT_YEAR)).c_str());
    QString titleAddText    = networkStyle->getTitleAddText();

    // create a bitmap according to device pixelratio
    QSize splashSize(splashWidth*devicePixelRatio, splashHeight*devicePixelRatio);
    pixmap = QPixmap(splashSize);
    pixmap.setDevicePixelRatio(devicePixelRatio);

    const GUITheme::Tokens& theme = GUITheme::tokens();
    QPainter pixPaint(&pixmap);
    pixPaint.setRenderHint(QPainter::Antialiasing);
    pixPaint.setRenderHint(QPainter::SmoothPixmapTransform);
    pixPaint.fillRect(QRect(0, 0, splashWidth, splashHeight), theme.surface);

    // draw the neurai icon, vertically centred on the left
    const int iconSize = 210;
    const QRect rectIcon(32, (splashHeight - iconSize) / 2, iconSize, iconSize);
    pixPaint.drawPixmap(rectIcon, networkStyle->getSplashIcon().pixmap(QSize(1024, 1024)));

    // text column to the right of the icon
    const int textLeft = rectIcon.right() + 26;
    const int textWidth = splashWidth - textLeft - 24;
    auto fittedFont = [&](int pixelSize, QFont::Weight weight, const QString& text) {
        QFont font(GUITheme::FONT_FAMILY);
        font.setWeight(weight);
        font.setPixelSize(pixelSize);
        while (pixelSize > 8 && QFontMetrics(font).horizontalAdvance(text) > textWidth) {
            font.setPixelSize(--pixelSize);
        }
        return font;
    };

    const QFont titleFont = fittedFont(40, QFont::Bold, titleText);
    const QFont versionFont = fittedFont(13, QFont::Medium, versionText);
    QFont copyrightFont(GUITheme::FONT_FAMILY);
    copyrightFont.setPixelSize(11);
    const int titleHeight = QFontMetrics(titleFont).height();
    const int versionHeight = QFontMetrics(versionFont).height();
    const QRect copyrightBounds = QFontMetrics(copyrightFont).boundingRect(QRect(0, 0, textWidth, splashHeight), Qt::TextWordWrap, copyrightText);
    const int blockHeight = titleHeight + versionHeight + 14 + copyrightBounds.height();
    int y = std::max(24, (splashHeight - blockHeight) / 2);

    pixPaint.setFont(titleFont);
    pixPaint.setPen(theme.primary);
    pixPaint.drawText(QRect(textLeft, y, textWidth, titleHeight), Qt::AlignLeft | Qt::AlignVCenter, titleText);
    y += titleHeight;

    pixPaint.setFont(versionFont);
    pixPaint.setPen(theme.text);
    pixPaint.drawText(QRect(textLeft, y, textWidth, versionHeight), Qt::AlignLeft | Qt::AlignVCenter, versionText);
    y += versionHeight + 14;

    pixPaint.setFont(copyrightFont);
    pixPaint.setPen(theme.textMuted);
    pixPaint.drawText(QRect(textLeft, y, textWidth, splashHeight - y - 8), Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, copyrightText);

    // draw additional text if special network
    if(!titleAddText.isEmpty()) {
        QFont boldFont(GUITheme::FONT_FAMILY);
        boldFont.setWeight(QFont::Bold);
        boldFont.setPixelSize(11);
        pixPaint.setFont(boldFont);
        pixPaint.setPen(theme.error);
        pixPaint.drawText(QRect(0, 10, splashWidth - 12, 16), Qt::AlignRight | Qt::AlignVCenter, titleAddText);
    }

    pixPaint.end();

    // Set window title
    setWindowTitle(titleText + " " + titleAddText);

    // Resize window and move to center of desktop, disallow resizing
    QRect r(QPoint(), QSize(splashWidth, splashHeight));
    resize(r.size());
    setFixedSize(r.size());
    move(QGuiApplication::primaryScreen()->geometry().center() - r.center());

    subscribeToCoreSignals();
    installEventFilter(this);
}

SplashScreen::~SplashScreen()
{
    unsubscribeFromCoreSignals();
}

bool SplashScreen::eventFilter(QObject * obj, QEvent * ev) {
    if (ev->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(ev);
        if(keyEvent->text()[0] == 'q') {
            StartShutdown();
        }
    }
    return QObject::eventFilter(obj, ev);
}

void SplashScreen::slotFinish(QWidget *mainWin)
{
    Q_UNUSED(mainWin);

    /* If the window is minimized, hide() will be ignored. */
    /* Make sure we de-minimize the splashscreen window before hiding */
    if (isMinimized())
        showNormal();
    hide();
    deleteLater(); // No more need for this
}

static void InitMessage(SplashScreen *splash, const std::string &message)
{
    QMetaObject::invokeMethod(splash, "showMessage",
        Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(int, Qt::AlignBottom|Qt::AlignHCenter),
        Q_ARG(QColor, QColor(55,55,55)));
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress, bool resume_possible)
{
    InitMessage(splash, title + std::string("\n") +
            (resume_possible ? _("(press q to shutdown and continue later)")
                                : _("press q to shutdown")) +
            strprintf("\n%d", nProgress) + "%");
}

#ifdef ENABLE_WALLET
void SplashScreen::ConnectWallet(CWallet* wallet)
{
    m_walletConnections[wallet] = wallet->ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2, false));
    connectedWallets.push_back(wallet);
}
#endif

void SplashScreen::subscribeToCoreSignals()
{
    // Connect signals to client
    m_coreSignalConnections.push_back(uiInterface.InitMessage.connect(boost::bind(InitMessage, this, _1)));
    m_coreSignalConnections.push_back(uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2, _3)));
#ifdef ENABLE_WALLET
    m_coreSignalConnections.push_back(uiInterface.LoadWallet.connect(boost::bind(&SplashScreen::ConnectWallet, this, _1)));
#endif
}

void SplashScreen::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    for (auto& c : m_coreSignalConnections) c.disconnect();
    m_coreSignalConnections.clear();
#ifdef ENABLE_WALLET
    for (auto& kv : m_walletConnections) kv.second.disconnect();
    m_walletConnections.clear();
#endif
}

void SplashScreen::showMessage(const QString &message, int alignment, const QColor &color)
{
    curMessage = message;
    curAlignment = alignment;
    curColor = color;
    update();
}

void SplashScreen::paintEvent(QPaintEvent *event)
{
    QPainter painter(this);
    painter.drawPixmap(0, 0, pixmap);
    QRect r = rect().adjusted(5, 5, -5, -8);
    QFont messageFont(GUITheme::FONT_FAMILY);
    messageFont.setPixelSize(11);
    painter.setFont(messageFont);
    painter.setPen(curColor);
    painter.drawText(r, curAlignment, painter.fontMetrics().elidedText(curMessage, Qt::ElideRight, r.width()));
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    StartShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}
