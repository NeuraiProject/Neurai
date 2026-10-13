// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "guitheme.h"

#include "platformstyle.h"

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QPalette>
#include <QStyleFactory>
#include <QWidget>

#include <utility>

namespace GUITheme
{

const char* const FONT_FAMILY = "Inter";

namespace
{

// Same values as the DaisyUI themes of the web wallet (src/styles/tailwind.css).
const Tokens LIGHT_TOKENS = {
    /* page */         QColor("#f4f4f6"),
    /* surface */      QColor("#ffffff"),
    /* surfaceAlt */   QColor("#f9fafb"),
    /* border */       QColor("#e5e7eb"),
    /* fieldBorder */  QColor("#d1d5db"),
    /* text */         QColor("#111827"),
    /* textMuted */    QColor("#6b7280"),
    /* primary */      QColor("#f97316"),
    /* primaryHover */ QColor("#ea6c10"),
    /* primaryText */  QColor("#ffffff"),
    /* accent */       QColor("#fff7ed"),
    /* success */      QColor("#16a34a"),
    /* warning */      QColor("#d97706"),
    /* error */        QColor("#ef4444"),
    /* shadow */       QColor(17, 24, 39, 34),
};

const Tokens DARK_TOKENS = {
    /* page */         QColor("#111827"),
    /* surface */      QColor("#1f2937"),
    /* surfaceAlt */   QColor("#273343"),
    /* border */       QColor("#374151"),
    /* fieldBorder */  QColor("#4b5563"),
    /* text */         QColor("#f9fafb"),
    /* textMuted */    QColor("#9ca3af"),
    /* primary */      QColor("#f97316"),
    /* primaryHover */ QColor("#ea6c10"),
    /* primaryText */  QColor("#ffffff"),
    /* accent */       QColor("#40342f"),
    /* success */      QColor("#22c55e"),
    /* warning */      QColor("#f59e0b"),
    /* error */        QColor("#f87171"),
    /* shadow */       QColor(0, 0, 0, 110),
};

QString css(const QColor& color)
{
    if (color.alpha() == 255) {
        return color.name();
    }
    return QString("rgba(%1, %2, %3, %4)").arg(color.red()).arg(color.green()).arg(color.blue()).arg(color.alpha());
}

QColor withAlpha(QColor color, int alpha)
{
    color.setAlpha(alpha);
    return color;
}

QPalette makePalette(const Tokens& t, bool dark)
{
    QPalette p;
    p.setColor(QPalette::Window, t.page);
    p.setColor(QPalette::WindowText, t.text);
    p.setColor(QPalette::Base, t.surface);
    p.setColor(QPalette::AlternateBase, t.surfaceAlt);
    p.setColor(QPalette::ToolTipBase, dark ? t.text : QColor("#111827"));
    p.setColor(QPalette::ToolTipText, dark ? t.page : QColor("#ffffff"));
    p.setColor(QPalette::PlaceholderText, t.textMuted);
    p.setColor(QPalette::Text, t.text);
    p.setColor(QPalette::Button, t.surface);
    p.setColor(QPalette::ButtonText, t.text);
    p.setColor(QPalette::BrightText, t.error);
    p.setColor(QPalette::Link, t.primary);
    p.setColor(QPalette::LinkVisited, t.primaryHover);
    p.setColor(QPalette::Highlight, t.primary);
    p.setColor(QPalette::HighlightedText, t.primaryText);
    // Bevel colours used by Fusion for frames and separators.
    p.setColor(QPalette::Light, dark ? t.border : QColor("#ffffff"));
    p.setColor(QPalette::Midlight, t.surfaceAlt);
    p.setColor(QPalette::Mid, t.fieldBorder);
    p.setColor(QPalette::Dark, dark ? QColor("#0b1220") : QColor("#9ca3af"));
    p.setColor(QPalette::Shadow, dark ? QColor("#000000") : QColor("#6b7280"));

    for (QPalette::ColorRole role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText}) {
        p.setColor(QPalette::Disabled, role, t.textMuted);
    }
    p.setColor(QPalette::Disabled, QPalette::Highlight, t.fieldBorder);
    p.setColor(QPalette::Disabled, QPalette::Base, t.surfaceAlt);
    return p;
}

// Application wide rules. Widgets that still set their own style sheet keep
// working: their rules are merged on top of these.
const char* const STYLE_SHEET_TEMPLATE = R"(
QToolTip { background-color: @tooltipbg; color: @tooltiptext; border: none; border-radius: 6px; padding: 6px 8px; }

QMenuBar { background-color: @page; border: none; padding: 2px 6px; }
QMenuBar::item { background: transparent; padding: 5px 10px; border-radius: 6px; }
QMenuBar::item:selected { background-color: @border; }
QMenu { background-color: @surface; border: 1px solid @border; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 6px 22px 6px 30px; border-radius: 6px; color: @text; }
QMenu::item:selected { background-color: @accent; color: @text; }
QMenu::item:disabled { color: @muted; }
QMenu::icon { padding-left: 8px; }
QMenu::separator { height: 1px; background: @border; margin: 5px 8px; }

QPushButton { background-color: @surface; color: @text; border: 1px solid @border; border-radius: @fieldradiuspx; padding: 7px 16px; font-weight: 600; }
QPushButton:hover { background-color: @surfalt; border-color: @fieldborder; }
QPushButton:pressed { background-color: @border; }
QPushButton:checked { background-color: @accent; border-color: @primary; color: @primary; }
QPushButton:disabled { color: @muted; background-color: @surfalt; border-color: @border; }
QPushButton:default, QPushButton[primary="true"] { background-color: @primary; color: @primtext; border-color: @primary; }
QPushButton:default:hover, QPushButton[primary="true"]:hover { background-color: @primhover; border-color: @primhover; }
QPushButton:default:disabled, QPushButton[primary="true"]:disabled { background-color: @primdisabled; border-color: @primdisabled; color: @primtext; }
QPushButton:flat { background: transparent; border: none; }

QToolButton { background: transparent; border: 1px solid transparent; border-radius: 8px; padding: 4px; color: @text; }
QToolButton:hover { background-color: @surfalt; border-color: @border; }
QToolButton:pressed, QToolButton:checked { background-color: @accent; border-color: @primary; }

QLineEdit, QPlainTextEdit, QTextEdit, QAbstractSpinBox, QComboBox {
    background-color: @surface; color: @text; border: 1px solid @fieldborder; border-radius: @fieldradiuspx;
    padding: 5px 9px; selection-background-color: @primary; selection-color: @primtext;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QAbstractSpinBox:focus, QComboBox:focus { border-color: @primary; }
QLineEdit:disabled, QPlainTextEdit:disabled, QTextEdit:disabled, QAbstractSpinBox:disabled, QComboBox:disabled { background-color: @surfalt; color: @muted; }
QLineEdit[readOnly="true"], QPlainTextEdit[readOnly="true"], QTextEdit[readOnly="true"] { background-color: @surfalt; }
QTextEdit, QPlainTextEdit { padding: 4px 6px; }

QComboBox { padding-right: 26px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 24px; border: none; background: transparent; }
QComboBox::down-arrow { image: url(:/icons/ui_chevron_down); width: 12px; height: 12px; }
QComboBox QAbstractItemView { background-color: @surface; color: @text; border: 1px solid @border; border-radius: 8px; padding: 4px; outline: 0; selection-background-color: @accent; selection-color: @text; }

QAbstractSpinBox { padding-right: 22px; }
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button { subcontrol-origin: border; width: 20px; border: none; background: transparent; }
QAbstractSpinBox::up-button { subcontrol-position: top right; margin-top: 2px; }
QAbstractSpinBox::down-button { subcontrol-position: bottom right; margin-bottom: 2px; }
QAbstractSpinBox::up-arrow { image: url(:/icons/ui_chevron_up); width: 10px; height: 10px; }
QAbstractSpinBox::down-arrow { image: url(:/icons/ui_chevron_down); width: 10px; height: 10px; }

QCheckBox, QRadioButton { spacing: 8px; background: transparent; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid @fieldborder; border-radius: 5px; background-color: @surface; }
QCheckBox::indicator:hover { border-color: @primary; }
QCheckBox::indicator:checked, QCheckBox::indicator:indeterminate { background-color: @primary; border-color: @primary; image: url(:/icons/ui_check); }
QCheckBox::indicator:disabled { background-color: @surfalt; border-color: @border; }
QCheckBox::indicator:checked:disabled { background-color: @primdisabled; border-color: @primdisabled; }
QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid @fieldborder; border-radius: 9px; background-color: @surface; }
QRadioButton::indicator:hover { border-color: @primary; }
QRadioButton::indicator:checked { width: 8px; height: 8px; border: 5px solid @primary; border-radius: 9px; background-color: @surface; }
QRadioButton::indicator:disabled { background-color: @surfalt; border-color: @border; }

QTableView, QTreeView, QListView {
    background-color: @surface; alternate-background-color: @surfalt; color: @text; border: 1px solid @border;
    border-radius: @cardradiuspx; gridline-color: @border; outline: 0;
    selection-background-color: @accent; selection-color: @text;
}
QTableView::item:selected, QTreeView::item:selected, QListView::item:selected { background-color: @accent; color: @text; }
QHeaderView { background: transparent; border: none; }
QHeaderView::section { background-color: @surface; color: @muted; border: none; border-bottom: 1px solid @border; padding: 7px 8px; font-weight: 600; }
QHeaderView::section:horizontal:first { border-top-left-radius: @cardradiuspx; }
QHeaderView::section:horizontal:last { border-top-right-radius: @cardradiuspx; }
QTableCornerButton::section { background-color: @surface; border: none; }

QScrollBar:vertical { background: transparent; width: 12px; margin: 3px 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px 3px; }
QScrollBar::handle:vertical { background-color: @fieldborder; border-radius: 4px; min-height: 32px; margin: 0 2px; }
QScrollBar::handle:horizontal { background-color: @fieldborder; border-radius: 4px; min-width: 32px; margin: 2px 0; }
QScrollBar::handle:hover { background-color: @muted; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

QTabWidget::pane { background-color: @surface; border: 1px solid @border; border-radius: @cardradiuspx; top: -1px; }
QTabBar::tab { background: transparent; color: @muted; border: none; border-bottom: 2px solid transparent; padding: 8px 14px; font-weight: 600; }
QTabBar::tab:hover { color: @text; }
QTabBar::tab:selected { color: @primary; border-bottom: 2px solid @primary; }

QGroupBox { background-color: @surface; border: 1px solid @border; border-radius: @cardradiuspx; margin-top: 16px; padding: 10px 8px 8px 8px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left: 12px; padding: 0 4px; color: @muted; }

QProgressBar { background-color: @border; border: none; border-radius: 6px; text-align: center; color: @text; min-height: 14px; }
QProgressBar::chunk { background-color: @primary; border-radius: 6px; }

QSlider::groove:horizontal { height: 4px; background-color: @border; border-radius: 2px; }
QSlider::sub-page:horizontal { background-color: @primary; border-radius: 2px; }
QSlider::handle:horizontal { background-color: @primary; width: 16px; height: 16px; margin: -6px 0; border-radius: 8px; }

QFrame[frameShape="4"] { border: none; background-color: @border; min-height: 1px; max-height: 1px; }
QFrame[frameShape="5"] { border: none; background-color: @border; min-width: 1px; max-width: 1px; }
QComboBox QLineEdit, QAbstractSpinBox QLineEdit { border: none; background: transparent; padding: 0; }

QStatusBar { background-color: @page; border-top: 1px solid @border; color: @muted; }
QStatusBar::item { border: none; }
QSplitter::handle { background-color: @border; }

/* Main window header (see NeuraiGUI::createToolBars). */
QFrame#headerCard { background-color: @surface; border: 1px solid @border; border-radius: @cardradiuspx; }
QLabel#headerTitle { color: @primary; font-size: 19px; font-weight: 700; }
QLabel#headerBalance { color: @text; font-size: 15px; font-weight: 700; }
QLabel#headerPrice { color: @muted; font-size: 11px; }
QLabel#networkChip { border-radius: 6px; padding: 2px 8px; font-size: 10px; font-weight: 700; }
QLabel#networkChip[mainnet="true"] { color: @success; background-color: @successbg; border: 1px solid @successborder; }
QLabel#networkChip[mainnet="false"] { color: @error; background-color: @errorbg; border: 1px solid @errorborder; }
QComboBox#headerCurrency { padding: 1px 22px 1px 6px; font-size: 11px; border-radius: 6px; }
QToolBar#navBar { background: transparent; border: none; spacing: 2px; }
QToolBar#navBar QToolButton { color: @text; background: transparent; border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 5px 7px 4px 7px; font-size: 12px; font-weight: 500; }
QToolBar#navBar QToolButton:hover { color: @primary; }
QToolBar#navBar QToolButton:checked { color: @primary; border-bottom: 2px solid @primary; }
QToolBar#navBar QToolButton:disabled { color: @muted; }
QToolBar#navBar QToolButton[popupMode="2"] { padding-left: 16px; padding-right: 16px; }
QToolBar#navBar QToolButton::menu-indicator { image: url(:/icons/ui_chevron_down); subcontrol-origin: padding; subcontrol-position: center right; width: 10px; height: 10px; right: 3px; }
)";

QString buildStyleSheet(const Tokens& t, bool dark)
{
    QString qss = QString::fromLatin1(STYLE_SHEET_TEMPLATE);
    const QColor primaryDisabled = dark ? QColor("#7c4a2a") : QColor("#fdba74");
    // Longer keys first so that no key is a prefix of one replaced later.
    const std::pair<const char*, QString> replacements[] = {
        {"@cardradiuspx", QString("%1px").arg(CARD_RADIUS)},
        {"@fieldradiuspx", QString("%1px").arg(FIELD_RADIUS)},
        {"@tooltiptext", css(dark ? t.page : QColor("#ffffff"))},
        {"@tooltipbg", css(dark ? t.text : QColor("#111827"))},
        {"@primdisabled", css(primaryDisabled)},
        {"@successborder", css(withAlpha(t.success, 120))},
        {"@successbg", css(withAlpha(t.success, 36))},
        {"@errorborder", css(withAlpha(t.error, 120))},
        {"@errorbg", css(withAlpha(t.error, 36))},
        {"@fieldborder", css(t.fieldBorder)},
        {"@primhover", css(t.primaryHover)},
        {"@primtext", css(t.primaryText)},
        {"@primary", css(t.primary)},
        {"@surfalt", css(t.surfaceAlt)},
        {"@surface", css(t.surface)},
        {"@border", css(t.border)},
        {"@accent", css(t.accent)},
        {"@success", css(t.success)},
        {"@error", css(t.error)},
        {"@muted", css(t.textMuted)},
        {"@page", css(t.page)},
        {"@text", css(t.text)},
    };
    for (const auto& replacement : replacements) {
        qss.replace(QLatin1String(replacement.first), replacement.second);
    }
    return qss;
}

void loadFonts()
{
    for (const char* file : {":/fonts/inter-regular", ":/fonts/inter-medium", ":/fonts/inter-semibold", ":/fonts/inter-bold"}) {
        QFontDatabase::addApplicationFont(QString::fromLatin1(file));
    }
}

} // namespace

const Tokens& tokens()
{
    return darkModeEnabled ? DARK_TOKENS : LIGHT_TOKENS;
}

void apply(QApplication& app, bool dark)
{
    const Tokens& t = dark ? DARK_TOKENS : LIGHT_TOKENS;

    loadFonts();
#if !defined(Q_OS_MAC)
    QFont font = QApplication::font();
    font.setFamily(FONT_FAMILY);
    app.setFont(font);
#endif

    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    app.setPalette(makePalette(t, dark));
    app.setStyleSheet(buildStyleSheet(t, dark));
}

void makeCard(QWidget* widget, const QString& extraRules)
{
    if (widget->objectName().isEmpty()) {
        widget->setObjectName(QString("card%1").arg(reinterpret_cast<quintptr>(widget), 0, 16));
    }
    const Tokens& t = tokens();
    widget->setStyleSheet(QString("%1#%2 { background-color: %3; border: 1px solid %4; border-radius: %5px; %6 }")
        .arg(QString::fromLatin1(widget->metaObject()->className()), widget->objectName(), css(t.surface), css(t.border))
        .arg(CARD_RADIUS)
        .arg(extraRules));
}

} // namespace GUITheme
