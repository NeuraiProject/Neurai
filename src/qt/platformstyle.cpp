// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "platformstyle.h"

#include "guiconstants.h"
#include "guitheme.h"

#include <QApplication>
#include <QColor>
#include <QIcon>
#include <QImage>
#include <QPalette>
#include <QPixmap>

bool darkModeEnabled = false;

static const struct {
    const char *platformId;
    /** Show images on push buttons */
    const bool imagesOnButtons;
    /** Colorize single-color icons */
    const bool colorizeIcons;
    /** Extra padding/spacing in transactionview */
    const bool useExtraSpacing;
} platform_styles[] = {
    // Text-only push buttons on every platform, as in the web wallet.
    {"macosx", false, true, true},
    {"windows", false, true, false},
    /* Other: linux, unix, ... */
    {"other", false, true, false}
};
static const unsigned platform_styles_count = sizeof(platform_styles)/sizeof(*platform_styles);

namespace {
/* Local functions for colorizing single-color images */

void MakeSingleColorImage(QImage& img, const QColor& colorbase)
{
    img = img.convertToFormat(QImage::Format_ARGB32);
    for (int x = img.width(); x--; )
    {
        for (int y = img.height(); y--; )
        {
            const QRgb rgb = img.pixel(x, y);
            img.setPixel(x, y, qRgba(colorbase.red(), colorbase.green(), colorbase.blue(), qAlpha(rgb)));
        }
    }
}

QIcon ColorizeIcon(const QIcon& ico, const QColor& colorbase)
{
    QIcon new_ico;
    for (const QSize sz : ico.availableSizes())
    {
        QImage img(ico.pixmap(sz).toImage());
        MakeSingleColorImage(img, colorbase);
        new_ico.addPixmap(QPixmap::fromImage(img));
    }
    return new_ico;
}

QImage ColorizeImage(const QString& filename, const QColor& colorbase)
{
    QImage img(filename);
    MakeSingleColorImage(img, colorbase);
    return img;
}

QIcon ColorizeIcon(const QString& filename, const QColor& colorbase)
{
    return QIcon(QPixmap::fromImage(ColorizeImage(filename, colorbase)));
}

}


PlatformStyle::PlatformStyle(const QString &_name, bool _imagesOnButtons, bool _colorizeIcons, bool _useExtraSpacing):
    name(_name),
    imagesOnButtons(_imagesOnButtons),
    colorizeIcons(_colorizeIcons),
    useExtraSpacing(_useExtraSpacing),
    singleColor(0,0,0),
    textColor(0,0,0)
{
    // Determine icon highlighting color
    if (colorizeIcons) {
        const QColor colorHighlightBg(QApplication::palette().color(QPalette::Highlight));
        const QColor colorHighlightFg(QApplication::palette().color(QPalette::HighlightedText));
        const QColor colorText(QApplication::palette().color(QPalette::WindowText));
        const int colorTextLightness = colorText.lightness();
        QColor colorbase;
        if (abs(colorHighlightBg.lightness() - colorTextLightness) < abs(colorHighlightFg.lightness() - colorTextLightness))
            colorbase = colorHighlightBg;
        else
            colorbase = colorHighlightFg;
        singleColor = colorbase;
    }
    // Determine text color
    textColor = QColor(QApplication::palette().color(QPalette::WindowText));
}

QImage PlatformStyle::SingleColorImage(const QString& filename) const
{
    if (!colorizeIcons)
        return QImage(filename);
    return ColorizeImage(filename, SingleColor());
}

QIcon PlatformStyle::SingleColorIcon(const QString& filename) const
{
    if (!colorizeIcons)
        return QIcon(filename);
    return ColorizeIcon(filename, SingleColor());
}

QIcon PlatformStyle::SingleColorIconOnOff(const QString& filenameOn, const QString& filenameOff) const
{
    QIcon icon;
    icon.addPixmap(QPixmap(filenameOn), QIcon::Normal, QIcon::On);
    icon.addPixmap(QPixmap(filenameOff), QIcon::Normal, QIcon::Off);
    return icon;
}

QIcon PlatformStyle::SingleColorIcon(const QIcon& icon) const
{
    if (!colorizeIcons)
        return icon;
    return ColorizeIcon(icon, SingleColor());
}

QIcon PlatformStyle::SingleColorIcon(const QIcon& icon, const QColor& color) const
{
    if (!colorizeIcons)
        return icon;
    return ColorizeIcon(icon, color);
}

QIcon PlatformStyle::OrangeColorIcon(const QString& filename) const
{
    if (!colorizeIcons)
        return QIcon(filename);
    return ColorizeIcon(filename, DarkOrangeColor());
}

QIcon PlatformStyle::OrangeColorIcon(const QIcon& icon) const
{
    if (!colorizeIcons)
        return icon;
    return ColorizeIcon(icon, DarkOrangeColor());
}


QIcon PlatformStyle::NavigationIcon(const QString& filename) const
{
    const GUITheme::Tokens& t = GUITheme::tokens();
    const QPixmap idle = QPixmap::fromImage(ColorizeImage(filename, t.text));
    const QPixmap active = QPixmap::fromImage(ColorizeImage(filename, t.primary));
    const QPixmap disabled = QPixmap::fromImage(ColorizeImage(filename, t.textMuted));
    QIcon icon;
    icon.addPixmap(idle, QIcon::Normal, QIcon::Off);
    icon.addPixmap(active, QIcon::Normal, QIcon::On);
    icon.addPixmap(active, QIcon::Active, QIcon::Off);
    icon.addPixmap(active, QIcon::Active, QIcon::On);
    icon.addPixmap(disabled, QIcon::Disabled, QIcon::Off);
    icon.addPixmap(disabled, QIcon::Disabled, QIcon::On);
    return icon;
}

QIcon PlatformStyle::TextColorIcon(const QString& filename) const
{
    return ColorizeIcon(filename, TextColor());
}

QIcon PlatformStyle::TextColorIcon(const QIcon& icon) const
{
    return ColorizeIcon(icon, TextColor());
}

QColor PlatformStyle::TextColor() const
{
    return GUITheme::tokens().text;
}

QColor PlatformStyle::ToolBarSelectedTextColor() const
{
    return GUITheme::tokens().primary;
}

QColor PlatformStyle::ToolBarNotSelectedTextColor() const
{
    return GUITheme::tokens().text;
}

QColor PlatformStyle::MainBackGroundColor() const
{
    return GUITheme::tokens().page;
}

QColor PlatformStyle::TopWidgetBackGroundColor() const
{
    return GUITheme::tokens().surface;
}

QColor PlatformStyle::WidgetBackGroundColor() const
{
    return GUITheme::tokens().surface;
}

QColor PlatformStyle::SendEntriesBackGroundColor() const
{
    return GUITheme::tokens().surface;
}

QColor PlatformStyle::ShadowColor() const
{
    return GUITheme::tokens().shadow;
}

QColor PlatformStyle::LightBlueColor() const
{
    return GUITheme::tokens().surfaceAlt;
}

QColor PlatformStyle::DarkBlueColor() const
{
    return GUITheme::tokens().text;
}

QColor PlatformStyle::LightOrangeColor() const
{
    return GUITheme::tokens().primary;
}

QColor PlatformStyle::DarkOrangeColor() const
{
    return GUITheme::tokens().primaryHover;
}

QColor PlatformStyle::SingleColor() const
{
    return GUITheme::tokens().text;
}

QColor PlatformStyle::AssetTxColor() const
{
    return GUITheme::tokens().primary;
}


const PlatformStyle *PlatformStyle::instantiate(const QString &platformId)
{
    for (unsigned x=0; x<platform_styles_count; ++x)
    {
        if (platformId == platform_styles[x].platformId)
        {
            return new PlatformStyle(
                    platform_styles[x].platformId,
                    platform_styles[x].imagesOnButtons,
                    platform_styles[x].colorizeIcons,
                    platform_styles[x].useExtraSpacing);
        }
    }
    return 0;
}

