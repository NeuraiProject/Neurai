/*
 * QRKude Qt - common enums and helpers.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef QRKUDEGLOBAL_H
#define QRKUDEGLOBAL_H

#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtGui/QColor>

#include <optional>

#include "qrkude.h"

namespace QRKude {

/* The numeric values match the C core (qrk_module_shape, qrk_eye_shape...). */

enum class ModuleShape : quint8 {
    Square = QRK_MODULE_SQUARE,
    Dot = QRK_MODULE_DOT,
    Rounded = QRK_MODULE_ROUNDED,
    Diamond = QRK_MODULE_DIAMOND,
    Star = QRK_MODULE_STAR,
    Fluid = QRK_MODULE_FLUID,
    Liquid = QRK_MODULE_LIQUID,
    Bevel = QRK_MODULE_BEVEL,
    Classy = QRK_MODULE_CLASSY,
    HBars = QRK_MODULE_HBARS,
    VBars = QRK_MODULE_VBARS,
};

enum class EyeShape : quint8 {
    Square = QRK_EYE_SQUARE,
    Rounded = QRK_EYE_ROUNDED,
    Circle = QRK_EYE_CIRCLE,
    Leaf = QRK_EYE_LEAF,
    Drop = QRK_EYE_DROP,
    Bevel = QRK_EYE_BEVEL,
    Diamond = QRK_EYE_DIAMOND,
    Dots = QRK_EYE_DOTS,
    None = QRK_EYE_NONE, /* alignment patterns only: draw as data modules */
};

enum class LogoShape : quint8 {
    Square = QRK_LOGO_SQUARE,
    Rounded = QRK_LOGO_ROUNDED,
    Circle = QRK_LOGO_CIRCLE,
};

enum class LabelPosition : quint8 {
    Bottom = QRK_LABEL_BOTTOM,
    Top = QRK_LABEL_TOP,
};

enum class Ecc : quint8 {
    Low = QRK_ECC_LOW,
    Medium = QRK_ECC_MEDIUM,
    Quartile = QRK_ECC_QUARTILE,
    High = QRK_ECC_HIGH,
};

/* Drawing layers, bottom to top. */
enum class Layer : quint8 {
    Background = QRK_LAYER_BACKGROUND,
    Border = QRK_LAYER_BORDER,
    Modules = QRK_LAYER_MODULES,
    EyeFrames = QRK_LAYER_EYE_FRAMES,
    EyeBalls = QRK_LAYER_EYE_BALLS,
    LogoBackground = QRK_LAYER_LOGO_BACKGROUND,
};
constexpr int LayerCount = QRK_LAYER_COUNT;

enum class PaintType : quint8 {
    None = QRK_PAINT_NONE,
    Solid = QRK_PAINT_SOLID,
    Linear = QRK_PAINT_LINEAR,
    Radial = QRK_PAINT_RADIAL,
};

/* Version of the bundled C core. */
QString coreVersion();

/* Names used by the cross-language JSON format ("fluid", "leaf", ...). */
QString moduleShapeName(ModuleShape shape);
std::optional<ModuleShape> moduleShapeFromName(const QString &name);
QStringList moduleShapeNames();

QString eyeShapeName(EyeShape shape); /* None -> empty string */
std::optional<EyeShape> eyeShapeFromName(const QString &name);
QStringList eyeShapeNames(); /* without None */

QString logoShapeName(LogoShape shape);
std::optional<LogoShape> logoShapeFromName(const QString &name);

QString eccName(Ecc ecc); /* "L", "M", "Q", "H" */
std::optional<Ecc> eccFromName(const QString &name);

/* Color conversion between QColor and the core's 0xRRGGBBAA. */
qrk_color toQrkColor(const QColor &color);
QColor fromQrkColor(qrk_color color);
/* "#rrggbb" or "#rrggbbaa" (alpha != 255), lower case, as the JSON format. */
QString colorName(const QColor &color);
/* Parses "#rgb", "#rrggbb", "#rrggbbaa" or "transparent" (JSON format). */
std::optional<QColor> parseColor(const QString &text);

} // namespace QRKude

#endif // QRKUDEGLOBAL_H
