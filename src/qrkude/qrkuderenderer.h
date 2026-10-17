/*
 * QRKude Qt - QPainter renderer.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef QRKUDERENDERER_H
#define QRKUDERENDERER_H

#include <QtCore/QRectF>
#include <QtCore/QStringList>
#include <QtGui/QBrush>
#include <QtGui/QFont>
#include <QtGui/QImage>
#include <QtGui/QPainterPath>
#include <QtGui/QTransform>

#include <array>
#include <optional>

#include "qrkudecode.h"
#include "qrkudestyle.h"

class QPainter;

namespace QRKude {

/* Canvas layout, in modules ("canvas units"). */
struct Layout
{
    QSizeF canvas;        /* whole canvas (quiet zone, border and label band included) */
    QPointF symbolOrigin; /* top-left of module (0, 0) */
    int modules = 0;      /* modules per side */
    bool hasLogo = false;
    QRectF logoBox;       /* square box the logo image is fitted into */
    bool hasLabel = false;
    QPointF labelAnchor;  /* x = text center, y = baseline */
};

/*
 * Draws a Code with a Style through QPainter. Geometry comes from the C core
 * (qrk_emit_layer), so the result matches the SVG writer of every port.
 *
 * Paths and brushes are in canvas units (modules); paint() maps them into
 * the target rectangle, keeping the aspect ratio. A Renderer caches its
 * paths: share one instance between threads only for reading after the
 * cache is warm, or give each thread its own copy.
 */
class Renderer
{
public:
    Renderer();
    Renderer(const Code &code, const Style &style);
    /* Encodes `text` with the style's default ECC rule. */
    explicit Renderer(const QString &text, const Style &style = Style(),
                      const EncodeOptions &options = EncodeOptions());

    const Code &code() const { return m_code; }
    void setCode(const Code &code);
    const Style &style() const { return m_style; }
    void setStyle(const Style &style);

    bool isValid() const { return m_code.isValid(); }

    Layout layout() const;
    QSizeF canvasSize() const;

    /* Geometry of one layer in canvas units, fill rule Qt::WindingFill. */
    QPainterPath layerPath(Layer layer) const;
    /* Fill of one layer in canvas units (Qt::NoBrush when invisible). */
    QBrush layerBrush(Layer layer) const;
    /* Label font with a pixel size of `pixelSize` (the style size is in modules). */
    QFont labelFont(int pixelSize) const;

    /* Largest rectangle with the canvas aspect ratio, centered in `target`. */
    QRectF fittedRect(const QRectF &target) const;
    /* Canvas units -> target coordinates (as used by paint()). */
    QTransform canvasTransform(const QRectF &target) const;

    /* Paints everything into `target` (aspect ratio kept, centered) with
     * antialiasing. Without `logo`, the logo is loaded from the style's href
     * when it is a data: URI, a local file or a Qt resource. */
    void paint(QPainter &painter, const QRectF &target, const QImage &logo = QImage()) const;
    /* ARGB32 premultiplied image, `width` pixels wide (height from the aspect). */
    QImage toImage(int width, const QImage &logo = QImage()) const;
    /* SVG from the core writer (byte-identical in every port). */
    QByteArray toSvg(double widthPx = 0) const;
    QByteArray toSvg(const SvgOptions &options) const;

    /* Scannability warnings ("logo-risky", "low-contrast", ...). */
    QStringList lint() const;
    quint32 lintFlags() const;
    /* Worst-case share of an RS block hidden by the logo (> 1 = unreadable). */
    double logoDamage() const;

    /* The logo loaded from the style's href (cached), or a null image. */
    QImage styleLogo() const;
    /* Loads data: URIs, file paths/URLs and Qt resources (":/", "qrc:/"). */
    static QImage loadImage(const QString &href);

private:
    void invalidate();

    Code m_code;
    Style m_style;
    mutable std::array<std::optional<QPainterPath>, LayerCount> m_paths;
    mutable std::optional<QImage> m_logo;
};

} // namespace QRKude

#endif // QRKUDERENDERER_H
