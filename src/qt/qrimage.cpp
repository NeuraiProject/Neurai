// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qrimage.h"

#include "qrkude/qrkuderenderer.h"

#include <QCoreApplication>

namespace {

// Navy dots and eyes on a cream card. The style asks for high error
// correction because it has a logo; excavation clears the modules under it.
// Logo size and minimum version keep the logo below half of the correction
// capacity of every block, also for short texts (QRKude logo damage <= 0.43).
const char* const NEURAI_QR_STYLE = R"({
    "margin": 2,
    "modules": {"shape": "dot", "size": 0.9, "color": "#1d3557"},
    "eyes": {"frame": "rounded", "ball": "rounded", "frameColor": "#1d3557", "ballColor": "#1d3557"},
    "background": {"color": "#fff8e7", "radius": 3},
    "border": {"width": 1, "color": "#1d3557"},
    "logo": {"size": 0.2, "margin": 1, "shape": "rounded", "excavate": true},
    "label": {"font": "DejaVu Sans Mono, Menlo, Consolas, monospace", "size": 2.6,
              "color": "#1d3557", "position": "bottom", "bold": false}
})";

//! Characters kept at each end of a long caption.
const int CAPTION_KEEP = 14;

//! Smaller symbols would let the logo hide too much of a block.
const int MIN_VERSION = 6;

QRKude::Style NeuraiStyle()
{
    return QRKude::Style::fromJson(QByteArray(NEURAI_QR_STYLE));
}

QRKude::EncodeOptions NeuraiEncoding()
{
    QRKude::EncodeOptions options;
    options.minVersion = MIN_VERSION;
    return options;
}

} // namespace

QImage NeuraiQRImage(const QString& text, int size, QString& error, const QString& caption, qreal dpr)
{
    QRKude::Style style = NeuraiStyle();
    if (!caption.isEmpty()) {
        QString shown = caption;
        if (shown.size() > 2 * CAPTION_KEEP + 1)
            shown = shown.left(CAPTION_KEEP) + QString::fromUtf8("\u2026") + shown.right(CAPTION_KEEP);
        style.setLabelText(shown);
    }
    const QRKude::Renderer renderer(text, style, NeuraiEncoding());
    if (!renderer.isValid()) {
        error = QCoreApplication::translate("ReceiveRequestDialog", "Error encoding URI into QR Code.");
        return QImage();
    }
    static const QImage logo(":/icons/qr_logo");
    QImage image = renderer.toImage(qRound(size * dpr), logo);
    image.setDevicePixelRatio(dpr);
    return image;
}

QStringList NeuraiQRWarnings(const QString& text)
{
    const QRKude::Renderer renderer(text, NeuraiStyle(), NeuraiEncoding());
    return renderer.isValid() ? renderer.lint() : QStringList{"encode-failed"};
}
