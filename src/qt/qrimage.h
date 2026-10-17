// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_QRIMAGE_H
#define NEURAI_QT_QRIMAGE_H

#include <QImage>
#include <QString>
#include <QStringList>

/** QR code of `text` in the Neurai style: navy dots and rounded eyes on a
 *  cream card with a navy border and the Neurai logo in the middle (high error
 *  correction, so the logo does not hide data). The image is `size` pixels
 *  wide in device-independent pixels, drawn for `dpr`. A non-empty `caption`
 *  is printed under the symbol, inside the card; a long one keeps its start
 *  and end. Returns a null image, with `error` set, when `text` cannot be
 *  encoded. */
QImage NeuraiQRImage(const QString& text, int size, QString& error, const QString& caption = QString(), qreal dpr = 1.0);

/** Scannability warnings of that QR code (e.g. "logo-risky"); empty when it
 *  reads reliably. */
QStringList NeuraiQRWarnings(const QString& text);

#endif // NEURAI_QT_QRIMAGE_H
