/*
 * QRKude Qt - encoded QR code (module matrix).
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef QRKUDECODE_H
#define QRKUDECODE_H

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <memory>

#include "qrkudestyle.h"

namespace QRKude {

/*
 * An encoded QR code. Cheap to copy (the matrix is shared and immutable).
 *
 * When EncodeOptions::ecc is not set, the error correction level follows the
 * default rule of the format: High when the style has a logo, else Medium.
 */
class Code
{
public:
    Code(); /* null code */

    /* Encodes the UTF-8 bytes of `text`. */
    static Code encode(const QString &text, const Style &style = Style(),
                       const EncodeOptions &options = EncodeOptions());
    static Code encode(const char *utf8, const Style &style = Style(),
                       const EncodeOptions &options = EncodeOptions());
    /* Encodes raw bytes. */
    static Code encode(const QByteArray &data, const Style &style = Style(),
                       const EncodeOptions &options = EncodeOptions());

    bool isNull() const { return !m_code; }
    bool isValid() const { return bool(m_code); }
    /* Why encoding failed ("data too long", ...); empty when valid. */
    QString errorString() const { return m_error; }

    int version() const;  /* 1..40, 0 when null */
    int size() const;     /* modules per side */
    Ecc ecc() const;
    int mask() const;     /* 0..7 */
    int mode() const;     /* qrk_mode of the data */

    /* true = dark module; out of range = false. */
    bool isDark(int x, int y) const;

    const qrk_code *raw() const { return m_code.get(); }

    bool operator==(const Code &other) const;
    bool operator!=(const Code &other) const { return !(*this == other); }

private:
    std::shared_ptr<const qrk_code> m_code;
    QString m_error;
};

} // namespace QRKude

Q_DECLARE_METATYPE(QRKude::Code)

#endif // QRKUDECODE_H
