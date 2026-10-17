/*
 * QRKude Qt - encoded QR code (module matrix).
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "qrkudecode.h"

#include <cstring>
#include <vector>

namespace QRKude {

Code::Code() = default;

Code Code::encode(const QString &text, const Style &style, const EncodeOptions &options)
{
    return encode(text.toUtf8(), style, options);
}

Code Code::encode(const char *utf8, const Style &style, const EncodeOptions &options)
{
    return encode(QByteArray(utf8 ? utf8 : ""), style, options);
}

Code Code::encode(const QByteArray &data, const Style &style, const EncodeOptions &options)
{
    Code out;
    auto code = std::make_shared<qrk_code>();
    std::vector<uint8_t> scratch(QRK_BUFFER_LEN_MAX);
    const qrk_encode_opts opts = options.toRaw(style);
    qrk_status st = qrk_encode(code.get(), data.constData(), size_t(data.size()), &opts, scratch.data());
    if (st != QRK_OK) {
        out.m_error = QString::fromLatin1(qrk_status_str(st));
        return out;
    }
    out.m_code = std::move(code);
    return out;
}

int Code::version() const
{
    return m_code ? m_code->version : 0;
}

int Code::size() const
{
    return m_code ? m_code->size : 0;
}

Ecc Code::ecc() const
{
    return m_code ? Ecc(m_code->ecc) : Ecc::Medium;
}

int Code::mask() const
{
    return m_code ? m_code->mask : -1;
}

int Code::mode() const
{
    return m_code ? m_code->mode : 0;
}

bool Code::isDark(int x, int y) const
{
    return m_code && qrk_get_module(m_code.get(), x, y);
}

bool Code::operator==(const Code &other) const
{
    if (m_code == other.m_code)
        return true;
    if (!m_code || !other.m_code)
        return false;
    const qrk_code &a = *m_code, &b = *other.m_code;
    if (a.version != b.version || a.size != b.size || a.ecc != b.ecc || a.mask != b.mask)
        return false;
    const size_t bytes = (size_t(a.size) * a.size + 7) / 8;
    return std::memcmp(a.modules, b.modules, bytes) == 0;
}

} // namespace QRKude
