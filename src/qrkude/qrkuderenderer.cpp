/*
 * QRKude Qt - QPainter renderer.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "qrkuderenderer.h"

#include <QtCore/QFileInfo>
#include <QtCore/QUrl>
#include <QtCore/QtMath>
#include <QtGui/QFontMetricsF>
#include <QtGui/QLinearGradient>
#include <QtGui/QPainter>
#include <QtGui/QRadialGradient>

#include <cmath>

namespace QRKude {

/* ---- path sink ---------------------------------------------------------- */

namespace {

struct PathBuilder
{
    QPainterPath path;
    QPointF start, current;
};

void sinkMove(void *user, double x, double y)
{
    auto *b = static_cast<PathBuilder *>(user);
    b->path.moveTo(x, y);
    b->start = b->current = QPointF(x, y);
}

void sinkLine(void *user, double x, double y)
{
    auto *b = static_cast<PathBuilder *>(user);
    b->path.lineTo(x, y);
    b->current = QPointF(x, y);
}

/* Circular arc from the current point to (x, y) around (cx, cy), emitted as
 * cubic Beziers (one per <= 90 degrees) that end exactly on (x, y).
 * `clockwise` is on screen (y down), where clockwise is a positive angle. */
void sinkArc(void *user, double r, bool clockwise, double x, double y, double cx, double cy)
{
    auto *b = static_cast<PathBuilder *>(user);
    const QPointF p0 = b->current, p3(x, y), c(cx, cy);
    const QPointF v0 = p0 - c, v1 = p3 - c;
    const double cross = v0.x() * v1.y() - v0.y() * v1.x();
    const double dot = v0.x() * v1.x() + v0.y() * v1.y();
    double theta = std::atan2(cross, dot);
    if (r <= 0 || std::abs(theta) < 1e-12) {
        b->path.lineTo(p3);
        b->current = p3;
        return;
    }
    if (clockwise && theta < -1e-9)
        theta += 2 * M_PI;
    else if (!clockwise && theta > 1e-9)
        theta -= 2 * M_PI;

    const int segments = qMax(1, int(std::ceil(std::abs(theta) / (M_PI / 2) - 1e-9)));
    const double step = theta / segments;
    const double k = 4.0 / 3.0 * std::tan(step / 4);
    const double a0 = std::atan2(v0.y(), v0.x());
    QPointF from = p0;
    for (int i = 1; i <= segments; i++) {
        const double a = a0 + step * i;
        const QPointF to = i == segments ? p3 : c + QPointF(r * std::cos(a), r * std::sin(a));
        const QPointF f = from - c, t = to - c;
        /* tangents: derivative of the rotation, (-y, x) */
        const QPointF c1 = from + k * QPointF(-f.y(), f.x());
        const QPointF c2 = to - k * QPointF(-t.y(), t.x());
        b->path.cubicTo(c1, c2, to);
        from = to;
    }
    b->current = p3;
}

void sinkClose(void *user)
{
    auto *b = static_cast<PathBuilder *>(user);
    b->path.closeSubpath();
    b->current = b->start;
}

const qrk_path_sink kSink = {sinkMove, sinkLine, sinkArc, sinkClose};

void appendSvg(void *user, const char *data, size_t len)
{
    static_cast<QByteArray *>(user)->append(data, int(len));
}

/* Gradient stops as SVG treats them: offsets clamped to [0, 1] and never
 * below the previous one. QGradient merges equal offsets, so hard color
 * changes are kept with a tiny offset nudge. */
QGradientStops gradientStops(const qrk_paint &p)
{
    const int n = qMin<int>(p.stop_count, QRK_MAX_STOPS);
    QVector<double> offsets(n);
    double prev = 0;
    for (int i = 0; i < n; i++) {
        double o = qBound(0.0, p.stops[i].offset, 1.0);
        if (i > 0 && o < prev)
            o = prev;
        offsets[i] = prev = o;
    }
    const double eps = 1e-6;
    for (int i = 1; i < n; i++)
        if (offsets[i] <= offsets[i - 1])
            offsets[i] = offsets[i - 1] + eps;
    for (int i = n - 1; i >= 0; i--) {
        const double limit = i == n - 1 ? 1.0 : offsets[i + 1] - eps;
        if (offsets[i] > limit)
            offsets[i] = qMax(0.0, limit);
    }
    QGradientStops stops;
    for (int i = 0; i < n; i++)
        stops.append(QGradientStop(offsets[i], fromQrkColor(p.stops[i].color)));
    return stops;
}

QString cssUnquote(QString s)
{
    s = s.trimmed();
    if (s.size() >= 2 && (s.startsWith(QLatin1Char('"')) || s.startsWith(QLatin1Char('\''))) &&
        s.endsWith(s.at(0)))
        s = s.mid(1, s.size() - 2);
    return s;
}

} // namespace

/* ---- Renderer ----------------------------------------------------------- */

Renderer::Renderer() = default;

Renderer::Renderer(const Code &code, const Style &style) : m_code(code), m_style(style) {}

Renderer::Renderer(const QString &text, const Style &style, const EncodeOptions &options)
    : m_code(Code::encode(text, style, options)), m_style(style)
{
}

void Renderer::setCode(const Code &code)
{
    m_code = code;
    invalidate();
}

void Renderer::setStyle(const Style &style)
{
    const bool hrefChanged = style.logoHref() != m_style.logoHref();
    m_style = style;
    invalidate();
    if (hrefChanged)
        m_logo.reset();
}

void Renderer::invalidate()
{
    for (auto &p : m_paths)
        p.reset();
}

Layout Renderer::layout() const
{
    Layout out;
    if (!isValid())
        return out;
    const qrk_style s = m_style.toRaw();
    qrk_layout L;
    qrk_get_layout(m_code.raw(), &s, &L);
    out.canvas = QSizeF(L.width, L.height);
    out.symbolOrigin = QPointF(L.symbol_x, L.symbol_y);
    out.modules = L.modules;
    out.hasLogo = L.has_logo;
    out.logoBox = QRectF(L.logo_x, L.logo_y, L.logo_size, L.logo_size);
    out.hasLabel = L.has_label;
    out.labelAnchor = QPointF(L.label_x, L.label_baseline);
    return out;
}

QSizeF Renderer::canvasSize() const
{
    return layout().canvas;
}

QPainterPath Renderer::layerPath(Layer layer) const
{
    const int i = int(layer);
    if (i < 0 || i >= LayerCount || !isValid())
        return QPainterPath();
    if (!m_paths[i]) {
        const qrk_style s = m_style.toRaw();
        PathBuilder b;
        qrk_emit_layer(m_code.raw(), &s, qrk_layer(i), &kSink, &b);
        /* (setFillRule() on an empty path would insert a MoveTo(0, 0)) */
        if (!b.path.isEmpty())
            b.path.setFillRule(Qt::WindingFill);
        m_paths[i] = b.path;
    }
    return *m_paths[i];
}

QBrush Renderer::layerBrush(Layer layer) const
{
    if (!isValid())
        return QBrush();
    const qrk_style s = m_style.toRaw();
    const qrk_paint p = qrk_layer_paint(&s, qrk_layer(layer));
    switch (p.type) {
    case QRK_PAINT_SOLID:
        if ((p.color & 0xFF) == 0)
            return QBrush();
        return QBrush(fromQrkColor(p.color));
    case QRK_PAINT_LINEAR:
    case QRK_PAINT_RADIAL:
        break;
    default:
        return QBrush();
    }
    const QGradientStops stops = gradientStops(p);
    if (stops.isEmpty())
        return QBrush();
    if (stops.size() == 1)
        return stops.first().second.alpha() ? QBrush(stops.first().second) : QBrush();

    qrk_gradient_geometry g;
    qrk_gradient_geometry_for(m_code.raw(), &s, qrk_layer(layer), &g);
    if (p.type == QRK_PAINT_LINEAR) {
        QLinearGradient lg(g.x1, g.y1, g.x2, g.y2);
        lg.setStops(stops);
        lg.setSpread(QGradient::PadSpread);
        lg.setInterpolationMode(QGradient::ComponentInterpolation); /* unpremultiplied, as SVG */
        return QBrush(lg);
    }
    QRadialGradient rg(QPointF(g.cx, g.cy), g.r);
    rg.setStops(stops);
    rg.setSpread(QGradient::PadSpread);
    rg.setInterpolationMode(QGradient::ComponentInterpolation);
    return QBrush(rg);
}

QFont Renderer::labelFont(int pixelSize) const
{
    QString spec = m_style.labelFont().trimmed();
    if (spec.isEmpty())
        spec = QStringLiteral("sans-serif");
    QStringList families;
    QFont::StyleHint hint = QFont::AnyStyle;
    const QStringList parts = spec.split(QLatin1Char(','));
    for (const QString &part : parts) {
        const QString name = cssUnquote(part);
        const QString lower = name.toLower();
        if (name.isEmpty())
            continue;
        if (lower == QLatin1String("sans-serif") || lower == QLatin1String("system-ui")) {
            if (hint == QFont::AnyStyle)
                hint = QFont::SansSerif;
            families << QStringLiteral("sans-serif") << QStringLiteral("Helvetica") << QStringLiteral("Arial");
        } else if (lower == QLatin1String("serif")) {
            if (hint == QFont::AnyStyle)
                hint = QFont::Serif;
            families << QStringLiteral("serif") << QStringLiteral("Times New Roman") << QStringLiteral("Times");
        } else if (lower == QLatin1String("monospace")) {
            if (hint == QFont::AnyStyle)
                hint = QFont::Monospace;
            families << QStringLiteral("monospace") << QStringLiteral("Courier New") << QStringLiteral("Courier");
        } else if (lower == QLatin1String("cursive")) {
            if (hint == QFont::AnyStyle)
                hint = QFont::Cursive;
        } else if (lower == QLatin1String("fantasy")) {
            if (hint == QFont::AnyStyle)
                hint = QFont::Fantasy;
        } else {
            families << name;
        }
    }
    QFont font;
    if (!families.isEmpty())
        font.setFamily(families.first());
#if QT_VERSION >= QT_VERSION_CHECK(5, 13, 0)
    if (!families.isEmpty())
        font.setFamilies(families);
#endif
    font.setStyleHint(hint == QFont::AnyStyle ? QFont::SansSerif : hint);
    font.setPixelSize(qMax(1, pixelSize));
    font.setBold(m_style.labelBold());
    return font;
}

QRectF Renderer::fittedRect(const QRectF &target) const
{
    const QSizeF canvas = canvasSize();
    if (canvas.isEmpty() || target.isEmpty())
        return QRectF();
    const double scale = qMin(target.width() / canvas.width(), target.height() / canvas.height());
    const QSizeF size(canvas.width() * scale, canvas.height() * scale);
    return QRectF(target.center() - QPointF(size.width() / 2, size.height() / 2), size);
}

QTransform Renderer::canvasTransform(const QRectF &target) const
{
    const QRectF r = fittedRect(target);
    const QSizeF canvas = canvasSize();
    if (r.isEmpty())
        return QTransform();
    QTransform t;
    t.translate(r.x(), r.y());
    t.scale(r.width() / canvas.width(), r.height() / canvas.height());
    return t;
}

void Renderer::paint(QPainter &painter, const QRectF &target, const QImage &logo) const
{
    if (!isValid() || target.isEmpty())
        return;
    const Layout L = layout();

    painter.save();
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
    painter.setRenderHint(QPainter::TextAntialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setTransform(canvasTransform(target), true);

    /* background, border, modules, eye frames, eye balls, logo background */
    for (int i = 0; i < LayerCount; i++) {
        const QBrush brush = layerBrush(Layer(i));
        if (brush.style() == Qt::NoBrush)
            continue;
        const QPainterPath path = layerPath(Layer(i));
        if (!path.isEmpty())
            painter.fillPath(path, brush);
    }

    if (L.hasLogo) {
        QImage image = logo.isNull() ? styleLogo() : logo;
        if (!image.isNull()) {
            /* xMidYMid meet */
            QSizeF size = image.size();
            size.scale(L.logoBox.size(), Qt::KeepAspectRatio);
            const QRectF box(L.logoBox.center() - QPointF(size.width() / 2, size.height() / 2), size);
            /* Large downscales: pre-filter, bilinear sampling alone aliases. */
            const QRectF device = painter.worldTransform().mapRect(box);
            if (painter.worldTransform().type() <= QTransform::TxScale &&
                image.width() > device.width() * 1.5 && device.width() >= 1 && device.height() >= 1)
                image = image.scaled(QSize(int(std::ceil(device.width())), int(std::ceil(device.height()))),
                                     Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
            painter.drawImage(box, image);
        }
    }

    if (L.hasLabel) {
        const double f = qMax(m_style.labelSize(), 0.1);
        const QTransform world = painter.worldTransform();
        const double deviceScale = std::sqrt(std::abs(world.determinant()));
        const int pixelSize = qMax(1, qRound(f * deviceScale));
        const QFont font = labelFont(pixelSize);
        const QString text = m_style.labelText();
        const double advance = QFontMetricsF(font).horizontalAdvance(text);
        painter.translate(L.labelAnchor);
        painter.scale(f / pixelSize, f / pixelSize);
        painter.setFont(font);
        painter.setPen(m_style.labelColor());
        painter.setBrush(Qt::NoBrush);
        painter.drawText(QPointF(-advance / 2, 0), text); /* text-anchor middle, baseline */
    }
    painter.restore();
}

QImage Renderer::toImage(int width, const QImage &logo) const
{
    if (!isValid() || width <= 0)
        return QImage();
    const QSizeF canvas = canvasSize();
    const int height = qMax(1, qRound(width * canvas.height() / canvas.width()));
    QImage image(width, height, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    QPainter painter(&image);
    paint(painter, QRectF(0, 0, width, height), logo);
    painter.end();
    return image;
}

QByteArray Renderer::toSvg(double widthPx) const
{
    SvgOptions o;
    o.width = widthPx;
    return toSvg(o);
}

QByteArray Renderer::toSvg(const SvgOptions &options) const
{
    QByteArray out;
    if (!isValid())
        return out;
    const qrk_style s = m_style.toRaw();
    const QByteArray prefix = options.idPrefix.toUtf8();
    qrk_svg_opts o;
    qrk_svg_opts_default(&o);
    o.width = options.width;
    if (!prefix.isEmpty())
        o.id_prefix = prefix.constData();
    qrk_svg_write(m_code.raw(), &s, &o, appendSvg, &out);
    return out;
}

quint32 Renderer::lintFlags() const
{
    if (!isValid())
        return 0;
    const qrk_style s = m_style.toRaw();
    return qrk_lint(m_code.raw(), &s);
}

QStringList Renderer::lint() const
{
    QStringList out;
    const quint32 flags = lintFlags();
    for (int bit = 0; bit < 32; bit++) {
        const uint32_t flag = uint32_t(1) << bit;
        if (!(flags & flag))
            continue;
        const char *name = qrk_lint_name(flag);
        out << (name ? QString::fromLatin1(name) : QStringLiteral("lint-0x%1").arg(flag, 0, 16));
    }
    return out;
}

double Renderer::logoDamage() const
{
    if (!isValid())
        return 0;
    const qrk_style s = m_style.toRaw();
    return qrk_logo_damage(m_code.raw(), &s);
}

QImage Renderer::styleLogo() const
{
    if (!m_logo)
        m_logo = loadImage(m_style.logoHref());
    return *m_logo;
}

QImage Renderer::loadImage(const QString &href)
{
    const QString h = href.trimmed();
    if (h.isEmpty())
        return QImage();
    if (h.startsWith(QLatin1String("data:"), Qt::CaseInsensitive)) {
        const int comma = h.indexOf(QLatin1Char(','));
        if (comma < 0)
            return QImage();
        const QString meta = h.mid(5, comma - 5);
        const QString payload = h.mid(comma + 1);
        const QByteArray bytes = meta.endsWith(QLatin1String(";base64"), Qt::CaseInsensitive)
                                     ? QByteArray::fromBase64(payload.toLatin1())
                                     : QByteArray::fromPercentEncoding(payload.toUtf8());
        return QImage::fromData(bytes);
    }
    if (h.startsWith(QLatin1String(":/")))
        return QImage(h);
    if (QFileInfo::exists(h))
        return QImage(h);
    const QUrl url(h);
    if (url.scheme() == QLatin1String("qrc"))
        return QImage(QLatin1Char(':') + url.path());
    if (url.isLocalFile())
        return QImage(url.toLocalFile());
    return QImage(); /* remote URLs: pass the image to paint() yourself */
}

} // namespace QRKude
