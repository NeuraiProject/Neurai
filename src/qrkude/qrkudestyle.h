/*
 * QRKude Qt - style value types (Paint, Style, EncodeOptions, SvgOptions).
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef QRKUDESTYLE_H
#define QRKUDESTYLE_H

#include <QtCore/QByteArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>
#include <QtCore/QMetaType>
#include <QtCore/QPointF>
#include <QtCore/QSharedDataPointer>
#include <QtGui/QBrush>
#include <QtGui/QColor>
#include <QtGui/QGradient>

#include "qrkudeglobal.h"

namespace QRKude {

/*
 * A fill: none, a solid color, or a linear / radial gradient.
 *
 * Linear gradients use an angle in degrees (0 = left to right, 90 = top to
 * bottom) across the painted area; radial gradients a center and a radius
 * relative to the painted area (see docs/SPEC.md section 8.4). At most
 * QRK_MAX_STOPS (8) stops are kept.
 */
class Paint
{
public:
    Paint(); /* None */
    Paint(const QColor &color); /* NOLINT: implicit on purpose, Solid */

    static Paint none();
    static Paint solid(const QColor &color);
    static Paint linear(const QGradientStops &stops, double angleDegrees = 0);
    static Paint linear(const QColor &from, const QColor &to, double angleDegrees = 0);
    static Paint radial(const QGradientStops &stops, const QPointF &center = QPointF(0.5, 0.5),
                        double radius = 0.75);
    static Paint radial(const QColor &center, const QColor &edge);

    PaintType type() const;
    bool isNone() const { return type() == PaintType::None; }
    bool isSolid() const { return type() == PaintType::Solid; }
    bool isGradient() const { return type() == PaintType::Linear || type() == PaintType::Radial; }

    /* Solid color; for gradients the color of the first stop. */
    QColor color() const;
    QGradientStops stops() const;
    double angle() const;    /* linear */
    QPointF center() const;  /* radial, relative (0..1) */
    double radius() const;   /* radial, relative to the larger side */

    void setColor(const QColor &color); /* makes the paint solid */
    void setStops(const QGradientStops &stops);
    void setAngle(double degrees);
    void setCenter(const QPointF &center);
    void setRadius(double radius);

    /* JSON: null, "#rrggbb[aa]" or {"type": "linear", ...}. */
    QJsonValue toJson() const;
    static Paint fromJson(const QJsonValue &value, bool *ok = nullptr);

    /* Raw C representation. */
    const qrk_paint &raw() const { return m_paint; }
    static Paint fromRaw(const qrk_paint &paint);

    bool operator==(const Paint &other) const;
    bool operator!=(const Paint &other) const { return !(*this == other); }

private:
    qrk_paint m_paint;
};

class StyleData;

/*
 * Complete visual description of a QR code. Implicitly shared value type
 * that owns its strings (logo href, label text and font), so copies never
 * point into freed JSON buffers.
 *
 * Construct it with the setters or from the cross-language JSON format
 * (docs/SPEC.md section 2), which is parsed by the C core itself.
 */
class Style
{
public:
    Style(); /* qrk_style_default() */
    Style(const Style &other);
    Style(Style &&other) noexcept;
    Style &operator=(const Style &other);
    Style &operator=(Style &&other) noexcept;
    ~Style();

    /* Accepts a bare style object or {"encode": ..., "style": ..., "svg": ...}.
     * On error returns the default style and sets *ok = false. */
    static Style fromJson(const QByteArray &json, bool *ok = nullptr, QString *errorString = nullptr);
    static Style fromJson(const QJsonObject &json, bool *ok = nullptr, QString *errorString = nullptr);
    /* Full style object (every key written, lossless round trip). */
    QJsonObject toJson() const;
    QByteArray toJsonData(QJsonDocument::JsonFormat format = QJsonDocument::Indented) const;

    /* Quiet zone in modules (default 4). */
    double margin() const;
    void setMargin(double modules);

    ModuleShape moduleShape() const;
    void setModuleShape(ModuleShape shape);
    double moduleSize() const; /* 0.1..1 */
    void setModuleSize(double size);
    double moduleRoundness() const; /* 0..1 */
    void setModuleRoundness(double roundness);
    Paint modulePaint() const;
    void setModulePaint(const Paint &paint);
    /* Shortcuts for the module paint. */
    void setColor(const QColor &color) { setModulePaint(Paint::solid(color)); }
    void setLinearGradient(const QGradientStops &stops, double angleDegrees)
    {
        setModulePaint(Paint::linear(stops, angleDegrees));
    }
    void setRadialGradient(const QGradientStops &stops, const QPointF &center = QPointF(0.5, 0.5),
                           double radius = 0.75)
    {
        setModulePaint(Paint::radial(stops, center, radius));
    }

    EyeShape eyeFrame() const;
    void setEyeFrame(EyeShape shape);
    EyeShape eyeBall() const;
    void setEyeBall(EyeShape shape);
    /* Paint::none() = same as the modules. */
    Paint eyeFramePaint() const;
    void setEyeFramePaint(const Paint &paint);
    Paint eyeBallPaint() const;
    void setEyeBallPaint(const Paint &paint);

    /* EyeShape::None (default) = alignment patterns are drawn as modules. */
    EyeShape alignmentFrame() const;
    void setAlignmentFrame(EyeShape shape);
    EyeShape alignmentBall() const;
    void setAlignmentBall(EyeShape shape);

    /* Paint::none() = transparent. */
    Paint background() const;
    void setBackground(const Paint &paint);
    void setBackgroundColor(const QColor &color) { setBackground(Paint::solid(color)); }
    double backgroundRadius() const; /* modules */
    void setBackgroundRadius(double modules);

    double borderWidth() const; /* modules, 0 = none */
    void setBorderWidth(double modules);
    QColor borderColor() const;
    void setBorderColor(const QColor &color);

    /* Logo: present when logoSize() > 0 (fraction of the symbol width). */
    bool hasLogo() const { return logoSize() > 0; }
    double logoSize() const;
    void setLogoSize(double fraction);
    double logoMargin() const; /* modules */
    void setLogoMargin(double modules);
    LogoShape logoShape() const;
    void setLogoShape(LogoShape shape);
    bool logoExcavate() const;
    void setLogoExcavate(bool excavate);
    QColor logoBackground() const; /* transparent = none */
    void setLogoBackground(const QColor &color);
    /* Image URL or data: URI, written to the SVG. The Qt renderer also loads
     * data: URIs, local files and Qt resources from it when no logo image is
     * passed explicitly. */
    QString logoHref() const;
    void setLogoHref(const QString &href);

    /* Label: shown when the text is not empty. */
    bool hasLabel() const { return !labelText().isEmpty(); }
    QString labelText() const;
    void setLabelText(const QString &text);
    QString labelFont() const; /* CSS-like family list, e.g. "Inter, sans-serif" */
    void setLabelFont(const QString &family);
    double labelSize() const; /* font size in modules */
    void setLabelSize(double modules);
    QColor labelColor() const;
    void setLabelColor(const QColor &color);
    LabelPosition labelPosition() const;
    void setLabelPosition(LabelPosition position);
    bool labelBold() const;
    void setLabelBold(bool bold);

    /* Recommended ECC: High with a logo, else Medium. */
    Ecc recommendedEcc() const;

    /* The C style. Its string pointers stay valid while this Style is alive
     * and not modified. */
    qrk_style toRaw() const;
    /* Copies the strings of `style`. */
    static Style fromRaw(const qrk_style &style);

    bool operator==(const Style &other) const;
    bool operator!=(const Style &other) const { return !(*this == other); }

private:
    QSharedDataPointer<StyleData> d;
};

/* Encoding options ("encode" object of the JSON format). */
struct EncodeOptions
{
    std::optional<Ecc> ecc; /* unset = Style::recommendedEcc() */
    int minVersion = 1;
    int maxVersion = QRK_MAX_VERSION;
    int mask = -1; /* -1 = automatic, 0..7 forced */
    bool boostEcc = true;
    bool eci = false;

    /* Reads the "encode" object of a JSON document (defaults otherwise). */
    static EncodeOptions fromJson(const QByteArray &json, bool *ok = nullptr);
    QJsonObject toJson() const;
    qrk_encode_opts toRaw(const Style &style) const;

    bool operator==(const EncodeOptions &o) const
    {
        return ecc == o.ecc && minVersion == o.minVersion && maxVersion == o.maxVersion &&
               mask == o.mask && boostEcc == o.boostEcc && eci == o.eci;
    }
    bool operator!=(const EncodeOptions &o) const { return !(*this == o); }
};

/* SVG options ("svg" object of the JSON format). */
struct SvgOptions
{
    double width = 0;  /* width attribute in px, 0 = omit width/height */
    QString idPrefix;  /* gradient id prefix, empty = "qrk" */

    static SvgOptions fromJson(const QByteArray &json, bool *ok = nullptr);
    QJsonObject toJson() const;
};

} // namespace QRKude

Q_DECLARE_METATYPE(QRKude::Paint)
Q_DECLARE_METATYPE(QRKude::Style)

#endif // QRKUDESTYLE_H
