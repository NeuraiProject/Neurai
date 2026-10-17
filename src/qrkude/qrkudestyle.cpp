/*
 * QRKude Qt - style value types.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "qrkudestyle.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonParseError>

#include <cstring>

namespace QRKude {

/* ---- enums and names ---------------------------------------------------- */

static_assert(int(ModuleShape::VBars) + 1 == QRK_MODULE_SHAPE_COUNT, "module shapes out of sync");
static_assert(int(EyeShape::Dots) + 1 == QRK_EYE_SHAPE_COUNT, "eye shapes out of sync");
static_assert(int(Layer::LogoBackground) + 1 == QRK_LAYER_COUNT, "layers out of sync");

QString coreVersion()
{
    return QStringLiteral(QRK_LIB_VERSION);
}

QString moduleShapeName(ModuleShape shape)
{
    const char *name = qrk_module_shape_name(int(shape));
    return name ? QString::fromLatin1(name) : QString();
}

std::optional<ModuleShape> moduleShapeFromName(const QString &name)
{
    int v = qrk_module_shape_from_name(name.trimmed().toLower().toUtf8().constData());
    if (v < 0)
        return std::nullopt;
    return ModuleShape(v);
}

QStringList moduleShapeNames()
{
    QStringList out;
    for (int i = 0; i < QRK_MODULE_SHAPE_COUNT; i++)
        out << QString::fromLatin1(qrk_module_shape_name(i));
    return out;
}

QString eyeShapeName(EyeShape shape)
{
    const char *name = qrk_eye_shape_name(int(shape));
    return name ? QString::fromLatin1(name) : QString();
}

std::optional<EyeShape> eyeShapeFromName(const QString &name)
{
    int v = qrk_eye_shape_from_name(name.trimmed().toLower().toUtf8().constData());
    if (v < 0)
        return std::nullopt;
    return EyeShape(v);
}

QStringList eyeShapeNames()
{
    QStringList out;
    for (int i = 0; i < QRK_EYE_SHAPE_COUNT; i++)
        out << QString::fromLatin1(qrk_eye_shape_name(i));
    return out;
}

QString logoShapeName(LogoShape shape)
{
    switch (shape) {
    case LogoShape::Rounded: return QStringLiteral("rounded");
    case LogoShape::Circle: return QStringLiteral("circle");
    default: return QStringLiteral("square");
    }
}

std::optional<LogoShape> logoShapeFromName(const QString &name)
{
    const QString n = name.trimmed().toLower();
    if (n == QLatin1String("square")) return LogoShape::Square;
    if (n == QLatin1String("rounded")) return LogoShape::Rounded;
    if (n == QLatin1String("circle")) return LogoShape::Circle;
    return std::nullopt;
}

QString eccName(Ecc ecc)
{
    static const char levels[] = "LMQH";
    int i = int(ecc);
    return i >= 0 && i < 4 ? QString(QLatin1Char(levels[i])) : QString();
}

std::optional<Ecc> eccFromName(const QString &name)
{
    const QString n = name.trimmed().toUpper();
    if (n == QLatin1String("L")) return Ecc::Low;
    if (n == QLatin1String("M")) return Ecc::Medium;
    if (n == QLatin1String("Q")) return Ecc::Quartile;
    if (n == QLatin1String("H")) return Ecc::High;
    return std::nullopt;
}

qrk_color toQrkColor(const QColor &color)
{
    if (!color.isValid())
        return QRK_TRANSPARENT;
    const QColor c = color.toRgb();
    return QRK_RGBA(c.red(), c.green(), c.blue(), c.alpha());
}

QColor fromQrkColor(qrk_color c)
{
    return QColor(int(c >> 24), int((c >> 16) & 0xFF), int((c >> 8) & 0xFF), int(c & 0xFF));
}

QString colorName(const QColor &color)
{
    const qrk_color c = toQrkColor(color);
    if ((c & 0xFF) == 0xFF)
        return QString::asprintf("#%06x", unsigned(c >> 8));
    return QString::asprintf("#%08x", unsigned(c));
}

std::optional<QColor> parseColor(const QString &text)
{
    const QByteArray s = text.trimmed().toLatin1();
    qrk_color c;
    if (!qrk_parse_color(s.constData(), size_t(s.size()), &c))
        return std::nullopt;
    return fromQrkColor(c);
}

/* ---- JSON helpers ------------------------------------------------------- */

static QString describeJsonError(const QByteArray &json, qrk_status status)
{
    QJsonParseError pe;
    QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
    if (pe.error != QJsonParseError::NoError)
        return QStringLiteral("JSON syntax error at offset %1: %2").arg(pe.offset).arg(pe.errorString());
    if (!doc.isObject())
        return QStringLiteral("the style must be a JSON object");
    if (status == QRK_ERR_BUFFER_TOO_SMALL)
        return QStringLiteral("string buffer too small");
    return QStringLiteral("invalid style value (unknown shape name, color, gradient type or wrong value type)");
}

static QJsonValue jsonString(const QByteArray &s)
{
    return s.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(QString::fromUtf8(s));
}

/* ---- Paint -------------------------------------------------------------- */

Paint::Paint()
{
    m_paint = qrk_paint_solid(QRK_TRANSPARENT);
    m_paint.type = QRK_PAINT_NONE;
}

Paint::Paint(const QColor &color) : m_paint(qrk_paint_solid(toQrkColor(color))) {}

Paint Paint::none()
{
    return Paint();
}

Paint Paint::solid(const QColor &color)
{
    return Paint(color);
}

Paint Paint::linear(const QGradientStops &stops, double angleDegrees)
{
    Paint p;
    p.m_paint.type = QRK_PAINT_LINEAR;
    p.setStops(stops);
    p.m_paint.angle = angleDegrees;
    return p;
}

Paint Paint::linear(const QColor &from, const QColor &to, double angleDegrees)
{
    return fromRaw(qrk_paint_linear(angleDegrees, toQrkColor(from), toQrkColor(to)));
}

Paint Paint::radial(const QGradientStops &stops, const QPointF &center, double radius)
{
    Paint p;
    p.m_paint.type = QRK_PAINT_RADIAL;
    p.setStops(stops);
    p.m_paint.cx = center.x();
    p.m_paint.cy = center.y();
    p.m_paint.r = radius;
    return p;
}

Paint Paint::radial(const QColor &center, const QColor &edge)
{
    return fromRaw(qrk_paint_radial(toQrkColor(center), toQrkColor(edge)));
}

PaintType Paint::type() const
{
    return PaintType(m_paint.type);
}

QColor Paint::color() const
{
    if (isGradient() && m_paint.stop_count > 0)
        return fromQrkColor(m_paint.stops[0].color);
    return fromQrkColor(m_paint.color);
}

QGradientStops Paint::stops() const
{
    QGradientStops out;
    int n = qMin<int>(m_paint.stop_count, QRK_MAX_STOPS);
    for (int i = 0; i < n; i++)
        out.append(QGradientStop(m_paint.stops[i].offset, fromQrkColor(m_paint.stops[i].color)));
    return out;
}

double Paint::angle() const
{
    return m_paint.angle;
}

QPointF Paint::center() const
{
    return QPointF(m_paint.cx, m_paint.cy);
}

double Paint::radius() const
{
    return m_paint.r;
}

void Paint::setColor(const QColor &color)
{
    m_paint.type = QRK_PAINT_SOLID;
    m_paint.color = toQrkColor(color);
}

void Paint::setStops(const QGradientStops &stops)
{
    int n = qMin(int(stops.size()), QRK_MAX_STOPS);
    m_paint.stop_count = uint8_t(n);
    for (int i = 0; i < n; i++) {
        m_paint.stops[i].offset = stops.at(i).first;
        m_paint.stops[i].color = toQrkColor(stops.at(i).second);
    }
    if (n > 0)
        m_paint.color = m_paint.stops[0].color;
}

void Paint::setAngle(double degrees)
{
    m_paint.angle = degrees;
}

void Paint::setCenter(const QPointF &center)
{
    m_paint.cx = center.x();
    m_paint.cy = center.y();
}

void Paint::setRadius(double radius)
{
    m_paint.r = radius;
}

QJsonValue Paint::toJson() const
{
    switch (type()) {
    case PaintType::None:
        return QJsonValue(QJsonValue::Null);
    case PaintType::Solid:
        return colorName(fromQrkColor(m_paint.color));
    default:
        break;
    }
    QJsonObject o;
    QJsonArray stopArray;
    int n = qMin<int>(m_paint.stop_count, QRK_MAX_STOPS);
    for (int i = 0; i < n; i++) {
        QJsonObject s;
        s.insert(QStringLiteral("offset"), m_paint.stops[i].offset);
        s.insert(QStringLiteral("color"), colorName(fromQrkColor(m_paint.stops[i].color)));
        stopArray.append(s);
    }
    if (type() == PaintType::Linear) {
        o.insert(QStringLiteral("type"), QStringLiteral("linear"));
        o.insert(QStringLiteral("angle"), m_paint.angle);
    } else {
        o.insert(QStringLiteral("type"), QStringLiteral("radial"));
        o.insert(QStringLiteral("cx"), m_paint.cx);
        o.insert(QStringLiteral("cy"), m_paint.cy);
        o.insert(QStringLiteral("r"), m_paint.r);
    }
    o.insert(QStringLiteral("stops"), stopArray);
    return o;
}

Paint Paint::fromJson(const QJsonValue &value, bool *ok)
{
    /* Let the core parse it so that every port agrees on the semantics. */
    QJsonObject modules;
    modules.insert(QStringLiteral("color"), value);
    QJsonObject doc;
    doc.insert(QStringLiteral("modules"), modules);
    const QByteArray json = QJsonDocument(doc).toJson(QJsonDocument::Compact);
    qrk_style s;
    qrk_style_default(&s);
    qrk_status st = qrk_style_from_json(json.constData(), size_t(json.size()), &s, nullptr, nullptr,
                                        nullptr, 0);
    if (ok)
        *ok = st == QRK_OK;
    return st == QRK_OK ? fromRaw(s.modules.paint) : Paint();
}

Paint Paint::fromRaw(const qrk_paint &paint)
{
    Paint p;
    p.m_paint = paint;
    if (p.m_paint.stop_count > QRK_MAX_STOPS)
        p.m_paint.stop_count = QRK_MAX_STOPS;
    return p;
}

bool Paint::operator==(const Paint &o) const
{
    const qrk_paint &a = m_paint, &b = o.m_paint;
    if (a.type != b.type)
        return false;
    switch (a.type) {
    case QRK_PAINT_NONE:
        return true;
    case QRK_PAINT_SOLID:
        return a.color == b.color;
    case QRK_PAINT_LINEAR:
        if (a.angle != b.angle)
            return false;
        break;
    default:
        if (a.cx != b.cx || a.cy != b.cy || a.r != b.r)
            return false;
        break;
    }
    if (a.stop_count != b.stop_count)
        return false;
    for (int i = 0; i < a.stop_count && i < QRK_MAX_STOPS; i++)
        if (a.stops[i].offset != b.stops[i].offset || a.stops[i].color != b.stops[i].color)
            return false;
    return true;
}

/* ---- Style -------------------------------------------------------------- */

class StyleData : public QSharedData
{
public:
    StyleData()
    {
        qrk_style_default(&s);
        labelFont = QByteArray(s.label.font);
        detachStrings();
    }

    /* The struct never keeps string pointers: toRaw() re-attaches them. */
    void detachStrings()
    {
        s.logo.href = nullptr;
        s.label.text = nullptr;
        s.label.font = nullptr;
    }

    qrk_style s;
    QByteArray href, labelText, labelFont;
};

Style::Style() : d(new StyleData) {}
Style::Style(const Style &other) = default;
Style::Style(Style &&other) noexcept = default;
Style &Style::operator=(const Style &other) = default;
Style &Style::operator=(Style &&other) noexcept = default;
Style::~Style() = default;

qrk_style Style::toRaw() const
{
    qrk_style s = d->s;
    s.logo.href = d->href.isNull() ? nullptr : d->href.constData();
    s.label.text = d->labelText.isNull() ? nullptr : d->labelText.constData();
    s.label.font = d->labelFont.isNull() ? nullptr : d->labelFont.constData();
    return s;
}

Style Style::fromRaw(const qrk_style &style)
{
    Style out;
    StyleData *data = out.d.data();
    data->s = style;
    data->href = style.logo.href ? QByteArray(style.logo.href) : QByteArray();
    data->labelText = style.label.text ? QByteArray(style.label.text) : QByteArray();
    data->labelFont = style.label.font ? QByteArray(style.label.font) : QByteArray();
    data->detachStrings();
    for (qrk_paint *p : {&data->s.modules.paint, &data->s.eyes.frame_paint, &data->s.eyes.ball_paint,
                         &data->s.background.paint})
        if (p->stop_count > QRK_MAX_STOPS)
            p->stop_count = QRK_MAX_STOPS;
    return out;
}

Style Style::fromJson(const QByteArray &json, bool *ok, QString *errorString)
{
    qrk_style s;
    qrk_style_default(&s);
    /* Decoded strings are never longer than their JSON source. */
    QByteArray arena(json.size() + 16, '\0');
    qrk_status st = qrk_style_from_json(json.constData(), size_t(json.size()), &s, nullptr, nullptr,
                                        arena.data(), size_t(arena.size()));
    if (ok)
        *ok = st == QRK_OK;
    if (st != QRK_OK) {
        if (errorString)
            *errorString = describeJsonError(json, st);
        return Style();
    }
    if (errorString)
        errorString->clear();
    return fromRaw(s); /* copies the strings out of the arena */
}

Style Style::fromJson(const QJsonObject &json, bool *ok, QString *errorString)
{
    return fromJson(QJsonDocument(json).toJson(QJsonDocument::Compact), ok, errorString);
}

static QJsonValue eyeShapeJson(uint8_t shape, bool allowNull)
{
    if (shape >= QRK_EYE_SHAPE_COUNT)
        return allowNull ? QJsonValue(QJsonValue::Null) : QJsonValue(QStringLiteral("square"));
    return QString::fromLatin1(qrk_eye_shape_name(shape));
}

QJsonObject Style::toJson() const
{
    const qrk_style &s = d->s;
    QJsonObject o;
    o.insert(QStringLiteral("margin"), s.margin);

    QJsonObject modules;
    const char *shape = qrk_module_shape_name(s.modules.shape);
    modules.insert(QStringLiteral("shape"), QString::fromLatin1(shape ? shape : "square"));
    modules.insert(QStringLiteral("size"), s.modules.size);
    modules.insert(QStringLiteral("roundness"), s.modules.roundness);
    modules.insert(QStringLiteral("color"), Paint::fromRaw(s.modules.paint).toJson());
    o.insert(QStringLiteral("modules"), modules);

    QJsonObject eyes;
    eyes.insert(QStringLiteral("frame"), eyeShapeJson(s.eyes.frame, false));
    eyes.insert(QStringLiteral("ball"), eyeShapeJson(s.eyes.ball, false));
    eyes.insert(QStringLiteral("frameColor"), Paint::fromRaw(s.eyes.frame_paint).toJson());
    eyes.insert(QStringLiteral("ballColor"), Paint::fromRaw(s.eyes.ball_paint).toJson());
    o.insert(QStringLiteral("eyes"), eyes);

    QJsonObject alignment;
    alignment.insert(QStringLiteral("frame"), eyeShapeJson(s.alignment.frame, true));
    alignment.insert(QStringLiteral("ball"), eyeShapeJson(s.alignment.ball, true));
    o.insert(QStringLiteral("alignment"), alignment);

    QJsonObject background;
    background.insert(QStringLiteral("color"), Paint::fromRaw(s.background.paint).toJson());
    background.insert(QStringLiteral("radius"), s.background.radius);
    o.insert(QStringLiteral("background"), background);

    QJsonObject border;
    border.insert(QStringLiteral("width"), s.border.width);
    border.insert(QStringLiteral("color"), colorName(fromQrkColor(s.border.color)));
    o.insert(QStringLiteral("border"), border);

    QJsonObject logo;
    logo.insert(QStringLiteral("href"), jsonString(d->href));
    logo.insert(QStringLiteral("size"), s.logo.size);
    logo.insert(QStringLiteral("margin"), s.logo.margin);
    logo.insert(QStringLiteral("shape"), logoShapeName(LogoShape(s.logo.shape)));
    logo.insert(QStringLiteral("excavate"), s.logo.excavate);
    logo.insert(QStringLiteral("background"),
                s.logo.background == QRK_TRANSPARENT
                    ? QJsonValue(QJsonValue::Null)
                    : QJsonValue(colorName(fromQrkColor(s.logo.background))));
    o.insert(QStringLiteral("logo"), logo);

    QJsonObject label;
    label.insert(QStringLiteral("text"), QString::fromUtf8(d->labelText));
    label.insert(QStringLiteral("font"), jsonString(d->labelFont));
    label.insert(QStringLiteral("size"), s.label.size);
    label.insert(QStringLiteral("color"), colorName(fromQrkColor(s.label.color)));
    label.insert(QStringLiteral("position"), s.label.position == QRK_LABEL_TOP ? QStringLiteral("top")
                                                                              : QStringLiteral("bottom"));
    label.insert(QStringLiteral("bold"), s.label.bold);
    o.insert(QStringLiteral("label"), label);
    return o;
}

QByteArray Style::toJsonData(QJsonDocument::JsonFormat format) const
{
    return QJsonDocument(toJson()).toJson(format);
}

double Style::margin() const { return d->s.margin; }
void Style::setMargin(double modules) { d->s.margin = modules; }

ModuleShape Style::moduleShape() const
{
    return d->s.modules.shape < QRK_MODULE_SHAPE_COUNT ? ModuleShape(d->s.modules.shape) : ModuleShape::Square;
}
void Style::setModuleShape(ModuleShape shape) { d->s.modules.shape = uint8_t(shape); }
double Style::moduleSize() const { return d->s.modules.size; }
void Style::setModuleSize(double size) { d->s.modules.size = size; }
double Style::moduleRoundness() const { return d->s.modules.roundness; }
void Style::setModuleRoundness(double roundness) { d->s.modules.roundness = roundness; }
Paint Style::modulePaint() const { return Paint::fromRaw(d->s.modules.paint); }
void Style::setModulePaint(const Paint &paint) { d->s.modules.paint = paint.raw(); }

static EyeShape eyeShapeOf(uint8_t v, EyeShape fallback)
{
    return v < QRK_EYE_SHAPE_COUNT ? EyeShape(v) : fallback;
}

static uint8_t eyeValue(EyeShape shape, bool allowNone)
{
    uint8_t v = uint8_t(shape);
    if (v < QRK_EYE_SHAPE_COUNT)
        return v;
    return allowNone ? uint8_t(QRK_EYE_NONE) : uint8_t(QRK_EYE_SQUARE);
}

EyeShape Style::eyeFrame() const { return eyeShapeOf(d->s.eyes.frame, EyeShape::Square); }
void Style::setEyeFrame(EyeShape shape) { d->s.eyes.frame = eyeValue(shape, false); }
EyeShape Style::eyeBall() const { return eyeShapeOf(d->s.eyes.ball, EyeShape::Square); }
void Style::setEyeBall(EyeShape shape) { d->s.eyes.ball = eyeValue(shape, false); }
Paint Style::eyeFramePaint() const { return Paint::fromRaw(d->s.eyes.frame_paint); }
void Style::setEyeFramePaint(const Paint &paint) { d->s.eyes.frame_paint = paint.raw(); }
Paint Style::eyeBallPaint() const { return Paint::fromRaw(d->s.eyes.ball_paint); }
void Style::setEyeBallPaint(const Paint &paint) { d->s.eyes.ball_paint = paint.raw(); }

EyeShape Style::alignmentFrame() const { return eyeShapeOf(d->s.alignment.frame, EyeShape::None); }
void Style::setAlignmentFrame(EyeShape shape) { d->s.alignment.frame = eyeValue(shape, true); }
EyeShape Style::alignmentBall() const { return eyeShapeOf(d->s.alignment.ball, EyeShape::None); }
void Style::setAlignmentBall(EyeShape shape) { d->s.alignment.ball = eyeValue(shape, true); }

Paint Style::background() const { return Paint::fromRaw(d->s.background.paint); }
void Style::setBackground(const Paint &paint) { d->s.background.paint = paint.raw(); }
double Style::backgroundRadius() const { return d->s.background.radius; }
void Style::setBackgroundRadius(double modules) { d->s.background.radius = modules; }

double Style::borderWidth() const { return d->s.border.width; }
void Style::setBorderWidth(double modules) { d->s.border.width = modules; }
QColor Style::borderColor() const { return fromQrkColor(d->s.border.color); }
void Style::setBorderColor(const QColor &color) { d->s.border.color = toQrkColor(color); }

double Style::logoSize() const { return d->s.logo.size; }
void Style::setLogoSize(double fraction) { d->s.logo.size = fraction; }
double Style::logoMargin() const { return d->s.logo.margin; }
void Style::setLogoMargin(double modules) { d->s.logo.margin = modules; }
LogoShape Style::logoShape() const
{
    return d->s.logo.shape <= QRK_LOGO_CIRCLE ? LogoShape(d->s.logo.shape) : LogoShape::Square;
}
void Style::setLogoShape(LogoShape shape) { d->s.logo.shape = uint8_t(shape); }
bool Style::logoExcavate() const { return d->s.logo.excavate; }
void Style::setLogoExcavate(bool excavate) { d->s.logo.excavate = excavate; }
QColor Style::logoBackground() const { return fromQrkColor(d->s.logo.background); }
void Style::setLogoBackground(const QColor &color) { d->s.logo.background = toQrkColor(color); }
QString Style::logoHref() const { return QString::fromUtf8(d->href); }
void Style::setLogoHref(const QString &href) { d->href = href.isNull() ? QByteArray() : href.toUtf8(); }

QString Style::labelText() const { return QString::fromUtf8(d->labelText); }
void Style::setLabelText(const QString &text) { d->labelText = text.isNull() ? QByteArray() : text.toUtf8(); }
QString Style::labelFont() const { return QString::fromUtf8(d->labelFont); }
void Style::setLabelFont(const QString &family)
{
    d->labelFont = family.isNull() ? QByteArray() : family.toUtf8();
}
double Style::labelSize() const { return d->s.label.size; }
void Style::setLabelSize(double modules) { d->s.label.size = modules; }
QColor Style::labelColor() const { return fromQrkColor(d->s.label.color); }
void Style::setLabelColor(const QColor &color) { d->s.label.color = toQrkColor(color); }
LabelPosition Style::labelPosition() const
{
    return d->s.label.position == QRK_LABEL_TOP ? LabelPosition::Top : LabelPosition::Bottom;
}
void Style::setLabelPosition(LabelPosition position) { d->s.label.position = uint8_t(position); }
bool Style::labelBold() const { return d->s.label.bold; }
void Style::setLabelBold(bool bold) { d->s.label.bold = bold; }

Ecc Style::recommendedEcc() const
{
    const qrk_style s = toRaw();
    return Ecc(qrk_recommended_ecc(&s));
}

bool Style::operator==(const Style &other) const
{
    if (d == other.d)
        return true;
    const qrk_style &a = d->s, &b = other.d->s;
    return a.margin == b.margin && a.modules.shape == b.modules.shape &&
           a.modules.size == b.modules.size && a.modules.roundness == b.modules.roundness &&
           Paint::fromRaw(a.modules.paint) == Paint::fromRaw(b.modules.paint) &&
           a.eyes.frame == b.eyes.frame && a.eyes.ball == b.eyes.ball &&
           Paint::fromRaw(a.eyes.frame_paint) == Paint::fromRaw(b.eyes.frame_paint) &&
           Paint::fromRaw(a.eyes.ball_paint) == Paint::fromRaw(b.eyes.ball_paint) &&
           a.alignment.frame == b.alignment.frame && a.alignment.ball == b.alignment.ball &&
           Paint::fromRaw(a.background.paint) == Paint::fromRaw(b.background.paint) &&
           a.background.radius == b.background.radius && a.border.width == b.border.width &&
           a.border.color == b.border.color && a.logo.size == b.logo.size &&
           a.logo.margin == b.logo.margin && a.logo.shape == b.logo.shape &&
           a.logo.excavate == b.logo.excavate && a.logo.background == b.logo.background &&
           d->href == other.d->href && d->labelText == other.d->labelText &&
           d->labelFont == other.d->labelFont && a.label.size == b.label.size &&
           a.label.color == b.label.color && a.label.position == b.label.position &&
           a.label.bold == b.label.bold;
}

/* ---- EncodeOptions / SvgOptions ----------------------------------------- */

EncodeOptions EncodeOptions::fromJson(const QByteArray &json, bool *ok)
{
    qrk_encode_opts e;
    qrk_encode_opts_default(&e);
    qrk_status st = qrk_style_from_json(json.constData(), size_t(json.size()), nullptr, &e, nullptr,
                                        nullptr, 0);
    if (ok)
        *ok = st == QRK_OK;
    EncodeOptions out;
    if (st != QRK_OK)
        return out;
    /* The core always fills a level; the default rule needs to know whether
     * the document specified one. */
    const QJsonObject encode =
        QJsonDocument::fromJson(json).object().value(QStringLiteral("encode")).toObject();
    if (encode.contains(QStringLiteral("ecc")))
        out.ecc = Ecc(e.ecc);
    out.minVersion = e.min_version;
    out.maxVersion = e.max_version;
    out.mask = e.mask;
    out.boostEcc = e.boost_ecc;
    out.eci = e.eci;
    return out;
}

QJsonObject EncodeOptions::toJson() const
{
    QJsonObject o;
    if (ecc)
        o.insert(QStringLiteral("ecc"), eccName(*ecc));
    o.insert(QStringLiteral("minVersion"), minVersion);
    o.insert(QStringLiteral("maxVersion"), maxVersion);
    o.insert(QStringLiteral("mask"), mask);
    o.insert(QStringLiteral("boostEcc"), boostEcc);
    o.insert(QStringLiteral("eci"), eci);
    return o;
}

qrk_encode_opts EncodeOptions::toRaw(const Style &style) const
{
    qrk_encode_opts o;
    qrk_encode_opts_default(&o);
    o.ecc = ecc ? qrk_ecc(*ecc) : qrk_ecc(style.recommendedEcc());
    o.min_version = minVersion;
    o.max_version = maxVersion;
    o.mask = mask;
    o.boost_ecc = boostEcc;
    o.eci = eci;
    return o;
}

SvgOptions SvgOptions::fromJson(const QByteArray &json, bool *ok)
{
    qrk_svg_opts o;
    qrk_svg_opts_default(&o);
    QByteArray arena(json.size() + 16, '\0');
    qrk_status st = qrk_style_from_json(json.constData(), size_t(json.size()), nullptr, nullptr, &o,
                                        arena.data(), size_t(arena.size()));
    if (ok)
        *ok = st == QRK_OK;
    SvgOptions out;
    if (st != QRK_OK)
        return out;
    out.width = o.width;
    if (o.id_prefix && std::strcmp(o.id_prefix, "qrk") != 0)
        out.idPrefix = QString::fromUtf8(o.id_prefix);
    return out;
}

QJsonObject SvgOptions::toJson() const
{
    QJsonObject o;
    o.insert(QStringLiteral("width"), width);
    if (!idPrefix.isEmpty())
        o.insert(QStringLiteral("idPrefix"), idPrefix);
    return o;
}

} // namespace QRKude
