/*
 * QRKude - style defaults, layout, shape model and vector geometry.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <math.h>
#include <string.h>

#include "qrk_internal.h"

/* ---- names --------------------------------------------------------------- */

static const char *const MODULE_SHAPE_NAMES[QRK_MODULE_SHAPE_COUNT] = {
    "square", "dot", "rounded", "diamond", "star", "fluid",
    "liquid", "bevel", "classy", "hbars", "vbars",
};

static const char *const EYE_SHAPE_NAMES[QRK_EYE_SHAPE_COUNT] = {
    "square", "rounded", "circle", "leaf", "drop", "bevel", "diamond", "dots",
};

int qrk_module_shape_from_name(const char *name)
{
    for (int i = 0; name && i < QRK_MODULE_SHAPE_COUNT; i++)
        if (strcmp(name, MODULE_SHAPE_NAMES[i]) == 0)
            return i;
    return -1;
}

const char *qrk_module_shape_name(int shape)
{
    return shape >= 0 && shape < QRK_MODULE_SHAPE_COUNT ? MODULE_SHAPE_NAMES[shape] : NULL;
}

int qrk_eye_shape_from_name(const char *name)
{
    for (int i = 0; name && i < QRK_EYE_SHAPE_COUNT; i++)
        if (strcmp(name, EYE_SHAPE_NAMES[i]) == 0)
            return i;
    return -1;
}

const char *qrk_eye_shape_name(int shape)
{
    return shape >= 0 && shape < QRK_EYE_SHAPE_COUNT ? EYE_SHAPE_NAMES[shape] : NULL;
}

/* ---- colors and paints --------------------------------------------------- */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool qrk_parse_color(const char *s, size_t len, qrk_color *out)
{
    if (len == 11 && strncmp(s, "transparent", 11) == 0) {
        *out = QRK_TRANSPARENT;
        return true;
    }
    if (len < 1 || s[0] != '#')
        return false;
    uint32_t v = 0;
    for (size_t i = 1; i < len; i++) {
        int d = hex_digit(s[i]);
        if (d < 0)
            return false;
        v = v << 4 | (uint32_t)d;
    }
    switch (len) {
    case 4: /* #rgb */
        *out = QRK_RGB(((v >> 8) & 15) * 17, ((v >> 4) & 15) * 17, (v & 15) * 17);
        return true;
    case 7:
        *out = (v << 8) | 0xFF;
        return true;
    case 9:
        *out = v;
        return true;
    default:
        return false;
    }
}

qrk_paint qrk_paint_solid(qrk_color color)
{
    qrk_paint p;
    memset(&p, 0, sizeof p);
    p.type = QRK_PAINT_SOLID;
    p.color = color;
    p.cx = p.cy = 0.5;
    p.r = 0.75;
    return p;
}

qrk_paint qrk_paint_linear(double angle_deg, qrk_color from, qrk_color to)
{
    qrk_paint p = qrk_paint_solid(from);
    p.type = QRK_PAINT_LINEAR;
    p.angle = angle_deg;
    p.stop_count = 2;
    p.stops[0].offset = 0;
    p.stops[0].color = from;
    p.stops[1].offset = 1;
    p.stops[1].color = to;
    return p;
}

qrk_paint qrk_paint_radial(qrk_color center, qrk_color edge)
{
    qrk_paint p = qrk_paint_linear(0, center, edge);
    p.type = QRK_PAINT_RADIAL;
    return p;
}

void qrk_style_default(qrk_style *s)
{
    memset(s, 0, sizeof *s);
    s->margin = 4;
    s->modules.shape = QRK_MODULE_SQUARE;
    s->modules.size = 1;
    s->modules.roundness = 1;
    s->modules.paint = qrk_paint_solid(QRK_HEX(0x000000));
    s->eyes.frame = QRK_EYE_SQUARE;
    s->eyes.ball = QRK_EYE_SQUARE;
    s->alignment.frame = QRK_EYE_NONE;
    s->alignment.ball = QRK_EYE_NONE;
    s->background.paint = qrk_paint_solid(QRK_HEX(0xFFFFFF));
    s->border.color = QRK_HEX(0x000000);
    s->logo.size = 0;
    s->logo.margin = 1;
    s->logo.shape = QRK_LOGO_SQUARE;
    s->logo.excavate = true;
    s->label.font = "sans-serif";
    s->label.size = 4;
    s->label.color = QRK_HEX(0x000000);
    s->label.position = QRK_LABEL_BOTTOM;
    s->label.bold = true;
}

qrk_ecc qrk_recommended_ecc(const qrk_style *style)
{
    return style && style->logo.size > 0 ? QRK_ECC_HIGH : QRK_ECC_MEDIUM;
}

/* ---- layout -------------------------------------------------------------- */

void qrk__layout_init(qrk__layout *L, const qrk_code *code, const qrk_style *s)
{
    memset(L, 0, sizeof *L);
    L->code = code;
    L->style = s;
    int n = L->n = code->size;

    L->margin = s->margin > 0 ? s->margin : 0;
    L->border = s->border.width > 0 ? s->border.width : 0;
    L->shape = s->modules.shape < QRK_MODULE_SHAPE_COUNT ? s->modules.shape : QRK_MODULE_SQUARE;
    L->size = qrk__clamp(s->modules.size, 0.1, 1);
    L->roundness = qrk__clamp(s->modules.roundness, 0, 1);

    double frame = L->margin + L->border;
    L->W = n + 2 * frame;
    L->H = L->W;
    L->ox = frame;
    L->oy = frame;

    L->has_label = s->label.text && s->label.text[0];
    if (L->has_label) {
        double f = s->label.size > 0.1 ? s->label.size : 0.1;
        L->band_h = f * 1.5;
        L->H += L->band_h;
        if (s->label.position == QRK_LABEL_TOP) {
            L->band_y = L->border;
            L->oy += L->band_h;
        } else {
            L->band_y = L->W - L->border;
        }
        L->label_x = L->W / 2;
        L->label_baseline = L->band_y + f * 1.1;
    }
    double min_side = L->W < L->H ? L->W : L->H;
    L->bg_radius = qrk__clamp(s->background.radius, 0, min_side / 2);

    L->has_logo = s->logo.size > 0;
    if (L->has_logo) {
        L->excavate = s->logo.excavate;
        L->logo_cx = L->ox + n / 2.0;
        L->logo_cy = L->oy + n / 2.0;
        L->logo_half = n * qrk__clamp(s->logo.size, 0, 1) / 2;
        L->logo_area_half = L->logo_half + (s->logo.margin > 0 ? s->logo.margin : 0);
    }

    L->align_styled = s->alignment.frame < QRK_EYE_SHAPE_COUNT;
    if (L->align_styled)
        L->align_count = qrk__alignment_positions(code->version, L->align_pos);
}

void qrk_get_layout(const qrk_code *code, const qrk_style *style, qrk_layout *out)
{
    qrk__layout L;
    qrk__layout_init(&L, code, style);
    out->width = L.W;
    out->height = L.H;
    out->symbol_x = L.ox;
    out->symbol_y = L.oy;
    out->modules = L.n;
    out->has_logo = L.has_logo;
    out->logo_x = L.logo_cx - L.logo_half;
    out->logo_y = L.logo_cy - L.logo_half;
    out->logo_size = 2 * L.logo_half;
    out->has_label = L.has_label;
    out->label_x = L.label_x;
    out->label_baseline = L.label_baseline;
}

bool qrk__is_finder(int n, int x, int y)
{
    return (x < 7 && y < 7) || (x >= n - 7 && y < 7) || (x < 7 && y >= n - 7);
}

static bool is_alignment_center(int k, int i, int j)
{
    return !((i == 0 && j == 0) || (i == 0 && j == k - 1) || (i == k - 1 && j == 0));
}

bool qrk__in_styled_alignment(const qrk__layout *L, int x, int y)
{
    if (!L->align_styled)
        return false;
    int k = L->align_count;
    for (int i = 0; i < k; i++) {
        int dy = y - L->align_pos[i];
        if (dy < -2 || dy > 2)
            continue;
        for (int j = 0; j < k; j++) {
            int dx = x - L->align_pos[j];
            if (dx >= -2 && dx <= 2 && is_alignment_center(k, i, j))
                return true;
        }
    }
    return false;
}

/* Module overlaps the logo area (box + margin). Used for excavation and for
 * the damage estimate. */
static bool in_logo_area(const qrk__layout *L, int x, int y)
{
    double c = L->n / 2.0, h = L->logo_area_half;
    double dx = fabs(x + 0.5 - c), dy = fabs(y + 0.5 - c);
    if (L->style->logo.shape == QRK_LOGO_CIRCLE) {
        double nx = dx - 0.5 > 0 ? dx - 0.5 : 0;
        double ny = dy - 0.5 > 0 ? dy - 0.5 : 0;
        return nx * nx + ny * ny < h * h;
    }
    return dx < h + 0.5 && dy < h + 0.5;
}

bool qrk__is_excavated(const qrk__layout *L, int x, int y)
{
    return L->excavate && in_logo_area(L, x, y);
}

bool qrk__is_data_cell(const qrk__layout *L, int x, int y)
{
    int n = L->n;
    if (x < 0 || y < 0 || x >= n || y >= n)
        return false;
    return !qrk__is_finder(n, x, y) && !qrk__in_styled_alignment(L, x, y) &&
           !qrk__is_excavated(L, x, y);
}

bool qrk__is_data_dark(const qrk__layout *L, int x, int y)
{
    return qrk_get_module(L->code, x, y) && qrk__is_data_cell(L, x, y);
}

/* ---- shape model --------------------------------------------------------- */

static void set_corners(qrk__corner c[4], uint8_t kind, double a)
{
    for (int i = 0; i < 4; i++) {
        c[i].kind = kind;
        c[i].a = a;
    }
}

bool qrk__module_crect(const qrk__layout *L, int x, int y, qrk__crect *r)
{
    double s = L->size, d = (1 - s) / 2, rho = L->roundness;
    r->x0 = d;
    r->y0 = d;
    r->x1 = 1 - d;
    r->y1 = 1 - d;
    set_corners(r->c, QRK_CORNER_NONE, 0);

    switch (L->shape) {
    case QRK_MODULE_SQUARE:
        return true;
    case QRK_MODULE_DOT:
        set_corners(r->c, QRK_CORNER_ROUND, s / 2);
        return true;
    case QRK_MODULE_ROUNDED:
        set_corners(r->c, QRK_CORNER_ROUND, rho * s / 2);
        return true;
    case QRK_MODULE_DIAMOND:
        set_corners(r->c, QRK_CORNER_CHAMFER, s / 2);
        return true;
    case QRK_MODULE_STAR:
        return false;
    case QRK_MODULE_HBARS: {
        bool l = qrk__is_data_dark(L, x - 1, y), rt = qrk__is_data_dark(L, x + 1, y);
        if (l) r->x0 = 0;
        if (rt) r->x1 = 1;
        double a = rho * s / 2;
        if (!l) { r->c[QRK_TL].kind = r->c[QRK_BL].kind = QRK_CORNER_ROUND; r->c[QRK_TL].a = r->c[QRK_BL].a = a; }
        if (!rt) { r->c[QRK_TR].kind = r->c[QRK_BR].kind = QRK_CORNER_ROUND; r->c[QRK_TR].a = r->c[QRK_BR].a = a; }
        return true;
    }
    case QRK_MODULE_VBARS: {
        bool u = qrk__is_data_dark(L, x, y - 1), dn = qrk__is_data_dark(L, x, y + 1);
        if (u) r->y0 = 0;
        if (dn) r->y1 = 1;
        double a = rho * s / 2;
        if (!u) { r->c[QRK_TL].kind = r->c[QRK_TR].kind = QRK_CORNER_ROUND; r->c[QRK_TL].a = r->c[QRK_TR].a = a; }
        if (!dn) { r->c[QRK_BL].kind = r->c[QRK_BR].kind = QRK_CORNER_ROUND; r->c[QRK_BL].a = r->c[QRK_BR].a = a; }
        return true;
    }
    default: break;
    }

    /* connected shapes always fill the whole cell */
    r->x0 = r->y0 = 0;
    r->x1 = r->y1 = 1;
    bool up = qrk__is_data_dark(L, x, y - 1), down = qrk__is_data_dark(L, x, y + 1);
    bool left = qrk__is_data_dark(L, x - 1, y), right = qrk__is_data_dark(L, x + 1, y);
    bool open[4] = {!up && !left, !up && !right, !down && !right, !down && !left};
    uint8_t kind = L->shape == QRK_MODULE_BEVEL ? QRK_CORNER_CHAMFER : QRK_CORNER_ROUND;
    for (int i = 0; i < 4; i++) {
        bool use = open[i];
        if (L->shape == QRK_MODULE_CLASSY && (i == QRK_TR || i == QRK_BL))
            use = false;
        if (use) {
            r->c[i].kind = kind;
            r->c[i].a = rho / 2;
        }
    }
    return true;
}

int qrk__fillet_mask(const qrk__layout *L, int x, int y)
{
    if (L->shape != QRK_MODULE_LIQUID || L->roundness <= 0)
        return 0;
    bool up = qrk__is_data_dark(L, x, y - 1), down = qrk__is_data_dark(L, x, y + 1);
    bool left = qrk__is_data_dark(L, x - 1, y), right = qrk__is_data_dark(L, x + 1, y);
    int m = 0;
    if (up && left && qrk__is_data_dark(L, x - 1, y - 1)) m |= 1 << QRK_TL;
    if (up && right && qrk__is_data_dark(L, x + 1, y - 1)) m |= 1 << QRK_TR;
    if (down && right && qrk__is_data_dark(L, x + 1, y + 1)) m |= 1 << QRK_BR;
    if (down && left && qrk__is_data_dark(L, x - 1, y + 1)) m |= 1 << QRK_BL;
    return m;
}

void qrk__eye_corners(int shape, double s, int cc, qrk__corner c[4])
{
    set_corners(c, QRK_CORNER_NONE, 0);
    switch (shape) {
    case QRK_EYE_ROUNDED: set_corners(c, QRK_CORNER_ROUND, s * 0.25); break;
    case QRK_EYE_CIRCLE: set_corners(c, QRK_CORNER_ROUND, s / 2); break;
    /* leaf/drop use 0.36 * s: fully rounded versions break finder detection */
    case QRK_EYE_LEAF:
        c[cc].kind = c[(cc + 2) % 4].kind = QRK_CORNER_ROUND;
        c[cc].a = c[(cc + 2) % 4].a = s * 0.36;
        break;
    case QRK_EYE_DROP:
        set_corners(c, QRK_CORNER_ROUND, s * 0.36);
        c[cc].kind = QRK_CORNER_NONE;
        c[cc].a = 0;
        break;
    case QRK_EYE_BEVEL: set_corners(c, QRK_CORNER_CHAMFER, s * 0.25); break;
    case QRK_EYE_DIAMOND: set_corners(c, QRK_CORNER_CHAMFER, s / 2); break;
    default: break;
    }
}

int qrk__ball_shape(int shape)
{
    /* a grid of dots breaks the 1:1:3:1:1 finder ratio: draw a circle */
    if (shape == QRK_EYE_DOTS)
        return QRK_EYE_CIRCLE;
    return shape < QRK_EYE_SHAPE_COUNT ? shape : QRK_EYE_SQUARE;
}

void qrk__inner_corners(const qrk__corner outer[4], double s_inner, qrk__corner out[4])
{
    for (int i = 0; i < 4; i++) {
        double a = outer[i].a;
        if (outer[i].kind == QRK_CORNER_ROUND)
            a -= 1;
        else if (outer[i].kind == QRK_CORNER_CHAMFER)
            a -= 2 - sqrt(2.0);
        a = qrk__clamp(a, 0, s_inner / 2);
        out[i].kind = a > 0 ? outer[i].kind : QRK_CORNER_NONE;
        out[i].a = a > 0 ? a : 0;
    }
}

void qrk__logo_bg_crect(const qrk__layout *L, qrk__crect *r)
{
    double h = L->logo_area_half;
    r->x0 = L->logo_cx - h;
    r->y0 = L->logo_cy - h;
    r->x1 = L->logo_cx + h;
    r->y1 = L->logo_cy + h;
    switch (L->style->logo.shape) {
    case QRK_LOGO_ROUNDED: set_corners(r->c, QRK_CORNER_ROUND, h * 0.3); break;
    case QRK_LOGO_CIRCLE: set_corners(r->c, QRK_CORNER_ROUND, h); break;
    default: set_corners(r->c, QRK_CORNER_NONE, 0); break;
    }
}

/* ---- paints -------------------------------------------------------------- */

qrk_paint qrk__resolve_paint(const qrk_style *s, int layer)
{
    switch (layer) {
    case QRK_LAYER_BACKGROUND: return s->background.paint;
    case QRK_LAYER_BORDER: return qrk_paint_solid(s->border.color);
    case QRK_LAYER_EYE_FRAMES:
        return s->eyes.frame_paint.type != QRK_PAINT_NONE ? s->eyes.frame_paint : s->modules.paint;
    case QRK_LAYER_EYE_BALLS:
        return s->eyes.ball_paint.type != QRK_PAINT_NONE ? s->eyes.ball_paint : s->modules.paint;
    case QRK_LAYER_LOGO_BACKGROUND: return qrk_paint_solid(s->logo.background);
    default: return s->modules.paint;
    }
}

bool qrk_layer_visible(const qrk_code *code, const qrk_style *style, qrk_layer layer)
{
    qrk_paint p = qrk__resolve_paint(style, layer);
    bool painted = p.type == QRK_PAINT_LINEAR || p.type == QRK_PAINT_RADIAL ||
                   (p.type == QRK_PAINT_SOLID && (p.color & 0xFF) != 0);
    switch (layer) {
    case QRK_LAYER_BORDER: return painted && style->border.width > 0;
    case QRK_LAYER_LOGO_BACKGROUND: return painted && style->logo.size > 0;
    case QRK_LAYER_MODULES: return painted && qrk_emit_layer(code, style, layer, NULL, NULL) > 0;
    default: return painted;
    }
}

qrk_paint qrk_layer_paint(const qrk_style *style, qrk_layer layer)
{
    return qrk__resolve_paint(style, layer);
}

void qrk__gradient_geometry(const qrk__layout *L, int layer, const qrk_paint *p,
                            qrk_gradient_geometry *g)
{
    double ax, ay, aw, ah;
    if (layer == QRK_LAYER_BACKGROUND) {
        ax = 0; ay = 0; aw = L->W; ah = L->H;
    } else {
        ax = L->ox; ay = L->oy; aw = L->n; ah = L->n;
    }
    double cx = ax + aw / 2, cy = ay + ah / 2;

    double a = fmod(p->angle, 360.0);
    if (a < 0)
        a += 360.0;
    double dx, dy;
    if (a == 0) { dx = 1; dy = 0; }
    else if (a == 90) { dx = 0; dy = 1; }
    else if (a == 180) { dx = -1; dy = 0; }
    else if (a == 270) { dx = 0; dy = -1; }
    else {
        double rad = a * 3.14159265358979323846 / 180.0;
        dx = cos(rad);
        dy = sin(rad);
    }
    double half = (fabs(dx) * aw + fabs(dy) * ah) / 2;
    g->x1 = cx - dx * half;
    g->y1 = cy - dy * half;
    g->x2 = cx + dx * half;
    g->y2 = cy + dy * half;

    g->cx = ax + aw * p->cx;
    g->cy = ay + ah * p->cy;
    g->r = p->r * (aw > ah ? aw : ah);
}

void qrk_gradient_geometry_for(const qrk_code *code, const qrk_style *style, qrk_layer layer,
                               qrk_gradient_geometry *out)
{
    qrk__layout L;
    qrk__layout_init(&L, code, style);
    qrk_paint p = qrk__resolve_paint(style, layer);
    qrk__gradient_geometry(&L, layer, &p, out);
}

/* ---- path emitter -------------------------------------------------------- */

/* Normalizes the command stream so that every sink (and every port) sees the
 * same thing: zero-length lines are dropped and a line that returns to the
 * sub-path start right before close is omitted. */
typedef struct {
    const qrk_path_sink *sink;
    void *user;
    double sx, sy, cx, cy;
    bool pending;
    double px, py;
    int count;
} emitter;

static void em_flush(emitter *e)
{
    if (e->pending) {
        if (e->sink)
            e->sink->line_to(e->user, e->px, e->py);
        e->pending = false;
    }
}

static void em_move(emitter *e, double x, double y)
{
    em_flush(e);
    e->sx = e->cx = x;
    e->sy = e->cy = y;
    e->count++;
    if (e->sink)
        e->sink->move_to(e->user, x, y);
}

static void em_line(emitter *e, double x, double y)
{
    if (x == e->cx && y == e->cy)
        return;
    em_flush(e);
    e->pending = true;
    e->px = e->cx = x;
    e->py = e->cy = y;
}

static void em_arc(emitter *e, double r, bool cw, double x, double y, double ccx, double ccy)
{
    em_flush(e);
    e->cx = x;
    e->cy = y;
    if (e->sink)
        e->sink->arc_to(e->user, r, cw, x, y, ccx, ccy);
}

static void em_close(emitter *e)
{
    if (e->pending && !(e->px == e->sx && e->py == e->sy))
        em_flush(e);
    e->pending = false;
    e->cx = e->sx;
    e->cy = e->sy;
    if (e->sink)
        e->sink->close(e->user);
}

static double camt(const qrk__corner *c)
{
    return c->kind == QRK_CORNER_NONE ? 0 : c->a;
}

static void em_corner(emitter *e, const qrk__corner *c, bool cw, double x, double y,
                      double ccx, double ccy)
{
    if (c->kind == QRK_CORNER_ROUND && c->a > 0)
        em_arc(e, c->a, cw, x, y, ccx, ccy);
    else if (c->kind == QRK_CORNER_CHAMFER && c->a > 0)
        em_line(e, x, y);
}

/* Clockwise (filled) rectangle with corner treatments. */
static void em_crect(emitter *e, const qrk__crect *r)
{
    double x0 = r->x0, y0 = r->y0, x1 = r->x1, y1 = r->y1;
    double tl = camt(&r->c[QRK_TL]), tr = camt(&r->c[QRK_TR]);
    double br = camt(&r->c[QRK_BR]), bl = camt(&r->c[QRK_BL]);
    em_move(e, x0 + tl, y0);
    em_line(e, x1 - tr, y0);
    em_corner(e, &r->c[QRK_TR], true, x1, y0 + tr, x1 - tr, y0 + tr);
    em_line(e, x1, y1 - br);
    em_corner(e, &r->c[QRK_BR], true, x1 - br, y1, x1 - br, y1 - br);
    em_line(e, x0 + bl, y1);
    em_corner(e, &r->c[QRK_BL], true, x0, y1 - bl, x0 + bl, y1 - bl);
    em_line(e, x0, y0 + tl);
    em_corner(e, &r->c[QRK_TL], true, x0 + tl, y0, x0 + tl, y0 + tl);
    em_close(e);
}

/* Counter-clockwise version, used for holes. */
static void em_crect_ccw(emitter *e, const qrk__crect *r)
{
    double x0 = r->x0, y0 = r->y0, x1 = r->x1, y1 = r->y1;
    double tl = camt(&r->c[QRK_TL]), tr = camt(&r->c[QRK_TR]);
    double br = camt(&r->c[QRK_BR]), bl = camt(&r->c[QRK_BL]);
    em_move(e, x0, y0 + tl);
    em_line(e, x0, y1 - bl);
    em_corner(e, &r->c[QRK_BL], false, x0 + bl, y1, x0 + bl, y1 - bl);
    em_line(e, x1 - br, y1);
    em_corner(e, &r->c[QRK_BR], false, x1, y1 - br, x1 - br, y1 - br);
    em_line(e, x1, y0 + tr);
    em_corner(e, &r->c[QRK_TR], false, x1 - tr, y0, x1 - tr, y0 + tr);
    em_line(e, x0 + tl, y0);
    em_corner(e, &r->c[QRK_TL], false, x0, y0 + tl, x0 + tl, y0 + tl);
    em_close(e);
}

static void crect_simple(qrk__crect *r, double x0, double y0, double x1, double y1,
                         uint8_t kind, double a)
{
    r->x0 = x0;
    r->y0 = y0;
    r->x1 = x1;
    r->y1 = y1;
    set_corners(r->c, kind, a);
}

/* Four-point star: tips at distance h, concave arcs of radius h*sqrt(2.5)
 * centered at (+-1.5h, +-1.5h). */
static void em_star(emitter *e, double cx, double cy, double h)
{
    double r = sqrt(2.5) * h, c = 1.5 * h;
    em_move(e, cx, cy - h);
    em_arc(e, r, false, cx + h, cy, cx + c, cy - c);
    em_arc(e, r, false, cx, cy + h, cx + c, cy + c);
    em_arc(e, r, false, cx - h, cy, cx - c, cy + c);
    em_arc(e, r, false, cx, cy - h, cx - c, cy - c);
    em_close(e);
}

static void em_fillet(emitter *e, int corner, double X, double Y, double r)
{
    switch (corner) {
    case QRK_TL:
        em_move(e, X, Y);
        em_line(e, X + r, Y);
        em_arc(e, r, false, X, Y + r, X + r, Y + r);
        break;
    case QRK_TR:
        em_move(e, X + 1, Y);
        em_line(e, X + 1, Y + r);
        em_arc(e, r, false, X + 1 - r, Y, X + 1 - r, Y + r);
        break;
    case QRK_BR:
        em_move(e, X + 1, Y + 1);
        em_line(e, X + 1 - r, Y + 1);
        em_arc(e, r, false, X + 1, Y + 1 - r, X + 1 - r, Y + 1 - r);
        break;
    default:
        em_move(e, X, Y + 1);
        em_line(e, X, Y + 1 - r);
        em_arc(e, r, false, X + r, Y + 1, X + r, Y + 1 - r);
        break;
    }
    em_close(e);
}

static void emit_modules(emitter *e, const qrk__layout *L)
{
    int n = L->n;
    double ox = L->ox, oy = L->oy, s = L->size, d = (1 - s) / 2;

    if ((L->shape == QRK_MODULE_SQUARE && s == 1) || L->shape == QRK_MODULE_HBARS) {
        bool bars = L->shape == QRK_MODULE_HBARS;
        double inset = bars ? d : 0, a = bars ? L->roundness * s / 2 : 0;
        for (int y = 0; y < n; y++) {
            for (int x = 0; x < n;) {
                if (!qrk__is_data_dark(L, x, y)) { x++; continue; }
                int x0 = x;
                while (x < n && qrk__is_data_dark(L, x, y))
                    x++;
                qrk__crect r;
                crect_simple(&r, ox + x0 + inset, oy + y + inset, ox + x - inset, oy + y + 1 - inset,
                             bars ? QRK_CORNER_ROUND : QRK_CORNER_NONE, a);
                em_crect(e, &r);
            }
        }
        return;
    }
    if (L->shape == QRK_MODULE_VBARS) {
        double a = L->roundness * s / 2;
        for (int x = 0; x < n; x++) {
            for (int y = 0; y < n;) {
                if (!qrk__is_data_dark(L, x, y)) { y++; continue; }
                int y0 = y;
                while (y < n && qrk__is_data_dark(L, x, y))
                    y++;
                qrk__crect r;
                crect_simple(&r, ox + x + d, oy + y0 + d, ox + x + 1 - d, oy + y - d,
                             QRK_CORNER_ROUND, a);
                em_crect(e, &r);
            }
        }
        return;
    }

    for (int y = 0; y < n; y++) {
        for (int x = 0; x < n; x++) {
            double X = ox + x, Y = oy + y;
            if (qrk__is_data_dark(L, x, y)) {
                qrk__crect r;
                if (!qrk__module_crect(L, x, y, &r)) {
                    em_star(e, X + 0.5, Y + 0.5, s / 2);
                    continue;
                }
                r.x0 += X; r.x1 += X; r.y0 += Y; r.y1 += Y;
                em_crect(e, &r);
            } else if (qrk__is_data_cell(L, x, y)) {
                int m = qrk__fillet_mask(L, x, y);
                for (int c = 0; c < 4; c++)
                    if (m & (1 << c))
                        em_fillet(e, c, X, Y, L->roundness / 2);
            }
        }
    }
}

/* One eye-like pattern: frame (size fs) or ball (size bs) at (X, Y). */
static void emit_eye_part(emitter *e, int shape, double X, double Y, double s, bool ring, int cc)
{
    if (shape == QRK_EYE_DOTS) {
        int k = (int)s;
        for (int j = 0; j < k; j++)
            for (int i = 0; i < k; i++) {
                if (ring && !(i == 0 || j == 0 || i == k - 1 || j == k - 1))
                    continue;
                qrk__crect r;
                crect_simple(&r, X + i, Y + j, X + i + 1, Y + j + 1, QRK_CORNER_ROUND, 0.5);
                em_crect(e, &r);
            }
        return;
    }
    qrk__crect outer;
    outer.x0 = X; outer.y0 = Y; outer.x1 = X + s; outer.y1 = Y + s;
    qrk__eye_corners(shape, s, cc, outer.c);
    em_crect(e, &outer);
    if (ring) {
        qrk__crect inner;
        inner.x0 = X + 1; inner.y0 = Y + 1; inner.x1 = X + s - 1; inner.y1 = Y + s - 1;
        qrk__inner_corners(outer.c, s - 2, inner.c);
        em_crect_ccw(e, &inner);
    }
}

static void emit_eyes(emitter *e, const qrk__layout *L, bool frames)
{
    const qrk_style *st = L->style;
    int n = L->n;
    const int ex[3] = {0, n - 7, 0}, ey[3] = {0, 0, n - 7};
    const int cc[3] = {QRK_BR, QRK_BL, QRK_TR};
    int fs = st->eyes.frame < QRK_EYE_SHAPE_COUNT ? st->eyes.frame : QRK_EYE_SQUARE;
    int bs = qrk__ball_shape(st->eyes.ball);
    for (int i = 0; i < 3; i++) {
        double X = L->ox + ex[i], Y = L->oy + ey[i];
        if (frames)
            emit_eye_part(e, fs, X, Y, 7, true, cc[i]);
        else
            emit_eye_part(e, bs, X + 2, Y + 2, 3, false, cc[i]);
    }
    if (!L->align_styled)
        return;
    int afs = st->alignment.frame;
    int abs_ = qrk__ball_shape(st->alignment.ball);
    int k = L->align_count;
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++) {
            if (!is_alignment_center(k, i, j))
                continue;
            double X = L->ox + L->align_pos[j], Y = L->oy + L->align_pos[i];
            if (frames)
                emit_eye_part(e, afs, X - 2, Y - 2, 5, true, QRK_BR);
            else
                emit_eye_part(e, abs_, X, Y, 1, false, QRK_BR);
        }
}

static void canvas_crect(const qrk__layout *L, qrk__crect *r, double inset)
{
    double a = L->bg_radius - inset;
    crect_simple(r, inset, inset, L->W - inset, L->H - inset,
                 a > 0 ? QRK_CORNER_ROUND : QRK_CORNER_NONE, a > 0 ? a : 0);
}

int qrk_emit_layer(const qrk_code *code, const qrk_style *style, qrk_layer layer,
                   const qrk_path_sink *sink, void *user)
{
    qrk__layout L;
    qrk__layout_init(&L, code, style);
    emitter e;
    memset(&e, 0, sizeof e);
    e.sink = sink;
    e.user = user;
    qrk__crect r;

    switch (layer) {
    case QRK_LAYER_BACKGROUND:
        canvas_crect(&L, &r, 0);
        em_crect(&e, &r);
        break;
    case QRK_LAYER_BORDER:
        if (L.border > 0) {
            canvas_crect(&L, &r, 0);
            em_crect(&e, &r);
            canvas_crect(&L, &r, L.border);
            em_crect_ccw(&e, &r);
        }
        break;
    case QRK_LAYER_MODULES:
        emit_modules(&e, &L);
        break;
    case QRK_LAYER_EYE_FRAMES:
        emit_eyes(&e, &L, true);
        break;
    case QRK_LAYER_EYE_BALLS:
        emit_eyes(&e, &L, false);
        break;
    case QRK_LAYER_LOGO_BACKGROUND:
        if (L.has_logo && (style->logo.background & 0xFF) != 0) {
            qrk__logo_bg_crect(&L, &r);
            em_crect(&e, &r);
        }
        break;
    default:
        break;
    }
    return e.count;
}

/* ---- logo damage --------------------------------------------------------- */

double qrk_logo_damage(const qrk_code *code, const qrk_style *style)
{
    qrk__layout L;
    qrk__layout_init(&L, code, style);
    if (!L.has_logo)
        return 0;

    int ver = code->version, ecc = code->ecc, size = code->size;
    int num_blocks = qrk__num_ecc_blocks(ecc, ver);
    int block_ecc = qrk__ecc_codewords_per_block(ecc, ver);
    int raw = qrk__raw_codewords(ver);
    int data_len = raw - num_blocks * block_ecc;
    int num_short = num_blocks - raw % num_blocks;
    int short_len = raw / num_blocks - block_ecc;

    int damaged[81];
    memset(damaged, 0, sizeof damaged);
    int last_cw = -1;
    bool last_hit = false;

    int bit = 0;
    for (int right = size - 1; right >= 1; right -= 2) {
        if (right == 6)
            right = 5;
        for (int vert = 0; vert < size; vert++) {
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                bool upward = ((right + 1) & 2) == 0;
                int y = upward ? size - 1 - vert : vert;
                if (qrk__is_function_module(ver, x, y) || bit >= raw * 8)
                    continue;
                int cw = bit / 8;
                bit++;
                if (cw != last_cw) {
                    last_cw = cw;
                    last_hit = false;
                }
                if (last_hit || !in_logo_area(&L, x, y))
                    continue;
                last_hit = true;
                int block;
                if (cw < data_len)
                    block = cw < short_len * num_blocks ? cw % num_blocks
                                                        : num_short + (cw - short_len * num_blocks);
                else
                    block = (cw - data_len) % num_blocks;
                damaged[block]++;
            }
        }
    }

    double worst = 0;
    int correctable = block_ecc / 2;
    for (int b = 0; b < num_blocks; b++) {
        double ratio = (double)damaged[b] / correctable;
        if (ratio > worst)
            worst = ratio;
    }
    return worst;
}
