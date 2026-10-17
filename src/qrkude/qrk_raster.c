/*
 * QRKude - scanline rasterizer. Evaluates the shape model per sample, so it
 * needs no path buffers and streams spans: suitable for microcontrollers.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <math.h>
#include <string.h>

#include "qrk_internal.h"

typedef struct {
    float r, g, b, a; /* premultiplied, 0..1 */
} rgbaf;

typedef struct {
    float x0, y0, x1, y1;
    uint8_t kind[4];
    float a[4];
} fcrect;

typedef struct {
    int x, y;
    int kind; /* 0 empty, 1 crect, 2 star, 3 fillets */
    int fillets;
    fcrect r; /* cell-local */
} cell_cache;

typedef struct {
    qrk__layout L;
    const qrk_style *style;
    qrk_paint paint[QRK_LAYER_COUNT];
    float gx1[QRK_LAYER_COUNT], gy1[QRK_LAYER_COUNT], gdx[QRK_LAYER_COUNT], gdy[QRK_LAYER_COUNT];
    float glen2[QRK_LAYER_COUNT], gcx[QRK_LAYER_COUNT], gcy[QRK_LAYER_COUNT], gr[QRK_LAYER_COUNT];
    bool bg_visible, logo_bg;
    float W, H, ox, oy, star_h, fillet_r;
    fcrect canvas, border_inner, logo_bg_rect;
    /* eyes: 3 finders followed by alignment patterns */
    int eye_frame, eye_ball, align_frame, align_ball;
    fcrect eye_outer[3], eye_inner[3], eye_ball_rect[3];
    fcrect al_outer, al_inner, al_ball; /* local to the 5x5 box */
    /* logo bitmap */
    const qrk_image *logo;
    float logo_x0, logo_y0, logo_w, logo_h, logo_scale;
    cell_cache cache;
} raster_ctx;

static void to_fcrect(const qrk__crect *c, fcrect *f)
{
    f->x0 = (float)c->x0;
    f->y0 = (float)c->y0;
    f->x1 = (float)c->x1;
    f->y1 = (float)c->y1;
    for (int i = 0; i < 4; i++) {
        f->kind[i] = c->c[i].a > 0 ? c->c[i].kind : QRK_CORNER_NONE;
        f->a[i] = (float)c->c[i].a;
    }
}

static bool in_fcrect(const fcrect *r, float u, float v)
{
    if (u < r->x0 || u >= r->x1 || v < r->y0 || v >= r->y1)
        return false;
    for (int i = 0; i < 4; i++) {
        if (r->kind[i] == QRK_CORNER_NONE)
            continue;
        float dx = (i == QRK_TL || i == QRK_BL) ? u - r->x0 : r->x1 - u;
        float dy = (i == QRK_TL || i == QRK_TR) ? v - r->y0 : r->y1 - v;
        float a = r->a[i];
        if (r->kind[i] == QRK_CORNER_ROUND) {
            if (dx < a && dy < a) {
                float ex = a - dx, ey = a - dy;
                if (ex * ex + ey * ey > a * a)
                    return false;
            }
        } else if (dx + dy < a) {
            return false;
        }
    }
    return true;
}

static void eye_rects(int shape, double X, double Y, double s, int cc, bool ring, fcrect *outer,
                      fcrect *inner)
{
    qrk__crect o;
    o.x0 = X; o.y0 = Y; o.x1 = X + s; o.y1 = Y + s;
    qrk__eye_corners(shape, s, cc, o.c);
    to_fcrect(&o, outer);
    if (ring && inner) {
        qrk__crect in;
        in.x0 = X + 1; in.y0 = Y + 1; in.x1 = X + s - 1; in.y1 = Y + s - 1;
        qrk__inner_corners(o.c, s - 2, in.c);
        to_fcrect(&in, inner);
    }
}

/* ---- colors -------------------------------------------------------------- */

static void over(rgbaf *dst, qrk_color c)
{
    float a = (float)(c & 0xFF) / 255.0f;
    if (a <= 0)
        return;
    float k = 1 - a;
    dst->r = (float)(c >> 24) / 255.0f * a + dst->r * k;
    dst->g = (float)((c >> 16) & 0xFF) / 255.0f * a + dst->g * k;
    dst->b = (float)((c >> 8) & 0xFF) / 255.0f * a + dst->b * k;
    dst->a = a + dst->a * k;
}

static qrk_color lerp_color(qrk_color a, qrk_color b, float t)
{
    qrk_color out = 0;
    for (int sh = 0; sh < 32; sh += 8) {
        float ca = (float)((a >> sh) & 0xFF), cb = (float)((b >> sh) & 0xFF);
        int v = (int)(ca + (cb - ca) * t + 0.5f);
        out |= (qrk_color)(v < 0 ? 0 : v > 255 ? 255 : v) << sh;
    }
    return out;
}

static qrk_color paint_at(const raster_ctx *R, int layer, float u, float v)
{
    const qrk_paint *p = &R->paint[layer];
    if (p->type == QRK_PAINT_SOLID)
        return p->color;
    if (p->type == QRK_PAINT_NONE || p->stop_count == 0)
        return 0;
    float t;
    if (p->type == QRK_PAINT_LINEAR) {
        t = R->glen2[layer] > 0
                ? ((u - R->gx1[layer]) * R->gdx[layer] + (v - R->gy1[layer]) * R->gdy[layer]) / R->glen2[layer]
                : 0;
    } else {
        float dx = u - R->gcx[layer], dy = v - R->gcy[layer];
        t = R->gr[layer] > 0 ? sqrtf(dx * dx + dy * dy) / R->gr[layer] : 0;
    }
    int n = p->stop_count < QRK_MAX_STOPS ? p->stop_count : QRK_MAX_STOPS;
    if (t <= (float)p->stops[0].offset)
        return p->stops[0].color;
    for (int i = 0; i + 1 < n; i++) {
        float o0 = (float)p->stops[i].offset, o1 = (float)p->stops[i + 1].offset;
        if (t <= o1)
            return o1 > o0 ? lerp_color(p->stops[i].color, p->stops[i + 1].color, (t - o0) / (o1 - o0))
                           : p->stops[i + 1].color;
    }
    return p->stops[n - 1].color;
}

static qrk_color fetch_pixel(const qrk_image *img, int x, int y)
{
    size_t stride = img->stride;
    const uint8_t *row;
    switch (img->format) {
    case QRK_PIXEL_RGBA8888:
        row = (const uint8_t *)img->pixels + y * (stride ? stride : (size_t)img->width * 4) + x * 4;
        return QRK_RGBA(row[0], row[1], row[2], row[3]);
    case QRK_PIXEL_BGRA8888:
        row = (const uint8_t *)img->pixels + y * (stride ? stride : (size_t)img->width * 4) + x * 4;
        return QRK_RGBA(row[2], row[1], row[0], row[3]);
    case QRK_PIXEL_RGB888:
        row = (const uint8_t *)img->pixels + y * (stride ? stride : (size_t)img->width * 3) + x * 3;
        return QRK_RGB(row[0], row[1], row[2]);
    case QRK_PIXEL_RGB565:
    case QRK_PIXEL_RGB565_SWAPPED: {
        row = (const uint8_t *)img->pixels + y * (stride ? stride : (size_t)img->width * 2) + x * 2;
        uint16_t v;
        memcpy(&v, row, 2);
        if (img->format == QRK_PIXEL_RGB565_SWAPPED)
            v = (uint16_t)((v >> 8) | (v << 8));
        int r = (v >> 11) & 31, g = (v >> 5) & 63, b = v & 31;
        return QRK_RGB(r * 255 / 31, g * 255 / 63, b * 255 / 31);
    }
    case QRK_PIXEL_GRAY8:
        row = (const uint8_t *)img->pixels + y * (stride ? stride : (size_t)img->width) + x;
        return QRK_RGB(row[0], row[0], row[0]);
    case QRK_PIXEL_MONO: {
        row = (const uint8_t *)img->pixels + y * (stride ? stride : (size_t)(img->width + 7) / 8) + x / 8;
        bool dark = (row[0] >> (7 - x % 8)) & 1;
        return dark ? QRK_HEX(0x000000) : QRK_HEX(0xFFFFFF);
    }
    }
    return 0;
}

/* ---- setup --------------------------------------------------------------- */

static void ctx_init(raster_ctx *R, const qrk_code *code, const qrk_style *style,
                     const qrk_image *logo)
{
    memset(R, 0, sizeof *R);
    qrk__layout *L = &R->L;
    qrk__layout_init(L, code, style);
    R->style = style;
    R->W = (float)L->W;
    R->H = (float)L->H;
    R->ox = (float)L->ox;
    R->oy = (float)L->oy;
    R->star_h = (float)(L->size / 2);
    R->fillet_r = (float)(L->roundness / 2);

    for (int layer = 0; layer < QRK_LAYER_COUNT; layer++) {
        R->paint[layer] = qrk__resolve_paint(style, layer);
        qrk_gradient_geometry g;
        qrk__gradient_geometry(L, layer, &R->paint[layer], &g);
        R->gx1[layer] = (float)g.x1;
        R->gy1[layer] = (float)g.y1;
        R->gdx[layer] = (float)(g.x2 - g.x1);
        R->gdy[layer] = (float)(g.y2 - g.y1);
        R->glen2[layer] = R->gdx[layer] * R->gdx[layer] + R->gdy[layer] * R->gdy[layer];
        R->gcx[layer] = (float)g.cx;
        R->gcy[layer] = (float)g.cy;
        R->gr[layer] = (float)g.r;
    }
    const qrk_paint *bg = &style->background.paint;
    R->bg_visible = bg->type == QRK_PAINT_LINEAR || bg->type == QRK_PAINT_RADIAL ||
                    (bg->type == QRK_PAINT_SOLID && (bg->color & 0xFF) != 0);

    qrk__crect c;
    double rad = L->bg_radius;
    c.x0 = 0; c.y0 = 0; c.x1 = L->W; c.y1 = L->H;
    for (int i = 0; i < 4; i++) { c.c[i].kind = QRK_CORNER_ROUND; c.c[i].a = rad; }
    to_fcrect(&c, &R->canvas);
    double b = L->border, ri = rad - b > 0 ? rad - b : 0;
    c.x0 = b; c.y0 = b; c.x1 = L->W - b; c.y1 = L->H - b;
    for (int i = 0; i < 4; i++) c.c[i].a = ri;
    to_fcrect(&c, &R->border_inner);

    R->logo_bg = L->has_logo && (style->logo.background & 0xFF) != 0;
    if (L->has_logo) {
        qrk__logo_bg_crect(L, &c);
        to_fcrect(&c, &R->logo_bg_rect);
    }
    if (L->has_logo && logo && logo->pixels && logo->width > 0 && logo->height > 0) {
        R->logo = logo;
        float box = (float)(2 * L->logo_half);
        int big = logo->width > logo->height ? logo->width : logo->height;
        R->logo_scale = box / (float)big;
        R->logo_w = (float)logo->width * R->logo_scale;
        R->logo_h = (float)logo->height * R->logo_scale;
        R->logo_x0 = (float)(L->logo_cx - L->logo_half) + (box - R->logo_w) / 2;
        R->logo_y0 = (float)(L->logo_cy - L->logo_half) + (box - R->logo_h) / 2;
    }

    int n = L->n;
    R->eye_frame = style->eyes.frame < QRK_EYE_SHAPE_COUNT ? style->eyes.frame : QRK_EYE_SQUARE;
    R->eye_ball = qrk__ball_shape(style->eyes.ball);
    const int ex[3] = {0, n - 7, 0}, ey[3] = {0, 0, n - 7};
    const int cc[3] = {QRK_BR, QRK_BL, QRK_TR};
    for (int i = 0; i < 3; i++) {
        double X = L->ox + ex[i], Y = L->oy + ey[i];
        eye_rects(R->eye_frame, X, Y, 7, cc[i], true, &R->eye_outer[i], &R->eye_inner[i]);
        eye_rects(R->eye_ball, X + 2, Y + 2, 3, cc[i], false, &R->eye_ball_rect[i], NULL);
    }
    if (L->align_styled) {
        R->align_frame = style->alignment.frame;
        R->align_ball = qrk__ball_shape(style->alignment.ball);
        eye_rects(R->align_frame, 0, 0, 5, QRK_BR, true, &R->al_outer, &R->al_inner);
        eye_rects(R->align_ball, 2, 2, 1, QRK_BR, false, &R->al_ball, NULL);
    }
    R->cache.x = R->cache.y = -1000;
}

/* ---- per-sample evaluation ----------------------------------------------- */

static const cell_cache *cell_info(raster_ctx *R, int x, int y)
{
    cell_cache *c = &R->cache;
    if (c->x == x && c->y == y)
        return c;
    c->x = x;
    c->y = y;
    c->kind = 0;
    if (qrk__is_data_dark(&R->L, x, y)) {
        qrk__crect r;
        if (qrk__module_crect(&R->L, x, y, &r)) {
            to_fcrect(&r, &c->r);
            c->kind = 1;
        } else {
            c->kind = 2;
        }
    } else if (qrk__is_data_cell(&R->L, x, y)) {
        c->fillets = qrk__fillet_mask(&R->L, x, y);
        if (c->fillets)
            c->kind = 3;
    }
    return c;
}

static bool in_fillet(int corner, float lx, float ly, float r)
{
    float dx = (corner == QRK_TL || corner == QRK_BL) ? lx : 1 - lx;
    float dy = (corner == QRK_TL || corner == QRK_TR) ? ly : 1 - ly;
    if (dx >= r || dy >= r)
        return false;
    float ex = r - dx, ey = r - dy;
    return ex * ex + ey * ey > r * r;
}

static bool in_dot_cell(float lx, float ly)
{
    float dx = lx - 0.5f, dy = ly - 0.5f;
    return dx * dx + dy * dy <= 0.25f;
}

/* 0 = nothing, 1 = frame, 2 = ball */
static int eye_hit(const raster_ctx *R, int x, int y, float u, float v)
{
    int n = R->L.n;
    int idx = -1, lx = 0, ly = 0;
    if (x < 7 && y < 7) { idx = 0; lx = x; ly = y; }
    else if (x >= n - 7 && y < 7) { idx = 1; lx = x - (n - 7); ly = y; }
    else if (x < 7 && y >= n - 7) { idx = 2; lx = x; ly = y - (n - 7); }

    float fx = u - R->ox - (float)x, fy = v - R->oy - (float)y; /* cell local */
    if (idx >= 0) {
        bool ring = lx == 0 || ly == 0 || lx == 6 || ly == 6;
        bool ball = lx >= 2 && lx <= 4 && ly >= 2 && ly <= 4;
        if (R->eye_frame == QRK_EYE_DOTS) {
            if (ring && in_dot_cell(fx, fy))
                return 1;
        } else if (in_fcrect(&R->eye_outer[idx], u, v) && !in_fcrect(&R->eye_inner[idx], u, v)) {
            return 1;
        }
        if (R->eye_ball == QRK_EYE_DOTS) {
            if (ball && in_dot_cell(fx, fy))
                return 2;
        } else if (in_fcrect(&R->eye_ball_rect[idx], u, v)) {
            return 2;
        }
        return 0;
    }

    if (!R->L.align_styled)
        return 0;
    int k = R->L.align_count;
    for (int i = 0; i < k; i++) {
        int dy = y - R->L.align_pos[i];
        if (dy < -2 || dy > 2)
            continue;
        for (int j = 0; j < k; j++) {
            int dx = x - R->L.align_pos[j];
            if (dx < -2 || dx > 2 || (i == 0 && j == 0) || (i == 0 && j == k - 1) ||
                (i == k - 1 && j == 0))
                continue;
            float bu = u - R->ox - (float)(R->L.align_pos[j] - 2);
            float bv = v - R->oy - (float)(R->L.align_pos[i] - 2);
            bool ring = dx == -2 || dx == 2 || dy == -2 || dy == 2;
            if (R->align_frame == QRK_EYE_DOTS) {
                if (ring && in_dot_cell(fx, fy))
                    return 1;
            } else if (in_fcrect(&R->al_outer, bu, bv) && !in_fcrect(&R->al_inner, bu, bv)) {
                return 1;
            }
            if (R->align_ball == QRK_EYE_DOTS) {
                if (dx == 0 && dy == 0 && in_dot_cell(fx, fy))
                    return 2;
            } else if (in_fcrect(&R->al_ball, bu, bv)) {
                return 2;
            }
            return 0;
        }
    }
    return 0;
}

static void sample(raster_ctx *R, float u, float v, rgbaf *out)
{
    out->r = out->g = out->b = out->a = 0;
    if (u < 0 || v < 0 || u >= R->W || v >= R->H)
        return;
    if (!in_fcrect(&R->canvas, u, v))
        return;
    if (R->bg_visible)
        over(out, paint_at(R, QRK_LAYER_BACKGROUND, u, v));
    if (R->L.border > 0 && !in_fcrect(&R->border_inner, u, v))
        over(out, R->paint[QRK_LAYER_BORDER].color);

    float su = u - R->ox, sv = v - R->oy;
    int n = R->L.n;
    if (su >= 0 && sv >= 0 && su < (float)n && sv < (float)n) {
        int x = (int)su, y = (int)sv;
        float lx = su - (float)x, ly = sv - (float)y;
        const cell_cache *c = cell_info(R, x, y);
        bool hit = false;
        if (c->kind == 1) {
            hit = in_fcrect(&c->r, lx, ly);
        } else if (c->kind == 2) {
            float h = R->star_h, ax = fabsf(lx - 0.5f), ay = fabsf(ly - 0.5f);
            if (ax <= h && ay <= h) {
                float ex = 1.5f * h - ax, ey = 1.5f * h - ay;
                hit = ex * ex + ey * ey > 2.5f * h * h;
            }
        } else if (c->kind == 3) {
            for (int k = 0; k < 4 && !hit; k++)
                if (c->fillets & (1 << k))
                    hit = in_fillet(k, lx, ly, R->fillet_r);
        }
        if (hit)
            over(out, paint_at(R, QRK_LAYER_MODULES, u, v));
        int eye = eye_hit(R, x, y, u, v);
        if (eye == 1)
            over(out, paint_at(R, QRK_LAYER_EYE_FRAMES, u, v));
        else if (eye == 2)
            over(out, paint_at(R, QRK_LAYER_EYE_BALLS, u, v));
    }

    if (R->logo_bg && in_fcrect(&R->logo_bg_rect, u, v))
        over(out, R->style->logo.background);
    if (R->logo && u >= R->logo_x0 && v >= R->logo_y0 && u < R->logo_x0 + R->logo_w &&
        v < R->logo_y0 + R->logo_h) {
        int ix = (int)((u - R->logo_x0) / R->logo_scale);
        int iy = (int)((v - R->logo_y0) / R->logo_scale);
        if (ix >= R->logo->width) ix = R->logo->width - 1;
        if (iy >= R->logo->height) iy = R->logo->height - 1;
        over(out, fetch_pixel(R->logo, ix, iy));
    }
}

/* ---- public API ---------------------------------------------------------- */

void qrk_raster_opts_default(qrk_raster_opts *opts, int width, int height)
{
    opts->width = width;
    opts->height = height;
    opts->supersample = 2;
    opts->integer_scale = true;
    opts->clear_color = QRK_HEX(0xFFFFFF);
    opts->logo = NULL;
}

static int to_byte(float v)
{
    int i = (int)(v * 255.0f + 0.5f);
    return i < 0 ? 0 : i > 255 ? 255 : i;
}

qrk_status qrk_render_spans(const qrk_code *code, const qrk_style *style,
                            const qrk_raster_opts *opts, qrk_span_fn span, void *user)
{
    if (!code || !style || !opts || !span || opts->width <= 0 || opts->height <= 0)
        return QRK_ERR_INVALID_ARGUMENT;
    raster_ctx R;
    ctx_init(&R, code, style, opts->logo);

    float scale = (float)opts->width / R.W;
    if ((float)opts->height / R.H < scale)
        scale = (float)opts->height / R.H;
    if (opts->integer_scale && scale >= 1)
        scale = floorf(scale);
    float offx = ((float)opts->width - R.W * scale) / 2;
    float offy = ((float)opts->height - R.H * scale) / 2;
    if (opts->integer_scale) {
        offx = floorf(offx);
        offy = floorf(offy);
    }
    int ss = opts->supersample < 1 ? 1 : opts->supersample > 4 ? 4 : opts->supersample;
    float inv = 1.0f / (float)(ss * ss);

    rgbaf clear;
    clear.a = (float)(opts->clear_color & 0xFF) / 255.0f;
    clear.r = (float)(opts->clear_color >> 24) / 255.0f * clear.a;
    clear.g = (float)((opts->clear_color >> 16) & 0xFF) / 255.0f * clear.a;
    clear.b = (float)((opts->clear_color >> 8) & 0xFF) / 255.0f * clear.a;

    for (int py = 0; py < opts->height; py++) {
        int run_x = 0;
        qrk_color run_color = 0;
        for (int px = 0; px < opts->width; px++) {
            rgbaf acc = {0, 0, 0, 0};
            for (int j = 0; j < ss; j++) {
                float v = ((float)py + ((float)j + 0.5f) / (float)ss - offy) / scale;
                for (int i = 0; i < ss; i++) {
                    float u = ((float)px + ((float)i + 0.5f) / (float)ss - offx) / scale;
                    rgbaf s;
                    sample(&R, u, v, &s);
                    acc.r += s.r;
                    acc.g += s.g;
                    acc.b += s.b;
                    acc.a += s.a;
                }
            }
            float k = 1 - acc.a * inv;
            float r = acc.r * inv + clear.r * k, g = acc.g * inv + clear.g * k;
            float b = acc.b * inv + clear.b * k, a = acc.a * inv + clear.a * k;
            qrk_color color = 0;
            if (a > 0)
                color = QRK_RGBA(to_byte(r / a), to_byte(g / a), to_byte(b / a), to_byte(a));
            if (px == 0) {
                run_color = color;
            } else if (color != run_color) {
                span(user, run_x, py, px - run_x, run_color);
                run_x = px;
                run_color = color;
            }
        }
        span(user, run_x, py, opts->width - run_x, run_color);
    }
    return QRK_OK;
}

size_t qrk_pixel_buffer_size(qrk_pixel_format format, int width, int height)
{
    switch (format) {
    case QRK_PIXEL_RGBA8888:
    case QRK_PIXEL_BGRA8888: return (size_t)width * height * 4;
    case QRK_PIXEL_RGB888: return (size_t)width * height * 3;
    case QRK_PIXEL_RGB565:
    case QRK_PIXEL_RGB565_SWAPPED: return (size_t)width * height * 2;
    case QRK_PIXEL_GRAY8: return (size_t)width * height;
    case QRK_PIXEL_MONO: return (size_t)(width + 7) / 8 * height;
    }
    return 0;
}

typedef struct {
    uint8_t *pixels;
    size_t stride;
    qrk_pixel_format format;
} buffer_target;

static void buffer_span(void *user, int x, int y, int len, qrk_color c)
{
    buffer_target *t = (buffer_target *)user;
    uint8_t *row = t->pixels + (size_t)y * t->stride;
    uint8_t r = (uint8_t)(c >> 24), g = (uint8_t)(c >> 16), b = (uint8_t)(c >> 8), a = (uint8_t)c;
    uint16_t v565 = (uint16_t)(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
    if (t->format == QRK_PIXEL_RGB565_SWAPPED)
        v565 = (uint16_t)((v565 >> 8) | (v565 << 8));
    uint8_t gray = (uint8_t)((r * 299 + g * 587 + b * 114 + 500) / 1000);
    for (int i = x; i < x + len; i++) {
        switch (t->format) {
        case QRK_PIXEL_RGBA8888:
            row[i * 4] = r; row[i * 4 + 1] = g; row[i * 4 + 2] = b; row[i * 4 + 3] = a;
            break;
        case QRK_PIXEL_BGRA8888:
            row[i * 4] = b; row[i * 4 + 1] = g; row[i * 4 + 2] = r; row[i * 4 + 3] = a;
            break;
        case QRK_PIXEL_RGB888:
            row[i * 3] = r; row[i * 3 + 1] = g; row[i * 3 + 2] = b;
            break;
        case QRK_PIXEL_RGB565:
        case QRK_PIXEL_RGB565_SWAPPED:
            memcpy(row + i * 2, &v565, 2);
            break;
        case QRK_PIXEL_GRAY8:
            row[i] = gray;
            break;
        case QRK_PIXEL_MONO:
            if (gray < 128)
                row[i / 8] |= (uint8_t)(0x80 >> (i % 8));
            else
                row[i / 8] &= (uint8_t)~(0x80 >> (i % 8));
            break;
        }
    }
}

qrk_status qrk_render_buffer(const qrk_code *code, const qrk_style *style,
                             const qrk_raster_opts *opts, qrk_pixel_format format, void *pixels,
                             size_t stride)
{
    if (!pixels || !opts)
        return QRK_ERR_INVALID_ARGUMENT;
    buffer_target t;
    t.pixels = (uint8_t *)pixels;
    t.format = format;
    t.stride = stride ? stride : qrk_pixel_buffer_size(format, opts->width, 1);
    return qrk_render_spans(code, style, opts, buffer_span, &t);
}
