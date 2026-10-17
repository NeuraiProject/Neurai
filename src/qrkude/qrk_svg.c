/*
 * QRKude - SVG writer. The output is byte-identical across all ports.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <math.h>
#include <string.h>

#include "qrk_internal.h"

size_t qrk_format_number(double value, char out[32])
{
    if (!(value > -1e15 && value < 1e15)) /* NaN, infinities, absurd sizes */
        value = 0;
    long long n = (long long)floor(value * 1000.0 + 0.5);
    char tmp[32];
    size_t len = 0;
    bool neg = n < 0;
    if (neg)
        n = -n;
    long long ip = n / 1000;
    int fp = (int)(n % 1000);
    if (neg)
        out[len++] = '-';
    size_t k = 0;
    do {
        tmp[k++] = (char)('0' + ip % 10);
        ip /= 10;
    } while (ip > 0);
    while (k > 0)
        out[len++] = tmp[--k];
    if (fp) {
        out[len++] = '.';
        out[len++] = (char)('0' + fp / 100);
        if (fp % 100) {
            out[len++] = (char)('0' + fp / 10 % 10);
            if (fp % 10)
                out[len++] = (char)('0' + fp % 10);
        }
    }
    out[len] = 0;
    return len;
}

void qrk_svg_opts_default(qrk_svg_opts *opts)
{
    opts->width = 0;
    opts->id_prefix = "qrk";
}

typedef struct {
    qrk_write_fn write;
    void *user;
    double lx, ly;
} svg_ctx;

static void ws(svg_ctx *c, const char *s)
{
    c->write(c->user, s, strlen(s));
}

static void wn(svg_ctx *c, double v)
{
    char buf[32];
    size_t len = qrk_format_number(v, buf);
    c->write(c->user, buf, len);
}

static void wesc(svg_ctx *c, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '&': ws(c, "&amp;"); break;
        case '<': ws(c, "&lt;"); break;
        case '>': ws(c, "&gt;"); break;
        case '"': ws(c, "&quot;"); break;
        default: c->write(c->user, s, 1); break;
        }
    }
}

static void wcolor(svg_ctx *c, qrk_color color)
{
    static const char hex[] = "0123456789abcdef";
    char buf[8];
    buf[0] = '#';
    for (int i = 0; i < 6; i++)
        buf[1 + i] = hex[(color >> (28 - 4 * i)) & 15];
    c->write(c->user, buf, 7);
}

/* ---- path sink ----------------------------------------------------------- */

static void s_move(void *u, double x, double y)
{
    svg_ctx *c = (svg_ctx *)u;
    ws(c, "M");
    wn(c, x);
    ws(c, " ");
    wn(c, y);
    c->lx = x;
    c->ly = y;
}

static void s_line(void *u, double x, double y)
{
    svg_ctx *c = (svg_ctx *)u;
    if (y == c->ly) {
        ws(c, "H");
        wn(c, x);
    } else if (x == c->lx) {
        ws(c, "V");
        wn(c, y);
    } else {
        ws(c, "L");
        wn(c, x);
        ws(c, " ");
        wn(c, y);
    }
    c->lx = x;
    c->ly = y;
}

static void s_arc(void *u, double r, bool cw, double x, double y, double cx, double cy)
{
    (void)cx;
    (void)cy;
    svg_ctx *c = (svg_ctx *)u;
    ws(c, "A");
    wn(c, r);
    ws(c, " ");
    wn(c, r);
    ws(c, cw ? " 0 0 1 " : " 0 0 0 ");
    wn(c, x);
    ws(c, " ");
    wn(c, y);
    c->lx = x;
    c->ly = y;
}

static void s_close(void *u)
{
    ws((svg_ctx *)u, "Z");
}

static const qrk_path_sink SVG_SINK = {s_move, s_line, s_arc, s_close};

/* ---- paints -------------------------------------------------------------- */

static bool is_gradient(const qrk_paint *p)
{
    return p->type == QRK_PAINT_LINEAR || p->type == QRK_PAINT_RADIAL;
}

static void w_opacity(svg_ctx *c, const char *attr, qrk_color color)
{
    unsigned a = color & 0xFF;
    if (a != 255) {
        ws(c, " ");
        ws(c, attr);
        ws(c, "=\"");
        wn(c, a / 255.0);
        ws(c, "\"");
    }
}

static void w_fill(svg_ctx *c, const qrk_paint *p, const char *prefix, const char *id)
{
    if (is_gradient(p)) {
        ws(c, " fill=\"url(#");
        ws(c, prefix);
        ws(c, "-");
        ws(c, id);
        ws(c, ")\"");
    } else if (p->type == QRK_PAINT_SOLID) {
        ws(c, " fill=\"");
        wcolor(c, p->color);
        ws(c, "\"");
        w_opacity(c, "fill-opacity", p->color);
    } else {
        ws(c, " fill=\"none\"");
    }
}

static void w_gradient(svg_ctx *c, const qrk__layout *L, int layer, const qrk_paint *p,
                       const char *prefix, const char *id)
{
    qrk_gradient_geometry g;
    qrk__gradient_geometry(L, layer, p, &g);
    bool linear = p->type == QRK_PAINT_LINEAR;
    ws(c, linear ? "<linearGradient id=\"" : "<radialGradient id=\"");
    ws(c, prefix);
    ws(c, "-");
    ws(c, id);
    ws(c, "\" gradientUnits=\"userSpaceOnUse\"");
    if (linear) {
        ws(c, " x1=\""); wn(c, g.x1);
        ws(c, "\" y1=\""); wn(c, g.y1);
        ws(c, "\" x2=\""); wn(c, g.x2);
        ws(c, "\" y2=\""); wn(c, g.y2);
    } else {
        ws(c, " cx=\""); wn(c, g.cx);
        ws(c, "\" cy=\""); wn(c, g.cy);
        ws(c, "\" r=\""); wn(c, g.r);
    }
    ws(c, "\">");
    int count = p->stop_count < QRK_MAX_STOPS ? p->stop_count : QRK_MAX_STOPS;
    for (int i = 0; i < count; i++) {
        ws(c, "<stop offset=\"");
        wn(c, p->stops[i].offset);
        ws(c, "\" stop-color=\"");
        wcolor(c, p->stops[i].color);
        ws(c, "\"");
        w_opacity(c, "stop-opacity", p->stops[i].color);
        ws(c, "/>");
    }
    ws(c, linear ? "</linearGradient>" : "</radialGradient>");
}

static void w_layer_path(svg_ctx *c, const qrk_code *code, const qrk_style *style, int layer,
                         const qrk_paint *paint, const char *prefix, const char *id)
{
    if (qrk_emit_layer(code, style, (qrk_layer)layer, NULL, NULL) == 0)
        return;
    ws(c, "<path d=\"");
    qrk_emit_layer(code, style, (qrk_layer)layer, &SVG_SINK, c);
    ws(c, "\"");
    w_fill(c, paint, prefix, id);
    ws(c, "/>\n");
}

/* ---- document ------------------------------------------------------------ */

qrk_status qrk_svg_write(const qrk_code *code, const qrk_style *style, const qrk_svg_opts *opts,
                         qrk_write_fn write, void *user)
{
    if (!code || !style || !write)
        return QRK_ERR_INVALID_ARGUMENT;
    qrk_svg_opts o;
    if (opts)
        o = *opts;
    else
        qrk_svg_opts_default(&o);
    const char *prefix = o.id_prefix && o.id_prefix[0] ? o.id_prefix : "qrk";

    qrk__layout L;
    qrk__layout_init(&L, code, style);
    svg_ctx c = {write, user, 0, 0};

    ws(&c, "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" viewBox=\"0 0 ");
    wn(&c, L.W);
    ws(&c, " ");
    wn(&c, L.H);
    ws(&c, "\"");
    if (o.width > 0) {
        ws(&c, " width=\"");
        wn(&c, o.width);
        ws(&c, "\" height=\"");
        wn(&c, o.width * L.H / L.W);
        ws(&c, "\"");
    }
    ws(&c, ">\n");

    const qrk_paint *bg = &style->background.paint;
    const qrk_paint *fg = &style->modules.paint;
    const qrk_paint *ef = &style->eyes.frame_paint;
    const qrk_paint *eb = &style->eyes.ball_paint;
    if (is_gradient(bg) || is_gradient(fg) || is_gradient(ef) || is_gradient(eb)) {
        ws(&c, "<defs>");
        if (is_gradient(bg)) w_gradient(&c, &L, QRK_LAYER_BACKGROUND, bg, prefix, "bg");
        if (is_gradient(fg)) w_gradient(&c, &L, QRK_LAYER_MODULES, fg, prefix, "fg");
        if (is_gradient(ef)) w_gradient(&c, &L, QRK_LAYER_EYE_FRAMES, ef, prefix, "ef");
        if (is_gradient(eb)) w_gradient(&c, &L, QRK_LAYER_EYE_BALLS, eb, prefix, "eb");
        ws(&c, "</defs>\n");
    }

    bool bg_visible = is_gradient(bg) || (bg->type == QRK_PAINT_SOLID && (bg->color & 0xFF) != 0);
    if (bg_visible) {
        ws(&c, "<rect width=\"");
        wn(&c, L.W);
        ws(&c, "\" height=\"");
        wn(&c, L.H);
        ws(&c, "\"");
        if (L.bg_radius > 0) {
            ws(&c, " rx=\"");
            wn(&c, L.bg_radius);
            ws(&c, "\"");
        }
        w_fill(&c, bg, prefix, "bg");
        ws(&c, "/>\n");
    }

    qrk_paint border = qrk_paint_solid(style->border.color);
    w_layer_path(&c, code, style, QRK_LAYER_BORDER, &border, prefix, "");
    w_layer_path(&c, code, style, QRK_LAYER_MODULES, fg, prefix, "fg");
    w_layer_path(&c, code, style, QRK_LAYER_EYE_FRAMES,
                 ef->type != QRK_PAINT_NONE ? ef : fg, prefix, ef->type != QRK_PAINT_NONE ? "ef" : "fg");
    w_layer_path(&c, code, style, QRK_LAYER_EYE_BALLS,
                 eb->type != QRK_PAINT_NONE ? eb : fg, prefix, eb->type != QRK_PAINT_NONE ? "eb" : "fg");
    qrk_paint logo_bg = qrk_paint_solid(style->logo.background);
    w_layer_path(&c, code, style, QRK_LAYER_LOGO_BACKGROUND, &logo_bg, prefix, "");

    if (L.has_logo && style->logo.href && style->logo.href[0]) {
        ws(&c, "<image x=\"");
        wn(&c, L.logo_cx - L.logo_half);
        ws(&c, "\" y=\"");
        wn(&c, L.logo_cy - L.logo_half);
        ws(&c, "\" width=\"");
        wn(&c, 2 * L.logo_half);
        ws(&c, "\" height=\"");
        wn(&c, 2 * L.logo_half);
        ws(&c, "\" preserveAspectRatio=\"xMidYMid meet\" xlink:href=\"");
        wesc(&c, style->logo.href);
        ws(&c, "\"/>\n");
    }

    if (L.has_label) {
        double f = style->label.size > 0.1 ? style->label.size : 0.1;
        ws(&c, "<text x=\"");
        wn(&c, L.label_x);
        ws(&c, "\" y=\"");
        wn(&c, L.label_baseline);
        ws(&c, "\" text-anchor=\"middle\" font-family=\"");
        wesc(&c, style->label.font && style->label.font[0] ? style->label.font : "sans-serif");
        ws(&c, "\" font-size=\"");
        wn(&c, f);
        ws(&c, "\"");
        if (style->label.bold)
            ws(&c, " font-weight=\"bold\"");
        ws(&c, " fill=\"");
        wcolor(&c, style->label.color);
        ws(&c, "\"");
        w_opacity(&c, "fill-opacity", style->label.color);
        ws(&c, ">");
        wesc(&c, style->label.text);
        ws(&c, "</text>\n");
    }

    ws(&c, "</svg>\n");
    return QRK_OK;
}

typedef struct {
    char *buf;
    size_t cap, len;
} buf_ctx;

static void buf_write(void *u, const char *data, size_t len)
{
    buf_ctx *b = (buf_ctx *)u;
    for (size_t i = 0; i < len; i++, b->len++)
        if (b->len + 1 < b->cap)
            b->buf[b->len] = data[i];
}

size_t qrk_svg_to_buffer(const qrk_code *code, const qrk_style *style, const qrk_svg_opts *opts,
                         char *buf, size_t cap)
{
    buf_ctx b = {buf, cap, 0};
    if (qrk_svg_write(code, style, opts, buf_write, &b) != QRK_OK)
        return 0;
    if (cap > 0)
        buf[b.len < cap ? b.len : cap - 1] = 0;
    return b.len;
}
