/*
 * QRKude - internal definitions shared by the core translation units.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef QRK_INTERNAL_H
#define QRK_INTERNAL_H

#include "qrkude.h"

#define QRK_CORNER_NONE 0
#define QRK_CORNER_ROUND 1
#define QRK_CORNER_CHAMFER 2

/* Corner order everywhere: top-left, top-right, bottom-right, bottom-left. */
#define QRK_TL 0
#define QRK_TR 1
#define QRK_BR 2
#define QRK_BL 3

typedef struct {
    uint8_t kind;
    double a; /* radius or chamfer length */
} qrk__corner;

/* Axis-aligned rectangle with per-corner rounding / chamfering. */
typedef struct {
    double x0, y0, x1, y1;
    qrk__corner c[4];
} qrk__crect;

typedef struct {
    const qrk_code *code;
    const qrk_style *style;
    int n;
    /* clamped style values */
    double margin, border, bg_radius;
    int shape;
    double size, roundness;
    /* canvas */
    double W, H, ox, oy;
    bool has_label;
    double band_y, band_h, label_x, label_baseline;
    /* logo (canvas units) */
    bool has_logo, excavate;
    double logo_cx, logo_cy, logo_half, logo_area_half;
    /* alignment patterns */
    bool align_styled;
    int align_count;
    uint8_t align_pos[7];
} qrk__layout;

/* qrk_encode.c */
int qrk__alignment_positions(int version, uint8_t out[7]);
bool qrk__is_function_module(int version, int x, int y);
int qrk__ecc_codewords_per_block(int ecc, int version);
int qrk__num_ecc_blocks(int ecc, int version);
int qrk__raw_codewords(int version);

/* qrk_layout.c */
void qrk__layout_init(qrk__layout *L, const qrk_code *code, const qrk_style *style);
bool qrk__is_finder(int n, int x, int y);
bool qrk__in_styled_alignment(const qrk__layout *L, int x, int y);
bool qrk__is_excavated(const qrk__layout *L, int x, int y);
bool qrk__is_data_cell(const qrk__layout *L, int x, int y);
bool qrk__is_data_dark(const qrk__layout *L, int x, int y);
/* Cell-local shape of a dark data module; returns false for the star shape
 * (handled separately). */
bool qrk__module_crect(const qrk__layout *L, int x, int y, qrk__crect *out);
/* Which corners of a light data cell get a liquid fillet (bit i = corner i). */
int qrk__fillet_mask(const qrk__layout *L, int x, int y);
void qrk__eye_corners(int shape, double s, int center_corner, qrk__corner out[4]);
int qrk__ball_shape(int shape);
void qrk__inner_corners(const qrk__corner outer[4], double s_inner, qrk__corner out[4]);
void qrk__logo_bg_crect(const qrk__layout *L, qrk__crect *out);
qrk_paint qrk__resolve_paint(const qrk_style *style, int layer);
void qrk__gradient_geometry(const qrk__layout *L, int layer, const qrk_paint *p,
                            qrk_gradient_geometry *out);

static inline double qrk__clamp(double v, double lo, double hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

static inline bool qrk__bit(const uint8_t *buf, int index)
{
    return (buf[index >> 3] >> (index & 7)) & 1;
}

#endif
