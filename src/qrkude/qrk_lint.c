/*
 * QRKude - scannability checks.
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <math.h>

#include "qrk_internal.h"

/* WCAG relative luminance of a color composited over white. */
static double luminance(qrk_color c)
{
    double a = (c & 0xFF) / 255.0;
    double ch[3];
    for (int i = 0; i < 3; i++) {
        double v = ((c >> (24 - 8 * i)) & 0xFF) / 255.0;
        v = v * a + (1 - a);
        ch[i] = v <= 0.04045 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4);
    }
    return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}

/* Min / max luminance over a paint (solid color or gradient stops). */
static bool paint_range(const qrk_paint *p, double *lo, double *hi)
{
    if (p->type == QRK_PAINT_SOLID) {
        *lo = *hi = luminance(p->color);
        return true;
    }
    if ((p->type == QRK_PAINT_LINEAR || p->type == QRK_PAINT_RADIAL) && p->stop_count > 0) {
        int n = p->stop_count < QRK_MAX_STOPS ? p->stop_count : QRK_MAX_STOPS;
        *lo = 1;
        *hi = 0;
        for (int i = 0; i < n; i++) {
            double l = luminance(p->stops[i].color);
            if (l < *lo) *lo = l;
            if (l > *hi) *hi = l;
        }
        return true;
    }
    return false;
}

uint32_t qrk_lint(const qrk_code *code, const qrk_style *style)
{
    uint32_t w = 0;
    qrk__layout L;
    qrk__layout_init(&L, code, style);

    if (L.has_logo) {
        double d = qrk_logo_damage(code, style);
        if (d > 1)
            w |= QRK_LINT_LOGO_UNREADABLE;
        else if (d > 0.7)
            w |= QRK_LINT_LOGO_RISKY;
    }

    double bg_lo = 1, bg_hi = 1;
    const qrk_paint *bg = &style->background.paint;
    if (!paint_range(bg, &bg_lo, &bg_hi) ||
        (bg->type == QRK_PAINT_SOLID && (bg->color & 0xFF) == 0)) {
        w |= QRK_LINT_TRANSPARENT_BACKGROUND;
        bg_lo = bg_hi = 1;
    }
    double fg_lo = 1, fg_hi = 0;
    bool any = false;
    for (int layer = QRK_LAYER_MODULES; layer <= QRK_LAYER_EYE_BALLS; layer++) {
        qrk_paint p = qrk__resolve_paint(style, layer);
        double lo, hi;
        if (!paint_range(&p, &lo, &hi))
            continue;
        any = true;
        if (lo < fg_lo) fg_lo = lo;
        if (hi > fg_hi) fg_hi = hi;
    }
    if (!any)
        fg_lo = fg_hi = 0;
    double contrast;
    if ((fg_lo + fg_hi) / 2 > (bg_lo + bg_hi) / 2) {
        w |= QRK_LINT_INVERTED;
        contrast = (fg_lo + 0.05) / (bg_hi + 0.05);
    } else {
        contrast = (bg_lo + 0.05) / (fg_hi + 0.05);
    }
    if (contrast < 3)
        w |= QRK_LINT_LOW_CONTRAST;

    if (L.margin < 2)
        w |= QRK_LINT_QUIET_ZONE;

    switch (L.shape) {
    case QRK_MODULE_SQUARE: case QRK_MODULE_DOT: case QRK_MODULE_ROUNDED:
    case QRK_MODULE_DIAMOND: case QRK_MODULE_STAR: case QRK_MODULE_HBARS: case QRK_MODULE_VBARS:
        if (L.size < 0.6)
            w |= QRK_LINT_SMALL_MODULES;
        break;
    default:
        break;
    }

    /* Measured with zxing: diamond frames break finder detection with any
     * ball; diamond balls only work inside round or beveled frames. */
    int frame = style->eyes.frame, ball = qrk__ball_shape(style->eyes.ball);
    if (frame == QRK_EYE_DIAMOND ||
        (ball == QRK_EYE_DIAMOND && (frame == QRK_EYE_SQUARE || frame == QRK_EYE_LEAF)))
        w |= QRK_LINT_EYE_SHAPES;
    return w;
}

const char *qrk_lint_name(uint32_t flag)
{
    switch (flag) {
    case QRK_LINT_LOGO_RISKY: return "logo-risky";
    case QRK_LINT_LOGO_UNREADABLE: return "logo-unreadable";
    case QRK_LINT_LOW_CONTRAST: return "low-contrast";
    case QRK_LINT_INVERTED: return "inverted";
    case QRK_LINT_TRANSPARENT_BACKGROUND: return "transparent-background";
    case QRK_LINT_QUIET_ZONE: return "quiet-zone";
    case QRK_LINT_SMALL_MODULES: return "small-modules";
    case QRK_LINT_EYE_SHAPES: return "eye-shapes";
    default: return NULL;
    }
}
