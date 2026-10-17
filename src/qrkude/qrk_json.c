/*
 * QRKude - JSON style reader (no allocation, locale independent).
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>
#if defined(__AVR__) && !defined(QRK_NO_LOCALE)
#define QRK_NO_LOCALE /* avr-libc's <locale.h> has no struct lconv */
#endif
#ifndef QRK_NO_LOCALE
#include <locale.h>
#endif

#include "qrk_internal.h"

typedef struct {
    const char *s;
    size_t len, pos;
    char *arena;
    size_t arena_len, arena_pos;
    bool err, arena_full;
} jp;

static void ws(jp *p)
{
    while (p->pos < p->len && (p->s[p->pos] == ' ' || p->s[p->pos] == '\t' ||
                               p->s[p->pos] == '\n' || p->s[p->pos] == '\r'))
        p->pos++;
}

static char peek(jp *p)
{
    ws(p);
    return p->pos < p->len ? p->s[p->pos] : 0;
}

static bool eat(jp *p, char c)
{
    if (peek(p) == c) {
        p->pos++;
        return true;
    }
    return false;
}

static bool fail(jp *p)
{
    p->err = true;
    return false;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool read_hex4(jp *p, uint32_t *out)
{
    if (p->pos + 4 > p->len)
        return false;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(p->s[p->pos++]);
        if (h < 0)
            return false;
        v = v << 4 | (uint32_t)h;
    }
    *out = v;
    return true;
}

/* Parses a string into dst (NUL-terminated). Returns its length or -1.
 * With `truncate`, a string that does not fit yields "" (used for object
 * keys: an over-long key cannot be a known one and is skipped). */
static long parse_string_ex(jp *p, char *dst, size_t cap, bool truncate)
{
    bool overflow = false;
    if (!eat(p, '"') || cap == 0) {
        fail(p);
        return -1;
    }
    size_t n = 0;
#define EMIT(ch) do { if (n + 1 >= cap) { if (!truncate) { fail(p); return -1; } overflow = true; } else dst[n++] = (char)(ch); } while (0)
    while (p->pos < p->len) {
        char c = p->s[p->pos++];
        if (c == '"') {
            if (overflow)
                n = 0;
            dst[n] = 0;
            return (long)n;
        }
        if (c != '\\') {
            EMIT(c);
            continue;
        }
        if (p->pos >= p->len)
            break;
        c = p->s[p->pos++];
        switch (c) {
        case 'n': EMIT('\n'); break;
        case 't': EMIT('\t'); break;
        case 'r': EMIT('\r'); break;
        case 'b': EMIT('\b'); break;
        case 'f': EMIT('\f'); break;
        case 'u': {
            uint32_t cp;
            if (!read_hex4(p, &cp)) { fail(p); return -1; }
            if (cp >= 0xD800 && cp < 0xDC00 && p->pos + 6 <= p->len && p->s[p->pos] == '\\' &&
                p->s[p->pos + 1] == 'u') {
                uint32_t lo;
                p->pos += 2;
                if (!read_hex4(p, &lo)) { fail(p); return -1; }
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            }
            if (cp < 0x80) {
                EMIT(cp);
            } else if (cp < 0x800) {
                EMIT(0xC0 | (cp >> 6)); EMIT(0x80 | (cp & 63));
            } else if (cp < 0x10000) {
                EMIT(0xE0 | (cp >> 12)); EMIT(0x80 | ((cp >> 6) & 63)); EMIT(0x80 | (cp & 63));
            } else {
                EMIT(0xF0 | (cp >> 18)); EMIT(0x80 | ((cp >> 12) & 63));
                EMIT(0x80 | ((cp >> 6) & 63)); EMIT(0x80 | (cp & 63));
            }
            break;
        }
        default: EMIT(c); break;
        }
    }
#undef EMIT
    fail(p);
    return -1;
}

static long parse_string(jp *p, char *dst, size_t cap)
{
    return parse_string_ex(p, dst, cap, false);
}

static bool skip_value(jp *p);

static const char *arena_string(jp *p)
{
    if (peek(p) == 'n' && p->pos + 4 <= p->len && strncmp(p->s + p->pos, "null", 4) == 0) {
        p->pos += 4;
        return NULL;
    }
    if (!p->arena) {
        skip_value(p);
        return NULL;
    }
    char *dst = p->arena + p->arena_pos;
    size_t start = p->pos;
    long n = parse_string(p, dst, p->arena_len - p->arena_pos);
    if (n < 0) {
        /* distinguish "does not fit" from malformed JSON */
        size_t save = p->pos;
        p->pos = start;
        p->err = false;
        if (skip_value(p))
            p->arena_full = true;
        p->pos = save;
        p->err = true;
        return NULL;
    }
    p->arena_pos += (size_t)n + 1;
    return dst;
}

/* JSON numbers become the nearest double. Short inputs (<= 15 significant
 * digits, |exponent| <= 22) are converted exactly with one rounding; longer
 * ones go through strtod with the locale's decimal point substituted, so a
 * comma locale (es_ES, de_DE...) cannot break parsing. */
static bool parse_number(jp *p, double *out)
{
    ws(p);
    size_t start = p->pos;
    bool neg = false;
    if (p->pos < p->len && p->s[p->pos] == '-') {
        neg = true;
        p->pos++;
    }
    uint64_t mant = 0;
    int digits = 0, scale = 0;
    bool any = false, exact = true;
    while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') {
        if (digits < 18) { mant = mant * 10 + (uint64_t)(p->s[p->pos] - '0'); if (mant) digits++; }
        else { scale++; exact = false; }
        p->pos++;
        any = true;
    }
    if (p->pos < p->len && p->s[p->pos] == '.') {
        p->pos++;
        while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') {
            if (digits < 18) { mant = mant * 10 + (uint64_t)(p->s[p->pos] - '0'); if (mant) digits++; scale--; }
            else exact = false;
            p->pos++;
            any = true;
        }
    }
    if (!any)
        return fail(p);
    if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
        p->pos++;
        bool eneg = false;
        if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-'))
            eneg = p->s[p->pos++] == '-';
        int e = 0;
        while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') {
            if (e < 100000)
                e = e * 10 + (p->s[p->pos] - '0');
            p->pos++;
        }
        scale += eneg ? -e : e;
    }
    if (exact && digits <= 15 && scale >= -22 && scale <= 22) {
        double v = (double)mant, pow10 = 1;
        for (int k = scale < 0 ? -scale : scale; k > 0; k--)
            pow10 *= 10;
        v = scale < 0 ? v / pow10 : v * pow10;
        *out = neg ? -v : v;
        return true;
    }
    char buf[400];
    size_t n = p->pos - start;
    if (n >= sizeof buf)
        return fail(p);
    char point = '.';
#ifndef QRK_NO_LOCALE
    const struct lconv *lc = localeconv();
    if (lc && lc->decimal_point && lc->decimal_point[0])
        point = lc->decimal_point[0];
#endif
    for (size_t i = 0; i < n; i++)
        buf[i] = p->s[start + i] == '.' ? point : p->s[start + i];
    buf[n] = 0;
    *out = strtod(buf, NULL);
    return true;
}

static bool parse_literal(jp *p, const char *lit)
{
    size_t n = strlen(lit);
    ws(p);
    if (p->pos + n <= p->len && strncmp(p->s + p->pos, lit, n) == 0) {
        p->pos += n;
        return true;
    }
    return false;
}

static bool is_null(jp *p)
{
    return peek(p) == 'n' && parse_literal(p, "null");
}

static bool parse_bool(jp *p, bool *out)
{
    if (parse_literal(p, "true")) { *out = true; return true; }
    if (parse_literal(p, "false")) { *out = false; return true; }
    return fail(p);
}

static bool skip_value(jp *p)
{
    char c = peek(p);
    if (c == '"') {
        p->pos++;
        while (p->pos < p->len) {
            char ch = p->s[p->pos++];
            if (ch == '\\') p->pos++;
            else if (ch == '"') return true;
        }
        return fail(p);
    }
    if (c == '{' || c == '[') {
        char close = c == '{' ? '}' : ']';
        p->pos++;
        if (eat(p, close))
            return true;
        do {
            if (c == '{') {
                char key[32];
                if (parse_string_ex(p, key, sizeof key, true) < 0 || !eat(p, ':'))
                    return fail(p);
            }
            if (!skip_value(p))
                return false;
        } while (eat(p, ','));
        return eat(p, close) || fail(p);
    }
    if (parse_literal(p, "true") || parse_literal(p, "false") || parse_literal(p, "null"))
        return true;
    double d;
    return parse_number(p, &d);
}

/* Iterates object members: call with *first = true; returns false at '}'. */
static bool next_key(jp *p, bool *first, char *key, size_t cap)
{
    if (p->err)
        return false;
    if (*first) {
        *first = false;
        if (!eat(p, '{'))
            return fail(p);
        if (eat(p, '}'))
            return false;
    } else {
        if (eat(p, '}'))
            return false;
        if (!eat(p, ','))
            return fail(p);
    }
    if (parse_string_ex(p, key, cap, true) < 0 || !eat(p, ':'))
        return fail(p);
    return true;
}

static bool parse_color_value(jp *p, qrk_color *out)
{
    if (is_null(p)) {
        *out = QRK_TRANSPARENT;
        return true;
    }
    char buf[32];
    long n = parse_string(p, buf, sizeof buf);
    if (n < 0 || !qrk_parse_color(buf, (size_t)n, out))
        return fail(p);
    return true;
}

static bool parse_paint(jp *p, qrk_paint *out)
{
    if (is_null(p)) {
        memset(out, 0, sizeof *out);
        out->type = QRK_PAINT_NONE;
        return true;
    }
    if (peek(p) == '"') {
        qrk_color c;
        if (!parse_color_value(p, &c))
            return false;
        *out = qrk_paint_solid(c);
        return true;
    }
    *out = qrk_paint_solid(0);
    out->type = QRK_PAINT_LINEAR;
    char key[32];
    bool first = true;
    while (next_key(p, &first, key, sizeof key)) {
        if (strcmp(key, "type") == 0) {
            char t[16];
            if (parse_string(p, t, sizeof t) < 0)
                return false;
            if (strcmp(t, "radial") == 0) out->type = QRK_PAINT_RADIAL;
            else if (strcmp(t, "linear") == 0) out->type = QRK_PAINT_LINEAR;
            else return fail(p);
        } else if (strcmp(key, "angle") == 0) {
            parse_number(p, &out->angle);
        } else if (strcmp(key, "cx") == 0) {
            parse_number(p, &out->cx);
        } else if (strcmp(key, "cy") == 0) {
            parse_number(p, &out->cy);
        } else if (strcmp(key, "r") == 0) {
            parse_number(p, &out->r);
        } else if (strcmp(key, "stops") == 0) {
            if (!eat(p, '['))
                return fail(p);
            out->stop_count = 0;
            if (!eat(p, ']')) {
                do {
                    qrk_stop st = {0, 0};
                    bool f2 = true;
                    while (next_key(p, &f2, key, sizeof key)) {
                        if (strcmp(key, "offset") == 0) parse_number(p, &st.offset);
                        else if (strcmp(key, "color") == 0) parse_color_value(p, &st.color);
                        else skip_value(p);
                    }
                    if (out->stop_count < QRK_MAX_STOPS)
                        out->stops[out->stop_count++] = st;
                } while (!p->err && eat(p, ','));
                if (!eat(p, ']'))
                    return fail(p);
            }
        } else {
            skip_value(p);
        }
    }
    if (out->stop_count > 0)
        out->color = out->stops[0].color;
    return !p->err;
}

static bool parse_shape(jp *p, uint8_t *out, bool eye, bool allow_null)
{
    if (is_null(p)) {
        if (!allow_null)
            return fail(p);
        *out = QRK_EYE_NONE;
        return true;
    }
    char name[16];
    if (parse_string(p, name, sizeof name) < 0)
        return false;
    int v = eye ? qrk_eye_shape_from_name(name) : qrk_module_shape_from_name(name);
    if (v < 0)
        return fail(p);
    *out = (uint8_t)v;
    return true;
}

static bool parse_style_key(jp *p, const char *k, qrk_style *s)
{
    char key[32];
    bool first = true;
    if (strcmp(k, "margin") == 0)
        return parse_number(p, &s->margin);

    if (strcmp(k, "modules") == 0) {
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "shape") == 0) parse_shape(p, &s->modules.shape, false, false);
            else if (strcmp(key, "size") == 0) parse_number(p, &s->modules.size);
            else if (strcmp(key, "roundness") == 0) parse_number(p, &s->modules.roundness);
            else if (strcmp(key, "color") == 0) parse_paint(p, &s->modules.paint);
            else skip_value(p);
        }
    } else if (strcmp(k, "eyes") == 0) {
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "frame") == 0) parse_shape(p, &s->eyes.frame, true, false);
            else if (strcmp(key, "ball") == 0) parse_shape(p, &s->eyes.ball, true, false);
            else if (strcmp(key, "frameColor") == 0) parse_paint(p, &s->eyes.frame_paint);
            else if (strcmp(key, "ballColor") == 0) parse_paint(p, &s->eyes.ball_paint);
            else skip_value(p);
        }
    } else if (strcmp(k, "alignment") == 0) {
        if (is_null(p))
            return true;
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "frame") == 0) parse_shape(p, &s->alignment.frame, true, true);
            else if (strcmp(key, "ball") == 0) parse_shape(p, &s->alignment.ball, true, true);
            else skip_value(p);
        }
    } else if (strcmp(k, "background") == 0) {
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "color") == 0) parse_paint(p, &s->background.paint);
            else if (strcmp(key, "radius") == 0) parse_number(p, &s->background.radius);
            else skip_value(p);
        }
    } else if (strcmp(k, "border") == 0) {
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "width") == 0) parse_number(p, &s->border.width);
            else if (strcmp(key, "color") == 0) parse_color_value(p, &s->border.color);
            else skip_value(p);
        }
    } else if (strcmp(k, "logo") == 0) {
        if (is_null(p)) {
            s->logo.size = 0;
            return true;
        }
        s->logo.size = 0.2;
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "href") == 0) s->logo.href = arena_string(p);
            else if (strcmp(key, "size") == 0) parse_number(p, &s->logo.size);
            else if (strcmp(key, "margin") == 0) parse_number(p, &s->logo.margin);
            else if (strcmp(key, "excavate") == 0) parse_bool(p, &s->logo.excavate);
            else if (strcmp(key, "background") == 0) parse_color_value(p, &s->logo.background);
            else if (strcmp(key, "shape") == 0) {
                char name[16];
                if (parse_string(p, name, sizeof name) < 0) return false;
                if (strcmp(name, "square") == 0) s->logo.shape = QRK_LOGO_SQUARE;
                else if (strcmp(name, "rounded") == 0) s->logo.shape = QRK_LOGO_ROUNDED;
                else if (strcmp(name, "circle") == 0) s->logo.shape = QRK_LOGO_CIRCLE;
                else return fail(p);
            } else skip_value(p);
        }
    } else if (strcmp(k, "label") == 0) {
        if (is_null(p)) {
            s->label.text = NULL;
            return true;
        }
        while (next_key(p, &first, key, sizeof key)) {
            if (strcmp(key, "text") == 0) s->label.text = arena_string(p);
            else if (strcmp(key, "font") == 0) s->label.font = arena_string(p);
            else if (strcmp(key, "size") == 0) parse_number(p, &s->label.size);
            else if (strcmp(key, "color") == 0) parse_color_value(p, &s->label.color);
            else if (strcmp(key, "bold") == 0) parse_bool(p, &s->label.bold);
            else if (strcmp(key, "position") == 0) {
                char name[16];
                if (parse_string(p, name, sizeof name) < 0) return false;
                if (strcmp(name, "bottom") == 0) s->label.position = QRK_LABEL_BOTTOM;
                else if (strcmp(name, "top") == 0) s->label.position = QRK_LABEL_TOP;
                else return fail(p);
            } else skip_value(p);
        }
    } else {
        return skip_value(p);
    }
    return !p->err;
}

static bool parse_encode(jp *p, qrk_encode_opts *e)
{
    char key[32];
    bool first = true;
    double d;
    while (next_key(p, &first, key, sizeof key)) {
        if (strcmp(key, "ecc") == 0) {
            char v[4];
            if (parse_string(p, v, sizeof v) < 0) return false;
            const char *levels = "LMQH";
            const char *f = v[0] && !v[1] ? strchr(levels, v[0]) : NULL;
            if (!f) return fail(p);
            e->ecc = (qrk_ecc)(f - levels);
        } else if (strcmp(key, "minVersion") == 0) {
            if (parse_number(p, &d)) e->min_version = (int)d;
        } else if (strcmp(key, "maxVersion") == 0) {
            if (parse_number(p, &d)) e->max_version = (int)d;
        } else if (strcmp(key, "mask") == 0) {
            if (parse_number(p, &d)) e->mask = (int)d;
        } else if (strcmp(key, "boostEcc") == 0) {
            parse_bool(p, &e->boost_ecc);
        } else if (strcmp(key, "eci") == 0) {
            parse_bool(p, &e->eci);
        } else {
            skip_value(p);
        }
    }
    return !p->err;
}

static bool parse_svg(jp *p, qrk_svg_opts *o)
{
    char key[32];
    bool first = true;
    while (next_key(p, &first, key, sizeof key)) {
        if (strcmp(key, "width") == 0) parse_number(p, &o->width);
        else if (strcmp(key, "idPrefix") == 0) o->id_prefix = arena_string(p);
        else skip_value(p);
    }
    return !p->err;
}

qrk_status qrk_style_from_json(const char *json, size_t len, qrk_style *style,
                               qrk_encode_opts *encode, qrk_svg_opts *svg, char *arena,
                               size_t arena_len)
{
    if (!json)
        return QRK_ERR_INVALID_ARGUMENT;
    jp p = {json, len, 0, arena, arena_len, 0, false, false};
    qrk_style dummy_style;
    qrk_encode_opts dummy_enc;
    qrk_svg_opts dummy_svg;
    if (!style) { qrk_style_default(&dummy_style); style = &dummy_style; }
    if (!encode) { qrk_encode_opts_default(&dummy_enc); encode = &dummy_enc; }
    if (!svg) { qrk_svg_opts_default(&dummy_svg); svg = &dummy_svg; }

    char key[32];
    bool first = true;
    while (next_key(&p, &first, key, sizeof key)) {
        if (strcmp(key, "encode") == 0) {
            parse_encode(&p, encode);
        } else if (strcmp(key, "svg") == 0) {
            parse_svg(&p, svg);
        } else if (strcmp(key, "style") == 0) {
            char k2[32];
            bool f2 = true;
            while (next_key(&p, &f2, k2, sizeof k2))
                parse_style_key(&p, k2, style);
        } else {
            parse_style_key(&p, key, style);
        }
    }
    if (p.err)
        return p.arena_full ? QRK_ERR_BUFFER_TOO_SMALL : QRK_ERR_PARSE;
    return QRK_OK;
}
