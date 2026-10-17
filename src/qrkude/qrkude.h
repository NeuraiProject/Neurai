/*
 * QRKude - styled QR Code generator
 * C99 reference implementation.
 *
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Overview
 * --------
 *   1. Encode:  qrk_encode()          text/bytes -> qrk_code (module matrix)
 *   2. Style:   qrk_style_default()   then tweak the qrk_style fields
 *               (or qrk_style_from_json() with the cross-language JSON format)
 *   3. Output:  qrk_svg_write()       streaming SVG (identical in every port)
 *               qrk_render_spans()    raster output as horizontal spans
 *               qrk_render_buffer()   raster output into a pixel buffer
 *               qrk_emit_layer()      vector geometry (for QPainter, Skia...)
 *
 * The library never allocates memory, except qrk_encode() when it is given a
 * NULL scratch buffer (disable with -DQRK_NO_MALLOC).
 */
#ifndef QRKUDE_H
#define QRKUDE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QRK_LIB_VERSION "0.1.0"

/* Largest QR version this build can produce. Lower it on small MCUs to shrink
 * qrk_code (version 10 -> 412 bytes, version 40 -> 3922 bytes). */
#ifndef QRK_MAX_VERSION
#define QRK_MAX_VERSION 40
#endif

#define QRK_SIZE_FOR_VERSION(v) ((v) * 4 + 17)
#define QRK_BUFFER_LEN_FOR_VERSION(v) \
    ((QRK_SIZE_FOR_VERSION(v) * QRK_SIZE_FOR_VERSION(v) + 7) / 8)
#define QRK_BUFFER_LEN_MAX QRK_BUFFER_LEN_FOR_VERSION(QRK_MAX_VERSION)

#define QRK_MAX_STOPS 8

typedef enum {
    QRK_OK = 0,
    QRK_ERR_INVALID_ARGUMENT = -1,
    QRK_ERR_DATA_TOO_LONG = -2,
    QRK_ERR_OUT_OF_MEMORY = -3,
    QRK_ERR_BUFFER_TOO_SMALL = -4,
    QRK_ERR_PARSE = -5
} qrk_status;

const char *qrk_status_str(qrk_status status);

/* ------------------------------------------------------------------------ */
/* Encoding                                                                 */
/* ------------------------------------------------------------------------ */

typedef enum {
    QRK_ECC_AUTO = -1,    /* MEDIUM, or HIGH with a logo (qrk_encode_for_style) */
    QRK_ECC_LOW = 0,      /* ~7% recovery  */
    QRK_ECC_MEDIUM = 1,   /* ~15% recovery */
    QRK_ECC_QUARTILE = 2, /* ~25% recovery */
    QRK_ECC_HIGH = 3      /* ~30% recovery */
} qrk_ecc;

typedef enum {
    QRK_MODE_NUMERIC = 1,
    QRK_MODE_ALPHANUMERIC = 2,
    QRK_MODE_BYTE = 4
} qrk_mode;

typedef struct {
    qrk_ecc ecc;      /* minimum error correction level (default AUTO)        */
    int min_version;  /* 1..40 (default 1)                                    */
    int max_version;  /* 1..40 (default QRK_MAX_VERSION)                      */
    int mask;         /* -1 = automatic (default), 0..7 = forced              */
    bool boost_ecc;   /* raise ECC while the version does not grow (default)  */
    bool eci;         /* prepend an ECI UTF-8 (26) header (default false)     */
} qrk_encode_opts;

typedef struct {
    uint8_t version; /* 1..40                  */
    uint8_t size;    /* modules per side       */
    uint8_t ecc;     /* qrk_ecc actually used  */
    uint8_t mask;    /* 0..7                   */
    uint8_t mode;    /* qrk_mode of the data   */
    uint8_t modules[QRK_BUFFER_LEN_MAX]; /* row-major bit matrix */
} qrk_code;

void qrk_encode_opts_default(qrk_encode_opts *opts);

/* Encodes `len` bytes. The mode (numeric / alphanumeric / byte) is chosen
 * automatically. `tmp` must be NULL or point to QRK_BUFFER_LEN_MAX bytes. */
qrk_status qrk_encode(qrk_code *out, const void *data, size_t len,
                      const qrk_encode_opts *opts, uint8_t *tmp);

/* Convenience wrapper for NUL-terminated (UTF-8) strings. */
qrk_status qrk_encode_text(qrk_code *out, const char *text,
                           const qrk_encode_opts *opts, uint8_t *tmp);

/* true = dark module. Out-of-range coordinates return false. */
bool qrk_get_module(const qrk_code *code, int x, int y);

/* ------------------------------------------------------------------------ */
/* Style                                                                    */
/* ------------------------------------------------------------------------ */

typedef uint32_t qrk_color; /* 0xRRGGBBAA */
#define QRK_RGBA(r, g, b, a) \
    ((qrk_color)(((uint32_t)(r) << 24) | ((uint32_t)(g) << 16) | ((uint32_t)(b) << 8) | (uint32_t)(a)))
#define QRK_RGB(r, g, b) QRK_RGBA(r, g, b, 255)
#define QRK_HEX(rgb) ((qrk_color)(((uint32_t)(rgb) << 8) | 0xFFu))
#define QRK_TRANSPARENT ((qrk_color)0)

typedef enum {
    QRK_MODULE_SQUARE = 0, /* classic squares (size < 1 adds gaps)           */
    QRK_MODULE_DOT,        /* circles                                        */
    QRK_MODULE_ROUNDED,    /* individual rounded squares                     */
    QRK_MODULE_DIAMOND,    /* rotated squares                                */
    QRK_MODULE_STAR,       /* four-point sparkles                            */
    QRK_MODULE_FLUID,      /* connected, outer corners rounded               */
    QRK_MODULE_LIQUID,     /* fluid + concave fillets on inner corners       */
    QRK_MODULE_BEVEL,      /* connected, outer corners cut at 45 degrees     */
    QRK_MODULE_CLASSY,     /* connected, top-left/bottom-right corners round */
    QRK_MODULE_HBARS,      /* horizontal runs merged into pills              */
    QRK_MODULE_VBARS,      /* vertical runs merged into pills                */
    QRK_MODULE_SHAPE_COUNT
} qrk_module_shape;

typedef enum {
    QRK_EYE_SQUARE = 0,
    QRK_EYE_ROUNDED,
    QRK_EYE_CIRCLE,
    QRK_EYE_LEAF,    /* two opposite corners fully rounded       */
    QRK_EYE_DROP,    /* all round except the corner facing center */
    QRK_EYE_BEVEL,   /* chamfered corners                         */
    QRK_EYE_DIAMOND, /* fully chamfered                           */
    QRK_EYE_DOTS,    /* frames: one dot per module; balls: circle  */
    QRK_EYE_SHAPE_COUNT,
    QRK_EYE_NONE = 255 /* alignment patterns only: draw as data modules */
} qrk_eye_shape;

typedef enum { QRK_LOGO_SQUARE = 0, QRK_LOGO_ROUNDED, QRK_LOGO_CIRCLE } qrk_logo_shape;
typedef enum { QRK_LABEL_BOTTOM = 0, QRK_LABEL_TOP } qrk_label_position;

typedef enum {
    QRK_PAINT_NONE = 0, /* transparent, or "inherit" for eye paints */
    QRK_PAINT_SOLID,
    QRK_PAINT_LINEAR,
    QRK_PAINT_RADIAL
} qrk_paint_type;

typedef struct {
    double offset; /* 0..1 */
    qrk_color color;
} qrk_stop;

typedef struct {
    uint8_t type;       /* qrk_paint_type                                   */
    uint8_t stop_count; /* gradients: 1..QRK_MAX_STOPS                       */
    qrk_color color;    /* SOLID                                            */
    double angle;       /* LINEAR: degrees, 0 = left->right, 90 = top->down */
    double cx, cy, r;   /* RADIAL: relative to the painted area             */
    qrk_stop stops[QRK_MAX_STOPS];
} qrk_paint;

typedef struct {
    double margin; /* quiet zone in modules (default 4) */

    struct {
        uint8_t shape;    /* qrk_module_shape                                */
        double size;      /* 0.1..1, dot/square/rounded/diamond/star/bars    */
        double roundness; /* 0..1, rounded/fluid/liquid/bevel/classy/bars    */
        qrk_paint paint;
    } modules;

    struct {
        uint8_t frame;        /* qrk_eye_shape of the 7x7 ring  */
        uint8_t ball;         /* qrk_eye_shape of the 3x3 center */
        qrk_paint frame_paint; /* NONE = same as modules         */
        qrk_paint ball_paint;  /* NONE = same as modules         */
    } eyes;

    struct {
        uint8_t frame; /* QRK_EYE_NONE (default) = draw like data modules */
        uint8_t ball;
    } alignment;

    struct {
        qrk_paint paint; /* NONE = transparent */
        double radius;   /* corner radius in modules */
    } background;

    struct {
        double width; /* modules, drawn outside the quiet zone (0 = none) */
        qrk_color color;
    } border;

    struct {
        double size;          /* fraction of the symbol width (0 = no logo) */
        double margin;        /* clear space around the logo, in modules    */
        uint8_t shape;        /* qrk_logo_shape of the cleared area          */
        bool excavate;        /* remove the modules behind the logo          */
        qrk_color background; /* fill of the cleared area (0 = none)         */
        const char *href;     /* SVG only: image URL or data: URI            */
    } logo;

    struct {
        const char *text; /* NULL/empty = no label. Not drawn by the raster */
        const char *font;
        double size; /* font size in modules */
        qrk_color color;
        uint8_t position; /* qrk_label_position */
        bool bold;
    } label;
} qrk_style;

void qrk_style_default(qrk_style *style);

qrk_paint qrk_paint_solid(qrk_color color);
qrk_paint qrk_paint_linear(double angle_deg, qrk_color from, qrk_color to);
qrk_paint qrk_paint_radial(qrk_color center, qrk_color edge);

/* Style names as used by the JSON format ("fluid", "leaf", ...).
 * Return -1 / NULL when unknown. */
int qrk_module_shape_from_name(const char *name);
const char *qrk_module_shape_name(int shape);
int qrk_eye_shape_from_name(const char *name);
const char *qrk_eye_shape_name(int shape);

/* Parses "#rgb", "#rrggbb", "#rrggbbaa" or "transparent". */
bool qrk_parse_color(const char *str, size_t len, qrk_color *out);

/* Recommended ECC for a style: HIGH when a logo is present, else MEDIUM. */
qrk_ecc qrk_recommended_ecc(const qrk_style *style);

/* Like qrk_encode, but QRK_ECC_AUTO resolves with qrk_recommended_ecc(style)
 * (HIGH when the style has a logo). qrk_encode treats AUTO as MEDIUM. */
qrk_status qrk_encode_for_style(qrk_code *out, const void *data, size_t len,
                                const qrk_encode_opts *opts, const qrk_style *style,
                                uint8_t *tmp);

/* Worst-case logo damage: max over RS blocks of
 * (codewords hidden by the logo area) / (codewords the block can correct).
 * 0 = no logo. > 1 = the code cannot be decoded. Keep it <= 0.6 or so. */
double qrk_logo_damage(const qrk_code *code, const qrk_style *style);

/* Scannability checks (bit flags returned by qrk_lint). */
#define QRK_LINT_LOGO_RISKY 0x01            /* logo damage > 0.7             */
#define QRK_LINT_LOGO_UNREADABLE 0x02       /* logo damage > 1: cannot decode */
#define QRK_LINT_LOW_CONTRAST 0x04          /* WCAG contrast below 3:1       */
#define QRK_LINT_INVERTED 0x08              /* light modules on dark ground  */
#define QRK_LINT_TRANSPARENT_BACKGROUND 0x10
#define QRK_LINT_QUIET_ZONE 0x20            /* margin below 2 modules        */
#define QRK_LINT_SMALL_MODULES 0x40         /* module size below 0.6         */
#define QRK_LINT_EYE_SHAPES 0x80            /* diamond frame, or diamond ball in a square/leaf frame */

uint32_t qrk_lint(const qrk_code *code, const qrk_style *style);
/* "logo-risky", "low-contrast", ... for a single flag; NULL if unknown. */
const char *qrk_lint_name(uint32_t flag);

/* ------------------------------------------------------------------------ */
/* Layout and vector geometry                                               */
/* ------------------------------------------------------------------------ */

/* All coordinates are in modules ("canvas units"); multiply by your scale. */
typedef struct {
    double width, height;        /* whole canvas                         */
    double symbol_x, symbol_y;   /* top-left of module (0,0)             */
    int modules;                 /* modules per side                     */
    bool has_logo;
    double logo_x, logo_y, logo_size; /* logo image box (square)          */
    bool has_label;
    double label_x, label_baseline;   /* text anchor (middle), baseline   */
} qrk_layout;

void qrk_get_layout(const qrk_code *code, const qrk_style *style, qrk_layout *out);

typedef enum {
    QRK_LAYER_BACKGROUND = 0,
    QRK_LAYER_BORDER,
    QRK_LAYER_MODULES,
    QRK_LAYER_EYE_FRAMES,
    QRK_LAYER_EYE_BALLS,
    QRK_LAYER_LOGO_BACKGROUND,
    QRK_LAYER_COUNT
} qrk_layer;

/* Path callbacks. All sub-paths are closed; fill with the non-zero rule.
 * arc_to draws a circular arc of radius r from the current point to (x, y)
 * around the center (cx, cy); clockwise refers to the screen (y down).
 * Arcs never exceed 90 degrees. */
typedef struct {
    void (*move_to)(void *user, double x, double y);
    void (*line_to)(void *user, double x, double y);
    void (*arc_to)(void *user, double r, bool clockwise, double x, double y,
                   double cx, double cy);
    void (*close)(void *user);
} qrk_path_sink;

/* Emits the geometry of one layer. Returns the number of sub-paths. */
int qrk_emit_layer(const qrk_code *code, const qrk_style *style, qrk_layer layer,
                   const qrk_path_sink *sink, void *user);

/* Whether a layer draws anything visible, with the same rules as the SVG
 * writer (background with alpha > 0 or a gradient, border width > 0, logo
 * background only with a logo and alpha > 0). */
bool qrk_layer_visible(const qrk_code *code, const qrk_style *style, qrk_layer layer);

/* Paint used by a layer (eye paints resolved, border/logo as solid). */
qrk_paint qrk_layer_paint(const qrk_style *style, qrk_layer layer);

/* Gradient geometry in canvas units, as written to the SVG. */
typedef struct {
    double x1, y1, x2, y2; /* LINEAR */
    double cx, cy, r;      /* RADIAL */
} qrk_gradient_geometry;

void qrk_gradient_geometry_for(const qrk_code *code, const qrk_style *style,
                               qrk_layer layer, qrk_gradient_geometry *out);

/* ------------------------------------------------------------------------ */
/* SVG                                                                      */
/* ------------------------------------------------------------------------ */

typedef void (*qrk_write_fn)(void *user, const char *data, size_t len);

typedef struct {
    double width;          /* width attribute in px (0 = omit width/height) */
    const char *id_prefix; /* gradient id prefix (default "qrk")            */
} qrk_svg_opts;

void qrk_svg_opts_default(qrk_svg_opts *opts);

qrk_status qrk_svg_write(const qrk_code *code, const qrk_style *style,
                         const qrk_svg_opts *opts, qrk_write_fn write, void *user);

/* Writes a NUL-terminated SVG into buf. Returns the full length (without the
 * NUL) even when it does not fit, like snprintf. */
size_t qrk_svg_to_buffer(const qrk_code *code, const qrk_style *style,
                         const qrk_svg_opts *opts, char *buf, size_t cap);

/* Formats a number the way every QRKude port does (max 3 decimals). */
size_t qrk_format_number(double value, char out[32]);

/* ------------------------------------------------------------------------ */
/* Raster                                                                   */
/* ------------------------------------------------------------------------ */

typedef enum {
    QRK_PIXEL_RGBA8888 = 0,   /* bytes R,G,B,A                          */
    QRK_PIXEL_BGRA8888,       /* bytes B,G,R,A (LVGL 9 ARGB8888, Cairo) */
    QRK_PIXEL_RGB888,         /* bytes R,G,B                            */
    QRK_PIXEL_RGB565,         /* uint16 native endian                   */
    QRK_PIXEL_RGB565_SWAPPED, /* uint16 byte-swapped (SPI displays)     */
    QRK_PIXEL_GRAY8,
    QRK_PIXEL_MONO /* 1 bpp, MSB first, 1 = dark (luminance < 50%) */
} qrk_pixel_format;

typedef struct {
    int width, height;
    qrk_pixel_format format;
    const void *pixels;
    size_t stride; /* bytes per row, 0 = tightly packed */
} qrk_image;

typedef struct {
    int width, height;     /* output size in pixels                         */
    int supersample;       /* anti-aliasing: 1 = off (default 2), max 4     */
    bool integer_scale;    /* snap modules to whole pixels (default true)   */
    qrk_color clear_color; /* outside the canvas / under transparency       */
    const qrk_image *logo; /* optional logo bitmap (style.logo.size > 0)    */
} qrk_raster_opts;

void qrk_raster_opts_default(qrk_raster_opts *opts, int width, int height);

/* Called for each horizontal run of equally colored pixels, row by row.
 * Colors are already composited over clear_color. */
typedef void (*qrk_span_fn)(void *user, int x, int y, int len, qrk_color color);

qrk_status qrk_render_spans(const qrk_code *code, const qrk_style *style,
                            const qrk_raster_opts *opts, qrk_span_fn span,
                            void *user);

size_t qrk_pixel_buffer_size(qrk_pixel_format format, int width, int height);

qrk_status qrk_render_buffer(const qrk_code *code, const qrk_style *style,
                             const qrk_raster_opts *opts, qrk_pixel_format format,
                             void *pixels, size_t stride);

/* ------------------------------------------------------------------------ */
/* JSON style (cross-language format, see docs/SPEC.md)                     */
/* ------------------------------------------------------------------------ */

/* Parses {"encode": {...}, "style": {...}, "svg": {...}} or a bare style
 * object. Any output pointer may be NULL. Fields absent from the JSON keep
 * their current value: an absent "ecc" leaves QRK_ECC_AUTO in place, which
 * qrk_encode_for_style() resolves. Strings (logo href, label) are copied
 * into `arena`, which must outlive the style. */
qrk_status qrk_style_from_json(const char *json, size_t len, qrk_style *style,
                               qrk_encode_opts *encode, qrk_svg_opts *svg,
                               char *arena, size_t arena_len);

/* ------------------------------------------------------------------------ */
/* Payload helpers. All return the full length like snprintf.               */
/* ------------------------------------------------------------------------ */

/* auth: "WPA", "WEP", "nopass" or NULL. */
size_t qrk_payload_wifi(char *out, size_t cap, const char *ssid,
                        const char *password, const char *auth, bool hidden);
size_t qrk_payload_email(char *out, size_t cap, const char *to,
                         const char *subject, const char *body);
size_t qrk_payload_sms(char *out, size_t cap, const char *number, const char *message);
size_t qrk_payload_tel(char *out, size_t cap, const char *number);
size_t qrk_payload_geo(char *out, size_t cap, double latitude, double longitude);

typedef struct {
    const char *first_name, *last_name, *organization, *title;
    const char *phone, *email, *url, *address, *note;
} qrk_vcard;
size_t qrk_payload_vcard(char *out, size_t cap, const qrk_vcard *card);

typedef struct {
    const char *summary;
    const char *start, *end; /* "20261017T120000Z" style timestamps */
    const char *location, *description;
} qrk_event;
size_t qrk_payload_event(char *out, size_t cap, const qrk_event *event);

#ifdef __cplusplus
}
#endif

#endif /* QRKUDE_H */
