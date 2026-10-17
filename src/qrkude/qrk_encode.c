/*
 * QRKude - QR Code encoder (ISO/IEC 18004, model 2, versions 1-40).
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#include "qrk_internal.h"

/* Index: [ecc][version], ecc in L, M, Q, H order. */
static const int8_t ECC_CODEWORDS_PER_BLOCK[4][41] = {
    {-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
     28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
     26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
    {-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
     28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    {-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
     30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
};

static const int8_t NUM_ECC_BLOCKS[4][41] = {
    {-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
     8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
    {-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
     17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
    {-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
     23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
    {-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
     25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
};

/* Format information ECC bits for L, M, Q, H. */
static const uint8_t ECC_FORMAT_BITS[4] = {1, 0, 3, 2};

static const char ALPHANUMERIC_CHARSET[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

const char *qrk_status_str(qrk_status status)
{
    switch (status) {
    case QRK_OK: return "ok";
    case QRK_ERR_INVALID_ARGUMENT: return "invalid argument";
    case QRK_ERR_DATA_TOO_LONG: return "data too long";
    case QRK_ERR_OUT_OF_MEMORY: return "out of memory";
    case QRK_ERR_BUFFER_TOO_SMALL: return "buffer too small";
    case QRK_ERR_PARSE: return "parse error";
    }
    return "unknown error";
}

/* ---- tables -------------------------------------------------------------- */

int qrk__ecc_codewords_per_block(int ecc, int version)
{
    return ECC_CODEWORDS_PER_BLOCK[ecc][version];
}

int qrk__num_ecc_blocks(int ecc, int version)
{
    return NUM_ECC_BLOCKS[ecc][version];
}

static int raw_data_modules(int ver)
{
    int result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int num_align = ver / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if (ver >= 7)
            result -= 36;
    }
    return result;
}

int qrk__raw_codewords(int version)
{
    return raw_data_modules(version) / 8;
}

static int data_codewords(int ver, int ecc)
{
    return qrk__raw_codewords(ver) - ECC_CODEWORDS_PER_BLOCK[ecc][ver] * NUM_ECC_BLOCKS[ecc][ver];
}

int qrk__alignment_positions(int ver, uint8_t out[7])
{
    if (ver == 1)
        return 0;
    int num_align = ver / 7 + 2;
    int step = (ver * 8 + num_align * 3 + 5) / (num_align * 4 - 4) * 2;
    for (int i = num_align - 1, pos = ver * 4 + 10; i >= 1; i--, pos -= step)
        out[i] = (uint8_t)pos;
    out[0] = 6;
    return num_align;
}

bool qrk__is_function_module(int ver, int x, int y)
{
    int size = QRK_SIZE_FOR_VERSION(ver);
    /* finders + separators + format information + dark module */
    if (x <= 8 && y <= 8)
        return true;
    if (x >= size - 8 && y <= 8)
        return true;
    if (x <= 8 && y >= size - 8)
        return true;
    /* timing patterns */
    if (x == 6 || y == 6)
        return true;
    /* version information */
    if (ver >= 7) {
        if (x >= size - 11 && x < size - 8 && y < 6)
            return true;
        if (y >= size - 11 && y < size - 8 && x < 6)
            return true;
    }
    /* alignment patterns */
    uint8_t pos[7];
    int n = qrk__alignment_positions(ver, pos);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0))
                continue;
            int dx = x - pos[j], dy = y - pos[i];
            if (dx >= -2 && dx <= 2 && dy >= -2 && dy <= 2)
                return true;
        }
    }
    return false;
}

/* ---- module access ------------------------------------------------------- */

bool qrk_get_module(const qrk_code *code, int x, int y)
{
    int size = code->size;
    if (x < 0 || y < 0 || x >= size || y >= size)
        return false;
    return qrk__bit(code->modules, y * size + x);
}

static void set_module(qrk_code *qr, int x, int y, bool dark)
{
    int index = y * qr->size + x;
    if (dark)
        qr->modules[index >> 3] |= (uint8_t)(1u << (index & 7));
    else
        qr->modules[index >> 3] &= (uint8_t)~(1u << (index & 7));
}

static void set_module_checked(qrk_code *qr, int x, int y, bool dark)
{
    if (x >= 0 && y >= 0 && x < qr->size && y < qr->size)
        set_module(qr, x, y, dark);
}

/* ---- Reed-Solomon over GF(2^8 / 0x11D) ---------------------------------- */

static uint8_t gf_mul(uint8_t x, uint8_t y)
{
    int z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y >> i) & 1) * x;
    }
    return (uint8_t)z;
}

static void rs_divisor(int degree, uint8_t *result)
{
    memset(result, 0, (size_t)degree);
    result[degree - 1] = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            result[j] = gf_mul(result[j], root);
            if (j + 1 < degree)
                result[j] ^= result[j + 1];
        }
        root = gf_mul(root, 0x02);
    }
}

static void rs_remainder(const uint8_t *data, int len, const uint8_t *divisor, int degree,
                         uint8_t *result)
{
    memset(result, 0, (size_t)degree);
    for (int i = 0; i < len; i++) {
        uint8_t factor = data[i] ^ result[0];
        memmove(&result[0], &result[1], (size_t)(degree - 1));
        result[degree - 1] = 0;
        for (int j = 0; j < degree; j++)
            result[j] ^= gf_mul(divisor[j], factor);
    }
}

/* ---- data segment -------------------------------------------------------- */

static int alnum_index(uint8_t c)
{
    const char *p = c ? strchr(ALPHANUMERIC_CHARSET, c) : NULL;
    return p ? (int)(p - ALPHANUMERIC_CHARSET) : -1;
}

static int detect_mode(const uint8_t *data, size_t len)
{
    bool numeric = true, alnum = true;
    for (size_t i = 0; i < len; i++) {
        if (data[i] < '0' || data[i] > '9')
            numeric = false;
        if (alnum_index(data[i]) < 0)
            alnum = false;
    }
    if (numeric)
        return QRK_MODE_NUMERIC;
    if (alnum)
        return QRK_MODE_ALPHANUMERIC;
    return QRK_MODE_BYTE;
}

static int char_count_bits(int mode, int ver)
{
    int i = (ver + 7) / 17;
    switch (mode) {
    case QRK_MODE_NUMERIC: return (int[]){10, 12, 14}[i];
    case QRK_MODE_ALPHANUMERIC: return (int[]){9, 11, 13}[i];
    default: return (int[]){8, 16, 16}[i];
    }
}

static long payload_bits(int mode, size_t len)
{
    switch (mode) {
    case QRK_MODE_NUMERIC: return (long)(len / 3) * 10 + (long[]){0, 4, 7}[len % 3];
    case QRK_MODE_ALPHANUMERIC: return (long)(len / 2) * 11 + (long)(len % 2) * 6;
    default: return (long)len * 8;
    }
}

/* Total bit length for this version, or -1 if the count field overflows. */
static long total_bits(int mode, size_t len, bool eci, int ver)
{
    long bits = eci ? 12 : 0;
    if (len > 0) {
        int ccb = char_count_bits(mode, ver);
        if (len >= ((size_t)1 << ccb))
            return -1;
        bits += 4 + ccb + payload_bits(mode, len);
    }
    return bits;
}

typedef struct {
    uint8_t *buf;
    int bits;
} bitbuf;

static void bb_append(bitbuf *bb, uint32_t value, int n)
{
    for (int i = n - 1; i >= 0; i--, bb->bits++) {
        if ((value >> i) & 1)
            bb->buf[bb->bits >> 3] |= (uint8_t)(0x80 >> (bb->bits & 7));
    }
}

/* ---- function patterns --------------------------------------------------- */

static void draw_format_bits(qrk_code *qr, int mask)
{
    int data = ECC_FORMAT_BITS[qr->ecc] << 3 | mask;
    int rem = data;
    for (int i = 0; i < 10; i++)
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    int bits = (data << 10 | rem) ^ 0x5412;
    int size = qr->size;

    for (int i = 0; i <= 5; i++)
        set_module(qr, 8, i, (bits >> i) & 1);
    set_module(qr, 8, 7, (bits >> 6) & 1);
    set_module(qr, 8, 8, (bits >> 7) & 1);
    set_module(qr, 7, 8, (bits >> 8) & 1);
    for (int i = 9; i < 15; i++)
        set_module(qr, 14 - i, 8, (bits >> i) & 1);

    for (int i = 0; i < 8; i++)
        set_module(qr, size - 1 - i, 8, (bits >> i) & 1);
    for (int i = 8; i < 15; i++)
        set_module(qr, 8, size - 15 + i, (bits >> i) & 1);
    set_module(qr, 8, size - 8, true);
}

static void draw_finder(qrk_code *qr, int cx, int cy)
{
    for (int dy = -4; dy <= 4; dy++) {
        for (int dx = -4; dx <= 4; dx++) {
            int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
            int dist = adx > ady ? adx : ady;
            set_module_checked(qr, cx + dx, cy + dy, dist != 2 && dist != 4);
        }
    }
}

static void draw_function_patterns(qrk_code *qr)
{
    int size = qr->size, ver = qr->version;
    for (int i = 0; i < size; i++) {
        set_module(qr, 6, i, i % 2 == 0);
        set_module(qr, i, 6, i % 2 == 0);
    }
    draw_finder(qr, 3, 3);
    draw_finder(qr, size - 4, 3);
    draw_finder(qr, 3, size - 4);

    uint8_t pos[7];
    int n = qrk__alignment_positions(ver, pos);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0))
                continue;
            for (int dy = -2; dy <= 2; dy++)
                for (int dx = -2; dx <= 2; dx++) {
                    int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
                    set_module(qr, pos[j] + dx, pos[i] + dy, (adx > ady ? adx : ady) != 1);
                }
        }
    }

    draw_format_bits(qr, 0); /* placeholder, redrawn after masking */

    if (ver >= 7) {
        int rem = ver;
        for (int i = 0; i < 12; i++)
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        long bits = (long)ver << 12 | rem;
        for (int i = 0; i < 18; i++) {
            bool bit = (bits >> i) & 1;
            int a = size - 11 + i % 3, b = i / 3;
            set_module(qr, a, b, bit);
            set_module(qr, b, a, bit);
        }
    }
}

static void place_codewords(qrk_code *qr, const uint8_t *data, int len)
{
    int size = qr->size, i = 0;
    for (int right = size - 1; right >= 1; right -= 2) {
        if (right == 6)
            right = 5;
        for (int vert = 0; vert < size; vert++) {
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                bool upward = ((right + 1) & 2) == 0;
                int y = upward ? size - 1 - vert : vert;
                if (!qrk__is_function_module(qr->version, x, y) && i < len * 8) {
                    set_module(qr, x, y, (data[i >> 3] >> (7 - (i & 7))) & 1);
                    i++;
                }
            }
        }
    }
}

static bool mask_bit(int mask, int x, int y)
{
    switch (mask) {
    case 0: return (x + y) % 2 == 0;
    case 1: return y % 2 == 0;
    case 2: return x % 3 == 0;
    case 3: return (x + y) % 3 == 0;
    case 4: return (x / 3 + y / 2) % 2 == 0;
    case 5: return x * y % 2 + x * y % 3 == 0;
    case 6: return (x * y % 2 + x * y % 3) % 2 == 0;
    default: return ((x + y) % 2 + x * y % 3) % 2 == 0;
    }
}

/* `function_map` has one bit per module, set for function patterns. */
static void apply_mask(qrk_code *qr, int mask, const uint8_t *function_map)
{
    int size = qr->size;
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++) {
            int index = y * size + x;
            if (!qrk__bit(function_map, index) && mask_bit(mask, x, y))
                qr->modules[index >> 3] ^= (uint8_t)(1u << (index & 7));
        }
}

/* ---- mask penalty -------------------------------------------------------- */

static void run_history_add(int run, int history[7], int size)
{
    if (history[0] == 0)
        run += size; /* light border before the first run */
    memmove(&history[1], &history[0], 6 * sizeof(history[0]));
    history[0] = run;
}

static int finder_like_count(const int h[7])
{
    int n = h[1];
    bool core = n > 0 && h[2] == n && h[3] == n * 3 && h[4] == n && h[5] == n;
    return (core && h[0] >= n * 4 && h[6] >= n ? 1 : 0) +
           (core && h[6] >= n * 4 && h[0] >= n ? 1 : 0);
}

static int finder_terminate(bool color, int run, int history[7], int size)
{
    if (color) {
        run_history_add(run, history, size);
        run = 0;
    }
    run += size;
    run_history_add(run, history, size);
    return finder_like_count(history);
}

static long penalty_score(const qrk_code *qr)
{
    int size = qr->size;
    long result = 0;

    for (int pass = 0; pass < 2; pass++) {
        for (int a = 0; a < size; a++) {
            bool color = false;
            int run = 0, history[7] = {0};
            for (int b = 0; b < size; b++) {
                bool m = pass == 0 ? qrk_get_module(qr, b, a) : qrk_get_module(qr, a, b);
                if (m == color) {
                    run++;
                    if (run == 5)
                        result += 3;
                    else if (run > 5)
                        result++;
                } else {
                    run_history_add(run, history, size);
                    if (!color)
                        result += finder_like_count(history) * 40;
                    color = m;
                    run = 1;
                }
            }
            result += finder_terminate(color, run, history, size) * 40;
        }
    }

    for (int y = 0; y < size - 1; y++)
        for (int x = 0; x < size - 1; x++) {
            bool c = qrk_get_module(qr, x, y);
            if (c == qrk_get_module(qr, x + 1, y) && c == qrk_get_module(qr, x, y + 1) &&
                c == qrk_get_module(qr, x + 1, y + 1))
                result += 3;
        }

    long dark = 0;
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            dark += qrk_get_module(qr, x, y);
    long total = (long)size * size;
    long diff = dark * 20 - total * 10;
    if (diff < 0)
        diff = -diff;
    long k = (diff + total - 1) / total - 1;
    result += k * 10;
    return result;
}

/* ---- public API ---------------------------------------------------------- */

void qrk_encode_opts_default(qrk_encode_opts *opts)
{
    opts->ecc = QRK_ECC_AUTO;
    opts->min_version = 1;
    opts->max_version = QRK_MAX_VERSION;
    opts->mask = -1;
    opts->boost_ecc = true;
    opts->eci = false;
}

static qrk_status encode_with(qrk_code *qr, const uint8_t *data, size_t len,
                              const qrk_encode_opts *o, uint8_t *tmp)
{
    int mode = detect_mode(data, len);

    int ver = 0;
    long used = 0;
    for (int v = o->min_version; v <= o->max_version; v++) {
        long bits = total_bits(mode, len, o->eci, v);
        if (bits >= 0 && bits <= (long)data_codewords(v, o->ecc) * 8) {
            ver = v;
            used = bits;
            break;
        }
    }
    if (ver == 0)
        return QRK_ERR_DATA_TOO_LONG;

    int ecc = o->ecc;
    if (o->boost_ecc) {
        for (int e = ecc + 1; e <= QRK_ECC_HIGH; e++)
            if (used <= (long)data_codewords(ver, e) * 8)
                ecc = e;
    }

    /* data codewords */
    int data_len = data_codewords(ver, ecc);
    memset(tmp, 0, (size_t)qrk__raw_codewords(ver));
    bitbuf bb = {tmp, 0};
    if (o->eci) {
        bb_append(&bb, 0x7, 4);
        bb_append(&bb, 26, 8);
    }
    if (len > 0) {
        bb_append(&bb, (uint32_t)mode, 4);
        bb_append(&bb, (uint32_t)len, char_count_bits(mode, ver));
        if (mode == QRK_MODE_NUMERIC) {
            size_t i = 0;
            for (; i + 3 <= len; i += 3)
                bb_append(&bb, (uint32_t)((data[i] - '0') * 100 + (data[i + 1] - '0') * 10 + (data[i + 2] - '0')), 10);
            if (len - i == 2)
                bb_append(&bb, (uint32_t)((data[i] - '0') * 10 + (data[i + 1] - '0')), 7);
            else if (len - i == 1)
                bb_append(&bb, (uint32_t)(data[i] - '0'), 4);
        } else if (mode == QRK_MODE_ALPHANUMERIC) {
            size_t i = 0;
            for (; i + 2 <= len; i += 2)
                bb_append(&bb, (uint32_t)(alnum_index(data[i]) * 45 + alnum_index(data[i + 1])), 11);
            if (i < len)
                bb_append(&bb, (uint32_t)alnum_index(data[i]), 6);
        } else {
            for (size_t i = 0; i < len; i++)
                bb_append(&bb, data[i], 8);
        }
    }
    int capacity = data_len * 8;
    int term = capacity - bb.bits;
    bb_append(&bb, 0, term < 4 ? term : 4);
    bb_append(&bb, 0, (8 - bb.bits % 8) % 8);
    for (uint8_t pad = 0xEC; bb.bits < capacity; pad ^= 0xEC ^ 0x11)
        bb_append(&bb, pad, 8);

    /* error correction + interleaving into qr->modules (used as scratch) */
    int num_blocks = NUM_ECC_BLOCKS[ecc][ver];
    int block_ecc_len = ECC_CODEWORDS_PER_BLOCK[ecc][ver];
    int raw = qrk__raw_codewords(ver);
    int num_short = num_blocks - raw % num_blocks;
    int short_len = raw / num_blocks - block_ecc_len;
    uint8_t divisor[30], ecc_buf[30];
    rs_divisor(block_ecc_len, divisor);
    uint8_t *out = qr->modules;
    const uint8_t *dat = tmp;
    for (int i = 0; i < num_blocks; i++) {
        int dat_len = short_len + (i < num_short ? 0 : 1);
        rs_remainder(dat, dat_len, divisor, block_ecc_len, ecc_buf);
        for (int j = 0, k = i; j < dat_len; j++, k += num_blocks) {
            if (j == short_len)
                k -= num_short;
            out[k] = dat[j];
        }
        for (int j = 0, k = data_len + i; j < block_ecc_len; j++, k += num_blocks)
            out[k] = ecc_buf[j];
        dat += dat_len;
    }
    memcpy(tmp, out, (size_t)raw);

    /* matrix */
    qr->version = (uint8_t)ver;
    qr->size = (uint8_t)QRK_SIZE_FOR_VERSION(ver);
    qr->ecc = (uint8_t)ecc;
    qr->mode = (uint8_t)mode;
    memset(qr->modules, 0, (size_t)QRK_BUFFER_LEN_FOR_VERSION(ver));
    draw_function_patterns(qr);
    place_codewords(qr, tmp, raw);

    /* the scratch buffer is free again: reuse it as a function-module map */
    int size = qr->size;
    memset(tmp, 0, (size_t)QRK_BUFFER_LEN_FOR_VERSION(ver));
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (qrk__is_function_module(ver, x, y))
                tmp[(y * size + x) >> 3] |= (uint8_t)(1u << ((y * size + x) & 7));

    int mask = o->mask;
    if (mask < 0) {
        long best = -1;
        for (int m = 0; m < 8; m++) {
            apply_mask(qr, m, tmp);
            draw_format_bits(qr, m);
            long p = penalty_score(qr);
            if (best < 0 || p < best) {
                best = p;
                mask = m;
            }
            apply_mask(qr, m, tmp);
        }
    }
    apply_mask(qr, mask, tmp);
    draw_format_bits(qr, mask);
    qr->mask = (uint8_t)mask;
    return QRK_OK;
}

qrk_status qrk_encode(qrk_code *out, const void *data, size_t len,
                      const qrk_encode_opts *opts, uint8_t *tmp)
{
    qrk_encode_opts o;
    if (opts)
        o = *opts;
    else
        qrk_encode_opts_default(&o);
    if (!out || (!data && len > 0) || o.min_version < 1 || o.max_version > QRK_MAX_VERSION ||
        o.min_version > o.max_version || o.mask < -1 || o.mask > 7 ||
        !(o.ecc == QRK_ECC_AUTO || o.ecc == QRK_ECC_LOW || o.ecc == QRK_ECC_MEDIUM ||
          o.ecc == QRK_ECC_QUARTILE || o.ecc == QRK_ECC_HIGH))
        return QRK_ERR_INVALID_ARGUMENT;
    if (o.ecc == QRK_ECC_AUTO)
        o.ecc = QRK_ECC_MEDIUM;

    if (tmp)
        return encode_with(out, (const uint8_t *)data, len, &o, tmp);
#ifdef QRK_NO_MALLOC
    return QRK_ERR_INVALID_ARGUMENT;
#else
    uint8_t *scratch = (uint8_t *)malloc(QRK_BUFFER_LEN_MAX);
    if (!scratch)
        return QRK_ERR_OUT_OF_MEMORY;
    qrk_status st = encode_with(out, (const uint8_t *)data, len, &o, scratch);
    free(scratch);
    return st;
#endif
}

qrk_status qrk_encode_for_style(qrk_code *out, const void *data, size_t len,
                                const qrk_encode_opts *opts, const qrk_style *style,
                                uint8_t *tmp)
{
    qrk_encode_opts o;
    if (opts)
        o = *opts;
    else
        qrk_encode_opts_default(&o);
    if (o.ecc == QRK_ECC_AUTO)
        o.ecc = qrk_recommended_ecc(style);
    return qrk_encode(out, data, len, &o, tmp);
}

qrk_status qrk_encode_text(qrk_code *out, const char *text, const qrk_encode_opts *opts,
                           uint8_t *tmp)
{
    return qrk_encode(out, text, text ? strlen(text) : 0, opts, tmp);
}
