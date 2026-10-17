/*
 * QRKude - payload builders (Wi-Fi, vCard, event, mailto, SMS, tel, geo).
 * Copyright 2026 The QRKude Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <math.h>
#include <string.h>

#include "qrk_internal.h"

typedef struct {
    char *out;
    size_t cap, len;
} sbuf;

static void put(sbuf *b, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++, b->len++)
        if (b->len + 1 < b->cap)
            b->out[b->len] = s[i];
}

static void puts_(sbuf *b, const char *s)
{
    if (s)
        put(b, s, strlen(s));
}

static size_t finish(sbuf *b)
{
    if (b->cap > 0)
        b->out[b->len < b->cap ? b->len : b->cap - 1] = 0;
    return b->len;
}

static bool empty(const char *s)
{
    return !s || !s[0];
}

/* Backslash-escapes every character of `special`; newlines become "\n". */
static void put_escaped(sbuf *b, const char *s, const char *special)
{
    for (; s && *s; s++) {
        if (*s == '\n') {
            put(b, "\\n", 2);
            continue;
        }
        if (strchr(special, *s))
            put(b, "\\", 1);
        put(b, s, 1);
    }
}

static void put_percent(sbuf *b, const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            put(b, (const char *)&c, 1);
        } else {
            char enc[3] = {'%', hex[c >> 4], hex[c & 15]};
            put(b, enc, 3);
        }
    }
}

size_t qrk_payload_wifi(char *out, size_t cap, const char *ssid, const char *password,
                        const char *auth, bool hidden)
{
    sbuf b = {out, cap, 0};
    const char *special = "\\;,:\"";
    puts_(&b, "WIFI:");
    if (!empty(auth)) {
        puts_(&b, "T:");
        puts_(&b, auth);
        puts_(&b, ";");
    }
    puts_(&b, "S:");
    put_escaped(&b, ssid, special);
    puts_(&b, ";");
    if (!empty(password) && !(auth && strcmp(auth, "nopass") == 0)) {
        puts_(&b, "P:");
        put_escaped(&b, password, special);
        puts_(&b, ";");
    }
    if (hidden)
        puts_(&b, "H:true;");
    puts_(&b, ";");
    return finish(&b);
}

size_t qrk_payload_email(char *out, size_t cap, const char *to, const char *subject,
                         const char *body)
{
    sbuf b = {out, cap, 0};
    puts_(&b, "mailto:");
    puts_(&b, to);
    const char *sep = "?";
    if (!empty(subject)) {
        puts_(&b, sep);
        puts_(&b, "subject=");
        put_percent(&b, subject);
        sep = "&";
    }
    if (!empty(body)) {
        puts_(&b, sep);
        puts_(&b, "body=");
        put_percent(&b, body);
    }
    return finish(&b);
}

size_t qrk_payload_sms(char *out, size_t cap, const char *number, const char *message)
{
    sbuf b = {out, cap, 0};
    puts_(&b, "SMSTO:");
    puts_(&b, number);
    if (!empty(message)) {
        puts_(&b, ":");
        puts_(&b, message);
    }
    return finish(&b);
}

size_t qrk_payload_tel(char *out, size_t cap, const char *number)
{
    sbuf b = {out, cap, 0};
    puts_(&b, "tel:");
    puts_(&b, number);
    return finish(&b);
}

/* Same rounding rule as qrk_format_number, with 6 decimals. */
static void put_fixed6(sbuf *b, double v)
{
    long long n = (long long)floor(v * 1000000.0 + 0.5);
    char tmp[32];
    int k = 0;
    bool neg = n < 0;
    if (neg)
        n = -n;
    long long ip = n / 1000000;
    long fp = (long)(n % 1000000);
    if (neg)
        put(b, "-", 1);
    do {
        tmp[k++] = (char)('0' + ip % 10);
        ip /= 10;
    } while (ip > 0);
    while (k > 0)
        put(b, &tmp[--k], 1);
    if (fp) {
        char frac[7];
        for (int i = 5; i >= 0; i--) {
            frac[i] = (char)('0' + fp % 10);
            fp /= 10;
        }
        int len = 6;
        while (frac[len - 1] == '0')
            len--;
        put(b, ".", 1);
        put(b, frac, (size_t)len);
    }
}

size_t qrk_payload_geo(char *out, size_t cap, double latitude, double longitude)
{
    sbuf b = {out, cap, 0};
    puts_(&b, "geo:");
    put_fixed6(&b, latitude);
    puts_(&b, ",");
    put_fixed6(&b, longitude);
    return finish(&b);
}

static void vline(sbuf *b, const char *key, const char *value, bool always)
{
    if (!always && empty(value))
        return;
    puts_(b, key);
    puts_(b, ":");
    put_escaped(b, value, "\\;,");
    puts_(b, "\n");
}

size_t qrk_payload_vcard(char *out, size_t cap, const qrk_vcard *c)
{
    sbuf b = {out, cap, 0};
    const char *special = "\\;,";
    puts_(&b, "BEGIN:VCARD\nVERSION:3.0\nN:");
    put_escaped(&b, c->last_name, special);
    puts_(&b, ";");
    put_escaped(&b, c->first_name, special);
    puts_(&b, ";;;\nFN:");
    put_escaped(&b, c->first_name, special);
    if (!empty(c->first_name) && !empty(c->last_name))
        puts_(&b, " ");
    put_escaped(&b, c->last_name, special);
    puts_(&b, "\n");
    vline(&b, "ORG", c->organization, false);
    vline(&b, "TITLE", c->title, false);
    vline(&b, "TEL", c->phone, false);
    vline(&b, "EMAIL", c->email, false);
    vline(&b, "URL", c->url, false);
    if (!empty(c->address)) {
        puts_(&b, "ADR:;;");
        put_escaped(&b, c->address, special);
        puts_(&b, ";;;;\n");
    }
    vline(&b, "NOTE", c->note, false);
    puts_(&b, "END:VCARD");
    return finish(&b);
}

size_t qrk_payload_event(char *out, size_t cap, const qrk_event *e)
{
    sbuf b = {out, cap, 0};
    puts_(&b, "BEGIN:VEVENT\n");
    vline(&b, "SUMMARY", e->summary, true);
    vline(&b, "DTSTART", e->start, false);
    vline(&b, "DTEND", e->end, false);
    vline(&b, "LOCATION", e->location, false);
    vline(&b, "DESCRIPTION", e->description, false);
    puts_(&b, "END:VEVENT");
    return finish(&b);
}
