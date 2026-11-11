#include "tm.h"

int tm_log_level = 0;

/* ---- memória ---- */

static void oom(void)
{
    fputs(TM_NAME ": out of memory\n", stderr);
    abort();
}

void *tm_alloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) oom();
    return p;
}

void *tm_zalloc(size_t n)
{
    void *p = calloc(1, n ? n : 1);
    if (!p) oom();
    return p;
}

void *tm_realloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) oom();
    return q;
}

char *tm_strndup(const char *s, size_t n)
{
    char *d = tm_alloc(n + 1);
    if (n) memcpy(d, s, n);
    d[n] = 0;
    return d;
}

char *tm_strdup(const char *s)
{
    return s ? tm_strndup(s, strlen(s)) : NULL;
}

void tm_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* ---- erro ---- */

int tm_fail(tm_err *e, int code, const char *fmt, ...)
{
    if (e) {
        va_list ap;
        e->code = code;
        e->sqlstate[0] = 0;
        va_start(ap, fmt);
        vsnprintf(e->msg, sizeof e->msg, fmt, ap);
        va_end(ap);
    }
    return -1;
}

void tm_err_clear(tm_err *e)
{
    if (e) {
        e->code = 0;
        e->msg[0] = 0;
        e->sqlstate[0] = 0;
    }
}

/* ---- buffer ---- */

void buf_init(tm_buf *b)
{
    b->p = NULL;
    b->len = b->cap = 0;
}

void buf_free(tm_buf *b)
{
    free(b->p);
    buf_init(b);
}

void buf_reset(tm_buf *b)
{
    b->len = 0;
}

void buf_reserve(tm_buf *b, size_t extra)
{
    size_t need = b->len + extra + 1; /* +1: espaço para o NUL de buf_cstr */
    if (need < b->len) oom();
    if (need <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) oom();
        cap *= 2;
    }
    b->p = tm_realloc(b->p, cap);
    b->cap = cap;
}

void buf_put(tm_buf *b, const void *data, size_t n)
{
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->p + b->len, data, n);
    b->len += n;
}

void buf_putc(tm_buf *b, int c)
{
    buf_reserve(b, 1);
    b->p[b->len++] = (uint8_t)c;
}

void buf_puts(tm_buf *b, const char *s)
{
    if (s) buf_put(b, s, strlen(s));
}

void buf_fill(tm_buf *b, int c, size_t n)
{
    buf_reserve(b, n);
    memset(b->p + b->len, c, n);
    b->len += n;
}

void buf_printf(tm_buf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf_reserve(b, (size_t)n);
        vsnprintf((char *)b->p + b->len, (size_t)n + 1, fmt, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

void buf_u16be(tm_buf *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    buf_put(b, t, 2);
}

void buf_u32be(tm_buf *b, uint32_t v)
{
    uint8_t t[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    buf_put(b, t, 4);
}

void buf_u16le(tm_buf *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    buf_put(b, t, 2);
}

void buf_u32le(tm_buf *b, uint32_t v)
{
    uint8_t t[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    buf_put(b, t, 4);
}

void buf_u64le(tm_buf *b, uint64_t v)
{
    buf_u32le(b, (uint32_t)v);
    buf_u32le(b, (uint32_t)(v >> 32));
}

char *buf_cstr(tm_buf *b)
{
    buf_reserve(b, 0);
    b->p[b->len] = 0;
    return (char *)b->p;
}

/* ---- leitor ---- */

void rd_init(tm_rd *r, const void *p, size_t len)
{
    r->p = p;
    r->len = len;
    r->pos = 0;
    r->bad = false;
}

size_t rd_left(const tm_rd *r)
{
    return r->bad ? 0 : r->len - r->pos;
}

const uint8_t *rd_bytes(tm_rd *r, size_t n)
{
    if (r->bad || n > r->len - r->pos) {
        r->bad = true;
        return NULL;
    }
    const uint8_t *p = r->p + r->pos;
    r->pos += n;
    return p;
}

void rd_skip(tm_rd *r, size_t n)
{
    (void)rd_bytes(r, n);
}

uint8_t rd_u8(tm_rd *r)
{
    const uint8_t *p = rd_bytes(r, 1);
    return p ? p[0] : 0;
}

uint16_t rd_u16be(tm_rd *r)
{
    const uint8_t *p = rd_bytes(r, 2);
    return p ? (uint16_t)((p[0] << 8) | p[1]) : 0;
}

uint32_t rd_u32be(tm_rd *r)
{
    const uint8_t *p = rd_bytes(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3] : 0;
}

uint16_t rd_u16le(tm_rd *r)
{
    const uint8_t *p = rd_bytes(r, 2);
    return p ? (uint16_t)(p[0] | (p[1] << 8)) : 0;
}

uint32_t rd_u32le(tm_rd *r)
{
    const uint8_t *p = rd_bytes(r, 4);
    return p ? p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24) : 0;
}

uint64_t rd_u64le(tm_rd *r)
{
    uint64_t lo = rd_u32le(r);
    uint64_t hi = rd_u32le(r);
    return lo | (hi << 32);
}

const char *rd_cstr(tm_rd *r, size_t *len)
{
    if (len) *len = 0;
    if (r->bad) return "";
    const uint8_t *start = r->p + r->pos;
    const uint8_t *nul = memchr(start, 0, r->len - r->pos);
    if (!nul) {
        r->bad = true;
        return "";
    }
    size_t n = (size_t)(nul - start);
    r->pos += n + 1;
    if (len) *len = n;
    return (const char *)start;
}

/* ---- texto ---- */

static int lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

int tm_stricmp(const char *a, const char *b)
{
    for (;; a++, b++) {
        int d = lower((unsigned char)*a) - lower((unsigned char)*b);
        if (d || !*a) return d;
    }
}

int tm_strnicmp(const char *a, const char *b, size_t n)
{
    for (; n; a++, b++, n--) {
        int d = lower((unsigned char)*a) - lower((unsigned char)*b);
        if (d || !*a) return d;
    }
    return 0;
}

bool tm_streq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    return strcmp(a, b) == 0;
}

size_t tm_utf8_cut(const char *s, size_t len, size_t n)
{
    if (n >= len) return len;
    while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
    return n;
}

void tm_hex(char *out, const uint8_t *in, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        *out++ = d[in[i] >> 4];
        *out++ = d[in[i] & 15];
    }
    *out = 0;
}

static void put_cp(tm_buf *out, uint32_t cp)
{
    if (cp < 0x80) {
        buf_putc(out, (int)cp);
    } else if (cp < 0x800) {
        buf_putc(out, (int)(0xC0 | (cp >> 6)));
        buf_putc(out, (int)(0x80 | (cp & 63)));
    } else if (cp < 0x10000) {
        buf_putc(out, (int)(0xE0 | (cp >> 12)));
        buf_putc(out, (int)(0x80 | ((cp >> 6) & 63)));
        buf_putc(out, (int)(0x80 | (cp & 63)));
    } else {
        buf_putc(out, (int)(0xF0 | (cp >> 18)));
        buf_putc(out, (int)(0x80 | ((cp >> 12) & 63)));
        buf_putc(out, (int)(0x80 | ((cp >> 6) & 63)));
        buf_putc(out, (int)(0x80 | (cp & 63)));
    }
}

void tm_utf16le_to_utf8(tm_buf *out, const uint8_t *p, size_t nbytes)
{
    buf_reserve(out, nbytes + nbytes / 2);
    for (size_t i = 0; i + 1 < nbytes; i += 2) {
        uint32_t u = p[i] | ((uint32_t)p[i + 1] << 8);
        if (u >= 0xD800 && u <= 0xDBFF && i + 3 < nbytes) {
            uint32_t lo = p[i + 2] | ((uint32_t)p[i + 3] << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else {
                u = 0xFFFD;
            }
        } else if (u >= 0xD800 && u <= 0xDFFF) {
            u = 0xFFFD; /* metade de par substituto solta */
        }
        put_cp(out, u);
    }
}

void tm_utf8_to_utf16le(tm_buf *out, const char *s, size_t n)
{
    const unsigned char *u = (const unsigned char *)s;
    for (size_t i = 0; i < n;) {
        uint32_t cp = u[i];
        size_t len = cp < 0x80 ? 1 : (cp & 0xE0) == 0xC0 ? 2 : (cp & 0xF0) == 0xE0 ? 3 : (cp & 0xF8) == 0xF0 ? 4 : 0;
        if (len == 0 || i + len > n) {
            cp = 0xFFFD;
            len = 1;
        } else if (len > 1) {
            cp &= 0xFFu >> (len + 1);
            for (size_t k = 1; k < len; k++) {
                if ((u[i + k] & 0xC0) != 0x80) {
                    cp = 0xFFFD;
                    len = k;
                    break;
                }
                cp = (cp << 6) | (u[i + k] & 0x3F);
            }
        }
        i += len;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            buf_u16le(out, (uint16_t)(0xD800 | (cp >> 10)));
            buf_u16le(out, (uint16_t)(0xDC00 | (cp & 0x3FF)));
        } else {
            buf_u16le(out, (uint16_t)cp);
        }
    }
}

void tm_cp1252_to_utf8(tm_buf *out, const uint8_t *p, size_t n)
{
    /* 0x80–0x9F é onde o Windows-1252 difere do Latin-1. */
    static const uint16_t HIGH[32] = { 0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
                                       0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
                                       0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
                                       0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178 };
    buf_reserve(out, n + n / 4);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        put_cp(out, c >= 0x80 && c <= 0x9F ? HIGH[c - 0x80] : c);
    }
}

void tm_civil_from_days(int64_t z, int *y, int *m, int *d)
{
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    *d = (int)(doy - (153 * mp + 2) / 5 + 1);
    *m = (int)(mp < 10 ? mp + 3 : mp - 9);
    *y = (int)(yoe + era * 400 + (*m <= 2));
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t tm_b64_enc(char *out, const uint8_t *in, size_t n)
{
    char *o = out;
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        *o++ = B64[v >> 18];
        *o++ = B64[(v >> 12) & 63];
        *o++ = B64[(v >> 6) & 63];
        *o++ = B64[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        *o++ = B64[v >> 18];
        *o++ = B64[(v >> 12) & 63];
        *o++ = '=';
        *o++ = '=';
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        *o++ = B64[v >> 18];
        *o++ = B64[(v >> 12) & 63];
        *o++ = B64[(v >> 6) & 63];
        *o++ = '=';
    }
    *o = 0;
    return (size_t)(o - out);
}

int tm_b64_dec(uint8_t *out, size_t cap, const char *in, size_t n)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)in[i], v;
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)o;
}

/* ---- log ---- */

void tm_log(int level, const char *fmt, ...)
{
    if (level > tm_log_level) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[" TM_NAME "] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(ap);
}
