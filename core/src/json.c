#include "json.h"

/* ---- arena ---- */

typedef struct chunk {
    struct chunk *next;
    size_t        used, cap;
} chunk;

static void *arena_alloc(js_doc *d, size_t n)
{
    n = (n + 15) & ~(size_t)15;
    chunk *c = d->chunks;
    if (!c || c->cap - c->used < n) {
        size_t cap = n > 16384 ? n : 16384;
        c = tm_alloc(sizeof(chunk) + cap);
        c->next = d->chunks;
        c->used = 0;
        c->cap = cap;
        d->chunks = c;
    }
    void *p = (uint8_t *)(c + 1) + c->used;
    c->used += n;
    return p;
}

void js_free(js_doc *d)
{
    chunk *c = d->chunks;
    while (c) {
        chunk *n = c->next;
        free(c);
        c = n;
    }
    d->chunks = NULL;
    d->root = NULL;
}

/* ---- leitor ---- */

#define JS_MAX_DEPTH 64

typedef struct {
    js_doc     *doc;
    const char *p, *end;
    tm_err     *err;
    int         depth;
} parser;

static int perr(parser *ps, const char *what)
{
    return tm_fail(ps->err, TM_E_PROTOCOL, "JSON: %s", what);
}

static void skip_ws(parser *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static int hex4(parser *ps, unsigned *out)
{
    if (ps->end - ps->p < 4) return -1;
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        int c = (unsigned char)ps->p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    ps->p += 4;
    *out = v;
    return 0;
}

static char *put_utf8(char *o, unsigned cp)
{
    if (cp < 0x80) {
        *o++ = (char)cp;
    } else if (cp < 0x800) {
        *o++ = (char)(0xC0 | (cp >> 6));
        *o++ = (char)(0x80 | (cp & 63));
    } else if (cp < 0x10000) {
        *o++ = (char)(0xE0 | (cp >> 12));
        *o++ = (char)(0x80 | ((cp >> 6) & 63));
        *o++ = (char)(0x80 | (cp & 63));
    } else {
        *o++ = (char)(0xF0 | (cp >> 18));
        *o++ = (char)(0x80 | ((cp >> 12) & 63));
        *o++ = (char)(0x80 | ((cp >> 6) & 63));
        *o++ = (char)(0x80 | (cp & 63));
    }
    return o;
}

/* Lê um texto entre aspas; o resultado nunca é maior que a entrada. */
static int parse_string(parser *ps, const char **out, size_t *outlen)
{
    ps->p++; /* aspas de abertura */
    const char *q = ps->p;
    while (q < ps->end && *q != '"') {
        if (*q == '\\') q++;
        q++;
    }
    if (q >= ps->end) return perr(ps, "unterminated string");
    char *dst = arena_alloc(ps->doc, (size_t)(q - ps->p) + 1);
    char *o = dst;
    while (*ps->p != '"') {
        unsigned char c = (unsigned char)*ps->p++;
        if (c < 0x20) return perr(ps, "control character in string");
        if (c != '\\') {
            *o++ = (char)c;
            continue;
        }
        switch (*ps->p++) {
        case '"': *o++ = '"'; break;
        case '\\': *o++ = '\\'; break;
        case '/': *o++ = '/'; break;
        case 'b': *o++ = '\b'; break;
        case 'f': *o++ = '\f'; break;
        case 'n': *o++ = '\n'; break;
        case 'r': *o++ = '\r'; break;
        case 't': *o++ = '\t'; break;
        case 'u': {
            unsigned cp, lo;
            if (hex4(ps, &cp)) return perr(ps, "bad \\u escape");
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (ps->end - ps->p >= 6 && ps->p[0] == '\\' && ps->p[1] == 'u') {
                    ps->p += 2;
                    if (hex4(ps, &lo)) return perr(ps, "bad \\u escape");
                    if (lo >= 0xDC00 && lo <= 0xDFFF)
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    else
                        cp = 0xFFFD;
                } else {
                    cp = 0xFFFD;
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                cp = 0xFFFD;
            }
            o = put_utf8(o, cp);
            break;
        }
        default:
            return perr(ps, "bad escape");
        }
    }
    ps->p++; /* aspas de fechamento */
    *o = 0;
    *out = dst;
    *outlen = (size_t)(o - dst);
    return 0;
}

static int parse_value(parser *ps, js_val **out);

static int parse_container(parser *ps, js_val *v, bool is_obj)
{
    char close = is_obj ? '}' : ']';
    js_val **tail = &v->child;
    ps->p++;
    if (++ps->depth > JS_MAX_DEPTH) return perr(ps, "nesting too deep");
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == close) {
        ps->p++;
        ps->depth--;
        return 0;
    }
    for (;;) {
        const char *key = NULL;
        size_t klen;
        skip_ws(ps);
        if (is_obj) {
            if (ps->p >= ps->end || *ps->p != '"') return perr(ps, "expected member name");
            if (parse_string(ps, &key, &klen)) return -1;
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') return perr(ps, "expected ':'");
            ps->p++;
        }
        js_val *item;
        if (parse_value(ps, &item)) return -1;
        item->key = key;
        *tail = item;
        tail = &item->next;
        skip_ws(ps);
        if (ps->p >= ps->end) return perr(ps, "unexpected end");
        if (*ps->p == ',') {
            ps->p++;
            continue;
        }
        if (*ps->p == close) {
            ps->p++;
            ps->depth--;
            return 0;
        }
        return perr(ps, "expected ',' or closing bracket");
    }
}

static bool lit(parser *ps, const char *word)
{
    size_t n = strlen(word);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, word, n) != 0) return false;
    ps->p += n;
    return true;
}

static int parse_value(parser *ps, js_val **out)
{
    skip_ws(ps);
    if (ps->p >= ps->end) return perr(ps, "unexpected end");
    js_val *v = arena_alloc(ps->doc, sizeof *v);
    memset(v, 0, sizeof *v);
    *out = v;
    char c = *ps->p;
    if (c == '{') {
        v->t = JS_OBJ;
        return parse_container(ps, v, true);
    }
    if (c == '[') {
        v->t = JS_ARR;
        return parse_container(ps, v, false);
    }
    if (c == '"') {
        v->t = JS_STR;
        return parse_string(ps, &v->s, &v->slen);
    }
    if (lit(ps, "true")) {
        v->t = JS_BOOL;
        v->b = true;
        return 0;
    }
    if (lit(ps, "false")) {
        v->t = JS_BOOL;
        return 0;
    }
    if (lit(ps, "null")) return 0;
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *s = ps->p;
        while (ps->p < ps->end && (strchr("+-.eE", *ps->p) || (*ps->p >= '0' && *ps->p <= '9')))
            ps->p++;
        size_t n = (size_t)(ps->p - s);
        if (!js_is_number(s, n)) return perr(ps, "bad number");
        char *copy = arena_alloc(ps->doc, n + 1);
        memcpy(copy, s, n);
        copy[n] = 0;
        v->t = JS_NUM;
        v->s = copy;
        v->slen = n;
        v->num = strtod(copy, NULL);
        return 0;
    }
    return perr(ps, "unexpected character");
}

int js_parse(js_doc *doc, const char *text, size_t len, tm_err *err)
{
    parser ps = { doc, text, text + len, err, 0 };
    doc->chunks = NULL;
    doc->root = NULL;
    js_val *root;
    if (parse_value(&ps, &root)) return -1;
    skip_ws(&ps);
    if (ps.p != ps.end) return perr(&ps, "trailing data");
    doc->root = root;
    return 0;
}

const js_val *js_get(const js_val *obj, const char *key)
{
    if (!obj || obj->t != JS_OBJ) return NULL;
    for (const js_val *m = obj->child; m; m = m->next)
        if (m->key && strcmp(m->key, key) == 0) return m;
    return NULL;
}

const char *js_get_str(const js_val *obj, const char *key, const char *def)
{
    const js_val *v = js_get(obj, key);
    return (v && v->t == JS_STR) ? v->s : def;
}

long long js_get_int(const js_val *obj, const char *key, long long def)
{
    const js_val *v = js_get(obj, key);
    if (v && v->t == JS_NUM) return (long long)v->num;
    if (v && v->t == JS_STR && js_is_number(v->s, v->slen)) return strtoll(v->s, NULL, 10);
    return def;
}

bool js_get_bool(const js_val *obj, const char *key, bool def)
{
    const js_val *v = js_get(obj, key);
    return (v && v->t == JS_BOOL) ? v->b : def;
}

bool js_is_number(const char *s, size_t n)
{
    size_t i = 0;
    if (i < n && s[i] == '-') i++;
    if (i >= n) return false;
    if (s[i] == '0') {
        i++;
    } else if (s[i] >= '1' && s[i] <= '9') {
        while (i < n && s[i] >= '0' && s[i] <= '9') i++;
    } else {
        return false;
    }
    if (i < n && s[i] == '.') {
        size_t d = ++i;
        while (i < n && s[i] >= '0' && s[i] <= '9') i++;
        if (i == d) return false;
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++;
        if (i < n && (s[i] == '+' || s[i] == '-')) i++;
        size_t d = i;
        while (i < n && s[i] >= '0' && s[i] <= '9') i++;
        if (i == d) return false;
    }
    return i == n;
}

/* ---- escritor ---- */

/* Tamanho da sequência UTF-8 válida que começa em s, ou 0 se inválida. */
static size_t utf8_seq(const unsigned char *s, size_t n)
{
    unsigned char c = s[0];
    size_t len;
    unsigned cp;
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1Fu; }
    else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0Fu; }
    else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07u; }
    else return 0;
    if (n < len) return 0;
    for (size_t i = 1; i < len; i++) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3Fu);
    }
    if (len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return 0;
    if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) return 0;
    return len;
}

void jw_str(tm_buf *b, const char *s, size_t n)
{
    const unsigned char *u = (const unsigned char *)s;
    buf_reserve(b, n + 2);
    buf_putc(b, '"');
    size_t i = 0, run = 0;
    while (i < n) {
        unsigned char c = u[i];
        if (c >= 0x20 && c < 0x80 && c != '"' && c != '\\') {
            i++;
            continue;
        }
        size_t seq = c >= 0x80 ? utf8_seq(u + i, n - i) : 0;
        if (seq) {
            i += seq;
            continue;
        }
        buf_put(b, u + run, i - run);
        switch (c) {
        case '"': buf_puts(b, "\\\""); break;
        case '\\': buf_puts(b, "\\\\"); break;
        case '\n': buf_puts(b, "\\n"); break;
        case '\r': buf_puts(b, "\\r"); break;
        case '\t': buf_puts(b, "\\t"); break;
        default:
            if (c < 0x20) buf_printf(b, "\\u%04x", c);
            else buf_puts(b, "\xEF\xBF\xBD"); /* U+FFFD */
        }
        run = ++i;
    }
    buf_put(b, u + run, n - run);
    buf_putc(b, '"');
}

void jw_cstr(tm_buf *b, const char *s)
{
    if (s) jw_str(b, s, strlen(s));
    else buf_puts(b, "null");
}

void jw_key(tm_buf *b, const char *key)
{
    jw_cstr(b, key);
    buf_putc(b, ':');
}

void jw_val(tm_buf *b, const js_val *v)
{
    if (!v) {
        buf_puts(b, "null");
        return;
    }
    switch (v->t) {
    case JS_NULL: buf_puts(b, "null"); break;
    case JS_BOOL: buf_puts(b, v->b ? "true" : "false"); break;
    case JS_NUM: buf_put(b, v->s, v->slen); break;
    case JS_STR: jw_str(b, v->s, v->slen); break;
    case JS_ARR:
    case JS_OBJ:
        buf_putc(b, v->t == JS_OBJ ? '{' : '[');
        for (const js_val *c = v->child; c; c = c->next) {
            if (c != v->child) buf_putc(b, ',');
            if (v->t == JS_OBJ) jw_key(b, c->key);
            jw_val(b, c);
        }
        buf_putc(b, v->t == JS_OBJ ? '}' : ']');
        break;
    }
}
