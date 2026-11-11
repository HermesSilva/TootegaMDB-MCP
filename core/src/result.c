#include "db.h"

/* ---- montagem ---- */

void res_init(tm_result *r, int max_rows, int max_cell)
{
    memset(r, 0, sizeof *r);
    r->max_rows = max_rows > 0 ? max_rows : 500;
    r->max_cell = max_cell > 0 ? max_cell : 4000;
    buf_init(&r->notices);
}

void res_free(tm_result *r)
{
    tm_rowset *rs = r->first;
    while (rs) {
        tm_rowset *next = rs->next;
        for (int i = 0; i < rs->ncols; i++) {
            free(rs->cols[i].name);
            free(rs->cols[i].type);
        }
        free(rs->cols);
        buf_free(&rs->cells);
        free(rs);
        rs = next;
    }
    buf_free(&r->notices);
    memset(r, 0, sizeof *r);
}

void res_reset(tm_result *r)
{
    int max_rows = r->max_rows, max_cell = r->max_cell;
    res_free(r);
    res_init(r, max_rows, max_cell);
}

tm_rowset *res_begin_set(tm_result *r, int ncols)
{
    tm_rowset *rs = tm_zalloc(sizeof *rs);
    if (ncols < 0) ncols = 0;
    rs->ncols = ncols;
    rs->cols = tm_zalloc((size_t)ncols * sizeof *rs->cols);
    rs->affected = -1;
    buf_init(&rs->cells);
    if (r->last) r->last->next = rs;
    else r->first = rs;
    r->last = rs;
    r->in_row = false;
    return rs;
}

void res_set_col(tm_rowset *rs, int i, const char *name, size_t nlen, const char *type)
{
    if (i < 0 || i >= rs->ncols) return;
    free(rs->cols[i].name);
    free(rs->cols[i].type);
    rs->cols[i].name = tm_strndup(name ? name : "", name ? nlen : 0);
    rs->cols[i].type = tm_strdup(type ? type : "");
}

bool res_row_begin(tm_result *r)
{
    if (!r->last) res_begin_set(r, 0);
    if (r->total_rows >= (size_t)r->max_rows) {
        r->truncated = true;
        r->skipped_rows++;
        r->in_row = false;
        return false;
    }
    r->total_rows++;
    r->last->nrows++;
    r->in_row = true;
    return true;
}

void res_cell(tm_result *r, tm_ckind kind, const void *p, size_t n)
{
    static const char ELLIPSIS[] = "\xE2\x80\xA6"; /* … */
    if (!r->in_row) return;
    tm_buf *b = &r->last->cells;
    bool cut = false;
    if (kind == CK_NULL) n = 0;
    if (kind == CK_TEXT && n > (size_t)r->max_cell) {
        n = tm_utf8_cut(p, n, (size_t)r->max_cell);
        cut = true;
        r->cells_cut = true;
    }
    buf_putc(b, kind);
    buf_u32le(b, (uint32_t)(n + (cut ? 3 : 0)));
    buf_put(b, p, n);
    if (cut) buf_put(b, ELLIPSIS, 3);
}

void res_cell_bin(tm_result *r, const void *p, size_t n)
{
    if (!r->in_row) return;
    /* Só converte o que cabe: um blob de 1 GB não vira 2 GB de texto. */
    size_t keep = ((size_t)r->max_cell - 2) / 2;
    bool cut = n > keep;
    if (cut) n = keep;
    char *hex = tm_alloc(2 * n + 3);
    hex[0] = '0';
    hex[1] = 'x';
    tm_hex(hex + 2, p, n);
    size_t len = 2 * n + 2;
    tm_buf *b = &r->last->cells;
    buf_putc(b, CK_TEXT);
    buf_u32le(b, (uint32_t)(len + (cut ? 3 : 0)));
    buf_put(b, hex, len);
    if (cut) {
        buf_put(b, "\xE2\x80\xA6", 3);
        r->cells_cut = true;
    }
    free(hex);
}

void res_command(tm_result *r, long long affected, const char *tag)
{
    tm_rowset *rs = r->last;
    if (!rs || rs->done) rs = res_begin_set(r, 0);
    rs->done = true;
    rs->affected = affected;
    if (tag) snprintf(rs->tag, sizeof rs->tag, "%s", tag);
    r->in_row = false;
}

void res_notice(tm_result *r, const char *text)
{
    if (!text || !*text || r->notices.len > 8192) return;
    buf_puts(&r->notices, text);
    buf_putc(&r->notices, '\n');
}

/* ---- saída ---- */

int fmt_parse(const char *s)
{
    if (!s || !*s || tm_stricmp(s, "json") == 0) return FMT_JSON;
    if (tm_stricmp(s, "csv") == 0) return FMT_CSV;
    if (tm_stricmp(s, "markdown") == 0 || tm_stricmp(s, "md") == 0) return FMT_MARKDOWN;
    return -1;
}

typedef struct {
    tm_ckind    kind;
    const char *p;
    size_t      n;
} cell;

static bool next_cell(tm_rd *rd, cell *c)
{
    c->kind = (tm_ckind)rd_u8(rd);
    c->n = rd_u32le(rd);
    c->p = (const char *)rd_bytes(rd, c->n);
    return !rd->bad;
}

static void json_cell(tm_buf *out, const cell *c)
{
    switch (c->kind) {
    case CK_NULL: buf_puts(out, "null"); break;
    case CK_BOOL: buf_put(out, c->p, c->n); break;
    case CK_NUM:
        if (js_is_number(c->p, c->n)) buf_put(out, c->p, c->n);
        else jw_str(out, c->p, c->n); /* NaN, Infinity, dinheiro com símbolo... */
        break;
    default: jw_str(out, c->p, c->n);
    }
}

static void rowset_fields(tm_buf *out, const tm_rowset *rs)
{
    if (rs->ncols == 0) {
        buf_puts(out, "\"ok\":true");
        if (rs->affected >= 0) buf_printf(out, ",\"affected\":%lld", rs->affected);
        if (rs->tag[0]) {
            buf_puts(out, ",\"tag\":");
            jw_cstr(out, rs->tag);
        }
        return;
    }
    buf_puts(out, "\"columns\":[");
    for (int i = 0; i < rs->ncols; i++) {
        if (i) buf_putc(out, ',');
        jw_cstr(out, rs->cols[i].name);
    }
    buf_puts(out, "],\"types\":[");
    for (int i = 0; i < rs->ncols; i++) {
        if (i) buf_putc(out, ',');
        jw_cstr(out, rs->cols[i].type);
    }
    buf_puts(out, "],\"rows\":[");
    tm_rd rd;
    rd_init(&rd, rs->cells.p, rs->cells.len);
    for (size_t row = 0; row < rs->nrows; row++) {
        buf_puts(out, row ? ",\n[" : "\n[");
        for (int i = 0; i < rs->ncols; i++) {
            cell c;
            if (!next_cell(&rd, &c)) break;
            if (i) buf_putc(out, ',');
            json_cell(out, &c);
        }
        buf_putc(out, ']');
    }
    buf_printf(out, "%s],\"rowCount\":%llu", rs->nrows ? "\n" : "", (unsigned long long)rs->nrows);
}

void fmt_rowset_json(tm_buf *out, const tm_rowset *rs)
{
    buf_putc(out, '{');
    if (rs) rowset_fields(out, rs);
    else buf_puts(out, "\"ok\":true");
    buf_putc(out, '}');
}

static void json_trailer(tm_buf *out, const tm_result *r)
{
    if (r->truncated)
        buf_printf(out, ",\"truncated\":true,\"rowLimit\":%d", r->max_rows);
    if (r->cells_cut) buf_puts(out, ",\"cellsTruncated\":true");
    if (r->notices.len) {
        buf_puts(out, ",\"notices\":[");
        const char *p = (const char *)r->notices.p, *end = p + r->notices.len;
        bool first = true;
        while (p < end) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            if (!nl) nl = end;
            if (!first) buf_putc(out, ',');
            jw_str(out, p, (size_t)(nl - p));
            first = false;
            p = nl + 1;
        }
        buf_putc(out, ']');
    }
}

static void fmt_json(tm_buf *out, const tm_result *r)
{
    buf_putc(out, '{');
    if (!r->first) {
        buf_puts(out, "\"ok\":true");
    } else if (!r->first->next) {
        rowset_fields(out, r->first);
    } else {
        buf_puts(out, "\"results\":[");
        for (const tm_rowset *rs = r->first; rs; rs = rs->next) {
            if (rs != r->first) buf_putc(out, ',');
            fmt_rowset_json(out, rs);
        }
        buf_putc(out, ']');
    }
    json_trailer(out, r);
    buf_putc(out, '}');
}

static void csv_field(tm_buf *out, const char *p, size_t n)
{
    bool quote = false;
    for (size_t i = 0; i < n && !quote; i++)
        quote = p[i] == ',' || p[i] == '"' || p[i] == '\n' || p[i] == '\r';
    if (!quote) {
        buf_put(out, p, n);
        return;
    }
    buf_putc(out, '"');
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '"') buf_putc(out, '"');
        buf_putc(out, p[i]);
    }
    buf_putc(out, '"');
}

static void md_field(tm_buf *out, const char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '|') buf_puts(out, "\\|");
        else if (p[i] == '\n') buf_puts(out, "<br>");
        else if (p[i] != '\r') buf_putc(out, p[i]);
    }
}

static void fmt_text(tm_buf *out, const tm_result *r, bool md)
{
    for (const tm_rowset *rs = r->first; rs; rs = rs->next) {
        if (rs != r->first) buf_putc(out, '\n');
        if (rs->ncols == 0) {
            if (rs->tag[0]) buf_printf(out, "%s\n", rs->tag);
            else if (rs->affected >= 0) buf_printf(out, "affected: %lld\n", rs->affected);
            else buf_puts(out, "ok\n");
            continue;
        }
        for (int i = 0; i < rs->ncols; i++) {
            const char *name = rs->cols[i].name;
            if (md) {
                buf_puts(out, i ? " | " : "| ");
                md_field(out, name, strlen(name));
            } else {
                if (i) buf_putc(out, ',');
                csv_field(out, name, strlen(name));
            }
        }
        buf_puts(out, md ? " |\n" : "\n");
        if (md) {
            for (int i = 0; i < rs->ncols; i++) buf_puts(out, "|---");
            buf_puts(out, "|\n");
        }
        tm_rd rd;
        rd_init(&rd, rs->cells.p, rs->cells.len);
        for (size_t row = 0; row < rs->nrows; row++) {
            for (int i = 0; i < rs->ncols; i++) {
                cell c;
                if (!next_cell(&rd, &c)) break;
                if (md) {
                    buf_puts(out, i ? " | " : "| ");
                    if (c.kind == CK_NULL) buf_puts(out, "NULL");
                    else md_field(out, c.p, c.n);
                } else {
                    if (i) buf_putc(out, ',');
                    if (c.kind != CK_NULL) csv_field(out, c.p, c.n);
                }
            }
            buf_puts(out, md ? " |\n" : "\n");
        }
    }
    if (r->truncated) buf_printf(out, "%s truncated at %d rows\n", md ? "\n>" : "#", r->max_rows);
}

void fmt_result(tm_buf *out, const tm_result *r, tm_format f)
{
    if (f == FMT_JSON) fmt_json(out, r);
    else fmt_text(out, r, f == FMT_MARKDOWN);
}
