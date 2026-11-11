/* Driver SQL Server — protocolo TDS 7.4, implementação própria.
 * Login SQL, lote de SQL (SQL Batch) e leitura completa do fluxo de tokens,
 * com decodificação de todos os tipos de dado do servidor para texto.
 *
 * O SQL Server não tem transação somente leitura; no caminho de leitura a
 * proteção é a guarda léxica (db.c), mais a recomendação de um login só-leitura. */
#include "db.h"
#include "i18n.h"
#include "plat.h"
#include "tls.h"

#define TDS_HEADER      8
#define TDS_DRAIN_LIMIT 200000

enum { PKT_BATCH = 0x01, PKT_REPLY = 0x04, PKT_LOGIN7 = 0x10, PKT_PRELOGIN = 0x12 };

enum {
    TOK_RETURNSTATUS = 0x79, TOK_COLMETADATA = 0x81, TOK_TABNAME = 0xA4, TOK_COLINFO = 0xA5, TOK_ORDER = 0xA9,
    TOK_ERROR = 0xAA, TOK_INFO = 0xAB, TOK_LOGINACK = 0xAD, TOK_FEATUREEXTACK = 0xAE, TOK_ROW = 0xD1,
    TOK_NBCROW = 0xD2, TOK_ENVCHANGE = 0xE3, TOK_SESSIONSTATE = 0xE4, TOK_SSPI = 0xED, TOK_FEDAUTHINFO = 0xEE,
    TOK_DONE = 0xFD, TOK_DONEPROC = 0xFE, TOK_DONEINPROC = 0xFF
};

/* Tipos de dado TDS */
enum {
    T_NULL = 0x1F, T_INT1 = 0x30, T_BIT = 0x32, T_INT2 = 0x34, T_INT4 = 0x38, T_DATETIM4 = 0x3A, T_FLT4 = 0x3B,
    T_MONEY = 0x3C, T_DATETIME = 0x3D, T_FLT8 = 0x3E, T_MONEY4 = 0x7A, T_INT8 = 0x7F,
    T_GUID = 0x24, T_INTN = 0x26, T_BITN = 0x68, T_DECIMALN = 0x6A, T_NUMERICN = 0x6C, T_FLTN = 0x6D,
    T_MONEYN = 0x6E, T_DATETIMN = 0x6F, T_DATEN = 0x28, T_TIMEN = 0x29, T_DATETIME2N = 0x2A,
    T_DATETIMEOFFSETN = 0x2B, T_CHAR = 0x2F, T_VARCHAR = 0x27, T_BINARY = 0x2D, T_VARBINARY = 0x25,
    T_BIGVARBIN = 0xA5, T_BIGVARCHAR = 0xA7, T_BIGBINARY = 0xAD, T_BIGCHAR = 0xAF, T_NVARCHAR = 0xE7,
    T_NCHAR = 0xEF, T_XML = 0xF1, T_UDT = 0xF0, T_TEXT = 0x23, T_IMAGE = 0x22, T_NTEXT = 0x63, T_VARIANT = 0x62
};

typedef enum { F_FIXED, F_BYTELEN, F_USHORTLEN, F_PLP, F_LONGLEN, F_VARIANT } framing;

typedef struct column {
    uint8_t type, fixed, prec, scale;
    framing frame;
    bool    utf8; /* texto não-Unicode cuja ordenação já é UTF-8 */
} column;

struct tm_dbc {
    tm_io    io;
    tm_buf   in, out, val, text;
    size_t   ipos;
    bool     eom;      /* último pacote da mensagem já lido */
    bool     bad;      /* falha de leitura: o erro está em *err */
    tm_err  *err;
    size_t   packet_size;
    uint8_t  packet_id;
    char     version[128];
    column  *cols;
    int      ncols;
    size_t   val_cap;  /* teto do que se guarda de um valor grande */
    /* transporte do TLS quando o aperto de mão vai embrulhado em pacotes TDS */
    tm_buf   tls_in;
    size_t   tls_ipos, tls_raw_left;
    bool     tls_done;
};

/* ---- pacotes ---- */

static int send_message(tm_dbc *c, int type, const uint8_t *p, size_t n, tm_err *err)
{
    size_t chunk = c->packet_size - TDS_HEADER;
    buf_reset(&c->out);
    do {
        size_t take = n < chunk ? n : chunk;
        size_t total = take + TDS_HEADER;
        uint8_t hdr[TDS_HEADER] = { (uint8_t)type, n == take ? 1 : 0, (uint8_t)(total >> 8), (uint8_t)total,
                                    0, 0, ++c->packet_id, 0 };
        buf_put(&c->out, hdr, TDS_HEADER);
        buf_put(&c->out, p, take);
        p += take;
        n -= take;
    } while (n);
    return io_write(&c->io, c->out.p, c->out.len, err);
}

static void begin_read(tm_dbc *c, tm_err *err)
{
    buf_reset(&c->in);
    c->ipos = 0;
    c->eom = false;
    c->bad = false;
    c->err = err;
}

static int next_packet(tm_dbc *c)
{
    uint8_t hdr[TDS_HEADER];
    if (c->eom) {
        c->io.broken = true;
        return tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "token stream ended early");
    }
    if (io_read(&c->io, hdr, TDS_HEADER, c->err)) return -1;
    size_t len = ((size_t)hdr[2] << 8) | hdr[3];
    if (len < TDS_HEADER) {
        c->io.broken = true;
        return tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "packet length");
    }
    len -= TDS_HEADER;
    buf_reset(&c->in);
    buf_reserve(&c->in, len);
    if (len && io_read(&c->io, c->in.p, len, c->err)) return -1;
    c->in.len = len;
    c->ipos = 0;
    c->eom = (hdr[1] & 1) != 0;
    return 0;
}

/* Lê n bytes do fluxo, atravessando pacotes. dst NULL = descartar. */
static void take(tm_dbc *c, void *dst, size_t n)
{
    uint8_t *d = dst;
    while (n && !c->bad) {
        if (c->ipos == c->in.len) {
            if (next_packet(c)) c->bad = true;
            continue;
        }
        size_t have = c->in.len - c->ipos;
        if (have > n) have = n;
        if (d) {
            memcpy(d, c->in.p + c->ipos, have);
            d += have;
        }
        c->ipos += have;
        n -= have;
    }
    if (c->bad && d) memset(d, 0, n);
}

static uint8_t g8(tm_dbc *c)
{
    uint8_t v = 0;
    take(c, &v, 1);
    return v;
}

static uint16_t g16(tm_dbc *c)
{
    uint8_t b[2] = { 0, 0 };
    take(c, b, 2);
    return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t g32(tm_dbc *c)
{
    uint8_t b[4] = { 0, 0, 0, 0 };
    take(c, b, 4);
    return b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t g64(tm_dbc *c)
{
    uint64_t lo = g32(c);
    return lo | ((uint64_t)g32(c) << 32);
}

/* Texto UCS-2 de `chars` caracteres, convertido para UTF-8 em c->text. */
static const char *gstr(tm_dbc *c, size_t chars)
{
    buf_reset(&c->val);
    buf_reserve(&c->val, chars * 2);
    take(c, c->val.p, chars * 2);
    buf_reset(&c->text);
    if (!c->bad) tm_utf16le_to_utf8(&c->text, c->val.p, chars * 2);
    return buf_cstr(&c->text);
}

/* Acrescenta n bytes do fluxo a c->val, guardando só até o teto. */
static void take_val(tm_dbc *c, size_t n)
{
    size_t room = c->val.len < c->val_cap ? c->val_cap - c->val.len : 0;
    size_t keep = n < room ? n : room;
    if (keep) {
        buf_reserve(&c->val, keep);
        take(c, c->val.p + c->val.len, keep);
        if (!c->bad) c->val.len += keep;
    }
    take(c, NULL, n - keep);
}

/* ---- valores -> texto ---- */

static void cell_int(tm_result *r, const uint8_t *p, size_t n)
{
    char t[24];
    long long v = 0;
    if (n == 1) v = p[0];
    else if (n == 2) v = (int16_t)(p[0] | (p[1] << 8));
    else if (n == 4) v = (int32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
    else if (n == 8) {
        uint64_t u = 0;
        for (int i = 7; i >= 0; i--) u = (u << 8) | p[i];
        v = (long long)u;
    }
    int len = snprintf(t, sizeof t, "%lld", v);
    res_cell(r, CK_NUM, t, (size_t)len);
}

/* Menor representação decimal que volta ao mesmo valor. */
static void cell_float(tm_result *r, const uint8_t *p, size_t n)
{
    char t[40];
    int len = 0;
    if (n == 4) {
        float f;
        memcpy(&f, p, 4);
        for (int prec = 6; prec <= 9; prec++) {
            len = snprintf(t, sizeof t, "%.*g", prec, (double)f);
            if (strtof(t, NULL) == f) break;
        }
    } else {
        double d;
        memcpy(&d, p, 8);
        for (int prec = 15; prec <= 17; prec++) {
            len = snprintf(t, sizeof t, "%.*g", prec, d);
            if (strtod(t, NULL) == d) break;
        }
    }
    res_cell(r, CK_NUM, t, (size_t)len);
}

static void cell_money(tm_result *r, const uint8_t *p, size_t n)
{
    char t[32];
    int64_t v;
    if (n == 4) {
        v = (int32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
    } else { /* metade alta primeiro, cada metade em little-endian */
        uint64_t hi = p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        uint64_t lo = p[4] | ((uint32_t)p[5] << 8) | ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
        v = (int64_t)((hi << 32) | lo);
    }
    uint64_t mag = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    int len = snprintf(t, sizeof t, "%s%llu.%04llu", v < 0 ? "-" : "", (unsigned long long)(mag / 10000),
                       (unsigned long long)(mag % 10000));
    res_cell(r, CK_NUM, t, (size_t)len);
}

/* decimal/numeric: byte de sinal + magnitude little-endian de até 128 bits */
static void cell_decimal(tm_result *r, const uint8_t *p, size_t n, int scale)
{
    uint32_t w[4] = { 0, 0, 0, 0 };
    char digits[48], out[56];
    int nd = 0, o = 0;
    bool negative = n && p[0] == 0;
    for (size_t i = 1; i < n && i <= 16; i++) w[(i - 1) / 4] |= (uint32_t)p[i] << (8 * ((i - 1) % 4));
    while (w[0] | w[1] | w[2] | w[3]) {
        uint64_t rem = 0;
        for (int i = 3; i >= 0; i--) {
            uint64_t cur = (rem << 32) | w[i];
            w[i] = (uint32_t)(cur / 10);
            rem = cur % 10;
        }
        digits[nd++] = (char)('0' + rem);
    }
    while (nd <= scale) digits[nd++] = '0'; /* garante um dígito antes da vírgula */
    if (negative) out[o++] = '-';
    for (int i = nd - 1; i >= 0; i--) {
        out[o++] = digits[i];
        if (i == scale && scale > 0) out[o++] = '.';
    }
    res_cell(r, CK_NUM, out, (size_t)o);
}

static int fmt_date(char *out, size_t cap, int64_t days_from_year1)
{
    int y, m, d;
    tm_civil_from_days(days_from_year1 - 719162, &y, &m, &d);
    return snprintf(out, cap, "%04d-%02d-%02d", y, m, d);
}

/* `units` em 10^-scale segundos desde a meia-noite */
static int fmt_time(char *out, size_t cap, uint64_t units, int scale)
{
    uint64_t div = 1;
    for (int i = 0; i < scale; i++) div *= 10;
    uint64_t secs = units / div, frac = units % div;
    int n = snprintf(out, cap, "%02llu:%02llu:%02llu", (unsigned long long)(secs / 3600),
                     (unsigned long long)(secs / 60 % 60), (unsigned long long)(secs % 60));
    if (scale > 0) n += snprintf(out + n, cap - (size_t)n, ".%0*llu", scale, (unsigned long long)frac);
    return n;
}

static uint64_t le_uint(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    for (size_t i = n; i-- > 0;) v = (v << 8) | p[i];
    return v;
}

static size_t time_bytes(int scale)
{
    return scale <= 2 ? 3 : scale <= 4 ? 4 : 5;
}

static void cell_temporal(tm_result *r, int type, const uint8_t *p, size_t n, int scale)
{
    char t[64];
    int len = 0;
    if (type == T_DATETIME || (type == T_DATETIMN && n == 8)) {
        int32_t days = (int32_t)le_uint(p, 4);
        uint64_t ticks = le_uint(p + 4, 4);          /* 1/300 s */
        uint64_t ms = (ticks * 10 + 1) / 3;
        len = fmt_date(t, sizeof t, (int64_t)days + 693595);
        t[len++] = ' ';
        len += fmt_time(t + len, sizeof t - (size_t)len, ms, 3);
    } else if (type == T_DATETIM4 || (type == T_DATETIMN && n == 4)) {
        len = fmt_date(t, sizeof t, (int64_t)le_uint(p, 2) + 693595);
        t[len++] = ' ';
        len += fmt_time(t + len, sizeof t - (size_t)len, le_uint(p + 2, 2) * 60, 0);
    } else if (type == T_DATEN) {
        len = fmt_date(t, sizeof t, (int64_t)le_uint(p, 3));
    } else if (type == T_TIMEN) {
        len = fmt_time(t, sizeof t, le_uint(p, n), scale);
    } else {
        size_t tb = time_bytes(scale);
        if (n < tb + 3) {
            res_cell_bin(r, p, n);
            return;
        }
        uint64_t units = le_uint(p, tb);
        int64_t days = (int64_t)le_uint(p + tb, 3);
        int offset = 0;
        if (type == T_DATETIMEOFFSETN && n >= tb + 5) {
            /* Vem em UTC com o deslocamento ao lado: mostra a hora local daquele fuso. */
            offset = (int16_t)le_uint(p + tb + 3, 2);
            uint64_t per_day = 86400, div = 1;
            for (int i = 0; i < scale; i++) div *= 10;
            per_day *= div;
            int64_t total = (int64_t)units + (int64_t)offset * 60 * (int64_t)div;
            if (total < 0) {
                total += (int64_t)per_day;
                days--;
            } else if (total >= (int64_t)per_day) {
                total -= (int64_t)per_day;
                days++;
            }
            units = (uint64_t)total;
        }
        len = fmt_date(t, sizeof t, days);
        t[len++] = ' ';
        len += fmt_time(t + len, sizeof t - (size_t)len, units, scale);
        if (type == T_DATETIMEOFFSETN) {
            int a = offset < 0 ? -offset : offset;
            len += snprintf(t + len, sizeof t - (size_t)len, " %c%02d:%02d", offset < 0 ? '-' : '+', a / 60, a % 60);
        }
    }
    res_cell(r, CK_TEXT, t, (size_t)len);
}

static void cell_guid(tm_result *r, const uint8_t *p)
{
    char t[40];
    int len = snprintf(t, sizeof t, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                       p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6], p[8], p[9], p[10], p[11], p[12], p[13],
                       p[14], p[15]);
    res_cell(r, CK_TEXT, t, (size_t)len);
}

/* Converte o valor bruto de um tipo para uma célula. */
static void emit(tm_dbc *c, tm_result *r, int type, const uint8_t *p, size_t n, int prec, int scale, bool utf8)
{
    (void)prec;
    switch (type) {
    case T_INT1: case T_INT2: case T_INT4: case T_INT8: case T_INTN:
        cell_int(r, p, n);
        break;
    case T_BIT: case T_BITN:
        res_cell(r, CK_BOOL, p[0] ? "true" : "false", p[0] ? 4 : 5);
        break;
    case T_FLT4: case T_FLT8: case T_FLTN:
        cell_float(r, p, n);
        break;
    case T_MONEY: case T_MONEY4: case T_MONEYN:
        cell_money(r, p, n);
        break;
    case T_DECIMALN: case T_NUMERICN:
        cell_decimal(r, p, n, scale);
        break;
    case T_DATETIME: case T_DATETIM4: case T_DATETIMN: case T_DATEN: case T_TIMEN: case T_DATETIME2N:
    case T_DATETIMEOFFSETN:
        cell_temporal(r, type, p, n, scale);
        break;
    case T_GUID:
        if (n == 16) cell_guid(r, p);
        else res_cell_bin(r, p, n);
        break;
    case T_NVARCHAR: case T_NCHAR: case T_NTEXT: case T_XML:
        buf_reset(&c->text);
        tm_utf16le_to_utf8(&c->text, p, n);
        res_cell(r, CK_TEXT, c->text.p, c->text.len);
        break;
    case T_BIGVARCHAR: case T_BIGCHAR: case T_VARCHAR: case T_CHAR: case T_TEXT:
        if (utf8) {
            res_cell(r, CK_TEXT, p, n);
        } else {
            buf_reset(&c->text);
            tm_cp1252_to_utf8(&c->text, p, n);
            res_cell(r, CK_TEXT, c->text.p, c->text.len);
        }
        break;
    default: /* binários, UDT e o que mais aparecer */
        res_cell_bin(r, p, n);
    }
}

static bool collation_utf8(const uint8_t *coll)
{
    return (coll[3] & 0x04) != 0; /* bit fUTF8 das ColFlags */
}

/* sql_variant: tipo base, propriedades e então o valor. */
static void emit_variant(tm_dbc *c, tm_result *r, const uint8_t *p, size_t n)
{
    if (n < 2 || (size_t)p[1] + 2 > n) {
        res_cell_bin(r, p, n);
        return;
    }
    int base = p[0];
    size_t props = p[1];
    const uint8_t *pp = p + 2, *v = p + 2 + props;
    size_t vn = n - 2 - props;
    int prec = 0, scale = 0;
    bool utf8 = false;
    if ((base == T_DECIMALN || base == T_NUMERICN) && props >= 2) {
        prec = pp[0];
        scale = pp[1];
    } else if ((base == T_TIMEN || base == T_DATETIME2N || base == T_DATETIMEOFFSETN) && props >= 1) {
        scale = pp[0];
    } else if ((base == T_BIGVARCHAR || base == T_BIGCHAR) && props >= 5) {
        utf8 = collation_utf8(pp);
    }
    emit(c, r, base, v, vn, prec, scale, utf8);
}

/* ---- metadados de coluna ---- */

static const char *type_name(const column *col, size_t maxlen)
{
    switch (col->type) {
    case T_INT1: return "tinyint";
    case T_INT2: return "smallint";
    case T_INT4: return "int";
    case T_INT8: return "bigint";
    case T_INTN: return maxlen == 1 ? "tinyint" : maxlen == 2 ? "smallint" : maxlen == 4 ? "int" : "bigint";
    case T_BIT: case T_BITN: return "bit";
    case T_FLT4: return "real";
    case T_FLT8: return "float";
    case T_FLTN: return maxlen == 4 ? "real" : "float";
    case T_MONEY: return "money";
    case T_MONEY4: return "smallmoney";
    case T_MONEYN: return maxlen == 4 ? "smallmoney" : "money";
    case T_DATETIME: return "datetime";
    case T_DATETIM4: return "smalldatetime";
    case T_DATETIMN: return maxlen == 4 ? "smalldatetime" : "datetime";
    case T_DECIMALN: return "decimal";
    case T_NUMERICN: return "numeric";
    case T_GUID: return "uniqueidentifier";
    case T_DATEN: return "date";
    case T_TIMEN: return "time";
    case T_DATETIME2N: return "datetime2";
    case T_DATETIMEOFFSETN: return "datetimeoffset";
    case T_BIGVARCHAR: case T_VARCHAR: return "varchar";
    case T_BIGCHAR: case T_CHAR: return "char";
    case T_NVARCHAR: return "nvarchar";
    case T_NCHAR: return "nchar";
    case T_BIGVARBIN: case T_VARBINARY: return "varbinary";
    case T_BIGBINARY: case T_BINARY: return "binary";
    case T_TEXT: return "text";
    case T_NTEXT: return "ntext";
    case T_IMAGE: return "image";
    case T_XML: return "xml";
    case T_VARIANT: return "sql_variant";
    case T_UDT: return "udt";
    default: return "unknown";
    }
}

static void skip_bvarchar(tm_dbc *c)
{
    take(c, NULL, (size_t)g8(c) * 2);
}

static void skip_usvarchar(tm_dbc *c)
{
    take(c, NULL, (size_t)g16(c) * 2);
}

static int read_colmetadata(tm_dbc *c, tm_result *r)
{
    unsigned count = g16(c);
    if (count == 0xFFFF) count = 0;
    tm_rowset *rs = res_begin_set(r, (int)count);
    free(c->cols);
    c->cols = tm_zalloc(count * sizeof *c->cols);
    c->ncols = (int)count;

    for (unsigned i = 0; i < count && !c->bad; i++) {
        column *col = &c->cols[i];
        size_t maxlen = 0;
        uint8_t coll[5];
        g32(c); /* UserType */
        g16(c); /* Flags */
        col->type = g8(c);
        switch (col->type) {
        case T_NULL: col->frame = F_FIXED; col->fixed = 0; break;
        case T_INT1: case T_BIT: col->frame = F_FIXED; col->fixed = 1; break;
        case T_INT2: col->frame = F_FIXED; col->fixed = 2; break;
        case T_INT4: case T_DATETIM4: case T_FLT4: case T_MONEY4: col->frame = F_FIXED; col->fixed = 4; break;
        case T_MONEY: case T_DATETIME: case T_FLT8: case T_INT8: col->frame = F_FIXED; col->fixed = 8; break;
        case T_GUID: case T_INTN: case T_BITN: case T_FLTN: case T_MONEYN: case T_DATETIMN:
            col->frame = F_BYTELEN;
            maxlen = g8(c);
            break;
        case T_DECIMALN: case T_NUMERICN:
            col->frame = F_BYTELEN;
            maxlen = g8(c);
            col->prec = g8(c);
            col->scale = g8(c);
            break;
        case T_DATEN: col->frame = F_BYTELEN; break;
        case T_TIMEN: case T_DATETIME2N: case T_DATETIMEOFFSETN:
            col->frame = F_BYTELEN;
            col->scale = g8(c);
            break;
        case T_CHAR: case T_VARCHAR:
            col->frame = F_BYTELEN;
            maxlen = g8(c);
            take(c, coll, 5);
            col->utf8 = collation_utf8(coll);
            break;
        case T_BINARY: case T_VARBINARY:
            col->frame = F_BYTELEN;
            maxlen = g8(c);
            break;
        case T_BIGVARCHAR: case T_BIGCHAR: case T_NVARCHAR: case T_NCHAR:
            maxlen = g16(c);
            col->frame = maxlen == 0xFFFF ? F_PLP : F_USHORTLEN;
            take(c, coll, 5);
            col->utf8 = collation_utf8(coll);
            break;
        case T_BIGVARBIN: case T_BIGBINARY:
            maxlen = g16(c);
            col->frame = maxlen == 0xFFFF ? F_PLP : F_USHORTLEN;
            break;
        case T_XML:
            col->frame = F_PLP;
            if (g8(c)) { /* esquema XML presente */
                skip_bvarchar(c);
                skip_bvarchar(c);
                skip_usvarchar(c);
            }
            break;
        case T_UDT:
            col->frame = F_PLP;
            g16(c);
            skip_bvarchar(c);
            skip_bvarchar(c);
            skip_bvarchar(c);
            skip_usvarchar(c);
            break;
        case T_TEXT: case T_NTEXT: case T_IMAGE: {
            col->frame = F_LONGLEN;
            g32(c);
            if (col->type != T_IMAGE) {
                take(c, coll, 5);
                col->utf8 = collation_utf8(coll);
            }
            unsigned parts = g8(c); /* nome da tabela, em partes */
            for (unsigned k = 0; k < parts; k++) skip_usvarchar(c);
            break;
        }
        case T_VARIANT:
            col->frame = F_VARIANT;
            g32(c);
            break;
        default:
            c->io.broken = true;
            return tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "unknown column type");
        }
        size_t nchars = g8(c);
        const char *name = gstr(c, nchars);
        res_set_col(rs, (int)i, name, strlen(name), type_name(col, maxlen));
    }
    return c->bad ? -1 : 0;
}

/* Lê o valor de uma coluna para c->val. Devolve false se for NULL. */
static bool read_value(tm_dbc *c, const column *col)
{
    buf_reset(&c->val);
    switch (col->frame) {
    case F_FIXED:
        take_val(c, col->fixed);
        return col->type != T_NULL;
    case F_BYTELEN: {
        size_t n = g8(c);
        if (n == 0 && col->type != T_CHAR && col->type != T_VARCHAR && col->type != T_BINARY &&
            col->type != T_VARBINARY)
            return false;
        if (n == 0xFF && (col->type == T_CHAR || col->type == T_VARCHAR || col->type == T_BINARY ||
                          col->type == T_VARBINARY))
            return false;
        take_val(c, n);
        return true;
    }
    case F_USHORTLEN: {
        size_t n = g16(c);
        if (n == 0xFFFF) return false;
        take_val(c, n);
        return true;
    }
    case F_PLP: {
        uint64_t total = g64(c);
        if (total == UINT64_MAX) return false;
        for (;;) {
            uint32_t chunk = g32(c);
            if (!chunk || c->bad) break;
            take_val(c, chunk);
        }
        return true;
    }
    case F_LONGLEN: {
        size_t ptr = g8(c);
        if (ptr == 0) return false;
        take(c, NULL, ptr + 8); /* ponteiro de texto + carimbo */
        take_val(c, g32(c));
        return true;
    }
    case F_VARIANT: {
        uint32_t n = g32(c);
        if (n == 0) return false;
        take_val(c, n);
        return true;
    }
    }
    return false;
}

static void read_row(tm_dbc *c, tm_result *r, bool nbc)
{
    uint8_t bitmap[512];
    size_t nbytes = ((size_t)c->ncols + 7) / 8;
    if (nbc) {
        if (nbytes > sizeof bitmap) {
            c->bad = true;
            tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "too many columns");
            return;
        }
        take(c, bitmap, nbytes);
    }
    bool keep = res_row_begin(r);
    for (int i = 0; i < c->ncols && !c->bad; i++) {
        const column *col = &c->cols[i];
        if (nbc && (bitmap[i / 8] >> (i % 8)) & 1) {
            if (keep) res_cell(r, CK_NULL, NULL, 0);
            continue;
        }
        bool has = read_value(c, col);
        if (!keep || c->bad) continue;
        if (!has) res_cell(r, CK_NULL, NULL, 0);
        else if (col->frame == F_VARIANT) emit_variant(c, r, c->val.p, c->val.len);
        else emit(c, r, col->type, c->val.p, c->val.len, col->prec, col->scale, col->utf8);
    }
}

/* ---- fluxo de tokens ---- */

static void read_message_token(tm_dbc *c, bool is_error, tm_result *r, tm_err *first, bool *failed)
{
    g16(c); /* tamanho */
    uint32_t number = g32(c);
    g8(c);  /* estado */
    g8(c);  /* classe */
    char msg[640];
    snprintf(msg, sizeof msg, "%s", gstr(c, g16(c)));
    skip_bvarchar(c); /* servidor */
    skip_bvarchar(c); /* procedimento */
    uint32_t line = g32(c);
    if (c->bad) return;
    if (is_error) {
        if (*failed) return;
        *failed = true;
        bool auth = number == 18456 || number == 18452 || number == 4060 || number == 18488;
        if (line > 1) tm_fail(first, auth ? TM_E_AUTH : TM_E_SERVER, "Msg %u, line %u: %s", number, line, msg);
        else tm_fail(first, auth ? TM_E_AUTH : TM_E_SERVER, "Msg %u: %s", number, msg);
    } else if (r && number != 5701 && number != 5703) { /* troca de banco / de idioma: ruído */
        res_notice(r, msg);
    }
}

static void read_envchange(tm_dbc *c)
{
    size_t len = g16(c);
    if (!len) return;
    uint8_t type = g8(c);
    len--;
    if (type == 4 && len >= 1) { /* tamanho de pacote negociado */
        size_t chars = g8(c);
        len--;
        if (chars * 2 <= len) {
            long v = strtol(gstr(c, chars), NULL, 10);
            len -= chars * 2;
            if (v >= 512 && v <= 32767) c->packet_size = (size_t)v;
        }
    }
    take(c, NULL, len);
}

/* Lê a resposta inteira. r NULL = só consumir (login). */
static int read_reply(tm_dbc *c, tm_result *r, tm_err *err)
{
    tm_err first;
    bool failed = false;
    tm_err_clear(&first);
    begin_read(c, err);
    c->val_cap = r ? (size_t)r->max_cell * 4 + 64 : 4096;

    for (;;) {
        uint8_t tok = g8(c);
        if (c->bad) return -1;
        switch (tok) {
        case TOK_COLMETADATA:
            if (r) {
                if (read_colmetadata(c, r)) return -1;
            } else {
                c->io.broken = true;
                return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "unexpected result set");
            }
            break;
        case TOK_ROW:
        case TOK_NBCROW:
            if (!r) {
                c->io.broken = true;
                return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "unexpected row");
            }
            read_row(c, r, tok == TOK_NBCROW);
            if (r->skipped_rows > TDS_DRAIN_LIMIT) {
                io_close(&c->io);
                res_notice(r, T(M_RESULT_TOO_BIG));
                return 0;
            }
            break;
        case TOK_DONE:
        case TOK_DONEPROC:
        case TOK_DONEINPROC: {
            uint16_t status = g16(c);
            g16(c);
            uint64_t rows = g64(c);
            if (c->bad) return -1;
            if (r && tok != TOK_DONEINPROC) {
                bool open_set = r->last && !r->last->done;
                if (open_set || (status & 0x10)) res_command(r, (status & 0x10) && !open_set ? (long long)rows : -1, NULL);
            } else if (r && r->last && !r->last->done && r->last->ncols) {
                res_command(r, -1, NULL);
            }
            if (tok != TOK_DONEINPROC && !(status & 0x1)) {
                if (failed) {
                    *err = first;
                    return -1;
                }
                return 0;
            }
            break;
        }
        case TOK_ERROR:
        case TOK_INFO:
            read_message_token(c, tok == TOK_ERROR, r, &first, &failed);
            break;
        case TOK_LOGINACK: {
            g16(c);
            g8(c);
            g32(c);
            skip_bvarchar(c);
            unsigned major = g8(c), minor = g8(c), build = (unsigned)(g8(c) << 8);
            build |= g8(c);
            static const struct { unsigned major; const char *year; } YEARS[] = {
                { 17, "2025" }, { 16, "2022" }, { 15, "2019" }, { 14, "2017" }, { 13, "2016" },
                { 12, "2014" }, { 11, "2012" }, { 10, "2008" }, { 9, "2005" },
            };
            const char *year = "";
            for (size_t i = 0; i < TM_COUNT(YEARS); i++)
                if (YEARS[i].major == major) year = YEARS[i].year;
            snprintf(c->version, sizeof c->version, "Microsoft SQL Server %s%s(%u.%u.%u)", year, *year ? " " : "",
                     major, minor, build);
            break;
        }
        case TOK_ENVCHANGE:
            read_envchange(c);
            break;
        case TOK_ORDER:
        case TOK_TABNAME:
        case TOK_COLINFO:
        case TOK_SSPI:
            take(c, NULL, g16(c));
            break;
        case TOK_RETURNSTATUS:
            g32(c);
            break;
        case TOK_SESSIONSTATE:
        case TOK_FEDAUTHINFO:
            take(c, NULL, g32(c));
            break;
        case TOK_FEATUREEXTACK:
            while (!c->bad && g8(c) != 0xFF) take(c, NULL, g32(c));
            break;
        default:
            c->io.broken = true;
            return tm_fail(err, TM_E_PROTOCOL, "%s 0x%02X", "unknown TDS token", tok);
        }
        if (c->bad) return -1;
    }
}

/* ---- conexão ---- */

static void put_ucs2(tm_buf *b, const char *s)
{
    if (s) tm_utf8_to_utf16le(b, s, strlen(s));
}

/* Porta de uma instância nomeada, pelo serviço SQL Browser (UDP 1434). */
static int browse_instance(const tm_conn_cfg *cfg, tm_err *err)
{
    uint8_t req[130], resp[2048];
    size_t n = strlen(cfg->instance);
    if (n > 120) n = 120;
    req[0] = 0x04;
    memcpy(req + 1, cfg->instance, n);
    req[n + 1] = 0;
    int got = plat_udp_query(cfg->host, 1434, req, n + 2, resp, sizeof resp - 1, 3000);
    if (got > 3) {
        resp[got] = 0;
        const char *tcp = strstr((const char *)resp + 3, ";tcp;");
        if (tcp) {
            int port = atoi(tcp + 5);
            if (port > 0 && port < 65536) return port;
        }
    }
    return tm_fail(err, TM_E_IO, T(M_INSTANCE_LOOKUP), cfg->instance, cfg->host);
}

/* No TDS 7.x o aperto de mão TLS viaja dentro de pacotes PRELOGIN; só depois dele
 * o TLS passa a correr direto sobre o socket, com os pacotes TDS por dentro. */
static int wrapped_send(void *ctx, const uint8_t *p, size_t n, tm_err *err)
{
    tm_dbc *c = ctx;
    if (!c->tls_done) return send_message(c, PKT_PRELOGIN, p, n, err);
    while (n) { /* aperto de mão concluído: registros TLS direto no socket */
        int rc = io_raw_send(&c->io, p, n, err);
        if (rc < 0) return -1;
        p += rc;
        n -= (size_t)rc;
    }
    return 0;
}

static int raw_exact(tm_io *io, uint8_t *p, size_t n, tm_err *err)
{
    while (n) {
        int rc = io_raw_recv(io, p, n, err);
        if (rc <= 0) return -1;
        p += rc;
        n -= (size_t)rc;
    }
    return 0;
}

/* Recebe bytes do TLS vindos do servidor, que chegam de duas formas: embrulhados em
 * pacotes TDS PRELOGIN (durante o aperto de mão — e, no TLS 1.3, também os bilhetes de
 * sessão que o servidor emite logo depois) ou como registros TLS puros. O primeiro byte
 * distingue: 0x12 é pacote TDS; registros TLS começam com 20 a 23. Tudo é lido sem
 * buffer do socket, para não sobrar nada em claro. */
static int wrapped_recv(void *ctx, uint8_t *p, size_t n, tm_err *err)
{
    tm_dbc *c = ctx;
    if (c->tls_ipos == c->tls_in.len && c->tls_raw_left) { /* corpo de um registro TLS puro */
        size_t want = n < c->tls_raw_left ? n : c->tls_raw_left;
        int rc = io_raw_recv(&c->io, p, want, err);
        if (rc > 0) c->tls_raw_left -= (size_t)rc;
        return rc;
    }
    if (c->tls_ipos == c->tls_in.len) {
        uint8_t hdr[TDS_HEADER];
        buf_reset(&c->tls_in);
        c->tls_ipos = 0;
        if (raw_exact(&c->io, hdr, 5, err)) return -1;
        if (hdr[0] == PKT_PRELOGIN) {
            if (raw_exact(&c->io, hdr + 5, 3, err)) return -1;
            size_t len = ((size_t)hdr[2] << 8) | hdr[3];
            if (len <= TDS_HEADER) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "TLS packet");
            len -= TDS_HEADER;
            buf_reserve(&c->tls_in, len);
            if (raw_exact(&c->io, c->tls_in.p, len, err)) return -1;
            c->tls_in.len = len;
        } else { /* registro TLS puro: entrega o cabeçalho e depois o corpo, direto do socket */
            buf_put(&c->tls_in, hdr, 5);
            c->tls_raw_left = ((size_t)hdr[3] << 8) | hdr[4];
        }
    }
    size_t take = c->tls_in.len - c->tls_ipos;
    if (take > n) take = n;
    memcpy(p, c->tls_in.p + c->tls_ipos, take);
    c->tls_ipos += take;
    return (int)take;
}

typedef enum { ENC_PLAIN, ENC_WRAPPED, ENC_STRICT } enc_mode;

static int prelogin(tm_dbc *c, const tm_conn_cfg *cfg, enc_mode mode, tm_err *err)
{
    bool use_tls = mode == ENC_WRAPPED;
    /* ENCRYPTION: com TLS pedimos cifra da sessão inteira (ON); sem, declaramos NOT_SUP. */
    uint8_t body[] = {
        0x00, 0x00, 26, 0x00, 6,  /* VERSION */
        0x01, 0x00, 32, 0x00, 1,  /* ENCRYPTION */
        0x02, 0x00, 33, 0x00, 1,  /* INSTOPT */
        0x03, 0x00, 34, 0x00, 4,  /* THREADID */
        0x04, 0x00, 38, 0x00, 1,  /* MARS */
        0xFF,
        0, 0, 0, 0, 0, 0,         /* versão do cliente */
        0x02,                     /* ENCRYPT_NOT_SUP */
        0x00,                     /* instância: vazio */
        0, 0, 0, 0,               /* thread */
        0x00,                     /* MARS desligado */
    };
    body[32] = use_tls ? 0x01 : 0x02;
    if (send_message(c, PKT_PRELOGIN, body, sizeof body, err)) return -1;
    begin_read(c, err);
    if (next_packet(c)) return -1;
    tm_rd rd;
    uint8_t enc = 0x02;
    rd_init(&rd, c->in.p, c->in.len);
    for (;;) {
        uint8_t tok = rd_u8(&rd);
        if (tok == 0xFF || rd.bad) break;
        uint16_t off = rd_u16be(&rd), len = rd_u16be(&rd);
        if (tok == 0x01 && len >= 1 && off < c->in.len) enc = c->in.p[off];
    }
    bool server_wants = enc == 0x01 || enc == 0x03;
    if (mode == ENC_STRICT) return 0; /* TDS 8.0: o TLS já envolve tudo; este campo não decide nada */
    if (!use_tls) /* pedimos sem cifra: só serve se o servidor não a exigir */
        return server_wants ? tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_REQUIRED)) : 0;
    if (!server_wants) {
        if (cfg->ssl >= SSL_REQUIRE) return tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_REFUSED));
        return 0;
    }
    tls_opts o;
    tls_opts_from_cfg(&o, cfg);
    o.send = wrapped_send;
    o.recv = wrapped_recv;
    o.ctx = c;
    if (tls_start(&c->io, &o, err)) return -1;
    c->tls_done = true; /* daqui em diante enviamos TLS puro; a recepção aceita os dois formatos */
    c->packet_id = 0;
    return 0;
}

static int login(tm_dbc *c, const tm_conn_cfg *cfg, bool tds8, tm_err *err)
{
    tm_buf b, data;
    buf_init(&b);
    buf_init(&data);
    const char *app = cfg->app_name ? cfg->app_name : TM_TITLE;

    buf_u32le(&b, 0);          /* tamanho total, preenchido no fim */
    buf_u32le(&b, tds8 ? 0x08000000 : 0x74000004); /* TDS 8.0 (modo estrito) ou 7.4 */
    buf_u32le(&b, 4096);       /* tamanho de pacote */
    buf_u32le(&b, 0x00000100); /* versão do programa cliente */
    buf_u32le(&b, 0);          /* PID */
    buf_u32le(&b, 0);          /* id da conexão */
    buf_putc(&b, 0xE0);        /* OptionFlags1: USE_DB, falha se o banco não existir, SET_LANG */
    buf_putc(&b, 0x03);        /* OptionFlags2: idioma obrigatório, padrões ANSI (ODBC) */
    buf_putc(&b, 0x00);        /* TypeFlags */
    buf_putc(&b, 0x00);        /* OptionFlags3 */
    buf_u32le(&b, 0);          /* fuso */
    buf_u32le(&b, 0);          /* LCID */

    /* Tabela de deslocamentos: (offset, tamanho em caracteres) de cada texto. */
    const size_t header = 94;
    const char *texts[9] = { "tmdb", cfg->user, NULL /* senha */, app, cfg->host, NULL, TM_NAME, NULL, cfg->database };
    for (int i = 0; i < 9; i++) {
        size_t before = data.len;
        if (i == 2) {
            put_ucs2(&data, cfg->password);
            for (size_t k = before; k < data.len; k++) { /* embaralhamento do protocolo */
                uint8_t v = data.p[k];
                data.p[k] = (uint8_t)(((v << 4) | (v >> 4)) ^ 0xA5);
            }
        } else {
            put_ucs2(&data, texts[i]);
        }
        buf_u16le(&b, (uint16_t)(header + before));
        buf_u16le(&b, (uint16_t)((data.len - before) / 2));
    }
    buf_fill(&b, 0, 6); /* ClientID */
    for (int i = 0; i < 3; i++) { /* SSPI, arquivo a anexar, troca de senha: ausentes */
        buf_u16le(&b, (uint16_t)(header + data.len));
        buf_u16le(&b, 0);
    }
    buf_u32le(&b, 0); /* cbSSPILong */
    buf_put(&b, data.p, data.len);
    uint32_t total = (uint32_t)b.len;
    b.p[0] = (uint8_t)total;
    b.p[1] = (uint8_t)(total >> 8);
    b.p[2] = (uint8_t)(total >> 16);
    b.p[3] = (uint8_t)(total >> 24);

    int rc = send_message(c, PKT_LOGIN7, b.p, b.len, err);
    tm_wipe(data.p, data.len);
    tm_wipe(b.p, b.len);
    buf_free(&b);
    buf_free(&data);
    return rc ? -1 : read_reply(c, NULL, err);
}

static void ms_close(tm_dbc *c)
{
    if (!c) return;
    io_close(&c->io);
    buf_free(&c->in);
    buf_free(&c->out);
    buf_free(&c->val);
    buf_free(&c->text);
    buf_free(&c->tls_in);
    free(c->cols);
    free(c);
}

static int ms_attempt(const tm_conn_cfg *cfg, enc_mode mode, tm_dbc **out, tm_err *err)
{
    int port = cfg->port;
    if (cfg->instance) {
        port = browse_instance(cfg, err);
        if (port < 0) return -1;
    }
    tm_dbc *c = tm_zalloc(sizeof *c);
    buf_init(&c->in);
    buf_init(&c->out);
    buf_init(&c->val);
    buf_init(&c->text);
    c->packet_size = 4096;
    if (io_connect(&c->io, cfg->host, port, cfg->connect_timeout_ms, err)) {
        free(c);
        return -1;
    }
    io_set_timeout(&c->io, cfg->connect_timeout_ms);
    if (mode == ENC_STRICT) {
        /* TDS 8.0: TLS primeiro, direto sobre o socket, anunciando o protocolo por ALPN. */
        tls_opts o;
        tls_opts_from_cfg(&o, cfg);
        o.alpn = "tds/8.0";
        if (tls_start(&c->io, &o, err)) {
            ms_close(c);
            return -1;
        }
    }
    if (prelogin(c, cfg, mode, err) || login(c, cfg, mode == ENC_STRICT, err)) {
        ms_close(c);
        return -1;
    }
    if (!c->version[0]) snprintf(c->version, sizeof c->version, "Microsoft SQL Server");
    *out = c;
    return 0;
}

static int ms_connect(const tm_conn_cfg *cfg, tm_dbc **out, tm_err *err)
{
    if (cfg->ssl == SSL_DISABLE) return ms_attempt(cfg, ENC_PLAIN, out, err);
    /* Primeiro o caminho comum: TDS 7.x com o aperto de mão TLS embrulhado. Se o servidor
     * derrubar a conexão (é o que faz quando exige o modo estrito), tenta TDS 8.0, com o
     * TLS antes de tudo. Erros de senha ou de certificado encerram na hora. */
    int rc = ms_attempt(cfg, ENC_WRAPPED, out, err);
    if (rc && (err->code == TM_E_IO || err->code == TM_E_PROTOCOL || err->code == TM_E_TIMEOUT)) {
        tm_err second;
        tm_err_clear(&second);
        tm_log(1, "mssql: TDS 7.x TLS attempt failed: %s", err->msg);
        rc = ms_attempt(cfg, ENC_STRICT, out, &second);
        if (rc) tm_log(1, "mssql: strict (TDS 8.0) attempt failed: %s", second.msg);
        if (rc && (second.code == TM_E_AUTH || second.code == TM_E_SERVER || second.code == TM_E_UNSUPPORTED ||
                   second.code == TM_E_CONFIG))
            *err = second;
        else if (rc) /* nenhum dos dois fechou: quase sempre é servidor que só tem TLS 1.2 */
            tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_MSSQL));
    }
    if (rc && tls_prefer_fallback(cfg, err)) rc = ms_attempt(cfg, ENC_PLAIN, out, err);
    return rc;
}

static int ms_query(tm_dbc *c, const char *sql, const tm_qopts *o, tm_result *r, tm_err *err)
{
    tm_buf b;
    io_set_timeout(&c->io, o->timeout_ms);
    buf_init(&b);
    /* ALL_HEADERS: só o descritor de transação (nenhuma transação em curso). */
    buf_u32le(&b, 22);
    buf_u32le(&b, 18);
    buf_u16le(&b, 2);
    buf_u64le(&b, 0);
    buf_u32le(&b, 1);
    tm_utf8_to_utf16le(&b, sql, strlen(sql));
    int rc = send_message(c, PKT_BATCH, b.p, b.len, err);
    buf_free(&b);
    return rc ? -1 : read_reply(c, r, err);
}

static bool ms_alive(tm_dbc *c)
{
    return !c->io.broken;
}

static const char *ms_version(tm_dbc *c)
{
    return c->version;
}

const tm_driver DRV_MSSQL = { FL_MSSQL, ms_connect, ms_query, ms_alive, ms_version, ms_close };
