/* Driver Oracle — protocolo TNS + TTC, implementação própria (sem OCI).
 *
 * O protocolo não tem especificação pública; o formato dos bytes foi conferido
 * com a implementação aberta de referência (python-oracledb, modo "thin").
 * Cobre: conexão por service name ou SID, login O5LOGON com verificadores 11g
 * e 12c, execução, definição de LOB/JSON como texto e leitura de linhas.
 * Leitura: SET TRANSACTION READ ONLY + consulta + ROLLBACK. */
#include <time.h>

#include "crypto/aes.h"
#include "crypto/hash.h"
#include "db.h"
#include "i18n.h"
#include "plat.h"
#include "tls.h"

/* ---- constantes do protocolo ---- */
enum { PKT_CONNECT = 1, PKT_ACCEPT = 2, PKT_REFUSE = 4, PKT_REDIRECT = 5, PKT_DATA = 6, PKT_RESEND = 11,
       PKT_MARKER = 12, PKT_CONTROL = 14 };

enum { MSG_PROTOCOL = 1, MSG_DATA_TYPES = 2, MSG_FUNCTION = 3, MSG_ERROR = 4, MSG_ROW_HEADER = 6,
       MSG_ROW_DATA = 7, MSG_PARAMETER = 8, MSG_STATUS = 9, MSG_IO_VECTOR = 11, MSG_WARNING = 15,
       MSG_DESCRIBE_INFO = 16, MSG_PIGGYBACK = 17, MSG_FLUSH_OUT_BINDS = 19, MSG_BIT_VECTOR = 21,
       MSG_SERVER_PIGGYBACK = 23, MSG_IMPLICIT_RESULTSET = 27 };

enum { FN_FETCH = 5, FN_LOGOFF = 9, FN_ROLLBACK = 15, FN_EXECUTE = 94, FN_CLOSE_CURSORS = 105,
       FN_AUTH_PHASE_TWO = 115, FN_AUTH_PHASE_ONE = 118 };

enum { OPT_PARSE = 0x01, OPT_DEFINE = 0x10, OPT_EXECUTE = 0x20, OPT_FETCH = 0x40, OPT_COMMIT = 0x100,
       OPT_NOT_PLSQL = 0x8000 };

enum { ORA_VARCHAR = 1, ORA_NUMBER = 2, ORA_BINARY_INTEGER = 3, ORA_LONG = 8, ORA_ROWID = 11, ORA_DATE = 12,
       ORA_RAW = 23, ORA_LONG_RAW = 24, ORA_CHAR = 96, ORA_BINARY_FLOAT = 100, ORA_BINARY_DOUBLE = 101,
       ORA_CURSOR = 102, ORA_OBJECT = 109, ORA_CLOB = 112, ORA_BLOB = 113, ORA_BFILE = 114, ORA_JSON = 119,
       ORA_VECTOR = 127, ORA_TIMESTAMP = 180, ORA_TIMESTAMP_TZ = 181, ORA_INTERVAL_YM = 182,
       ORA_INTERVAL_DS = 183, ORA_UROWID = 208, ORA_TIMESTAMP_LTZ = 231, ORA_BOOLEAN = 252 };

#define TNS_VERSION_DESIRED   318
#define TNS_VERSION_MINIMUM   300
#define TNS_VERSION_ACCEPTED  315      /* 12.1: daqui em diante o tamanho do pacote tem 4 bytes */
#define TNS_SDU               8192
#define FIELD_VERSION_12_2      8
#define FIELD_VERSION_12_2_EXT1 9
#define FIELD_VERSION_20_1      14
#define FIELD_VERSION_23_1      17
#define FIELD_VERSION_23_1_EXT1 18
#define FIELD_VERSION_23_1_EXT3 20
#define FIELD_VERSION_23_4      24
#define FIELD_VERSION_OURS      24     /* o servidor baixa para a dele, se for mais antigo */
#define CHARSET_UTF8          873
#define CHARSET_UTF16         2000
#define MAX_LONG              0x7fffffff
#define ERR_NO_DATA_FOUND     1403
#define ORA_DRAIN_LIMIT       200000
#define FETCH_ROWS            200

typedef struct ocol {
    uint8_t  type;
    uint8_t  csfrm;      /* 1 = conjunto de caracteres do banco, 2 = nacional (NCHAR) */
    uint32_t buffer_size;
    bool     lob;        /* buscado como LONG por definição nossa */
    tm_buf   last;       /* valor anterior, para colunas repetidas entre linhas */
    bool     last_null;
} ocol;

struct tm_dbc {
    tm_io    io;
    tm_buf   out, pkt, val, text;
    size_t   pos;
    bool     large;      /* tamanho de pacote em 4 bytes (após o ACCEPT) */
    uint32_t sdu;
    uint8_t  seq;
    bool     bad;        /* leitura interrompida: erro em *err, ou reinício em `restart` */
    bool     restart;    /* o servidor mandou um marcador: recomeçar a leitura da resposta */
    tm_err  *err;
    int      field_version;
    uint16_t ncharset;
    char     version[160];
    size_t   val_cap;

    ocol    *cols;
    int      ncols;
    uint8_t  bitvec[512];
    bool     has_bitvec;
    uint32_t close_ids[32];
    int      nclose;

    /* última mensagem de erro/estado recebida */
    uint32_t err_num_last; /* erro da última instrução executada (sobrevive ao ROLLBACK seguinte) */
    uint32_t err_num;
    uint16_t err_cursor;
    uint64_t rowcount;
    char     err_msg[640];

    /* parâmetros devolvidos pelo login */
    char     sesskey[200], vfr_data[80], csk_salt[80], svr_response[200];
    uint32_t verifier_type, vgen_count, sder_count, version_no;
};

/* ---- pacotes ---- */

static int send_packet(tm_dbc *c, int type, const uint8_t *p, size_t n, tm_err *err)
{
    uint8_t hdr[8] = { 0 };
    size_t total = n + 8;
    if (c->large) {
        hdr[0] = (uint8_t)(total >> 24);
        hdr[1] = (uint8_t)(total >> 16);
        hdr[2] = (uint8_t)(total >> 8);
        hdr[3] = (uint8_t)total;
    } else {
        hdr[0] = (uint8_t)(total >> 8);
        hdr[1] = (uint8_t)total;
    }
    hdr[4] = (uint8_t)type;
    tm_buf b;
    buf_init(&b);
    buf_put(&b, hdr, 8);
    buf_put(&b, p, n);
    int rc = io_write(&c->io, b.p, b.len, err);
    buf_free(&b);
    return rc;
}

/* Envia c->out como um ou mais pacotes de dados (2 bytes de flags + conteúdo). */
static int send_data(tm_dbc *c, tm_err *err)
{
    size_t chunk = c->sdu - 10, off = 0;
    tm_buf b;
    int rc = 0;
    buf_init(&b);
    do {
        size_t take = c->out.len - off < chunk ? c->out.len - off : chunk;
        buf_reset(&b);
        buf_u16be(&b, 0);
        buf_put(&b, c->out.p + off, take);
        rc = send_packet(c, PKT_DATA, b.p, b.len, err);
        off += take;
    } while (rc == 0 && off < c->out.len);
    buf_free(&b);
    buf_reset(&c->out);
    return rc;
}

static int send_marker(tm_dbc *c, uint8_t kind, tm_err *err)
{
    uint8_t body[3] = { 1, 0, kind };
    return send_packet(c, PKT_MARKER, body, 3, err);
}

/* Lê o próximo pacote para c->pkt. Devolve o tipo, ou -1. */
static int read_packet(tm_dbc *c, tm_err *err)
{
    uint8_t hdr[8];
    if (io_read(&c->io, hdr, 8, err)) return -1;
    size_t len = c->large ? ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) | ((size_t)hdr[2] << 8) | hdr[3]
                          : ((size_t)hdr[0] << 8) | hdr[1];
    if (len < 8 || len > (64u << 20)) {
        c->io.broken = true;
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "packet length");
    }
    len -= 8;
    buf_reset(&c->pkt);
    buf_reserve(&c->pkt, len);
    if (len && io_read(&c->io, c->pkt.p, len, err)) return -1;
    c->pkt.len = len;
    c->pos = 0;
    if (tm_log_level >= 2) {
        char hex[2 * 160 + 1];
        tm_hex(hex, c->pkt.p, len < 160 ? len : 160);
        tm_log(2, "oracle <- packet type %d, %u bytes: %s%s", hdr[4], (unsigned)len, hex, len > 160 ? "..." : "");
    }
    return hdr[4];
}

/* Avança para o próximo pacote de DADOS da resposta. Um marcador no meio do
 * caminho significa que o servidor interrompeu a chamada: responde com o
 * marcador de reinício, descarta até a confirmação e pede o recomeço da leitura. */
static int next_data_packet(tm_dbc *c)
{
    bool reset_sent = false, reset_seen = false;
    for (;;) {
        int type = read_packet(c, c->err);
        if (type < 0) return -1;
        if (type == PKT_CONTROL) continue;
        if (type == PKT_MARKER) {
            if (!reset_sent) {
                if (send_marker(c, 2, c->err)) return -1;
                reset_sent = true;
            }
            if (c->pkt.len >= 3 && c->pkt.p[2] == 2) reset_seen = true;
            continue;
        }
        if (type != PKT_DATA) {
            c->io.broken = true;
            return tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "packet type");
        }
        if (reset_sent && !reset_seen) continue; /* dados anteriores à interrupção: descarta */
        if (c->pkt.len < 2) continue;
        if (c->pkt.p[0] == 0x00 && c->pkt.p[1] == 0x40) { /* EOF: servidor encerrou */
            c->io.broken = true;
            return tm_fail(c->err, TM_E_IO, "%s", T(M_IO_CLOSED));
        }
        c->pos = 2;
        if (reset_sent) {
            c->restart = true;
            return 1;
        }
        return 0;
    }
}

/* Lê n bytes da resposta. dst NULL = descartar. Depois de uma falha (ou de um
 * pedido de recomeço) não consome mais nada e devolve zeros. */
static void take(tm_dbc *c, void *dst, size_t n)
{
    uint8_t *d = dst;
    while (n && !c->bad) {
        if (c->pos == c->pkt.len) {
            if (next_data_packet(c) != 0) c->bad = true;
            continue;
        }
        size_t have = c->pkt.len - c->pos;
        if (have > n) have = n;
        if (d) {
            memcpy(d, c->pkt.p + c->pos, have);
            d += have;
        }
        c->pos += have;
        n -= have;
    }
    if (c->bad && d && n) memset(d, 0, n);
}

static uint8_t g8(tm_dbc *c)
{
    uint8_t v = 0;
    take(c, &v, 1);
    return v;
}

static uint16_t g16be(tm_dbc *c)
{
    uint8_t b[2] = { 0, 0 };
    take(c, b, 2);
    return (uint16_t)((b[0] << 8) | b[1]);
}

static uint16_t g16le(tm_dbc *c)
{
    uint8_t b[2] = { 0, 0 };
    take(c, b, 2);
    return (uint16_t)(b[0] | (b[1] << 8));
}

/* Inteiro "universal": um byte de tamanho (bit alto = negativo) e os bytes em big-endian. */
static uint64_t gvar(tm_dbc *c, bool *negative)
{
    uint8_t len = g8(c), b[8];
    uint64_t v = 0;
    if (negative) *negative = (len & 0x80) != 0;
    len &= 0x7F;
    if (len > 8) {
        if (!c->bad) {
            c->bad = true;
            c->io.broken = true;
            tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "integer length");
        }
        return 0;
    }
    take(c, b, len);
    for (int i = 0; i < len; i++) v = (v << 8) | b[i];
    return v;
}

static uint32_t gub4(tm_dbc *c)
{
    return (uint32_t)gvar(c, NULL);
}

static uint16_t gub2(tm_dbc *c)
{
    return (uint16_t)gvar(c, NULL);
}

static int32_t gsb4(tm_dbc *c)
{
    bool neg;
    int32_t v = (int32_t)gvar(c, &neg);
    return neg ? -v : v;
}

/* Acrescenta n bytes da resposta a dst, guardando só até o teto. */
static void take_into(tm_dbc *c, tm_buf *dst, size_t n, size_t cap)
{
    size_t room = dst->len < cap ? cap - dst->len : 0;
    size_t keep = n < room ? n : room;
    if (keep) {
        buf_reserve(dst, keep);
        take(c, dst->p + dst->len, keep);
        if (!c->bad) dst->len += keep;
    }
    take(c, NULL, n - keep);
}

/* Bytes precedidos do tamanho: 0 ou 255 = nulo; 254 = em pedaços. false se nulo. */
static bool gbytes(tm_dbc *c, tm_buf *dst, size_t cap)
{
    uint8_t len = g8(c);
    buf_reset(dst);
    if (len == 0 || len == 255) return false;
    if (len != 254) {
        take_into(c, dst, len, cap);
        return true;
    }
    for (;;) {
        uint32_t chunk = gub4(c);
        if (!chunk || c->bad) break;
        take_into(c, dst, chunk, cap);
    }
    return true;
}

static void skip_bytes(tm_dbc *c)
{
    gbytes(c, &c->val, 0);
}

/* ub4 de tamanho e, se não for zero, os bytes. */
static bool gbytes_len(tm_dbc *c, tm_buf *dst, size_t cap)
{
    buf_reset(dst);
    return gub4(c) > 0 ? gbytes(c, dst, cap) : false;
}

static void skip_bytes_len(tm_dbc *c)
{
    gbytes_len(c, &c->val, 0);
}

/* Texto precedido de ub4: devolve em c->text (terminado em NUL). */
static const char *gstr_len(tm_dbc *c)
{
    gbytes_len(c, &c->text, 4096);
    return buf_cstr(&c->text);
}

/* ---- escrita ---- */

static void pvar(tm_buf *b, uint64_t v)
{
    if (v == 0) {
        buf_putc(b, 0);
    } else if (v <= 0xFF) {
        buf_putc(b, 1);
        buf_putc(b, (int)v);
    } else if (v <= 0xFFFF) {
        buf_putc(b, 2);
        buf_u16be(b, (uint16_t)v);
    } else if (v <= 0xFFFFFFFFu) {
        buf_putc(b, 4);
        buf_u32be(b, (uint32_t)v);
    } else {
        buf_putc(b, 8);
        buf_u32be(b, (uint32_t)(v >> 32));
        buf_u32be(b, (uint32_t)v);
    }
}

/* Bytes com o tamanho na frente; acima de 252, em pedaços de até 32767. */
static void pbytes(tm_buf *b, const void *p, size_t n)
{
    const uint8_t *u = p;
    if (n <= 252) {
        buf_putc(b, (int)n);
        buf_put(b, u, n);
        return;
    }
    buf_putc(b, 254);
    while (n) {
        size_t chunk = n < 32767 ? n : 32767;
        pvar(b, chunk);
        buf_put(b, u, chunk);
        u += chunk;
        n -= chunk;
    }
    pvar(b, 0);
}

/* ub4 de tamanho e depois os bytes com tamanho (nada mais se vazio). */
static void pbytes2(tm_buf *b, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    pvar(b, n);
    if (n) pbytes(b, s, n);
}

static void pkeyval(tm_buf *b, const char *key, const char *value, uint32_t flags)
{
    pbytes2(b, key);
    pbytes2(b, value);
    pvar(b, flags);
}

static uint8_t next_seq(tm_dbc *c)
{
    if (++c->seq == 0) c->seq = 1;
    return c->seq;
}

/* Cabeçalho de chamada de função; cursores a fechar pegam carona na frente. */
static void function_header(tm_dbc *c, int fn)
{
    buf_reset(&c->out);
    if (c->nclose) {
        buf_putc(&c->out, MSG_PIGGYBACK);
        buf_putc(&c->out, FN_CLOSE_CURSORS);
        buf_putc(&c->out, next_seq(c));
        if (c->field_version >= FIELD_VERSION_23_1_EXT1) pvar(&c->out, 0); /* token */
        buf_putc(&c->out, 1);
        pvar(&c->out, (uint64_t)c->nclose);
        for (int i = 0; i < c->nclose; i++) pvar(&c->out, c->close_ids[i]);
        c->nclose = 0;
    }
    buf_putc(&c->out, MSG_FUNCTION);
    buf_putc(&c->out, fn);
    buf_putc(&c->out, next_seq(c));
    if (c->field_version >= FIELD_VERSION_23_1_EXT1) pvar(&c->out, 0); /* token */
}

/* ---- valores -> texto ---- */

static void utf16be_cell(tm_dbc *c, tm_result *r, const uint8_t *p, size_t n)
{
    tm_buf le;
    buf_init(&le);
    buf_reserve(&le, n);
    for (size_t i = 0; i + 1 < n; i += 2) {
        buf_putc(&le, p[i + 1]);
        buf_putc(&le, p[i]);
    }
    buf_reset(&c->text);
    tm_utf16le_to_utf8(&c->text, le.p, le.len);
    buf_free(&le);
    res_cell(r, CK_TEXT, c->text.p, c->text.len);
}

/* NUMBER: expoente em base 100 e mantissa de dígitos em base 100. */
static void number_cell(tm_result *r, const uint8_t *p, size_t n)
{
    char digits[48], out[140];
    bool positive = (p[0] & 0x80) != 0;
    if (n == 1) {
        if (positive) res_cell(r, CK_NUM, "0", 1);
        else res_cell(r, CK_NUM, "-1e126", 6);
        return;
    }
    int exp100 = (int)((positive ? p[0] : (uint8_t)~p[0]) & 0x7F) - 65;
    if (!positive && p[n - 1] == 102) n--;
    if (n > 21) n = 21;
    int nd = 0;
    for (size_t i = 1; i < n; i++) {
        int pair = positive ? p[i] - 1 : 101 - p[i];
        if (pair < 0) pair = 0;
        if (pair > 99) pair = 99;
        digits[nd++] = (char)('0' + pair / 10);
        digits[nd++] = (char)('0' + pair % 10);
    }
    int intlen = (exp100 + 1) * 2; /* quantos dígitos ficam antes da vírgula */
    int o = 0;
    if (!positive) out[o++] = '-';
    if (intlen <= 0) {
        out[o++] = '0';
        out[o++] = '.';
        for (int i = intlen; i < 0 && o < 130; i++) out[o++] = '0';
        for (int i = 0; i < nd; i++) out[o++] = digits[i];
    } else {
        int start = o;
        for (int i = 0; i < intlen && o < 130; i++) out[o++] = i < nd ? digits[i] : '0';
        /* tira zeros à esquerda da parte inteira, deixando ao menos um */
        int lead = start;
        while (lead < o - 1 && out[lead] == '0') lead++;
        if (lead > start) {
            memmove(out + start, out + lead, (size_t)(o - lead));
            o -= lead - start;
        }
        if (nd > intlen) {
            out[o++] = '.';
            for (int i = intlen; i < nd; i++) out[o++] = digits[i];
        }
    }
    if (memchr(out, '.', (size_t)o)) { /* tira zeros à direita da parte fracionária */
        while (out[o - 1] == '0') o--;
        if (out[o - 1] == '.') o--;
    }
    res_cell(r, CK_NUM, out, (size_t)o);
}

static void date_cell(tm_result *r, int type, const uint8_t *p, size_t n)
{
    char t[64];
    if (n < 7) {
        res_cell_bin(r, p, n);
        return;
    }
    int year = (p[0] - 100) * 100 + (p[1] - 100);
    int len = snprintf(t, sizeof t, "%04d-%02d-%02d %02d:%02d:%02d", year, p[2], p[3], p[4] - 1, p[5] - 1, p[6] - 1);
    if (n >= 11) {
        uint32_t nanos = ((uint32_t)p[7] << 24) | ((uint32_t)p[8] << 16) | ((uint32_t)p[9] << 8) | p[10];
        if (nanos) {
            len += snprintf(t + len, sizeof t - (size_t)len, ".%09u", nanos);
            while (t[len - 1] == '0') len--; /* .5 em vez de .500000000 */
        }
    }
    if (type == ORA_TIMESTAMP_TZ && n >= 13) {
        /* O valor vem em UTC; o deslocamento vai ao lado, sem recalcular a hora. */
        if (p[11] & 0x80) {
            len += snprintf(t + len, sizeof t - (size_t)len, " UTC (region id)");
        } else {
            int th = p[11] - 20, tmn = p[12] - 60;
            len += snprintf(t + len, sizeof t - (size_t)len, " UTC (offset %c%02d:%02d)",
                            th < 0 || tmn < 0 ? '-' : '+', th < 0 ? -th : th, tmn < 0 ? -tmn : tmn);
        }
    }
    res_cell(r, CK_TEXT, t, (size_t)len);
}

static void interval_cell(tm_result *r, int type, const uint8_t *p, size_t n)
{
    char t[64];
    int len;
    if ((type == ORA_INTERVAL_YM && n < 5) || (type == ORA_INTERVAL_DS && n < 11)) {
        res_cell_bin(r, p, n);
        return;
    }
    int64_t first = (int64_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]) -
                    0x80000000LL;
    if (type == ORA_INTERVAL_YM) {
        int months = p[4] - 60;
        bool neg = first < 0 || months < 0;
        len = snprintf(t, sizeof t, "%s%lld-%02d", neg ? "-" : "+", (long long)(first < 0 ? -first : first),
                       months < 0 ? -months : months);
    } else {
        int h = p[4] - 60, m = p[5] - 60, s = p[6] - 60;
        int64_t ns = (int64_t)(((uint32_t)p[7] << 24) | ((uint32_t)p[8] << 16) | ((uint32_t)p[9] << 8) | p[10]) -
                     0x80000000LL;
        bool neg = first < 0 || h < 0 || m < 0 || s < 0 || ns < 0;
        len = snprintf(t, sizeof t, "%s%lld %02d:%02d:%02d.%06lld", neg ? "-" : "+",
                       (long long)(first < 0 ? -first : first), h < 0 ? -h : h, m < 0 ? -m : m, s < 0 ? -s : s,
                       (long long)((ns < 0 ? -ns : ns) / 1000));
    }
    res_cell(r, CK_TEXT, t, (size_t)len);
}

/* BINARY_FLOAT/DOUBLE: IEEE em big-endian com o bit de sinal invertido (ordenável). */
static void binary_float_cell(tm_result *r, const uint8_t *p, size_t n)
{
    uint8_t b[8];
    char t[40];
    int len = 0;
    if (n != 4 && n != 8) {
        res_cell_bin(r, p, n);
        return;
    }
    memcpy(b, p, n);
    if (b[0] & 0x80) b[0] &= 0x7F;
    else
        for (size_t i = 0; i < n; i++) b[i] = (uint8_t)~b[i];
    if (n == 4) {
        uint32_t bits = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        float f;
        memcpy(&f, &bits, 4);
        for (int prec = 6; prec <= 9; prec++) {
            len = snprintf(t, sizeof t, "%.*g", prec, (double)f);
            if (strtof(t, NULL) == f) break;
        }
    } else {
        uint64_t bits = 0;
        double d;
        for (int i = 0; i < 8; i++) bits = (bits << 8) | b[i];
        memcpy(&d, &bits, 8);
        for (int prec = 15; prec <= 17; prec++) {
            len = snprintf(t, sizeof t, "%.*g", prec, d);
            if (strtod(t, NULL) == d) break;
        }
    }
    res_cell(r, CK_NUM, t, (size_t)len);
}

static void rowid_text(char *out, uint32_t rba, uint16_t part, uint32_t block, uint16_t slot)
{
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const struct { uint32_t v; int n; } parts[4] = { { rba, 6 }, { part, 3 }, { block, 6 }, { slot, 3 } };
    int o = 0;
    for (int k = 0; k < 4; k++)
        for (int i = parts[k].n - 1; i >= 0; i--) out[o++] = A[(parts[k].v >> (6 * i)) & 63];
    out[o] = 0;
}

static void emit(tm_dbc *c, tm_result *r, const ocol *col, const uint8_t *p, size_t n)
{
    switch (col->type) {
    case ORA_VARCHAR: case ORA_CHAR: case ORA_LONG:
        if (col->csfrm == 2 && c->ncharset == CHARSET_UTF16) utf16be_cell(c, r, p, n);
        else res_cell(r, CK_TEXT, p, n);
        break;
    case ORA_NUMBER: case ORA_BINARY_INTEGER:
        number_cell(r, p, n);
        break;
    case ORA_DATE: case ORA_TIMESTAMP: case ORA_TIMESTAMP_TZ: case ORA_TIMESTAMP_LTZ:
        date_cell(r, col->type, p, n);
        break;
    case ORA_INTERVAL_YM: case ORA_INTERVAL_DS:
        interval_cell(r, col->type, p, n);
        break;
    case ORA_BINARY_FLOAT: case ORA_BINARY_DOUBLE:
        binary_float_cell(r, p, n);
        break;
    case ORA_BOOLEAN: {
        bool v = n && p[n - 1] == 1;
        res_cell(r, CK_BOOL, v ? "true" : "false", v ? 4 : 5);
        break;
    }
    default:
        res_cell_bin(r, p, n);
    }
}

static const char *type_name(const ocol *col)
{
    switch (col->type) {
    case ORA_VARCHAR: return col->csfrm == 2 ? "NVARCHAR2" : "VARCHAR2";
    case ORA_CHAR: return col->csfrm == 2 ? "NCHAR" : "CHAR";
    case ORA_NUMBER: return "NUMBER";
    case ORA_BINARY_INTEGER: return "BINARY_INTEGER";
    case ORA_LONG: return "LONG";
    case ORA_ROWID: case ORA_UROWID: return "ROWID";
    case ORA_DATE: return "DATE";
    case ORA_RAW: return "RAW";
    case ORA_LONG_RAW: return "LONG RAW";
    case ORA_BINARY_FLOAT: return "BINARY_FLOAT";
    case ORA_BINARY_DOUBLE: return "BINARY_DOUBLE";
    case ORA_CLOB: return col->csfrm == 2 ? "NCLOB" : "CLOB";
    case ORA_BLOB: return "BLOB";
    case ORA_BFILE: return "BFILE";
    case ORA_JSON: return "JSON";
    case ORA_VECTOR: return "VECTOR";
    case ORA_TIMESTAMP: return "TIMESTAMP";
    case ORA_TIMESTAMP_TZ: return "TIMESTAMP WITH TIME ZONE";
    case ORA_TIMESTAMP_LTZ: return "TIMESTAMP WITH LOCAL TIME ZONE";
    case ORA_INTERVAL_YM: return "INTERVAL YEAR TO MONTH";
    case ORA_INTERVAL_DS: return "INTERVAL DAY TO SECOND";
    case ORA_BOOLEAN: return "BOOLEAN";
    case ORA_OBJECT: return "OBJECT";
    case ORA_CURSOR: return "CURSOR";
    default: return "UNKNOWN";
    }
}

static bool is_lob(int type)
{
    return type == ORA_CLOB || type == ORA_BLOB || type == ORA_JSON || type == ORA_VECTOR;
}

/* ---- mensagens do servidor ---- */

static void free_cols(tm_dbc *c)
{
    for (int i = 0; i < c->ncols; i++) buf_free(&c->cols[i].last);
    free(c->cols);
    c->cols = NULL;
    c->ncols = 0;
}

static void read_describe(tm_dbc *c, tm_result *r)
{
    skip_bytes(c);
    gub4(c); /* tamanho máximo da linha */
    uint32_t count = gub4(c);
    if (count > 4096) {
        c->bad = true;
        c->io.broken = true;
        tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "column count");
        return;
    }
    if (count) g8(c);
    free_cols(c);
    c->cols = tm_zalloc(count * sizeof *c->cols);
    c->ncols = (int)count;
    tm_rowset *rs = r ? res_begin_set(r, (int)count) : NULL;
    for (uint32_t i = 0; i < count && !c->bad; i++) {
        ocol *col = &c->cols[i];
        buf_init(&col->last);
        col->last_null = true;
        col->type = g8(c);
        g8(c);                       /* flags */
        g8(c);                       /* precisão */
        g8(c);                       /* escala */
        col->buffer_size = gub4(c);
        gub4(c);                     /* máximo de elementos */
        gvar(c, NULL);               /* cont flags */
        skip_bytes_len(c);           /* OID */
        gub2(c);                     /* versão */
        gub2(c);                     /* conjunto de caracteres */
        col->csfrm = g8(c);
        gub4(c);                     /* tamanho máximo */
        if (c->field_version >= FIELD_VERSION_12_2) gub4(c);
        g8(c);                       /* aceita nulo */
        g8(c);
        char name[256];
        snprintf(name, sizeof name, "%s", gstr_len(c));
        skip_bytes_len(c);           /* schema */
        skip_bytes_len(c);           /* nome do tipo */
        gub2(c);                     /* posição */
        gub4(c);                     /* flags uds */
        if (c->field_version >= FIELD_VERSION_23_1) {
            skip_bytes_len(c);       /* schema do domínio */
            skip_bytes_len(c);       /* nome do domínio */
        }
        if (c->field_version >= FIELD_VERSION_23_1_EXT3) {
            if (gub4(c) > 0) {       /* anotações */
                g8(c);
                uint32_t n = gub4(c);
                g8(c);
                for (uint32_t k = 0; k < n && !c->bad; k++) {
                    skip_bytes_len(c);
                    skip_bytes_len(c);
                    gub4(c);
                }
                gub4(c);
            }
        }
        if (c->field_version >= FIELD_VERSION_23_4) {
            gub4(c);                 /* dimensões do vetor */
            g8(c);
            g8(c);
        }
        if (rs) res_set_col(rs, (int)i, name, strlen(name), type_name(col));
    }
    skip_bytes_len(c); /* data atual */
    gub4(c);
    gub4(c);
    gub4(c);
    gub4(c);
    skip_bytes_len(c);
}

static void read_error_info(tm_dbc *c)
{
    gub4(c);                 /* estado do fim de chamada */
    gub2(c);                 /* sequência */
    gub4(c);                 /* linha atual */
    gub2(c);                 /* número do erro (curto) */
    gub2(c);
    gub2(c);
    c->err_cursor = gub2(c);
    gvar(c, NULL);           /* posição do erro (com sinal) */
    g8(c);
    g8(c);
    g8(c);
    g8(c);
    g8(c);
    g8(c);
    gub4(c);                 /* rowid: rba, partição, (1 byte), bloco, slot */
    gub2(c);
    g8(c);
    gub4(c);
    gub2(c);
    gub4(c);                 /* erro do SO */
    g8(c);
    g8(c);
    gub2(c);
    gub4(c);                 /* iterações com sucesso */
    skip_bytes_len(c);

    uint16_t nerr = gub2(c); /* erros em lote: não usamos, só atravessamos */
    if (nerr) {
        uint8_t first = g8(c);
        for (unsigned i = 0; i < nerr && !c->bad; i++) {
            if (first == 254) gub4(c);
            gub2(c);
        }
        if (first == 254) g8(c);
    }
    uint32_t noff = gub4(c);
    if (noff) {
        uint8_t first = g8(c);
        for (uint32_t i = 0; i < noff && i < 65536 && !c->bad; i++) {
            if (first == 254) gub4(c);
            gub4(c);
        }
        if (first == 254) g8(c);
    }
    uint16_t nmsg = gub2(c);
    if (nmsg) {
        g8(c);
        for (unsigned i = 0; i < nmsg && !c->bad; i++) {
            gub2(c);
            skip_bytes(c);
            take(c, NULL, 2);
        }
    }
    c->err_num = gub4(c);
    c->rowcount = gvar(c, NULL);
    if (c->field_version >= FIELD_VERSION_20_1) {
        gub4(c);             /* tipo do SQL */
        gub4(c);             /* soma de verificação do servidor */
    }
    c->err_msg[0] = 0;
    if (c->err_num != 0) {
        gbytes(c, &c->text, 2048);
        size_t n = c->text.len;
        while (n && (c->text.p[n - 1] == '\n' || c->text.p[n - 1] == ' ')) n--;
        snprintf(c->err_msg, sizeof c->err_msg, "%.*s", (int)n, (const char *)c->text.p);
    }
}

static void read_server_piggyback(tm_dbc *c)
{
    uint8_t op = g8(c);
    switch (op) {
    case 7: /* LTXID */
        skip_bytes_len(c);
        break;
    case 1: case 3:
        break;
    case 2:
        gub2(c);
        skip_bytes(c);
        break;
    case 5: { /* SYNC: pares chave/valor */
        gub2(c);
        g8(c);
        uint16_t n = gub2(c);
        g8(c);
        for (unsigned i = 0; i < n && !c->bad; i++) {
            if (gub2(c)) skip_bytes(c);
            if (gub2(c)) skip_bytes(c);
            gub2(c);
        }
        gub4(c);
        break;
    }
    case 9:
        gub2(c);
        g8(c);
        break;
    case 8:
        gub2(c);
        g8(c);
        gub4(c);
        gub4(c);
        g8(c);
        skip_bytes_len(c);
        break;
    case 4: {
        gub2(c);
        g8(c);
        uint16_t n = gub2(c);
        if (n) {
            g8(c);
            for (unsigned i = 0; i < n && !c->bad; i++) {
                if (gub2(c)) skip_bytes(c);
                if (gub2(c)) skip_bytes(c);
                gub2(c);
            }
        }
        gub4(c);
        gub4(c);
        gub2(c);
        break;
    }
    case 10:
        gub2(c);
        g8(c);
        gvar(c, NULL);
        gvar(c, NULL);
        gvar(c, NULL);
        break;
    default:
        c->bad = true;
        c->io.broken = true;
        tm_fail(c->err, TM_E_PROTOCOL, T(M_PROTO), "server piggyback");
    }
}

/* Parâmetros de retorno de uma execução: nada que nos interesse, só atravessa. */
static void read_exec_params(tm_dbc *c)
{
    uint16_t n = gub2(c);
    for (unsigned i = 0; i < n && !c->bad; i++) gub4(c);
    take(c, NULL, gub2(c));
    n = gub2(c);
    for (unsigned i = 0; i < n && !c->bad; i++) {
        if (gub2(c)) skip_bytes(c);
        if (gub2(c)) skip_bytes(c);
        gub2(c);
    }
    take(c, NULL, gub2(c));
}

/* Parâmetros de retorno do login: pares nome/valor em texto. */
static void read_auth_params(tm_dbc *c)
{
    static const struct { const char *key; size_t off, cap; } WANT[] = {
        { "AUTH_SESSKEY", offsetof(tm_dbc, sesskey), sizeof(((tm_dbc *)0)->sesskey) },
        { "AUTH_VFR_DATA", offsetof(tm_dbc, vfr_data), sizeof(((tm_dbc *)0)->vfr_data) },
        { "AUTH_PBKDF2_CSK_SALT", offsetof(tm_dbc, csk_salt), sizeof(((tm_dbc *)0)->csk_salt) },
        { "AUTH_SVR_RESPONSE", offsetof(tm_dbc, svr_response), sizeof(((tm_dbc *)0)->svr_response) },
    };
    uint16_t n = gub2(c);
    for (unsigned i = 0; i < n && !c->bad; i++) {
        char key[64], value[256];
        snprintf(key, sizeof key, "%s", gstr_len(c));
        snprintf(value, sizeof value, "%s", gstr_len(c));
        uint32_t flags = gub4(c);
        for (size_t k = 0; k < TM_COUNT(WANT); k++)
            if (strcmp(key, WANT[k].key) == 0) snprintf((char *)c + WANT[k].off, WANT[k].cap, "%s", value);
        if (strcmp(key, "AUTH_VFR_DATA") == 0) c->verifier_type = flags;
        else if (strcmp(key, "AUTH_PBKDF2_VGEN_COUNT") == 0) c->vgen_count = (uint32_t)strtoul(value, NULL, 10);
        else if (strcmp(key, "AUTH_PBKDF2_SDER_COUNT") == 0) c->sder_count = (uint32_t)strtoul(value, NULL, 10);
        else if (strcmp(key, "AUTH_VERSION_NO") == 0) c->version_no = (uint32_t)strtoul(value, NULL, 10);
    }
}

/* Valor de uma coluna, já no formato de busca. Devolve false se nulo; o valor fica em c->val. */
static bool read_column(tm_dbc *c, const ocol *col, char *rowid, bool *is_rowid)
{
    *is_rowid = false;
    buf_reset(&c->val);
    /* Coluna redefinida por nós chega como LONG, não mais como localizador de LOB. */
    int type = col->lob ? (col->type == ORA_BLOB ? ORA_LONG_RAW : ORA_LONG) : col->type;
    if (col->buffer_size == 0 && type != ORA_LONG && type != ORA_LONG_RAW && type != ORA_UROWID) return false;

    if (type == ORA_ROWID) {
        uint8_t n = g8(c);
        if (n == 0 || n == 255) return false;
        uint32_t rba = gub4(c);
        uint16_t part = gub2(c);
        g8(c);
        uint32_t block = gub4(c);
        uint16_t slot = gub2(c);
        rowid_text(rowid, rba, part, block, slot);
        *is_rowid = true;
        return true;
    }
    if (type == ORA_UROWID) {
        if (!gbytes(c, &c->val, 64)) return false;
        if (!gbytes(c, &c->val, c->val_cap) || c->val.len < 13) return false;
        const uint8_t *p = c->val.p;
        if (p[0] == 1) { /* rowid físico */
            rowid_text(rowid, ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4],
                       (uint16_t)((p[5] << 8) | p[6]),
                       ((uint32_t)p[7] << 24) | ((uint32_t)p[8] << 16) | ((uint32_t)p[9] << 8) | p[10],
                       (uint16_t)((p[11] << 8) | p[12]));
            *is_rowid = true;
        }
        return true;
    }
    if (type == ORA_CLOB || type == ORA_BLOB || type == ORA_BFILE || type == ORA_JSON || type == ORA_VECTOR) {
        /* Localizador de LOB (só chega aqui o que não redefinimos como LONG). */
        if (gub4(c) == 0) return false;
        if (type != ORA_BFILE) {
            gvar(c, NULL);
            gub4(c);
        }
        gbytes(c, &c->val, c->val_cap);
        return true;
    }
    if (type == ORA_OBJECT) {
        skip_bytes_len(c); /* OID do tipo */
        skip_bytes_len(c); /* OID */
        skip_bytes_len(c); /* snapshot */
        gub2(c);
        uint32_t n = gub4(c);
        gub2(c);
        if (n == 0) return false;
        gbytes(c, &c->val, c->val_cap);
        return true;
    }
    bool has = gbytes(c, &c->val, c->val_cap);
    if (type == ORA_LONG || type == ORA_LONG_RAW) {
        gsb4(c); /* indicador de nulo */
        gub4(c); /* código de retorno */
    }
    return has;
}

static void read_row(tm_dbc *c, tm_result *r)
{
    bool keep = res_row_begin(r);
    for (int i = 0; i < c->ncols && !c->bad; i++) {
        ocol *col = &c->cols[i];
        /* Bit desligado no vetor = igual à linha anterior: o servidor não reenvia. */
        bool dup = c->has_bitvec && !((c->bitvec[i / 8] >> (i % 8)) & 1);
        if (!dup) {
            char rowid[24];
            bool is_rowid;
            bool has = read_column(c, col, rowid, &is_rowid);
            if (c->bad) break;
            buf_reset(&col->last);
            col->last_null = !has;
            if (has && is_rowid) buf_puts(&col->last, rowid);
            else if (has) buf_put(&col->last, c->val.p, c->val.len);
        }
        if (!keep) continue;
        if (col->last_null) {
            res_cell(r, CK_NULL, NULL, 0);
        } else if (col->type == ORA_ROWID || (col->type == ORA_UROWID && col->last.len == 18)) {
            res_cell(r, CK_TEXT, col->last.p, col->last.len);
        } else {
            ocol view = *col;
            if (col->lob) view.type = col->type == ORA_BLOB ? ORA_LONG_RAW : ORA_LONG;
            emit(c, r, &view, col->last.p, col->last.len);
        }
    }
    c->has_bitvec = false;
}

typedef enum { RESP_PROTOCOL, RESP_DATA_TYPES, RESP_AUTH, RESP_EXEC } resp_kind;

/* Lê uma resposta inteira. Para execuções, r recebe colunas e linhas. */
static int read_response(tm_dbc *c, resp_kind kind, tm_result *r, tm_err *err)
{
    c->err = err;
    c->bad = false;
    c->restart = false;
    c->pos = c->pkt.len = 0;
    c->err_num = 0;
    c->err_cursor = 0;
    c->rowcount = 0;
    c->err_msg[0] = 0;
    c->val_cap = r ? (size_t)r->max_cell * 4 + 64 : 4096;

    for (;;) {
        uint8_t msg = g8(c);
        bool done = false;
        if (!c->bad) {
            switch (msg) {
            case MSG_PROTOCOL: {
                g8(c); /* versão do servidor */
                g8(c);
                while (!c->bad && g8(c) != 0) {} /* banner */
                g16le(c);                        /* conjunto de caracteres do banco */
                g8(c);
                take(c, NULL, (size_t)g16le(c) * 5);
                size_t fdo_len = g16be(c);
                buf_reset(&c->val);
                take_into(c, &c->val, fdo_len, 4096);
                if (c->val.len >= 7) {
                    size_t ix = 6 + (size_t)c->val.p[5] + c->val.p[6];
                    if (ix + 5 <= c->val.len) c->ncharset = (uint16_t)((c->val.p[ix + 3] << 8) | c->val.p[ix + 4]);
                }
                if (gbytes(c, &c->val, 256) && c->val.len > 7 && c->val.p[7] < c->field_version)
                    c->field_version = c->val.p[7];
                gbytes(c, &c->val, 256); /* capacidades de execução */
                done = kind == RESP_PROTOCOL;
                break;
            }
            case MSG_DATA_TYPES:
                while (!c->bad) {
                    if (g16be(c) == 0) break;
                    if (g16be(c) != 0) take(c, NULL, 4);
                }
                done = kind == RESP_DATA_TYPES;
                break;
            case MSG_ERROR:
                read_error_info(c);
                done = true;
                break;
            case MSG_STATUS:
                gub4(c);
                gub2(c);
                done = true;
                break;
            case MSG_PARAMETER:
                if (kind == RESP_AUTH) read_auth_params(c);
                else read_exec_params(c);
                break;
            case MSG_WARNING: {
                uint16_t num = gub2(c), len = gub2(c);
                gub2(c);
                if (num && len) skip_bytes(c);
                break;
            }
            case MSG_SERVER_PIGGYBACK:
                read_server_piggyback(c);
                break;
            case MSG_DESCRIBE_INFO:
                read_describe(c, r);
                break;
            case MSG_ROW_HEADER:
                g8(c);
                gub2(c);
                gub4(c);
                gub4(c);
                gub2(c);
                {
                    uint32_t n = gub4(c);
                    if (n) {
                        g8(c);
                        if (n <= sizeof c->bitvec) {
                            take(c, c->bitvec, n);
                            c->has_bitvec = true;
                        } else {
                            take(c, NULL, n);
                        }
                    }
                }
                skip_bytes_len(c);
                break;
            case MSG_BIT_VECTOR: {
                gub2(c); /* colunas enviadas */
                size_t n = ((size_t)c->ncols + 7) / 8;
                if (n <= sizeof c->bitvec) {
                    take(c, c->bitvec, n);
                    c->has_bitvec = true;
                } else {
                    take(c, NULL, n);
                }
                break;
            }
            case MSG_ROW_DATA:
                if (!r) {
                    c->bad = true;
                    c->io.broken = true;
                    tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "unexpected row");
                    break;
                }
                read_row(c, r);
                break;
            case MSG_FLUSH_OUT_BINDS:
                done = true;
                break;
            default:
                c->bad = true;
                c->io.broken = true;
                tm_fail(err, TM_E_PROTOCOL, "%s %u", "unknown Oracle message type", msg);
            }
        }
        if (c->bad) {
            if (!c->restart) return -1;
            /* Interrupção do servidor: a resposta recomeça no pacote atual. */
            c->bad = false;
            c->restart = false;
            continue;
        }
        if (done) return 0;
    }
}

/* Erro do banco (ORA-xxxxx) na última resposta? Preenche err e devolve -1. */
static int check_server_error(tm_dbc *c, tm_err *err)
{
    c->err_num_last = c->err_num;
    if (c->err_num == 0 || c->err_num == ERR_NO_DATA_FOUND) return 0;
    bool auth = c->err_num == 1017 || c->err_num == 28000 || c->err_num == 28001 || c->err_num == 1045;
    if (c->err_msg[0]) tm_fail(err, auth ? TM_E_AUTH : TM_E_SERVER, "%s", c->err_msg);
    else tm_fail(err, auth ? TM_E_AUTH : TM_E_SERVER, "ORA-%05u", c->err_num);
    return -1;
}

/* ---- conexão ---- */

static bool safe_token(const char *s)
{
    for (; s && *s; s++)
        if (*s == '(' || *s == ')' || *s == '=' || (unsigned char)*s < 0x21) return false;
    return true;
}

static int tns_connect(tm_dbc *c, const tm_conn_cfg *cfg, tm_err *err)
{
    const char *target = cfg->service ? cfg->service : cfg->sid;
    if (!target || !safe_token(target) || !safe_token(cfg->host))
        return tm_fail(err, TM_E_CONFIG, "%s", T(M_ORA_TARGET));

    tm_buf cs, b;
    buf_init(&cs);
    buf_init(&b);
    buf_printf(&cs, "(DESCRIPTION=(ADDRESS=(PROTOCOL=%s)(HOST=%s)(PORT=%d))(CONNECT_DATA=(%s=%s)"
                    "(CID=(PROGRAM=tmdb)(HOST=tmdb)(USER=tmdb))))",
               c->io.tls ? "tcps" : "tcp", cfg->host, cfg->port, cfg->service ? "SERVICE_NAME" : "SID", target);
    int rc = -1;
    for (int attempt = 0; attempt < 3; attempt++) {
        buf_reset(&b);
        buf_u16be(&b, TNS_VERSION_DESIRED);
        buf_u16be(&b, TNS_VERSION_MINIMUM);
        buf_u16be(&b, 0x0001);          /* opções de serviço */
        buf_u16be(&b, TNS_SDU);
        buf_u16be(&b, TNS_SDU);
        buf_u16be(&b, 0x4F98);          /* características do protocolo */
        buf_u16be(&b, 0);
        buf_u16be(&b, 1);
        buf_u16be(&b, (uint16_t)cs.len);
        buf_u16be(&b, 74);              /* onde começam os dados de conexão */
        buf_u32be(&b, 0);
        buf_putc(&b, 0x84);             /* sem criptografia nativa (NNE) */
        buf_putc(&b, 0x84);
        buf_fill(&b, 0, 24);
        buf_u32be(&b, TNS_SDU);
        buf_u32be(&b, TNS_SDU);
        buf_u32be(&b, 0);
        buf_u32be(&b, 0);
        bool split = cs.len > 230;      /* dados longos vão num pacote à parte */
        if (!split) buf_put(&b, cs.p, cs.len);
        if (send_packet(c, PKT_CONNECT, b.p, b.len, err)) break;
        if (split) {
            buf_reset(&b);
            buf_u16be(&b, 0);
            buf_put(&b, cs.p, cs.len);
            if (send_packet(c, PKT_DATA, b.p, b.len, err)) break;
        }
        int type = read_packet(c, err);
        if (type < 0) break;
        if (type == PKT_RESEND) continue;
        if (type == PKT_ACCEPT) {
            tm_rd rd;
            rd_init(&rd, c->pkt.p, c->pkt.len);
            uint16_t version = rd_u16be(&rd);
            rd_skip(&rd, 2 + 10);
            uint8_t flags1 = rd_u8(&rd);
            rd_skip(&rd, 9);
            uint32_t sdu = rd_u32be(&rd);
            if (rd.bad || version < TNS_VERSION_ACCEPTED) {
                tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_ORA_TOO_OLD));
                break;
            }
            if (flags1 & 0x10) {
                tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_ORA_NNE));
                break;
            }
            c->large = true;
            c->sdu = sdu >= 512 && sdu <= 2097152 ? sdu : TNS_SDU;
            rc = 0;
            break;
        }
        if (type == PKT_REFUSE) {
            const char *text = c->pkt.len > 4 ? (const char *)c->pkt.p + 4 : "";
            int n = c->pkt.len > 4 ? (int)c->pkt.len - 4 : 0;
            char msg[300];
            snprintf(msg, sizeof msg, "%.*s", n, text);
            if (strstr(msg, "ERR=12514") || strstr(msg, "ERR=12505"))
                tm_fail(err, TM_E_CONFIG, T(M_ORA_NO_SERVICE), target, cfg->host, cfg->port);
            else
                tm_fail(err, TM_E_IO, T(M_ORA_REFUSED), msg);
            break;
        }
        tm_fail(err, TM_E_UNSUPPORTED, T(M_PROTO), type == PKT_REDIRECT ? "listener redirect" : "connect reply");
        break;
    }
    buf_free(&cs);
    buf_free(&b);
    return rc;
}

static int negotiate(tm_dbc *c, tm_err *err)
{
    /* Protocolo */
    buf_reset(&c->out);
    buf_putc(&c->out, MSG_PROTOCOL);
    buf_putc(&c->out, 6);
    buf_putc(&c->out, 0);
    buf_puts(&c->out, TM_NAME);
    buf_putc(&c->out, 0);
    if (send_data(c, err) || read_response(c, RESP_PROTOCOL, NULL, err)) return -1;

    /* Tipos de dado e capacidades. São as mesmas que o cliente oficial declara: o
     * servidor molda o formato das respostas por elas, então divergir aqui muda os
     * bytes que chegam. */
    uint8_t ccaps[55] = { 0 }, rcaps[13] = { 0 };
    ccaps[0] = 6;                               /* versão do SQL */
    ccaps[4] = 8 | 2 | 32 | 64 | 0x80;          /* formas de login (O5LOGON etc.) */
    ccaps[5] = 0x08 | 0x10;
    ccaps[7] = (uint8_t)c->field_version;
    ccaps[8] = 1;
    ccaps[9] = 1;
    ccaps[15] = 0x20 | 0x01 | 0x08;             /* vetor de bits rápido, estado de fim de chamada */
    ccaps[16] = 0x10 | 0x80;
    ccaps[17] = 3;
    ccaps[18] = 7;
    ccaps[19] = 3;
    ccaps[21] = 1;
    ccaps[23] = 0x01 | 0x02 | 0x40 | 0x08 | 0x80 | 0x04; /* LOB */
    ccaps[26] = 0x04;
    ccaps[27] = 1;
    ccaps[31] = 0x10;
    ccaps[34] = 12;
    ccaps[35] = 0x20;
    ccaps[37] = 0x10 | 0x20 | 0x80 | 0x08;
    ccaps[39] = 8;
    ccaps[40] = 0x04 | 0x40;
    ccaps[42] = 0x01 | 0x04;
    ccaps[44] = 0x08 | 0x02 | 0x04 | 0x10 | 0x20;
    ccaps[45] = 0x02 | 0x20 | 0x01;
    ccaps[52] = 0x01 | 0x02;
    ccaps[54] = 0x04;
    rcaps[0] = 2;
    rcaps[6] = 0x01 | 0x04;

    static const uint16_t TYPES[][3] = {
#include "ora_types.inc"
    };
    buf_reset(&c->out);
    buf_putc(&c->out, MSG_DATA_TYPES);
    buf_u16le(&c->out, CHARSET_UTF8);
    buf_u16le(&c->out, CHARSET_UTF8);
    buf_putc(&c->out, 0x01 | 0x02);
    pbytes(&c->out, ccaps, sizeof ccaps);
    pbytes(&c->out, rcaps, sizeof rcaps);
    for (size_t i = 0; i < TM_COUNT(TYPES); i++) {
        buf_u16be(&c->out, TYPES[i][0]);
        buf_u16be(&c->out, TYPES[i][1]);
        buf_u16be(&c->out, TYPES[i][2]);
        buf_u16be(&c->out, 0);
    }
    buf_u16be(&c->out, 0);
    return send_data(c, err) || read_response(c, RESP_DATA_TYPES, NULL, err) ? -1 : 0;
}

/* ---- login O5LOGON ---- */

static int unhex(uint8_t *out, size_t cap, const char *hex)
{
    size_t n = strlen(hex) / 2;
    if (n > cap) return -1;
    for (size_t i = 0; i < n; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            int ch = (unsigned char)hex[2 * i + (size_t)k], d;
            if (ch >= '0' && ch <= '9') d = ch - '0';
            else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
            else return -1;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    return (int)n;
}

static void hex_upper(char *out, const uint8_t *p, size_t n)
{
    static const char D[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        *out++ = D[p[i] >> 4];
        *out++ = D[p[i] & 15];
    }
    *out = 0;
}

/* AES-CBC com IV zero e preenchimento "n bytes de valor n" (sempre ao menos um bloco). */
static size_t cbc_encrypt_padded(const aes_key *k, const uint8_t *in, size_t n, uint8_t *out)
{
    static const uint8_t iv[16] = { 0 };
    size_t pad = 16 - n % 16, total = n + pad;
    memcpy(out, in, n);
    memset(out + n, (int)pad, pad);
    aes_cbc_encrypt(k, iv, out, total, out);
    return total;
}

static int auth_phase_one(tm_dbc *c, const tm_conn_cfg *cfg, tm_err *err)
{
    const char *user = cfg->user ? cfg->user : "";
    function_header(c, FN_AUTH_PHASE_ONE);
    buf_putc(&c->out, 1);
    pvar(&c->out, strlen(user));
    pvar(&c->out, 0x1);              /* modo: logon */
    buf_putc(&c->out, 1);
    pvar(&c->out, 5);                /* pares chave/valor */
    buf_putc(&c->out, 1);
    buf_putc(&c->out, 1);
    pbytes(&c->out, user, strlen(user));
    pkeyval(&c->out, "AUTH_TERMINAL", "unknown", 0);
    pkeyval(&c->out, "AUTH_PROGRAM_NM", "tmdb", 0);
    pkeyval(&c->out, "AUTH_MACHINE", "tmdb", 0);
    pkeyval(&c->out, "AUTH_PID", "1", 0);
    pkeyval(&c->out, "AUTH_SID", "tmdb", 0);
    if (send_data(c, err) || read_response(c, RESP_AUTH, NULL, err)) return -1;
    return check_server_error(c, err);
}

static int auth_phase_two(tm_dbc *c, const tm_conn_cfg *cfg, tm_err *err)
{
    static const uint8_t iv[16] = { 0 };
    const char *user = cfg->user ? cfg->user : "", *pw = cfg->password ? cfg->password : "";
    bool v12 = c->verifier_type == 0x4815;
    if (!v12 && c->verifier_type != 0xB152 && c->verifier_type != 0x1B25) {
        char what[40];
        snprintf(what, sizeof what, "verifier 0x%X", c->verifier_type);
        return tm_fail(err, TM_E_AUTH, T(M_AUTH_UNSUPPORTED), what);
    }

    uint8_t vfr[40], hash[64], part_a[64], part_b[64], enc[160], session[32], pwkey[64], tmp[400];
    char sesskey_hex[200], speedy_hex[200] = "", pw_hex[800];
    int vfrlen = unhex(vfr, sizeof vfr, c->vfr_data);
    int alen = unhex(part_a, sizeof part_a, c->sesskey);
    size_t keylen = v12 ? 32 : 24, pwlen = strlen(pw);
    if (vfrlen <= 0 || (alen != 32 && alen != 48) || pwlen > 256)
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "login parameters");

    /* Chave derivada da senha, conforme o verificador que o servidor guarda. */
    if (v12) {
        uint8_t salt[80];
        tm_hash_ctx h;
        memcpy(salt, vfr, (size_t)vfrlen);
        memcpy(salt + vfrlen, "AUTH_PBKDF2_SPEEDY_KEY", 22);
        pbkdf2(&TM_SHA512, pw, pwlen, salt, (size_t)vfrlen + 22, c->vgen_count, pwkey, 64);
        hash_init(&TM_SHA512, &h);
        hash_update(&TM_SHA512, &h, pwkey, 64);
        hash_update(&TM_SHA512, &h, vfr, (size_t)vfrlen);
        hash_final(&TM_SHA512, &h, hash);
    } else {
        tm_hash_ctx h;
        hash_init(&TM_SHA1, &h);
        hash_update(&TM_SHA1, &h, pw, pwlen);
        hash_update(&TM_SHA1, &h, vfr, (size_t)vfrlen);
        hash_final(&TM_SHA1, &h, hash);
        memset(hash + 20, 0, 4);
    }

    /* Metade do servidor (decifrada) e a nossa metade (aleatória, cifrada). */
    aes_key k;
    aes_init(&k, hash, keylen);
    aes_cbc_decrypt(&k, iv, part_a, (size_t)alen, part_a);
    if (plat_random(part_b, (size_t)alen)) return tm_fail(err, TM_E_GENERIC, "random");
    cbc_encrypt_padded(&k, part_b, (size_t)alen, enc);
    hex_upper(sesskey_hex, enc, (size_t)alen);

    /* Chave de sessão a partir das duas metades. */
    if (alen == 48) {
        uint8_t mix[24], d1[16], d2[16];
        for (int i = 16; i < 40; i++) mix[i - 16] = part_a[i] ^ part_b[i];
        hash_once(&TM_MD5, mix, 16, d1);
        hash_once(&TM_MD5, mix + 16, 8, d2);
        memcpy(session, d1, 16);
        memcpy(session + 16, d2, 16); /* usa-se só o que a chave pedir (24 ou 32 bytes) */
    } else {
        uint8_t salt[40], both[64];
        char both_hex[130];
        int saltlen = unhex(salt, sizeof salt, c->csk_salt);
        if (saltlen <= 0) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "session key salt");
        memcpy(both, part_b, keylen);
        memcpy(both + keylen, part_a, keylen);
        hex_upper(both_hex, both, 2 * keylen);
        pbkdf2(&TM_SHA512, both_hex, strlen(both_hex), salt, (size_t)saltlen, c->sder_count, session, keylen);
    }
    aes_init(&k, session, keylen);

    uint8_t rnd[16];
    if (plat_random(rnd, 16)) return tm_fail(err, TM_E_GENERIC, "random");
    if (v12) { /* "chave rápida": deixa o servidor pular o PBKDF2 nas próximas conexões */
        memcpy(tmp, rnd, 16);
        memcpy(tmp + 16, pwkey, 64);
        cbc_encrypt_padded(&k, tmp, 80, enc);
        hex_upper(speedy_hex, enc, 80);
        if (plat_random(rnd, 16)) return tm_fail(err, TM_E_GENERIC, "random");
    }
    memcpy(tmp, rnd, 16);
    memcpy(tmp + 16, pw, pwlen);
    uint8_t pwenc[400];
    size_t pwenc_len = cbc_encrypt_padded(&k, tmp, 16 + pwlen, pwenc);
    hex_upper(pw_hex, pwenc, pwenc_len);
    tm_wipe(tmp, sizeof tmp);
    tm_wipe(pwkey, sizeof pwkey);
    tm_wipe(hash, sizeof hash);

    /* Fuso da sessão igual ao desta máquina, como fazem os clientes da Oracle. */
    char alter[80];
    time_t now = time(NULL);
    struct tm g = *gmtime(&now), l = *localtime(&now);
    g.tm_isdst = l.tm_isdst;
    long off = (long)difftime(mktime(&l), mktime(&g)) / 60;
    snprintf(alter, sizeof alter, "ALTER SESSION SET TIME_ZONE='%c%02ld:%02ld'", off < 0 ? '-' : '+',
             (off < 0 ? -off : off) / 60, (off < 0 ? -off : off) % 60);

    function_header(c, FN_AUTH_PHASE_TWO);
    buf_putc(&c->out, 1);
    pvar(&c->out, strlen(user));
    pvar(&c->out, 0x1 | 0x100);      /* logon com senha */
    buf_putc(&c->out, 1);
    pvar(&c->out, v12 ? 7 : 6);
    buf_putc(&c->out, 1);
    buf_putc(&c->out, 1);
    pbytes(&c->out, user, strlen(user));
    pkeyval(&c->out, "AUTH_SESSKEY", sesskey_hex, 1);
    if (v12) pkeyval(&c->out, "AUTH_PBKDF2_SPEEDY_KEY", speedy_hex, 0);
    pkeyval(&c->out, "AUTH_PASSWORD", pw_hex, 0);
    pkeyval(&c->out, "SESSION_CLIENT_CHARSET", "873", 0);
    pkeyval(&c->out, "SESSION_CLIENT_DRIVER_NAME", TM_NAME " : " TM_VERSION, 0);
    pkeyval(&c->out, "SESSION_CLIENT_VERSION", "318767104", 0);
    /* O servidor espera o NUL final neste valor. */
    {
        size_t n = strlen(alter) + 1;
        pbytes2(&c->out, "AUTH_ALTER_SESSION");
        pvar(&c->out, n);
        pbytes(&c->out, alter, n);
        pvar(&c->out, 1);
    }
    tm_wipe(pw_hex, sizeof pw_hex);
    c->svr_response[0] = 0;
    if (send_data(c, err) || read_response(c, RESP_AUTH, NULL, err)) return -1;
    if (check_server_error(c, err)) return -1;

    /* O servidor prova que também tem a chave: sem isso seria um impostor. */
    uint8_t resp[100];
    int rlen = unhex(resp, sizeof resp, c->svr_response);
    if (rlen < 32 || rlen % 16) return tm_fail(err, TM_E_AUTH, "%s", T(M_AUTH_SERVER_SIG));
    aes_cbc_decrypt(&k, iv, resp, (size_t)rlen, resp);
    if (memcmp(resp + 16, "SERVER_TO_CLIENT", 16) != 0) return tm_fail(err, TM_E_AUTH, "%s", T(M_AUTH_SERVER_SIG));
    tm_wipe(session, sizeof session);
    return 0;
}

/* ---- execução ---- */

typedef enum { ST_QUERY, ST_PLSQL, ST_OTHER } stmt_kind;

static stmt_kind classify(const char *sql)
{
    const char *p = sql;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == '(') p++;
        if (p[0] == '-' && p[1] == '-') {
            while (*p && *p != '\n') p++;
        } else if (p[0] == '/' && p[1] == '*') {
            const char *e = strstr(p + 2, "*/");
            p = e ? e + 2 : p + strlen(p);
        } else {
            break;
        }
    }
    if (tm_strnicmp(p, "SELECT", 6) == 0 || tm_strnicmp(p, "WITH", 4) == 0) return ST_QUERY;
    if (tm_strnicmp(p, "BEGIN", 5) == 0 || tm_strnicmp(p, "DECLARE", 7) == 0 || tm_strnicmp(p, "CALL", 4) == 0)
        return ST_PLSQL;
    return ST_OTHER;
}

/* Mensagem de execução (OALL8). `sql` NULL = só definir colunas num cursor já aberto. */
static void put_execute(tm_dbc *c, const char *sql, size_t sqllen, uint32_t options, uint32_t cursor, bool is_query,
                        uint32_t exec_count, int ndefines)
{
    tm_buf *b = &c->out;
    function_header(c, FN_EXECUTE);
    pvar(b, options);
    pvar(b, cursor);
    if (sql) {
        buf_putc(b, 1);
        pvar(b, sqllen);
    } else {
        buf_putc(b, 0);
        pvar(b, 0);
    }
    buf_putc(b, 1);            /* vetor al8i4 */
    pvar(b, 13);
    buf_putc(b, 0);
    buf_putc(b, 0);
    pvar(b, 0);                /* tamanho do buffer de pré-busca */
    pvar(b, ndefines ? FETCH_ROWS : 0); /* linhas de pré-busca */
    pvar(b, MAX_LONG);
    buf_putc(b, 0);            /* binds */
    pvar(b, 0);
    buf_putc(b, 0);
    buf_putc(b, 0);
    buf_putc(b, 0);
    buf_putc(b, 0);
    buf_putc(b, 0);
    if (ndefines) {
        buf_putc(b, 1);
        pvar(b, (uint64_t)ndefines);
    } else {
        buf_putc(b, 0);
        pvar(b, 0);
    }
    pvar(b, 0);                /* id de registro (baixo) */
    buf_putc(b, 0);
    buf_putc(b, 1);
    buf_putc(b, 0);
    pvar(b, 0);
    buf_putc(b, 0);
    pvar(b, 0);
    pvar(b, 0);                /* id de registro (alto) */
    buf_putc(b, 0);
    pvar(b, 0);
    buf_putc(b, 0);
    if (c->field_version >= FIELD_VERSION_12_2) {
        buf_putc(b, 0);
        pvar(b, 0);
        buf_putc(b, 0);
        pvar(b, 0);
        buf_putc(b, 0);
        if (c->field_version >= FIELD_VERSION_12_2_EXT1) {
            buf_putc(b, 0);
            pvar(b, 0);
        }
    }
    if (sql) {
        pbytes(b, sql, sqllen);
        pvar(b, 1);            /* al8i4[0]: analisar */
    } else {
        pvar(b, 0);
    }
    pvar(b, exec_count);       /* al8i4[1] */
    pvar(b, 0);
    pvar(b, 0);
    pvar(b, 0);
    pvar(b, 0);
    pvar(b, 0);
    pvar(b, is_query ? 1 : 0); /* al8i4[7] */
    pvar(b, 0);
    pvar(b, 0);                /* al8i4[9]: flags de execução */
    pvar(b, 0);
    pvar(b, 0);
    pvar(b, 0);
}

/* Redefine colunas LOB/JSON para virem inteiras, como texto ou binário longo. */
static int define_lobs(tm_dbc *c, uint32_t cursor, tm_result *r, tm_err *err)
{
    put_execute(c, NULL, 0, OPT_DEFINE | OPT_FETCH | OPT_NOT_PLSQL, cursor, true, FETCH_ROWS, c->ncols);
    for (int i = 0; i < c->ncols; i++) {
        ocol *col = &c->cols[i];
        int type = col->type;
        uint32_t size = col->buffer_size;
        int csfrm = col->csfrm;
        if (is_lob(type)) {
            col->lob = true;
            type = col->type == ORA_BLOB ? ORA_LONG_RAW : ORA_LONG;
            size = MAX_LONG;
            if (type == ORA_LONG && !csfrm) csfrm = 1;
        }
        buf_putc(&c->out, type);
        buf_putc(&c->out, 1);  /* usa indicadores */
        buf_putc(&c->out, 0);
        buf_putc(&c->out, 0);
        pvar(&c->out, size);
        pvar(&c->out, 0);
        pvar(&c->out, 0);      /* cont flags */
        pvar(&c->out, 0);      /* OID */
        pvar(&c->out, 0);      /* versão */
        pvar(&c->out, csfrm ? CHARSET_UTF8 : 0);
        buf_putc(&c->out, csfrm);
        pvar(&c->out, 0);
        if (c->field_version >= FIELD_VERSION_12_2) pvar(&c->out, 0);
    }
    /* A definição viaja junto com a primeira busca: as linhas já vêm nesta resposta. */
    return send_data(c, err) || read_response(c, RESP_EXEC, r, err) ? -1 : check_server_error(c, err);
}

static void close_later(tm_dbc *c, uint32_t cursor)
{
    if (cursor && c->nclose < (int)TM_COUNT(c->close_ids)) c->close_ids[c->nclose++] = cursor;
}

/* Executa uma instrução e, se for consulta, busca as linhas. */
static int run(tm_dbc *c, const char *sql, bool commit, tm_result *r, tm_err *err)
{
    stmt_kind kind = classify(sql);
    size_t len = strlen(sql);
    if (kind != ST_PLSQL) { /* o Oracle recusa ';' no fim de SQL comum */
        while (len && (sql[len - 1] == ';' || sql[len - 1] == ' ' || sql[len - 1] == '\n' ||
                       sql[len - 1] == '\r' || sql[len - 1] == '\t'))
            len--;
    }
    uint32_t options = OPT_PARSE | OPT_EXECUTE;
    if (kind != ST_PLSQL) options |= OPT_NOT_PLSQL;
    if (commit && kind != ST_QUERY) options |= OPT_COMMIT;

    put_execute(c, sql, len, options, 0, kind == ST_QUERY, kind == ST_QUERY ? 0 : 1, 0);
    if (send_data(c, err) || read_response(c, RESP_EXEC, r, err)) return -1;
    uint32_t cursor = c->err_cursor;
    if (check_server_error(c, err)) {
        close_later(c, cursor);
        return -1;
    }
    if (kind != ST_QUERY) {
        close_later(c, cursor);
        res_command(r, kind == ST_PLSQL ? -1 : (long long)c->rowcount, NULL);
        return 0;
    }

    bool lobs = false;
    for (int i = 0; i < c->ncols; i++) lobs = lobs || is_lob(c->cols[i].type);
    if (lobs && define_lobs(c, cursor, r, err)) {
        close_later(c, cursor);
        return -1;
    }

    int rc = 0;
    bool finished = lobs && (c->err_num == ERR_NO_DATA_FOUND || r->truncated);
    while (!finished) {
        function_header(c, FN_FETCH);
        pvar(&c->out, cursor);
        pvar(&c->out, FETCH_ROWS);
        if (send_data(c, err) || read_response(c, RESP_EXEC, r, err)) {
            rc = -1;
            break;
        }
        if (c->err_num == ERR_NO_DATA_FOUND) break;
        if (check_server_error(c, err)) {
            rc = -1;
            break;
        }
        if (r->truncated) break; /* já temos o que cabe: não busca o resto */
    }
    close_later(c, cursor);
    if (rc == 0) res_command(r, -1, NULL);
    return rc;
}

static int simple_function(tm_dbc *c, int fn, tm_err *err)
{
    function_header(c, fn);
    if (send_data(c, err) || read_response(c, RESP_EXEC, NULL, err)) return -1;
    return check_server_error(c, err);
}

static int ora_query(tm_dbc *c, const char *sql, const tm_qopts *o, tm_result *r, tm_err *err)
{
    io_set_timeout(&c->io, o->timeout_ms);
    if (!o->read_only) return run(c, sql, true, r, err);

    tm_result scratch;
    tm_err ignore;
    res_init(&scratch, 1, 64);
    int rc = run(c, "SET TRANSACTION READ ONLY", false, &scratch, err);
    res_free(&scratch);
    if (rc) return -1;
    rc = run(c, sql, false, r, err);
    uint32_t failed_with = rc ? c->err_num_last : 0; /* anotado antes do ROLLBACK, que zera o estado */
    if (!c->io.broken) simple_function(c, FN_ROLLBACK, &ignore);
    if (failed_with == 1466 && !c->io.broken) {
        /* ORA-01466: a transação somente leitura enxerga o banco num instante fixo
         * e recusa tabelas alteradas há pouco. Repete fora dela; a guarda léxica já
         * passou e o ROLLBACK ao final desfaz qualquer efeito. */
        res_reset(r);
        rc = run(c, sql, false, r, err);
        if (!c->io.broken) simple_function(c, FN_ROLLBACK, &ignore);
    }
    return rc;
}

static void ora_close(tm_dbc *c)
{
    if (!c) return;
    if (!c->io.broken) {
        tm_err ignore;
        io_set_timeout(&c->io, 1000);
        simple_function(c, FN_LOGOFF, &ignore);
    }
    io_close(&c->io);
    free_cols(c);
    buf_free(&c->out);
    buf_free(&c->pkt);
    buf_free(&c->val);
    buf_free(&c->text);
    tm_wipe(c->sesskey, sizeof c->sesskey);
    free(c);
}

static int ora_connect(const tm_conn_cfg *cfg, tm_dbc **out, tm_err *err)
{
    tm_dbc *c = tm_zalloc(sizeof *c);
    buf_init(&c->out);
    buf_init(&c->pkt);
    buf_init(&c->val);
    buf_init(&c->text);
    c->sdu = TNS_SDU;
    c->field_version = FIELD_VERSION_OURS;
    if (io_connect(&c->io, cfg->host, cfg->port, cfg->connect_timeout_ms, err)) {
        free(c);
        return -1;
    }
    io_set_timeout(&c->io, cfg->connect_timeout_ms);
    /* TCPS: no Oracle o TLS tem porta própria e começa antes de qualquer byte do TNS,
     * então só se usa quando pedido explicitamente ("require" em diante). */
    if (cfg->ssl >= SSL_REQUIRE) {
        tls_opts o;
        tls_opts_from_cfg(&o, cfg);
        if (tls_start(&c->io, &o, err)) {
            ora_close(c);
            return -1;
        }
    }
    if (tns_connect(c, cfg, err) || negotiate(c, err) || auth_phase_one(c, cfg, err) ||
        auth_phase_two(c, cfg, err)) {
        c->io.broken = true; /* nada de logoff numa sessão que não chegou a existir */
        ora_close(c);
        return -1;
    }
    uint32_t v = c->version_no;
    snprintf(c->version, sizeof c->version, "Oracle Database %u.%u.%u.%u.%u", (v >> 24) & 0xFF, (v >> 16) & 0xFF,
             (v >> 12) & 0x0F, (v >> 4) & 0xFF, v & 0x0F);

    if (cfg->schema) {
        /* Schema padrão: só nomes simples ou entre aspas, nunca texto livre. */
        tm_buf sql;
        tm_result scratch;
        bool ok = true;
        for (const char *p = cfg->schema; *p; p++) ok = ok && *p != '"' && (unsigned char)*p >= 0x20;
        if (ok) {
            buf_init(&sql);
            res_init(&scratch, 1, 64);
            buf_printf(&sql, "ALTER SESSION SET CURRENT_SCHEMA = \"%s\"", cfg->schema);
            int rc = run(c, buf_cstr(&sql), false, &scratch, err);
            buf_free(&sql);
            res_free(&scratch);
            if (rc) {
                ora_close(c);
                return -1;
            }
        }
    }
    *out = c;
    return 0;
}

static bool ora_alive(tm_dbc *c)
{
    return !c->io.broken;
}

static const char *ora_version(tm_dbc *c)
{
    return c->version;
}

const tm_driver DRV_ORACLE = { FL_ORACLE, ora_connect, ora_query, ora_alive, ora_version, ora_close };
