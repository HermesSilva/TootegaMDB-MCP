/* Driver MySQL / MariaDB — protocolo cliente/servidor, implementação própria.
 * Autenticação: mysql_native_password e caching_sha2_password (com RSA-OAEP
 * quando não há TLS). Consultas pelo protocolo texto (COM_QUERY).
 * Leitura: START TRANSACTION READ ONLY + instrução + ROLLBACK, e a conexão só
 * aceita várias instruções por comando durante uma chamada de escrita. */
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "db.h"
#include "i18n.h"
#include "plat.h"
#include "tls.h"

#define MY_MAX_PACKET   (256u << 20)
#define MY_DRAIN_LIMIT  200000

enum {
    CAP_LONG_PASSWORD = 0x1,
    CAP_FOUND_ROWS = 0x2,
    CAP_LONG_FLAG = 0x4,
    CAP_CONNECT_WITH_DB = 0x8,
    CAP_PROTOCOL_41 = 0x200,
    CAP_SSL = 0x800,
    CAP_TRANSACTIONS = 0x2000,
    CAP_SECURE_CONNECTION = 0x8000,
    CAP_MULTI_RESULTS = 0x20000,
    CAP_PLUGIN_AUTH = 0x80000,
    CAP_PLUGIN_AUTH_LENENC = 0x200000
};

enum { ST_IN_TRANS = 0x1, ST_MORE_RESULTS = 0x8 };
enum { COM_QUERY = 0x03, COM_SET_OPTION = 0x1B };

struct tm_dbc {
    tm_io    io;
    tm_buf   in, out;
    uint8_t  seq;
    char     version[96];
    bool     mariadb;
    bool     multi;   /* várias instruções por comando ligadas? */
    uint16_t status;
    struct {
        uint8_t type;
        bool    binary, is_unsigned;
    } *cols;
    int ncols;
};

/* ---- pacotes: 3 bytes de tamanho + 1 de sequência ---- */

static int send_packet(tm_dbc *c, const void *p, size_t n, tm_err *err)
{
    if (n >= 0xFFFFFF) return tm_fail(err, TM_E_UNSUPPORTED, T(M_PROTO), "statement larger than 16 MB");
    uint8_t hdr[4] = { (uint8_t)n, (uint8_t)(n >> 8), (uint8_t)(n >> 16), c->seq++ };
    buf_reset(&c->out);
    buf_put(&c->out, hdr, 4);
    buf_put(&c->out, p, n);
    return io_write(&c->io, c->out.p, c->out.len, err);
}

/* Lê um pacote lógico (juntando os fragmentos de 16 MB) para c->in. */
static int read_packet(tm_dbc *c, tm_rd *rd, tm_err *err)
{
    buf_reset(&c->in);
    for (;;) {
        uint8_t hdr[4];
        if (io_read(&c->io, hdr, 4, err)) return -1;
        size_t len = hdr[0] | ((size_t)hdr[1] << 8) | ((size_t)hdr[2] << 16);
        c->seq = (uint8_t)(hdr[3] + 1);
        if (c->in.len + len > MY_MAX_PACKET) {
            c->io.broken = true;
            return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "packet too large");
        }
        buf_reserve(&c->in, len);
        if (len && io_read(&c->io, c->in.p + c->in.len, len, err)) return -1;
        c->in.len += len;
        if (len < 0xFFFFFF) break;
    }
    rd_init(rd, c->in.p, c->in.len);
    return 0;
}

/* Inteiro de tamanho variável. *null fica true para 0xFB (NULL em linha de dados). */
static uint64_t rd_lenenc(tm_rd *rd, bool *null)
{
    uint8_t b = rd_u8(rd);
    if (null) *null = false;
    if (b < 0xFB) return b;
    if (b == 0xFB) {
        if (null) *null = true;
        return 0;
    }
    if (b == 0xFC) return rd_u16le(rd);
    if (b == 0xFD) {
        uint32_t lo = rd_u16le(rd);
        return lo | ((uint32_t)rd_u8(rd) << 16);
    }
    return rd_u64le(rd);
}

static const char *rd_lenstr(tm_rd *rd, size_t *len)
{
    uint64_t n = rd_lenenc(rd, NULL);
    const uint8_t *p = n <= rd_left(rd) ? rd_bytes(rd, (size_t)n) : NULL;
    if (!p) {
        rd->bad = n != 0 || rd->bad;
        *len = 0;
        return "";
    }
    *len = (size_t)n;
    return (const char *)p;
}

static int server_error(tm_rd *rd, tm_err *err)
{
    rd_u8(rd); /* 0xFF */
    unsigned code = rd_u16le(rd);
    char state[8] = "";
    if (rd_left(rd) >= 6 && rd->p[rd->pos] == '#') {
        rd_u8(rd);
        memcpy(state, rd_bytes(rd, 5), 5);
    }
    size_t n = rd_left(rd);
    const char *msg = (const char *)rd_bytes(rd, n);
    bool auth = code == 1045 || code == 1044 || code == 1698;
    tm_fail(err, auth ? TM_E_AUTH : TM_E_SERVER, "ERROR %u: %.*s", code, (int)n, msg ? msg : "");
    if (err) snprintf(err->sqlstate, sizeof err->sqlstate, "%s", state);
    return -1;
}

/* ---- autenticação ---- */

/* SHA1(senha) XOR SHA1(desafio + SHA1(SHA1(senha))) */
static size_t scramble_native(const char *pw, const uint8_t *nonce, uint8_t *out)
{
    uint8_t h1[20], h2[20], h3[20];
    tm_hash_ctx x;
    if (!pw || !*pw) return 0;
    hash_once(&TM_SHA1, pw, strlen(pw), h1);
    hash_once(&TM_SHA1, h1, 20, h2);
    hash_init(&TM_SHA1, &x);
    hash_update(&TM_SHA1, &x, nonce, 20);
    hash_update(&TM_SHA1, &x, h2, 20);
    hash_final(&TM_SHA1, &x, h3);
    for (int i = 0; i < 20; i++) out[i] = h1[i] ^ h3[i];
    return 20;
}

/* SHA256(senha) XOR SHA256(SHA256(SHA256(senha)) + desafio) */
static size_t scramble_sha2(const char *pw, const uint8_t *nonce, uint8_t *out)
{
    uint8_t h1[32], h2[32], h3[32];
    tm_hash_ctx x;
    if (!pw || !*pw) return 0;
    hash_once(&TM_SHA256, pw, strlen(pw), h1);
    hash_once(&TM_SHA256, h1, 32, h2);
    hash_init(&TM_SHA256, &x);
    hash_update(&TM_SHA256, &x, h2, 32);
    hash_update(&TM_SHA256, &x, nonce, 20);
    hash_final(&TM_SHA256, &x, h3);
    for (int i = 0; i < 32; i++) out[i] = h1[i] ^ h3[i];
    return 32;
}

/* Resposta ao desafio para o plugin pedido. -1 se o plugin não é suportado. */
static int auth_response(const char *plugin, const char *pw, const uint8_t *nonce, uint8_t *out, tm_err *err)
{
    if (strcmp(plugin, "mysql_native_password") == 0) return (int)scramble_native(pw, nonce, out);
    if (strcmp(plugin, "caching_sha2_password") == 0) return (int)scramble_sha2(pw, nonce, out);
    return tm_fail(err, TM_E_AUTH, T(M_AUTH_UNSUPPORTED), plugin);
}

/* caching_sha2 sem TLS: pede a chave pública e manda a senha cifrada com RSA-OAEP. */
static int sha2_full_auth(tm_dbc *c, const char *pw, const uint8_t *nonce, tm_err *err)
{
    static const uint8_t request_key = 0x02;
    tm_rd rd;
    if (c->io.tls) /* canal já cifrado: a senha vai direta, terminada em NUL */
        return send_packet(c, pw, strlen(pw) + 1, err);
    if (send_packet(c, &request_key, 1, err) || read_packet(c, &rd, err)) return -1;
    if (rd_left(&rd) && rd.p[0] == 0xFF) return server_error(&rd, err);
    if (rd_u8(&rd) != 0x01) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "public key");

    rsa_pub key;
    size_t pemlen = rd_left(&rd);
    if (rsa_pub_from_pem(&key, (const char *)rd_bytes(&rd, pemlen), pemlen))
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "public key format");

    /* senha + NUL, embaralhada com o desafio, e então cifrada */
    uint8_t plain[512], cipher[BN_MAX_BYTES];
    size_t n = strlen(pw) + 1;
    if (n > sizeof plain) return tm_fail(err, TM_E_AUTH, T(M_AUTH_UNSUPPORTED), "password too long");
    for (size_t i = 0; i < n; i++) plain[i] = (uint8_t)pw[i] ^ nonce[i % 20];
    int rc = rsa_oaep_encrypt(&key, &TM_SHA1, plain, n, cipher);
    tm_wipe(plain, sizeof plain);
    if (rc) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "RSA encryption");
    return send_packet(c, cipher, key.nlen, err);
}

static int handshake(tm_dbc *c, const tm_conn_cfg *cfg, bool use_tls, tm_err *err)
{
    tm_rd rd;
    if (read_packet(c, &rd, err)) return -1;
    if (rd_left(&rd) && rd.p[0] == 0xFF) return server_error(&rd, err);

    uint8_t nonce[20];
    char plugin[64] = "mysql_native_password";
    if (rd_u8(&rd) != 10) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "handshake version");
    const char *ver = rd_cstr(&rd, NULL);
    const char *maria = strstr(ver, "MariaDB");
    c->mariadb = maria != NULL;
    if (maria && strncmp(ver, "5.5.5-", 6) == 0) ver += 6; /* prefixo de compatibilidade */
    snprintf(c->version, sizeof c->version, "%s %s", maria ? "MariaDB" : "MySQL", ver);
    char *dash = strchr(c->version + 8, '-');
    if (dash) *dash = 0;

    rd_u32le(&rd); /* id da conexão */
    const uint8_t *p1 = rd_bytes(&rd, 8);
    rd_u8(&rd);
    uint32_t caps = rd_u16le(&rd);
    rd_u8(&rd);    /* charset do servidor */
    rd_u16le(&rd); /* status */
    caps |= (uint32_t)rd_u16le(&rd) << 16;
    uint8_t authlen = rd_u8(&rd);
    rd_skip(&rd, 10);
    size_t p2len = authlen > 8 ? (size_t)authlen - 8 : 13;
    if (p2len < 13) p2len = 13;
    const uint8_t *p2 = rd_bytes(&rd, p2len);
    if (!p1 || !p2 || !(caps & CAP_PROTOCOL_41) || !(caps & CAP_SECURE_CONNECTION))
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "handshake");
    memcpy(nonce, p1, 8);
    memcpy(nonce + 8, p2, 12);
    if ((caps & CAP_PLUGIN_AUTH) && rd_left(&rd)) snprintf(plugin, sizeof plugin, "%s", rd_cstr(&rd, NULL));

    const char *pw = cfg->password ? cfg->password : "";
    uint8_t resp[64];
    int rlen = auth_response(plugin, pw, nonce, resp, err);
    if (rlen < 0) return -1;

    uint32_t flags = CAP_LONG_PASSWORD | CAP_LONG_FLAG | CAP_PROTOCOL_41 | CAP_TRANSACTIONS | CAP_SECURE_CONNECTION |
                     CAP_MULTI_RESULTS | CAP_PLUGIN_AUTH | CAP_PLUGIN_AUTH_LENENC;
    if (cfg->database) flags |= CAP_CONNECT_WITH_DB;

    if (use_tls && !(caps & CAP_SSL) && cfg->ssl >= SSL_REQUIRE)
        return tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_REFUSED));
    if (use_tls && (caps & CAP_SSL)) {
        /* Pedido de TLS: só o começo da resposta, em claro; o resto vai cifrado. */
        uint8_t req[32] = { 0 };
        tls_opts o;
        flags |= CAP_SSL;
        req[0] = (uint8_t)flags;
        req[1] = (uint8_t)(flags >> 8);
        req[2] = (uint8_t)(flags >> 16);
        req[3] = (uint8_t)(flags >> 24);
        req[7] = 0x01; /* tamanho máximo de pacote: 0x01000000 */
        req[8] = 45;
        tls_opts_from_cfg(&o, cfg);
        if (send_packet(c, req, sizeof req, err) || tls_start(&c->io, &o, err)) return -1;
    }

    tm_buf b;
    buf_init(&b);
    buf_u32le(&b, flags);
    buf_u32le(&b, 0x01000000); /* tamanho máximo de pacote */
    buf_putc(&b, 45);          /* utf8mb4_general_ci: existe em MySQL e MariaDB */
    buf_fill(&b, 0, 23);
    buf_puts(&b, cfg->user ? cfg->user : "");
    buf_putc(&b, 0);
    buf_putc(&b, rlen);
    buf_put(&b, resp, (size_t)rlen);
    if (cfg->database) {
        buf_puts(&b, cfg->database);
        buf_putc(&b, 0);
    }
    buf_puts(&b, plugin);
    buf_putc(&b, 0);
    int rc = send_packet(c, b.p, b.len, err);
    buf_free(&b);
    if (rc) return -1;

    for (;;) {
        if (read_packet(c, &rd, err)) return -1;
        if (!rd_left(&rd)) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "empty auth packet");
        uint8_t head = rd.p[0];
        if (head == 0x00) return 0; /* OK */
        if (head == 0xFF) return server_error(&rd, err);
        if (head == 0xFE) {
            /* O servidor pede outro plugin: novo desafio, nova resposta. */
            rd_u8(&rd);
            snprintf(plugin, sizeof plugin, "%s", rd_cstr(&rd, NULL));
            const uint8_t *fresh = rd_bytes(&rd, 20);
            if (!fresh) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "auth switch");
            memcpy(nonce, fresh, 20);
            rlen = auth_response(plugin, pw, nonce, resp, err);
            if (rlen < 0 || send_packet(c, resp, (size_t)rlen, err)) return -1;
            continue;
        }
        if (head == 0x01) {
            rd_u8(&rd);
            uint8_t step = rd_u8(&rd);
            if (step == 0x03) continue; /* senha em cache no servidor: vem o OK */
            if (step == 0x04) {
                if (sha2_full_auth(c, pw, nonce, err)) return -1;
                continue;
            }
        }
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "auth step");
    }
}

/* ---- consulta ---- */

static const char *type_name(uint8_t t, bool binary)
{
    switch (t) {
    case 0: case 246: return "decimal";
    case 1: return "tinyint";
    case 2: return "smallint";
    case 3: return "int";
    case 4: return "float";
    case 5: return "double";
    case 6: return "null";
    case 7: return "timestamp";
    case 8: return "bigint";
    case 9: return "mediumint";
    case 10: return "date";
    case 11: return "time";
    case 12: return "datetime";
    case 13: return "year";
    case 16: return "bit";
    case 245: return "json";
    case 247: return "enum";
    case 248: return "set";
    case 249: case 250: case 251: case 252: return binary ? "blob" : "text";
    case 15: case 253: return binary ? "varbinary" : "varchar";
    case 254: return binary ? "binary" : "char";
    case 255: return "geometry";
    default: return "unknown";
    }
}

static bool type_numeric(uint8_t t)
{
    return t == 0 || t == 246 || (t >= 1 && t <= 5) || t == 8 || t == 9 || t == 13;
}

static int column_defs(tm_dbc *c, int n, tm_result *r, tm_err *err)
{
    tm_rowset *rs = res_begin_set(r, n);
    free(c->cols);
    c->cols = tm_zalloc((size_t)n * sizeof *c->cols);
    c->ncols = n;
    for (int i = 0; i < n; i++) {
        tm_rd rd;
        size_t len, nlen;
        if (read_packet(c, &rd, err)) return -1;
        rd_lenstr(&rd, &len); /* catálogo */
        rd_lenstr(&rd, &len); /* schema */
        rd_lenstr(&rd, &len); /* tabela */
        rd_lenstr(&rd, &len); /* tabela original */
        const char *name = rd_lenstr(&rd, &nlen);
        rd_lenstr(&rd, &len); /* nome original */
        rd_lenenc(&rd, NULL); /* tamanho dos campos fixos */
        uint16_t charset = rd_u16le(&rd);
        rd_u32le(&rd);
        uint8_t type = rd_u8(&rd);
        uint16_t flags = rd_u16le(&rd);
        if (rd.bad) return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "column definition");
        c->cols[i].type = type;
        c->cols[i].binary = charset == 63 && (type == 15 || type >= 249);
        c->cols[i].is_unsigned = (flags & 0x20) != 0;
        char tname[40];
        snprintf(tname, sizeof tname, "%s%s", type_name(type, c->cols[i].binary),
                 c->cols[i].is_unsigned && type_numeric(type) ? " unsigned" : "");
        res_set_col(rs, i, name, nlen, tname);
    }
    return 0;
}

static void data_row(tm_dbc *c, tm_rd *rd, tm_result *r)
{
    if (!res_row_begin(r)) return;
    for (int i = 0; i < c->ncols && !rd->bad; i++) {
        bool null;
        uint64_t n = rd_lenenc(rd, &null);
        if (null) {
            res_cell(r, CK_NULL, NULL, 0);
            continue;
        }
        const uint8_t *p = n <= rd_left(rd) ? rd_bytes(rd, (size_t)n) : NULL;
        if (!p && n) {
            rd->bad = true;
            break;
        }
        uint8_t t = c->cols[i].type;
        if (t == 16) { /* BIT: bytes em big-endian -> número */
            uint64_t v = 0;
            char txt[24];
            for (size_t k = 0; k < n && k < 8; k++) v = (v << 8) | p[k];
            int len = snprintf(txt, sizeof txt, "%llu", (unsigned long long)v);
            res_cell(r, CK_NUM, txt, (size_t)len);
        } else if (c->cols[i].binary || t == 255) {
            res_cell_bin(r, p, (size_t)n);
        } else {
            res_cell(r, type_numeric(t) ? CK_NUM : CK_TEXT, p, (size_t)n);
        }
    }
}

/* Lê a resposta completa de um comando (todos os conjuntos de resultado).
 * `keep` = guardar o resultado em r; senão só consome. */
static int read_response(tm_dbc *c, bool keep, tm_result *r, tm_err *err)
{
    tm_result scratch;
    tm_err first;
    bool failed = false, more = true;
    int rc = -1;
    res_init(&scratch, 1, 16);
    if (!keep) r = &scratch;
    tm_err_clear(&first);

    while (more) {
        tm_rd rd;
        if (read_packet(c, &rd, err)) goto out;
        if (!rd_left(&rd)) {
            tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "empty packet");
            goto out;
        }
        uint8_t head = rd.p[0];
        more = false;
        if (head == 0xFF) {
            server_error(&rd, &first);
            failed = true;
        } else if (head == 0x00) { /* OK: comando sem linhas */
            rd_u8(&rd);
            uint64_t affected = rd_lenenc(&rd, NULL);
            rd_lenenc(&rd, NULL); /* último id inserido */
            c->status = rd_u16le(&rd);
            res_command(r, (long long)affected, NULL);
            more = (c->status & ST_MORE_RESULTS) != 0;
        } else if (head == 0xFB) {
            /* LOAD DATA LOCAL: o servidor pede um arquivo nosso. Nunca mandamos. */
            if (send_packet(c, "", 0, err)) goto out;
            more = true;
        } else {
            uint64_t ncols = rd_lenenc(&rd, NULL);
            if (ncols == 0 || ncols > 4096) {
                tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "column count");
                c->io.broken = true;
                goto out;
            }
            if (column_defs(c, (int)ncols, r, err)) goto out;
            if (read_packet(c, &rd, err)) goto out; /* EOF após as colunas */
            for (;;) {
                if (read_packet(c, &rd, err)) goto out;
                uint8_t h = rd_left(&rd) ? rd.p[0] : 0;
                if (h == 0xFE && rd.len < 9) { /* EOF: fim das linhas */
                    rd_u8(&rd);
                    rd_u16le(&rd);
                    c->status = rd_u16le(&rd);
                    more = (c->status & ST_MORE_RESULTS) != 0;
                    res_command(r, -1, NULL);
                    break;
                }
                if (h == 0xFF) {
                    server_error(&rd, &first);
                    failed = true;
                    break;
                }
                data_row(c, &rd, r);
                if (r->skipped_rows > MY_DRAIN_LIMIT) {
                    io_close(&c->io);
                    res_notice(r, T(M_RESULT_TOO_BIG));
                    rc = 0;
                    goto out;
                }
            }
        }
    }
    if (failed) *err = first;
    rc = failed ? -1 : 0;
out:
    res_free(&scratch);
    return rc;
}

static int send_query(tm_dbc *c, const char *sql, tm_err *err)
{
    tm_buf b;
    buf_init(&b);
    buf_putc(&b, COM_QUERY);
    buf_puts(&b, sql);
    c->seq = 0;
    int rc = send_packet(c, b.p, b.len, err);
    buf_free(&b);
    return rc;
}

static int simple(tm_dbc *c, const char *sql, tm_err *err)
{
    return send_query(c, sql, err) ? -1 : read_response(c, false, NULL, err);
}

/* Liga/desliga várias instruções por comando. Só fica ligado durante uma escrita. */
static int set_multi(tm_dbc *c, bool on, tm_err *err)
{
    if (c->multi == on) return 0;
    uint8_t pkt[3] = { COM_SET_OPTION, on ? 0 : 1, 0 };
    tm_rd rd;
    c->seq = 0;
    if (send_packet(c, pkt, sizeof pkt, err) || read_packet(c, &rd, err)) return -1;
    if (rd_left(&rd) && rd.p[0] == 0xFF) return server_error(&rd, err);
    c->multi = on;
    return 0;
}

static int my_query(tm_dbc *c, const char *sql, const tm_qopts *o, tm_result *r, tm_err *err)
{
    io_set_timeout(&c->io, o->timeout_ms);
    if (set_multi(c, !o->read_only, err)) return -1;

    if (!o->read_only) {
        if (send_query(c, sql, err) || read_response(c, true, r, err)) return -1;
        if ((c->status & ST_IN_TRANS) && !c->io.broken) {
            tm_err ignore;
            simple(c, "ROLLBACK", &ignore);
            res_notice(r, "open transaction was rolled back; use START TRANSACTION ... COMMIT in a single call");
        }
        return 0;
    }

    /* Os três comandos vão de uma vez; o servidor responde em ordem. */
    tm_err e1, e2, e3;
    tm_err_clear(&e1);
    tm_err_clear(&e2);
    tm_err_clear(&e3);
    if (send_query(c, "START TRANSACTION READ ONLY", err) || send_query(c, sql, err) ||
        send_query(c, "ROLLBACK", err))
        return -1;
    int r1 = read_response(c, false, NULL, &e1);
    if (c->io.broken) { *err = e1; return -1; }
    int r2 = read_response(c, true, r, &e2);
    if (c->io.broken && r2) { *err = e2; return -1; }
    int r3 = c->io.broken ? 0 : read_response(c, false, NULL, &e3);
    if (r1) { *err = e1; return -1; }
    if (r2) { *err = e2; return -1; }
    if (r3) { *err = e3; return -1; }
    return 0;
}

static void my_close(tm_dbc *c)
{
    if (!c) return;
    if (!c->io.broken) {
        static const uint8_t quit = 0x01;
        tm_err ignore;
        io_set_timeout(&c->io, 500);
        c->seq = 0;
        send_packet(c, &quit, 1, &ignore);
    }
    io_close(&c->io);
    buf_free(&c->in);
    buf_free(&c->out);
    free(c->cols);
    free(c);
}

static int my_attempt(const tm_conn_cfg *cfg, bool use_tls, tm_dbc **out, tm_err *err)
{
    tm_dbc *c = tm_zalloc(sizeof *c);
    buf_init(&c->in);
    buf_init(&c->out);
    if (io_connect(&c->io, cfg->host, cfg->port, cfg->connect_timeout_ms, err)) {
        free(c);
        return -1;
    }
    io_set_timeout(&c->io, cfg->connect_timeout_ms);
    if (handshake(c, cfg, use_tls, err)) {
        my_close(c);
        return -1;
    }
    /* Teto de tempo no próprio servidor, para a consulta parar lá também. Melhor esforço. */
    char set[96];
    tm_err ignore;
    if (c->mariadb) snprintf(set, sizeof set, "SET SESSION max_statement_time=%d", cfg->query_timeout_ms / 1000);
    else snprintf(set, sizeof set, "SET SESSION MAX_EXECUTION_TIME=%d", cfg->query_timeout_ms);
    simple(c, set, &ignore);
    if (c->io.broken) {
        my_close(c);
        return tm_fail(err, TM_E_IO, "%s", T(M_IO_CLOSED));
    }
    *out = c;
    return 0;
}

static int my_connect(const tm_conn_cfg *cfg, tm_dbc **out, tm_err *err)
{
    int rc = my_attempt(cfg, cfg->ssl != SSL_DISABLE, out, err);
    if (rc && tls_prefer_fallback(cfg, err)) rc = my_attempt(cfg, false, out, err);
    return rc;
}

static bool my_alive(tm_dbc *c)
{
    return !c->io.broken;
}

static const char *my_version(tm_dbc *c)
{
    return c->version;
}

const tm_driver DRV_MYSQL = { FL_MYSQL, my_connect, my_query, my_alive, my_version, my_close };
