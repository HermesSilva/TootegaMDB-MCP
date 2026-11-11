/* Driver PostgreSQL — protocolo de rede v3, implementação própria.
 * Autenticação: trust, senha em claro, MD5 e SCRAM-SHA-256.
 * Leitura: instrução única pelo protocolo estendido, dentro de BEGIN READ ONLY ... ROLLBACK,
 * tudo enviado de uma vez (pipeline) para custar uma só ida e volta. */
#include "crypto/hash.h"
#include "db.h"
#include "i18n.h"
#include "plat.h"
#include "tls.h"

#define PG_MAX_MSG      (256u << 20)
#define PG_DRAIN_LIMIT  200000 /* linhas além do limite que aceitamos ler e descartar */

struct tm_dbc {
    tm_io     io;
    tm_buf    in, out;
    char      version[96];
    char      host[256];
    int       port;
    uint32_t  pid, key;
    char      txstatus;
    tm_ckind *kinds;
    int       nkinds;
};

/* ---- mensagens ---- */

static size_t msg_begin(tm_buf *b, char type)
{
    size_t start = b->len;
    if (type) buf_putc(b, type);
    buf_u32be(b, 0);
    return start;
}

static void msg_end(tm_buf *b, size_t start, bool typed)
{
    size_t at = start + (typed ? 1 : 0);
    uint32_t len = (uint32_t)(b->len - at);
    b->p[at] = (uint8_t)(len >> 24);
    b->p[at + 1] = (uint8_t)(len >> 16);
    b->p[at + 2] = (uint8_t)(len >> 8);
    b->p[at + 3] = (uint8_t)len;
}

static void put_cstr(tm_buf *b, const char *s)
{
    buf_puts(b, s);
    buf_putc(b, 0);
}

static int flush(tm_dbc *c, tm_err *err)
{
    int rc = io_write(&c->io, c->out.p, c->out.len, err);
    buf_reset(&c->out);
    return rc;
}

static int read_msg(tm_dbc *c, char *type, tm_rd *rd, tm_err *err)
{
    uint8_t hdr[5];
    if (io_read(&c->io, hdr, 5, err)) return -1;
    uint32_t len = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 8) | hdr[4];
    if (len < 4 || len > PG_MAX_MSG) {
        c->io.broken = true;
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "message length");
    }
    len -= 4;
    buf_reset(&c->in);
    buf_reserve(&c->in, len);
    if (len && io_read(&c->io, c->in.p, len, err)) return -1;
    c->in.len = len;
    *type = (char)hdr[0];
    rd_init(rd, c->in.p, len);
    return 0;
}

/* ErrorResponse / NoticeResponse: pares (código, texto) até um código zero. */
static void parse_fields(tm_rd *rd, tm_buf *text, char *sqlstate, size_t sscap)
{
    const char *sev = NULL, *msg = NULL, *detail = NULL, *hint = NULL;
    for (;;) {
        uint8_t code = rd_u8(rd);
        if (!code || rd->bad) break;
        const char *val = rd_cstr(rd, NULL);
        switch (code) {
        case 'S': sev = val; break;
        case 'M': msg = val; break;
        case 'D': detail = val; break;
        case 'H': hint = val; break;
        case 'C':
            if (sqlstate) snprintf(sqlstate, sscap, "%s", val);
            break;
        }
    }
    buf_printf(text, "%s: %s", sev ? sev : "ERROR", msg ? msg : "?");
    if (detail) buf_printf(text, " | %s", detail);
    if (hint) buf_printf(text, " | %s", hint);
}

static int server_error(tm_rd *rd, tm_err *err)
{
    tm_buf text;
    char state[12] = "";
    buf_init(&text);
    parse_fields(rd, &text, state, sizeof state);
    tm_fail(err, strncmp(state, "28", 2) == 0 ? TM_E_AUTH : TM_E_SERVER, "%s", buf_cstr(&text));
    if (err) snprintf(err->sqlstate, sizeof err->sqlstate, "%s", state);
    buf_free(&text);
    return -1;
}

/* ---- autenticação ---- */

static int send_password(tm_dbc *c, const char *pw, tm_err *err)
{
    size_t s = msg_begin(&c->out, 'p');
    put_cstr(&c->out, pw);
    msg_end(&c->out, s, true);
    return flush(c, err);
}

static int auth_md5(tm_dbc *c, const tm_conn_cfg *cfg, const uint8_t *salt, tm_err *err)
{
    uint8_t d[16];
    char hex1[33], out[36] = "md5";
    tm_hash_ctx h;
    hash_init(&TM_MD5, &h);
    hash_update(&TM_MD5, &h, cfg->password, strlen(cfg->password));
    hash_update(&TM_MD5, &h, cfg->user, strlen(cfg->user));
    hash_final(&TM_MD5, &h, d);
    tm_hex(hex1, d, 16);
    hash_init(&TM_MD5, &h);
    hash_update(&TM_MD5, &h, hex1, 32);
    hash_update(&TM_MD5, &h, salt, 4);
    hash_final(&TM_MD5, &h, d);
    tm_hex(out + 3, d, 16);
    return send_password(c, out, err);
}

typedef struct {
    char    client_first_bare[64];
    char    nonce[40];
    uint8_t salted[32];
    tm_buf  auth_msg;
} scram;

/* Acha "x=valor" numa lista separada por vírgulas; devolve o valor e seu tamanho. */
static const char *scram_attr(const char *s, size_t n, char key, size_t *vlen)
{
    const char *end = s + n;
    while (s < end) {
        const char *comma = memchr(s, ',', (size_t)(end - s));
        if (!comma) comma = end;
        if (comma - s >= 2 && s[0] == key && s[1] == '=') {
            *vlen = (size_t)(comma - s) - 2;
            return s + 2;
        }
        s = comma + 1;
    }
    return NULL;
}

static int scram_start(tm_dbc *c, scram *sc, tm_rd *rd, tm_err *err)
{
    bool offered = false;
    for (;;) {
        size_t n;
        const char *mech = rd_cstr(rd, &n);
        if (rd->bad || !n) break;
        if (strcmp(mech, "SCRAM-SHA-256") == 0) offered = true;
    }
    if (!offered) return tm_fail(err, TM_E_AUTH, T(M_AUTH_UNSUPPORTED), "SASL");

    uint8_t rnd[18];
    if (plat_random(rnd, sizeof rnd)) return tm_fail(err, TM_E_GENERIC, "random");
    tm_b64_enc(sc->nonce, rnd, sizeof rnd);
    snprintf(sc->client_first_bare, sizeof sc->client_first_bare, "n=,r=%s", sc->nonce);

    size_t s = msg_begin(&c->out, 'p');
    put_cstr(&c->out, "SCRAM-SHA-256");
    buf_u32be(&c->out, (uint32_t)strlen(sc->client_first_bare) + 3);
    buf_puts(&c->out, "n,,");
    buf_puts(&c->out, sc->client_first_bare);
    msg_end(&c->out, s, true);
    return flush(c, err);
}

static int scram_continue(tm_dbc *c, scram *sc, const tm_conn_cfg *cfg, tm_rd *rd, tm_err *err)
{
    size_t n = rd_left(rd), rlen, slen, ilen;
    const char *first = (const char *)rd_bytes(rd, n);
    const char *r = first ? scram_attr(first, n, 'r', &rlen) : NULL;
    const char *s = first ? scram_attr(first, n, 's', &slen) : NULL;
    const char *i = first ? scram_attr(first, n, 'i', &ilen) : NULL;
    size_t noncelen = strlen(sc->nonce);
    if (!r || !s || !i || rlen <= noncelen || strncmp(r, sc->nonce, noncelen) != 0 || ilen > 9)
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "SCRAM server-first");

    uint8_t salt[256];
    int saltlen = tm_b64_dec(salt, sizeof salt, s, slen);
    char itxt[12] = { 0 };
    memcpy(itxt, i, ilen);
    long iters = strtol(itxt, NULL, 10);
    if (saltlen <= 0 || iters < 1 || iters > 10000000)
        return tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "SCRAM parameters");

    pbkdf2(&TM_SHA256, cfg->password, strlen(cfg->password), salt, (size_t)saltlen, (uint32_t)iters,
           sc->salted, 32);

    /* AuthMessage = client-first-bare , server-first , client-final-without-proof */
    buf_puts(&sc->auth_msg, sc->client_first_bare);
    buf_putc(&sc->auth_msg, ',');
    buf_put(&sc->auth_msg, first, n);
    buf_puts(&sc->auth_msg, ",c=biws,r=");
    buf_put(&sc->auth_msg, r, rlen);

    uint8_t client_key[32], stored[32], sig[32], proof[32];
    char proof64[48];
    hmac_once(&TM_SHA256, sc->salted, 32, "Client Key", 10, client_key);
    hash_once(&TM_SHA256, client_key, 32, stored);
    hmac_once(&TM_SHA256, stored, 32, sc->auth_msg.p, sc->auth_msg.len, sig);
    for (int k = 0; k < 32; k++) proof[k] = client_key[k] ^ sig[k];
    tm_b64_enc(proof64, proof, 32);
    tm_wipe(client_key, sizeof client_key);

    size_t m = msg_begin(&c->out, 'p');
    buf_puts(&c->out, "c=biws,r=");
    buf_put(&c->out, r, rlen);
    buf_puts(&c->out, ",p=");
    buf_puts(&c->out, proof64);
    msg_end(&c->out, m, true);
    return flush(c, err);
}

/* O servidor também prova que conhece a senha: sem isso um impostor passaria. */
static int scram_finish(scram *sc, tm_rd *rd, tm_err *err)
{
    size_t n = rd_left(rd), vlen;
    const char *fin = (const char *)rd_bytes(rd, n);
    const char *v = fin ? scram_attr(fin, n, 'v', &vlen) : NULL;
    uint8_t server_key[32], expect[32], got[64];
    if (!v || tm_b64_dec(got, sizeof got, v, vlen) != 32)
        return tm_fail(err, TM_E_AUTH, "%s", T(M_AUTH_SERVER_SIG));
    hmac_once(&TM_SHA256, sc->salted, 32, "Server Key", 10, server_key);
    hmac_once(&TM_SHA256, server_key, 32, sc->auth_msg.p, sc->auth_msg.len, expect);
    if (!ct_equal(expect, got, 32)) return tm_fail(err, TM_E_AUTH, "%s", T(M_AUTH_SERVER_SIG));
    return 0;
}

static int handshake(tm_dbc *c, const tm_conn_cfg *cfg, tm_err *err)
{
    size_t s = msg_begin(&c->out, 0);
    buf_u32be(&c->out, 196608); /* protocolo 3.0 */
    put_cstr(&c->out, "user");
    put_cstr(&c->out, cfg->user ? cfg->user : "");
    if (cfg->database) {
        put_cstr(&c->out, "database");
        put_cstr(&c->out, cfg->database);
    }
    put_cstr(&c->out, "application_name");
    put_cstr(&c->out, cfg->app_name ? cfg->app_name : TM_TITLE);
    put_cstr(&c->out, "client_encoding");
    put_cstr(&c->out, "UTF8");
    put_cstr(&c->out, "DateStyle");
    put_cstr(&c->out, "ISO");
    if (cfg->schema) {
        put_cstr(&c->out, "search_path");
        put_cstr(&c->out, cfg->schema);
    }
    buf_putc(&c->out, 0);
    msg_end(&c->out, s, false);
    if (flush(c, err)) return -1;

    scram sc;
    memset(&sc, 0, sizeof sc);
    buf_init(&sc.auth_msg);
    int rc = -1;
    for (;;) {
        char type;
        tm_rd rd;
        if (read_msg(c, &type, &rd, err)) break;
        if (type == 'E') {
            server_error(&rd, err);
            break;
        }
        if (type == 'Z') {
            c->txstatus = (char)rd_u8(&rd);
            rc = 0;
            break;
        }
        if (type == 'S') {
            const char *name = rd_cstr(&rd, NULL);
            const char *val = rd_cstr(&rd, NULL);
            if (strcmp(name, "server_version") == 0)
                snprintf(c->version, sizeof c->version, "PostgreSQL %s", val);
            continue;
        }
        if (type == 'K') {
            c->pid = rd_u32be(&rd);
            c->key = rd_u32be(&rd);
            continue;
        }
        if (type != 'R') continue; /* avisos e afins */

        uint32_t kind = rd_u32be(&rd);
        if (kind == 0) continue; /* autenticado */
        if (!cfg->password) {
            tm_fail(err, TM_E_AUTH, "%s", T(M_PASSWORD_REQUIRED));
            break;
        }
        int step;
        if (kind == 3) {
            step = send_password(c, cfg->password, err);
        } else if (kind == 5) {
            const uint8_t *salt = rd_bytes(&rd, 4);
            step = salt ? auth_md5(c, cfg, salt, err) : tm_fail(err, TM_E_PROTOCOL, T(M_PROTO), "md5 salt");
        } else if (kind == 10) {
            step = scram_start(c, &sc, &rd, err);
        } else if (kind == 11) {
            step = scram_continue(c, &sc, cfg, &rd, err);
        } else if (kind == 12) {
            step = scram_finish(&sc, &rd, err);
        } else {
            char what[32];
            snprintf(what, sizeof what, "code %u", kind);
            step = tm_fail(err, TM_E_AUTH, T(M_AUTH_UNSUPPORTED), what);
        }
        if (step) break;
    }
    tm_wipe(sc.salted, sizeof sc.salted);
    buf_free(&sc.auth_msg);
    return rc;
}

static void pg_close(tm_dbc *c)
{
    if (!c) return;
    if (!c->io.broken) {
        static const uint8_t terminate[5] = { 'X', 0, 0, 0, 4 };
        tm_err ignore;
        io_set_timeout(&c->io, 500);
        io_write(&c->io, terminate, sizeof terminate, &ignore);
    }
    io_close(&c->io);
    buf_free(&c->in);
    buf_free(&c->out);
    free(c->kinds);
    free(c);
}

/* Pede TLS ao servidor (SSLRequest). O servidor responde um byte: 'S' aceita, 'N' recusa. */
static int start_tls(tm_dbc *c, const tm_conn_cfg *cfg, tm_err *err)
{
    static const uint8_t request[8] = { 0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F };
    uint8_t answer;
    if (io_write(&c->io, request, sizeof request, err) || io_read(&c->io, &answer, 1, err)) return -1;
    if (answer == 'S') {
        tls_opts o;
        tls_opts_from_cfg(&o, cfg);
        return tls_start(&c->io, &o, err);
    }
    if (cfg->ssl >= SSL_REQUIRE) return tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_REFUSED));
    return 0; /* "prefer": o servidor não oferece, segue em claro */
}

static int pg_attempt(const tm_conn_cfg *cfg, bool use_tls, tm_dbc **out, tm_err *err)
{
    tm_dbc *c = tm_zalloc(sizeof *c);
    buf_init(&c->in);
    buf_init(&c->out);
    snprintf(c->host, sizeof c->host, "%s", cfg->host);
    c->port = cfg->port;
    if (io_connect(&c->io, cfg->host, cfg->port, cfg->connect_timeout_ms, err)) {
        buf_free(&c->in);
        buf_free(&c->out);
        free(c);
        return -1;
    }
    io_set_timeout(&c->io, cfg->connect_timeout_ms);
    if ((use_tls && start_tls(c, cfg, err)) || handshake(c, cfg, err)) {
        pg_close(c);
        return -1;
    }
    *out = c;
    return 0;
}

static int pg_connect(const tm_conn_cfg *cfg, tm_dbc **out, tm_err *err)
{
    int rc = pg_attempt(cfg, cfg->ssl != SSL_DISABLE, out, err);
    /* "prefer": se o TLS não fechou (servidor só com versões antigas, por exemplo),
     * tenta de novo em claro. Erros de senha ou do banco não entram nessa regra. */
    if (rc && tls_prefer_fallback(cfg, err)) rc = pg_attempt(cfg, false, out, err);
    return rc;
}

/* ---- tipos ---- */

static const struct {
    uint32_t    oid;
    const char *name;
    tm_ckind    kind;
} PG_TYPES[] = {
    { 16, "bool", CK_BOOL },        { 17, "bytea", CK_TEXT },       { 18, "char", CK_TEXT },
    { 19, "name", CK_TEXT },        { 20, "int8", CK_NUM },         { 21, "int2", CK_NUM },
    { 23, "int4", CK_NUM },         { 25, "text", CK_TEXT },        { 26, "oid", CK_NUM },
    { 114, "json", CK_TEXT },       { 142, "xml", CK_TEXT },        { 650, "cidr", CK_TEXT },
    { 700, "float4", CK_NUM },      { 701, "float8", CK_NUM },      { 790, "money", CK_TEXT },
    { 829, "macaddr", CK_TEXT },    { 869, "inet", CK_TEXT },       { 1000, "bool[]", CK_TEXT },
    { 1005, "int2[]", CK_TEXT },    { 1007, "int4[]", CK_TEXT },    { 1009, "text[]", CK_TEXT },
    { 1015, "varchar[]", CK_TEXT }, { 1016, "int8[]", CK_TEXT },    { 1021, "float4[]", CK_TEXT },
    { 1022, "float8[]", CK_TEXT },  { 1042, "bpchar", CK_TEXT },    { 1043, "varchar", CK_TEXT },
    { 1082, "date", CK_TEXT },      { 1083, "time", CK_TEXT },      { 1114, "timestamp", CK_TEXT },
    { 1184, "timestamptz", CK_TEXT }, { 1186, "interval", CK_TEXT }, { 1231, "numeric[]", CK_TEXT },
    { 1266, "timetz", CK_TEXT },    { 1560, "bit", CK_TEXT },       { 1562, "varbit", CK_TEXT },
    { 1700, "numeric", CK_NUM },    { 2249, "record", CK_TEXT },    { 2278, "void", CK_TEXT },
    { 2950, "uuid", CK_TEXT },      { 2951, "uuid[]", CK_TEXT },    { 3614, "tsvector", CK_TEXT },
    { 3802, "jsonb", CK_TEXT },     { 3807, "jsonb[]", CK_TEXT },   { 3904, "int4range", CK_TEXT },
    { 3906, "numrange", CK_TEXT },  { 3908, "tsrange", CK_TEXT },   { 3910, "tstzrange", CK_TEXT },
    { 3912, "daterange", CK_TEXT }, { 3926, "int8range", CK_TEXT }, { 705, "unknown", CK_TEXT },
};

static void row_description(tm_dbc *c, tm_rd *rd, tm_result *r)
{
    int n = rd_u16be(rd);
    tm_rowset *rs = res_begin_set(r, n);
    free(c->kinds);
    c->kinds = tm_zalloc((size_t)n * sizeof *c->kinds);
    c->nkinds = n;
    for (int i = 0; i < n && !rd->bad; i++) {
        size_t nlen;
        const char *name = rd_cstr(rd, &nlen);
        rd_skip(rd, 6); /* tabela, coluna */
        uint32_t oid = rd_u32be(rd);
        rd_skip(rd, 8); /* tamanho, modificador, formato */
        const char *tname = NULL;
        char other[24];
        c->kinds[i] = CK_TEXT;
        for (size_t k = 0; k < TM_COUNT(PG_TYPES); k++)
            if (PG_TYPES[k].oid == oid) {
                tname = PG_TYPES[k].name;
                c->kinds[i] = PG_TYPES[k].kind;
                break;
            }
        if (!tname) {
            snprintf(other, sizeof other, "oid:%u", oid);
            tname = other;
        }
        res_set_col(rs, i, name, nlen, tname);
    }
}

static void data_row(tm_dbc *c, tm_rd *rd, tm_result *r)
{
    int n = rd_u16be(rd);
    if (!res_row_begin(r)) return;
    for (int i = 0; i < n && !rd->bad; i++) {
        uint32_t len = rd_u32be(rd);
        if (len == 0xFFFFFFFFu) {
            res_cell(r, CK_NULL, NULL, 0);
            continue;
        }
        const uint8_t *p = rd_bytes(rd, len);
        if (!p) break;
        tm_ckind kind = i < c->nkinds ? c->kinds[i] : CK_TEXT;
        if (kind == CK_BOOL) {
            bool t = len && p[0] == 't';
            res_cell(r, CK_BOOL, t ? "true" : "false", t ? 4 : 5);
        } else {
            res_cell(r, kind, p, len);
        }
    }
}

static void command_complete(tm_rd *rd, tm_result *r)
{
    const char *tag = rd_cstr(rd, NULL);
    long long affected = -1;
    const char *sp = strrchr(tag, ' ');
    if (sp && sp[1] >= '0' && sp[1] <= '9' && strncmp(tag, "SELECT", 6) != 0)
        affected = strtoll(sp + 1, NULL, 10);
    res_command(r, affected, tag);
}

/* ---- execução ---- */

/* Pedido de cancelamento: conexão à parte, sem autenticação, melhor esforço. */
static void cancel_running(tm_dbc *c)
{
    tm_io io;
    tm_err ignore;
    if (io_connect(&io, c->host, c->port, 2000, &ignore)) return;
    tm_buf b;
    buf_init(&b);
    buf_u32be(&b, 16);
    buf_u32be(&b, 80877102);
    buf_u32be(&b, c->pid);
    buf_u32be(&b, c->key);
    io_set_timeout(&io, 2000);
    io_write(&io, b.p, b.len, &ignore);
    buf_free(&b);
    io_close(&io);
}

/* Lê respostas até `ready` mensagens ReadyForQuery. Só guarda resultado enquanto
 * o número de ReadyForQuery já vistos for `capture` (-1 = sempre). O primeiro erro
 * do servidor é o que vale; a leitura segue até o fim para a conexão ficar limpa. */
static int read_results(tm_dbc *c, int ready, int capture, tm_result *r, tm_err *err)
{
    tm_err first;
    bool failed = false;
    tm_err_clear(&first);
    for (int seen = 0; seen < ready;) {
        char type;
        tm_rd rd;
        if (read_msg(c, &type, &rd, err)) {
            if (err->code == TM_E_TIMEOUT) cancel_running(c);
            return -1;
        }
        bool keep = capture < 0 || seen == capture;
        switch (type) {
        case 'T':
            if (keep) row_description(c, &rd, r);
            break;
        case 'D':
            if (keep) data_row(c, &rd, r);
            if (r->skipped_rows > PG_DRAIN_LIMIT) {
                cancel_running(c);
                io_close(&c->io);
                res_notice(r, T(M_RESULT_TOO_BIG));
                return 0;
            }
            break;
        case 'C':
            if (keep) command_complete(&rd, r);
            break;
        case 'I':
            if (keep) res_command(r, -1, NULL);
            break;
        case 's': /* portal suspenso: havia mais linhas que o limite pedido */
            if (keep) r->truncated = true;
            break;
        case 'E':
            if (!failed) {
                server_error(&rd, &first);
                failed = true;
            }
            break;
        case 'N': {
            tm_buf text;
            buf_init(&text);
            parse_fields(&rd, &text, NULL, 0);
            if (keep) res_notice(r, buf_cstr(&text));
            buf_free(&text);
            break;
        }
        case 'G': { /* COPY FROM STDIN: não há dados a mandar; recusa */
            size_t s = msg_begin(&c->out, 'f');
            put_cstr(&c->out, "COPY FROM STDIN is not supported");
            msg_end(&c->out, s, true);
            if (flush(c, err)) return -1;
            break;
        }
        case 'Z':
            c->txstatus = (char)rd_u8(&rd);
            seen++;
            break;
        default: /* 1 2 n t S A H d c ... nada a fazer */
            break;
        }
    }
    if (failed) {
        *err = first;
        return -1;
    }
    return 0;
}

static void put_query(tm_buf *b, const char *sql)
{
    size_t s = msg_begin(b, 'Q');
    put_cstr(b, sql);
    msg_end(b, s, true);
}

static int pg_query(tm_dbc *c, const char *sql, const tm_qopts *o, tm_result *r, tm_err *err)
{
    io_set_timeout(&c->io, o->timeout_ms);
    buf_reset(&c->out);

    if (!o->read_only) {
        put_query(&c->out, sql);
        if (flush(c, err) || read_results(c, 1, -1, r, err)) return -1;
        if (c->txstatus != 'I' && !c->io.broken) {
            /* Transação deixada aberta seguraria travas entre chamadas: desfaz. */
            tm_result scratch;
            tm_err ignore;
            res_init(&scratch, 1, 16);
            put_query(&c->out, "ROLLBACK");
            if (flush(c, &ignore) == 0) read_results(c, 1, -1, &scratch, &ignore);
            res_free(&scratch);
            res_notice(r, "open transaction was rolled back; use BEGIN ... COMMIT in a single call");
        }
        return 0;
    }

    size_t s;
    put_query(&c->out, "BEGIN TRANSACTION READ ONLY");

    s = msg_begin(&c->out, 'P'); /* Parse: instrução sem nome, sem tipos de parâmetro */
    buf_putc(&c->out, 0);
    put_cstr(&c->out, sql);
    buf_u16be(&c->out, 0);
    msg_end(&c->out, s, true);

    s = msg_begin(&c->out, 'B'); /* Bind: portal sem nome, tudo em texto */
    buf_putc(&c->out, 0);
    buf_putc(&c->out, 0);
    buf_u16be(&c->out, 0);
    buf_u16be(&c->out, 0);
    buf_u16be(&c->out, 0);
    msg_end(&c->out, s, true);

    s = msg_begin(&c->out, 'D'); /* Describe do portal: pede a descrição das colunas */
    buf_putc(&c->out, 'P');
    buf_putc(&c->out, 0);
    msg_end(&c->out, s, true);

    s = msg_begin(&c->out, 'E'); /* Execute com teto de linhas: o servidor para sozinho */
    buf_putc(&c->out, 0);
    buf_u32be(&c->out, (uint32_t)r->max_rows + 1);
    msg_end(&c->out, s, true);

    s = msg_begin(&c->out, 'S'); /* Sync */
    msg_end(&c->out, s, true);

    put_query(&c->out, "ROLLBACK");

    if (flush(c, err)) return -1;
    return read_results(c, 3, 1, r, err);
}

static bool pg_alive(tm_dbc *c)
{
    return !c->io.broken;
}

static const char *pg_version(tm_dbc *c)
{
    return c->version;
}

const tm_driver DRV_POSTGRES = { FL_POSTGRES, pg_connect, pg_query, pg_alive, pg_version, pg_close };
