/* TLS 1.3 (RFC 8446), cliente.
 *
 * Só TLS 1.3: troca de chaves X25519; cifras AES-128-GCM, AES-256-GCM e
 * ChaCha20-Poly1305; autenticação do servidor por certificado (RSA-PSS ou ECDSA).
 * Sem retomada de sessão, sem 0-RTT, sem certificado de cliente — nada disso é
 * necessário para falar com um banco de dados, e cada recurso a menos é superfície
 * de ataque a menos. */
#include "tls.h"
#include "crypto/aes.h"
#include "crypto/curve.h"
#include "crypto/hash.h"
#include "crypto/x509.h"
#include "i18n.h"

enum { REC_CCS = 20, REC_ALERT = 21, REC_HANDSHAKE = 22, REC_APPDATA = 23 };
enum { HS_CLIENT_HELLO = 1, HS_SERVER_HELLO = 2, HS_NEW_TICKET = 4, HS_ENCRYPTED_EXT = 8, HS_CERTIFICATE = 11,
       HS_CERT_REQUEST = 13, HS_CERT_VERIFY = 15, HS_FINISHED = 20, HS_KEY_UPDATE = 24 };
enum { SUITE_AES128 = 0x1301, SUITE_AES256 = 0x1302, SUITE_CHACHA = 0x1303 };

#define MAX_PLAIN  16384
#define MAX_CIPHER (MAX_PLAIN + 256)
#define MAX_CERTS  12

typedef struct keys {
    uint8_t  secret[TM_HASH_MAX_DIGEST];
    uint8_t  key[32], iv[12];
    aes_key  aes;
    uint64_t seq;
    bool     on;
} keys;

struct tm_tls {
    tm_io             *io;
    tls_send_fn        send;
    tls_recv_fn        recv;
    void              *ctx;
    const tm_hash_alg *hash;
    int                suite;
    size_t             keylen;
    keys               rd, wr;
    tm_hash_ctx        transcript;
    tm_buf             hs;      /* mensagens de aperto de mão em remontagem */
    size_t             hpos;
    tm_buf             plain;   /* dados de aplicação já decifrados, ainda não entregues */
    size_t             ppos;
    tm_buf             rec, out;
    bool               closed;
};

/* ---- transporte ---- */

static int sock_send(void *ctx, const uint8_t *p, size_t n, tm_err *err)
{
    tm_io *io = ctx;
    while (n) {
        int rc = io_raw_send(io, p, n, err);
        if (rc < 0) return -1;
        p += rc;
        n -= (size_t)rc;
    }
    return 0;
}

static int sock_recv(void *ctx, uint8_t *p, size_t n, tm_err *err)
{
    return io_raw_recv(ctx, p, n, err);
}

void tls_use_socket(tm_tls *t)
{
    t->send = sock_send;
    t->recv = sock_recv;
    t->ctx = t->io;
}

static int recv_exact(tm_tls *t, uint8_t *p, size_t n, tm_err *err)
{
    while (n) {
        int rc = t->recv(t->ctx, p, n, err);
        if (rc <= 0) return -1;
        p += rc;
        n -= (size_t)rc;
    }
    return 0;
}

static int fail(tm_tls *t, tm_err *err, const char *what)
{
    t->io->broken = true;
    return tm_fail(err, TM_E_PROTOCOL, T(M_TLS_HANDSHAKE), what);
}

/* ---- derivação de chaves (RFC 8446, 7.1) ---- */

static void expand_label(const tm_hash_alg *h, const uint8_t *secret, const char *label, const uint8_t *context,
                         size_t ctxlen, uint8_t *out, size_t outlen)
{
    uint8_t info[2 + 1 + 64 + 1 + TM_HASH_MAX_DIGEST];
    size_t ll = strlen(label), n = 0;
    info[n++] = (uint8_t)(outlen >> 8);
    info[n++] = (uint8_t)outlen;
    info[n++] = (uint8_t)(6 + ll);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, ll);
    n += ll;
    info[n++] = (uint8_t)ctxlen;
    if (ctxlen) memcpy(info + n, context, ctxlen);
    n += ctxlen;
    hkdf_expand(h, secret, info, n, out, outlen);
}

static void transcript_hash(const tm_tls *t, uint8_t *out)
{
    tm_hash_ctx copy = t->transcript;
    hash_final(t->hash, &copy, out);
}

static void set_keys(tm_tls *t, keys *k, const uint8_t *secret)
{
    memcpy(k->secret, secret, t->hash->digest_len);
    expand_label(t->hash, secret, "key", NULL, 0, k->key, t->keylen);
    expand_label(t->hash, secret, "iv", NULL, 0, k->iv, 12);
    if (t->suite != SUITE_CHACHA) aes_init(&k->aes, k->key, t->keylen);
    k->seq = 0;
    k->on = true;
}

static void nonce_for(const keys *k, uint8_t nonce[12])
{
    memcpy(nonce, k->iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(k->seq >> (8 * i));
}

/* ---- camada de registros ---- */

static int send_record(tm_tls *t, int type, const uint8_t *p, size_t n, tm_err *err)
{
    buf_reset(&t->out);
    if (!t->wr.on) {
        uint8_t hdr[5] = { (uint8_t)type, 3, 3, (uint8_t)(n >> 8), (uint8_t)n };
        buf_put(&t->out, hdr, 5);
        buf_put(&t->out, p, n);
    } else {
        /* conteúdo + tipo real, cifrados; por fora, sempre "dados de aplicação" */
        size_t inner = n + 1, total = inner + 16;
        uint8_t hdr[5] = { REC_APPDATA, 3, 3, (uint8_t)(total >> 8), (uint8_t)total }, nonce[12], tag[16];
        buf_put(&t->out, hdr, 5);
        buf_reserve(&t->out, total);
        uint8_t *body = t->out.p + 5;
        memcpy(body, p, n);
        body[n] = (uint8_t)type;
        nonce_for(&t->wr, nonce);
        if (t->suite == SUITE_CHACHA) chapoly_seal(t->wr.key, nonce, hdr, 5, body, inner, body, tag);
        else aes_gcm_seal(&t->wr.aes, nonce, hdr, 5, body, inner, body, tag);
        memcpy(body + inner, tag, 16);
        t->out.len = 5 + total;
        t->wr.seq++;
    }
    return t->send(t->ctx, t->out.p, t->out.len, err);
}

/* Lê um registro; o conteúdo (já decifrado) fica em t->rec. Devolve o tipo, ou -1. */
static int read_record(tm_tls *t, tm_err *err)
{
    for (;;) {
        uint8_t hdr[5];
        if (recv_exact(t, hdr, 5, err)) return -1;
        size_t len = ((size_t)hdr[3] << 8) | hdr[4];
        if (len > MAX_CIPHER) return fail(t, err, "record too large");
        buf_reset(&t->rec);
        buf_reserve(&t->rec, len);
        if (len && recv_exact(t, t->rec.p, len, err)) return -1;
        t->rec.len = len;
        int type = hdr[0];
        if (type == REC_CCS) continue; /* compatibilidade com equipamentos antigos: ignorar */
        if (!t->rd.on || type != REC_APPDATA) {
            if (t->rd.on && type != REC_ALERT) return fail(t, err, "unencrypted record after key exchange");
            return type;
        }
        if (len < 17) return fail(t, err, "short record");
        uint8_t nonce[12];
        size_t inner = len - 16;
        nonce_for(&t->rd, nonce);
        int rc = t->suite == SUITE_CHACHA
                     ? chapoly_open(t->rd.key, nonce, hdr, 5, t->rec.p, inner, t->rec.p + inner, t->rec.p)
                     : aes_gcm_open(&t->rd.aes, nonce, hdr, 5, t->rec.p, inner, t->rec.p + inner, t->rec.p);
        if (rc) return fail(t, err, "record authentication failed");
        t->rd.seq++;
        while (inner && t->rec.p[inner - 1] == 0) inner--; /* preenchimento */
        if (!inner) return fail(t, err, "empty record");
        type = t->rec.p[inner - 1];
        t->rec.len = inner - 1;
        return type;
    }
}

static int alert_error(tm_tls *t, tm_err *err)
{
    int code = t->rec.len >= 2 ? t->rec.p[1] : -1;
    t->io->broken = true;
    if (code == 0) return tm_fail(err, TM_E_IO, "%s", T(M_IO_CLOSED));
    if (code == 70) return tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_OLD)); /* protocol_version */
    return tm_fail(err, TM_E_PROTOCOL, T(M_TLS_ALERT), code);
}

/* ---- mensagens de aperto de mão ---- */

/* Devolve a próxima mensagem completa (cabeçalho de 4 bytes + corpo) em *msg. */
static int next_handshake(tm_tls *t, const uint8_t **msg, size_t *len, tm_err *err)
{
    for (;;) {
        size_t have = t->hs.len - t->hpos;
        if (have >= 4) {
            const uint8_t *p = t->hs.p + t->hpos;
            size_t body = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
            if (body > (1u << 20)) return fail(t, err, "handshake message too large");
            if (have >= 4 + body) {
                *msg = p;
                *len = 4 + body;
                t->hpos += 4 + body;
                return 0;
            }
        }
        if (t->hpos && t->hpos == t->hs.len) {
            buf_reset(&t->hs);
            t->hpos = 0;
        }
        int type = read_record(t, err);
        if (type < 0) return -1;
        if (type == REC_ALERT) return alert_error(t, err);
        if (type != REC_HANDSHAKE) return fail(t, err, "unexpected record type");
        buf_put(&t->hs, t->rec.p, t->rec.len);
    }
}

static int send_handshake(tm_tls *t, tm_buf *msg, tm_err *err)
{
    hash_update(t->hash, &t->transcript, msg->p, msg->len);
    return send_record(t, REC_HANDSHAKE, msg->p, msg->len, err);
}

static void put_u24(tm_buf *b, size_t v)
{
    buf_putc(b, (int)(v >> 16));
    buf_putc(b, (int)(v >> 8));
    buf_putc(b, (int)v);
}

static bool is_ip_literal(const char *host)
{
    bool digits_only = true;
    for (const char *p = host; *p; p++) {
        if (*p == ':') return true; /* IPv6 */
        if (!((*p >= '0' && *p <= '9') || *p == '.')) digits_only = false;
    }
    return digits_only;
}

static void build_client_hello(tm_buf *m, const uint8_t random[32], const uint8_t session[32],
                               const uint8_t pub[32], const uint8_t pub256[65], const tls_opts *o)
{
    tm_buf ext;
    buf_init(&ext);
    if (o->host && *o->host && !is_ip_literal(o->host)) { /* server_name */
        size_t n = strlen(o->host);
        buf_u16be(&ext, 0);
        buf_u16be(&ext, (uint16_t)(n + 5));
        buf_u16be(&ext, (uint16_t)(n + 3));
        buf_putc(&ext, 0);
        buf_u16be(&ext, (uint16_t)n);
        buf_put(&ext, o->host, n);
    }
    static const uint8_t fixed[] = {
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,             /* supported_versions: TLS 1.3 */
        0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, /* supported_groups: x25519, secp256r1 */
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,                   /* signature_algorithms */
        0x08, 0x04, 0x08, 0x05, 0x08, 0x06,                   /*   rsa_pss_rsae_sha256/384/512 */
        0x04, 0x03, 0x05, 0x03,                               /*   ecdsa_secp256r1_sha256, secp384r1_sha384 */
        0x04, 0x01, 0x05, 0x01, 0x06, 0x01,                   /*   rsa_pkcs1 (só em certificados) */
        0x06, 0x03,                                           /*   ecdsa_sha512 (só em certificados) */
    };
    buf_put(&ext, fixed, sizeof fixed);
    /* key_share: as duas chaves já vão no primeiro voo. PostgreSQL (até a 17) e MySQL só
     * aceitam P-256; mandando ambas, nenhum servidor precisa pedir nova tentativa. */
    buf_u16be(&ext, 0x0033);
    buf_u16be(&ext, 2 + 36 + 69);
    buf_u16be(&ext, 36 + 69);
    buf_u16be(&ext, 0x001d);
    buf_u16be(&ext, 32);
    buf_put(&ext, pub, 32);
    buf_u16be(&ext, 0x0017);
    buf_u16be(&ext, 65);
    buf_put(&ext, pub256, 65);
    if (o->alpn) {
        size_t n = strlen(o->alpn);
        buf_u16be(&ext, 0x0010);
        buf_u16be(&ext, (uint16_t)(n + 3));
        buf_u16be(&ext, (uint16_t)(n + 1));
        buf_putc(&ext, (int)n);
        buf_put(&ext, o->alpn, n);
    }

    buf_putc(m, HS_CLIENT_HELLO);
    put_u24(m, 0);
    buf_u16be(m, 0x0303);
    buf_put(m, random, 32);
    buf_putc(m, 32);
    buf_put(m, session, 32);
    buf_u16be(m, 6); /* cifras */
    buf_u16be(m, SUITE_AES128);
    buf_u16be(m, SUITE_CHACHA);
    buf_u16be(m, SUITE_AES256);
    buf_putc(m, 1); /* compressão: nenhuma */
    buf_putc(m, 0);
    buf_u16be(m, (uint16_t)ext.len);
    buf_put(m, ext.p, ext.len);
    size_t body = m->len - 4;
    m->p[1] = (uint8_t)(body >> 16);
    m->p[2] = (uint8_t)(body >> 8);
    m->p[3] = (uint8_t)body;
    buf_free(&ext);
}

static int parse_server_hello(tm_tls *t, const uint8_t *msg, size_t len, const uint8_t session[32],
                              uint8_t server_pub[65], int *group, tm_err *err)
{
    static const uint8_t HRR[32] = { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
                                     0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
                                     0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };
    tm_rd rd;
    rd_init(&rd, msg + 4, len - 4);
    rd_u16be(&rd);
    const uint8_t *random = rd_bytes(&rd, 32);
    size_t sidlen = rd_u8(&rd);
    const uint8_t *sid = rd_bytes(&rd, sidlen);
    int suite = rd_u16be(&rd);
    rd_u8(&rd);
    size_t extlen = rd.pos < rd.len ? rd_u16be(&rd) : 0;
    const uint8_t *exts = rd_bytes(&rd, extlen);
    if (rd.bad || !random) return fail(t, err, "malformed ServerHello");
    if (memcmp(random, HRR, 32) == 0)
        return fail(t, err, "server requires a key exchange group other than X25519 or P-256");

    bool v13 = false, share = false;
    tm_rd er;
    rd_init(&er, exts, extlen);
    while (rd_left(&er) >= 4) {
        unsigned type = rd_u16be(&er);
        size_t n = rd_u16be(&er);
        const uint8_t *p = rd_bytes(&er, n);
        if (!p && n) break;
        if (type == 0x002b && n == 2 && p[0] == 3 && p[1] == 4) v13 = true;
        if (type == 0x0033 && n >= 4) {
            int g = (p[0] << 8) | p[1];
            size_t klen = ((size_t)p[2] << 8) | p[3];
            if (klen + 4 == n && ((g == 0x001d && klen == 32) || (g == 0x0017 && klen == 65))) {
                memcpy(server_pub, p + 4, klen);
                *group = g;
                share = true;
            }
        }
    }
    if (!v13) {
        t->io->broken = true;
        return tm_fail(err, TM_E_UNSUPPORTED, "%s", T(M_TLS_OLD));
    }
    if (!share || sidlen != 32 || memcmp(sid, session, 32) != 0) return fail(t, err, "bad ServerHello");
    t->suite = suite;
    if (suite == SUITE_AES128) { t->hash = &TM_SHA256; t->keylen = 16; }
    else if (suite == SUITE_AES256) { t->hash = &TM_SHA384; t->keylen = 32; }
    else if (suite == SUITE_CHACHA) { t->hash = &TM_SHA256; t->keylen = 32; }
    else return fail(t, err, "server chose an unknown cipher suite");
    return 0;
}

/* Guarda os certificados da mensagem Certificate. */
static int parse_certificates(tm_tls *t, const uint8_t *msg, size_t len, x509_blob *certs, int *count, tm_err *err)
{
    tm_rd rd;
    rd_init(&rd, msg + 4, len - 4);
    rd_skip(&rd, rd_u8(&rd)); /* contexto do pedido */
    size_t total = ((size_t)rd_u8(&rd) << 16) | ((size_t)rd_u8(&rd) << 8);
    total |= rd_u8(&rd);
    *count = 0;
    while (!rd.bad && rd_left(&rd) >= 3 && total) {
        size_t n = ((size_t)rd_u8(&rd) << 16) | ((size_t)rd_u8(&rd) << 8);
        n |= rd_u8(&rd);
        const uint8_t *der = rd_bytes(&rd, n);
        rd_skip(&rd, rd_u16be(&rd)); /* extensões do certificado */
        if (!der) break;
        if (*count < MAX_CERTS) {
            certs[*count].p = der;
            certs[*count].len = n;
            (*count)++;
        }
    }
    if (rd.bad || *count == 0) return fail(t, err, "server sent no certificate");
    return 0;
}

static int check_certificate(tm_tls *t, const tls_opts *o, const x509_blob *certs, int count, tm_err *err)
{
    if (o->mode < SSL_VERIFY_CA) return 0; /* "require": cifra sem autenticar o servidor */
    x509_store store;
    x509_store_init(&store);
    if (o->ca_file) {
        tm_buf pem;
        buf_init(&pem);
        int rc = plat_read_file(o->ca_file, &pem, err);
        if (rc == 0) x509_store_add_pem(&store, (const char *)pem.p, pem.len);
        buf_free(&pem);
        if (rc) {
            x509_store_free(&store);
            return -1;
        }
    } else {
        x509_store_load_system(&store);
    }
    int rc;
    if (store.count == 0) rc = tm_fail(err, TM_E_CONFIG, "%s", T(M_TLS_NO_ROOTS));
    else rc = x509_validate(certs, count, &store, o->mode == SSL_VERIFY_FULL ? o->host : NULL, err);
    x509_store_free(&store);
    if (rc) t->io->broken = true;
    return rc;
}

int tls_start(tm_io *io, const tls_opts *o, tm_err *err)
{
    /* Nada pode ter sobrado no buffer antes do TLS: seriam bytes em claro, injetáveis. */
    if (io->rpos != io->rlen) {
        io->broken = true;
        return tm_fail(err, TM_E_PROTOCOL, T(M_TLS_HANDSHAKE), "unexpected data before TLS");
    }
    tm_tls *t = tm_zalloc(sizeof *t);
    t->io = io;
    buf_init(&t->hs);
    buf_init(&t->plain);
    buf_init(&t->rec);
    buf_init(&t->out);
    if (o->send && o->recv) {
        t->send = o->send;
        t->recv = o->recv;
        t->ctx = o->ctx;
    } else {
        tls_use_socket(t);
    }

    uint8_t priv[32], pub[32], priv256[32], pub256[65], random[32], session[32], server_pub[65], shared[32];
    int group = 0;
    uint8_t zeros[TM_HASH_MAX_DIGEST] = { 0 }, empty_hash[TM_HASH_MAX_DIGEST], th[TM_HASH_MAX_DIGEST];
    uint8_t early[TM_HASH_MAX_DIGEST], derived[TM_HASH_MAX_DIGEST], hs_secret[TM_HASH_MAX_DIGEST];
    uint8_t master[TM_HASH_MAX_DIGEST], c_hs[TM_HASH_MAX_DIGEST], s_hs[TM_HASH_MAX_DIGEST];
    uint8_t c_ap[TM_HASH_MAX_DIGEST], s_ap[TM_HASH_MAX_DIGEST], fkey[TM_HASH_MAX_DIGEST], verify[TM_HASH_MAX_DIGEST];
    tm_buf hello, m;
    const uint8_t *msg;
    size_t len;
    int rc = -1;
    buf_init(&hello);
    buf_init(&m);

    if (plat_random(priv, 32) || plat_random(random, 32) || plat_random(session, 32)) {
        tm_fail(err, TM_E_GENERIC, "random");
        goto out;
    }
    x25519_public(pub, priv);
    /* chave P-256: sorteia até cair no intervalo válido (quase sempre na primeira) */
    int tries = 0;
    do {
        if (plat_random(priv256, 32) || ++tries > 16) {
            tm_fail(err, TM_E_GENERIC, "random");
            goto out;
        }
    } while (ecdh_p256_keypair(priv256, pub256));
    build_client_hello(&hello, random, session, pub, pub256, o);
    if (send_record(t, REC_HANDSHAKE, hello.p, hello.len, err)) goto out;

    /* ServerHello: define a cifra e, com ela, o hash da transcrição */
    if (next_handshake(t, &msg, &len, err)) goto out;
    if (msg[0] != HS_SERVER_HELLO) {
        fail(t, err, "expected ServerHello");
        goto out;
    }
    if (parse_server_hello(t, msg, len, session, server_pub, &group, err)) goto out;
    size_t hl = t->hash->digest_len;
    hash_init(t->hash, &t->transcript);
    hash_update(t->hash, &t->transcript, hello.p, hello.len);
    hash_update(t->hash, &t->transcript, msg, len);

    if (group == 0x0017 ? ecdh_p256_shared(priv256, server_pub, 65, shared) : x25519(shared, priv, server_pub)) {
        fail(t, err, "invalid server key share");
        goto out;
    }
    hash_once(t->hash, "", 0, empty_hash);
    hkdf_extract(t->hash, NULL, 0, zeros, hl, early);
    expand_label(t->hash, early, "derived", empty_hash, hl, derived, hl);
    hkdf_extract(t->hash, derived, hl, shared, 32, hs_secret);
    transcript_hash(t, th);
    expand_label(t->hash, hs_secret, "c hs traffic", th, hl, c_hs, hl);
    expand_label(t->hash, hs_secret, "s hs traffic", th, hl, s_hs, hl);
    expand_label(t->hash, hs_secret, "derived", empty_hash, hl, derived, hl);
    hkdf_extract(t->hash, derived, hl, zeros, hl, master);
    set_keys(t, &t->rd, s_hs);
    set_keys(t, &t->wr, c_hs);

    /* Mensagens cifradas do servidor, na ordem fixa do protocolo */
    x509_blob certs[MAX_CERTS];
    tm_buf cert_copy;
    int ncerts = 0;
    bool got_cert = false, got_verify = false, cert_requested = false;
    buf_init(&cert_copy);
    for (;;) {
        if (next_handshake(t, &msg, &len, err)) goto out_certs;
        int type = msg[0];
        if (type == HS_ENCRYPTED_EXT) {
            /* nada a negociar além do que já foi pedido */
        } else if (type == HS_CERT_REQUEST) {
            cert_requested = true;
        } else if (type == HS_CERTIFICATE && !got_cert) {
            /* copia: o buffer de remontagem pode ser reaproveitado antes da validação */
            buf_put(&cert_copy, msg, len);
            if (parse_certificates(t, cert_copy.p, cert_copy.len, certs, &ncerts, err)) goto out_certs;
            got_cert = true;
        } else if (type == HS_CERT_VERIFY && got_cert && !got_verify) {
            /* O servidor assina a transcrição: prova que tem a chave do certificado. */
            uint8_t signed_data[64 + 34 + TM_HASH_MAX_DIGEST];
            tm_rd rd;
            x509 leaf;
            memset(signed_data, 0x20, 64);
            memcpy(signed_data + 64, "TLS 1.3, server CertificateVerify", 33);
            signed_data[97] = 0;
            transcript_hash(t, signed_data + 98);
            rd_init(&rd, msg + 4, len - 4);
            unsigned scheme = rd_u16be(&rd);
            size_t siglen = rd_u16be(&rd);
            const uint8_t *sig = rd_bytes(&rd, siglen);
            if (!sig || x509_parse(&leaf, certs[0].p, certs[0].len)) {
                fail(t, err, "malformed CertificateVerify");
                goto out_certs;
            }
            int v = x509_verify_tls(&leaf, scheme, signed_data, 98 + hl, sig, siglen);
            /* Assinatura errada é sempre fatal. Esquema que não conhecemos só é
             * tolerado quando o usuário pediu cifra sem autenticação ("require"). */
            if (v < 0 || (v > 0 && o->mode >= SSL_VERIFY_CA)) {
                fail(t, err, v < 0 ? "server signature does not match its certificate"
                                   : "unsupported server signature scheme");
                goto out_certs;
            }
            got_verify = true;
        } else if (type == HS_FINISHED && got_verify) {
            expand_label(t->hash, s_hs, "finished", NULL, 0, fkey, hl);
            transcript_hash(t, th);
            hmac_once(t->hash, fkey, hl, th, hl, verify);
            if (len != 4 + hl || !ct_equal(verify, msg + 4, hl)) {
                fail(t, err, "server Finished does not match");
                goto out_certs;
            }
            hash_update(t->hash, &t->transcript, msg, len);
            break;
        } else {
            fail(t, err, "unexpected handshake message");
            goto out_certs;
        }
        hash_update(t->hash, &t->transcript, msg, len);
    }
    if (check_certificate(t, o, certs, ncerts, err)) goto out_certs;

    /* Chaves de aplicação: a transcrição vai até o Finished do servidor */
    transcript_hash(t, th);
    expand_label(t->hash, master, "c ap traffic", th, hl, c_ap, hl);
    expand_label(t->hash, master, "s ap traffic", th, hl, s_ap, hl);

    if (cert_requested) { /* não temos certificado de cliente: lista vazia */
        static const uint8_t none[] = { HS_CERTIFICATE, 0, 0, 4, 0, 0, 0, 0 };
        buf_reset(&m);
        buf_put(&m, none, sizeof none);
        if (send_handshake(t, &m, err)) goto out_certs;
    }
    expand_label(t->hash, c_hs, "finished", NULL, 0, fkey, hl);
    transcript_hash(t, th);
    hmac_once(t->hash, fkey, hl, th, hl, verify);
    buf_reset(&m);
    buf_putc(&m, HS_FINISHED);
    put_u24(&m, hl);
    buf_put(&m, verify, hl);
    if (send_handshake(t, &m, err)) goto out_certs;

    set_keys(t, &t->rd, s_ap);
    set_keys(t, &t->wr, c_ap);
    rc = 0;

out_certs:
    buf_free(&cert_copy);
out:
    tm_wipe(priv, sizeof priv);
    tm_wipe(priv256, sizeof priv256);
    tm_wipe(shared, sizeof shared);
    tm_wipe(hs_secret, sizeof hs_secret);
    tm_wipe(master, sizeof master);
    tm_wipe(c_hs, sizeof c_hs);
    tm_wipe(s_hs, sizeof s_hs);
    tm_wipe(c_ap, sizeof c_ap);
    tm_wipe(s_ap, sizeof s_ap);
    buf_free(&hello);
    buf_free(&m);
    if (rc) {
        io->broken = true;
        tls_free(t);
        return -1;
    }
    io->tls = t;
    return 0;
}

/* ---- dados de aplicação ---- */

int tls_write(tm_tls *t, const void *p, size_t n, tm_err *err)
{
    const uint8_t *u = p;
    while (n) {
        size_t take = n < MAX_PLAIN ? n : MAX_PLAIN;
        if (send_record(t, REC_APPDATA, u, take, err)) return -1;
        u += take;
        n -= take;
    }
    return 0;
}

/* Troca de chave pedida pelo servidor (RFC 8446, 4.6.3). */
static int key_update(tm_tls *t, bool reply, tm_err *err)
{
    uint8_t next[TM_HASH_MAX_DIGEST];
    size_t hl = t->hash->digest_len;
    expand_label(t->hash, t->rd.secret, "traffic upd", NULL, 0, next, hl);
    set_keys(t, &t->rd, next);
    if (reply) {
        static const uint8_t msg[] = { HS_KEY_UPDATE, 0, 0, 1, 0 };
        if (send_record(t, REC_HANDSHAKE, msg, sizeof msg, err)) return -1;
        expand_label(t->hash, t->wr.secret, "traffic upd", NULL, 0, next, hl);
        set_keys(t, &t->wr, next);
    }
    return 0;
}

int tls_read(tm_tls *t, void *p, size_t cap, tm_err *err)
{
    while (t->ppos == t->plain.len) {
        if (t->closed) return tm_fail(err, TM_E_IO, "%s", T(M_IO_CLOSED));
        int type = read_record(t, err);
        if (type < 0) return -1;
        if (type == REC_APPDATA) {
            buf_reset(&t->plain);
            buf_put(&t->plain, t->rec.p, t->rec.len);
            t->ppos = 0;
        } else if (type == REC_ALERT) {
            t->closed = true;
            return alert_error(t, err);
        } else if (type == REC_HANDSHAKE) {
            /* depois do aperto de mão: bilhetes de sessão (ignorados) e troca de chave */
            tm_rd rd;
            rd_init(&rd, t->rec.p, t->rec.len);
            while (rd_left(&rd) >= 4) {
                int ht = rd_u8(&rd);
                size_t n = ((size_t)rd_u8(&rd) << 16) | ((size_t)rd_u8(&rd) << 8);
                n |= rd_u8(&rd);
                const uint8_t *body = rd_bytes(&rd, n);
                if (!body && n) break; /* mensagem partida entre registros: bilhete, descartado */
                if (ht == HS_KEY_UPDATE && n == 1 && key_update(t, body[0] == 1, err)) return -1;
            }
        } else {
            return fail(t, err, "unexpected record");
        }
    }
    size_t take = t->plain.len - t->ppos;
    if (take > cap) take = cap;
    memcpy(p, t->plain.p + t->ppos, take);
    t->ppos += take;
    return (int)take;
}

void tls_free(tm_tls *t)
{
    if (!t) return;
    if (t->wr.on && !t->io->broken && !t->closed) {
        static const uint8_t close_notify[2] = { 1, 0 };
        tm_err ignore;
        send_record(t, REC_ALERT, close_notify, 2, &ignore);
    }
    buf_free(&t->hs);
    buf_free(&t->plain);
    buf_free(&t->rec);
    buf_free(&t->out);
    tm_wipe(t, sizeof *t);
    free(t);
}

bool tls_prefer_fallback(const tm_conn_cfg *cfg, const tm_err *err)
{
    if (cfg->ssl != SSL_PREFER) return false;
    return err->code == TM_E_PROTOCOL || err->code == TM_E_UNSUPPORTED || err->code == TM_E_IO;
}

void tls_opts_from_cfg(tls_opts *o, const tm_conn_cfg *cfg)
{
    memset(o, 0, sizeof *o);
    o->host = cfg->host;
    o->mode = cfg->ssl;
    o->ca_file = cfg->ca_file;
}
