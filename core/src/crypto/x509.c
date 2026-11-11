/* X.509 (RFC 5280): o subconjunto necessário para autenticar um servidor TLS.
 * Toda entrada aqui vem da rede: nada é indexado sem conferir o limite antes. */
#include <time.h>

#include "x509.h"
#include "../i18n.h"
#include "../plat.h"
#include "curve.h"
#include "hash.h"

/* ---- OIDs (conteúdo DER) ---- */
#define OID(name, ...) static const uint8_t name[] = { __VA_ARGS__ }
OID(OID_RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01);
OID(OID_RSA_SHA1, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05);
OID(OID_RSA_PSS, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a);
OID(OID_RSA_SHA256, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b);
OID(OID_RSA_SHA384, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c);
OID(OID_RSA_SHA512, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d);
OID(OID_EC_KEY, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
OID(OID_P256, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07);
OID(OID_P384, 0x2b, 0x81, 0x04, 0x00, 0x22);
OID(OID_ECDSA_SHA256, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02);
OID(OID_ECDSA_SHA384, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03);
OID(OID_ECDSA_SHA512, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04);
OID(OID_SHA256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);
OID(OID_SHA384, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02);
OID(OID_SHA512, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03);
OID(OID_SAN, 0x55, 0x1d, 0x11);
OID(OID_BASIC, 0x55, 0x1d, 0x13);
OID(OID_CN, 0x55, 0x04, 0x03);

static bool oid_is(const tm_rd *v, const uint8_t *oid, size_t n)
{
    return v->len == n && memcmp(v->p, oid, n) == 0;
}
#define IS(v, oid) oid_is(&(v), oid, sizeof oid)

/* Lê um elemento guardando também os bytes crus (cabeçalho + conteúdo). */
static bool der_raw(tm_rd *r, int *tag, tm_rd *content, const uint8_t **raw, size_t *rawlen)
{
    const uint8_t *start = r->p + r->pos;
    if (!der_next(r, tag, content)) return false;
    *raw = start;
    *rawlen = (size_t)((r->p + r->pos) - start);
    return true;
}

static int64_t days_from_civil(int y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* UTCTime (AAMMDDHHMMSSZ) ou GeneralizedTime (AAAAMMDDHHMMSSZ) -> segundos desde 1970 */
static int64_t parse_time(int tag, const tm_rd *v)
{
    const uint8_t *p = v->p;
    size_t n = v->len, i = 0;
    int f[6] = { 0 };
    int year;
    for (size_t k = 0; k < n; k++)
        if (k < n - 1 && (p[k] < '0' || p[k] > '9')) return 0;
    if (tag == 0x17 && n >= 13) {
        year = (p[0] - '0') * 10 + (p[1] - '0');
        year += year < 50 ? 2000 : 1900;
        i = 2;
    } else if (tag == 0x18 && n >= 15) {
        year = (p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0');
        i = 4;
    } else {
        return 0;
    }
    for (int k = 0; k < 5; k++, i += 2) f[k] = (p[i] - '0') * 10 + (p[i + 1] - '0');
    return days_from_civil(year, f[0], f[1]) * 86400 + f[2] * 3600 + f[3] * 60 + f[4];
}

static x509_sig sig_from_alg(tm_rd alg)
{
    tm_rd oid, params, inner, hash_oid;
    int tag;
    if (!der_expect(&alg, DER_OID, &oid)) return XS_OTHER;
    if (IS(oid, OID_RSA_SHA256)) return XS_RSA_SHA256;
    if (IS(oid, OID_RSA_SHA384)) return XS_RSA_SHA384;
    if (IS(oid, OID_RSA_SHA512)) return XS_RSA_SHA512;
    if (IS(oid, OID_RSA_SHA1)) return XS_RSA_SHA1;
    if (IS(oid, OID_ECDSA_SHA256)) return XS_ECDSA_SHA256;
    if (IS(oid, OID_ECDSA_SHA384)) return XS_ECDSA_SHA384;
    if (IS(oid, OID_ECDSA_SHA512)) return XS_ECDSA_SHA512;
    if (IS(oid, OID_RSA_PSS)) {
        /* parâmetros: [0] { algoritmo de hash } ... — sem eles o padrão é SHA-1, que não aceitamos */
        if (!der_expect(&alg, DER_SEQUENCE, &params)) return XS_OTHER;
        if (!der_next(&params, &tag, &inner) || tag != 0xA0) return XS_OTHER;
        tm_rd halg;
        if (!der_expect(&inner, DER_SEQUENCE, &halg) || !der_expect(&halg, DER_OID, &hash_oid)) return XS_OTHER;
        if (IS(hash_oid, OID_SHA256)) return XS_PSS_SHA256;
        if (IS(hash_oid, OID_SHA384)) return XS_PSS_SHA384;
        if (IS(hash_oid, OID_SHA512)) return XS_PSS_SHA512;
    }
    return XS_OTHER;
}

static void parse_extensions(x509 *c, tm_rd exts)
{
    tm_rd list, ext, oid, value;
    int tag;
    if (!der_expect(&exts, DER_SEQUENCE, &list)) return;
    while (der_next(&list, &tag, &ext)) {
        if (tag != DER_SEQUENCE || !der_expect(&ext, DER_OID, &oid)) continue;
        if (!der_next(&ext, &tag, &value)) continue;
        if (tag == 0x01 && !der_next(&ext, &tag, &value)) continue; /* pula "critical" */
        if (tag != DER_OCTETSTRING) continue;
        if (IS(oid, OID_SAN)) {
            tm_rd names;
            if (der_expect(&value, DER_SEQUENCE, &names)) {
                c->san = names.p;
                c->san_len = names.len;
            }
        } else if (IS(oid, OID_BASIC)) {
            tm_rd bc, flag;
            if (der_expect(&value, DER_SEQUENCE, &bc) && der_next(&bc, &tag, &flag) && tag == 0x01 && flag.len == 1)
                c->is_ca = flag.p[0] != 0;
        }
    }
}

int x509_parse(x509 *c, const uint8_t *der, size_t len)
{
    tm_rd top, cert, tbs, v, alg, spki, keyalg, oid, bits;
    const uint8_t *raw;
    size_t rawlen;
    int tag;
    memset(c, 0, sizeof *c);
    c->der = der;
    c->len = len;
    rd_init(&top, der, len);
    if (!der_expect(&top, DER_SEQUENCE, &cert)) return -1;
    if (!der_raw(&cert, &tag, &tbs, &c->tbs, &c->tbs_len) || tag != DER_SEQUENCE) return -1;

    /* assinatura do certificado */
    if (!der_expect(&cert, DER_SEQUENCE, &alg)) return -1;
    c->sig_alg = sig_from_alg(alg);
    if (!der_expect(&cert, DER_BITSTRING, &bits) || bits.len < 1) return -1;
    c->sig = bits.p + 1;
    c->sig_len = bits.len - 1;

    /* conteúdo assinado */
    tm_rd probe = tbs;
    if (der_next(&probe, &tag, &v) && tag == 0xA0) tbs = probe; /* versão */
    if (!der_expect(&tbs, DER_INTEGER, &v)) return -1;          /* número de série */
    if (!der_expect(&tbs, DER_SEQUENCE, &v)) return -1;         /* algoritmo (repetido) */
    if (!der_raw(&tbs, &tag, &v, &c->issuer, &c->issuer_len) || tag != DER_SEQUENCE) return -1;
    tm_rd validity, t1, t2;
    int tag1, tag2;
    if (!der_expect(&tbs, DER_SEQUENCE, &validity) || !der_next(&validity, &tag1, &t1) ||
        !der_next(&validity, &tag2, &t2))
        return -1;
    c->not_before = parse_time(tag1, &t1);
    c->not_after = parse_time(tag2, &t2);
    if (!der_raw(&tbs, &tag, &v, &c->subject, &c->subject_len) || tag != DER_SEQUENCE) return -1;

    /* chave pública */
    if (!der_raw(&tbs, &tag, &spki, &raw, &rawlen) || tag != DER_SEQUENCE) return -1;
    tm_rd spki_inner = spki;
    if (!der_expect(&spki_inner, DER_SEQUENCE, &keyalg) || !der_expect(&keyalg, DER_OID, &oid)) return -1;
    if (IS(oid, OID_RSA)) {
        if (rsa_pub_from_der(&c->rsa, raw, rawlen) == 0) c->key_type = XK_RSA;
    } else if (IS(oid, OID_EC_KEY)) {
        tm_rd curve_oid;
        if (der_expect(&keyalg, DER_OID, &curve_oid) && der_expect(&spki_inner, DER_BITSTRING, &bits) &&
            bits.len >= 2 && bits.len - 1 <= sizeof c->ec) {
            memcpy(c->ec, bits.p + 1, bits.len - 1);
            c->ec_len = bits.len - 1;
            if (IS(curve_oid, OID_P256)) c->key_type = XK_EC256;
            else if (IS(curve_oid, OID_P384)) c->key_type = XK_EC384;
        }
    }

    /* extensões: [3] */
    while (der_next(&tbs, &tag, &v))
        if (tag == 0xA3) parse_extensions(c, v);
    return 0;
}

/* ---- assinaturas ---- */

static const tm_hash_alg *sig_hash(x509_sig s)
{
    switch (s) {
    case XS_RSA_SHA1: return &TM_SHA1;
    case XS_RSA_SHA256: case XS_PSS_SHA256: case XS_ECDSA_SHA256: return &TM_SHA256;
    case XS_RSA_SHA384: case XS_PSS_SHA384: case XS_ECDSA_SHA384: return &TM_SHA384;
    case XS_RSA_SHA512: case XS_PSS_SHA512: case XS_ECDSA_SHA512: return &TM_SHA512;
    default: return NULL;
    }
}

/* Assinatura ECDSA em DER: SEQUENCE { INTEGER r, INTEGER s } */
static int ecdsa_der_verify(const x509 *key, const uint8_t *digest, size_t dlen, const uint8_t *sig, size_t siglen)
{
    tm_rd top, seq, r, s;
    rd_init(&top, sig, siglen);
    if (!der_expect(&top, DER_SEQUENCE, &seq) || !der_expect(&seq, DER_INTEGER, &r) ||
        !der_expect(&seq, DER_INTEGER, &s))
        return -1;
    return ecdsa_verify(key->key_type == XK_EC256 ? 256 : 384, key->ec, key->ec_len, digest, dlen, r.p, r.len,
                        s.p, s.len);
}

/* Verifica `sig` sobre `msg` com a chave pública de `key`, no esquema dado. */
static int verify_with(const x509 *key, x509_sig alg, const uint8_t *msg, size_t msglen, const uint8_t *sig,
                       size_t siglen)
{
    const tm_hash_alg *h = sig_hash(alg);
    uint8_t digest[TM_HASH_MAX_DIGEST];
    if (!h) return 1;
    hash_once(h, msg, msglen, digest);
    switch (alg) {
    case XS_RSA_SHA1: case XS_RSA_SHA256: case XS_RSA_SHA384: case XS_RSA_SHA512:
        return key->key_type == XK_RSA ? rsa_pkcs1_verify(&key->rsa, h, digest, sig, siglen) : -1;
    case XS_PSS_SHA256: case XS_PSS_SHA384: case XS_PSS_SHA512:
        return key->key_type == XK_RSA ? rsa_pss_verify(&key->rsa, h, digest, sig, siglen) : -1;
    case XS_ECDSA_SHA256: case XS_ECDSA_SHA384: case XS_ECDSA_SHA512:
        if (key->key_type != XK_EC256 && key->key_type != XK_EC384) return -1;
        return ecdsa_der_verify(key, digest, h->digest_len, sig, siglen);
    default:
        return 1;
    }
}

int x509_verify_tls(const x509 *c, unsigned scheme, const uint8_t *msg, size_t msglen, const uint8_t *sig,
                    size_t siglen)
{
    /* No TLS 1.3 o esquema amarra chave, curva e hash; não se aceita combinação cruzada. */
    static const struct { unsigned scheme; x509_sig alg; x509_key key; } MAP[] = {
        { 0x0804, XS_PSS_SHA256, XK_RSA },   { 0x0805, XS_PSS_SHA384, XK_RSA },   { 0x0806, XS_PSS_SHA512, XK_RSA },
        { 0x0403, XS_ECDSA_SHA256, XK_EC256 }, { 0x0503, XS_ECDSA_SHA384, XK_EC384 },
    };
    for (size_t i = 0; i < TM_COUNT(MAP); i++)
        if (MAP[i].scheme == scheme) {
            if (c->key_type != MAP[i].key) return -1;
            return verify_with(c, MAP[i].alg, msg, msglen, sig, siglen);
        }
    return 1;
}

/* ---- repositório ---- */

void x509_store_init(x509_store *s)
{
    buf_init(&s->data);
    s->count = 0;
}

void x509_store_free(x509_store *s)
{
    buf_free(&s->data);
    s->count = 0;
}

void x509_store_add_der(x509_store *s, const uint8_t *der, size_t len)
{
    buf_u32le(&s->data, (uint32_t)len);
    buf_put(&s->data, der, len);
    s->count++;
}

int x509_store_add_pem(x509_store *s, const char *pem, size_t len)
{
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----", END[] = "-----END CERTIFICATE-----";
    const char *p = pem, *end = pem + len;
    int added = 0;
    uint8_t *der = tm_alloc(16384);
    while (p < end) {
        const char *b = NULL, *e = NULL;
        for (const char *q = p; q + sizeof BEGIN - 1 <= end; q++)
            if (memcmp(q, BEGIN, sizeof BEGIN - 1) == 0) {
                b = q + sizeof BEGIN - 1;
                break;
            }
        if (!b) break;
        for (const char *q = b; q + sizeof END - 1 <= end; q++)
            if (memcmp(q, END, sizeof END - 1) == 0) {
                e = q;
                break;
            }
        if (!e) break;
        int n = tm_b64_dec(der, 16384, b, (size_t)(e - b));
        if (n > 0) {
            x509_store_add_der(s, der, (size_t)n);
            added++;
        }
        p = e + sizeof END - 1;
    }
    free(der);
    return added;
}

int x509_store_load_system(x509_store *s)
{
    int before = s->count;
    plat_system_roots(s);
    return s->count - before;
}

/* ---- validação ---- */

static bool same_name(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && memcmp(a, b, an) == 0;
}

static bool issued_by(const x509 *child, const x509 *parent)
{
    if (!same_name(child->issuer, child->issuer_len, parent->subject, parent->subject_len)) return false;
    return verify_with(parent, child->sig_alg, child->tbs, child->tbs_len, child->sig, child->sig_len) == 0;
}

static bool valid_now(const x509 *c, int64_t now)
{
    return c->not_before && c->not_after && now >= c->not_before - 300 && now <= c->not_after;
}

/* "*.exemplo.com" casa só um rótulo à esquerda, e nunca o domínio inteiro. */
static bool name_matches(const char *pattern, size_t plen, const char *host)
{
    size_t hlen = strlen(host);
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = strchr(host, '.');
        if (!dot || dot == host) return false;
        size_t rest = hlen - (size_t)(dot - host);
        return rest == plen - 1 && tm_strnicmp(dot, pattern + 1, rest) == 0 && strchr(dot + 1, '.') != NULL;
    }
    return hlen == plen && tm_strnicmp(pattern, host, plen) == 0;
}

static bool parse_ipv4(const char *host, uint8_t ip[4])
{
    unsigned a, b, c, d;
    char tail;
    if (sscanf(host, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
        return false;
    ip[0] = (uint8_t)a;
    ip[1] = (uint8_t)b;
    ip[2] = (uint8_t)c;
    ip[3] = (uint8_t)d;
    return true;
}

static bool host_matches(const x509 *leaf, const char *host)
{
    uint8_t ip[4];
    bool is_ip = parse_ipv4(host, ip);
    if (leaf->san) {
        tm_rd names, v;
        int tag;
        rd_init(&names, leaf->san, leaf->san_len);
        while (der_next(&names, &tag, &v)) {
            if (tag == 0x82 && !is_ip && name_matches((const char *)v.p, v.len, host)) return true; /* dNSName */
            if (tag == 0x87 && is_ip && v.len == 4 && memcmp(v.p, ip, 4) == 0) return true;          /* iPAddress */
        }
        return false;
    }
    /* Sem subjectAltName: certificados antigos de banco ainda usam o CN. */
    tm_rd top, name, rdn, atv, oid, val;
    int tag;
    rd_init(&top, leaf->subject, leaf->subject_len);
    if (!der_expect(&top, DER_SEQUENCE, &name)) return false;
    while (der_next(&name, &tag, &rdn))
        while (der_next(&rdn, &tag, &atv))
            if (der_expect(&atv, DER_OID, &oid) && IS(oid, OID_CN) && der_next(&atv, &tag, &val) &&
                name_matches((const char *)val.p, val.len, host))
                return true;
    return false;
}

int x509_validate(const x509_blob *certs, int n, const x509_store *store, const char *host, tm_err *err)
{
    int64_t now = (int64_t)time(NULL);
    x509 cur, cand;
    if (n < 1 || x509_parse(&cur, certs[0].p, certs[0].len))
        return tm_fail(err, TM_E_AUTH, T(M_TLS_CERT), "unreadable certificate");
    if (host && !host_matches(&cur, host)) return tm_fail(err, TM_E_AUTH, T(M_TLS_CERT_HOST), host);

    for (int depth = 0; depth < 10; depth++) {
        if (!valid_now(&cur, now)) return tm_fail(err, TM_E_AUTH, T(M_TLS_CERT), "expired or not yet valid");

        /* confiável: é uma das autoridades, ou foi assinado por uma delas */
        tm_rd rd;
        rd_init(&rd, store->data.p, store->data.len);
        while (rd_left(&rd) >= 4) {
            uint32_t len = rd_u32le(&rd);
            const uint8_t *der = rd_bytes(&rd, len);
            if (!der) break;
            if (len == cur.len && memcmp(der, cur.der, len) == 0) return 0;
            if (x509_parse(&cand, der, len) == 0 && valid_now(&cand, now) && issued_by(&cur, &cand)) return 0;
        }

        /* senão, sobe um degrau na cadeia que o servidor mandou */
        bool climbed = false;
        for (int i = 1; i < n && !climbed; i++) {
            if (x509_parse(&cand, certs[i].p, certs[i].len)) continue;
            if (cand.len == cur.len && memcmp(cand.der, cur.der, cur.len) == 0) continue;
            if (cand.is_ca && issued_by(&cur, &cand)) {
                cur = cand;
                climbed = true;
            }
        }
        if (!climbed) break;
    }
    return tm_fail(err, TM_E_AUTH, T(M_TLS_CERT), "not issued by a trusted authority");
}
