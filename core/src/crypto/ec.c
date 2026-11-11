/* ECDSA em P-256 e P-384 — só verificação de assinatura (FIPS 186-4).
 * Tudo aqui opera sobre dados públicos (chave pública, assinatura, hash), então
 * o código privilegia clareza: coordenadas jacobianas e dobra-e-soma simples. */
#include "curve.h"
#include "rsa.h"

typedef uint32_t fe[BN_EC_LIMBS];

typedef struct curve {
    int      bytes;
    bn_field p, n;
    fe       b, gx, gy; /* na forma de Montgomery, módulo p */
    bool     ready;
} curve;

typedef struct point {
    fe x, y, z; /* jacobianas; z = 0 é o ponto no infinito */
} point;

static const uint8_t P256_P[] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff };
static const uint8_t P256_N[] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                                  0xfc, 0x63, 0x25, 0x51 };
static const uint8_t P256_B[] = { 0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98,
                                  0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e,
                                  0x27, 0xd2, 0x60, 0x4b };
static const uint8_t P256_GX[] = { 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                                   0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                                   0xd8, 0x98, 0xc2, 0x96 };
static const uint8_t P256_GY[] = { 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                                   0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                                   0x37, 0xbf, 0x51, 0xf5 };

static const uint8_t P384_P[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
static const uint8_t P384_N[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
                                  0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73 };
static const uint8_t P384_B[] = { 0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b,
                                  0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
                                  0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d,
                                  0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef };
static const uint8_t P384_GX[] = { 0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
                                   0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
                                   0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
                                   0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7 };
static const uint8_t P384_GY[] = { 0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
                                   0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
                                   0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
                                   0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f };

static curve C256, C384;

/* valor normal (bytes) -> forma de Montgomery módulo f */
static void to_mont(const bn_field *f, fe out, const uint8_t *bytes, size_t n)
{
    fe plain;
    bnf_from_bytes(f, plain, bytes, n);
    bnf_mul(f, out, plain, f->rr);
}

static curve *get_curve(int bits)
{
    curve *c = bits == 256 ? &C256 : bits == 384 ? &C384 : NULL;
    if (!c || c->ready) return c;
    bool small = bits == 256;
    c->bytes = bits / 8;
    bnf_init(&c->p, small ? P256_P : P384_P, (size_t)c->bytes);
    bnf_init(&c->n, small ? P256_N : P384_N, (size_t)c->bytes);
    to_mont(&c->p, c->b, small ? P256_B : P384_B, (size_t)c->bytes);
    to_mont(&c->p, c->gx, small ? P256_GX : P384_GX, (size_t)c->bytes);
    to_mont(&c->p, c->gy, small ? P256_GY : P384_GY, (size_t)c->bytes);
    c->ready = true;
    return c;
}

/* y^2 == x^3 - 3x + b ? (x, y na forma de Montgomery) */
static bool on_curve(const curve *c, const fe x, const fe y)
{
    const bn_field *f = &c->p;
    fe lhs, rhs, t;
    bnf_mul(f, lhs, y, y);
    bnf_mul(f, rhs, x, x);
    bnf_mul(f, rhs, rhs, x);
    bnf_add(f, t, x, x);
    bnf_add(f, t, t, x);
    bnf_sub(f, rhs, rhs, t);
    bnf_add(f, rhs, rhs, c->b);
    return bnf_cmp(f, lhs, rhs) == 0;
}

static void pt_double(const curve *c, point *r, const point *a)
{
    const bn_field *f = &c->p;
    fe delta, gamma, beta, alpha, t, u;
    if (bnf_is_zero(f, a->z)) {
        *r = *a;
        return;
    }
    bnf_mul(f, delta, a->z, a->z);
    bnf_mul(f, gamma, a->y, a->y);
    bnf_mul(f, beta, a->x, gamma);
    bnf_sub(f, t, a->x, delta);
    bnf_add(f, u, a->x, delta);
    bnf_mul(f, alpha, t, u);
    bnf_add(f, t, alpha, alpha);
    bnf_add(f, alpha, t, alpha); /* alpha = 3 (x - delta)(x + delta) */

    fe x3, y3, z3, beta4, beta8;
    bnf_add(f, beta4, beta, beta);
    bnf_add(f, beta4, beta4, beta4);
    bnf_add(f, beta8, beta4, beta4);
    bnf_mul(f, x3, alpha, alpha);
    bnf_sub(f, x3, x3, beta8);

    bnf_add(f, z3, a->y, a->z);
    bnf_mul(f, z3, z3, z3);
    bnf_sub(f, z3, z3, gamma);
    bnf_sub(f, z3, z3, delta);

    bnf_sub(f, t, beta4, x3);
    bnf_mul(f, y3, alpha, t);
    bnf_mul(f, t, gamma, gamma);
    bnf_add(f, t, t, t);
    bnf_add(f, t, t, t);
    bnf_add(f, t, t, t); /* 8 gamma^2 */
    bnf_sub(f, y3, y3, t);

    memcpy(r->x, x3, sizeof(fe));
    memcpy(r->y, y3, sizeof(fe));
    memcpy(r->z, z3, sizeof(fe));
}

static void pt_add(const curve *c, point *r, const point *a, const point *b)
{
    const bn_field *f = &c->p;
    if (bnf_is_zero(f, a->z)) {
        *r = *b;
        return;
    }
    if (bnf_is_zero(f, b->z)) {
        *r = *a;
        return;
    }
    fe z1z1, z2z2, u1, u2, s1, s2, h, rr, hh, hhh, v, t;
    bnf_mul(f, z1z1, a->z, a->z);
    bnf_mul(f, z2z2, b->z, b->z);
    bnf_mul(f, u1, a->x, z2z2);
    bnf_mul(f, u2, b->x, z1z1);
    bnf_mul(f, s1, a->y, b->z);
    bnf_mul(f, s1, s1, z2z2);
    bnf_mul(f, s2, b->y, a->z);
    bnf_mul(f, s2, s2, z1z1);
    bnf_sub(f, h, u2, u1);
    bnf_sub(f, rr, s2, s1);
    if (bnf_is_zero(f, h)) {
        if (bnf_is_zero(f, rr)) {
            pt_double(c, r, a);
        } else {
            memset(r, 0, sizeof *r); /* P + (-P) = infinito */
        }
        return;
    }
    bnf_mul(f, hh, h, h);
    bnf_mul(f, hhh, hh, h);
    bnf_mul(f, v, u1, hh);

    point out;
    bnf_mul(f, out.x, rr, rr);
    bnf_sub(f, out.x, out.x, hhh);
    bnf_sub(f, out.x, out.x, v);
    bnf_sub(f, out.x, out.x, v);
    bnf_sub(f, t, v, out.x);
    bnf_mul(f, out.y, rr, t);
    bnf_mul(f, t, s1, hhh);
    bnf_sub(f, out.y, out.y, t);
    bnf_mul(f, out.z, a->z, b->z);
    bnf_mul(f, out.z, out.z, h);
    *r = out;
}

/* r = k * a, com k em bytes big-endian */
static void pt_mul(const curve *c, point *r, const point *a, const uint8_t *k, size_t klen)
{
    point acc;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < klen; i++)
        for (int bit = 7; bit >= 0; bit--) {
            pt_double(c, &acc, &acc);
            if ((k[i] >> bit) & 1) pt_add(c, &acc, &acc, a);
        }
    *r = acc;
}

/* Coordenada x afim do ponto, em bytes big-endian. false se for o infinito. */
static bool pt_affine_x(const curve *c, const point *a, uint8_t *out)
{
    const bn_field *f = &c->p;
    if (bnf_is_zero(f, a->z)) return false;
    /* z^-1 = z^(p-2): passa por bytes para usar a exponenciação já existente */
    uint8_t zb[48], pb[48], eb[48], inv[48];
    fe plain, unit = { 1 }, zinv, x;
    size_t n = (size_t)c->bytes;
    bnf_mul(f, plain, a->z, unit); /* sai da forma de Montgomery */
    bnf_to_bytes(f, plain, zb, n);
    bnf_to_bytes(f, f->n, pb, n);
    memcpy(eb, pb, n);
    eb[n - 1] = (uint8_t)(eb[n - 1] - 2); /* os dois primos terminam em ...ff: sem empréstimo */
    if (bn_modexp(zb, n, eb, n, pb, n, inv)) return false;
    to_mont(f, zinv, inv, n);
    bnf_mul(f, zinv, zinv, zinv);
    bnf_mul(f, x, a->x, zinv);
    bnf_mul(f, x, x, unit);
    bnf_to_bytes(f, x, out, n);
    return true;
}

/* ---- ECDH em P-256 ---- */

/* k * a com escalar SECRETO: a cada bit faz sempre a dobra e a soma e escolhe o
 * resultado por máscara, de modo que a sequência de operações não revela os bits.
 * A chave é efêmera — usada num único aperto de mão e descartada. */
static void pt_mul_secret(const curve *c, point *r, const point *a, const uint8_t *k, size_t klen)
{
    point acc, sum;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < klen; i++)
        for (int bit = 7; bit >= 0; bit--) {
            pt_double(c, &acc, &acc);
            pt_add(c, &sum, &acc, a);
            uint32_t mask = (uint32_t)0 - (uint32_t)((k[i] >> bit) & 1);
            uint32_t *dst = (uint32_t *)&acc;
            const uint32_t *src = (const uint32_t *)&sum;
            for (size_t w = 0; w < sizeof acc / sizeof(uint32_t); w++) dst[w] ^= mask & (dst[w] ^ src[w]);
        }
    *r = acc;
    tm_wipe(&sum, sizeof sum);
}

/* Coordenadas afins (x, y) em bytes big-endian. false se for o infinito. */
static bool pt_affine(const curve *c, const point *a, uint8_t *x_out, uint8_t *y_out)
{
    const bn_field *f = &c->p;
    if (bnf_is_zero(f, a->z)) return false;
    uint8_t zb[48], pb[48], eb[48], inv[48];
    fe plain, unit = { 1 }, zinv, zinv2, zinv3, v;
    size_t n = (size_t)c->bytes;
    bnf_mul(f, plain, a->z, unit);
    bnf_to_bytes(f, plain, zb, n);
    bnf_to_bytes(f, f->n, pb, n);
    memcpy(eb, pb, n);
    eb[n - 1] = (uint8_t)(eb[n - 1] - 2);
    if (bn_modexp(zb, n, eb, n, pb, n, inv)) return false;
    to_mont(f, zinv, inv, n);
    bnf_mul(f, zinv2, zinv, zinv);
    bnf_mul(f, zinv3, zinv2, zinv);
    bnf_mul(f, v, a->x, zinv2);
    bnf_mul(f, v, v, unit);
    bnf_to_bytes(f, v, x_out, n);
    if (y_out) {
        bnf_mul(f, v, a->y, zinv3);
        bnf_mul(f, v, v, unit);
        bnf_to_bytes(f, v, y_out, n);
    }
    return true;
}

/* 0 < d < n ? */
static bool scalar_ok(const curve *c, const uint8_t *d)
{
    fe v;
    bnf_from_bytes(&c->n, v, d, (size_t)c->bytes);
    return !bnf_is_zero(&c->n, v) && bnf_cmp(&c->n, v, c->n.n) < 0;
}

int ecdh_p256_keypair(uint8_t priv[32], uint8_t pub[65])
{
    curve *c = get_curve(256);
    point g, q;
    if (!scalar_ok(c, priv)) return -1; /* quem chama sorteia de novo */
    memset(&g, 0, sizeof g);
    memcpy(g.x, c->gx, sizeof(fe));
    memcpy(g.y, c->gy, sizeof(fe));
    memcpy(g.z, c->p.one, sizeof(fe));
    pt_mul_secret(c, &q, &g, priv, 32);
    pub[0] = 0x04;
    return pt_affine(c, &q, pub + 1, pub + 33) ? 0 : -1;
}

int ecdh_p256_shared(const uint8_t priv[32], const uint8_t *peer, size_t peerlen, uint8_t out[32])
{
    curve *c = get_curve(256);
    point q, s;
    if (peerlen != 65 || peer[0] != 0x04) return -1;
    memset(&q, 0, sizeof q);
    to_mont(&c->p, q.x, peer + 1, 32);
    to_mont(&c->p, q.y, peer + 33, 32);
    memcpy(q.z, c->p.one, sizeof(fe));
    if (!on_curve(c, q.x, q.y)) return -1; /* ponto fora da curva: ataque clássico, recusar */
    pt_mul_secret(c, &s, &q, priv, 32);
    bool ok = pt_affine(c, &s, out, NULL);
    tm_wipe(&s, sizeof s);
    return ok ? 0 : -1;
}

int ecdsa_verify(int bits, const uint8_t *pub, size_t publen, const uint8_t *hash, size_t hashlen,
                 const uint8_t *r, size_t rlen, const uint8_t *s, size_t slen)
{
    curve *c = get_curve(bits);
    if (!c) return -1;
    size_t n = (size_t)c->bytes;
    if (publen != 1 + 2 * n || pub[0] != 0x04) return -1;
    while (rlen && !*r) { r++; rlen--; }
    while (slen && !*s) { s++; slen--; }
    if (!rlen || !slen || rlen > n || slen > n) return -1;

    const bn_field *fn = &c->n;
    fe rv, sv, ev, w, u1, u2, unit = { 1 };
    bnf_from_bytes(fn, rv, r, rlen);
    bnf_from_bytes(fn, sv, s, slen);
    if (bnf_cmp(fn, rv, fn->n) >= 0 || bnf_cmp(fn, sv, fn->n) >= 0) return -1;

    /* e = os bits mais à esquerda do hash, do tamanho da ordem */
    if (hashlen > n) hashlen = n;
    bnf_from_bytes(fn, ev, hash, hashlen);
    if (bnf_cmp(fn, ev, fn->n) >= 0) bnf_sub(fn, ev, ev, fn->n);

    /* w = s^-1 mod n (Fermat: s^(n-2)) */
    uint8_t sb[48], nb[48], eb[48], wb[48], u1b[48], u2b[48], xb[48];
    bnf_to_bytes(fn, sv, sb, n);
    bnf_to_bytes(fn, fn->n, nb, n);
    memcpy(eb, nb, n);
    eb[n - 1] = (uint8_t)(eb[n - 1] - 2); /* as duas ordens terminam em 0x51 e 0x73 */
    if (bn_modexp(sb, n, eb, n, nb, n, wb)) return -1;
    to_mont(fn, w, wb, n);
    bnf_mul(fn, u1, ev, w); /* (e R^0)(w R) R^-1 = e w */
    bnf_mul(fn, u2, rv, w);
    bnf_to_bytes(fn, u1, u1b, n);
    bnf_to_bytes(fn, u2, u2b, n);

    point g, q, a, b, sum;
    memset(&g, 0, sizeof g);
    memset(&q, 0, sizeof q);
    memcpy(g.x, c->gx, sizeof(fe));
    memcpy(g.y, c->gy, sizeof(fe));
    memcpy(g.z, c->p.one, sizeof(fe));
    to_mont(&c->p, q.x, pub + 1, n);
    to_mont(&c->p, q.y, pub + 1 + n, n);
    memcpy(q.z, c->p.one, sizeof(fe));
    if (!on_curve(c, q.x, q.y)) return -1;

    pt_mul(c, &a, &g, u1b, n);
    pt_mul(c, &b, &q, u2b, n);
    pt_add(c, &sum, &a, &b);
    if (!pt_affine_x(c, &sum, xb)) return -1;

    fe xv;
    bnf_from_bytes(fn, xv, xb, n);
    if (bnf_cmp(fn, xv, fn->n) >= 0) bnf_sub(fn, xv, xv, fn->n);
    (void)unit;
    return bnf_cmp(fn, xv, rv) == 0 ? 0 : -1;
}
