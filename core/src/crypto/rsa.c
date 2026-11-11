/* RSA de chave pública, inteiros grandes (Montgomery) e leitura de DER/PEM.
 * Só há operações com dados públicos aqui (cifrar, verificar), então tempo
 * constante não é requisito: nenhuma chave privada passa por este código. */
#include "rsa.h"
#include "../plat.h"

/* ---- DER / PEM ---- */

bool der_next(tm_rd *r, int *tag, tm_rd *content)
{
    if (rd_left(r) == 0) return false;
    int t = rd_u8(r);
    size_t len = rd_u8(r);
    if (len & 0x80) {
        size_t nb = len & 0x7F;
        if (nb == 0 || nb > 4) {
            r->bad = true;
            return false;
        }
        len = 0;
        while (nb--) len = (len << 8) | rd_u8(r);
    }
    const uint8_t *p = rd_bytes(r, len);
    if (!p && len) return false;
    if (r->bad) return false;
    rd_init(content, p ? p : r->p, len);
    *tag = t;
    return true;
}

bool der_expect(tm_rd *r, int tag, tm_rd *content)
{
    int got;
    if (!der_next(r, &got, content) || got != tag) {
        r->bad = true;
        return false;
    }
    return true;
}

int pem_decode(const char *pem, size_t len, uint8_t *out, size_t cap)
{
    const char *end = pem + len;
    const char *begin = NULL;
    for (const char *p = pem; p + 10 <= end; p++)
        if (memcmp(p, "-----BEGIN", 10) == 0) {
            begin = memchr(p, '\n', (size_t)(end - p));
            break;
        }
    if (!begin) return -1;
    begin++;
    const char *stop = NULL;
    for (const char *p = begin; p + 8 <= end; p++)
        if (memcmp(p, "-----END", 8) == 0) {
            stop = p;
            break;
        }
    if (!stop) return -1;
    return tm_b64_dec(out, cap, begin, (size_t)(stop - begin));
}

/* ---- inteiros grandes ---- */

#define BN_LIMBS (BN_MAX_BYTES / 4 + 1)
typedef uint32_t limb;

static void bn_from_bytes(limb *w, int k, const uint8_t *b, size_t n)
{
    memset(w, 0, (size_t)k * sizeof *w);
    for (size_t i = 0; i < n; i++) {
        size_t bit = (n - 1 - i);
        w[bit / 4] |= (limb)b[i] << (8 * (bit % 4));
    }
}

static void bn_to_bytes(const limb *w, int k, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        size_t byte = n - 1 - i;
        out[i] = byte / 4 < (size_t)k ? (uint8_t)(w[byte / 4] >> (8 * (byte % 4))) : 0;
    }
}

static int bn_cmp(const limb *a, const limb *b, int k)
{
    for (int i = k - 1; i >= 0; i--)
        if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
    return 0;
}

static void bn_sub(limb *r, const limb *a, const limb *b, int k)
{
    uint64_t borrow = 0;
    for (int i = 0; i < k; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (limb)d;
        borrow = (d >> 32) & 1;
    }
}

/* x = 2x mod n, com x < n */
static void bn_double_mod(limb *x, const limb *n, int k)
{
    limb carry = 0;
    for (int i = 0; i < k; i++) {
        limb next = x[i] >> 31;
        x[i] = (x[i] << 1) | carry;
        carry = next;
    }
    if (carry || bn_cmp(x, n, k) >= 0) bn_sub(x, x, n, k);
}

/* Multiplicação de Montgomery (CIOS): r = a*b*R^-1 mod n, com R = 2^(32k). */
static void mont_mul(limb *r, const limb *a, const limb *b, const limb *n, int k, limb n0)
{
    limb t[BN_LIMBS + 2];
    memset(t, 0, ((size_t)k + 2) * sizeof *t);
    for (int i = 0; i < k; i++) {
        uint64_t c = 0;
        for (int j = 0; j < k; j++) {
            uint64_t uv = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + c;
            t[j] = (limb)uv;
            c = uv >> 32;
        }
        uint64_t uv = (uint64_t)t[k] + c;
        t[k] = (limb)uv;
        t[k + 1] = (limb)(uv >> 32);

        limb m = t[0] * n0;
        uv = (uint64_t)t[0] + (uint64_t)m * n[0];
        c = uv >> 32;
        for (int j = 1; j < k; j++) {
            uv = (uint64_t)t[j] + (uint64_t)m * n[j] + c;
            t[j - 1] = (limb)uv;
            c = uv >> 32;
        }
        uv = (uint64_t)t[k] + c;
        t[k - 1] = (limb)uv;
        t[k] = t[k + 1] + (limb)(uv >> 32);
    }
    if (t[k] || bn_cmp(t, n, k) >= 0) bn_sub(r, t, n, k);
    else memcpy(r, t, (size_t)k * sizeof *r);
}

int bn_modexp(const uint8_t *base, size_t baselen, const uint8_t *exp, size_t explen,
              const uint8_t *mod, size_t modlen, uint8_t *out)
{
    size_t outlen = modlen;
    while (modlen && !*mod) { mod++; modlen--; }
    while (baselen && !*base) { base++; baselen--; }
    if (!modlen || modlen > BN_MAX_BYTES || !(mod[modlen - 1] & 1) || baselen > modlen) return -1;

    int k = (int)((modlen + 3) / 4);
    limb n[BN_LIMBS], b[BN_LIMBS], one[BN_LIMBS], r2[BN_LIMBS], acc[BN_LIMBS], bm[BN_LIMBS], unit[BN_LIMBS];
    bn_from_bytes(n, k, mod, modlen);
    bn_from_bytes(b, k, base, baselen);
    if (bn_cmp(b, n, k) >= 0) return -1;

    /* n0 = -n^-1 mod 2^32 (Newton: cada passo dobra os bits corretos) */
    limb inv = n[0];
    for (int i = 0; i < 5; i++) inv *= 2 - n[0] * inv;
    limb n0 = (limb)0 - inv;

    /* R mod n e R^2 mod n por duplicações sucessivas a partir de 1 */
    memset(r2, 0, (size_t)k * sizeof *r2);
    r2[0] = 1;
    if (k == 1 && n[0] == 1) r2[0] = 0;
    for (int i = 0; i < 32 * k; i++) bn_double_mod(r2, n, k);
    memcpy(one, r2, (size_t)k * sizeof *one);
    for (int i = 0; i < 32 * k; i++) bn_double_mod(r2, n, k);

    mont_mul(bm, b, r2, n, k, n0);
    memcpy(acc, one, (size_t)k * sizeof *acc);
    for (size_t i = 0; i < explen; i++)
        for (int bit = 7; bit >= 0; bit--) {
            mont_mul(acc, acc, acc, n, k, n0);
            if ((exp[i] >> bit) & 1) mont_mul(acc, acc, bm, n, k, n0);
        }
    memset(unit, 0, (size_t)k * sizeof *unit);
    unit[0] = 1;
    mont_mul(acc, acc, unit, n, k, n0);
    bn_to_bytes(acc, k, out, outlen);
    return 0;
}

/* ---- campo modular para a curva elíptica ---- */

int bnf_init(bn_field *f, const uint8_t *mod, size_t len)
{
    if (!len || len > BN_EC_LIMBS * 4 || !(mod[len - 1] & 1)) return -1;
    f->k = (int)((len + 3) / 4);
    bn_from_bytes(f->n, f->k, mod, len);
    limb inv = f->n[0];
    for (int i = 0; i < 5; i++) inv *= 2 - f->n[0] * inv;
    f->n0 = (limb)0 - inv;
    memset(f->rr, 0, sizeof f->rr);
    f->rr[0] = 1;
    for (int i = 0; i < 32 * f->k; i++) bn_double_mod(f->rr, f->n, f->k);
    memcpy(f->one, f->rr, sizeof f->one);
    for (int i = 0; i < 32 * f->k; i++) bn_double_mod(f->rr, f->n, f->k);
    return 0;
}

void bnf_from_bytes(const bn_field *f, uint32_t *w, const uint8_t *b, size_t n)
{
    while (n > (size_t)f->k * 4) { b++; n--; } /* descarta zeros à esquerda em excesso */
    bn_from_bytes(w, f->k, b, n);
}

void bnf_to_bytes(const bn_field *f, const uint32_t *w, uint8_t *out, size_t n)
{
    bn_to_bytes(w, f->k, out, n);
}

void bnf_mul(const bn_field *f, uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    mont_mul(r, a, b, f->n, f->k, f->n0);
}

void bnf_add(const bn_field *f, uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    uint64_t carry = 0;
    for (int i = 0; i < f->k; i++) {
        uint64_t s = (uint64_t)a[i] + b[i] + carry;
        r[i] = (limb)s;
        carry = s >> 32;
    }
    if (carry || bn_cmp(r, f->n, f->k) >= 0) bn_sub(r, r, f->n, f->k);
}

void bnf_sub(const bn_field *f, uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < f->k; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (limb)d;
        borrow = (d >> 32) & 1;
    }
    if (borrow) { /* ficou negativo: soma o módulo de volta */
        uint64_t carry = 0;
        for (int i = 0; i < f->k; i++) {
            uint64_t s = (uint64_t)r[i] + f->n[i] + carry;
            r[i] = (limb)s;
            carry = s >> 32;
        }
    }
}

bool bnf_is_zero(const bn_field *f, const uint32_t *a)
{
    limb acc = 0;
    for (int i = 0; i < f->k; i++) acc |= a[i];
    return acc == 0;
}

int bnf_cmp(const bn_field *f, const uint32_t *a, const uint32_t *b)
{
    return bn_cmp(a, b, f->k);
}

/* ---- chave pública ---- */

static int take_uint(tm_rd *seq, uint8_t *out, size_t cap, size_t *len)
{
    tm_rd v;
    if (!der_expect(seq, DER_INTEGER, &v)) return -1;
    const uint8_t *p = v.p;
    size_t n = v.len;
    while (n > 1 && !*p) { p++; n--; }
    if (!n || n > cap) return -1;
    memcpy(out, p, n);
    *len = n;
    return 0;
}

int rsa_pub_from_der(rsa_pub *k, const uint8_t *der, size_t len)
{
    tm_rd top, seq, inner, bits;
    int tag;
    rd_init(&top, der, len);
    if (!der_expect(&top, DER_SEQUENCE, &seq)) return -1;

    /* SubjectPublicKeyInfo começa com outra SEQUENCE (o algoritmo); PKCS#1, com o INTEGER. */
    tm_rd probe = seq;
    if (!der_next(&probe, &tag, &inner)) return -1;
    if (tag == DER_SEQUENCE) {
        seq = probe;
        if (!der_expect(&seq, DER_BITSTRING, &bits)) return -1;
        if (rd_u8(&bits) != 0) return -1; /* bits sem uso */
        if (!der_expect(&bits, DER_SEQUENCE, &seq)) return -1;
    }
    if (take_uint(&seq, k->n, sizeof k->n, &k->nlen)) return -1;
    if (take_uint(&seq, k->e, sizeof k->e, &k->elen)) return -1;
    if (k->nlen < 128 || !(k->n[k->nlen - 1] & 1)) return -1; /* mínimo de 1024 bits, ímpar */
    return 0;
}

int rsa_pub_from_pem(rsa_pub *k, const char *pem, size_t len)
{
    uint8_t der[BN_MAX_BYTES + 128];
    int n = pem_decode(pem, len, der, sizeof der);
    return n > 0 ? rsa_pub_from_der(k, der, (size_t)n) : -1;
}

static int rsa_public(const rsa_pub *k, const uint8_t *in, uint8_t *out)
{
    return bn_modexp(in, k->nlen, k->e, k->elen, k->n, k->nlen, out);
}

/* MGF1 (RFC 8017, B.2.1): máscara de tamanho arbitrário a partir de uma semente. */
static void mgf1_xor(const tm_hash_alg *h, const uint8_t *seed, size_t seedlen, uint8_t *data, size_t n)
{
    uint8_t d[TM_HASH_MAX_DIGEST], ctr[4];
    for (uint32_t c = 0; n; c++) {
        tm_hash_ctx x;
        ctr[0] = (uint8_t)(c >> 24);
        ctr[1] = (uint8_t)(c >> 16);
        ctr[2] = (uint8_t)(c >> 8);
        ctr[3] = (uint8_t)c;
        hash_init(h, &x);
        hash_update(h, &x, seed, seedlen);
        hash_update(h, &x, ctr, 4);
        hash_final(h, &x, d);
        size_t take = n < h->digest_len ? n : h->digest_len;
        for (size_t i = 0; i < take; i++) data[i] ^= d[i];
        data += take;
        n -= take;
    }
}

int rsa_oaep_encrypt(const rsa_pub *k, const tm_hash_alg *h, const uint8_t *msg, size_t mlen, uint8_t *out)
{
    size_t hl = h->digest_len, kl = k->nlen;
    if (kl < 2 * hl + 2 || mlen > kl - 2 * hl - 2) return -1;
    uint8_t em[BN_MAX_BYTES];
    uint8_t *seed = em + 1, *db = em + 1 + hl;
    size_t dblen = kl - hl - 1;

    em[0] = 0;
    if (plat_random(seed, hl)) return -1;
    hash_once(h, "", 0, db); /* lHash do rótulo vazio */
    memset(db + hl, 0, dblen - hl - mlen - 1);
    db[dblen - mlen - 1] = 0x01;
    memcpy(db + dblen - mlen, msg, mlen);
    mgf1_xor(h, seed, hl, db, dblen);
    mgf1_xor(h, db, dblen, seed, hl);
    int rc = rsa_public(k, em, out);
    tm_wipe(em, sizeof em);
    return rc;
}

static const struct {
    const tm_hash_alg *alg;
    uint8_t            prefix[19];
    size_t             len;
} DIGEST_INFO[] = {
    { &TM_SHA1, { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 }, 15 },
    { &TM_SHA256,
      { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
      19 },
    { &TM_SHA384,
      { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 },
      19 },
    { &TM_SHA512,
      { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
      19 },
};

int rsa_pkcs1_verify(const rsa_pub *k, const tm_hash_alg *h, const uint8_t *digest, const uint8_t *sig, size_t siglen)
{
    uint8_t em[BN_MAX_BYTES], want[BN_MAX_BYTES];
    size_t kl = k->nlen, hl = h->digest_len;
    if (siglen != kl) return -1;
    const uint8_t *prefix = NULL;
    size_t plen = 0;
    for (size_t i = 0; i < TM_COUNT(DIGEST_INFO); i++)
        if (DIGEST_INFO[i].alg == h) {
            prefix = DIGEST_INFO[i].prefix;
            plen = DIGEST_INFO[i].len;
        }
    if (!prefix || kl < plen + hl + 11) return -1;
    if (rsa_public(k, sig, em)) return -1;
    /* Monta o bloco esperado inteiro e compara: nada de "interpretar" o recebido. */
    size_t pad = kl - plen - hl - 3;
    want[0] = 0x00;
    want[1] = 0x01;
    memset(want + 2, 0xFF, pad);
    want[2 + pad] = 0x00;
    memcpy(want + 3 + pad, prefix, plen);
    memcpy(want + 3 + pad + plen, digest, hl);
    return ct_equal(em, want, kl) ? 0 : -1;
}

int rsa_pss_verify(const rsa_pub *k, const tm_hash_alg *h, const uint8_t *digest, const uint8_t *sig, size_t siglen)
{
    uint8_t em_full[BN_MAX_BYTES], db[BN_MAX_BYTES], hcalc[TM_HASH_MAX_DIGEST];
    static const uint8_t zeros[8] = { 0 };
    size_t kl = k->nlen, hl = h->digest_len;
    if (siglen != kl || rsa_public(k, sig, em_full)) return -1;

    /* emBits = bits do módulo - 1 */
    size_t modbits = kl * 8;
    for (uint8_t top = k->n[0]; !(top & 0x80); top <<= 1) modbits--;
    size_t embits = modbits - 1, emlen = (embits + 7) / 8;
    const uint8_t *em = em_full;
    if (emlen < kl) {
        if (em[0] != 0) return -1;
        em++;
    }
    if (emlen < hl + 2 || em[emlen - 1] != 0xBC) return -1;
    size_t dblen = emlen - hl - 1;
    const uint8_t *hrecv = em + dblen;
    uint8_t topmask = (uint8_t)(0xFF >> (8 * emlen - embits));
    if (em[0] & ~topmask) return -1;

    memcpy(db, em, dblen);
    mgf1_xor(h, hrecv, hl, db, dblen);
    db[0] &= topmask;
    size_t i = 0;
    while (i < dblen && db[i] == 0) i++;
    if (i == dblen || db[i] != 0x01) return -1;
    const uint8_t *salt = db + i + 1;
    size_t saltlen = dblen - i - 1;

    tm_hash_ctx x;
    hash_init(h, &x);
    hash_update(h, &x, zeros, 8);
    hash_update(h, &x, digest, hl);
    hash_update(h, &x, salt, saltlen);
    hash_final(h, &x, hcalc);
    return ct_equal(hcalc, hrecv, hl) ? 0 : -1;
}
