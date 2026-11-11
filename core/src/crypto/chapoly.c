/* ChaCha20-Poly1305 (RFC 8439). */
#include "curve.h"

typedef unsigned __int128 u128;

static uint32_t le32(const uint8_t *p)
{
    return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p)
{
    return le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL(d, 16); c += d; b ^= c; b = ROTL(b, 12); \
    a += b; d ^= a; d = ROTL(d, 8);  c += d; b ^= c; b = ROTL(b, 7)

static void chacha_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce + 4 * i);
    memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        out[4 * i] = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

static void chacha_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in,
                       size_t n, uint8_t *out)
{
    uint8_t ks[64];
    while (n) {
        chacha_block(key, nonce, counter++, ks);
        size_t take = n < 64 ? n : 64;
        for (size_t i = 0; i < take; i++) out[i] = in[i] ^ ks[i];
        in += take;
        out += take;
        n -= take;
    }
    tm_wipe(ks, sizeof ks);
}

/* ---- Poly1305 em limbos de 44/44/42 bits ---- */

#define M44 0xFFFFFFFFFFFULL
#define M42 0x3FFFFFFFFFFULL

typedef struct {
    uint64_t r[3], h[3], pad[2];
    uint8_t  buf[16];
    size_t   fill;
} poly;

static void poly_init(poly *p, const uint8_t key[32])
{
    uint64_t t0 = le64(key), t1 = le64(key + 8);
    p->r[0] = t0 & 0xFFC0FFFFFFFULL;
    p->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xFFFFFC0FFFFULL;
    p->r[2] = (t1 >> 24) & 0x00FFFFFFC0FULL;
    p->h[0] = p->h[1] = p->h[2] = 0;
    p->pad[0] = le64(key + 16);
    p->pad[1] = le64(key + 24);
    p->fill = 0;
}

static void poly_block(poly *p, const uint8_t *m, uint64_t hibit)
{
    uint64_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2];
    uint64_t s1 = r1 * 20, s2 = r2 * 20;
    uint64_t t0 = le64(m), t1 = le64(m + 8);
    uint64_t h0 = p->h[0] + (t0 & M44);
    uint64_t h1 = p->h[1] + (((t0 >> 44) | (t1 << 20)) & M44);
    uint64_t h2 = p->h[2] + (((t1 >> 24) & M42) | hibit);
    u128 d0 = (u128)h0 * r0 + (u128)h1 * s2 + (u128)h2 * s1;
    u128 d1 = (u128)h0 * r1 + (u128)h1 * r0 + (u128)h2 * s2;
    u128 d2 = (u128)h0 * r2 + (u128)h1 * r1 + (u128)h2 * r0;
    uint64_t c = (uint64_t)(d0 >> 44);
    h0 = (uint64_t)d0 & M44;
    d1 += c;
    c = (uint64_t)(d1 >> 44);
    h1 = (uint64_t)d1 & M44;
    d2 += c;
    c = (uint64_t)(d2 >> 42);
    h2 = (uint64_t)d2 & M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    p->h[0] = h0;
    p->h[1] = h1;
    p->h[2] = h2;
}

static void poly_update(poly *p, const uint8_t *m, size_t n)
{
    while (n) {
        size_t take = 16 - p->fill;
        if (take > n) take = n;
        memcpy(p->buf + p->fill, m, take);
        p->fill += take;
        m += take;
        n -= take;
        if (p->fill == 16) {
            poly_block(p, p->buf, 1ULL << 40);
            p->fill = 0;
        }
    }
}

static void poly_finish(poly *p, uint8_t tag[16])
{
    if (p->fill) {
        p->buf[p->fill] = 1;
        memset(p->buf + p->fill + 1, 0, 15 - p->fill);
        poly_block(p, p->buf, 0);
    }
    uint64_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], c;
    c = h1 >> 44; h1 &= M44;
    h2 += c; c = h2 >> 42; h2 &= M42;
    h0 += c * 5; c = h0 >> 44; h0 &= M44;
    h1 += c; c = h1 >> 44; h1 &= M44;
    h2 += c; c = h2 >> 42; h2 &= M42;
    h0 += c * 5; c = h0 >> 44; h0 &= M44;
    h1 += c;
    /* h - p: se não der negativo, é o valor reduzido */
    uint64_t g0 = h0 + 5;
    c = g0 >> 44; g0 &= M44;
    uint64_t g1 = h1 + c;
    c = g1 >> 44; g1 &= M44;
    uint64_t g2 = h2 + c - (1ULL << 42);
    uint64_t mask = (g2 >> 63) - 1; /* tudo 1 se g2 >= 0 */
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    uint64_t t0 = p->pad[0], t1 = p->pad[1];
    h0 += t0 & M44; c = h0 >> 44; h0 &= M44;
    h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c; c = h1 >> 44; h1 &= M44;
    h2 += ((t1 >> 24) & M42) + c; h2 &= M42;
    put64(tag, h0 | (h1 << 44));
    put64(tag + 8, (h1 >> 20) | (h2 << 24));
    tm_wipe(p, sizeof *p);
}

static void aead_tag(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                     const uint8_t *cipher, size_t n, uint8_t tag[16])
{
    static const uint8_t zeros[16] = { 0 };
    uint8_t block[64], lens[16];
    poly p;
    chacha_block(key, nonce, 0, block); /* a chave do Poly1305 é o primeiro bloco */
    poly_init(&p, block);
    poly_update(&p, aad, aadlen);
    if (aadlen % 16) poly_update(&p, zeros, 16 - aadlen % 16);
    poly_update(&p, cipher, n);
    if (n % 16) poly_update(&p, zeros, 16 - n % 16);
    put64(lens, aadlen);
    put64(lens + 8, n);
    poly_update(&p, lens, 16);
    poly_finish(&p, tag);
    tm_wipe(block, sizeof block);
}

void chapoly_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                  const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16])
{
    chacha_xor(key, nonce, 1, in, n, out);
    aead_tag(key, nonce, aad, aadlen, out, n, tag);
}

int chapoly_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                 const uint8_t *in, size_t n, const uint8_t tag[16], uint8_t *out)
{
    uint8_t expect[16];
    aead_tag(key, nonce, aad, aadlen, in, n, expect);
    if (!ct_equal(expect, tag, 16)) {
        memset(out, 0, n);
        return -1;
    }
    chacha_xor(key, nonce, 1, in, n, out);
    return 0;
}
