/* X25519 (RFC 7748): troca de chaves em Curve25519.
 * Campo GF(2^255 - 19) em cinco limbos de 51 bits; escada de Montgomery em tempo
 * constante (a troca condicional não depende de desvio nem de índice secreto). */
#include "curve.h"

typedef uint64_t fe[5];
typedef unsigned __int128 u128;

#define MASK51 ((1ULL << 51) - 1)

static uint64_t load64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void fe_frombytes(fe h, const uint8_t *s)
{
    h[0] = load64(s) & MASK51;
    h[1] = (load64(s + 6) >> 3) & MASK51;
    h[2] = (load64(s + 12) >> 6) & MASK51;
    h[3] = (load64(s + 19) >> 1) & MASK51;
    h[4] = (load64(s + 24) >> 12) & MASK51;
}

static void fe_carry(fe h)
{
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < 4; i++) {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK51;
        }
        h[0] += 19 * (h[4] >> 51);
        h[4] &= MASK51;
    }
}

static void fe_tobytes(uint8_t *s, const fe in)
{
    fe h;
    memcpy(h, in, sizeof(fe));
    fe_carry(h);
    /* redução final: se h >= p, subtrai p (calcula h + 19 e vê se passa de 2^255) */
    uint64_t q = (h[0] + 19) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;
    h[0] += 19 * q;
    for (int i = 0; i < 4; i++) {
        h[i + 1] += h[i] >> 51;
        h[i] &= MASK51;
    }
    h[4] &= MASK51;
    uint64_t w[4] = { h[0] | (h[1] << 51), (h[1] >> 13) | (h[2] << 38), (h[2] >> 26) | (h[3] << 25),
                      (h[3] >> 39) | (h[4] << 12) };
    for (int i = 0; i < 4; i++)
        for (int k = 0; k < 8; k++) s[8 * i + k] = (uint8_t)(w[i] >> (8 * k));
}

static void fe_add(fe h, const fe a, const fe b)
{
    for (int i = 0; i < 5; i++) h[i] = a[i] + b[i];
}

/* h = a - b, somando 2p antes para nunca ficar negativo */
static void fe_sub(fe h, const fe a, const fe b)
{
    h[0] = a[0] + 0xFFFFFFFFFFFDAULL - b[0];
    for (int i = 1; i < 5; i++) h[i] = a[i] + 0xFFFFFFFFFFFFEULL - b[i];
}

static void fe_mul(fe h, const fe a, const fe b)
{
    u128 t[5];
    uint64_t b1 = b[1] * 19, b2 = b[2] * 19, b3 = b[3] * 19, b4 = b[4] * 19;
    t[0] = (u128)a[0] * b[0] + (u128)a[1] * b4 + (u128)a[2] * b3 + (u128)a[3] * b2 + (u128)a[4] * b1;
    t[1] = (u128)a[0] * b[1] + (u128)a[1] * b[0] + (u128)a[2] * b4 + (u128)a[3] * b3 + (u128)a[4] * b2;
    t[2] = (u128)a[0] * b[2] + (u128)a[1] * b[1] + (u128)a[2] * b[0] + (u128)a[3] * b4 + (u128)a[4] * b3;
    t[3] = (u128)a[0] * b[3] + (u128)a[1] * b[2] + (u128)a[2] * b[1] + (u128)a[3] * b[0] + (u128)a[4] * b4;
    t[4] = (u128)a[0] * b[4] + (u128)a[1] * b[3] + (u128)a[2] * b[2] + (u128)a[3] * b[1] + (u128)a[4] * b[0];
    uint64_t c = 0;
    for (int i = 0; i < 5; i++) {
        t[i] += c;
        h[i] = (uint64_t)t[i] & MASK51;
        c = (uint64_t)(t[i] >> 51);
    }
    h[0] += c * 19;
    h[1] += h[0] >> 51;
    h[0] &= MASK51;
}

static void fe_mul_small(fe h, const fe a, uint64_t k)
{
    u128 c = 0;
    for (int i = 0; i < 5; i++) {
        u128 t = (u128)a[i] * k + c;
        h[i] = (uint64_t)t & MASK51;
        c = t >> 51;
    }
    h[0] += (uint64_t)c * 19;
    h[1] += h[0] >> 51;
    h[0] &= MASK51;
}

/* z^(p-2): inverso pelo pequeno teorema de Fermat */
static void fe_invert(fe out, const fe z)
{
    fe acc, base;
    memcpy(base, z, sizeof(fe));
    memset(acc, 0, sizeof(fe));
    acc[0] = 1;
    /* p - 2 = 2^255 - 21: bits 0, 1 e 3 ligados, bits 2 e 4 desligados, 5..254 ligados */
    for (int bit = 0; bit < 255; bit++) {
        if (bit != 2 && bit != 4) fe_mul(acc, acc, base);
        fe_mul(base, base, base);
    }
    memcpy(out, acc, sizeof(fe));
}

static void fe_cswap(fe a, fe b, uint64_t swap)
{
    uint64_t mask = 0 - swap;
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

int x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t e[32], u[32];
    fe x1, x2, z2, x3, z3, a, aa, b, bb, ee, c, d, da, cb, t;
    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    memcpy(u, point, 32);
    u[31] &= 127;

    fe_frombytes(x1, u);
    memset(x2, 0, sizeof(fe));
    x2[0] = 1;
    memset(z2, 0, sizeof(fe));
    memcpy(x3, x1, sizeof(fe));
    memset(z3, 0, sizeof(fe));
    z3[0] = 1;

    uint64_t swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(a, x2, z2);
        fe_mul(aa, a, a);
        fe_sub(b, x2, z2);
        fe_mul(bb, b, b);
        fe_sub(ee, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);
        fe_add(t, da, cb);
        fe_mul(x3, t, t);
        fe_sub(t, da, cb);
        fe_mul(t, t, t);
        fe_mul(z3, x1, t);
        fe_mul(x2, aa, bb);
        fe_mul_small(t, ee, 121665);
        fe_add(t, aa, t);
        fe_mul(z2, ee, t);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
    tm_wipe(e, sizeof e);

    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc ? 0 : -1; /* ponto de ordem pequena: segredo todo zero, recusar */
}

void x25519_public(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t base[32] = { 9 };
    x25519(out, scalar, base);
}
