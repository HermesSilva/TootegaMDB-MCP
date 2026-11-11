/* Vetores de teste publicados (RFCs / NIST) para cada primitiva. */
#include "../tools.h"
#include "aes.h"
#include "curve.h"
#include "hash.h"
#include "rsa.h"

static int g_fail;

static void check(const char *what, const uint8_t *got, size_t n, const char *expect_hex)
{
    char hex[2 * TM_HASH_MAX_DIGEST + 1];
    tm_hex(hex, got, n);
    bool ok = strcmp(hex, expect_hex) == 0;
    printf("%-28s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("    got    %s\n    expect %s\n", hex, expect_hex);
        g_fail++;
    }
}

int crypto_selftest(void)
{
    uint8_t d[TM_HASH_MAX_DIGEST];
    static const char two_blocks[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    g_fail = 0;

    hash_once(&TM_MD5, "abc", 3, d);
    check("MD5", d, 16, "900150983cd24fb0d6963f7d28e17f72");
    hash_once(&TM_SHA1, "abc", 3, d);
    check("SHA-1", d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    hash_once(&TM_SHA256, "abc", 3, d);
    check("SHA-256", d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    hash_once(&TM_SHA256, two_blocks, sizeof two_blocks - 1, d);
    check("SHA-256 (2 blocks)", d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    hash_once(&TM_SHA384, "abc", 3, d);
    check("SHA-384", d, 48,
          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
          "8086072ba1e7cc2358baeca134c825a7");
    hash_once(&TM_SHA512, "abc", 3, d);
    check("SHA-512", d, 64,
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    hmac_once(&TM_SHA256, "key", 3, "The quick brown fox jumps over the lazy dog", 43, d);
    check("HMAC-SHA-256", d, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    hmac_once(&TM_MD5, "key", 3, "The quick brown fox jumps over the lazy dog", 43, d);
    check("HMAC-MD5", d, 16, "80070713463e7749b90c2dc24911e275");

    pbkdf2(&TM_SHA256, "password", 8, "salt", 4, 1, d, 32);
    check("PBKDF2-SHA-256 (1)", d, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    pbkdf2(&TM_SHA256, "password", 8, "salt", 4, 4096, d, 32);
    check("PBKDF2-SHA-256 (4096)", d, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

    /* RFC 5869, caso 1 */
    {
        uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
        char hex[85];
        memset(ikm, 0x0b, sizeof ikm);
        for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
        for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
        hkdf_extract(&TM_SHA256, salt, sizeof salt, ikm, sizeof ikm, prk);
        hkdf_expand(&TM_SHA256, prk, info, sizeof info, okm, sizeof okm);
        tm_hex(hex, okm, sizeof okm);
        bool ok = strcmp(hex, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                              "34007208d5b887185865") == 0;
        printf("%-28s %s\n", "HKDF-SHA-256", ok ? "ok" : "FAIL");
        if (!ok) g_fail++;
    }

    /* Inteiros grandes: 4^13 mod 497 = 445, e Fermat (2^(p-1) mod p = 1) em primos conhecidos. */
    {
        uint8_t out[66], p[66], e[66], one[66];
        static const uint8_t b4 = 4, e13 = 13, m497[2] = { 0x01, 0xF1 }, two = 2;
        bn_modexp(&b4, 1, &e13, 1, m497, 2, out);
        check("modexp (small)", out, 2, "01bd");

        memset(p, 0xFF, 32); /* 2^255 - 19 */
        p[0] = 0x7F;
        p[31] = 0xED;
        memcpy(e, p, 32);
        e[31] = 0xEC;
        memset(one, 0, sizeof one);
        one[31] = 1;
        bn_modexp(&two, 1, e, 32, p, 32, out);
        check("modexp (2^255-19)", out, 32, "0000000000000000000000000000000000000000000000000000000000000001");

        memset(p, 0xFF, 66); /* 2^521 - 1 */
        p[0] = 0x01;
        memcpy(e, p, 66);
        e[65] = 0xFE;
        bn_modexp(&two, 1, e, 66, p, 66, out);
        bool ok = out[65] == 1;
        for (int i = 0; i < 65; i++) ok = ok && out[i] == 0;
        printf("%-28s %s\n", "modexp (2^521-1)", ok ? "ok" : "FAIL");
        if (!ok) g_fail++;
    }

    /* AES: FIPS 197 (apêndice C) e GCM (caso de teste 2 do NIST). */
    {
        uint8_t key[32], pt[16], ct[16], back[16], tag[16], zero[16] = { 0 };
        aes_key k;
        static const char *const expect[3] = { "69c4e0d86a7b0430d8cdb78070b4c55a",
                                               "dda97ca4864cdfe06eaf70a0ec0d7191",
                                               "8ea2b7ca516745bfeafc49904b496089" };
        static const char *const names[3] = { "AES-128", "AES-192", "AES-256" };
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(i * 0x11);
        for (int i = 0; i < 3; i++) {
            aes_init(&k, key, 16 + 8 * (size_t)i);
            aes_encrypt_block(&k, pt, ct);
            check(names[i], ct, 16, expect[i]);
            aes_decrypt_block(&k, ct, back);
            if (memcmp(back, pt, 16) != 0) {
                printf("%-28s FAIL\n", "AES decrypt");
                g_fail++;
            }
        }
        aes_init(&k, zero, 16);
        aes_gcm_seal(&k, zero, NULL, 0, zero, 16, ct, tag);
        check("AES-GCM ciphertext", ct, 16, "0388dace60b6a392f328c2b971b2fe78");
        check("AES-GCM tag", tag, 16, "ab6e47d42cec13bdf53a67b21257bddf");
        tag[0] ^= 1;
        bool rejected = aes_gcm_open(&k, zero, NULL, 0, ct, 16, tag, back) != 0;
        printf("%-28s %s\n", "AES-GCM rejects bad tag", rejected ? "ok" : "FAIL");
        if (!rejected) g_fail++;
    }

    /* X25519 (RFC 7748, 5.2) e ChaCha20-Poly1305 (RFC 8439, 2.8.2). */
    {
        static const uint8_t scalar[32] = { 0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
                                            0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
                                            0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 };
        static const uint8_t point[32] = { 0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1,
                                           0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3,
                                           0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c };
        uint8_t out[32];
        x25519(out, scalar, point);
        check("X25519", out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        /* Alice e Bob da RFC 7748, 6.1: os dois lados chegam ao mesmo segredo */
        static const uint8_t alice[32] = { 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                                           0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                                           0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a };
        x25519_public(out, alice);
        check("X25519 public key", out, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        uint8_t key[32], ct[114], tag[16], back[114];
        static const uint8_t nonce[12] = { 0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
        static const uint8_t aad[12] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
        static const char msg[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                                  "for the future, sunscreen would be it.";
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
        chapoly_seal(key, nonce, aad, sizeof aad, (const uint8_t *)msg, 114, ct, tag);
        check("ChaCha20-Poly1305 text", ct, 16, "d31a8d34648e60db7b86afbc53ef7ec2");
        check("ChaCha20-Poly1305 tag", tag, 16, "1ae10b594f09e26a7e902ecbd0600691");
        bool ok = chapoly_open(key, nonce, aad, sizeof aad, ct, 114, tag, back) == 0 && memcmp(back, msg, 114) == 0;
        ct[5] ^= 1;
        ok = ok && chapoly_open(key, nonce, aad, sizeof aad, ct, 114, tag, back) != 0;
        printf("%-28s %s\n", "ChaCha20-Poly1305 open", ok ? "ok" : "FAIL");
        if (!ok) g_fail++;
    }

    /* ECDSA P-256 com SHA-256 (RFC 6979, A.2.5, mensagem "sample"). */
    {
        static const char *const PUB = "04"
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
        static const char *const R = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
        static const char *const S = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
        uint8_t pub[65], r[32], s[32], h[32];
        const char *src[3] = { PUB, R, S };
        uint8_t *dst[3] = { pub, r, s };
        for (int k = 0; k < 3; k++)
            for (size_t i = 0; src[k][2 * i]; i++) {
                unsigned v;
                sscanf(src[k] + 2 * i, "%2x", &v);
                dst[k][i] = (uint8_t)v;
            }
        hash_once(&TM_SHA256, "sample", 6, h);
        bool ok = ecdsa_verify(256, pub, 65, h, 32, r, 32, s, 32) == 0;
        printf("%-28s %s\n", "ECDSA P-256 verify", ok ? "ok" : "FAIL");
        if (!ok) g_fail++;
        h[0] ^= 1;
        bool rejects = ecdsa_verify(256, pub, 65, h, 32, r, 32, s, 32) != 0;
        printf("%-28s %s\n", "ECDSA rejects altered hash", rejects ? "ok" : "FAIL");
        if (!rejects) g_fail++;
    }

    printf("%s\n", g_fail ? "SELFTEST FAILED" : "selftest passed");
    return g_fail ? 1 : 0;
}
