/* Hashes, HMAC, PBKDF2 e HKDF — implementação própria. */
#ifndef TM_HASH_H
#define TM_HASH_H

#include "../tm.h"

#define TM_HASH_MAX_DIGEST 64
#define TM_HASH_MAX_BLOCK  128

typedef struct tm_hash_ctx {
    union {
        uint32_t w32[8];
        uint64_t w64[8];
    } h;
    uint64_t nbytes;
    size_t   fill;
    uint8_t  block[TM_HASH_MAX_BLOCK];
} tm_hash_ctx;

typedef struct tm_hash_alg {
    const char *name;
    size_t      digest_len, block_len;
    void (*init)(tm_hash_ctx *c);
    void (*compress)(tm_hash_ctx *c, const uint8_t *block);
    void (*final)(tm_hash_ctx *c, uint8_t *out);
} tm_hash_alg;

extern const tm_hash_alg TM_MD5, TM_SHA1, TM_SHA256, TM_SHA384, TM_SHA512;

void hash_init(const tm_hash_alg *a, tm_hash_ctx *c);
void hash_update(const tm_hash_alg *a, tm_hash_ctx *c, const void *data, size_t n);
void hash_final(const tm_hash_alg *a, tm_hash_ctx *c, uint8_t *out);
void hash_once(const tm_hash_alg *a, const void *data, size_t n, uint8_t *out);

typedef struct tm_hmac {
    const tm_hash_alg *alg;
    tm_hash_ctx        inner, outer;
} tm_hmac;

void hmac_init(tm_hmac *h, const tm_hash_alg *a, const void *key, size_t klen);
void hmac_update(tm_hmac *h, const void *data, size_t n);
void hmac_final(tm_hmac *h, uint8_t *out);
void hmac_once(const tm_hash_alg *a, const void *key, size_t klen, const void *data, size_t n, uint8_t *out);

void pbkdf2(const tm_hash_alg *a, const void *pw, size_t pwlen, const void *salt, size_t slen,
            uint32_t iters, uint8_t *out, size_t outlen);

void hkdf_extract(const tm_hash_alg *a, const void *salt, size_t slen, const void *ikm, size_t ilen,
                  uint8_t *prk);
void hkdf_expand(const tm_hash_alg *a, const uint8_t *prk, const void *info, size_t infolen,
                 uint8_t *out, size_t outlen);

/* Comparação em tempo constante; true se iguais. */
bool ct_equal(const void *a, const void *b, size_t n);

#endif
