/* AES-128/192/256 (FIPS 197), modos CBC e GCM — implementação própria. */
#ifndef TM_AES_H
#define TM_AES_H

#include "../tm.h"

typedef struct aes_key {
    uint8_t rk[240]; /* chaves de rodada: 16 * (rodadas + 1) */
    int     rounds;
} aes_key;

/* keylen: 16, 24 ou 32 bytes. Devolve -1 para outro tamanho. */
int  aes_init(aes_key *k, const uint8_t *key, size_t keylen);
void aes_encrypt_block(const aes_key *k, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(const aes_key *k, const uint8_t in[16], uint8_t out[16]);

/* CBC sem preenchimento: n deve ser múltiplo de 16. in e out podem coincidir. */
void aes_cbc_encrypt(const aes_key *k, const uint8_t iv[16], const uint8_t *in, size_t n, uint8_t *out);
void aes_cbc_decrypt(const aes_key *k, const uint8_t iv[16], const uint8_t *in, size_t n, uint8_t *out);

/* GCM com nonce de 12 bytes e etiqueta de 16 (o perfil usado pelo TLS).
 * aes_gcm_open devolve 0 se a etiqueta confere, -1 caso contrário (e zera a saída). */
void aes_gcm_seal(const aes_key *k, const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                  const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16]);
int  aes_gcm_open(const aes_key *k, const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                  const uint8_t *in, size_t n, const uint8_t tag[16], uint8_t *out);

#endif
