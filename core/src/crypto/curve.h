/* X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439) e ECDSA P-256/P-384 (só verificação). */
#ifndef TM_CURVE_H
#define TM_CURVE_H

#include "../tm.h"
#include "hash.h"

/* out = scalar * point (coordenada u). Devolve -1 se o resultado for todo zero. */
int  x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_public(uint8_t out[32], const uint8_t scalar[32]);

/* ECDH em P-256 (secp256r1): par de chaves efêmero e segredo compartilhado.
 * Chave pública = ponto não comprimido, 65 bytes. Devolvem 0 em caso de sucesso. */
int ecdh_p256_keypair(uint8_t priv[32], uint8_t pub[65]);
int ecdh_p256_shared(const uint8_t priv[32], const uint8_t *peer, size_t peerlen, uint8_t out[32]);

/* AEAD ChaCha20-Poly1305 com nonce de 12 bytes e etiqueta de 16. */
void chapoly_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                  const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16]);
int  chapoly_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                  const uint8_t *in, size_t n, const uint8_t tag[16], uint8_t *out);

/* ECDSA: verifica (r, s) sobre o hash. curve: 256 ou 384. Chave pública = ponto
 * não comprimido (0x04 || X || Y). Tudo em big-endian. 0 = assinatura válida. */
int ecdsa_verify(int curve, const uint8_t *pub, size_t publen, const uint8_t *hash, size_t hashlen,
                 const uint8_t *r, size_t rlen, const uint8_t *s, size_t slen);

#endif
