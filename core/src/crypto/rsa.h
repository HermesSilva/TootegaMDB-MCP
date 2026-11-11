/* RSA (só operações de chave pública), inteiros grandes e leitura de DER/PEM. */
#ifndef TM_RSA_H
#define TM_RSA_H

#include "../tm.h"
#include "hash.h"

/* ---- DER (ASN.1) ---- */
enum {
    DER_INTEGER = 0x02,
    DER_BITSTRING = 0x03,
    DER_OCTETSTRING = 0x04,
    DER_NULL = 0x05,
    DER_OID = 0x06,
    DER_UTF8 = 0x0C,
    DER_SEQUENCE = 0x30,
    DER_SET = 0x31
};

/* Lê o próximo elemento: etiqueta e conteúdo. false no fim ou em erro (r->bad). */
bool der_next(tm_rd *r, int *tag, tm_rd *content);
/* Lê um elemento exigindo a etiqueta. */
bool der_expect(tm_rd *r, int tag, tm_rd *content);
/* Decodifica o primeiro bloco PEM do texto para DER. Devolve bytes, ou -1. */
int  pem_decode(const char *pem, size_t len, uint8_t *out, size_t cap);

/* ---- inteiros grandes: exponenciação modular (módulo ímpar) ---- */
#define BN_MAX_BYTES 1024 /* até 8192 bits */

/* out = base^exp mod mod. Todos big-endian; out tem modlen bytes. 0 = ok. */
int bn_modexp(const uint8_t *base, size_t baselen, const uint8_t *exp, size_t explen,
              const uint8_t *mod, size_t modlen, uint8_t *out);

/* Aritmética modular de Montgomery exposta para a curva elíptica (ec.c).
 * Valores em limbos de 32 bits, do menos para o mais significativo. */
#define BN_EC_LIMBS 12 /* até 384 bits */
typedef struct bn_field {
    uint32_t n[BN_EC_LIMBS], rr[BN_EC_LIMBS], one[BN_EC_LIMBS];
    uint32_t n0;
    int      k;
} bn_field;

int  bnf_init(bn_field *f, const uint8_t *mod, size_t len);         /* módulo ímpar, big-endian */
void bnf_from_bytes(const bn_field *f, uint32_t *w, const uint8_t *b, size_t n);
void bnf_to_bytes(const bn_field *f, const uint32_t *w, uint8_t *out, size_t n);
void bnf_mul(const bn_field *f, uint32_t *r, const uint32_t *a, const uint32_t *b); /* a*b*R^-1 */
void bnf_add(const bn_field *f, uint32_t *r, const uint32_t *a, const uint32_t *b);
void bnf_sub(const bn_field *f, uint32_t *r, const uint32_t *a, const uint32_t *b);
bool bnf_is_zero(const bn_field *f, const uint32_t *a);
int  bnf_cmp(const bn_field *f, const uint32_t *a, const uint32_t *b);

/* ---- RSA ---- */
typedef struct rsa_pub {
    uint8_t n[BN_MAX_BYTES];
    size_t  nlen; /* tamanho do módulo em bytes, sem zeros à esquerda */
    uint8_t e[8];
    size_t  elen;
} rsa_pub;

/* Chave em DER: SubjectPublicKeyInfo ou RSAPublicKey (PKCS#1). */
int rsa_pub_from_der(rsa_pub *k, const uint8_t *der, size_t len);
int rsa_pub_from_pem(rsa_pub *k, const char *pem, size_t len);
/* RSAES-OAEP (MGF1 com o mesmo hash, rótulo vazio). out tem k->nlen bytes. */
int rsa_oaep_encrypt(const rsa_pub *k, const tm_hash_alg *h, const uint8_t *msg, size_t mlen, uint8_t *out);
/* Verificação de assinatura: 0 = válida. `digest` é o hash da mensagem. */
int rsa_pkcs1_verify(const rsa_pub *k, const tm_hash_alg *h, const uint8_t *digest, const uint8_t *sig, size_t siglen);
int rsa_pss_verify(const rsa_pub *k, const tm_hash_alg *h, const uint8_t *digest, const uint8_t *sig, size_t siglen);

#endif
