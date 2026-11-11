/* Certificados X.509: leitura, verificação de assinatura, cadeia e nome do host. */
#ifndef TM_X509_H
#define TM_X509_H

#include "../tm.h"
#include "rsa.h"

typedef enum { XK_OTHER, XK_RSA, XK_EC256, XK_EC384 } x509_key;
typedef enum {
    XS_OTHER, XS_RSA_SHA1, XS_RSA_SHA256, XS_RSA_SHA384, XS_RSA_SHA512,
    XS_PSS_SHA256, XS_PSS_SHA384, XS_PSS_SHA512, XS_ECDSA_SHA256, XS_ECDSA_SHA384, XS_ECDSA_SHA512
} x509_sig;

typedef struct x509 {
    const uint8_t *der;      size_t len;
    const uint8_t *tbs;      size_t tbs_len;      /* parte assinada */
    const uint8_t *issuer;   size_t issuer_len;   /* nomes, em DER cru (comparação exata) */
    const uint8_t *subject;  size_t subject_len;
    const uint8_t *sig;      size_t sig_len;
    const uint8_t *san;      size_t san_len;      /* conteúdo da extensão subjectAltName */
    x509_sig       sig_alg;
    x509_key       key_type;
    rsa_pub        rsa;
    uint8_t        ec[97];   size_t ec_len;       /* ponto não comprimido */
    int64_t        not_before, not_after;         /* segundos desde 1970 */
    bool           is_ca;
} x509;

int x509_parse(x509 *c, const uint8_t *der, size_t len);

/* Verifica uma assinatura do TLS 1.3 (CertificateVerify) com a chave do certificado.
 * scheme = código SignatureScheme. 0 = válida; 1 = esquema não suportado; -1 = inválida. */
int x509_verify_tls(const x509 *c, unsigned scheme, const uint8_t *msg, size_t msglen, const uint8_t *sig,
                    size_t siglen);

/* Repositório de autoridades confiáveis: certificados em DER, um após o outro. */
typedef struct x509_store {
    tm_buf data; /* por entrada: tamanho (4, LE) + DER */
    int    count;
} x509_store;

void x509_store_init(x509_store *s);
void x509_store_free(x509_store *s);
void x509_store_add_der(x509_store *s, const uint8_t *der, size_t len);
int  x509_store_add_pem(x509_store *s, const char *pem, size_t len); /* quantos entraram */
/* Autoridades do sistema operacional. Devolve quantas foram carregadas. */
int  x509_store_load_system(x509_store *s);

typedef struct x509_blob {
    const uint8_t *p;
    size_t         len;
} x509_blob;

/* Valida a cadeia apresentada pelo servidor (certs[0] é o do servidor) contra o
 * repositório. host NULL = não confere o nome. 0 = ok; -1 com o motivo em err. */
int x509_validate(const x509_blob *certs, int n, const x509_store *store, const char *host, tm_err *err);

#endif
