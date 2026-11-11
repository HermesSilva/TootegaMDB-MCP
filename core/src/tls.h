/* TLS 1.3 (RFC 8446), cliente — implementação própria. */
#ifndef TM_TLS_H
#define TM_TLS_H

#include "db.h"
#include "plat.h"

typedef struct tm_tls tm_tls;

/* Transporte por baixo do TLS. O padrão é o socket; o SQL Server (TDS 7.x) embrulha
 * o aperto de mão em pacotes próprios e troca para o socket depois. */
typedef int (*tls_send_fn)(void *ctx, const uint8_t *p, size_t n, tm_err *err); /* manda tudo; 0 = ok */
typedef int (*tls_recv_fn)(void *ctx, uint8_t *p, size_t n, tm_err *err);       /* bytes (>0) ou -1 */

typedef struct tls_opts {
    const char *host;        /* nome para SNI e para conferir o certificado */
    tm_sslmode  mode;        /* require: só cifra; verify-ca: cadeia; verify-full: cadeia + nome */
    const char *ca_file;     /* PEM com as autoridades; NULL = as do sistema */
    const char *alpn;        /* protocolo de aplicação a anunciar, ou NULL */
    tls_send_fn send;        /* NULL = socket */
    tls_recv_fn recv;
    void       *ctx;
} tls_opts;

/* Faz o aperto de mão sobre a conexão aberta. Em caso de sucesso, io passa a cifrar tudo. */
int  tls_start(tm_io *io, const tls_opts *o, tm_err *err);
/* Volta a usar o socket diretamente como transporte (após aperto de mão embrulhado). */
void tls_use_socket(tm_tls *t);
int  tls_write(tm_tls *t, const void *p, size_t n, tm_err *err);
int  tls_read(tm_tls *t, void *p, size_t cap, tm_err *err); /* bytes lidos (>0), ou -1 */
void tls_free(tm_tls *t);

/* Opções de TLS a partir da configuração de uma conexão. */
void tls_opts_from_cfg(tls_opts *o, const tm_conn_cfg *cfg);
/* No modo "prefer", a falha `err` de uma tentativa com TLS justifica tentar em claro? */
bool tls_prefer_fallback(const tm_conn_cfg *cfg, const tm_err *err);

#endif
