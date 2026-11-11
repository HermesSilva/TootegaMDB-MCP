/* Camada de plataforma: tudo que difere entre Windows e Linux fica aqui. */
#ifndef TM_PLAT_H
#define TM_PLAT_H

#include "tm.h"

int         plat_init(void);            /* Winsock, stdio binário */
int64_t     plat_now_ms(void);          /* relógio monotônico */
int         plat_random(void *p, size_t n); /* aleatório do SO; 0 = ok */
const char *plat_lang(void);            /* "pt" ou "en", pelo idioma do SO */
const char *plat_getenv(const char *name);
char       *plat_default_config_path(void); /* alocado */
int64_t     plat_file_mtime(const char *path); /* -1 se não existir */
int         plat_read_file(const char *path, tm_buf *out, tm_err *err);

/* Proteção de segredos em repouso, amarrada ao usuário desta máquina.
 * Windows: DPAPI (só a mesma conta de usuário decifra). Linux: cifra com chave
 * derivada da máquina e do usuário — a barreira real ali é a permissão 0600 do arquivo. */
int plat_protect(const void *in, size_t n, tm_buf *out);
int plat_unprotect(const void *in, size_t n, tm_buf *out);
/* Grava de forma atômica um arquivo legível só pelo dono. 0 = ok. */
int plat_write_private(const char *path, const void *p, size_t n);

/* Carrega no repositório as autoridades certificadoras do sistema operacional. */
struct x509_store;
void plat_system_roots(struct x509_store *store);

/* ---- transporte: TCP com prazo, leitura com buffer; TLS entra por cima ---- */
struct tm_tls;

typedef struct tm_io {
    intptr_t       fd;
    int64_t        deadline; /* instante limite (plat_now_ms); 0 = sem limite */
    bool           broken;   /* após erro de E/S a conexão não serve mais */
    struct tm_tls *tls;
    size_t         rpos, rlen;
    uint8_t        rbuf[16384];
} tm_io;

int  io_connect(tm_io *io, const char *host, int port, int timeout_ms, tm_err *err);
void io_set_timeout(tm_io *io, int timeout_ms); /* prazo para as próximas operações */
int  io_write(tm_io *io, const void *p, size_t n, tm_err *err);
int  io_read(tm_io *io, void *p, size_t n, tm_err *err); /* exatamente n bytes */
void io_close(tm_io *io);

/* Pergunta e resposta por UDP (um datagrama cada). Devolve bytes recebidos, ou -1. */
int plat_udp_query(const char *host, int port, const void *req, size_t reqlen, void *resp, size_t cap,
                   int timeout_ms);

/* Acesso cru ao socket, usado pela camada TLS. Devolvem bytes, ou -1. */
int io_raw_send(tm_io *io, const void *p, size_t n, tm_err *err);
int io_raw_recv(tm_io *io, void *p, size_t n, tm_err *err);

#endif
