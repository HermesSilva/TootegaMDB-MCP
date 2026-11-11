/* TootegaMDB-MCP — base comum do núcleo.
 * C11 puro, sem bibliotecas de terceiros. */
#ifndef TM_H
#define TM_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TM_NAME    "tootega-mdb"
#define TM_TITLE   "Tootega Multi-Database MCP"
/* Versão = produto (aqui) + número do build (arquivo BUILD, somado a cada build de
 * distribuição por scripts/build-dist.sh e passado pelo Makefile). */
#define TM_VERSION_BASE "1.0.0"
#ifndef TM_BUILD
#  define TM_BUILD 0
#endif
#define TM_STR2(x) #x
#define TM_STR(x)  TM_STR2(x)
#define TM_VERSION TM_VERSION_BASE "." TM_STR(TM_BUILD)

#if defined(__MINGW32__)
#  define TM_PRINTF(a, b) __attribute__((format(gnu_printf, a, b)))
#elif defined(__GNUC__)
#  define TM_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#  define TM_PRINTF(a, b)
#endif

#define TM_COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* ---- memória (aborta em falta de memória: não há recuperação útil) ---- */
void *tm_alloc(size_t n);
void *tm_zalloc(size_t n);
void *tm_realloc(void *p, size_t n);
char *tm_strdup(const char *s);
char *tm_strndup(const char *s, size_t n);
/* Zera memória sensível sem o compilador poder eliminar a escrita. */
void  tm_wipe(void *p, size_t n);

/* ---- erro ---- */
enum {
    TM_E_GENERIC = 1,
    TM_E_IO,        /* rede/transporte: a conexão não é mais confiável */
    TM_E_TIMEOUT,
    TM_E_PROTOCOL,  /* resposta inesperada do servidor */
    TM_E_AUTH,
    TM_E_SERVER,    /* erro devolvido pelo banco (SQL inválido etc.) */
    TM_E_GUARD,     /* barrado pela guarda de leitura */
    TM_E_CONFIG,
    TM_E_UNSUPPORTED
};

typedef struct tm_err {
    int  code;
    char msg[768];
    char sqlstate[12];
} tm_err;

/* Preenche o erro e devolve -1 (para `return tm_fail(...)`). */
int  tm_fail(tm_err *e, int code, const char *fmt, ...) TM_PRINTF(3, 4);
void tm_err_clear(tm_err *e);

/* ---- buffer de bytes crescente ---- */
typedef struct tm_buf {
    uint8_t *p;
    size_t   len, cap;
} tm_buf;

void  buf_init(tm_buf *b);
void  buf_free(tm_buf *b);
void  buf_reset(tm_buf *b);
void  buf_reserve(tm_buf *b, size_t extra);
void  buf_put(tm_buf *b, const void *data, size_t n);
void  buf_putc(tm_buf *b, int c);
void  buf_puts(tm_buf *b, const char *s);
void  buf_printf(tm_buf *b, const char *fmt, ...) TM_PRINTF(2, 3);
void  buf_fill(tm_buf *b, int c, size_t n);
void  buf_u16be(tm_buf *b, uint16_t v);
void  buf_u32be(tm_buf *b, uint32_t v);
void  buf_u16le(tm_buf *b, uint16_t v);
void  buf_u32le(tm_buf *b, uint32_t v);
void  buf_u64le(tm_buf *b, uint64_t v);
/* Garante um NUL depois do conteúdo (sem contar em len) e devolve como texto. */
char *buf_cstr(tm_buf *b);

/* ---- leitor de bytes com checagem de limite ----
 * Qualquer leitura além do fim marca `bad` e devolve zeros; quem consome confere
 * `bad` uma vez no final. Entrada de rede é sempre tratada como hostil. */
typedef struct tm_rd {
    const uint8_t *p;
    size_t         len, pos;
    bool           bad;
} tm_rd;

void           rd_init(tm_rd *r, const void *p, size_t len);
size_t         rd_left(const tm_rd *r);
uint8_t        rd_u8(tm_rd *r);
uint16_t       rd_u16be(tm_rd *r);
uint32_t       rd_u32be(tm_rd *r);
uint16_t       rd_u16le(tm_rd *r);
uint32_t       rd_u32le(tm_rd *r);
uint64_t       rd_u64le(tm_rd *r);
const uint8_t *rd_bytes(tm_rd *r, size_t n);          /* NULL se faltar */
const char    *rd_cstr(tm_rd *r, size_t *len);        /* texto terminado em NUL */
void           rd_skip(tm_rd *r, size_t n);

/* ---- texto ---- */
int    tm_stricmp(const char *a, const char *b);
int    tm_strnicmp(const char *a, const char *b, size_t n);
bool   tm_streq(const char *a, const char *b);        /* tolera NULL */
/* Corta em limite de caractere UTF-8: maior n' <= n que não parte um caractere. */
size_t tm_utf8_cut(const char *s, size_t len, size_t n);
void   tm_hex(char *out, const uint8_t *in, size_t n); /* minúsculas, com NUL */
/* Conversões de codificação; o destino é sempre acrescentado ao buffer. */
void   tm_utf16le_to_utf8(tm_buf *out, const uint8_t *p, size_t nbytes);
void   tm_utf8_to_utf16le(tm_buf *out, const char *s, size_t n);
void   tm_cp1252_to_utf8(tm_buf *out, const uint8_t *p, size_t n);
/* Dias desde 1970-01-01 -> ano, mês, dia (calendário gregoriano proléptico). */
void   tm_civil_from_days(int64_t days, int *y, int *m, int *d);
size_t tm_b64_enc(char *out, const uint8_t *in, size_t n);            /* com NUL */
int    tm_b64_dec(uint8_t *out, size_t cap, const char *in, size_t n); /* bytes ou -1 */

/* ---- log (stderr; stdout é reservado ao protocolo MCP) ---- */
extern int tm_log_level; /* 0 erro, 1 info, 2 debug */
void tm_log(int level, const char *fmt, ...) TM_PRINTF(2, 3);

#endif
