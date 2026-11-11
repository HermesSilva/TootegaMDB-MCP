/* JSON: leitor em árvore (arena) e escritor direto em tm_buf. */
#ifndef TM_JSON_H
#define TM_JSON_H

#include "tm.h"

typedef enum { JS_NULL, JS_BOOL, JS_NUM, JS_STR, JS_ARR, JS_OBJ } js_type;

typedef struct js_val {
    js_type        t;
    struct js_val *next;  /* próximo irmão */
    struct js_val *child; /* primeiro filho (ARR/OBJ) */
    const char    *key;   /* nome, quando membro de objeto */
    const char    *s;     /* STR: texto já sem escapes; NUM: texto original */
    size_t         slen;
    double         num;
    bool           b;
} js_val;

typedef struct js_doc {
    void   *chunks; /* arena */
    js_val *root;
} js_doc;

/* Devolve 0 e preenche doc->root, ou -1 com o erro. Sempre chame js_free. */
int  js_parse(js_doc *doc, const char *text, size_t len, tm_err *err);
void js_free(js_doc *doc);

const js_val *js_get(const js_val *obj, const char *key);
const char   *js_get_str(const js_val *obj, const char *key, const char *def);
long long     js_get_int(const js_val *obj, const char *key, long long def);
bool          js_get_bool(const js_val *obj, const char *key, bool def);

/* ---- escritor ---- */
/* Texto entre aspas, escapado. Bytes que não formam UTF-8 válido viram U+FFFD,
 * para o resultado ser sempre JSON legal mesmo com dado sujo vindo do banco. */
void jw_str(tm_buf *b, const char *s, size_t n);
void jw_cstr(tm_buf *b, const char *s);       /* NULL vira null */
void jw_key(tm_buf *b, const char *key);      /* "key": */
void jw_val(tm_buf *b, const js_val *v);      /* reserializa um valor lido */
/* true se o texto é um número JSON legal (para emitir sem aspas). */
bool js_is_number(const char *s, size_t n);

#endif
