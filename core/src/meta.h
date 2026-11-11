/* SQL de catálogo por sabor, para as ferramentas de metadados. */
#ifndef TM_META_H
#define TM_META_H

#include "db.h"

typedef enum {
    MQ_INFO,
    MQ_SCHEMAS,
    MQ_TABLES,      /* schema?, pattern? */
    MQ_COLUMNS,     /* schema?, table */
    MQ_CONSTRAINTS, /* schema?, table */
    MQ_INDEXES,     /* schema?, table */
    MQ_SEARCH       /* pattern */
} meta_kind;

/* Monta o SQL em `sql`. Os nomes já devem ter passado por guard_ident. */
int meta_sql(tm_flavor f, meta_kind k, const char *schema, const char *table, const char *pattern,
             tm_buf *sql, tm_err *err);

/* Monta a instrução de plano de execução para `query`. */
int meta_explain(tm_flavor f, const char *query, tm_buf *sql, tm_err *err);

#endif
