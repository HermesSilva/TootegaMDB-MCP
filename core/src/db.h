/* Modelo comum aos quatro bancos: configuração, resultado, driver, guarda de leitura. */
#ifndef TM_DB_H
#define TM_DB_H

#include "json.h"
#include "tm.h"

/* ---- sabores ---- */
typedef enum { FL_POSTGRES, FL_MYSQL, FL_MSSQL, FL_ORACLE, FL_COUNT } tm_flavor;

const char *flavor_id(tm_flavor f);    /* "postgres", "mysql", "mssql", "oracle" */
const char *flavor_label(tm_flavor f); /* nome de exibição */
int         flavor_port(tm_flavor f);
int         flavor_parse(const char *s); /* aceita apelidos; -1 se desconhecido */

/* ---- configuração ---- */
typedef enum { SSL_DISABLE, SSL_PREFER, SSL_REQUIRE, SSL_VERIFY_CA, SSL_VERIFY_FULL } tm_sslmode;

typedef struct tm_conn_cfg {
    char      *id;       /* estável; liga a conexão ao segredo */
    char      *name;
    tm_flavor  flavor;
    char      *host;
    int        port;
    char      *user;
    char      *password;
    char      *database; /* banco (PG/MySQL/MSSQL) */
    char      *schema;   /* search_path (PG) / schema atual (Oracle) */
    char      *service;  /* Oracle: service name */
    char      *sid;      /* Oracle: SID */
    char      *instance; /* SQL Server: instância nomeada */
    char      *app_name;
    char      *environment; /* rótulo livre: dev, homologação, produção... */
    char      *ca_file;
    tm_sslmode ssl;
    bool       trust_cert;
    bool       read_only;
    int        connect_timeout_ms;
    int        query_timeout_ms;
    int        max_rows;
    int        max_cell;
} tm_conn_cfg;

typedef struct tm_config {
    tm_conn_cfg *items;
    size_t       n;
} tm_config;

/* Lê uma conexão de um objeto JSON; `secrets` (opcional) é um mapa id -> senha. */
int  cfg_parse_conn(const js_val *obj, const js_val *secrets, tm_conn_cfg *out, tm_err *err);
void cfg_conn_free(tm_conn_cfg *c);
int  cfg_load(tm_config *cfg, const char *path, tm_err *err);
void cfg_free(tm_config *cfg);
/* Procura por "nome" ou "tipo/nome", sem diferenciar maiúsculas. */
const tm_conn_cfg *cfg_find(const tm_config *cfg, const char *ref, tm_err *err);

/* ---- cofre de senhas ----
 * Arquivo "secrets.bin" ao lado do arquivo de conexões: um mapa id -> senha, cifrado
 * para o usuário desta máquina (ver plat_protect). É do executável, não de um cliente
 * específico: a tela de configuração grava aqui e qualquer cliente MCP usa. */
/* Carrega o mapa (objeto JSON em doc->root). -1 se não houver cofre legível. */
int secrets_load(const char *config_path, js_doc *doc);
/* Aplica alterações: `set` é um objeto id -> senha; `del`, um array de ids. */
int secrets_update(const char *config_path, const js_val *set, const js_val *del, tm_err *err);
int64_t secrets_mtime(const char *config_path);

/* Configuração viva: relê o arquivo quando ele muda em disco. */
typedef struct tm_app_cfg {
    char     *path;
    int64_t   mtime;
    int64_t   secrets_mtime;
    bool      loaded;
    tm_config cfg;
} tm_app_cfg;

/* Devolve a configuração atual, ou NULL com o erro. `changed` (opcional) indica
 * que houve recarga — quem chama deve então descartar as conexões abertas. */
const tm_config *app_cfg_get(tm_app_cfg *a, bool *changed, tm_err *err);

/* ---- resultado ----
 * Todo driver converte os valores para texto UTF-8 e informa a natureza do dado,
 * para a saída preservar número/booleano/nulo sem cada driver conhecer JSON. */
typedef enum { CK_NULL, CK_TEXT, CK_NUM, CK_BOOL } tm_ckind;

typedef struct tm_col {
    char *name;
    char *type;
} tm_col;

typedef struct tm_rowset {
    struct tm_rowset *next;
    tm_col           *cols;
    int               ncols;
    tm_buf            cells;    /* por célula: natureza (1), tamanho (4, LE), bytes */
    size_t            nrows;
    long long         affected; /* -1 = não se aplica */
    char              tag[64];  /* etiqueta do comando, quando o banco informa */
    bool              done;
} tm_rowset;

typedef struct tm_result {
    tm_rowset *first, *last;
    size_t     total_rows;   /* linhas guardadas, somando os conjuntos */
    size_t     skipped_rows; /* linhas descartadas por passar do limite */
    bool       truncated;
    bool       cells_cut;
    bool       in_row;       /* a linha atual está sendo guardada? */
    int        max_rows, max_cell;
    tm_buf     notices;      /* avisos do servidor, um por linha */
} tm_result;

void       res_init(tm_result *r, int max_rows, int max_cell);
void       res_free(tm_result *r);
void       res_reset(tm_result *r); /* esvazia, mantendo os limites: para repetir uma consulta */
tm_rowset *res_begin_set(tm_result *r, int ncols);
void       res_set_col(tm_rowset *rs, int i, const char *name, size_t nlen, const char *type);
/* Abre uma linha. false = passou do limite: a linha é contada e descartada. */
bool       res_row_begin(tm_result *r);
void       res_cell(tm_result *r, tm_ckind kind, const void *p, size_t n);
/* Dado binário: sai como texto "0x..." em hexadecimal, cortado no limite da célula. */
void       res_cell_bin(tm_result *r, const void *p, size_t n);
/* Fecha o comando em curso (linhas afetadas / etiqueta). */
void       res_command(tm_result *r, long long affected, const char *tag);
void       res_notice(tm_result *r, const char *text);

typedef enum { FMT_JSON, FMT_CSV, FMT_MARKDOWN } tm_format;
int  fmt_parse(const char *s); /* -1 se desconhecido */
void fmt_result(tm_buf *out, const tm_result *r, tm_format f);
/* Um conjunto só, como objeto JSON {"columns":[...],"rows":[...]}. */
void fmt_rowset_json(tm_buf *out, const tm_rowset *rs);

/* ---- driver ---- */
typedef struct tm_dbc tm_dbc; /* conexão aberta; cada driver define a sua */

typedef struct tm_qopts {
    bool read_only;  /* caminho de leitura: instrução única em transação somente leitura */
    int  timeout_ms;
} tm_qopts;

typedef struct tm_driver {
    tm_flavor flavor;
    int  (*connect)(const tm_conn_cfg *cfg, tm_dbc **out, tm_err *err);
    int  (*query)(tm_dbc *c, const char *sql, const tm_qopts *o, tm_result *r, tm_err *err);
    bool (*alive)(tm_dbc *c);
    const char *(*version)(tm_dbc *c);
    void (*close)(tm_dbc *c);
} tm_driver;

const tm_driver *db_driver(tm_flavor f); /* NULL se o driver não está nesta versão */

/* ---- sessões: uma conexão aberta por configuração, reaproveitada ---- */
int  db_query(const tm_conn_cfg *cfg, const char *sql, bool read_only, tm_result *r, tm_err *err);
int  db_test(const tm_conn_cfg *cfg, tm_buf *version, int *elapsed_ms, tm_err *err);
void db_close_all(void);

/* ---- guarda de leitura (camada léxica) ---- */
int guard_readonly(tm_flavor f, const char *sql, tm_err *err);
/* Recusa nomes que não podem ir com segurança para dentro de um literal SQL. */
int guard_ident(const char *name, tm_err *err);

#endif
