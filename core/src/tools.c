/* Ferramentas MCP: definição (com esquema de entrada) e execução. */
#include "tools.h"
#include "i18n.h"
#include "meta.h"

#define META_MAX_ROWS 5000

typedef struct tool_ctx {
    const tm_config *cfg;
    const js_val    *args;
    tm_buf          *out;
    tm_err          *err;
} tool_ctx;

/* ---- argumentos ---- */

static const char *arg_str(tool_ctx *x, const char *name, bool required)
{
    const char *s = js_get_str(x->args, name, NULL);
    if (s && !*s) s = NULL;
    if (!s && required) tm_fail(x->err, TM_E_CONFIG, T(M_ARG_REQUIRED), name);
    return s;
}

/* Nome que vai para dentro de um literal SQL: valida antes. */
static int arg_ident(tool_ctx *x, const char *name, bool required, const char **out)
{
    *out = arg_str(x, name, required);
    if (!*out) return required ? -1 : 0;
    return guard_ident(*out, x->err);
}

static const tm_conn_cfg *arg_conn(tool_ctx *x)
{
    const char *ref = arg_str(x, "connection", true);
    return ref ? cfg_find(x->cfg, ref, x->err) : NULL;
}

/* Roda um SQL de catálogo e devolve o resultado em `r` (que o chamador libera). */
static int run_meta(tool_ctx *x, const tm_conn_cfg *c, meta_kind k, const char *schema, const char *table,
                    const char *pattern, tm_result *r)
{
    tm_buf sql;
    buf_init(&sql);
    res_init(r, META_MAX_ROWS, c->max_cell);
    int rc = meta_sql(c->flavor, k, schema, table, pattern, &sql, x->err);
    if (rc == 0) rc = db_query(c, buf_cstr(&sql), true, r, x->err);
    buf_free(&sql);
    return rc;
}

static int simple_meta(tool_ctx *x, meta_kind k, const char *schema, const char *table, const char *pattern)
{
    const tm_conn_cfg *c = arg_conn(x);
    if (!c) return -1;
    tm_result r;
    int rc = run_meta(x, c, k, schema, table, pattern, &r);
    if (rc == 0) fmt_result(x->out, &r, FMT_JSON);
    res_free(&r);
    return rc;
}

/* ---- ferramentas ---- */

static int t_list_connections(tool_ctx *x)
{
    buf_puts(x->out, "{\"connections\":[");
    for (size_t i = 0; i < x->cfg->n; i++) {
        const tm_conn_cfg *c = &x->cfg->items[i];
        buf_puts(x->out, i ? ",\n{" : "\n{");
        jw_key(x->out, "name");
        jw_cstr(x->out, c->name);
        buf_puts(x->out, ",\"type\":");
        jw_cstr(x->out, flavor_id(c->flavor));
        buf_puts(x->out, ",\"host\":");
        jw_cstr(x->out, c->host);
        buf_printf(x->out, ",\"port\":%d", c->port);
        const char *db = c->database ? c->database : c->service ? c->service : c->sid;
        if (db) {
            buf_puts(x->out, ",\"database\":");
            jw_cstr(x->out, db);
        }
        if (c->environment) {
            buf_puts(x->out, ",\"environment\":");
            jw_cstr(x->out, c->environment);
        }
        buf_printf(x->out, ",\"readOnly\":%s,\"available\":%s}", c->read_only ? "true" : "false",
                   db_driver(c->flavor) ? "true" : "false");
    }
    buf_puts(x->out, x->cfg->n ? "\n]" : "]");
    if (!x->cfg->n) {
        buf_puts(x->out, ",\"hint\":");
        jw_cstr(x->out, T(M_NO_CONNECTIONS));
    }
    buf_putc(x->out, '}');
    return 0;
}

static int t_test_connection(tool_ctx *x)
{
    const tm_conn_cfg *c = arg_conn(x);
    if (!c) return -1;
    tm_buf version;
    int ms = 0;
    buf_init(&version);
    int rc = db_test(c, &version, &ms, x->err);
    if (rc == 0) {
        buf_puts(x->out, "{\"ok\":true,\"version\":");
        jw_cstr(x->out, buf_cstr(&version));
        buf_printf(x->out, ",\"elapsedMs\":%d}", ms);
    }
    buf_free(&version);
    return rc;
}

static int t_server_info(tool_ctx *x)
{
    return simple_meta(x, MQ_INFO, NULL, NULL, NULL);
}

static int t_list_schemas(tool_ctx *x)
{
    return simple_meta(x, MQ_SCHEMAS, NULL, NULL, NULL);
}

static int t_list_tables(tool_ctx *x)
{
    const char *schema, *pattern;
    if (arg_ident(x, "schema", false, &schema) || arg_ident(x, "pattern", false, &pattern)) return -1;
    return simple_meta(x, MQ_TABLES, schema, NULL, pattern);
}

static int t_search_columns(tool_ctx *x)
{
    const char *pattern;
    if (arg_ident(x, "pattern", true, &pattern)) return -1;
    return simple_meta(x, MQ_SEARCH, NULL, NULL, pattern);
}

static int t_describe_table(tool_ctx *x)
{
    static const struct {
        meta_kind   kind;
        const char *key;
    } PARTS[] = { { MQ_COLUMNS, "columns" }, { MQ_CONSTRAINTS, "constraints" }, { MQ_INDEXES, "indexes" } };
    const char *schema, *table;
    if (arg_ident(x, "table", true, &table) || arg_ident(x, "schema", false, &schema)) return -1;
    const tm_conn_cfg *c = arg_conn(x);
    if (!c) return -1;

    buf_puts(x->out, "{\"table\":");
    jw_cstr(x->out, table);
    for (size_t i = 0; i < TM_COUNT(PARTS); i++) {
        tm_result r;
        int rc = run_meta(x, c, PARTS[i].kind, schema, table, NULL, &r);
        if (rc == 0 && i == 0 && (!r.first || r.first->nrows == 0))
            rc = tm_fail(x->err, TM_E_SERVER, T(M_TABLE_NOT_FOUND), table);
        if (rc == 0) {
            buf_printf(x->out, ",\n\"%s\":", PARTS[i].key);
            fmt_rowset_json(x->out, r.first);
        }
        res_free(&r);
        if (rc) return -1;
    }
    buf_putc(x->out, '}');
    return 0;
}

static int run_sql(tool_ctx *x, const tm_conn_cfg *c, const char *sql, bool read_only)
{
    int fmt = fmt_parse(js_get_str(x->args, "format", NULL));
    if (fmt < 0) return tm_fail(x->err, TM_E_CONFIG, T(M_BAD_FORMAT), js_get_str(x->args, "format", ""));
    long long want = js_get_int(x->args, "max_rows", c->max_rows);
    if (want < 1 || want > c->max_rows) want = c->max_rows;

    tm_result r;
    res_init(&r, (int)want, c->max_cell);
    int rc = db_query(c, sql, read_only, &r, x->err);
    if (rc == 0) fmt_result(x->out, &r, (tm_format)fmt);
    res_free(&r);
    return rc;
}

/* Comando fixo nosso (não vem do modelo), fora da guarda; o resultado é descartado. */
static int internal_sql(const tm_conn_cfg *c, const char *sql, tm_err *err)
{
    tm_result r;
    res_init(&r, 1, 64);
    int rc = db_query(c, sql, false, &r, err);
    res_free(&r);
    return rc;
}

static int t_query(tool_ctx *x)
{
    const tm_conn_cfg *c = arg_conn(x);
    const char *sql = c ? arg_str(x, "sql", true) : NULL;
    return sql ? run_sql(x, c, sql, true) : -1;
}

static int t_explain(tool_ctx *x)
{
    const tm_conn_cfg *c = arg_conn(x);
    const char *sql = c ? arg_str(x, "sql", true) : NULL;
    if (!sql) return -1;
    tm_buf full;
    buf_init(&full);
    /* A consulta é julgada sozinha antes de ganhar o prefixo de plano. */
    int rc = guard_readonly(c->flavor, sql, x->err);
    if (rc == 0 && c->flavor == FL_MSSQL) {
        /* No SQL Server o plano é um modo da sessão: liga, manda a consulta (que então
         * não executa, só devolve o plano) e desliga — mesmo se a consulta falhar. */
        tm_err ignore;
        rc = internal_sql(c, "SET SHOWPLAN_TEXT ON", x->err);
        if (rc == 0) {
            rc = run_sql(x, c, sql, true);
            internal_sql(c, "SET SHOWPLAN_TEXT OFF", &ignore);
        }
    } else if (rc == 0 && c->flavor == FL_ORACLE) {
        /* No Oracle o plano é gravado numa tabela da sessão e lido em seguida. */
        size_t n = strlen(sql);
        while (n && (sql[n - 1] == ';' || sql[n - 1] == ' ' || sql[n - 1] == '\n' || sql[n - 1] == '\r')) n--;
        buf_puts(&full, "EXPLAIN PLAN FOR ");
        buf_put(&full, sql, n);
        rc = internal_sql(c, buf_cstr(&full), x->err);
        if (rc == 0) rc = run_sql(x, c, "select plan_table_output from table(dbms_xplan.display())", true);
    } else {
        if (rc == 0) rc = meta_explain(c->flavor, sql, &full, x->err);
        if (rc == 0) rc = run_sql(x, c, buf_cstr(&full), true);
    }
    buf_free(&full);
    return rc;
}

static int t_execute(tool_ctx *x)
{
    const tm_conn_cfg *c = arg_conn(x);
    const char *sql = c ? arg_str(x, "sql", true) : NULL;
    if (!sql) return -1;
    if (c->read_only) return tm_fail(x->err, TM_E_GUARD, T(M_READONLY_CONN), c->name);
    return run_sql(x, c, sql, false);
}

/* ---- tabela de ferramentas ---- */

typedef struct param {
    const char *name, *type;
    tm_msg      desc;
    bool        required;
} param;

typedef struct tool {
    const char *name;
    tm_msg      title, desc;
    bool        writes;
    int       (*run)(tool_ctx *x);
    param       params[5];
} tool;

#define P_CONN { "connection", "string", M_P_CONNECTION, true }
#define P_SQL  { "sql", "string", M_P_SQL, true }
#define P_ROWS { "max_rows", "integer", M_P_MAX_ROWS, false }
#define P_FMT  { "format", "string", M_P_FORMAT, false }

static const tool TOOLS[] = {
    { "list_connections", M_T_LIST_CONN_TITLE, M_T_LIST_CONN, false, t_list_connections, { { 0 } } },
    { "test_connection", M_T_TEST_TITLE, M_T_TEST, false, t_test_connection, { P_CONN } },
    { "server_info", M_T_INFO_TITLE, M_T_INFO, false, t_server_info, { P_CONN } },
    { "list_schemas", M_T_SCHEMAS_TITLE, M_T_SCHEMAS, false, t_list_schemas, { P_CONN } },
    { "list_tables", M_T_TABLES_TITLE, M_T_TABLES, false, t_list_tables,
      { P_CONN, { "schema", "string", M_P_SCHEMA_ALL, false }, { "pattern", "string", M_P_PATTERN, false } } },
    { "describe_table", M_T_DESCRIBE_TITLE, M_T_DESCRIBE, false, t_describe_table,
      { P_CONN, { "table", "string", M_P_TABLE, true }, { "schema", "string", M_P_SCHEMA, false } } },
    { "search_columns", M_T_SEARCH_TITLE, M_T_SEARCH, false, t_search_columns,
      { P_CONN, { "pattern", "string", M_P_PATTERN, true } } },
    { "query", M_T_QUERY_TITLE, M_T_QUERY, false, t_query, { P_CONN, P_SQL, P_ROWS, P_FMT } },
    { "explain", M_T_EXPLAIN_TITLE, M_T_EXPLAIN, false, t_explain, { P_CONN, P_SQL } },
    { "execute", M_T_EXECUTE_TITLE, M_T_EXECUTE, true, t_execute, { P_CONN, P_SQL, P_FMT } },
};

void tools_list_json(tm_buf *out)
{
    buf_puts(out, "{\"tools\":[");
    for (size_t i = 0; i < TM_COUNT(TOOLS); i++) {
        const tool *t = &TOOLS[i];
        buf_puts(out, i ? ",{" : "{");
        jw_key(out, "name");
        jw_cstr(out, t->name);
        buf_puts(out, ",\"title\":");
        jw_cstr(out, T(t->title));
        buf_puts(out, ",\"description\":");
        jw_cstr(out, T(t->desc));
        buf_puts(out, ",\"inputSchema\":{\"type\":\"object\",\"properties\":{");
        for (size_t k = 0; k < TM_COUNT(t->params) && t->params[k].name; k++) {
            const param *p = &t->params[k];
            if (k) buf_putc(out, ',');
            jw_key(out, p->name);
            buf_puts(out, "{\"type\":");
            jw_cstr(out, p->type);
            buf_puts(out, ",\"description\":");
            jw_cstr(out, T(p->desc));
            if (strcmp(p->name, "format") == 0) buf_puts(out, ",\"enum\":[\"json\",\"csv\",\"markdown\"]");
            buf_putc(out, '}');
        }
        buf_puts(out, "},\"required\":[");
        bool first = true;
        for (size_t k = 0; k < TM_COUNT(t->params) && t->params[k].name; k++) {
            if (!t->params[k].required) continue;
            if (!first) buf_putc(out, ',');
            jw_cstr(out, t->params[k].name);
            first = false;
        }
        buf_puts(out, "],\"additionalProperties\":false},\"annotations\":{\"title\":");
        jw_cstr(out, T(t->title));
        buf_printf(out, ",\"readOnlyHint\":%s,\"destructiveHint\":%s,\"idempotentHint\":%s,\"openWorldHint\":false}}",
                   t->writes ? "false" : "true", t->writes ? "true" : "false", t->writes ? "false" : "true");
    }
    buf_puts(out, "]}");
}

int tools_call(const tm_config *cfg, const char *name, const js_val *args, tm_buf *out, tm_err *err)
{
    tool_ctx x = { cfg, args, out, err };
    for (size_t i = 0; i < TM_COUNT(TOOLS); i++)
        if (strcmp(TOOLS[i].name, name) == 0) return TOOLS[i].run(&x);
    return tm_fail(err, TM_E_CONFIG, T(M_TOOL_UNKNOWN), name);
}
