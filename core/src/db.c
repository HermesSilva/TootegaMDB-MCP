/* Registro de drivers e sessões reaproveitadas (uma conexão aberta por configuração). */
#include "db.h"
#include "i18n.h"
#include "plat.h"

extern const tm_driver DRV_POSTGRES, DRV_MYSQL, DRV_MSSQL, DRV_ORACLE;

const tm_driver *db_driver(tm_flavor f)
{
    switch (f) {
    case FL_POSTGRES: return &DRV_POSTGRES;
    case FL_MYSQL: return &DRV_MYSQL;
    case FL_MSSQL: return &DRV_MSSQL;
    case FL_ORACLE: return &DRV_ORACLE;
    default: return NULL;
    }
}

typedef struct session {
    char            *key;
    const tm_driver *drv;
    tm_dbc          *dbc;
} session;

static session *g_sessions;
static size_t   g_nsessions;

static session *session_for(const tm_conn_cfg *cfg, const tm_driver *drv)
{
    char key[320];
    snprintf(key, sizeof key, "%s/%s", flavor_id(cfg->flavor), cfg->id);
    for (size_t i = 0; i < g_nsessions; i++)
        if (strcmp(g_sessions[i].key, key) == 0) return &g_sessions[i];
    g_sessions = tm_realloc(g_sessions, (g_nsessions + 1) * sizeof *g_sessions);
    session *s = &g_sessions[g_nsessions++];
    s->key = tm_strdup(key);
    s->drv = drv;
    s->dbc = NULL;
    return s;
}

static void session_drop(session *s)
{
    if (s->dbc) s->drv->close(s->dbc);
    s->dbc = NULL;
}

void db_close_all(void)
{
    for (size_t i = 0; i < g_nsessions; i++) {
        session_drop(&g_sessions[i]);
        free(g_sessions[i].key);
    }
    free(g_sessions);
    g_sessions = NULL;
    g_nsessions = 0;
}

int db_query(const tm_conn_cfg *cfg, const char *sql, bool read_only, tm_result *r, tm_err *err)
{
    const tm_driver *drv = db_driver(cfg->flavor);
    if (!drv) return tm_fail(err, TM_E_UNSUPPORTED, T(M_DRIVER_PENDING), flavor_label(cfg->flavor));
    if (read_only && guard_readonly(cfg->flavor, sql, err)) return -1;

    session *s = session_for(cfg, drv);
    tm_qopts opts = { read_only, cfg->query_timeout_ms };

    for (int attempt = 0;; attempt++) {
        bool reused = s->dbc && drv->alive(s->dbc);
        if (!reused) {
            session_drop(s);
            if (drv->connect(cfg, &s->dbc, err)) {
                s->dbc = NULL;
                return -1;
            }
        }
        int rc = drv->query(s->dbc, sql, &opts, r, err);
        if (!drv->alive(s->dbc)) session_drop(s);
        if (rc == 0) return 0;
        /* Conexão ociosa que o servidor já tinha encerrado: refaz uma vez. Só no
         * caminho de leitura — repetir uma escrita poderia aplicá-la em dobro. */
        bool stale = reused && read_only && err->code == TM_E_IO && !r->first && attempt == 0;
        if (!stale) return -1;
        tm_log(1, "stale connection to '%s', reconnecting", cfg->name);
    }
}

int db_test(const tm_conn_cfg *cfg, tm_buf *version, int *elapsed_ms, tm_err *err)
{
    const tm_driver *drv = db_driver(cfg->flavor);
    if (!drv) return tm_fail(err, TM_E_UNSUPPORTED, T(M_DRIVER_PENDING), flavor_label(cfg->flavor));
    int64_t t0 = plat_now_ms();
    tm_dbc *dbc = NULL;
    if (drv->connect(cfg, &dbc, err)) return -1;
    if (elapsed_ms) *elapsed_ms = (int)(plat_now_ms() - t0);
    if (version) buf_puts(version, drv->version(dbc));
    drv->close(dbc);
    return 0;
}
