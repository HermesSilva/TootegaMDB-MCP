#include "db.h"
#include "i18n.h"
#include "plat.h"

/* ---- sabores ---- */

static const struct {
    const char *id, *label;
    int         port;
} FLAVORS[FL_COUNT] = {
    [FL_POSTGRES] = { "postgres", "PostgreSQL", 5432 },
    [FL_MYSQL] = { "mysql", "MySQL", 3306 },
    [FL_MSSQL] = { "mssql", "SQL Server", 1433 },
    [FL_ORACLE] = { "oracle", "Oracle", 1521 },
};

const char *flavor_id(tm_flavor f)
{
    return FLAVORS[f].id;
}

const char *flavor_label(tm_flavor f)
{
    return FLAVORS[f].label;
}

int flavor_port(tm_flavor f)
{
    return FLAVORS[f].port;
}

int flavor_parse(const char *s)
{
    static const struct {
        const char *alias;
        tm_flavor   f;
    } ALIASES[] = {
        { "postgresql", FL_POSTGRES }, { "pg", FL_POSTGRES }, { "pgsql", FL_POSTGRES },
        { "mariadb", FL_MYSQL },       { "sqlserver", FL_MSSQL }, { "tds", FL_MSSQL },
        { "ora", FL_ORACLE },
    };
    if (!s) return -1;
    for (int f = 0; f < FL_COUNT; f++)
        if (tm_stricmp(s, FLAVORS[f].id) == 0) return f;
    for (size_t i = 0; i < TM_COUNT(ALIASES); i++)
        if (tm_stricmp(s, ALIASES[i].alias) == 0) return ALIASES[i].f;
    return -1;
}

/* ---- conexão ---- */

static char *dup_str(const js_val *obj, const char *key)
{
    const char *s = js_get_str(obj, key, NULL);
    return (s && *s) ? tm_strdup(s) : NULL;
}

static int clamp(long long v, int lo, int hi)
{
    return v < lo ? lo : v > hi ? hi : (int)v;
}

static tm_sslmode parse_ssl(const char *s)
{
    static const char *const names[] = { "disable", "prefer", "require", "verify-ca", "verify-full" };
    if (s)
        for (size_t i = 0; i < TM_COUNT(names); i++)
            if (tm_stricmp(s, names[i]) == 0) return (tm_sslmode)i;
    return SSL_PREFER;
}

/* Senha: "${env:NOME}" lê do ambiente; senão vale o texto; senão o mapa de segredos. */
static char *resolve_password(const js_val *obj, const js_val *secrets, const char *id)
{
    const char *pw = js_get_str(obj, "password", NULL);
    if (pw && *pw) {
        size_t n = strlen(pw);
        if (n > 7 && strncmp(pw, "${env:", 6) == 0 && pw[n - 1] == '}') {
            char *name = tm_strndup(pw + 6, n - 7);
            const char *val = plat_getenv(name);
            free(name);
            return tm_strdup(val);
        }
        return tm_strdup(pw);
    }
    if (secrets && id) return tm_strdup(js_get_str(secrets, id, NULL));
    return NULL;
}

int cfg_parse_conn(const js_val *obj, const js_val *secrets, tm_conn_cfg *c, tm_err *err)
{
    memset(c, 0, sizeof *c);
    if (!obj || obj->t != JS_OBJ) return tm_fail(err, TM_E_CONFIG, "%s", T(M_CFG_SHAPE));
    const char *name = js_get_str(obj, "name", "");
    const char *type = js_get_str(obj, "type", "");
    int f = flavor_parse(type);
    if (f < 0) return tm_fail(err, TM_E_CONFIG, T(M_CFG_FLAVOR), name, type);

    c->flavor = (tm_flavor)f;
    c->name = tm_strdup(name);
    c->id = dup_str(obj, "id");
    if (!c->id) c->id = tm_strdup(name);
    c->host = dup_str(obj, "host");
    if (!c->host) c->host = tm_strdup("localhost");
    c->port = clamp(js_get_int(obj, "port", flavor_port(c->flavor)), 0, 65535);
    if (!c->port) c->port = flavor_port(c->flavor);
    c->user = dup_str(obj, "user");
    c->password = resolve_password(obj, secrets, c->id);
    c->database = dup_str(obj, "database");
    c->schema = dup_str(obj, "schema");
    c->service = dup_str(obj, "serviceName");
    c->sid = dup_str(obj, "sid");
    c->instance = dup_str(obj, "instance");
    c->app_name = dup_str(obj, "applicationName");
    c->environment = dup_str(obj, "environment");
    c->ca_file = dup_str(obj, "caFile");
    c->ssl = parse_ssl(js_get_str(obj, "sslMode", NULL));
    c->trust_cert = js_get_bool(obj, "trustServerCertificate", false);
    c->read_only = js_get_bool(obj, "readOnly", true);
    c->connect_timeout_ms = clamp(js_get_int(obj, "connectTimeout", 10), 1, 600) * 1000;
    c->query_timeout_ms = clamp(js_get_int(obj, "queryTimeout", 30), 1, 3600) * 1000;
    c->max_rows = clamp(js_get_int(obj, "maxRows", 500), 1, 100000);
    c->max_cell = clamp(js_get_int(obj, "maxCellChars", 4000), 16, 1000000);
    return 0;
}

void cfg_conn_free(tm_conn_cfg *c)
{
    if (c->password) tm_wipe(c->password, strlen(c->password));
    free(c->id);
    free(c->name);
    free(c->host);
    free(c->user);
    free(c->password);
    free(c->database);
    free(c->schema);
    free(c->service);
    free(c->sid);
    free(c->instance);
    free(c->app_name);
    free(c->environment);
    free(c->ca_file);
    memset(c, 0, sizeof *c);
}

void cfg_free(tm_config *cfg)
{
    for (size_t i = 0; i < cfg->n; i++) cfg_conn_free(&cfg->items[i]);
    free(cfg->items);
    cfg->items = NULL;
    cfg->n = 0;
}

/* ---- cofre de senhas ---- */

static const char SECRETS_MAGIC[8] = { 'T', 'M', 'D', 'B', 'S', 'E', 'C', '1' };

static char *secrets_path(const char *config_path)
{
    const char *slash = NULL;
    for (const char *p = config_path; *p; p++)
        if (*p == '/' || *p == '\\') slash = p;
    tm_buf b;
    buf_init(&b);
    if (slash) buf_put(&b, config_path, (size_t)(slash - config_path) + 1);
    buf_puts(&b, "secrets.bin");
    return buf_cstr(&b);
}

int64_t secrets_mtime(const char *config_path)
{
    if (!config_path) return -1;
    char *path = secrets_path(config_path);
    int64_t t = plat_file_mtime(path);
    free(path);
    return t;
}

int secrets_load(const char *config_path, js_doc *doc)
{
    tm_buf raw, plain;
    tm_err ignore;
    int rc = -1;
    doc->chunks = NULL;
    doc->root = NULL;
    if (!config_path) return -1;
    char *path = secrets_path(config_path);
    buf_init(&raw);
    buf_init(&plain);
    if (plat_file_mtime(path) >= 0 && plat_read_file(path, &raw, &ignore) == 0 && raw.len > sizeof SECRETS_MAGIC &&
        memcmp(raw.p, SECRETS_MAGIC, sizeof SECRETS_MAGIC) == 0 &&
        plat_unprotect(raw.p + sizeof SECRETS_MAGIC, raw.len - sizeof SECRETS_MAGIC, &plain) == 0 &&
        js_parse(doc, (const char *)plain.p, plain.len, &ignore) == 0 && doc->root->t == JS_OBJ)
        rc = 0;
    if (rc) js_free(doc);
    /* a árvore JSON tem cópia própria dos textos; o texto decifrado pode ser apagado */
    if (plain.p) tm_wipe(plain.p, plain.len);
    buf_free(&plain);
    buf_free(&raw);
    free(path);
    return rc;
}

int secrets_update(const char *config_path, const js_val *set, const js_val *del, tm_err *err)
{
    js_doc old;
    tm_buf json, blob;
    bool first = true;
    if (!config_path) return tm_fail(err, TM_E_CONFIG, T(M_FILE_OPEN), "secrets.bin");
    bool have_old = secrets_load(config_path, &old) == 0;
    buf_init(&json);
    buf_init(&blob);
    buf_putc(&json, '{');
    /* o que já existia, menos o que foi removido ou será regravado */
    for (const js_val *m = have_old ? old.root->child : NULL; m; m = m->next) {
        bool drop = m->t != JS_STR || (set && js_get(set, m->key));
        for (const js_val *d = del && del->t == JS_ARR ? del->child : NULL; d && !drop; d = d->next)
            drop = d->t == JS_STR && strcmp(d->s, m->key) == 0;
        if (drop) continue;
        if (!first) buf_putc(&json, ',');
        jw_key(&json, m->key);
        jw_str(&json, m->s, m->slen);
        first = false;
    }
    for (const js_val *m = set && set->t == JS_OBJ ? set->child : NULL; m; m = m->next) {
        if (m->t != JS_STR || !m->slen) continue;
        if (!first) buf_putc(&json, ',');
        jw_key(&json, m->key);
        jw_str(&json, m->s, m->slen);
        first = false;
    }
    buf_putc(&json, '}');

    char *path = secrets_path(config_path);
    buf_put(&blob, SECRETS_MAGIC, sizeof SECRETS_MAGIC);
    int rc = plat_protect(json.p, json.len, &blob);
    if (rc == 0) rc = plat_write_private(path, blob.p, blob.len);
    if (rc) tm_fail(err, TM_E_CONFIG, T(M_FILE_OPEN), path);
    tm_wipe(json.p, json.len);
    buf_free(&json);
    buf_free(&blob);
    free(path);
    if (have_old) js_free(&old);
    return rc;
}

int cfg_load(tm_config *cfg, const char *path, tm_err *err)
{
    cfg->items = NULL;
    cfg->n = 0;
    if (!path || plat_file_mtime(path) < 0) return 0; /* sem arquivo: configuração vazia */

    tm_buf text;
    buf_init(&text);
    if (plat_read_file(path, &text, err)) {
        buf_free(&text);
        return -1;
    }

    js_doc doc, sdoc = { 0 };
    tm_err perr;
    int rc = -1;
    if (js_parse(&doc, (const char *)text.p, text.len, &perr)) {
        tm_fail(err, TM_E_CONFIG, T(M_CFG_PARSE), path, perr.msg);
        goto done;
    }
    const js_val *list = js_get(doc.root, "connections");
    if (!list || list->t != JS_ARR) {
        tm_fail(err, TM_E_CONFIG, T(M_CFG_PARSE), path, T(M_CFG_SHAPE));
        goto done;
    }

    /* Senhas nunca ficam no arquivo de conexões: vêm do cofre ao lado dele ou, se
     * informado, do ambiente do processo (que tem precedência). */
    const js_val *secrets = NULL;
    const char *senv = plat_getenv("TMDB_SECRETS");
    if (senv && js_parse(&sdoc, senv, strlen(senv), &perr) == 0) secrets = sdoc.root;
    else if (secrets_load(path, &sdoc) == 0) secrets = sdoc.root;

    size_t count = 0;
    for (const js_val *it = list->child; it; it = it->next) count++;
    cfg->items = tm_zalloc(count * sizeof *cfg->items);
    for (const js_val *it = list->child; it; it = it->next) {
        tm_err cerr;
        if (cfg_parse_conn(it, secrets, &cfg->items[cfg->n], &cerr) == 0) cfg->n++;
        else tm_log(0, "%s", cerr.msg);
    }
    rc = 0;
done:
    js_free(&doc);
    js_free(&sdoc);
    buf_free(&text);
    return rc;
}

const tm_config *app_cfg_get(tm_app_cfg *a, bool *changed, tm_err *err)
{
    int64_t mtime = a->path ? plat_file_mtime(a->path) : -1;
    int64_t smtime = secrets_mtime(a->path);
    if (changed) *changed = false;
    if (a->loaded && mtime == a->mtime && smtime == a->secrets_mtime) return &a->cfg;
    if (a->loaded) cfg_free(&a->cfg);
    a->loaded = false;
    if (changed) *changed = true;
    if (cfg_load(&a->cfg, a->path, err)) return NULL;
    a->loaded = true;
    a->mtime = mtime;
    a->secrets_mtime = smtime;
    return &a->cfg;
}

const tm_conn_cfg *cfg_find(const tm_config *cfg, const char *ref, tm_err *err)
{
    if (!cfg->n) {
        tm_fail(err, TM_E_CONFIG, "%s", T(M_NO_CONNECTIONS));
        return NULL;
    }
    const char *slash = strchr(ref, '/');
    if (slash) {
        char *type = tm_strndup(ref, (size_t)(slash - ref));
        int f = flavor_parse(type);
        free(type);
        if (f >= 0)
            for (size_t i = 0; i < cfg->n; i++)
                if (cfg->items[i].flavor == (tm_flavor)f && tm_stricmp(cfg->items[i].name, slash + 1) == 0)
                    return &cfg->items[i];
    }
    const tm_conn_cfg *found = NULL;
    int hits = 0;
    for (size_t i = 0; i < cfg->n; i++)
        if (tm_stricmp(cfg->items[i].name, ref) == 0) {
            found = &cfg->items[i];
            hits++;
        }
    if (hits == 1) return found;
    if (hits > 1) tm_fail(err, TM_E_CONFIG, T(M_CONN_AMBIGUOUS), ref, ref);
    else tm_fail(err, TM_E_CONFIG, T(M_CONN_NOT_FOUND), ref);
    return NULL;
}
