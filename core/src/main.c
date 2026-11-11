/* tmdb — ponto de entrada: servidor MCP e utilitários de linha de comando. */
#include "i18n.h"
#include "plat.h"
#include "tls.h"
#include "tools.h"

static const char *code_name(int code)
{
    switch (code) {
    case TM_E_IO: return "network";
    case TM_E_TIMEOUT: return "timeout";
    case TM_E_PROTOCOL: return "protocol";
    case TM_E_AUTH: return "auth";
    case TM_E_SERVER: return "server";
    case TM_E_GUARD: return "guard";
    case TM_E_CONFIG: return "config";
    case TM_E_UNSUPPORTED: return "unsupported";
    default: return "error";
    }
}

static void print_error_json(const tm_err *err)
{
    tm_buf out;
    buf_init(&out);
    buf_puts(&out, "{\"ok\":false,\"error\":");
    jw_cstr(&out, err->msg);
    buf_puts(&out, ",\"kind\":");
    jw_cstr(&out, code_name(err->code));
    if (err->sqlstate[0]) {
        buf_puts(&out, ",\"sqlstate\":");
        jw_cstr(&out, err->sqlstate);
    }
    buf_puts(&out, "}\n");
    fwrite(out.p, 1, out.len, stdout);
    buf_free(&out);
}

/* `tmdb test`: uma conexão em JSON na entrada padrão (a senha não passa por argv,
 * onde ficaria visível na lista de processos). Usado pelo botão Testar da extensão. */
/* `tmdb secret`: grava e remove senhas no cofre. Lê da entrada padrão
 * {"set":{"id":"senha"},"delete":["id"]} e responde só com os ids que têm senha —
 * nenhum valor sai daqui. Com "{}" apenas lista. Usado pela tela de configuração. */
static int cmd_secret(const char *config_path)
{
    tm_buf in, out;
    char chunk[4096];
    size_t n;
    js_doc doc, store;
    tm_err err;
    int rc = 1;
    buf_init(&in);
    buf_init(&out);
    while ((n = fread(chunk, 1, sizeof chunk, stdin)) > 0) buf_put(&in, chunk, n);
    tm_err_clear(&err);
    if (js_parse(&doc, (const char *)in.p, in.len, &err) == 0) {
        const js_val *set = js_get(doc.root, "set"), *del = js_get(doc.root, "delete");
        if ((!set && !del) || secrets_update(config_path, set, del, &err) == 0) {
            buf_puts(&out, "{\"ok\":true,\"ids\":[");
            if (secrets_load(config_path, &store) == 0) {
                for (const js_val *m = store.root->child; m; m = m->next) {
                    if (m != store.root->child) buf_putc(&out, ',');
                    jw_cstr(&out, m->key);
                }
                js_free(&store);
            }
            buf_puts(&out, "]}\n");
            fwrite(out.p, 1, out.len, stdout);
            rc = 0;
        }
    }
    if (rc) print_error_json(&err);
    js_free(&doc);
    if (in.p) tm_wipe(in.p, in.len);
    buf_free(&in);
    buf_free(&out);
    return rc;
}

static int cmd_test(const char *config_path)
{
    tm_buf in, version;
    char chunk[4096];
    size_t n;
    js_doc doc;
    tm_err err;
    tm_conn_cfg cfg;
    int ms = 0, rc = 1;

    buf_init(&in);
    buf_init(&version);
    while ((n = fread(chunk, 1, sizeof chunk, stdin)) > 0) buf_put(&in, chunk, n);

    /* Sem senha no pedido, vale a que está salva no cofre para aquele id. */
    js_doc store;
    bool have_store = secrets_load(config_path, &store) == 0;
    tm_err_clear(&err);
    if (js_parse(&doc, (const char *)in.p, in.len, &err) == 0 &&
        cfg_parse_conn(doc.root, have_store ? store.root : NULL, &cfg, &err) == 0) {
        if (db_test(&cfg, &version, &ms, &err) == 0) {
            tm_buf out;
            buf_init(&out);
            buf_puts(&out, "{\"ok\":true,\"version\":");
            jw_cstr(&out, buf_cstr(&version));
            buf_printf(&out, ",\"elapsedMs\":%d}\n", ms);
            fwrite(out.p, 1, out.len, stdout);
            buf_free(&out);
            rc = 0;
        }
        cfg_conn_free(&cfg);
    }
    if (rc) print_error_json(&err);
    js_free(&doc);
    if (have_store) js_free(&store);
    if (in.p) tm_wipe(in.p, in.len);
    buf_free(&in);
    buf_free(&version);
    return rc;
}

/* `tmdb call FERRAMENTA [JSON]`: executa uma ferramenta MCP direto, sem o protocolo. */
static int cmd_call(tm_app_cfg *app, const char *tool, const char *args_json)
{
    js_doc doc = { 0 };
    tm_err err;
    tm_buf out;
    int rc = 1;
    buf_init(&out);
    tm_err_clear(&err);
    const tm_config *cfg = app_cfg_get(app, NULL, &err);
    if (cfg && (!args_json || js_parse(&doc, args_json, strlen(args_json), &err) == 0) &&
        tools_call(cfg, tool, doc.root, &out, &err) == 0) {
        buf_putc(&out, '\n');
        fwrite(out.p, 1, out.len, stdout);
        rc = 0;
    } else {
        fprintf(stderr, "%s%s%s\n", err.msg, err.sqlstate[0] ? " SQLSTATE " : "", err.sqlstate);
    }
    js_free(&doc);
    buf_free(&out);
    db_close_all();
    return rc;
}

/* `tmdb tlsprobe HOST PORTA [modo] [arquivo-ca]`: só o aperto de mão TLS, para
 * diagnosticar certificado e compatibilidade sem envolver o protocolo do banco. */
static int cmd_tlsprobe(const char *host, const char *port, const char *mode, const char *ca)
{
    tm_io io;
    tm_err err;
    tls_opts o;
    memset(&o, 0, sizeof o);
    o.host = host;
    o.mode = SSL_REQUIRE;
    if (mode && strcmp(mode, "verify-ca") == 0) o.mode = SSL_VERIFY_CA;
    if (mode && strcmp(mode, "verify-full") == 0) o.mode = SSL_VERIFY_FULL;
    o.ca_file = ca;
    tm_err_clear(&err);
    if (io_connect(&io, host, atoi(port), 10000, &err) == 0) {
        io_set_timeout(&io, 10000);
        if (tls_start(&io, &o, &err) == 0) {
            printf("{\"ok\":true,\"tls\":\"1.3\"}\n");
            io_close(&io);
            return 0;
        }
        io_close(&io);
    }
    print_error_json(&err);
    return 1;
}

int main(int argc, char **argv)
{
    const char *command = "serve", *lang = NULL, *config = NULL;
    const char *pos[5] = { NULL, NULL, NULL, NULL, NULL };
    int npos = 0;

    plat_init();
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--lang") == 0 && i + 1 < argc) lang = argv[++i];
        else if (strcmp(a, "--config") == 0 && i + 1 < argc) config = argv[++i];
        else if (strcmp(a, "--verbose") == 0) tm_log_level = 2;
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) command = "help";
        else if (strcmp(a, "--version") == 0) command = "version";
        else if (npos < 5) pos[npos++] = a;
    }
    if (pos[0]) command = pos[0];

    if (!lang) lang = plat_getenv("TMDB_LANG");
    i18n_set_lang(lang ? lang : plat_lang());

    tm_app_cfg app;
    memset(&app, 0, sizeof app);
    if (!config) config = plat_getenv("TMDB_CONFIG");
    app.path = config ? tm_strdup(config) : plat_default_config_path();

    if (strcmp(command, "serve") == 0) return mcp_serve(&app);
    if (strcmp(command, "test") == 0) return cmd_test(app.path);
    if (strcmp(command, "secret") == 0) return cmd_secret(app.path);
    if (strcmp(command, "call") == 0 && pos[1]) return cmd_call(&app, pos[1], pos[2]);
    if (strcmp(command, "selftest") == 0) return crypto_selftest();
    if (strcmp(command, "tlsprobe") == 0 && pos[2]) return cmd_tlsprobe(pos[1], pos[2], pos[3], pos[4]);
    if (strcmp(command, "version") == 0) {
        puts(TM_NAME " " TM_VERSION);
        return 0;
    }
    fputs(T(M_USAGE), strcmp(command, "help") == 0 ? stdout : stderr);
    return strcmp(command, "help") == 0 ? 0 : 2;
}
