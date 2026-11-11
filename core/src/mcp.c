/* Servidor MCP: JSON-RPC 2.0 em stdio, uma mensagem por linha.
 * stdout é só do protocolo; qualquer diagnóstico vai para stderr. */
#include "i18n.h"
#include "tools.h"

static const char *const PROTOCOLS[] = { "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };
#define PROTOCOL_DEFAULT "2025-06-18"

/* Lê uma linha de tamanho arbitrário. false no fim da entrada. */
static bool read_line(tm_buf *line)
{
    char chunk[8192];
    buf_reset(line);
    while (fgets(chunk, sizeof chunk, stdin)) {
        size_t n = strlen(chunk);
        buf_put(line, chunk, n);
        if (n && chunk[n - 1] == '\n') return true;
    }
    return line->len > 0;
}

static void send_line(tm_buf *msg)
{
    buf_putc(msg, '\n');
    fwrite(msg->p, 1, msg->len, stdout);
    fflush(stdout);
}

static void reply_begin(tm_buf *out, const js_val *id)
{
    buf_reset(out);
    buf_puts(out, "{\"jsonrpc\":\"2.0\",\"id\":");
    jw_val(out, id);
}

static void reply_error(tm_buf *out, const js_val *id, int code, const char *message)
{
    reply_begin(out, id);
    buf_printf(out, ",\"error\":{\"code\":%d,\"message\":", code);
    jw_cstr(out, message);
    buf_puts(out, "}}");
    send_line(out);
}

static void on_initialize(tm_buf *out, const js_val *id, const js_val *params)
{
    const char *want = js_get_str(params, "protocolVersion", "");
    const char *use = PROTOCOL_DEFAULT;
    for (size_t i = 0; i < TM_COUNT(PROTOCOLS); i++)
        if (strcmp(want, PROTOCOLS[i]) == 0) use = PROTOCOLS[i];
    reply_begin(out, id);
    buf_puts(out, ",\"result\":{\"protocolVersion\":");
    jw_cstr(out, use);
    buf_puts(out, ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"" TM_NAME "\",\"title\":\"" TM_TITLE
                  "\",\"version\":\"" TM_VERSION "\"},\"instructions\":");
    jw_cstr(out, T(M_INSTRUCTIONS));
    buf_puts(out, "}}");
    send_line(out);
}

static void on_tools_call(tm_buf *out, const js_val *id, const js_val *params, tm_app_cfg *app)
{
    const char *name = js_get_str(params, "name", "");
    const js_val *args = js_get(params, "arguments");
    tm_buf text;
    tm_err err;
    buf_init(&text);
    tm_err_clear(&err);

    bool changed = false;
    const tm_config *cfg = app_cfg_get(app, &changed, &err);
    if (changed) db_close_all(); /* configuração nova: conexões antigas não valem mais */
    int rc = cfg ? tools_call(cfg, name, args, &text, &err) : -1;
    if (rc) {
        buf_reset(&text);
        buf_puts(&text, err.msg[0] ? err.msg : "error");
        if (err.sqlstate[0]) buf_printf(&text, " [SQLSTATE %s]", err.sqlstate);
        tm_log(1, "tool %s failed: %s", name, err.msg);
    }
    reply_begin(out, id);
    buf_puts(out, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    jw_str(out, (const char *)text.p, text.len);
    buf_printf(out, "}],\"isError\":%s}}", rc ? "true" : "false");
    send_line(out);
    buf_free(&text);
}

int mcp_serve(tm_app_cfg *app)
{
    tm_buf line, out;
    buf_init(&line);
    buf_init(&out);
    tm_log(1, "MCP server %s started (lang=%s)", TM_VERSION, i18n_lang());

    while (read_line(&line)) {
        js_doc doc;
        tm_err err;
        if (line.len == 0 || strspn(buf_cstr(&line), " \t\r\n") == line.len) continue;
        if (js_parse(&doc, (const char *)line.p, line.len, &err)) {
            reply_error(&out, NULL, -32700, err.msg);
            js_free(&doc);
            continue;
        }
        const js_val *root = doc.root;
        const char *method = js_get_str(root, "method", NULL);
        const js_val *id = js_get(root, "id");
        const js_val *params = js_get(root, "params");

        if (!method) {
            /* Resposta a algo que não pedimos, ou lixo: só reclama se tiver formato de pedido. */
            if (root->t != JS_OBJ) reply_error(&out, NULL, -32600, "Invalid Request");
        } else if (!id) {
            /* Notificação: nunca tem resposta. */
        } else if (strcmp(method, "initialize") == 0) {
            on_initialize(&out, id, params);
        } else if (strcmp(method, "ping") == 0) {
            reply_begin(&out, id);
            buf_puts(&out, ",\"result\":{}}");
            send_line(&out);
        } else if (strcmp(method, "tools/list") == 0) {
            reply_begin(&out, id);
            buf_puts(&out, ",\"result\":");
            tools_list_json(&out);
            buf_putc(&out, '}');
            send_line(&out);
        } else if (strcmp(method, "tools/call") == 0) {
            on_tools_call(&out, id, params, app);
        } else {
            reply_error(&out, id, -32601, "Method not found");
        }
        js_free(&doc);
    }
    db_close_all();
    buf_free(&line);
    buf_free(&out);
    return 0;
}
