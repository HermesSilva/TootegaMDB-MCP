#ifndef TM_TOOLS_H
#define TM_TOOLS_H

#include "db.h"

/* Resultado de tools/list: {"tools":[...]} no idioma ativo. */
void tools_list_json(tm_buf *out);
/* Executa uma ferramenta; o texto de saída vai em `out`. 0 = ok, -1 = erro em `err`. */
int tools_call(const tm_config *cfg, const char *name, const js_val *args, tm_buf *out, tm_err *err);

/* Servidor MCP em stdio. Devolve o código de saída do processo. */
int mcp_serve(tm_app_cfg *app);

/* Vetores de teste das primitivas criptográficas. 0 = tudo certo. */
int crypto_selftest(void);

#endif
