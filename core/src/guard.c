/* Guarda de leitura, camada léxica.
 *
 * Percorre o SQL como o banco percorreria — pulando comentários, literais e
 * identificadores entre aspas segundo as regras DAQUELE banco — e só então julga
 * as palavras que sobram. O cuidado central: nunca pular um trecho que o banco
 * executaria. Onde os dialetos divergem (comentário aninhado, "--" sem espaço,
 * barra invertida em literal), vale a regra do banco em questão; na dúvida, recusa.
 *
 * É defesa em profundidade. A garantia real é a transação somente leitura do
 * servidor (onde existe) e, acima de tudo, um usuário de banco sem permissão de escrita. */
#include "db.h"
#include "i18n.h"

static bool is_space(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static bool word_start(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80;
}

static bool word_char(tm_flavor f, int c)
{
    if (word_start(c) || (c >= '0' && c <= '9') || c == '$') return true;
    if (c == '#') return f == FL_MSSQL || f == FL_ORACLE;
    if (c == '@') return f == FL_MSSQL || f == FL_MYSQL;
    return false;
}

static bool in_list(const char *word, const char *const *list)
{
    for (; *list; list++)
        if (strcmp(word, *list) == 0) return true;
    return false;
}

static const char *const FIRST_PG[] = { "SELECT", "WITH", "SHOW", "EXPLAIN", "VALUES", "TABLE", NULL };
static const char *const FIRST_MY[] = { "SELECT", "WITH", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "VALUES",
                                        "TABLE", NULL };
static const char *const FIRST_STD[] = { "SELECT", "WITH", NULL };

/* Palavras que escrevem mesmo dentro de uma instrução que começa por SELECT/WITH/EXPLAIN. */
static const char *const DENY[] = { "INSERT", "UPDATE", "DELETE",   "MERGE",  "INTO",    "CREATE", "DROP",
                                    "ALTER",  "TRUNCATE", "GRANT", "REVOKE", "EXEC",    "EXECUTE", "CALL",
                                    NULL };
static const char *const DENY_MSSQL[] = { "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", NULL };

static int unterminated(tm_err *err)
{
    return tm_fail(err, TM_E_GUARD, "%s", T(M_GUARD_UNTERMINATED));
}

/* Pula um trecho delimitado por `q`, onde o delimitador dobrado é escape e,
 * se `bs`, a barra invertida também. Devolve o ponteiro após o fecho, ou NULL. */
static const char *skip_quoted(const char *p, char q, bool bs)
{
    for (p++; *p; p++) {
        if (bs && *p == '\\') {
            if (!p[1]) return NULL;
            p++;
        } else if (*p == q) {
            if (p[1] == q) p++;
            else return p + 1;
        }
    }
    return NULL;
}

static const char *skip_block_comment(const char *p, bool nested)
{
    int depth = 1;
    for (p += 2; *p; p++) {
        if (p[0] == '*' && p[1] == '/') {
            p++;
            if (--depth == 0) return p + 1;
        } else if (nested && p[0] == '/' && p[1] == '*') {
            p++;
            depth++;
        }
    }
    return NULL;
}

/* PostgreSQL: $etiqueta$ ... $etiqueta$. Devolve NULL se não for abertura válida
 * (ex.: $1), e *bad = true se abriu e não fechou. */
static const char *skip_dollar(const char *p, bool *bad)
{
    const char *t = p + 1;
    if (*t >= '0' && *t <= '9') return NULL;
    while (word_start((unsigned char)*t) || (*t >= '0' && *t <= '9')) t++;
    if (*t != '$') return NULL;
    size_t taglen = (size_t)(t - p) + 1;
    for (const char *q = t + 1; *q; q++)
        if (*q == '$' && strncmp(q, p, taglen) == 0) return q + taglen;
    *bad = true;
    return NULL;
}

/* Oracle: q'[ ... ]' (e variações de delimitador). p aponta para a aspa. */
static const char *skip_oracle_q(const char *p)
{
    char open = p[1], close;
    if (!open) return NULL;
    switch (open) {
    case '[': close = ']'; break;
    case '(': close = ')'; break;
    case '{': close = '}'; break;
    case '<': close = '>'; break;
    default: close = open;
    }
    for (p += 2; *p; p++)
        if (p[0] == close && p[1] == '\'') return p + 2;
    return NULL;
}

int guard_readonly(tm_flavor f, const char *sql, tm_err *err)
{
    const char *const *first = f == FL_POSTGRES ? FIRST_PG : f == FL_MYSQL ? FIRST_MY : FIRST_STD;
    const char *p = sql;
    bool seen_word = false, ended = false;
    char prev_word[8] = ""; /* palavra colada imediatamente antes (para E'..' e q'..') */

    while (*p) {
        unsigned char c = (unsigned char)*p;
        bool glued = prev_word[0] != 0; /* a palavra anterior termina exatamente aqui */
        char pw[8];
        memcpy(pw, prev_word, sizeof pw);
        prev_word[0] = 0;

        if (is_space(c)) {
            p++;
            continue;
        }
        /* comentários não contam como conteúdo */
        if (c == '-' && p[1] == '-' &&
            (f != FL_MYSQL || is_space((unsigned char)p[2]) || !p[2] || (unsigned char)p[2] < 0x20)) {
            while (*p && *p != '\n') p++;
            continue;
        }
        if (c == '#' && f == FL_MYSQL) {
            while (*p && *p != '\n') p++;
            continue;
        }
        if (c == '/' && p[1] == '*') {
            if (f == FL_MYSQL && (p[2] == '!' || (p[2] == 'M' && p[3] == '!')))
                return tm_fail(err, TM_E_GUARD, "%s", T(M_GUARD_EXEC_COMMENT));
            p = skip_block_comment(p, f == FL_POSTGRES || f == FL_MSSQL);
            if (!p) return unterminated(err);
            continue;
        }

        /* daqui em diante é conteúdo: depois de um ';' nada mais pode vir */
        if (ended) return tm_fail(err, TM_E_GUARD, "%s", T(M_GUARD_MULTI));

        if (c == ';') {
            ended = true;
            p++;
            continue;
        }
        if (c == '\'') {
            if (f == FL_ORACLE && glued && (tm_stricmp(pw, "Q") == 0 || tm_stricmp(pw, "NQ") == 0)) {
                p = skip_oracle_q(p);
            } else {
                bool bs = f == FL_MYSQL || (f == FL_POSTGRES && glued && tm_stricmp(pw, "E") == 0);
                p = skip_quoted(p, '\'', bs);
            }
            if (!p) return unterminated(err);
            continue;
        }
        if (c == '"') {
            p = skip_quoted(p, '"', f == FL_MYSQL);
            if (!p) return unterminated(err);
            continue;
        }
        if (c == '`' && f == FL_MYSQL) {
            p = skip_quoted(p, '`', false);
            if (!p) return unterminated(err);
            continue;
        }
        if (c == '[' && f == FL_MSSQL) {
            p = skip_quoted(p, ']', false);
            if (!p) return unterminated(err);
            continue;
        }
        if (c == '$' && f == FL_POSTGRES) {
            bool bad = false;
            const char *q = skip_dollar(p, &bad);
            if (bad) return unterminated(err);
            if (q) {
                p = q;
                continue;
            }
        }
        if (word_start(c) || (c == '@' && (f == FL_MSSQL || f == FL_MYSQL)) || (c == '#' && f == FL_MSSQL)) {
            char word[40];
            size_t n = 0;
            const char *start = p;
            while (word_char(f, (unsigned char)*p)) {
                if (n < sizeof word - 1) {
                    char ch = *p;
                    word[n++] = (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : ch;
                }
                p++;
            }
            word[n] = 0;
            if ((size_t)(p - start) < sizeof prev_word) memcpy(prev_word, word, n + 1);

            if (!seen_word) {
                seen_word = true;
                if (!in_list(word, first))
                    return tm_fail(err, TM_E_GUARD, T(M_GUARD_FIRST),
                                   f == FL_POSTGRES || f == FL_MYSQL ? "SELECT, WITH, SHOW, EXPLAIN"
                                                                     : "SELECT, WITH",
                                   word);
            }
            if (in_list(word, DENY) || (f == FL_MSSQL && in_list(word, DENY_MSSQL)))
                return tm_fail(err, TM_E_GUARD, T(M_GUARD_WORD), word);
            continue;
        }
        /* qualquer outro símbolo. Antes da primeira palavra só se aceita '(' */
        if (!seen_word && c != '(') {
            char sym[2] = { (char)c, 0 };
            return tm_fail(err, TM_E_GUARD, T(M_GUARD_FIRST), "SELECT, WITH", sym);
        }
        p++;
    }
    if (!seen_word) return tm_fail(err, TM_E_GUARD, "%s", T(M_GUARD_EMPTY));
    return 0;
}

int guard_ident(const char *name, tm_err *err)
{
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++, n++)
        if (*p == '\'' || *p == '\\' || *p < 0x20 || n > 255)
            return tm_fail(err, TM_E_GUARD, T(M_BAD_IDENT), name);
    return 0;
}
