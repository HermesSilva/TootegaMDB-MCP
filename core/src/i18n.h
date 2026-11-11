/* Textos em inglês e português. Uma linha por mensagem: X(id, en, pt). */
#ifndef TM_I18N_H
#define TM_I18N_H

#define TM_MESSAGES(X) \
    /* ---- plataforma / rede ---- */ \
    X(M_FILE_OPEN, "Cannot open file '%s'", "Não foi possível abrir o arquivo '%s'") \
    X(M_HOST_REQUIRED, "Host is required", "O host é obrigatório") \
    X(M_BAD_PORT, "Invalid port: %d", "Porta inválida: %d") \
    X(M_DNS_FAIL, "Cannot resolve host '%s'", "Não foi possível resolver o host '%s'") \
    X(M_CONNECT_TIMEOUT, "Timed out connecting to %s:%d", "Tempo esgotado ao conectar em %s:%d") \
    X(M_CONNECT_FAIL, "Cannot connect to %s:%d (refused or unreachable)", \
      "Não foi possível conectar em %s:%d (recusado ou inalcançável)") \
    X(M_IO_SEND, "Network error while sending", "Erro de rede ao enviar") \
    X(M_IO_RECV, "Network error while receiving", "Erro de rede ao receber") \
    X(M_IO_CLOSED, "Connection closed by the server", "Conexão encerrada pelo servidor") \
    X(M_IO_TIMEOUT, "Timed out waiting for the server", "Tempo esgotado aguardando o servidor") \
    /* ---- configuração ---- */ \
    X(M_CFG_PARSE, "Invalid configuration file '%s': %s", "Arquivo de configuração inválido '%s': %s") \
    X(M_CFG_SHAPE, "Configuration must be an object with a \"connections\" array", \
      "A configuração deve ser um objeto com um array \"connections\"") \
    X(M_CFG_FLAVOR, "Connection '%s': unknown database type '%s'", \
      "Conexão '%s': tipo de banco desconhecido '%s'") \
    X(M_CONN_NOT_FOUND, "Connection '%s' not found. Use list_connections to see the available ones.", \
      "Conexão '%s' não encontrada. Use list_connections para ver as disponíveis.") \
    X(M_CONN_AMBIGUOUS, "Connection name '%s' is ambiguous; use \"type/name\" (e.g. \"postgres/%s\")", \
      "O nome de conexão '%s' é ambíguo; use \"tipo/nome\" (ex.: \"postgres/%s\")") \
    X(M_NO_CONNECTIONS, \
      "No connections configured. Run \"Tootega Multi-Database MCP: Configure Connections\" in VS Code.", \
      "Nenhuma conexão configurada. Execute \"Tootega Multi-Database MCP: Configurar Conexões\" no VS Code.") \
    X(M_DRIVER_PENDING, "The %s driver is not available in this build yet", \
      "O driver %s ainda não está disponível nesta versão") \
    /* ---- protocolo / autenticação ---- */ \
    X(M_PROTO, "Unexpected response from the server (%s)", "Resposta inesperada do servidor (%s)") \
    X(M_AUTH_UNSUPPORTED, "Authentication method not supported: %s", \
      "Método de autenticação não suportado: %s") \
    X(M_AUTH_SERVER_SIG, "Server failed to prove it knows the password (possible impersonation)", \
      "O servidor não provou conhecer a senha (possível impostor)") \
    X(M_PASSWORD_REQUIRED, "The server requires a password and none is configured", \
      "O servidor exige senha e nenhuma foi configurada") \
    X(M_TLS_UNAVAILABLE, "The server requires an encrypted connection (TLS), not available in this build yet", \
      "O servidor exige conexão criptografada (TLS), ainda não disponível nesta versão") \
    X(M_TLS_REQUIRED, "The server requires an encrypted connection; set encryption to Prefer or Require", \
      "O servidor exige conexão criptografada; ajuste a criptografia para Preferir ou Exigir") \
    X(M_TLS_MSSQL, "Could not establish TLS 1.3 with this SQL Server. It needs SQL Server 2022 or newer with " \
      "TLS 1.3 enabled; servers limited to TLS 1.2 are not supported by this client.", \
      "Não foi possível estabelecer TLS 1.3 com este SQL Server. É preciso SQL Server 2022 ou mais novo com " \
      "TLS 1.3 habilitado; servidores limitados ao TLS 1.2 não são suportados por este cliente.") \
    X(M_TLS_REFUSED, "Encryption was requested but the server does not offer TLS", \
      "A criptografia foi pedida, mas o servidor não oferece TLS") \
    X(M_TLS_OLD, "The server does not support TLS 1.3 (only older versions); this client speaks TLS 1.3 only", \
      "O servidor não suporta TLS 1.3 (só versões mais antigas); este cliente fala apenas TLS 1.3") \
    X(M_TLS_HANDSHAKE, "TLS handshake failed: %s", "Falha no aperto de mão TLS: %s") \
    X(M_TLS_ALERT, "The server ended the TLS session with alert %d", \
      "O servidor encerrou a sessão TLS com o alerta %d") \
    X(M_TLS_CERT, "Server certificate rejected: %s", "Certificado do servidor recusado: %s") \
    X(M_TLS_CERT_HOST, "Server certificate is not valid for host '%s'", \
      "O certificado do servidor não vale para o host '%s'") \
    X(M_TLS_NO_ROOTS, "No trusted certificate authorities found; set a CA file for this connection", \
      "Nenhuma autoridade certificadora confiável encontrada; informe um arquivo de CA para esta conexão") \
    X(M_INSTANCE_LOOKUP, "Cannot find SQL Server instance '%s' on %s (is the SQL Browser service running, UDP 1434?)", \
      "Instância '%s' do SQL Server não encontrada em %s (o serviço SQL Browser está ativo, UDP 1434?)") \
    X(M_ORA_REFUSED, "The Oracle listener refused the connection: %s", \
      "O listener do Oracle recusou a conexão: %s") \
    X(M_ORA_NO_SERVICE, "Service name or SID '%s' is not known to the listener at %s:%d", \
      "O service name ou SID '%s' não é conhecido pelo listener em %s:%d") \
    X(M_ORA_TOO_OLD, "Oracle Database older than 12.1 is not supported", \
      "Oracle Database anterior ao 12.1 não é suportado") \
    X(M_ORA_NNE, "The server requires Oracle Native Network Encryption, which is not supported", \
      "O servidor exige a criptografia nativa de rede da Oracle (NNE), que não é suportada") \
    X(M_ORA_TARGET, "Oracle connection needs a service name or a SID", \
      "A conexão Oracle precisa de um service name ou de um SID") \
    X(M_RESULT_TOO_BIG, "Result abandoned: too many rows beyond the limit; connection was reset", \
      "Resultado abandonado: linhas demais além do limite; a conexão foi reiniciada") \
    /* ---- guarda de leitura ---- */ \
    X(M_GUARD_EMPTY, "Empty SQL statement", "Instrução SQL vazia") \
    X(M_GUARD_MULTI, "Read-only connection: only a single statement is allowed", \
      "Conexão somente leitura: só é permitida uma única instrução") \
    X(M_GUARD_FIRST, "Read-only connection: statement must start with %s (found '%s')", \
      "Conexão somente leitura: a instrução deve começar com %s (encontrado '%s')") \
    X(M_GUARD_WORD, "Read-only connection: keyword '%s' is not allowed. If it is a column or table name, quote it.", \
      "Conexão somente leitura: a palavra '%s' não é permitida. Se for nome de coluna ou tabela, coloque entre aspas.") \
    X(M_GUARD_UNTERMINATED, "SQL has an unterminated string, identifier or comment", \
      "O SQL tem texto, identificador ou comentário não terminado") \
    X(M_GUARD_EXEC_COMMENT, "Read-only connection: executable comments (/*! ... */) are not allowed", \
      "Conexão somente leitura: comentários executáveis (/*! ... */) não são permitidos") \
    X(M_READONLY_CONN, "Connection '%s' is read-only. Enable writing for it in the configuration to use 'execute'.", \
      "A conexão '%s' é somente leitura. Libere a escrita na configuração para usar 'execute'.") \
    X(M_BAD_IDENT, "Invalid name '%s': quotes, backslashes and control characters are not accepted", \
      "Nome inválido '%s': aspas, barras invertidas e caracteres de controle não são aceitos") \
    X(M_TABLE_NOT_FOUND, "Table or view '%s' not found. Check the schema, or use list_tables / search_columns.", \
      "Tabela ou view '%s' não encontrada. Confira o schema, ou use list_tables / search_columns.") \
    X(M_BAD_FORMAT, "Unknown format '%s'; use json, csv or markdown", \
      "Formato desconhecido '%s'; use json, csv ou markdown") \
    /* ---- MCP ---- */ \
    X(M_ARG_REQUIRED, "Missing required argument '%s'", "Falta o argumento obrigatório '%s'") \
    X(M_TOOL_UNKNOWN, "Unknown tool '%s'", "Ferramenta desconhecida '%s'") \
    X(M_INSTRUCTIONS, \
      "Database access for PostgreSQL, MySQL, SQL Server and Oracle. Start with list_connections, " \
      "then explore with list_schemas, list_tables and describe_table before writing SQL. " \
      "Use each database's own SQL dialect. Connections are read-only unless marked otherwise; " \
      "results are capped, so filter and aggregate in SQL instead of fetching everything.", \
      "Acesso a bancos PostgreSQL, MySQL, SQL Server e Oracle. Comece por list_connections e " \
      "explore com list_schemas, list_tables e describe_table antes de escrever SQL. " \
      "Use o dialeto SQL de cada banco. As conexões são somente leitura, salvo indicação contrária; " \
      "os resultados têm limite, então filtre e agregue no SQL em vez de trazer tudo.") \
    /* ---- ferramentas: títulos e descrições ---- */ \
    X(M_T_LIST_CONN_TITLE, "List connections", "Listar conexões") \
    X(M_T_LIST_CONN, "Lists the configured database connections: name, database type, host, database, " \
      "environment and whether writing is allowed. Call this first.", \
      "Lista as conexões de banco configuradas: nome, tipo de banco, host, banco, ambiente e se a " \
      "escrita é permitida. Chame esta primeiro.") \
    X(M_T_TEST_TITLE, "Test connection", "Testar conexão") \
    X(M_T_TEST, "Opens a fresh connection, authenticates and reports server version and latency.", \
      "Abre uma conexão nova, autentica e informa a versão do servidor e a latência.") \
    X(M_T_INFO_TITLE, "Server information", "Informações do servidor") \
    X(M_T_INFO, "Server version, current user, current database and default schema.", \
      "Versão do servidor, usuário atual, banco atual e schema padrão.") \
    X(M_T_SCHEMAS_TITLE, "List schemas", "Listar schemas") \
    X(M_T_SCHEMAS, "Lists schemas of the connection (databases, on MySQL). System schemas are omitted.", \
      "Lista os schemas da conexão (bancos, no MySQL). Schemas de sistema são omitidos.") \
    X(M_T_TABLES_TITLE, "List tables and views", "Listar tabelas e views") \
    X(M_T_TABLES, "Lists tables and views with estimated row counts. Without 'schema', lists every " \
      "non-system schema. 'pattern' is a LIKE filter on the name (e.g. \"%order%\").", \
      "Lista tabelas e views com contagem estimada de linhas. Sem 'schema', lista todos os schemas " \
      "que não são de sistema. 'pattern' é um filtro LIKE no nome (ex.: \"%pedido%\").") \
    X(M_T_DESCRIBE_TITLE, "Describe table", "Descrever tabela") \
    X(M_T_DESCRIBE, "Columns (type, nullability, default), primary and foreign keys, and indexes of a " \
      "table or view. Use it before writing a query against the table.", \
      "Colunas (tipo, nulabilidade, padrão), chaves primária e estrangeiras e índices de uma tabela " \
      "ou view. Use antes de escrever uma consulta contra a tabela.") \
    X(M_T_SEARCH_TITLE, "Search columns", "Procurar colunas") \
    X(M_T_SEARCH, "Finds tables and columns whose name matches a LIKE pattern, across all schemas. " \
      "Useful to locate where a piece of data lives.", \
      "Encontra tabelas e colunas cujo nome casa com um padrão LIKE, em todos os schemas. " \
      "Útil para localizar onde um dado mora.") \
    X(M_T_QUERY_TITLE, "Run read query", "Executar consulta de leitura") \
    X(M_T_QUERY, "Runs one read-only SQL statement (SELECT, WITH, SHOW, EXPLAIN) and returns the rows. " \
      "Rows beyond the limit are cut and 'truncated' is set: add WHERE, aggregate or page in SQL.", \
      "Executa uma instrução SQL de leitura (SELECT, WITH, SHOW, EXPLAIN) e devolve as linhas. " \
      "Linhas além do limite são cortadas e 'truncated' é marcado: use WHERE, agregue ou pagine no SQL.") \
    X(M_T_EXPLAIN_TITLE, "Explain query plan", "Explicar plano da consulta") \
    X(M_T_EXPLAIN, "Returns the execution plan the database would use for a query, without running it.", \
      "Devolve o plano de execução que o banco usaria para uma consulta, sem executá-la.") \
    X(M_T_EXECUTE_TITLE, "Execute write statement", "Executar instrução de escrita") \
    X(M_T_EXECUTE, "Runs SQL that changes data or structure (INSERT, UPDATE, DELETE, DDL). Only works " \
      "on connections with writing enabled. Changes are committed immediately.", \
      "Executa SQL que altera dados ou estrutura (INSERT, UPDATE, DELETE, DDL). Só funciona em " \
      "conexões com escrita liberada. As alterações são confirmadas imediatamente.") \
    /* ---- ferramentas: parâmetros ---- */ \
    X(M_P_CONNECTION, "Connection name, as returned by list_connections", \
      "Nome da conexão, como devolvido por list_connections") \
    X(M_P_SCHEMA, "Schema name (database name on MySQL). Defaults to the connection's current schema.", \
      "Nome do schema (nome do banco, no MySQL). Padrão: o schema atual da conexão.") \
    X(M_P_SCHEMA_ALL, "Schema name (database name on MySQL). Omit to list all non-system schemas.", \
      "Nome do schema (nome do banco, no MySQL). Omita para listar todos os que não são de sistema.") \
    X(M_P_TABLE, "Table or view name", "Nome da tabela ou view") \
    X(M_P_PATTERN, "LIKE pattern, case-insensitive; % matches any text", \
      "Padrão LIKE, sem diferenciar maiúsculas; % casa com qualquer texto") \
    X(M_P_SQL, "SQL text, in the dialect of the connection's database", \
      "Texto SQL, no dialeto do banco da conexão") \
    X(M_P_MAX_ROWS, "Maximum rows to return (capped by the connection's limit)", \
      "Máximo de linhas a devolver (limitado pelo teto da conexão)") \
    X(M_P_FORMAT, "Output format: json (default), csv or markdown", \
      "Formato de saída: json (padrão), csv ou markdown") \
    /* ---- linha de comando ---- */ \
    X(M_USAGE, \
      "Usage: tmdb [command] [options]\n" \
      "  serve            Run the MCP server on stdio (default)\n" \
      "  test             Read one connection as JSON from stdin, try it, print the result\n" \
      "  call TOOL [JSON] Run one MCP tool directly, e.g. call query '{\"connection\":\"x\",\"sql\":\"select 1\"}'\n" \
      "  selftest         Run the built-in cryptography test vectors\n" \
      "  version          Print the version\n" \
      "Options:\n" \
      "  --config FILE    Connections file (default: TMDB_CONFIG or the per-user file)\n" \
      "  --lang pt|en     Language of messages (default: TMDB_LANG or the system language)\n" \
      "  --verbose        Log to stderr\n", \
      "Uso: tmdb [comando] [opções]\n" \
      "  serve            Roda o servidor MCP em stdio (padrão)\n" \
      "  test             Lê uma conexão em JSON da entrada padrão, testa e imprime o resultado\n" \
      "  call FERR [JSON] Executa uma ferramenta MCP direto, ex.: call query '{\"connection\":\"x\",\"sql\":\"select 1\"}'\n" \
      "  selftest         Roda os vetores de teste de criptografia embutidos\n" \
      "  version          Imprime a versão\n" \
      "Opções:\n" \
      "  --config ARQ     Arquivo de conexões (padrão: TMDB_CONFIG ou o arquivo do usuário)\n" \
      "  --lang pt|en     Idioma das mensagens (padrão: TMDB_LANG ou o idioma do sistema)\n" \
      "  --verbose        Log em stderr\n")

typedef enum {
#define X(id, en, pt) id,
    TM_MESSAGES(X)
#undef X
    M__COUNT
} tm_msg;

void        i18n_set_lang(const char *lang); /* "pt..." ativa português; o resto é inglês */
const char *i18n_lang(void);                 /* "pt" ou "en" */
const char *T(tm_msg id);

#endif
