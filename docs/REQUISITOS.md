# Tootega Multi-Database MCP — Requisitos expandidos

Nome do produto: **Tootega Multi-Database MCP** (identificador técnico `tootega-mdb`, executável `tmdb`).

Servidor MCP multi-banco para o VS Code, com núcleo em C puro, sem bibliotecas de terceiros,
linkado estaticamente, para Windows e Linux.

## 1. Decisões de base

| Tema | Decisão |
|------|---------|
| Núcleo | C11, um único executável (`tmdb`), sem dependência de biblioteca externa |
| Linkagem | 100% estática. Linux: musl (`-static`). Windows: mingw-w64 (`-static`), só DLLs do próprio SO (kernel32, ws2_32, advapi32, crypt32) |
| Protocolos | Implementação própria do protocolo de rede de cada banco (sem libpq, libmysqlclient, ODBC, OCI) |
| Criptografia | Própria: MD5, SHA-1, SHA-2, HMAC, PBKDF2, HKDF, AES (CBC/GCM), ChaCha20-Poly1305, X25519, P-256/P-384, RSA |
| TLS | TLS 1.3 próprio em C, com validação de cadeia X.509 e de nome do host |
| Casca VS Code | Extensão mínima em JavaScript puro (exigência do VS Code), sem pacotes npm em runtime e sem etapa de build |
| Idiomas | Português e inglês em tudo: interface, descrições das ferramentas MCP, mensagens de erro |
| Build | Em container (Alpine: gcc/musl + mingw-w64), acionado pelo WSL; nada é instalado na máquina |

Limite conhecido do TLS 1.3 exclusivo: servidores que só falam TLS 1.2 (SQL Server até 2019,
SQL Server 2022 sem TLS 1.3 habilitado, Oracle anterior ao 23ai) não aceitam conexão
criptografada. A camada de transporte é abstraída para que TLS 1.2 entre depois como fase própria,
reaproveitando as mesmas primitivas.

Estado da implementação do TLS: troca de chaves X25519 e P-256 (PostgreSQL até a 17 e MySQL só
aceitam P-256); cifras AES-128-GCM, AES-256-GCM e ChaCha20-Poly1305; certificados RSA (PKCS#1 e
PSS) e ECDSA (P-256, P-384); modos `prefer`, `require`, `verify-ca` e `verify-full`. Verificado
contra PostgreSQL, MySQL, MariaDB, SQL Server 2022 (TDS 7.x com TLS 1.3 habilitado) e OpenSSL.
Pendente: Oracle TCPS contra um listener real e o modo estrito do SQL Server (TDS 8.0) contra um
servidor com certificado aceito para esse modo.

## 2. Arquitetura

```
VS Code ── extensão (JS) ──┬── webview de configuração (abas, lista, formulário, Testar)
                           ├── SecretStorage (senhas)            connections.json (sem senhas)
                           └── registra o servidor MCP ──► tmdb serve   (stdio, JSON-RPC 2.0)
                                                             │
                              ┌──────────────┬───────────────┼──────────────┬─────────────┐
                              MCP/JSON     ferramentas     guarda de      transporte    cripto/TLS
                                                           leitura        (TCP/TLS)
                              └──────────────┴───────┬───────┴──────────────┴─────────────┘
                                     drivers: PostgreSQL · MySQL · SQL Server (TDS) · Oracle (TNS/TTC)
```

- O executável também funciona sozinho (Claude Code, Cursor, linha de comando), lendo um arquivo
  de configuração, sem o VS Code.
- Um driver por banco atrás de uma interface única (`connect`, `query`, `close`); as ferramentas
  de metadados são SQL de catálogo por sabor, passando pelo mesmo caminho de consulta.

## 3. Bancos e o que cada driver cobre

| Banco | Protocolo | Autenticação | Particularidades na configuração |
|-------|-----------|--------------|----------------------------------|
| PostgreSQL | v3 (simples e estendido) | trust, senha em claro, MD5, SCRAM-SHA-256 | banco, `search_path`, `application_name`, modo SSL |
| MySQL / MariaDB | handshake v10, protocolo texto | `mysql_native_password`, `caching_sha2_password` (com RSA sem TLS) | banco padrão, charset, modo SSL |
| SQL Server | TDS 7.4 (e 8.0 no modo estrito) | login SQL | instância nomeada (SQL Browser), banco, `Encrypt`, confiar no certificado, `ApplicationIntent` |
| Oracle | TNS + TTC | O5LOGON (verificadores 11g e 12c) | Service Name ou SID, schema padrão |

## 4. Ferramentas MCP

| Ferramenta | Função | Efeito |
|------------|--------|--------|
| `list_connections` | Lista conexões configuradas (sem segredos) | leitura |
| `test_connection` | Conecta, autentica e devolve versão e latência | leitura |
| `server_info` | Versão, usuário, banco/schema atuais | leitura |
| `list_schemas` | Schemas (ou bancos, no MySQL) | leitura |
| `list_tables` | Tabelas e views de um schema, com filtro por padrão | leitura |
| `describe_table` | Colunas, tipos, nulabilidade, PK, FKs e índices | leitura |
| `search_columns` | Procura tabelas/colunas por nome em todos os schemas | leitura |
| `query` | Executa uma consulta de leitura | leitura |
| `explain` | Plano de execução de uma consulta | leitura |
| `execute` | DML/DDL — só existe para conexões com escrita liberada | escrita |

Requisitos de eficiência para o modelo:
- Resultado compacto (colunas uma vez, linhas como arrays), com formatos `json`, `csv` e `markdown`.
- Limite de linhas e de tamanho de célula por conexão e por chamada; sinalização de truncamento.
- Tipos preservados (número, booleano, nulo, texto); binário em hexadecimal abreviado.
- Anotações MCP (`readOnlyHint`, `destructiveHint`) e títulos/descrições no idioma ativo.

## 5. Segurança

- **Somente leitura por padrão**: toda conexão nasce `readOnly`. Escrita é opt-in por conexão,
  e só então a ferramenta `execute` aceita essa conexão.
- **Guarda de leitura em duas camadas**:
  1. léxica, igual para todos: instrução única, primeira palavra em lista permitida, palavras de
     escrita barradas fora de literais e comentários;
  2. no servidor, onde o banco oferece: transação `READ ONLY` com protocolo de instrução única
     (PostgreSQL estendido, MySQL sem multi-statements), sempre encerrada com `ROLLBACK`.
- A guarda é defesa em profundidade; a garantia real é um usuário de banco só com permissão de
  leitura — a interface diz isso.
- **Senhas** ficam no `SecretStorage` do VS Code (cofre do SO), nunca no arquivo de conexões nem
  em log. Chegam ao executável pelo ambiente do processo. No uso avulso, `${env:NOME}`.
- Senha nunca volta em resultado de ferramenta nem em mensagem de erro.
- TLS: modos `disable`, `prefer`, `require`, `verify-ca`, `verify-full`; CA do sistema ou arquivo
  informado; "confiar no certificado do servidor" explícito e sinalizado.
- Tempo limite de conexão e de consulta; conexão descartada ao estourar.
- Rótulo de ambiente (dev/homologação/produção) com cor, para o humano ver onde o agente está.

## 6. Tela de configuração (extensão)

- Abas no topo, uma por sabor: PostgreSQL, MySQL, SQL Server, Oracle, com contador de conexões.
- À esquerda, lista de conexões nomeadas do sabor ativo; no cabeçalho da lista, botões
  **Incluir** e **Remover** (e Duplicar).
- À direita, o formulário da conexão selecionada, com os campos que aquele banco exige, em
  grupos: Geral, Autenticação, Segurança (SSL/TLS), Limites, Avançado.
- Botão **Testar** no painel: executa o teste real pelo executável e mostra sucesso com versão do
  servidor e latência, ou o erro do banco traduzido.
- Extras: colar string/URL de conexão para preencher o formulário; validação em linha; indicação
  de alterações não salvas; Salvar/Descartar; nome único por sabor; porta padrão automática;
  atalhos de teclado; tema claro/escuro/alto contraste herdado do VS Code.
- Ao salvar, o VS Code é avisado e o servidor MCP passa a enxergar as conexões novas sem reinício
  manual.
- Comandos na paleta: abrir configuração, testar conexão, mostrar log do servidor.

## 7. Qualidade

- Avisos do compilador no máximo (`-Wall -Wextra -Werror`), sem comportamento indefinido conhecido;
  build de depuração com ASan/UBSan.
- `tmdb selftest`: vetores oficiais de teste para cada primitiva criptográfica.
- Testes de integração contra containers reais (`docker/compose.yml`), um por banco, cobrindo
  autenticação, tipos, nulos, Unicode, resultados grandes, erros e a guarda de leitura.
- Toda entrada de rede é tratada como hostil: tamanhos conferidos antes de ler, sem confiar em
  comprimentos declarados pelo servidor.

## 8. Página do Marketplace

- Página rica de apresentação do produto: proposta de valor, os quatro bancos, ferramentas MCP,
  segurança (somente leitura por padrão), "zero dependências", início rápido, perguntas frequentes.
- **Animações** da tela de configuração, no mínimo duas, cada uma com um banco diferente
  (ex.: PostgreSQL e SQL Server): incluir conexão, preencher, Testar, salvar. Geradas a partir da
  própria tela real da extensão, por script reprodutível, uma versão em PT e outra em EN.
- Formato GIF animado: o Marketplace recusa SVG em README e remove scripts, então não há como
  animar nem trocar idioma por código na página.
- **Idioma**: o Marketplace não escolhe o README pelo idioma do visitante — ele publica um único
  `README.md` e a documentação oficial só prevê tradução para `package.json` (`package.nls.*`),
  textos do código (`l10n`) e walkthroughs. Solução adotada:
  - `README.md` bilíngue, inglês primeiro (regra "outro idioma → EN"), com seletor
    **English | Português** no topo levando à seção completa em português, com suas próprias
    animações em PT;
  - nome, descrição, comandos e configurações traduzidos por `package.nls.json` (EN, padrão) e
    `package.nls.pt-br.json` — esses seguem o idioma do VS Code automaticamente;
  - walkthrough de boas-vindas dentro do VS Code, com as mesmas animações, em arquivos por
    idioma (`*.md` e `*.pt-br.md`) — aqui a troca automática PT/EN com queda para EN funciona.

## 9. Fases de entrega

| Fase | Conteúdo |
|------|----------|
| 0 | Esqueleto: build estático nos dois SOs, JSON, laço MCP, configuração, i18n, guarda de leitura |
| 1 | PostgreSQL completo + ferramentas |
| 2 | Extensão VS Code: tela de configuração, Testar, registro do servidor MCP |
| 3 | MySQL |
| 4 | SQL Server |
| 5 | Oracle |
| 6 | TLS 1.3 próprio + validação X.509, ligado aos quatro drivers |
| 7 | Empacotamento `.vsix` com binários das duas plataformas |
| 8 | Página do Marketplace: README bilíngue, animações PT/EN geradas por script, walkthrough localizado |
| Futuro | TLS 1.2, autenticação integrada (Kerberos/NTLM), túnel SSH, parâmetros vinculados |
