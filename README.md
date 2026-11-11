# Tootega Multi-Database MCP

Servidor MCP para PostgreSQL, MySQL / MariaDB, SQL Server e Oracle, com núcleo em C puro
(sem bibliotecas de terceiros, linkado estaticamente) e uma extensão do VS Code para configurar
as conexões. A página do produto está em [`extension/README.md`](extension/README.md); os
requisitos, em [`docs/REQUISITOS.md`](docs/REQUISITOS.md).

## Organização

| Pasta | Conteúdo |
|-------|----------|
| `core/` | O executável `tmdb`: protocolos dos quatro bancos, criptografia, TLS 1.3, servidor MCP |
| `extension/` | Extensão do VS Code (JavaScript puro): tela de conexões e registro do servidor MCP |
| `docker/` | Bancos de teste (`compose.yml`) e imagem de build (`build.Dockerfile`) |
| `scripts/` | Build de distribuição, empacotamento e atalho de desenvolvimento |
| `tests/` | Testes de integração contra bancos reais |
| `tools/` | Bancada da tela, gravador das animações, medição de desempenho |

## Compilar e testar

Tudo roda no WSL; nada precisa ser instalado no Windows além do Node (para a extensão).

```bash
docker compose -f docker/compose.yml up -d     # bancos de teste
bash scripts/dev.sh pg mysql mariadb mssql oracle mcp   # compila e roda os testes
bash tests/tls-setup.sh && bash tests/tls-setup-mssql.sh && bash tests/tls.sh   # TLS 1.3
make -C core debug                             # build com ASan/UBSan (core/build/tmdb-debug)
bash scripts/build-dist.sh                     # binários estáticos em dist/ (soma 1 ao BUILD)
```

No Windows (PowerShell):

```powershell
node tools\demo\ui-test.js      # interação da tela de conexões
node tools\demo\host-test.js    # host da extensão com a API do VS Code simulada
node tools\demo\record.js       # regrava as animações da página
pwsh scripts\package.ps1        # gera dist\tootega-mdb-<versão>.<build>.vsix
```

## Versão e build

A versão do produto fica em `core/src/tm.h` (`TM_VERSION_BASE`) e em `extension/package.json`.
O arquivo `BUILD` guarda o número do build: `scripts/build-dist.sh` soma um a cada execução e o
número entra no executável (`tmdb version` → `1.0.0.N`) e no nome do `.vsix`.

## Diagnóstico

```bash
tmdb selftest                                  # vetores de teste de toda a criptografia
tmdb tlsprobe HOST PORTA verify-full [ca.pem]  # só o aperto de mão TLS, com validação
tmdb --config arquivo.json call query '{"connection":"x","sql":"select 1"}'
```
