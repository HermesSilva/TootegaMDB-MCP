# Tootega Multi-Database MCP

**English** | [Português](README.pt-br.md)

MCP server for PostgreSQL, MySQL / MariaDB, SQL Server and Oracle, with a pure C core
(no third-party libraries, statically linked) and a VS Code extension to configure the
connections. Install it from the
[Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=HermesSilva.tootega-mdb).
The product page is [`extension/README.md`](extension/README.md); the
requirements are in [`docs/REQUISITOS.md`](docs/REQUISITOS.md).

## Layout

| Folder | Contents |
|--------|----------|
| `core/` | The `tmdb` executable: the four database protocols, cryptography, TLS 1.3, MCP server |
| `extension/` | VS Code extension (plain JavaScript): connections screen and MCP server registration |
| `docker/` | Test databases (`compose.yml`) and build image (`build.Dockerfile`) |
| `scripts/` | Distribution build, packaging and development shortcut |
| `tests/` | Integration tests against real databases |
| `tools/` | Screen test bench, animation recorder, performance measurement |

## Build and test

Everything runs in WSL; nothing needs to be installed on Windows besides Node (for the extension).

```bash
docker compose -f docker/compose.yml up -d     # test databases
bash scripts/dev.sh pg mysql mariadb mssql oracle mcp   # build and run the tests
bash tests/tls-setup.sh && bash tests/tls-setup-mssql.sh && bash tests/tls.sh   # TLS 1.3
make -C core debug                             # build with ASan/UBSan (core/build/tmdb-debug)
bash scripts/build-dist.sh                     # static binaries in dist/ (adds 1 to BUILD)
```

On Windows (PowerShell):

```powershell
node tools\demo\ui-test.js      # connections screen interaction
node tools\demo\host-test.js    # extension host with a simulated VS Code API
node tools\demo\record.js       # re-records the page animations
pwsh scripts\package.ps1        # produces dist\tootega-mdb-<version>.<build>.vsix
```

## Version and build

The product version lives in `core/src/tm.h` (`TM_VERSION_BASE`) and in `extension/package.json`.
The `BUILD` file holds the build number: `scripts/build-dist.sh` adds one on every run, and the
number goes into the executable (`tmdb version` → `1.0.0.N`) and into the `.vsix` file name.

## Diagnostics

```bash
tmdb selftest                                  # test vectors for all the cryptography
tmdb tlsprobe HOST PORT verify-full [ca.pem]   # TLS handshake only, with validation
tmdb --config file.json call query '{"connection":"x","sql":"select 1"}'
```
