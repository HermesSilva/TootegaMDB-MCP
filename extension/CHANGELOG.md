# Changelog

## 1.0.0

First version.

- Native C core, statically linked, for Windows x64 and Linux x64 — no dependencies.
- Own implementation of four wire protocols: PostgreSQL (v3), MySQL / MariaDB, SQL Server (TDS 7.4)
  and Oracle (TNS / TTC).
- Authentication: SCRAM-SHA-256 and MD5 (PostgreSQL), `caching_sha2_password` with RSA and
  `mysql_native_password` (MySQL), SQL login (SQL Server), O5LOGON 11g / 12c (Oracle).
- Registers itself with Claude Code (user scope) when the Claude Code CLI is installed.
- Ten MCP tools: `list_connections`, `test_connection`, `server_info`, `list_schemas`,
  `list_tables`, `describe_table`, `search_columns`, `query`, `explain`, `execute`.
- Native TLS 1.3 client (X25519 and P-256 key exchange, AES-GCM, ChaCha20-Poly1305, RSA and ECDSA
  certificate chains, host name verification) with the modes Prefer, Require, Verify CA, Verify full.
- Read-only by default, with a dialect-aware SQL guard and read-only transactions.
- Connections screen with one tab per database, connection-string import and a Test button.
- English and Portuguese.

Known limits: TLS 1.3 only (no TLS 1.2); Oracle TCPS not yet verified against a live listener.
