#!/usr/bin/env bash
# Compila o núcleo e roda os testes pedidos; para se a compilação falhar.
# Uso (WSL, na raiz do projeto):  bash scripts/dev.sh [pg mysql mssql oracle mcp ...]
#   sem argumentos: só compila e roda o selftest.
set -uo pipefail
cd "$(dirname "$0")/.."

if ! make -C core -s 2>&1 | grep -v '^make' | head -40; then :; fi
if ! make -C core -s -q 2>/dev/null; then
  echo "BUILD FALHOU"
  exit 1
fi
./core/build/tmdb selftest | tail -1

status=0
for t in "$@"; do
  echo
  echo "######## $t"
  bash "tests/$t.sh" || status=1
done
exit $status
