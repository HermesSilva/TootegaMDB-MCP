#!/usr/bin/env bash
# Teste do protocolo MCP em stdio: uma sessão completa, como um cliente faria.
# Uso (WSL, na raiz do projeto):  bash tests/mcp.sh
set -u
cd "$(dirname "$0")/.."
pass=0; fail=0

out="$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"teste","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"query","arguments":{"connection":"pg","sql":"select 41+1 as resposta"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query","arguments":{"connection":"pg","sql":"drop table x"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"nao/existe"}' \
  '{"jsonrpc":"2.0","id":6,"method":"ping"}' \
  'isto nao e json' \
  | ./core/build/tmdb serve --lang pt --config tests/connections.json)"

check() {
  if grep -qF -- "$2" <<<"$out"; then pass=$((pass+1)); printf '  ok    %s\n' "$1"
  else fail=$((fail+1)); printf '  FAIL  %s\n        esperado: %s\n' "$1" "$2"; fi
}

check "initialize"               '"id":1,"result":{"protocolVersion":"2025-06-18"'
check "serverInfo"               '"serverInfo":{"name":"tootega-mdb"'
check "tools/list"               '"id":2,"result":{"tools":[{"name":"list_connections"'
check "descrição em português"   'Executa uma instrução SQL de leitura'
check "anotação readOnlyHint"    '"readOnlyHint":true'
check "tools/call com id texto"  '"id":"abc","result":{"content":[{"type":"text","text":"{\"columns\":[\"resposta\"]'
check "valor da consulta"        '[42]'
check "erro de ferramenta"       '"isError":true'
check "método desconhecido"      '"id":5,"error":{"code":-32601'
check "ping"                     '"id":6,"result":{}'
check "JSON inválido"            '"id":null,"error":{"code":-32700'

lines="$(grep -c . <<<"$out")"
if [ "$lines" -eq 7 ]; then pass=$((pass+1)); echo "  ok    notificação não gera resposta (7 linhas)"
else fail=$((fail+1)); echo "  FAIL  esperadas 7 linhas de resposta, vieram $lines"; fi

# Cada linha de saída precisa ser JSON legal.
if command -v node >/dev/null; then
  if node -e 'require("fs").readFileSync(0,"utf8").trim().split("\n").forEach(l=>JSON.parse(l))' <<<"$out" 2>/dev/null
  then pass=$((pass+1)); echo "  ok    toda linha é JSON válido"
  else fail=$((fail+1)); echo "  FAIL  linha com JSON inválido"; fi
fi

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
