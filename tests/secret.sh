#!/usr/bin/env bash
# Teste do cofre de senhas do executável (secrets.bin ao lado do arquivo de conexões).
# Uso (WSL, na raiz do projeto):  bash tests/secret.sh
set -u
cd "$(dirname "$0")/.."
B="$(pwd)/${TMDB:-core/build/tmdb}"
D="$(mktemp -d)"; C="$D/connections.json"
pass=0; fail=0
check() { if [ "$2" = "1" ]; then pass=$((pass+1)); printf '  ok    %s\n' "$1"; else fail=$((fail+1)); printf '  FAIL  %s\n        %s\n' "$1" "${3:-}"; fi; }
has() { grep -qF -- "$2" <<<"$1" && echo 1 || echo 0; }

cat > "$C" <<'EOF'
{"version":1,"connections":[
 {"id":"a1","name":"sem-senha-no-arquivo","type":"postgres","host":"127.0.0.1","port":55432,"user":"tmdb","database":"tmdb"}]}
EOF

out="$($B --lang en --config "$C" call test_connection '{"connection":"sem-senha-no-arquivo"}' 2>&1)"
check "sem cofre: o servidor pede senha"        "$(has "$out" 'requires a password')" "$out"

out="$(printf '%s' '{"set":{"a1":"Tmdb_Test_123","b2":"outra \"senha\" ção"}}' | $B --config "$C" secret)"
check "gravar devolve só os ids"                "$(has "$out" '"ids":["a1","b2"]')" "$out"
check "resposta não contém a senha"             "$([ "$(has "$out" 'Tmdb_Test_123')" = 0 ] && echo 1 || echo 0)" "$out"
check "arquivo do cofre não tem a senha em claro" "$(grep -qa 'Tmdb_Test_123' "$D/secrets.bin" && echo 0 || echo 1)"
check "cofre legível só pelo dono (0600)"       "$([ "$(stat -c %a "$D/secrets.bin")" = 600 ] && echo 1 || echo 0)" "$(stat -c %a "$D/secrets.bin")"

out="$($B --lang en --config "$C" call test_connection '{"connection":"sem-senha-no-arquivo"}' 2>&1)"
check "com cofre: conecta sem senha no arquivo nem no ambiente" "$(has "$out" '"ok":true')" "$out"

out="$(printf '%s' '{"name":"x","id":"a1","type":"postgres","host":"127.0.0.1","port":55432,"user":"tmdb","database":"tmdb"}' | $B --config "$C" test)"
check "tmdb test usa a senha salva pelo id"     "$(has "$out" '"ok":true')" "$out"
out="$(printf '%s' '{"name":"x","id":"a1","type":"postgres","host":"127.0.0.1","port":55432,"user":"tmdb","database":"tmdb","password":"errada"}' | $B --config "$C" test)"
check "senha digitada vale sobre a salva"       "$(has "$out" '"kind":"auth"')" "$out"

out="$(printf '%s' '{}' | $B --config "$C" secret)"
check "listar"                                  "$(has "$out" '"ids":["a1","b2"]')" "$out"
out="$(printf '%s' '{"delete":["a1"]}' | $B --config "$C" secret)"
check "remover"                                 "$(has "$out" '"ids":["b2"]')" "$out"

printf 'lixo' > "$D/secrets.bin"
out="$(printf '%s' '{}' | $B --config "$C" secret)"
check "cofre corrompido é tratado como vazio"   "$(has "$out" '"ids":[]')" "$out"

# o servidor em execução passa a enxergar uma senha gravada depois que ele subiu
rm -f "$D/secrets.bin"
out="$( { echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_connection","arguments":{"connection":"sem-senha-no-arquivo"}}}';
          sleep 0.5; printf '%s' '{"set":{"a1":"Tmdb_Test_123"}}' | $B --config "$C" secret >/dev/null; sleep 0.5;
          echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test_connection","arguments":{"connection":"sem-senha-no-arquivo"}}}'; sleep 0.5; } \
        | $B serve --lang en --config "$C")"
check "servidor em execução: antes de salvar, falha"   "$(has "$out" '"id":1,"result":{"content":[{"type":"text","text":"The server requires a password')" "$out"
check "servidor em execução: depois de salvar, conecta sem reiniciar" "$(has "$out" '"id":2,"result":{"content":[{"type":"text","text":"{\"ok\":true')" "$out"

rm -rf "$D"
echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
