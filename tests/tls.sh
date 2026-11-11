#!/usr/bin/env bash
# Teste do TLS 1.3 próprio contra servidores reais.
# Antes:  bash tests/tls-setup.sh   (gera certificados e sobe os PostgreSQL com TLS)
# Uso (WSL, na raiz do projeto):  bash tests/tls.sh
set -u
cd "$(dirname "$0")/.."
B="${TMDB:-./core/build/tmdb}"
T="$B --lang en --config tests/connections.json"
pass=0; fail=0

run() {
  local name="$1" expect="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if grep -qF -- "$expect" <<<"$out"; then pass=$((pass+1)); printf '  ok    %s\n' "$name"
  else fail=$((fail+1)); printf '  FAIL  %s\n        esperado: %s\n        obtido:   %s\n' "$name" "$expect" "${out:0:500}"; fi
}
call() { $T call "$@"; }
Q="'"
SSL='select ssl, version, cipher from pg_stat_ssl where pid = pg_backend_pid()'

echo "== PostgreSQL (certificado RSA)"
run "require: sessão cifrada em TLS 1.3"    '[true,"TLSv1.3","TLS_AES_' call query '{"connection":"pg-tls","sql":"'"$SSL"'"}'
run "verify-full: cadeia e nome conferem"   '[true,"TLSv1.3"'           call query '{"connection":"pg-full","sql":"'"$SSL"'"}'
run "verify-full: nome do host não confere" 'not valid for host'        call test_connection '{"connection":"pg-badhost"}'
run "verify-ca: autoridade errada"          'not issued by a trusted authority' call test_connection '{"connection":"pg-wrongca"}'
run "require contra servidor sem TLS"       'does not offer TLS'        call test_connection '{"connection":"pg-notls"}'
run "prefer contra servidor sem TLS: em claro" '"ok":true'              call test_connection '{"connection":"pg"}'
run "dados grandes pela sessão cifrada"     '"rowCount":500'            call query '{"connection":"pg-tls","sql":"select g, repeat(md5(g::text), 40) from generate_series(1, 5000) g"}'
run "SCRAM por cima do TLS e Unicode"       'ação 日本語 🚀'             call query '{"connection":"pg-full","sql":"select '"$Q"'ação 日本語 🚀'"$Q"' as t"}'

echo "== PostgreSQL (ECDSA P-256, intermediária P-384)"
run "verify-full com cadeia de três níveis" '[true,"TLSv1.3"'           call query '{"connection":"pg-ec","sql":"'"$SSL"'"}'

echo "== MySQL e MariaDB"
MSSL='show session status where variable_name = '"$Q"'Ssl_version'"$Q"
run "MySQL require: TLS 1.3"                '["Ssl_version","TLSv1.3"]' call query '{"connection":"my-tls","sql":"'"$MSSL"'"}'
run "MySQL verify-ca com a CA do servidor"  '["Ssl_version","TLSv1.3"]' call query '{"connection":"my-ca","sql":"'"$MSSL"'"}'
run "MySQL verify-ca com as CAs do sistema: recusa" 'not issued by a trusted authority' call test_connection '{"connection":"my-sys"}'
run "MySQL prefer usa TLS quando há"        '["Ssl_version","TLSv1.3"]' call query '{"connection":"my","sql":"'"$MSSL"'"}'
run "MariaDB require: TLS 1.3"              '["Ssl_version","TLSv1.3"]' call query '{"connection":"maria-tls","sql":"'"$MSSL"'"}'

echo "== SQL Server (TLS 1.3 dentro do TDS; requer tests/tls-setup-mssql.sh)"
if docker ps --format '{{.Names}}' | grep -q '^tmdb-ms-tls$'; then
  MS='select encrypt_option from sys.dm_exec_connections where session_id = @@spid'
  run "verify-full: sessão cifrada"       '["TRUE"]'  call query '{"connection":"ms-strict","sql":"'"$MS"'"}'
  run "prefer usa TLS quando há"          '["TRUE"]'  call query '{"connection":"ms-strict-pref","sql":"'"$MS"'"}'
  run "resultado grande pela sessão cifrada" '"rowCount":500' call query '{"connection":"ms-strict","sql":"select top 3000 a.object_id, a.name, replicate(a.name, 20) from sys.all_objects a cross join sys.all_objects b"}'
else
  echo "  --    container tmdb-ms-tls não está no ar: pulado"
fi
run "servidor só TLS 1.2 com require: mensagem clara" 'TLS 1.3 enabled' call test_connection '{"connection":"ms-tls"}'
run "servidor só TLS 1.2 com prefer: cai para sem cifra" '"ok":true'  call test_connection '{"connection":"ms"}'

echo "== sonda direta (openssl s_server)"
( cd /tmp/tmdb-tls && for s in "44331 -ciphersuites TLS_AES_256_GCM_SHA384" "44332 -ciphersuites TLS_CHACHA20_POLY1305_SHA256" "44333 -tls1_2"; do
    set -- $s; port=$1; shift
    openssl s_server -accept "$port" -cert server.pem -key server.key -quiet "$@" >/dev/null 2>&1 &
  done; sleep 1 )
run "AES-256-GCM / SHA-384"        '"ok":true'  $B --lang en tlsprobe localhost 44331 verify-full /tmp/tmdb-tls/ca.pem
run "ChaCha20-Poly1305"            '"ok":true'  $B --lang en tlsprobe localhost 44332 verify-full /tmp/tmdb-tls/ca.pem
run "servidor só TLS 1.2: mensagem clara" 'does not support TLS 1.3' $B --lang en tlsprobe localhost 44333
pkill -f "openssl s_server" >/dev/null 2>&1

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
