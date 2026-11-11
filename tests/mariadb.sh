#!/usr/bin/env bash
# MariaDB: mesmo driver do MySQL, outro método de autenticação (mysql_native_password).
# Uso (WSL, na raiz do projeto):  bash tests/mariadb.sh
set -u
cd "$(dirname "$0")/.."
T="${TMDB:-./core/build/tmdb} --lang en --config tests/connections.json"
pass=0; fail=0

run() {
  local name="$1" expect="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if grep -qF -- "$expect" <<<"$out"; then pass=$((pass+1)); printf '  ok    %s\n' "$name"
  else fail=$((fail+1)); printf '  FAIL  %s\n        esperado: %s\n        obtido:   %s\n' "$name" "$expect" "${out:0:500}"; fi
}
call() { $T call "$@"; }
Q="'"

run "mysql_native_password"   '"ok":true,"version":"MariaDB 11' call test_connection '{"connection":"maria"}'
printf '%s' '{"name":"x","type":"mysql","host":"127.0.0.1","port":53307,"user":"tmdb","password":"errada"}' >/tmp/tmdb_bad.json
run "senha errada"            '"kind":"auth"' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_bad.json"
call execute '{"connection":"maria-rw","sql":"drop table if exists tmdb_t; create table tmdb_t(id int primary key, nome varchar(200) not null, valor decimal(10,2)) default charset=utf8mb4; insert into tmdb_t values (1, '"$Q"'ação 日本語 🚀'"$Q"', 1.5), (2, '"$Q"'b'"$Q"', null)"}' >/dev/null
run "consulta e unicode"      '[1,"ação 日本語 🚀",1.50]'   call query '{"connection":"maria","sql":"select * from tmdb_t order by id"}'
run "nulo"                    '[2,"b",null]'               call query '{"connection":"maria","sql":"select * from tmdb_t order by id"}'
run "guarda de leitura"       'must start with'            call query '{"connection":"maria-rw","sql":"delete from tmdb_t"}'
run "describe"                '["valor","decimal(10,2)","YES"' call describe_table '{"connection":"maria","table":"tmdb_t"}'
run "list_tables"             '"tmdb_t","table"'           call list_tables '{"connection":"maria"}'
run "explain"                 'tmdb_t'                     call explain '{"connection":"maria","sql":"select * from tmdb_t where id = 1"}'

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
