#!/usr/bin/env bash
# Teste de integração do driver MySQL contra o container de docker/compose.yml.
# Uso (WSL, na raiz do projeto):  bash tests/mysql.sh
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

echo "== conexão e autenticação"
run "caching_sha2 + RSA (usuário comum)" '"ok":true,"version":"MySQL 8' call test_connection '{"connection":"my"}'
run "root"                                '"ok":true'                   call test_connection '{"connection":"my-rw"}'
printf '%s' '{"name":"x","type":"mysql","host":"127.0.0.1","port":53306,"user":"tmdb","password":"errada"}' >/tmp/tmdb_bad.json
run "senha errada" '"kind":"auth"' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_bad.json"

echo "== mysql_native_password"
call execute '{"connection":"my-rw","sql":"drop user if exists nativo@'"$Q"'%'"$Q"'"}' >/dev/null
native="$(call execute '{"connection":"my-rw","sql":"create user nativo@'"$Q"'%'"$Q"' identified with mysql_native_password by '"$Q"'Nat_123456'"$Q"'"}' 2>&1)"
if grep -q '"ok":true' <<<"$native"; then
  printf '%s' '{"name":"x","type":"mysql","host":"127.0.0.1","port":53306,"user":"nativo","password":"Nat_123456"}' >/tmp/tmdb_nat.json
  run "login com mysql_native_password (troca de plugin)" '"ok":true' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_nat.json"
else
  echo "  --    plugin mysql_native_password desligado neste servidor (padrão do MySQL 8.4): pulado"
fi

echo "== preparação (escrita, várias instruções)"
call execute '{"connection":"my-rw","sql":"set session cte_max_recursion_depth = 5000; drop table if exists tmdb_t; create table tmdb_t(id int primary key, nome varchar(200) not null, valor decimal(10,2), ativo tinyint(1) default 1, criado datetime default current_timestamp, dados json, bin varbinary(8), grande bigint unsigned, flag bit(3), key tmdb_t_nome(nome)) default charset=utf8mb4; insert into tmdb_t(id,nome,valor,ativo,dados,bin,grande,flag) with recursive g(n) as (select 1 union all select n+1 from g where n < 1200) select n, concat('"$Q"'item '"$Q"', n), n*1.5, n%2=0, json_object('"$Q"'n'"$Q"', n), unhex('"$Q"'DEADBEEF'"$Q"'), 18446744073709551615, b'"$Q"'101'"$Q"' from g; insert into tmdb_t(id,nome) values (5000, '"$Q"'ação “üñí” 日本語 🚀'"$Q"'); grant select on tmdb.* to tmdb@'"$Q"'%'"$Q"'"}' >/dev/null
run "execute devolve afetados"  '"affected":1'   call execute '{"connection":"my-rw","sql":"update tmdb_t set valor = 1 where id = 1"}'

echo "== consulta e tipos"
run "tipos e valores"   '[1,"item 1",1.00,0,"{\"n\": 1}","0xdeadbeef",18446744073709551615,5]' call query '{"connection":"my","sql":"select id,nome,valor,ativo,dados,bin,grande,flag from tmdb_t where id=1"}'
run "nomes de tipo"     '"types":["int","varchar","decimal","tinyint","json","varbinary","bigint unsigned","bit"]' call query '{"connection":"my","sql":"select id,nome,valor,ativo,dados,bin,grande,flag from tmdb_t where id=1"}'
run "nulo"              '[5000,null]'            call query '{"connection":"my","sql":"select id, valor from tmdb_t where id=5000"}'
run "unicode"           'ação “üñí” 日本語 🚀'    call query '{"connection":"my","sql":"select nome from tmdb_t where id=5000"}'
run "limite de linhas"  '"rowCount":500,"truncated":true' call query '{"connection":"my","sql":"select id from tmdb_t order by id"}'
run "max_rows"          '"rowCount":3,"truncated":true'   call query '{"connection":"my","sql":"select id from tmdb_t order by id","max_rows":3}'
run "erro de SQL"       'SQLSTATE 42S02'         call query '{"connection":"my","sql":"select * from nao_existe"}'
run "conexão sobrevive ao erro" '"rows":['       call query '{"connection":"my","sql":"select 1 as um"}'
run "SHOW"              '"tmdb_t"'               call query '{"connection":"my","sql":"show tables"}'
run "célula grande cortada" '"cellsTruncated":true' call query '{"connection":"my","sql":"select repeat('"$Q"'x'"$Q"', 20000) as big"}'

echo "== guarda de leitura"
run "DML barrado"            'must start with'           call query '{"connection":"my-rw","sql":"delete from tmdb_t"}'
run "multi-instrução"        'only a single statement'   call query '{"connection":"my-rw","sql":"select 1; select 2"}'
run "comentário executável"  'executable comments'       call query '{"connection":"my-rw","sql":"select 1 /*!50000 , sleep(0) */"}'
run "INTO OUTFILE"           "keyword 'INTO'"            call query '{"connection":"my-rw","sql":"select 1 into outfile '"$Q"'/tmp/x'"$Q"'"}'
run "-- sem espaço não é comentário" "keyword 'INTO'"   call query '{"connection":"my-rw","sql":"select 5 --1 into @v"}'
run "execute em conexão RO"  'is read-only'              call execute '{"connection":"my","sql":"delete from tmdb_t"}'
run "dados intactos"         '[1201]'                    call query '{"connection":"my","sql":"select count(*) from tmdb_t"}'

echo "== metadados"
run "server_info"      '"database"'                    call server_info '{"connection":"my"}'
run "list_schemas"     '["tmdb",'                      call list_schemas '{"connection":"my"}'
run "list_tables"      '["tmdb","tmdb_t","table"'      call list_tables '{"connection":"my","pattern":"tmdb%"}'
run "describe colunas" '["valor","decimal(10,2)","YES",null,null,null]' call describe_table '{"connection":"my","table":"tmdb_t"}'
run "describe PK"      '["PRIMARY","primary key","id"' call describe_table '{"connection":"my","table":"tmdb_t"}'
run "describe índice"  '["tmdb_t_nome","no","nome"'    call describe_table '{"connection":"my","table":"tmdb_t"}'
run "tabela inexistente" 'not found'                   call describe_table '{"connection":"my","table":"xyz"}'
run "search_columns"   '"tmdb_t","criado"'             call search_columns '{"connection":"my","pattern":"cria%"}'
run "explain"          'tmdb_t'                        call explain '{"connection":"my","sql":"select * from tmdb_t where id = 7"}'

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
