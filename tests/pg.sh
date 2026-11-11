#!/usr/bin/env bash
# Teste de integração do driver PostgreSQL contra o container de docker/compose.yml.
# Uso (WSL, na raiz do projeto):  bash tests/pg.sh
set -u
cd "$(dirname "$0")/.."
T="./core/build/tmdb --lang en --config tests/connections.json"
pass=0; fail=0

# run "descrição" "trecho esperado na saída" comando...
run() {
  local name="$1" expect="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if grep -qF -- "$expect" <<<"$out"; then pass=$((pass+1)); printf '  ok    %s\n' "$name"
  else fail=$((fail+1)); printf '  FAIL  %s\n        esperado: %s\n        obtido:   %s\n' "$name" "$expect" "${out:0:400}"; fi
}
call() { $T call "$@"; }

echo "== conexão e autenticação"
run "test_connection (SCRAM)"   '"ok":true,"version":"PostgreSQL' call test_connection '{"connection":"pg"}'
run "senha errada"              'password authentication failed'   call test_connection '{"connection":"pg-bad"}'
run "conexão inexistente"       "not found"                        call test_connection '{"connection":"nope"}'

echo "== preparação (escrita)"
call execute '{"connection":"pg-rw","sql":"drop table if exists tmdb_t; drop sequence if exists tmdb_seq; create sequence tmdb_seq; create table tmdb_t(id int primary key, nome text not null, valor numeric(10,2), ativo boolean default true, criado timestamptz default now(), dados jsonb); create index tmdb_t_nome on tmdb_t(nome); insert into tmdb_t(id,nome,valor,ativo,dados) select g, '"'"'item '"'"'||g, g*1.5, g%2=0, jsonb_build_object('"'"'n'"'"',g) from generate_series(1,1200) g; insert into tmdb_t(id,nome) values (5000, '"'"'ação “üñí” 日本語 🚀'"'"')"}' >/dev/null
run "execute devolve afetados"  '"affected":1'   call execute '{"connection":"pg-rw","sql":"update tmdb_t set valor = 1 where id = 1"}'

echo "== consulta e tipos"
run "tipos e valores"   '[1,"item 1",1.00,false,' call query '{"connection":"pg","sql":"select id,nome,valor,ativo,dados from tmdb_t where id=1"}'
run "nomes de tipo"     '"types":["int4","text","numeric","bool","jsonb"]' call query '{"connection":"pg","sql":"select id,nome,valor,ativo,dados from tmdb_t where id=1"}'
run "nulo"              '[5000,null]'            call query '{"connection":"pg","sql":"select id, valor from tmdb_t where id=5000"}'
run "unicode"           'ação “üñí” 日本語 🚀'    call query '{"connection":"pg","sql":"select nome from tmdb_t where id=5000"}'
run "limite de linhas"  '"rowCount":500,"truncated":true' call query '{"connection":"pg","sql":"select id from tmdb_t order by id"}'
run "max_rows"          '"rowCount":3,"truncated":true'   call query '{"connection":"pg","sql":"select id from tmdb_t order by id","max_rows":3}'
run "csv"               'id,nome'                call query '{"connection":"pg","sql":"select id,nome from tmdb_t where id<3 order by id","format":"csv"}'
run "markdown"          '| id | nome |'          call query '{"connection":"pg","sql":"select id,nome from tmdb_t where id<3 order by id","format":"markdown"}'
run "erro de SQL"       'SQLSTATE 42P01'         call query '{"connection":"pg","sql":"select * from nao_existe"}'
run "conexão sobrevive ao erro" '"rows":['       call query '{"connection":"pg","sql":"select 1 as um"}'
run "célula grande cortada" '"cellsTruncated":true' call query '{"connection":"pg","sql":"select repeat('"'"'x'"'"', 20000) as big"}'

echo "== guarda de leitura"
run "DML barrado"           "must start with"                  call query '{"connection":"pg","sql":"delete from tmdb_t"}'
run "primeira palavra"      'must start with'                   call query '{"connection":"pg","sql":"drop table tmdb_t"}'
run "multi-instrução"       'only a single statement'           call query '{"connection":"pg","sql":"select 1; select 2"}'
run "CTE com escrita"       "keyword 'DELETE'"                  call query '{"connection":"pg","sql":"with x as (delete from tmdb_t returning *) select * from x"}'
run "SELECT INTO"           "keyword 'INTO'"                    call query '{"connection":"pg","sql":"select * into copia from tmdb_t"}'
run "palavra em literal ok" '"rows":['                          call query '{"connection":"pg","sql":"select '"'"'delete; drop'"'"' as texto -- update\n"}'
# Passa pela guarda léxica (é um SELECT), mas escreve: quem barra é a transação READ ONLY do servidor.
run "transação RO no servidor (função que escreve)" 'read-only transaction' call query '{"connection":"pg","sql":"select nextval('"'"'tmdb_seq'"'"')"}'
run "execute em conexão RO" 'is read-only'                      call execute '{"connection":"pg","sql":"delete from tmdb_t"}'
run "dados intactos"        '[1201]'                            call query '{"connection":"pg","sql":"select count(*) from tmdb_t"}'

echo "== metadados"
run "list_connections" '"name":"pg","type":"postgres"' call list_connections
run "server_info"      '"database"'                   call server_info '{"connection":"pg"}'
run "list_schemas"     '["public",'                   call list_schemas '{"connection":"pg"}'
run "list_tables"      '"tmdb_t","table"'             call list_tables '{"connection":"pg","pattern":"tmdb%"}'
run "describe colunas" '["valor","numeric(10,2)",true,null,null]' call describe_table '{"connection":"pg","table":"tmdb_t"}'
run "describe PK"      'PRIMARY KEY (id)'             call describe_table '{"connection":"pg","table":"tmdb_t"}'
run "describe índice"  'tmdb_t_nome'                  call describe_table '{"connection":"pg","table":"tmdb_t"}'
run "tabela inexistente" 'not found'                  call describe_table '{"connection":"pg","table":"xyz"}'
run "search_columns"   '"tmdb_t","criado"'            call search_columns '{"connection":"pg","pattern":"cria%"}'
run "explain"          'Index Scan'                   call explain '{"connection":"pg","sql":"select * from tmdb_t where id = 7"}'
run "nome com aspas recusado" 'Invalid name'          call describe_table '{"connection":"pg","table":"a'"'"'b"}'

echo "== português"
run "mensagem em pt" 'somente leitura' ./core/build/tmdb --lang pt --config tests/connections.json call query '{"connection":"pg","sql":"delete from tmdb_t"}'

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
