#!/usr/bin/env bash
# Teste de integração do driver SQL Server contra o container de docker/compose.yml.
# Uso (WSL, na raiz do projeto):  bash tests/mssql.sh
set -u
cd "$(dirname "$0")/.."
T="${TMDB:-./core/build/tmdb} --lang en --config tests/connections.json"
pass=0; fail=0

run() {
  local name="$1" expect="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if grep -qF -- "$expect" <<<"$out"; then pass=$((pass+1)); printf '  ok    %s\n' "$name"
  else fail=$((fail+1)); printf '  FAIL  %s\n        esperado: %s\n        obtido:   %s\n' "$name" "$expect" "${out:0:600}"; fi
}
call() { $T call "$@"; }
Q="'"

echo "== conexão e autenticação"
run "login SQL" '"ok":true,"version":"Microsoft SQL Server 2022' call test_connection '{"connection":"ms"}'
printf '%s' '{"name":"x","type":"mssql","host":"127.0.0.1","port":51433,"user":"sa","password":"errada"}' >/tmp/tmdb_bad.json
run "senha errada" '"kind":"auth"' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_bad.json"
printf '%s' '{"name":"x","type":"mssql","host":"127.0.0.1","port":51433,"user":"sa","password":"Tmdb_Test_123","database":"nao_existe"}' >/tmp/tmdb_bad.json
run "banco inexistente" '"ok":false' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_bad.json"

echo "== preparação (escrita)"
call execute '{"connection":"ms-rw","sql":"if db_id('"$Q"'tmdb'"$Q"') is null create database tmdb"}' >/dev/null
call execute '{"connection":"ms-rw","sql":"use tmdb; drop table if exists dbo.tmdb_f; drop table if exists dbo.tmdb_t; create table dbo.tmdb_t(id int not null constraint pk_tmdb_t primary key, nome nvarchar(200) not null, valor decimal(10,2), ativo bit default 1, criado datetime2(3) default sysdatetime(), obs varchar(50), bin varbinary(8), grande bigint, preco money, guid uniqueidentifier, dia date, hora time(2), dto datetimeoffset(0), real4 real, dbl float, longo nvarchar(max), antigo datetime, xmlc xml); create index tmdb_t_nome on dbo.tmdb_t(nome); create table dbo.tmdb_f(id int primary key, t_id int constraint fk_tmdb_f references dbo.tmdb_t(id)); with g(n) as (select 1 union all select n + 1 from g where n < 1200) insert into dbo.tmdb_t(id, nome, valor, ativo, obs, bin, grande, preco, guid, dia, hora, dto, real4, dbl, longo, antigo, xmlc) select n, concat('"$Q"'item '"$Q"', n), n * 1.5, n % 2, '"$Q"'ação'"$Q"', 0xDEADBEEF, 9223372036854775807, -12.3456, '"$Q"'6F9619FF-8B86-D011-B42D-00C04FC964FF'"$Q"', '"$Q"'2024-02-29'"$Q"', '"$Q"'13:45:07.25'"$Q"', '"$Q"'2024-02-29 23:30:00 -03:00'"$Q"', 1.5, 0.1, replicate(cast(N'"$Q"'ab'"$Q"' as nvarchar(max)), 6000), '"$Q"'1999-12-31 23:59:59.997'"$Q"', '"$Q"'<a b=\"1\"/>'"$Q"' from g option (maxrecursion 5000); insert into dbo.tmdb_t(id, nome) values (5000, N'"$Q"'ação “üñí” 日本語 🚀'"$Q"')"}' >/dev/null
run "execute devolve afetados" '"affected":1' call execute '{"connection":"ms-rw","sql":"update tmdb.dbo.tmdb_t set valor = 1 where id = 1"}'

S='select id, nome, valor, ativo, obs, bin, grande, preco, guid, dia, hora, dto, real4, dbl, antigo, xmlc from tmdb.dbo.tmdb_t where id = 1'
echo "== consulta e tipos"
run "inteiro, texto, decimal, bit" '[1,"item 1",1.00,true,"ação","0xdeadbeef",9223372036854775807,-12.3456,' call query '{"connection":"ms","sql":"'"$S"'"}'
run "guid"            '"6F9619FF-8B86-D011-B42D-00C04FC964FF"' call query '{"connection":"ms","sql":"'"$S"'"}'
run "date e time"     '"2024-02-29","13:45:07.25"'              call query '{"connection":"ms","sql":"'"$S"'"}'
run "datetimeoffset"  '"2024-02-29 23:30:00 -03:00"'            call query '{"connection":"ms","sql":"'"$S"'"}'
run "real e float"    ',1.5,0.1,'                               call query '{"connection":"ms","sql":"'"$S"'"}'
run "datetime antigo" '"1999-12-31 23:59:59.997"'               call query '{"connection":"ms","sql":"'"$S"'"}'
run "xml"             '<a b=\"1\"/>'                            call query '{"connection":"ms","sql":"'"$S"'"}'
run "nomes de tipo"   '"types":["int","nvarchar","decimal","bit","varchar","varbinary","bigint","money","uniqueidentifier","date","time","datetimeoffset","real","float","datetime","xml"]' call query '{"connection":"ms","sql":"'"$S"'"}'
run "datetime2"       '"2024-01-02 03:04:05.678"'  call query '{"connection":"ms","sql":"select cast('"$Q"'2024-01-02 03:04:05.678'"$Q"' as datetime2(3)) as d"}'
run "nvarchar(max) longo cortado" '"cellsTruncated":true' call query '{"connection":"ms","sql":"select longo from tmdb.dbo.tmdb_t where id = 1"}'
run "nulos (NBCROW)"  '[5000,null,null,null,null]' call query '{"connection":"ms","sql":"select id, valor, obs, guid, longo from tmdb.dbo.tmdb_t where id = 5000"}'
run "unicode"         'ação “üñí” 日本語 🚀'        call query '{"connection":"ms","sql":"select nome from tmdb.dbo.tmdb_t where id = 5000"}'
run "sql_variant"     '["Developer Edition (64-bit)"' call query '{"connection":"ms","sql":"select serverproperty('"$Q"'Edition'"$Q"') as e, serverproperty('"$Q"'ProductMajorVersion'"$Q"') as v"}'
run "decimal negativo e pequeno" '[-0.05,123456789012345678901234567890.12]' call query '{"connection":"ms","sql":"select cast(-0.05 as decimal(5,2)) as a, cast(123456789012345678901234567890.12 as decimal(38,2)) as b"}'
run "smalldatetime e smallmoney" '["2024-05-06 07:08:00",1.5000]' call query '{"connection":"ms","sql":"select cast('"$Q"'2024-05-06 07:08'"$Q"' as smalldatetime) as a, cast(1.5 as smallmoney) as b"}'
run "limite de linhas" '"rowCount":500,"truncated":true' call query '{"connection":"ms","sql":"select id from tmdb.dbo.tmdb_t order by id"}'
run "resultado de vários pacotes" '"rowCount":300' call query '{"connection":"ms","sql":"select top 300 id, nome, obs, guid from tmdb.dbo.tmdb_t order by id"}'
run "erro de SQL"      'Msg 208'                  call query '{"connection":"ms","sql":"select * from nao_existe"}'
run "conexão sobrevive ao erro" '"rows":['        call query '{"connection":"ms","sql":"select 1 as um"}'
run "aviso PRINT"      '"notices":["ola"]'        call execute '{"connection":"ms-rw","sql":"print '"$Q"'ola'"$Q"'; select 1 as um"}'
run "vários conjuntos" '"results":['              call execute '{"connection":"ms-rw","sql":"select 1 as a; select 2 as b"}'

echo "== guarda de leitura"
run "DML barrado"        'must start with'          call query '{"connection":"ms-rw","sql":"delete from tmdb.dbo.tmdb_t"}'
run "multi-instrução"    'only a single statement'  call query '{"connection":"ms-rw","sql":"select 1; select 2"}'
run "lote sem ponto e vírgula" "keyword 'DELETE'"   call query '{"connection":"ms-rw","sql":"select 1 delete from tmdb.dbo.tmdb_t"}'
run "SELECT INTO"        "keyword 'INTO'"           call query '{"connection":"ms-rw","sql":"select * into tmdb.dbo.copia from tmdb.dbo.tmdb_t"}'
run "EXEC"               "keyword 'EXEC'"           call query '{"connection":"ms-rw","sql":"select 1 exec sp_who"}'
run "OPENROWSET"         "keyword 'OPENROWSET'"     call query '{"connection":"ms-rw","sql":"select * from openrowset(bulk '"$Q"'x'"$Q"', single_clob) a"}'
run "colchetes protegem nome" '"rows":['            call query '{"connection":"ms","sql":"select 1 as [delete]"}'
run "execute em conexão RO" 'is read-only'          call execute '{"connection":"ms","sql":"delete from tmdb.dbo.tmdb_t"}'
run "dados intactos"     '[1201]'                   call query '{"connection":"ms","sql":"select count(*) from tmdb.dbo.tmdb_t"}'

echo "== metadados"
sed 's/"database": "master", "readOnly": false/"database": "tmdb", "readOnly": false/; s/"database": "master" }/"database": "tmdb" }/' tests/connections.json >/tmp/tmdb_ms.json
M="${TMDB:-./core/build/tmdb} --lang en --config /tmp/tmdb_ms.json call"
run "server_info"      '"tmdb","dbo"'               $M server_info '{"connection":"ms"}'
run "list_schemas"     '["dbo","dbo",2]'            $M list_schemas '{"connection":"ms"}'
run "list_tables"      '["dbo","tmdb_t","table",1201' $M list_tables '{"connection":"ms","pattern":"tmdb%"}'
run "describe colunas" '["valor","decimal(10,2)","YES",null,null,null]' $M describe_table '{"connection":"ms","table":"tmdb_t"}'
run "describe default" '["ativo","bit","YES","((1))"' $M describe_table '{"connection":"ms","table":"tmdb_t"}'
run "describe PK"      '["pk_tmdb_t","primary key","id",null,null]' $M describe_table '{"connection":"ms","table":"tmdb_t"}'
run "describe FK"      '["fk_tmdb_f","foreign key","t_id","dbo.tmdb_t","id"]' $M describe_table '{"connection":"ms","table":"tmdb_f","schema":"dbo"}'
run "describe índice"  '["tmdb_t_nome","no","nome","nonclustered"]' $M describe_table '{"connection":"ms","table":"tmdb_t"}'
run "tabela inexistente" 'not found'                $M describe_table '{"connection":"ms","table":"xyz"}'
run "search_columns"   '["dbo","tmdb_t","criado","datetime2"]' $M search_columns '{"connection":"ms","pattern":"cria%"}'
run "explain não executa" 'Clustered Index Seek'    $M explain '{"connection":"ms","sql":"select * from tmdb_t where id = 7"}'
run "plano desligado depois" '[7]'                  $M query '{"connection":"ms","sql":"select id from tmdb_t where id = 7"}'

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
