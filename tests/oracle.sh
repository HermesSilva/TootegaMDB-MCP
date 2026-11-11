#!/usr/bin/env bash
# Teste de integração do driver Oracle contra o container de docker/compose.yml.
# Uso (WSL, na raiz do projeto):  bash tests/oracle.sh
set -u
cd "$(dirname "$0")/.."
T="${TMDB:-./core/build/tmdb} --lang en --config tests/connections.json"
pass=0; fail=0

run() {
  local name="$1" expect="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if grep -qF -- "$expect" <<<"$out"; then pass=$((pass+1)); printf '  ok    %s\n' "$name"
  else fail=$((fail+1)); printf '  FAIL  %s\n        esperado: %s\n        obtido:   %s\n' "$name" "$expect" "${out:0:700}"; fi
}
call() { $T call "$@"; }
Q="'"

echo "== conexão e autenticação"
run "login O5LOGON" '"ok":true,"version":"Oracle Database 23' call test_connection '{"connection":"ora"}'
printf '%s' '{"name":"x","type":"oracle","host":"127.0.0.1","port":51521,"user":"tmdb","password":"errada","serviceName":"FREEPDB1"}' >/tmp/tmdb_bad.json
run "senha errada" 'ORA-01017' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_bad.json"
printf '%s' '{"name":"x","type":"oracle","host":"127.0.0.1","port":51521,"user":"tmdb","password":"x","serviceName":"NAOEXISTE"}' >/tmp/tmdb_bad.json
run "serviço inexistente" 'not known to the listener' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_bad.json"
printf '%s' '{"name":"x","type":"oracle","host":"127.0.0.1","port":51521,"user":"system","password":"Tmdb_Test_123","sid":"FREE"}' >/tmp/tmdb_sid.json
run "conexão por SID" '"ok":true' bash -c "${TMDB:-./core/build/tmdb} test </tmp/tmdb_sid.json"

echo "== preparação (escrita, uma instrução por chamada)"
x() { call execute "{\"connection\":\"ora-rw\",\"sql\":\"$1\"}" >/dev/null 2>&1; }
x "drop table tmdb_f purge"
x "drop table tmdb_t purge"
run "DDL" '"ok":true' call execute '{"connection":"ora-rw","sql":"create table tmdb_t(id number(10) constraint pk_tmdb_t primary key, nome varchar2(200 char) not null, valor number(10,2), ativo number(1) default 1, criado timestamp(3) default systimestamp, obs nvarchar2(50), bin raw(8), grande number(38), dia date, tz timestamp(0) with time zone, flt binary_double, longo clob, bl blob, ym interval year to month, ds interval day to second)"}'
x "create index tmdb_t_nome on tmdb_t(nome)"
x "create table tmdb_f(id number primary key, t_id number constraint fk_tmdb_f references tmdb_t(id))"
x "comment on column tmdb_t.valor is ${Q}valor em reais${Q}"
run "INSERT em massa devolve afetados" '"affected":1200' call execute '{"connection":"ora-rw","sql":"insert into tmdb_t(id, nome, valor, ativo, obs, bin, grande, dia, tz, flt, longo, bl, ym, ds) select level, '"$Q"'item '"$Q"' || level, level * 1.5, mod(level, 2), n'"$Q"'ação'"$Q"', hextoraw('"$Q"'DEADBEEF'"$Q"'), 12345678901234567890123456789012345678, date '"$Q"'2024-02-29'"$Q"', timestamp '"$Q"'2024-02-29 23:30:00 -03:00'"$Q"', 0.1, to_clob(rpad('"$Q"'ab'"$Q"', 3000, '"$Q"'ab'"$Q"')) || rpad('"$Q"'cd'"$Q"', 3000, '"$Q"'cd'"$Q"'), hextoraw('"$Q"'CAFEBABE'"$Q"'), interval '"$Q"'2-3'"$Q"' year to month, interval '"$Q"'4 05:06:07.5'"$Q"' day to second from dual connect by level <= 1200"}'
x "insert into tmdb_t(id, nome) values (5000, ${Q}ação “üñí” 日本語 🚀${Q})"
run "UPDATE devolve afetados" '"affected":1' call execute '{"connection":"ora-rw","sql":"update tmdb_t set valor = 1 where id = 1"}'

S='select id, nome, valor, ativo, obs, bin, grande, dia, flt from tmdb_t where id = 1'
echo "== consulta e tipos"
run "número, texto, nvarchar, raw" '[1,"item 1",1,1,"ação","0xdeadbeef",12345678901234567890123456789012345678,"2024-02-29 00:00:00",0.1]' call query '{"connection":"ora","sql":"'"$S"'"}'
run "nomes de tipo"   '"types":["NUMBER","VARCHAR2","NUMBER","NUMBER","NVARCHAR2","RAW","NUMBER","DATE","BINARY_DOUBLE"]' call query '{"connection":"ora","sql":"'"$S"'"}'
run "números variados" '[0,-1.5,0.001,-0.05,1000000,123.456,-99999999.99]' call query '{"connection":"ora","sql":"select 0, -1.5, 0.001, -0.05, 1000000, 123.456, -99999999.99 from dual"}'
run "timestamp"       '"2024-01-02 03:04:05.678"' call query '{"connection":"ora","sql":"select timestamp '"$Q"'2024-01-02 03:04:05.678'"$Q"' from dual"}'
run "timestamp com fuso" '"2024-03-01 02:30:00 UTC (offset -03:00)"' call query '{"connection":"ora","sql":"select tz from tmdb_t where id = 1"}'
run "intervalos"      '["+2-03","+4 05:06:07.500000"]' call query '{"connection":"ora","sql":"select ym, ds from tmdb_t where id = 1"}'
run "CLOB inteiro como texto" 'ababab'            call query '{"connection":"ora","sql":"select longo from tmdb_t where id = 1"}'
run "CLOB longo cortado" '"cellsTruncated":true'  call query '{"connection":"ora","sql":"select longo from tmdb_t where id = 1"}'
run "BLOB em hexadecimal" '"0xcafebabe"'          call query '{"connection":"ora","sql":"select bl from tmdb_t where id = 1"}'
run "CLOB e colunas comuns juntos" '[2,"item 2","0xcafebabe"' call query '{"connection":"ora","sql":"select id, nome, bl, longo from tmdb_t where id = 2"}'
run "rowid"           '"rowCount":1'              call query '{"connection":"ora","sql":"select rowid, id from tmdb_t where id = 3"}'
run "nulos"           '[5000,null,null,null,null,null]' call query '{"connection":"ora","sql":"select id, valor, obs, dia, longo, bl from tmdb_t where id = 5000"}'
run "unicode"         'ação “üñí” 日本語 🚀'       call query '{"connection":"ora","sql":"select nome from tmdb_t where id = 5000"}'
run "limite de linhas" '"rowCount":500,"truncated":true' call query '{"connection":"ora","sql":"select id from tmdb_t order by id"}'
run "valores repetidos entre linhas" '[1200,"ação"]' call query '{"connection":"ora","sql":"select count(*), max(obs) from (select id, obs from tmdb_t where id <= 1200)"}'
run "coluna repetida (vetor de bits)" '[3,"ação","0xdeadbeef"]' call query '{"connection":"ora","sql":"select id, obs, bin from tmdb_t where id <= 5 order by id"}'
run "várias buscas (mais de 200 linhas)" '"rowCount":450' call query '{"connection":"ora","sql":"select id, nome from tmdb_t where id <= 450 order by id"}'
run "erro de SQL"     'ORA-00942'                 call query '{"connection":"ora","sql":"select * from nao_existe"}'
run "conexão sobrevive ao erro" '"rows":['        call query '{"connection":"ora","sql":"select 1 as um from dual"}'
run "ponto e vírgula final tolerado" '[2]'        call query '{"connection":"ora","sql":"select 1 + 1 from dual;"}'
run "PL/SQL"          '"ok":true'                 call execute '{"connection":"ora-rw","sql":"begin update tmdb_t set valor = 2 where id = 2; end;"}'
run "PL/SQL confirmou" '[2]'                      call query '{"connection":"ora","sql":"select valor from tmdb_t where id = 2"}'

echo "== guarda de leitura"
run "DML barrado"        'must start with'          call query '{"connection":"ora-rw","sql":"delete from tmdb_t"}'
run "multi-instrução"    'only a single statement'  call query '{"connection":"ora-rw","sql":"select 1 from dual; select 2 from dual"}'
run "bloco PL/SQL"       'must start with'          call query '{"connection":"ora-rw","sql":"begin null; end;"}'
run "FOR UPDATE"         "keyword 'UPDATE'"         call query '{"connection":"ora-rw","sql":"select * from tmdb_t for update"}'
run "literal q-quote"    '"rows":['                 call query '{"connection":"ora","sql":"select q'"$Q"'[delete; drop]'"$Q"' as t from dual"}'
x "create or replace function tmdb_escreve return number is pragma autonomous_transaction; begin null; return 1; end;"
x "create or replace function tmdb_dml return number is begin delete from tmdb_f; return 1; end;"
run "transação RO no servidor (função com DML)" 'ORA-' call query '{"connection":"ora-rw","sql":"select tmdb_dml from dual"}'
run "execute em conexão RO" 'is read-only'          call execute '{"connection":"ora","sql":"delete from tmdb_t"}'
run "dados intactos"     '[1201]'                   call query '{"connection":"ora","sql":"select count(*) from tmdb_t"}'

echo "== metadados"
run "server_info"      '"TMDB"'                     call server_info '{"connection":"ora"}'
run "list_schemas"     '["TMDB",'                   call list_schemas '{"connection":"ora"}'
run "list_tables"      '["TMDB","TMDB_T","table"'   call list_tables '{"connection":"ora","pattern":"tmdb%"}'
run "describe colunas" '["VALOR","NUMBER(10,2)","YES",null,"valor em reais"]' call describe_table '{"connection":"ora","table":"tmdb_t"}'
run "describe default (coluna LONG)" '["ATIVO","NUMBER(1)","YES","1"' call describe_table '{"connection":"ora","table":"tmdb_t"}'
run "describe PK"      '["PK_TMDB_T","primary key","ID",null,null,null]' call describe_table '{"connection":"ora","table":"tmdb_t"}'
run "describe FK"      '["FK_TMDB_F","foreign key","T_ID","TMDB.TMDB_T","ID",null]' call describe_table '{"connection":"ora","table":"TMDB_F","schema":"tmdb"}'
run "describe índice"  '["TMDB_T_NOME","no","NOME","normal"]' call describe_table '{"connection":"ora","table":"tmdb_t"}'
run "tabela inexistente" 'not found'                call describe_table '{"connection":"ora","table":"xyz"}'
run "search_columns"   '["TMDB","TMDB_T","CRIADO","TIMESTAMP(3)"]' call search_columns '{"connection":"ora","pattern":"cria%"}'
run "explain"          'INDEX UNIQUE SCAN'          call explain '{"connection":"ora","sql":"select * from tmdb_t where id = 7"}'

echo
echo "passou: $pass   falhou: $fail"
[ "$fail" -eq 0 ]
