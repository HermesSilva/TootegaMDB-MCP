#include "meta.h"
#include "i18n.h"

/* Literal SQL entre aspas simples. Os nomes já foram validados por guard_ident
 * (sem aspas simples nem barra invertida), então não há o que escapar. */
static void lit(tm_buf *b, const char *s)
{
    buf_putc(b, '\'');
    buf_puts(b, s);
    buf_putc(b, '\'');
}

/* ---- PostgreSQL ---- */

static void pg_schema_or_current(tm_buf *b, const char *schema)
{
    if (schema) lit(b, schema);
    else buf_puts(b, "current_schema()");
}

static int pg_meta(meta_kind k, const char *schema, const char *table, const char *pattern, tm_buf *b)
{
    switch (k) {
    case MQ_INFO:
        buf_puts(b, "select version() as version, current_user as \"user\", current_database() as database, "
                    "current_schema() as schema, current_setting('server_encoding') as encoding, "
                    "current_setting('TimeZone') as timezone");
        return 0;
    case MQ_SCHEMAS:
        buf_puts(b, "select n.nspname as schema, pg_get_userbyid(n.nspowner) as owner, "
                    "(select count(*) from pg_class c where c.relnamespace = n.oid "
                    "and c.relkind in ('r','p','v','m','f')) as tables "
                    "from pg_namespace n where n.nspname !~ '^pg_' and n.nspname <> 'information_schema' "
                    "order by 1");
        return 0;
    case MQ_TABLES:
        buf_puts(b, "select n.nspname as schema, c.relname as name, "
                    "case c.relkind when 'r' then 'table' when 'p' then 'partitioned table' "
                    "when 'v' then 'view' when 'm' then 'materialized view' else 'foreign table' end as type, "
                    "case when c.reltuples < 0 then null else c.reltuples::bigint end as estimated_rows, "
                    "obj_description(c.oid, 'pg_class') as comment "
                    "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
                    "where c.relkind in ('r','p','v','m','f') "
                    "and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'");
        if (schema) {
            buf_puts(b, " and n.nspname = ");
            lit(b, schema);
        }
        if (pattern) {
            buf_puts(b, " and c.relname ilike ");
            lit(b, pattern);
        }
        buf_puts(b, " order by 1, 2");
        return 0;
    case MQ_COLUMNS:
        buf_puts(b, "select a.attname as \"column\", format_type(a.atttypid, a.atttypmod) as type, "
                    "not a.attnotnull as nullable, pg_get_expr(d.adbin, d.adrelid) as \"default\", "
                    "col_description(c.oid, a.attnum) as comment "
                    "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
                    "join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped "
                    "left join pg_attrdef d on d.adrelid = c.oid and d.adnum = a.attnum "
                    "where c.relname = ");
        lit(b, table);
        buf_puts(b, " and n.nspname = ");
        pg_schema_or_current(b, schema);
        buf_puts(b, " order by a.attnum");
        return 0;
    case MQ_CONSTRAINTS:
        buf_puts(b, "select con.conname as name, case con.contype when 'p' then 'primary key' "
                    "when 'f' then 'foreign key' when 'u' then 'unique' when 'c' then 'check' "
                    "else con.contype::text end as type, pg_get_constraintdef(con.oid) as definition "
                    "from pg_constraint con join pg_class c on c.oid = con.conrelid "
                    "join pg_namespace n on n.oid = c.relnamespace where c.relname = ");
        lit(b, table);
        buf_puts(b, " and n.nspname = ");
        pg_schema_or_current(b, schema);
        /* O PostgreSQL 18 registra cada NOT NULL como restrição ('n'): já está em "nullable". */
        buf_puts(b, " and con.contype <> 'n' order by con.contype <> 'p', con.conname");
        return 0;
    case MQ_INDEXES:
        buf_puts(b, "select indexname as name, indexdef as definition from pg_indexes where tablename = ");
        lit(b, table);
        buf_puts(b, " and schemaname = ");
        pg_schema_or_current(b, schema);
        buf_puts(b, " order by 1");
        return 0;
    case MQ_SEARCH:
        buf_puts(b, "select table_schema as schema, table_name as \"table\", column_name as \"column\", "
                    "data_type as type from information_schema.columns "
                    "where table_schema !~ '^pg_' and table_schema <> 'information_schema' and (column_name ilike ");
        lit(b, pattern);
        buf_puts(b, " or table_name ilike ");
        lit(b, pattern);
        buf_puts(b, ") order by 1, 2, ordinal_position");
        return 0;
    }
    return -1;
}

/* ---- MySQL / MariaDB ---- */

#define MY_SYSTEM "('information_schema','performance_schema','mysql','sys')"

static void my_schema_or_current(tm_buf *b, const char *schema)
{
    if (schema) lit(b, schema);
    else buf_puts(b, "database()");
}

static int my_meta(meta_kind k, const char *schema, const char *table, const char *pattern, tm_buf *b)
{
    switch (k) {
    case MQ_INFO:
        buf_puts(b, "select version() as version, current_user() as `user`, database() as `database`, "
                    "@@character_set_server as charset, @@version_comment as edition, @@time_zone as timezone");
        return 0;
    case MQ_SCHEMAS:
        buf_puts(b, "select s.schema_name as `schema`, s.default_character_set_name as charset, "
                    "(select count(*) from information_schema.tables t where t.table_schema = s.schema_name) "
                    "as `tables` from information_schema.schemata s "
                    "where s.schema_name not in " MY_SYSTEM " order by 1");
        return 0;
    case MQ_TABLES:
        buf_puts(b, "select table_schema as `schema`, table_name as name, "
                    "case table_type when 'BASE TABLE' then 'table' when 'VIEW' then 'view' "
                    "else lower(table_type) end as type, table_rows as estimated_rows, "
                    "nullif(table_comment, '') as comment from information_schema.tables "
                    "where table_schema not in " MY_SYSTEM);
        if (schema) {
            buf_puts(b, " and table_schema = ");
            lit(b, schema);
        }
        if (pattern) {
            buf_puts(b, " and table_name like ");
            lit(b, pattern);
        }
        buf_puts(b, " order by 1, 2");
        return 0;
    case MQ_COLUMNS:
        buf_puts(b, "select column_name as `column`, column_type as type, is_nullable as nullable, "
                    "column_default as `default`, nullif(extra, '') as extra, "
                    "nullif(column_comment, '') as comment from information_schema.columns "
                    "where table_name = ");
        lit(b, table);
        buf_puts(b, " and table_schema = ");
        my_schema_or_current(b, schema);
        buf_puts(b, " order by ordinal_position");
        return 0;
    case MQ_CONSTRAINTS:
        buf_puts(b, "select tc.constraint_name as name, lower(tc.constraint_type) as type, "
                    "group_concat(kcu.column_name order by kcu.ordinal_position separator ', ') as `columns`, "
                    "max(concat(kcu.referenced_table_schema, '.', kcu.referenced_table_name)) as ref_table, "
                    "group_concat(kcu.referenced_column_name order by kcu.ordinal_position separator ', ') "
                    "as ref_columns from information_schema.table_constraints tc "
                    "left join information_schema.key_column_usage kcu "
                    "on kcu.constraint_schema = tc.constraint_schema and kcu.constraint_name = tc.constraint_name "
                    "and kcu.table_schema = tc.table_schema and kcu.table_name = tc.table_name "
                    "where tc.table_name = ");
        lit(b, table);
        buf_puts(b, " and tc.table_schema = ");
        my_schema_or_current(b, schema);
        buf_puts(b, " group by tc.constraint_name, tc.constraint_type "
                    "order by tc.constraint_type <> 'PRIMARY KEY', tc.constraint_name");
        return 0;
    case MQ_INDEXES:
        buf_puts(b, "select index_name as name, case non_unique when 0 then 'yes' else 'no' end as is_unique, "
                    "group_concat(column_name order by seq_in_index separator ', ') as `columns`, "
                    "index_type as type from information_schema.statistics where table_name = ");
        lit(b, table);
        buf_puts(b, " and table_schema = ");
        my_schema_or_current(b, schema);
        buf_puts(b, " group by index_name, non_unique, index_type order by 1");
        return 0;
    case MQ_SEARCH:
        buf_puts(b, "select table_schema as `schema`, table_name as `table`, column_name as `column`, "
                    "column_type as type from information_schema.columns "
                    "where table_schema not in " MY_SYSTEM " and (column_name like ");
        lit(b, pattern);
        buf_puts(b, " or table_name like ");
        lit(b, pattern);
        buf_puts(b, ") order by 1, 2, ordinal_position");
        return 0;
    }
    return -1;
}

/* ---- SQL Server ---- */

/* object_id(N'[schema].[tabela]') — os colchetes isolam o nome; ']' é dobrado. */
static void ms_object_id(tm_buf *b, const char *schema, const char *table)
{
    const char *parts[2] = { schema, table };
    buf_puts(b, "object_id(N'");
    for (int i = 0; i < 2; i++) {
        if (!parts[i]) continue;
        buf_putc(b, '[');
        for (const char *p = parts[i]; *p; p++) {
            if (*p == ']') buf_putc(b, ']');
            buf_putc(b, *p);
        }
        buf_puts(b, i == 0 ? "]." : "]");
    }
    buf_puts(b, "')");
}

/* Lista de colunas separada por vírgulas, compatível com versões sem STRING_AGG. */
#define MS_LIST(sel, from_where, order) \
    "stuff((select ', ' + " sel " from " from_where " order by " order " for xml path('')), 1, 2, '')"

static int ms_meta(meta_kind k, const char *schema, const char *table, const char *pattern, tm_buf *b)
{
    switch (k) {
    case MQ_INFO:
        buf_puts(b, "select @@version as version, suser_sname() as [user], db_name() as [database], "
                    "schema_name() as [schema], cast(serverproperty('Edition') as nvarchar(128)) as edition, "
                    "cast(serverproperty('Collation') as nvarchar(128)) as collation");
        return 0;
    case MQ_SCHEMAS:
        buf_puts(b, "select s.name as [schema], p.name as owner, "
                    "(select count(*) from sys.objects o where o.schema_id = s.schema_id "
                    "and o.type in ('U','V') and o.is_ms_shipped = 0) as tables from sys.schemas s "
                    "join sys.database_principals p on p.principal_id = s.principal_id "
                    "where s.schema_id < 16384 and s.name not in ('sys','INFORMATION_SCHEMA','guest') order by 1");
        return 0;
    case MQ_TABLES:
        buf_puts(b, "select s.name as [schema], o.name as name, "
                    "case o.type when 'U' then 'table' else 'view' end as type, "
                    "(select sum(p.rows) from sys.partitions p where p.object_id = o.object_id "
                    "and p.index_id in (0,1)) as estimated_rows, cast(ep.value as nvarchar(4000)) as comment "
                    "from sys.objects o join sys.schemas s on s.schema_id = o.schema_id "
                    "left join sys.extended_properties ep on ep.major_id = o.object_id and ep.minor_id = 0 "
                    "and ep.class = 1 and ep.name = 'MS_Description' "
                    "where o.type in ('U','V') and o.is_ms_shipped = 0");
        if (schema) {
            buf_puts(b, " and s.name = N");
            lit(b, schema);
        }
        if (pattern) {
            buf_puts(b, " and o.name like N");
            lit(b, pattern);
        }
        buf_puts(b, " order by 1, 2");
        return 0;
    case MQ_COLUMNS:
        buf_puts(b, "select c.name as [column], t.name + case "
                    "when t.name in ('varchar','char','varbinary','binary') then '(' + case c.max_length "
                    "when -1 then 'max' else cast(c.max_length as varchar(10)) end + ')' "
                    "when t.name in ('nvarchar','nchar') then '(' + case c.max_length "
                    "when -1 then 'max' else cast(c.max_length / 2 as varchar(10)) end + ')' "
                    "when t.name in ('decimal','numeric') then '(' + cast(c.precision as varchar(10)) + ',' "
                    "+ cast(c.scale as varchar(10)) + ')' "
                    "when t.name in ('datetime2','time','datetimeoffset') then '(' + cast(c.scale as varchar(10)) + ')' "
                    "else '' end as type, case c.is_nullable when 1 then 'YES' else 'NO' end as nullable, "
                    "dc.definition as [default], case when c.is_identity = 1 then 'identity' "
                    "when c.is_computed = 1 then 'computed' end as extra, "
                    "cast(ep.value as nvarchar(4000)) as comment "
                    "from sys.columns c join sys.types t on t.user_type_id = c.user_type_id "
                    "left join sys.default_constraints dc on dc.object_id = c.default_object_id "
                    "left join sys.extended_properties ep on ep.major_id = c.object_id "
                    "and ep.minor_id = c.column_id and ep.class = 1 and ep.name = 'MS_Description' "
                    "where c.object_id = ");
        ms_object_id(b, schema, table);
        buf_puts(b, " order by c.column_id");
        return 0;
    case MQ_CONSTRAINTS:
        buf_puts(b, "select kc.name as name, case kc.type when 'PK' then 'primary key' else 'unique' end as type, "
                    MS_LIST("c.name", "sys.index_columns ic join sys.columns c on c.object_id = ic.object_id "
                            "and c.column_id = ic.column_id where ic.object_id = kc.parent_object_id "
                            "and ic.index_id = kc.unique_index_id", "ic.key_ordinal")
                    " as [columns], cast(null as nvarchar(600)) as ref_table, "
                    "cast(null as nvarchar(max)) as ref_columns from sys.key_constraints kc "
                    "where kc.parent_object_id = ");
        ms_object_id(b, schema, table);
        buf_puts(b, " union all select fk.name, 'foreign key', "
                    MS_LIST("c.name", "sys.foreign_key_columns fc join sys.columns c "
                            "on c.object_id = fc.parent_object_id and c.column_id = fc.parent_column_id "
                            "where fc.constraint_object_id = fk.object_id", "fc.constraint_column_id")
                    ", schema_name(ro.schema_id) + '.' + ro.name, "
                    MS_LIST("c.name", "sys.foreign_key_columns fc join sys.columns c "
                            "on c.object_id = fc.referenced_object_id and c.column_id = fc.referenced_column_id "
                            "where fc.constraint_object_id = fk.object_id", "fc.constraint_column_id")
                    " from sys.foreign_keys fk join sys.objects ro on ro.object_id = fk.referenced_object_id "
                    "where fk.parent_object_id = ");
        ms_object_id(b, schema, table);
        buf_puts(b, " union all select cc.name, 'check', cc.definition, null, null "
                    "from sys.check_constraints cc where cc.parent_object_id = ");
        ms_object_id(b, schema, table);
        return 0;
    case MQ_INDEXES:
        buf_puts(b, "select i.name as name, case i.is_unique when 1 then 'yes' else 'no' end as is_unique, "
                    MS_LIST("c.name + case ic.is_descending_key when 1 then ' desc' else '' end",
                            "sys.index_columns ic join sys.columns c on c.object_id = ic.object_id "
                            "and c.column_id = ic.column_id where ic.object_id = i.object_id "
                            "and ic.index_id = i.index_id and ic.is_included_column = 0", "ic.key_ordinal")
                    " as [columns], lower(i.type_desc) as type from sys.indexes i where i.index_id > 0 "
                    "and i.object_id = ");
        ms_object_id(b, schema, table);
        buf_puts(b, " order by 1");
        return 0;
    case MQ_SEARCH:
        buf_puts(b, "select s.name as [schema], o.name as [table], c.name as [column], t.name as type "
                    "from sys.columns c join sys.objects o on o.object_id = c.object_id "
                    "join sys.schemas s on s.schema_id = o.schema_id "
                    "join sys.types t on t.user_type_id = c.user_type_id "
                    "where o.type in ('U','V') and o.is_ms_shipped = 0 and (c.name like N");
        lit(b, pattern);
        buf_puts(b, " or o.name like N");
        lit(b, pattern);
        buf_puts(b, ") order by 1, 2, c.column_id");
        return 0;
    }
    return -1;
}

/* ---- Oracle ---- */

/* O Oracle guarda nomes em maiúsculas, salvo os criados entre aspas: aceita os dois. */
static void ora_name_is(tm_buf *b, const char *column, const char *name)
{
    buf_printf(b, "(%s = ", column);
    lit(b, name);
    buf_printf(b, " or %s = upper(", column);
    lit(b, name);
    buf_puts(b, "))");
}

static void ora_owner_is(tm_buf *b, const char *column, const char *schema)
{
    if (schema) ora_name_is(b, column, schema);
    else buf_printf(b, "%s = sys_context('USERENV', 'CURRENT_SCHEMA')", column);
}

static int ora_meta(meta_kind k, const char *schema, const char *table, const char *pattern, tm_buf *b)
{
    switch (k) {
    case MQ_INFO:
        buf_puts(b, "select (select banner from v$version where rownum = 1) as \"version\", "
                    "user as \"user\", sys_context('USERENV', 'DB_NAME') as \"database\", "
                    "sys_context('USERENV', 'CURRENT_SCHEMA') as \"schema\", "
                    "sys_context('USERENV', 'CON_NAME') as \"container\", sessiontimezone as \"timezone\" "
                    "from dual");
        return 0;
    case MQ_SCHEMAS:
        buf_puts(b, "select u.username as \"schema\", (select count(*) from all_objects o "
                    "where o.owner = u.username and o.object_type in ('TABLE', 'VIEW')) as \"tables\" "
                    "from all_users u where u.oracle_maintained = 'N' order by 1");
        return 0;
    case MQ_TABLES:
        buf_puts(b, "select o.owner as \"schema\", o.object_name as \"name\", lower(o.object_type) as \"type\", "
                    "t.num_rows as \"estimated_rows\", c.comments as \"comment\" from all_objects o "
                    "left join all_tables t on t.owner = o.owner and t.table_name = o.object_name "
                    "left join all_tab_comments c on c.owner = o.owner and c.table_name = o.object_name "
                    "where o.object_type in ('TABLE', 'VIEW', 'MATERIALIZED VIEW') and o.oracle_maintained = 'N'");
        if (schema) {
            buf_puts(b, " and ");
            ora_name_is(b, "o.owner", schema);
        }
        if (pattern) {
            buf_puts(b, " and upper(o.object_name) like upper(");
            lit(b, pattern);
            buf_putc(b, ')');
        }
        buf_puts(b, " order by 1, 2");
        return 0;
    case MQ_COLUMNS:
        buf_puts(b, "select c.column_name as \"column\", c.data_type || case "
                    "when c.data_type in ('VARCHAR2', 'NVARCHAR2', 'CHAR', 'NCHAR') then '(' || c.char_length || "
                    "case c.char_used when 'C' then ' CHAR' else '' end || ')' "
                    "when c.data_type = 'NUMBER' and c.data_precision is not null then '(' || c.data_precision || "
                    "case when c.data_scale > 0 then ',' || c.data_scale else '' end || ')' "
                    "when c.data_type = 'RAW' then '(' || c.data_length || ')' else '' end as \"type\", "
                    "case c.nullable when 'Y' then 'YES' else 'NO' end as \"nullable\", "
                    "c.data_default as \"default\", m.comments as \"comment\" from all_tab_columns c "
                    "left join all_col_comments m on m.owner = c.owner and m.table_name = c.table_name "
                    "and m.column_name = c.column_name where ");
        ora_name_is(b, "c.table_name", table);
        buf_puts(b, " and ");
        ora_owner_is(b, "c.owner", schema);
        buf_puts(b, " order by c.column_id");
        return 0;
    case MQ_CONSTRAINTS:
        buf_puts(b, "select c.constraint_name as \"name\", case c.constraint_type when 'P' then 'primary key' "
                    "when 'R' then 'foreign key' when 'U' then 'unique' when 'C' then 'check' "
                    "else c.constraint_type end as \"type\", "
                    "(select listagg(cc.column_name, ', ') within group (order by cc.position) "
                    "from all_cons_columns cc where cc.owner = c.owner "
                    "and cc.constraint_name = c.constraint_name) as \"columns\", "
                    "case when c.constraint_type = 'R' then c.r_owner || '.' || (select r.table_name "
                    "from all_constraints r where r.owner = c.r_owner "
                    "and r.constraint_name = c.r_constraint_name) end as \"ref_table\", "
                    "case when c.constraint_type = 'R' then (select listagg(rc.column_name, ', ') "
                    "within group (order by rc.position) from all_cons_columns rc where rc.owner = c.r_owner "
                    "and rc.constraint_name = c.r_constraint_name) end as \"ref_columns\", "
                    "case when c.constraint_type = 'C' then c.search_condition_vc end as \"condition\" "
                    "from all_constraints c where ");
        ora_name_is(b, "c.table_name", table);
        buf_puts(b, " and ");
        ora_owner_is(b, "c.owner", schema);
        /* NOT NULL aparece como restrição de checagem gerada: já está em "nullable". */
        buf_puts(b, " and (c.constraint_type <> 'C' or c.search_condition_vc not like '%IS NOT NULL') "
                    "order by decode(c.constraint_type, 'P', 0, 1), c.constraint_name");
        return 0;
    case MQ_INDEXES:
        buf_puts(b, "select i.index_name as \"name\", case i.uniqueness when 'UNIQUE' then 'yes' else 'no' end "
                    "as \"is_unique\", (select listagg(ic.column_name, ', ') within group "
                    "(order by ic.column_position) from all_ind_columns ic where ic.index_owner = i.owner "
                    "and ic.index_name = i.index_name) as \"columns\", lower(i.index_type) as \"type\" "
                    "from all_indexes i where ");
        ora_name_is(b, "i.table_name", table);
        buf_puts(b, " and ");
        ora_owner_is(b, "i.table_owner", schema);
        buf_puts(b, " order by 1");
        return 0;
    case MQ_SEARCH:
        buf_puts(b, "select c.owner as \"schema\", c.table_name as \"table\", c.column_name as \"column\", "
                    "c.data_type as \"type\" from all_tab_columns c join all_users u on u.username = c.owner "
                    "where u.oracle_maintained = 'N' and (upper(c.column_name) like upper(");
        lit(b, pattern);
        buf_puts(b, ") or upper(c.table_name) like upper(");
        lit(b, pattern);
        buf_puts(b, ")) order by 1, 2, c.column_id");
        return 0;
    }
    return -1;
}

/* ---- despacho ---- */

int meta_sql(tm_flavor f, meta_kind k, const char *schema, const char *table, const char *pattern,
             tm_buf *sql, tm_err *err)
{
    int rc = -1;
    switch (f) {
    case FL_POSTGRES: rc = pg_meta(k, schema, table, pattern, sql); break;
    case FL_MYSQL: rc = my_meta(k, schema, table, pattern, sql); break;
    case FL_MSSQL: rc = ms_meta(k, schema, table, pattern, sql); break;
    case FL_ORACLE: rc = ora_meta(k, schema, table, pattern, sql); break;
    default: break;
    }
    if (rc) return tm_fail(err, TM_E_UNSUPPORTED, T(M_DRIVER_PENDING), flavor_label(f));
    return 0;
}

int meta_explain(tm_flavor f, const char *query, tm_buf *sql, tm_err *err)
{
    switch (f) {
    case FL_POSTGRES:
    case FL_MYSQL:
        buf_puts(sql, "EXPLAIN ");
        buf_puts(sql, query);
        return 0;
    default:
        return tm_fail(err, TM_E_UNSUPPORTED, T(M_DRIVER_PENDING), flavor_label(f));
    }
}
