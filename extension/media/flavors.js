/* Descrição de cada "sabor" de banco: o formulário é gerado a partir daqui.
 * Para dar suporte a um campo novo de um banco, basta descrevê-lo — a tela não muda.
 * Carregado pelo host da extensão (require) e pela webview (<script>). */
(function (root) {
  /* Larguras numa grade de 6 colunas. */
  const FULL = 6, WIDE = 4, HALF = 3, THIRD = 2;

  const ENVIRONMENTS = ['', 'development', 'test', 'staging', 'production'];
  const SSL_MODES = ['disable', 'prefer', 'require', 'verify-ca', 'verify-full'];

  /* ---- campos comuns ---- */
  const name = { key: 'name', type: 'text', w: WIDE, required: true, hint: 'h.name', autofocus: true };
  const environment = {
    key: 'environment', type: 'select', w: THIRD, hint: 'h.environment',
    options: ENVIRONMENTS.map((v) => ({ value: v, label: 'env.' + (v || 'none') })),
  };
  const host = { key: 'host', type: 'text', w: WIDE, required: true, placeholder: 'localhost' };
  const port = { key: 'port', type: 'number', w: THIRD, min: 1, max: 65535, required: true };
  const user = { key: 'user', type: 'text', w: HALF, required: true };
  const password = { key: 'password', type: 'password', w: HALF, hint: 'h.password' };
  const applicationName = {
    key: 'applicationName', type: 'text', w: HALF, hint: 'h.applicationName',
    placeholder: 'Tootega Multi-Database MCP',
  };

  const readOnly = { key: 'readOnly', type: 'checkbox', w: FULL };
  const sslMode = {
    key: 'sslMode', type: 'select', w: HALF,
    options: SSL_MODES.map((v) => ({ value: v, label: 'o.ssl.' + v })),
  };
  const caFile = {
    key: 'caFile', type: 'file', w: HALF, hint: 'h.caFile',
    showIf: (c) => c.sslMode === 'verify-ca' || c.sslMode === 'verify-full',
  };

  const limits = {
    id: 'limits', collapsed: true,
    fields: [
      { key: 'maxRows', type: 'number', w: HALF, min: 1, max: 100000, hint: 'h.maxRows' },
      { key: 'maxCellChars', type: 'number', w: HALF, min: 16, max: 1000000, hint: 'h.maxCellChars' },
      { key: 'connectTimeout', type: 'number', w: HALF, min: 1, max: 600 },
      { key: 'queryTimeout', type: 'number', w: HALF, min: 1, max: 3600 },
    ],
  };
  const general = { id: 'general', fields: [name, environment] };
  const auth = { id: 'auth', fields: [user, password] };
  const security = { id: 'security', fields: [readOnly, sslMode, caFile] };

  const database = (flavor, required) => ({
    key: 'database', type: 'text', w: HALF, required: !!required, hint: 'h.database.' + flavor,
  });

  const FLAVORS = {
    postgres: {
      label: 'PostgreSQL', short: 'PG', port: 5432, color: '#3d7ab8',
      groups: [
        general,
        { id: 'server', fields: [host, port, database('postgres'),
                                 { key: 'schema', type: 'text', w: HALF, hint: 'h.schema.postgres' },
                                 applicationName] },
        auth, security, limits,
      ],
    },
    mysql: {
      label: 'MySQL', short: 'MY', port: 3306, color: '#d98a1f',
      groups: [
        general,
        { id: 'server', fields: [host, port, database('mysql')] },
        auth, security, limits,
      ],
    },
    mssql: {
      label: 'SQL Server', short: 'MS', port: 1433, color: '#c8413b',
      groups: [
        general,
        { id: 'server', fields: [host, port,
                                 { key: 'instance', type: 'text', w: HALF, hint: 'h.instance' },
                                 database('mssql'), applicationName] },
        auth, security, limits,
      ],
    },
    oracle: {
      label: 'Oracle', short: 'OR', port: 1521, color: '#b5532f',
      groups: [
        general,
        { id: 'server', fields: [host, port,
                                 { key: 'oracleTarget', type: 'select', w: THIRD, label: 'f.oracleTarget',
                                   options: [{ value: 'serviceName', label: 'o.serviceName' },
                                             { value: 'sid', label: 'o.sid' }] },
                                 { key: 'serviceName', type: 'text', w: WIDE, required: true, hint: 'h.serviceName',
                                   showIf: (c) => c.oracleTarget !== 'sid' },
                                 { key: 'sid', type: 'text', w: WIDE, required: true, hint: 'h.sid',
                                   showIf: (c) => c.oracleTarget === 'sid' },
                                 { key: 'schema', type: 'text', w: HALF, hint: 'h.schema.oracle' }] },
        auth, security, limits,
      ],
    },
  };

  const ORDER = ['postgres', 'mysql', 'mssql', 'oracle'];

  function defaults(flavor) {
    const c = {
      type: flavor, name: '', environment: '', host: 'localhost', port: FLAVORS[flavor].port,
      user: '', readOnly: true, sslMode: 'prefer',
      maxRows: 500, maxCellChars: 4000, connectTimeout: 10, queryTimeout: 30,
    };
    if (flavor === 'oracle') c.oracleTarget = 'serviceName';
    return c;
  }

  /* Todos os campos de um sabor, em ordem. */
  function fields(flavor) {
    return FLAVORS[flavor].groups.reduce((all, g) => all.concat(g.fields), []);
  }

  /* ---- string de conexão -> campos ---- */

  function decode(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  /* "chave=valor;chave=valor" com chaves sem diferenciar maiúsculas. */
  function keyValues(text) {
    const out = {};
    text.split(';').forEach((part) => {
      const eq = part.indexOf('=');
      if (eq > 0) out[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
    });
    return out;
  }

  function pick(map, keys) {
    for (const k of keys) if (map[k] !== undefined && map[k] !== '') return map[k];
    return undefined;
  }

  function truthy(v) {
    return /^(true|yes|1|mandatory|strict|required)$/i.test(String(v || ''));
  }

  /* esquema://usuario:senha@host:porta/banco?param=valor */
  function parseUrl(text, schemes) {
    const m = /^(?:jdbc:)?([a-z0-9+]+):\/\/(?:([^:@/]*)(?::([^@/]*))?@)?(\[[^\]]+\]|[^:/?;]*)(?::(\d+))?(?:\/([^?;]*))?(?:\?(.*))?$/i
      .exec(text);
    if (!m || schemes.indexOf(m[1].toLowerCase()) < 0) return null;
    const out = {};
    if (m[2]) out.user = decode(m[2]);
    if (m[3] !== undefined) out.password = decode(m[3]);
    if (m[4]) out.host = m[4].replace(/^\[|\]$/g, '');
    if (m[5]) out.port = Number(m[5]);
    if (m[6]) out.database = decode(m[6]);
    const q = {};
    (m[7] || '').split('&').forEach((kv) => {
      const eq = kv.indexOf('=');
      if (eq > 0) q[kv.slice(0, eq).toLowerCase()] = decode(kv.slice(eq + 1));
    });
    out._query = q;
    return out;
  }

  function finishUrl(out) {
    const q = out._query || {};
    delete out._query;
    if (q.user && !out.user) out.user = q.user;
    if (q.password && out.password === undefined) out.password = q.password;
    const ssl = q.sslmode || q['ssl-mode'];
    if (ssl) {
      const v = ssl.toLowerCase().replace('_', '-');
      const map = { disabled: 'disable', preferred: 'prefer', required: 'require', 'verify-identity': 'verify-full' };
      const mode = map[v] || v;
      if (SSL_MODES.indexOf(mode) >= 0) out.sslMode = mode;
    }
    if (q.application_name) out.applicationName = q.application_name;
    if (q.currentschema || q.search_path) out.schema = q.currentschema || q.search_path;
    return out;
  }

  function parseMssql(text) {
    let body = text, hostPart = '';
    const jdbc = /^(?:jdbc:)?sqlserver:\/\/([^;]*);?(.*)$/i.exec(text);
    if (jdbc) {
      hostPart = jdbc[1];
      body = jdbc[2];
    }
    const kv = keyValues(body);
    if (!jdbc) {
      hostPart = pick(kv, ['server', 'data source', 'address', 'addr', 'network address']) || '';
      if (!hostPart) return null;
    }
    const out = {};
    hostPart = hostPart.replace(/^tcp:/i, '');
    /* host\instancia,porta  |  host,porta  |  host:porta */
    const hm = /^([^\\,:]*)(?:\\([^,:]*))?(?:[,:](\d+))?$/.exec(hostPart);
    if (hm) {
      if (hm[1]) out.host = hm[1] === '.' || hm[1] === '(local)' ? 'localhost' : hm[1];
      if (hm[2]) out.instance = hm[2];
      if (hm[3]) out.port = Number(hm[3]);
    }
    const db = pick(kv, ['database', 'initial catalog', 'databasename']);
    const usr = pick(kv, ['user id', 'uid', 'user', 'username']);
    const pwd = pick(kv, ['password', 'pwd']);
    const app = pick(kv, ['application name', 'applicationname', 'app']);
    if (db) out.database = db;
    if (usr) out.user = usr;
    if (pwd !== undefined) out.password = pwd;
    if (app) out.applicationName = app;
    if (kv.instancename) out.instance = kv.instancename;
    if (kv.encrypt !== undefined) {
      const trust = truthy(pick(kv, ['trustservercertificate']));
      out.sslMode = truthy(kv.encrypt) ? (trust ? 'require' : 'verify-full') : 'prefer';
    }
    return Object.keys(out).length ? out : null;
  }

  function parseOracle(text) {
    const out = {};
    let rest = text.replace(/^jdbc:oracle:thin:/i, '');
    /* usuario/senha@...  */
    const cred = /^([^/@]*)(?:\/([^@]*))?@(.*)$/.exec(rest);
    if (cred) {
      if (cred[1]) out.user = cred[1];
      if (cred[2] !== undefined) out.password = cred[2];
      rest = cred[3];
    }
    rest = rest.replace(/^\/\//, '');
    let m = /^([^:/]+)(?::(\d+))?\/([^?]+)$/.exec(rest); /* host:porta/servico */
    if (m) {
      out.host = m[1];
      if (m[2]) out.port = Number(m[2]);
      out.serviceName = m[3];
      out.oracleTarget = 'serviceName';
      return out;
    }
    m = /^([^:/]+):(\d+):([^?]+)$/.exec(rest); /* host:porta:SID */
    if (m) {
      out.host = m[1];
      out.port = Number(m[2]);
      out.sid = m[3];
      out.oracleTarget = 'sid';
      return out;
    }
    /* descritor TNS: (DESCRIPTION=(ADDRESS=(HOST=..)(PORT=..))(CONNECT_DATA=(SERVICE_NAME=..))) */
    const tns = (k) => {
      const r = new RegExp('\\(\\s*' + k + '\\s*=\\s*([^)\\s]+)\\s*\\)', 'i').exec(rest);
      return r ? r[1] : undefined;
    };
    if (tns('HOST')) {
      out.host = tns('HOST');
      if (tns('PORT')) out.port = Number(tns('PORT'));
      if (tns('SERVICE_NAME')) {
        out.serviceName = tns('SERVICE_NAME');
        out.oracleTarget = 'serviceName';
      } else if (tns('SID')) {
        out.sid = tns('SID');
        out.oracleTarget = 'sid';
      }
      return out;
    }
    return null;
  }

  /* Devolve os campos reconhecidos, ou null se a string não serve para o sabor. */
  function parseConnectionString(flavor, raw) {
    const text = String(raw || '').trim().replace(/^["']|["']$/g, '');
    if (!text) return null;
    if (flavor === 'postgres') {
      const u = parseUrl(text, ['postgres', 'postgresql']);
      if (u) return finishUrl(u);
      /* formato libpq: host=... port=... dbname=... user=... password=... */
      if (/\b(host|dbname|user)\s*=/.test(text)) {
        const kv = {};
        text.replace(/(\w+)\s*=\s*('(?:[^'\\]|\\.)*'|\S+)/g, (_, k, v) => {
          kv[k.toLowerCase()] = v.replace(/^'|'$/g, '');
          return '';
        });
        const out = {};
        if (kv.host) out.host = kv.host;
        if (kv.port) out.port = Number(kv.port);
        if (kv.dbname) out.database = kv.dbname;
        if (kv.user) out.user = kv.user;
        if (kv.password !== undefined) out.password = kv.password;
        if (kv.sslmode && SSL_MODES.indexOf(kv.sslmode) >= 0) out.sslMode = kv.sslmode;
        if (kv.application_name) out.applicationName = kv.application_name;
        return Object.keys(out).length ? out : null;
      }
      return null;
    }
    if (flavor === 'mysql') {
      const u = parseUrl(text, ['mysql', 'mariadb', 'mysqlx']);
      return u ? finishUrl(u) : null;
    }
    if (flavor === 'mssql') return parseMssql(text);
    if (flavor === 'oracle') return parseOracle(text);
    return null;
  }

  const api = { FLAVORS, ORDER, defaults, fields, parseConnectionString };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.TMDB_FLAVORS = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
