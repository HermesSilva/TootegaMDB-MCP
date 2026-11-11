/* Mede o desempenho do servidor MCP, para os números da documentação serem medidos
 * e reproduzíveis, não estimados.
 *
 * Uso (WSL, na raiz do projeto, com os containers de teste no ar):
 *   node tools/bench/bench.js [caminho-do-tmdb]            */
'use strict';
const cp = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const bin = process.argv[2] || path.join(root, 'dist', 'linux-x64', 'tmdb');
const config = path.join(root, 'tests', 'connections.json');

const ms = (ns) => Number(ns) / 1e6;
const median = (a) => a.slice().sort((x, y) => x - y)[Math.floor(a.length / 2)];
const p95 = (a) => a.slice().sort((x, y) => x - y)[Math.floor(a.length * 0.95)];

/* Tempo de parede de um processo do início ao fim. */
function timeProcess(cmd, args, runs) {
  const times = [];
  for (let i = 0; i < runs; i++) {
    const t0 = process.hrtime.bigint();
    cp.spawnSync(cmd, args, { stdio: 'ignore' });
    times.push(ms(process.hrtime.bigint() - t0));
  }
  return median(times);
}

/* Pico de memória residente (kB) de um processo, lido de /proc ao encerrar. */
function peakRss(cmd, args, input) {
  const script = `${[cmd].concat(args).map((a) => `'${a}'`).join(' ')} >/dev/null & pid=$!; ` +
    `while kill -0 $pid 2>/dev/null; do grep VmHWM /proc/$pid/status 2>/dev/null | tr -dc 0-9 > /tmp/tmdb_rss.$$ ; echo >> /tmp/tmdb_rss.$$; sleep 0.02; done; ` +
    `head -1 /tmp/tmdb_rss.$$; rm -f /tmp/tmdb_rss.$$`;
  const out = cp.spawnSync('bash', ['-c', `( ${input} ) | { ${script}; }`], { encoding: 'utf8' });
  return Number((out.stdout || '').trim().split('\n').pop());
}

/* Cliente MCP mínimo sobre stdio. */
class Client {
  constructor() {
    this.child = cp.spawn(bin, ['serve', '--lang', 'en', '--config', config], { stdio: ['pipe', 'pipe', 'inherit'] });
    this.buffer = '';
    this.waiting = new Map();
    this.nextId = 1;
    this.child.stdout.on('data', (d) => {
      this.buffer += d.toString('utf8');
      let nl;
      while ((nl = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, nl);
        this.buffer = this.buffer.slice(nl + 1);
        const msg = JSON.parse(line);
        const done = this.waiting.get(msg.id);
        if (done) {
          this.waiting.delete(msg.id);
          done(msg);
        }
      }
    });
  }

  request(method, params) {
    const id = this.nextId++;
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  async call(name, args) {
    const t0 = process.hrtime.bigint();
    const res = await this.request('tools/call', { name, arguments: args });
    const elapsed = ms(process.hrtime.bigint() - t0);
    if (res.result.isError) throw new Error(res.result.content[0].text);
    return { elapsed, text: res.result.content[0].text };
  }

  close() {
    this.child.stdin.end();
  }
}

async function series(client, name, args, runs) {
  const times = [];
  let bytes = 0;
  for (let i = 0; i < runs; i++) {
    const r = await client.call(name, args);
    times.push(r.elapsed);
    bytes = r.text.length;
  }
  return { median: median(times), p95: p95(times), bytes };
}

(async () => {
  const out = {};
  out.binaryKb = Math.round(fs.statSync(bin).size / 1024);
  const exe = path.join(root, 'dist', 'win32-x64', 'tmdb.exe');
  if (fs.existsSync(exe)) out.binaryWindowsKb = Math.round(fs.statSync(exe).size / 1024);

  out.startupMs = timeProcess(bin, ['version'], 200);
  out.nodeStartupMs = timeProcess(process.execPath, ['-e', '0'], 30);

  /* Aperto de mão MCP completo: processo novo, initialize e tools/list. */
  const hs = [];
  for (let i = 0; i < 30; i++) {
    const t0 = process.hrtime.bigint();
    const c = new Client();
    await c.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bench', version: '1' } });
    await c.request('tools/list', {});
    hs.push(ms(process.hrtime.bigint() - t0));
    c.close();
  }
  out.handshakeMs = median(hs);

  const init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"b","version":"1"}}}';
  const call = '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"connection":"pg","sql":"select id, nome, valor, criado from tmdb_t order by id"}}}';
  out.rssIdleKb = peakRss(bin, ['serve', '--config', config], `echo '${init}'; sleep 0.3`);
  out.rssAfterQueryKb = peakRss(bin, ['serve', '--config', config], `echo '${init}'; echo '${call}'; sleep 0.5`);
  out.nodeRssKb = peakRss(process.execPath, ['-e', 'setTimeout(()=>{},300)'], 'sleep 0.4');

  const client = new Client();
  await client.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bench', version: '1' } });
  const targets = [
    ['postgres', 'pg', 'select 1', 'select id, nome, valor, criado from tmdb_t order by id'],
    ['mysql', 'my', 'select 1', 'select id, nome, valor, criado from tmdb_t order by id'],
    ['mssql', 'ms', 'select 1', 'select top 500 id, nome, valor, criado from tmdb.dbo.tmdb_t order by id'],
    ['oracle', 'ora', 'select 1 from dual', 'select id, nome, valor, criado from tmdb_t order by id'],
  ];
  out.databases = {};
  for (const [label, conn, tiny, wide] of targets) {
    try {
      await client.call('query', { connection: conn, sql: tiny }); // abre a conexão
      const small = await series(client, 'query', { connection: conn, sql: tiny }, 300);
      const big = await series(client, 'query', { connection: conn, sql: wide }, 60);
      out.databases[label] = {
        roundTripMs: +small.median.toFixed(3), roundTripP95Ms: +small.p95.toFixed(3),
        rows500Ms: +big.median.toFixed(3), rows500Kb: Math.round(big.bytes / 1024),
      };
    } catch (e) {
      out.databases[label] = { error: e.message };
    }
  }
  client.close();

  out.startupMs = +out.startupMs.toFixed(2);
  out.nodeStartupMs = +out.nodeStartupMs.toFixed(1);
  out.handshakeMs = +out.handshakeMs.toFixed(2);
  console.log(JSON.stringify(out, null, 2));
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
