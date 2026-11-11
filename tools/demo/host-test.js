/* Teste do host da extensão: carrega extension.js com a API do VS Code simulada
 * e o executável real (tmdb), exercitando registro MCP, salvar, cofre e Testar.
 * Requer o PostgreSQL de teste no ar (docker/compose.yml).
 * Uso:  node host-test.js */
'use strict';
const Module = require('module');
const fs = require('fs');
const os = require('os');
const path = require('path');

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log('  ok    ' + name);
  } else {
    fail++;
    console.log('  FAIL  ' + name + (detail !== undefined ? '\n        ' + JSON.stringify(detail) : ''));
  }
}

const extDir = path.join(__dirname, '..', '..', 'extension');
const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'tmdb-host-'));

/* ---- VS Code simulado: só o que a extensão usa ---- */
const state = { secrets: new Map(), global: new Map(), commands: new Map(), provider: null, posted: [], receive: null,
                messages: [], language: 'pt-br', clipboard: '' };
class EventEmitter {
  constructor() { this.listeners = []; this.event = (fn) => { this.listeners.push(fn); return { dispose() {} }; }; }
  fire(v) { this.listeners.forEach((fn) => fn(v)); }
  dispose() {}
}
const Uri = {
  file: (p) => ({ fsPath: p, toString: () => 'file://' + p }),
  joinPath: (base, ...parts) => Uri.file(path.join(base.fsPath, ...parts)),
};
const vscode = {
  EventEmitter, Uri,
  ViewColumn: { Active: 1 }, StatusBarAlignment: { Right: 2 },
  McpStdioServerDefinition: class { constructor(label, command, args, env, version) { Object.assign(this, { label, command, args, env, version }); } },
  env: { get language() { return state.language; }, clipboard: { writeText: async (t) => { state.clipboard = t; } } },
  workspace: {
    /* O registro automático no Claude Code fica desligado aqui: ele chamaria o CLI de verdade. */
    getConfiguration: () => ({ get: (key, def) => (key === 'registerClaudeCode' ? false : def) }),
    onDidChangeConfiguration: () => ({ dispose() {} }),
  },
  lm: { registerMcpServerDefinitionProvider: (id, provider) => { state.provider = { id, provider }; return { dispose() {} }; } },
  commands: { registerCommand: (id, fn) => { state.commands.set(id, fn); return { dispose() {} }; } },
  window: {
    createStatusBarItem: () => ({ show() {}, dispose() {} }),
    setStatusBarMessage: (m) => state.messages.push(m),
    showWarningMessage: (m) => state.messages.push(m),
    showInformationMessage: (m) => state.messages.push(m),
    showErrorMessage: (m) => state.messages.push('ERRO ' + m),
    createWebviewPanel: () => ({
      webview: {
        cspSource: 'vscode-resource:', html: '',
        asWebviewUri: (u) => u,
        postMessage: async (m) => { state.posted.push(m); return true; },
        onDidReceiveMessage: (fn) => { state.receive = fn; },
      },
      reveal() {}, onDidDispose() {},
    }),
  },
};
const realLoad = Module._load;
Module._load = function (request, ...rest) {
  return request === 'vscode' ? vscode : realLoad.call(this, request, ...rest);
};

const context = {
  extensionPath: extDir,
  extensionUri: Uri.file(extDir),
  globalStorageUri: Uri.file(storage),
  extension: { packageJSON: require(path.join(extDir, 'package.json')) },
  subscriptions: [],
  secrets: {
    get: async (k) => state.secrets.get(k),
    store: async (k, v) => { state.secrets.set(k, v); },
    delete: async (k) => { state.secrets.delete(k); },
  },
  globalState: { get: (k, d) => (state.global.has(k) ? state.global.get(k) : d), update: async (k, v) => { state.global.set(k, v); } },
};

const last = (type) => state.posted.filter((m) => m.type === type).pop();
async function send(m) {
  await state.receive(m);
  await new Promise((r) => setTimeout(r, 20));
}

const vaultIds = () => {
  const bin = path.join(extDir, '..', 'dist', process.platform + '-' + process.arch, process.platform === 'win32' ? 'tmdb.exe' : 'tmdb');
  const r = require('child_process').spawnSync(bin, ['secret', '--config', path.join(storage, 'connections.json')], { input: '{}', encoding: 'utf8' });
  return JSON.parse(r.stdout).ids;
};

(async () => {
  /* estado de uma versão anterior: conexão salva com a senha no cofre do VS Code */
  fs.writeFileSync(path.join(storage, 'connections.json'), JSON.stringify({ version: 1, connections: [
    { id: 'm1', type: 'postgres', name: 'antiga', host: '127.0.0.1', port: 55432, user: 'tmdb', database: 'tmdb', readOnly: true } ] }));
  state.secrets.set('tootegaMdb.password.m1', 'Tmdb_Test_123');

  const ext = require(path.join(extDir, 'extension.js'));
  ext.activate(context);
  await new Promise((r) => setTimeout(r, 1200));

  console.log('== migração do cofre do VS Code para o cofre do executável');
  check('senha migrada para o cofre do executável', vaultIds().includes('m1'), vaultIds());
  check('cofre do VS Code esvaziado', state.secrets.size === 0);
  check('cofre não guarda a senha em claro', !fs.readFileSync(path.join(storage, 'secrets.bin')).includes('Tmdb_Test_123'));
  {
    const defs0 = await state.provider.provider.provideMcpServerDefinitions();
    const out0 = require('child_process').spawnSync(defs0[0].command, defs0[0].args, {
      env: Object.assign({}, process.env, defs0[0].env), encoding: 'utf8',
      input: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_connection","arguments":{"connection":"antiga"}}}\n' });
    check('servidor MCP usa a senha migrada, sem nada no ambiente', out0.stdout.includes('PostgreSQL'), out0.stdout.slice(0, 300));
  }

  console.log('== ativação');
  check('provedor MCP registrado com o id do manifesto',
        state.provider && state.provider.id === context.extension.packageJSON.contributes.mcpServerDefinitionProviders[0].id);
  check('comandos registrados', state.commands.has('tootegaMdb.configure') && state.commands.has('tootegaMdb.copyMcpConfig'));

  const defs = await state.provider.provider.provideMcpServerDefinitions();
  const def = defs[0];
  check('definição do servidor aponta para o executável desta plataforma',
        defs.length === 1 && fs.existsSync(def.command) && /tmdb(\.exe)?$/.test(def.command), def && def.command);
  check('argumentos: serve em português', def.args.join(' ') === 'serve --lang pt', def.args);
  check('configuração fora do repositório, sem segredos na definição',
        def.env.TMDB_CONFIG.startsWith(storage) && def.env.TMDB_SECRETS === undefined);

  console.log('== tela: abrir, salvar, cofre');
  state.commands.get('tootegaMdb.configure')();
  await send({ type: 'ready' });
  check('init enviado em pt, com a senha migrada marcada', last('init') && last('init').lang === 'pt' && last('init').hasPassword.m1 === true);

  let changed = 0;
  // o emissor de mudança é interno: observa-se pelo efeito na versão da definição
  const conn = { id: 'c1', type: 'postgres', name: 'teste', host: '127.0.0.1', port: 55432, user: 'tmdb', database: 'tmdb',
                 readOnly: true, password: 'NAO-DEVE-IR-PARA-O-ARQUIVO' };
  await send({ type: 'save', connections: [conn], passwords: { c1: 'Tmdb_Test_123' }, cleared: [] });
  const file = path.join(storage, 'connections.json');
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  check('arquivo de conexões gravado', saved.connections.length === 1 && saved.connections[0].name === 'teste');
  check('senha nunca vai para o arquivo', !fs.readFileSync(file, 'utf8').includes('Tmdb_Test_123') &&
        !fs.readFileSync(file, 'utf8').includes('NAO-DEVE'), saved);
  check('senha guardada no cofre do executável', vaultIds().includes('c1') && !vaultIds().includes('m1'), vaultIds());
  check('nada no cofre do VS Code', state.secrets.size === 0);
  check('tela recebe "saved" com hasPassword', last('saved') && last('saved').hasPassword.c1 === true);
  const defs2 = await state.provider.provider.provideMcpServerDefinitions();
  check('versão da definição muda ao salvar (reinicia o servidor)', defs2[0].version !== def.version, [def.version, defs2[0].version]);
  const resolved = await state.provider.provider.resolveMcpServerDefinition(defs2[0]);
  check('nenhuma senha no ambiente do servidor', resolved.env.TMDB_SECRETS === undefined);

  console.log('== botão Testar (executável real)');
  await send({ type: 'test', connection: conn, useStored: true });
  await new Promise((r) => setTimeout(r, 1500));
  let res = last('testResult');
  check('teste com a senha do cofre', res && res.ok === true && /PostgreSQL/.test(res.version), res);
  await send({ type: 'test', connection: conn, password: 'errada' });
  await new Promise((r) => setTimeout(r, 1500));
  res = last('testResult');
  check('teste com senha digitada errada falha com a mensagem do banco', res && res.ok === false && /password/.test(res.error), res);
  await send({ type: 'test', connection: Object.assign({}, conn, { port: 59999, connectTimeout: 2 }) });
  await new Promise((r) => setTimeout(r, 3500));
  res = last('testResult');
  check('porta errada: erro em português', res && res.ok === false && /conectar/.test(res.error), res);

  console.log('== servidor MCP iniciado como o VS Code faria');
  const cp = require('child_process');
  const out = cp.spawnSync(resolved.command, resolved.args, {
    env: Object.assign({}, process.env, resolved.env), encoding: 'utf8',
    input: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}\n' +
           '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"connection":"teste","sql":"select 6*7 as resposta"}}}\n',
  });
  check('consulta pela conexão salva, com a senha lida do cofre pelo próprio servidor', out.stdout.includes('[42]'), out.stdout.slice(-300) + out.stderr);

  console.log('== remover');
  await send({ type: 'save', connections: [], passwords: {}, cleared: [] });
  check('remover a conexão apaga a senha do cofre', vaultIds().length === 0, vaultIds());

  await state.commands.get('tootegaMdb.copyMcpConfig')();
  check('copiar configuração MCP', JSON.parse(state.clipboard).mcpServers['tootega-mdb'].args[0] === 'serve');
  check('nenhum erro mostrado ao usuário', !state.messages.some((m) => String(m).startsWith('ERRO')), state.messages);
  void changed;

  console.log('== registro no Claude Code (CLI simulado)');
  {
    const clients = require(path.join(extDir, 'clients.js'));
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'tmdb-claude-'));
    const saved = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = home;
    const bin = path.join(home, 'dir com espaço', 'tmdb.exe'), cfg = path.join(home, 'connections.json');
    const ran = [];
    const exec = async (command) => { ran.push(command); return ''; };
    check('comando registrado', state.commands.has('tootegaMdb.registerClaudeCode'));
    check('sem entrada: registra', await clients.syncClaudeCode({ bin, configFile: cfg, exec }) === 'registered');
    check('usa mcp add no escopo do usuário, com aspas no caminho',
          ran.length === 2 && ran[1].includes('mcp add tootega-mdb --scope user') && ran[1].includes('"' + bin + '" serve'), ran);
    const write = (command) => fs.writeFileSync(clients.claudeConfigPath(), JSON.stringify(
      { mcpServers: { 'tootega-mdb': { type: 'stdio', command, args: ['serve'], env: { TMDB_CONFIG: cfg } } } }));
    write(bin);
    ran.length = 0;
    check('entrada igual: não chama o CLI', await clients.syncClaudeCode({ bin, configFile: cfg, exec }) === 'current' && ran.length === 0, ran);
    write(path.join(home, 'versao-antiga', 'tmdb.exe'));
    check('caminho antigo: atualiza', await clients.syncClaudeCode({ bin, configFile: cfg, exec }) === 'updated');
    check('remove antes de adicionar', ran.length === 3 && ran[1].includes('mcp remove tootega-mdb --scope user') && ran[2].includes('mcp add'), ran);
    fs.rmSync(clients.claudeConfigPath());
    const none = async () => { throw new Error('não encontrado'); };
    check('sem o CLI: não faz nada', await clients.syncClaudeCode({ bin, configFile: cfg, exec: none }) === 'no-cli');
    if (saved === undefined) delete process.env.CLAUDE_CONFIG_DIR; else process.env.CLAUDE_CONFIG_DIR = saved;
    fs.rmSync(home, { recursive: true, force: true });
  }

  fs.rmSync(storage, { recursive: true, force: true });
  console.log(`\npassou: ${pass}   falhou: ${fail}`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
