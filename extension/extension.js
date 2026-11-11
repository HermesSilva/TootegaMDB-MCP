/* Tootega Multi-Database MCP — extensão do VS Code.
 *
 * A extensão é só a casca: guarda as conexões, mostra a tela de configuração e
 * registra o servidor MCP. Todo o acesso a banco está no executável em C (tmdb).
 * JavaScript puro, sem dependências e sem etapa de build. */
'use strict';

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const crypto = require('crypto');

const STRINGS = require('./media/strings.js');
const { FLAVORS } = require('./media/flavors.js');
const CLIENTS = require('./clients.js');

const PROVIDER_ID = 'tootegaMdb';
const SERVER_LABEL = 'Tootega Multi-Database MCP';
const SECRET_PREFIX = 'tootegaMdb.password.';

/* ---------- idioma ---------- */

function language() {
  const forced = vscode.workspace.getConfiguration('tootegaMdb').get('language', 'auto');
  if (forced === 'pt' || forced === 'en') return forced;
  return String(vscode.env.language || 'en').toLowerCase().startsWith('pt') ? 'pt' : 'en';
}

function t(key, ...args) {
  return STRINGS.translator(language())(key, ...args);
}

/* ---------- armazenamento ---------- */

class Store {
  /** @param {vscode.ExtensionContext} context */
  constructor(context) {
    this.context = context;
    this.dir = context.globalStorageUri.fsPath;
    this.file = path.join(this.dir, 'connections.json');
    this.adopt();
  }

  /** Builds de antes da publicação usavam o publisher "tootega": traz as conexões e o cofre de lá. */
  adopt() {
    const old = path.join(path.dirname(this.dir), 'tootega.tootega-mdb');
    if (fs.existsSync(this.file) || !fs.existsSync(path.join(old, 'connections.json'))) return;
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      for (const name of ['secrets.bin', 'connections.json']) {
        if (fs.existsSync(path.join(old, name))) fs.copyFileSync(path.join(old, name), path.join(this.dir, name));
      }
    } catch (e) { /* sem acesso à pasta antiga: começa vazio */ }
  }

  /** Conexões salvas, sem senhas. */
  load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return Array.isArray(data.connections) ? data.connections.filter((c) => c && FLAVORS[c.type]) : [];
    } catch (e) {
      return [];
    }
  }

  /** Grava de forma atômica: o servidor nunca vê um arquivo pela metade. */
  save(connections) {
    fs.mkdirSync(this.dir, { recursive: true });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ version: 1, connections }, null, 2) + '\n', 'utf8');
    fs.renameSync(tmp, this.file);
  }

  /**
   * Cofre de senhas. Pertence ao executável (arquivo secrets.bin ao lado das conexões,
   * cifrado para o usuário desta máquina), não ao VS Code: assim a senha salva aqui vale
   * para qualquer cliente MCP que inicie o servidor — VS Code, Claude Code, Cursor...
   * Aplica as alterações e devolve os ids que têm senha; nenhum valor volta.
   */
  async vault(changes) {
    const bin = serverPath(this.context);
    if (!bin) throw new Error(t('test.noBinary', platformKey()));
    fs.mkdirSync(this.dir, { recursive: true });
    const res = await runTool(bin, ['secret', '--config', this.file], JSON.stringify(changes || {}), 15000);
    if (!res || res.ok !== true) throw new Error((res && res.error) || 'secret store');
    return res.ids || [];
  }

  async hasPasswordMap() {
    const out = {};
    try {
      for (const id of await this.vault({})) out[id] = true;
    } catch (e) { /* sem executável: a tela abre mesmo assim, sem marcar senhas salvas */ }
    return out;
  }

  /** Versões anteriores guardavam a senha no cofre do VS Code: leva para o cofre do executável. */
  async migrate() {
    const set = {};
    for (const c of this.load()) {
      const pw = await this.context.secrets.get(SECRET_PREFIX + c.id);
      if (pw) set[c.id] = pw;
    }
    if (!Object.keys(set).length) return;
    const already = new Set(await this.vault({}));
    for (const id of Object.keys(set)) if (already.has(id)) delete set[id]; // não sobrescreve senha mais nova
    if (Object.keys(set).length) await this.vault({ set });
    for (const c of this.load()) await this.context.secrets.delete(SECRET_PREFIX + c.id);
  }

  /** Muda a cada gravação: sinaliza ao VS Code que a definição do servidor mudou. */
  revision() {
    return this.context.globalState.get('revision', 0);
  }

  bump() {
    return this.context.globalState.update('revision', this.revision() + 1);
  }
}

/* ---------- executável ---------- */

function platformKey() {
  return process.platform + '-' + process.arch;
}

/** Caminho do tmdb para esta plataforma, ou null. */
function serverPath(context) {
  const custom = vscode.workspace.getConfiguration('tootegaMdb').get('serverPath', '');
  if (custom) return fs.existsSync(custom) ? custom : null;
  const exe = process.platform === 'win32' ? 'tmdb.exe' : 'tmdb';
  const candidates = [
    path.join(context.extensionPath, 'bin', platformKey(), exe),
    path.join(context.extensionPath, '..', 'dist', platformKey(), exe), // rodando do repositório
  ];
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    if (process.platform !== 'win32') {
      try { fs.chmodSync(file, 0o755); } catch (e) { /* pacote somente leitura: segue */ }
    }
    return file;
  }
  return null;
}

/**
 * Testa uma conexão com `tmdb test`. A conexão (e a senha, se digitada) vão pela entrada
 * padrão. Com `configFile`, uma conexão sem senha usa a que está salva no cofre.
 */
function runTest(bin, configFile, connection, password) {
  const args = ['test', '--lang', language()];
  if (configFile) args.push('--config', configFile);
  const limit = (Number(connection.connectTimeout) || 10) * 1000 + 5000;
  return runTool(bin, args, JSON.stringify(Object.assign({}, connection, password ? { password } : {})), limit);
}

/** Roda o executável com `input` na entrada padrão e devolve o JSON que ele imprime. */
function runTool(bin, args, input, limit) {
  return new Promise((resolve) => {
    let out = '';
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(result);
    };
    const child = cp.spawn(bin, args, { windowsHide: true });
    const timer = setTimeout(() => {
      child.kill();
      finish({ ok: false, error: t('test.timeout') });
    }, limit);
    child.stdout.on('data', (d) => { out += d.toString('utf8'); });
    child.on('error', (e) => finish({ ok: false, error: e.message }));
    child.on('close', () => {
      try {
        finish(JSON.parse(out));
      } catch (e) {
        finish({ ok: false, error: out.trim() || t('test.timeout') });
      }
    });
    child.stdin.on('error', () => { /* processo morreu antes de ler: o close resolve */ });
    child.stdin.end(input);
  });
}

/* ---------- tela de configuração ---------- */

class ConfigPanel {
  static current = null;

  static show(context, store, onSaved) {
    if (ConfigPanel.current) {
      ConfigPanel.current.panel.reveal();
      return;
    }
    ConfigPanel.current = new ConfigPanel(context, store, onSaved);
  }

  constructor(context, store, onSaved) {
    this.context = context;
    this.store = store;
    this.onSaved = onSaved;
    const media = vscode.Uri.joinPath(context.extensionUri, 'media');
    this.panel = vscode.window.createWebviewPanel('tootegaMdb.config', t('app.title'), vscode.ViewColumn.Active, {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [media],
    });
    this.panel.iconPath = vscode.Uri.joinPath(media, 'icon.png');
    this.panel.webview.html = this.html(media);
    this.panel.webview.onDidReceiveMessage((m) => this.receive(m).catch((e) => {
      vscode.window.showErrorMessage(SERVER_LABEL + ': ' + (e && e.message ? e.message : String(e)));
    }));
    this.panel.onDidDispose(() => { ConfigPanel.current = null; });
  }

  html(media) {
    const w = this.panel.webview;
    const nonce = crypto.randomBytes(16).toString('base64');
    const uri = (name) => w.asWebviewUri(vscode.Uri.joinPath(media, name));
    return `<!DOCTYPE html>
<html lang="${language() === 'pt' ? 'pt-BR' : 'en'}">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src ${w.cspSource}; script-src 'nonce-${nonce}'; img-src ${w.cspSource} data:;">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${uri('config.css')}">
<title>${SERVER_LABEL}</title>
</head>
<body>
<div id="app"></div>
<script nonce="${nonce}" src="${uri('strings.js')}"></script>
<script nonce="${nonce}" src="${uri('flavors.js')}"></script>
<script nonce="${nonce}" src="${uri('config.js')}"></script>
</body>
</html>`;
  }

  async post(type) {
    await this.panel.webview.postMessage({
      type,
      lang: language(),
      connections: this.store.load(),
      hasPassword: await this.store.hasPasswordMap(),
    });
  }

  async receive(m) {
    if (!m || typeof m.type !== 'string') return;
    if (m.type === 'ready') return this.post('init');
    if (m.type === 'save') return this.save(m);
    if (m.type === 'test') return this.test(m);
    if (m.type === 'pickFile') {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        title: t('pick.caFile'),
        filters: { PEM: ['pem', 'crt', 'cer'], '*': ['*'] },
      });
      if (picked && picked[0])
        await this.panel.webview.postMessage({ type: 'filePicked', id: m.id, key: m.key, path: picked[0].fsPath });
    }
  }

  async save(m) {
    const incoming = Array.isArray(m.connections) ? m.connections : [];
    const connections = incoming.filter((c) => c && typeof c.id === 'string' && FLAVORS[c.type]).map((c) => {
      const copy = Object.assign({}, c);
      delete copy.password; // senha nunca vai para o arquivo
      return copy;
    });
    const before = this.store.load();
    const kept = new Set(connections.map((c) => c.id));

    this.store.save(connections);
    /* senhas: novas e trocadas entram; as de conexões removidas ou "esquecidas" saem */
    const set = {};
    for (const id of Object.keys(m.passwords || {}))
      if (kept.has(id) && m.passwords[id]) set[id] = String(m.passwords[id]);
    const gone = before.filter((old) => !kept.has(old.id)).map((old) => old.id)
      .concat((m.cleared || []).map(String)).filter((id) => !set[id]);
    if (Object.keys(set).length || gone.length) await this.store.vault({ set, delete: gone });

    await this.store.bump();
    this.onSaved();
    await this.post('saved');
    vscode.window.setStatusBarMessage('$(check) ' + t('msg.saved'), 5000);
  }

  async test(m) {
    const c = m.connection;
    if (!c || !c.id) return;
    const bin = serverPath(this.context);
    let result;
    if (!bin) {
      result = { ok: false, error: t('test.noBinary', platformKey()) };
    } else {
      /* senha digitada vale sobre a salva; sem nenhuma das duas, testa sem senha */
      const password = typeof m.password === 'string' && m.password ? m.password : undefined;
      const conn = Object.assign({}, c);
      delete conn.password; // a senha só vem do campo próprio ou do cofre, nunca de dentro da conexão
      result = await runTest(bin, !password && m.useStored ? this.store.file : null, conn, password);
    }
    await this.panel.webview.postMessage(Object.assign({ type: 'testResult', id: c.id }, result));
  }
}

/* ---------- ativação ---------- */

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  const store = new Store(context);
  const changed = new vscode.EventEmitter();
  context.subscriptions.push(changed);

  const version = context.extension.packageJSON.version;
  let warned = false;

  store.migrate().catch((e) => {
    vscode.window.showWarningMessage(SERVER_LABEL + ': ' + (e && e.message ? e.message : String(e)));
  });

  /* Servidor MCP: o VS Code inicia o tmdb sob demanda e o reinicia quando a versão muda. */
  if (vscode.lm && typeof vscode.lm.registerMcpServerDefinitionProvider === 'function') {
    context.subscriptions.push(vscode.lm.registerMcpServerDefinitionProvider(PROVIDER_ID, {
      onDidChangeMcpServerDefinitions: changed.event,
      provideMcpServerDefinitions: () => {
        const bin = serverPath(context);
        if (!bin) {
          if (!warned) vscode.window.showWarningMessage(t('msg.noBinary', platformKey()));
          warned = true;
          return [];
        }
        const args = ['serve', '--lang', language()];
        if (vscode.workspace.getConfiguration('tootegaMdb').get('verbose', false)) args.push('--verbose');
        return [new vscode.McpStdioServerDefinition(
          SERVER_LABEL, bin, args, { TMDB_CONFIG: store.file }, version + '+' + store.revision())];
      },
      /* Nenhuma senha passa por aqui: o servidor lê o próprio cofre, ao lado das conexões. */
      resolveMcpServerDefinition: async (server) => server,
    }));
  }

  context.subscriptions.push(
    vscode.commands.registerCommand('tootegaMdb.configure', () => {
      ConfigPanel.show(context, store, () => changed.fire());
    }),
    vscode.commands.registerCommand('tootegaMdb.copyMcpConfig', async () => {
      const bin = serverPath(context);
      if (!bin) {
        vscode.window.showWarningMessage(t('msg.noBinary', platformKey()));
        return;
      }
      const config = { mcpServers: { 'tootega-mdb': { command: bin, args: ['serve'], env: { TMDB_CONFIG: store.file } } } };
      await vscode.env.clipboard.writeText(JSON.stringify(config, null, 2));
      vscode.window.showInformationMessage(t('msg.copied'));
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('tootegaMdb')) changed.fire();
    }),
  );

  /* Claude Code não enxerga os servidores MCP do VS Code: a extensão mantém a entrada dele. */
  const registerClaudeCode = async (announce) => {
    const bin = serverPath(context);
    if (!bin) {
      if (announce) vscode.window.showWarningMessage(t('msg.noBinary', platformKey()));
      return;
    }
    try {
      const outcome = await CLIENTS.syncClaudeCode({ bin, configFile: store.file });
      if (outcome === 'registered') vscode.window.showInformationMessage(t('msg.claudeRegistered'));
      else if (announce) vscode.window.showInformationMessage(t(outcome === 'no-cli' ? 'msg.claudeNoCli' : 'msg.claudeCurrent'));
    } catch (e) {
      vscode.window.showWarningMessage(t('msg.claudeFailed', e && e.message ? e.message : String(e)));
    }
  };
  context.subscriptions.push(
    vscode.commands.registerCommand('tootegaMdb.registerClaudeCode', () => registerClaudeCode(true)));
  if (vscode.workspace.getConfiguration('tootegaMdb').get('registerClaudeCode', true)) registerClaudeCode(false);

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 90);
  status.text = '$(database) MDB';
  status.tooltip = SERVER_LABEL;
  status.command = 'tootegaMdb.configure';
  status.show();
  context.subscriptions.push(status);
}

function deactivate() {}

module.exports = { activate, deactivate };
