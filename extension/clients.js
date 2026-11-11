/* Registro do servidor MCP em clientes que não usam a API de MCP do VS Code.
 *
 * O Copilot Chat recebe o servidor pelo provider registrado em extension.js. O Claude Code
 * (CLI e extensão) lê a própria lista, em ~/.claude.json; aqui a extensão mantém nela a
 * entrada "tootega-mdb", no escopo do usuário, pelo próprio CLI (`claude mcp add`), que é
 * quem sabe gravar aquele arquivo. Sem o CLI instalado, nada é feito. */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const SERVER_NAME = 'tootega-mdb';

function claudeConfigPath() {
  const dir = (process.env.CLAUDE_CONFIG_DIR || '').trim() || os.homedir();
  return path.join(dir, '.claude.json');
}

/** Entrada atual do servidor no escopo do usuário, ou null. */
function readClaudeEntry() {
  try {
    const json = JSON.parse(fs.readFileSync(claudeConfigPath(), 'utf8'));
    return (json.mcpServers && json.mcpServers[SERVER_NAME]) || null;
  } catch (e) {
    return null;
  }
}

function samePath(a, b) {
  if (!a || !b) return false;
  const norm = (p) => {
    const full = path.resolve(p);
    return process.platform === 'win32' ? full.toLowerCase() : full;
  };
  return norm(a) === norm(b);
}

function isCurrent(entry, bin, configFile) {
  return !!entry && samePath(entry.command, bin) &&
    Array.isArray(entry.args) && entry.args.length === 1 && entry.args[0] === 'serve' &&
    samePath(entry.env && entry.env.TMDB_CONFIG, configFile);
}

function quote(value) {
  return /[\s"'&|<>^()]/.test(value) ? '"' + value.replace(/"/g, '\\"') + '"' : value;
}

function addCommand(cli, bin, configFile) {
  return quote(cli) + ' mcp add ' + SERVER_NAME + ' --scope user -e ' +
    quote('TMDB_CONFIG=' + configFile) + ' -- ' + quote(bin) + ' serve';
}

function run(command, timeout) {
  return new Promise((resolve, reject) => {
    cp.exec(command, { windowsHide: true, timeout: timeout || 30000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(String(stderr || error.message).trim()));
      else resolve(stdout);
    });
  });
}

function knownCliPaths() {
  const home = os.homedir();
  const list = [path.join(home, '.local', 'bin', 'claude')];
  if (process.platform === 'win32') {
    list.push(path.join(home, '.local', 'bin', 'claude.exe'));
    if (process.env.APPDATA) list.push(path.join(process.env.APPDATA, 'npm', 'claude.cmd'));
    if (process.env.ProgramFiles) list.push(path.join(process.env.ProgramFiles, 'nodejs', 'claude.cmd'));
  } else {
    list.push('/usr/local/bin/claude', '/opt/homebrew/bin/claude');
  }
  return list.filter((c) => fs.existsSync(c));
}

async function locateCli(exec) {
  for (const candidate of ['claude', ...knownCliPaths()]) {
    try {
      await exec(quote(candidate) + ' --version', 10000);
      return candidate;
    } catch (e) { /* tenta o próximo */ }
  }
  return null;
}

/**
 * Deixa a entrada do Claude Code apontando para este executável e este arquivo de conexões.
 * Devolve 'current' (nada a fazer), 'registered', 'updated' ou 'no-cli'; lança se o CLI recusar.
 * @param {{bin: string, configFile: string, exec?: (command: string, timeout?: number) => Promise<string>}} options
 */
async function syncClaudeCode(options) {
  const exec = options.exec || run;
  const entry = readClaudeEntry();
  if (isCurrent(entry, options.bin, options.configFile)) return 'current';
  const cli = await locateCli(exec);
  if (!cli) return 'no-cli';
  /* O CLI não sobrescreve um nome que já existe. */
  if (entry) await exec(quote(cli) + ' mcp remove ' + SERVER_NAME + ' --scope user');
  await exec(addCommand(cli, options.bin, options.configFile));
  return entry ? 'updated' : 'registered';
}

module.exports = { SERVER_NAME, syncClaudeCode, readClaudeEntry, isCurrent, addCommand, claudeConfigPath };
