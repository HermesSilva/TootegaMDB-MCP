// Executa o registro no Claude Code como a extensão faz ao ativar: node claude-register.js <exe> <connections.json>
const clients = require('../../extension/clients.js');
const [bin, configFile] = process.argv.slice(2);
clients.syncClaudeCode({ bin, configFile }).then(
  (outcome) => { console.log('resultado:', outcome); console.log(JSON.stringify(clients.readClaudeEntry(), null, 2)); },
  (e) => { console.error('falhou:', e.message); process.exit(1); });
