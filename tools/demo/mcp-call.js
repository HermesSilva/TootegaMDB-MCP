// Chama uma ferramenta do servidor MCP por stdio: node mcp-call.js <exe> <config> <tool> <args-json>
const { spawn } = require('child_process');
const [exe, config, tool, args] = process.argv.slice(2);
const p = spawn(exe, ['serve', '--lang', 'pt'], { env: { ...process.env, TMDB_CONFIG: config } });
let out = '';
p.stdout.on('data', d => {
  out += d;
  let i;
  while ((i = out.indexOf('\n')) >= 0) {
    const msg = JSON.parse(out.slice(0, i));
    out = out.slice(i + 1);
    if (msg.id === 1) console.log('server:', JSON.stringify(msg.result.serverInfo));
    if (msg.id === 2) { console.log(msg.result.content[0].text); p.stdin.end(); }
  }
});
p.stderr.pipe(process.stderr);
const send = o => p.stdin.write(JSON.stringify(o) + '\n');
send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-call', version: '1' } } });
send({ jsonrpc: '2.0', method: 'notifications/initialized' });
send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: tool, arguments: JSON.parse(args || '{}') } });
