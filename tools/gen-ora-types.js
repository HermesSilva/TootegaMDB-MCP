/* Gera core/src/ora_types.inc: a lista de representações de tipos que o cliente
 * declara ao servidor Oracle na negociação de tipos de dado (mensagem DATA_TYPES).
 *
 * A lista é um dado do protocolo (centenas de trios numéricos), extraído da
 * implementação aberta de referência (python-oracledb, modo thin).
 * Uso:  node tools/gen-ora-types.js <data_types.pyx> <base_impl.pxd> */
'use strict';
const fs = require('fs');
const [typesFile, baseFile] = process.argv.slice(2);
const types = fs.readFileSync(typesFile, 'utf8');
const base = fs.readFileSync(baseFile, 'utf8');

const values = {};
for (const text of [base, types]) {
  for (const m of text.matchAll(/^\s*((?:TNS_DATA_TYPE|ORA_TYPE_NUM|TNS_TYPE_REP)_\w+)\s*=\s*([0-9+ ]+)\s*$/gm))
    values[m[1]] = m[2].split('+').reduce((sum, part) => sum + Number(part.trim()), 0);
}

const start = types.indexOf('DATA_TYPES = [');
const end = types.indexOf('\n]', start);
const rows = [];
for (const m of types.slice(start, end).matchAll(/\[\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\]/g)) {
  const row = [m[1], m[2], m[3]].map((name) => {
    if (/^\d+$/.test(name)) return Number(name);
    if (!(name in values)) throw new Error('constante desconhecida: ' + name);
    return values[name];
  });
  if (row[0] === 0) break;
  rows.push(row);
}

let out = '/* Gerado por tools/gen-ora-types.js — não editar à mão.\n' +
  ' * Trios (tipo, tipo de conversão, representação) da negociação de tipos do Oracle. */\n';
for (let i = 0; i < rows.length; i += 6)
  out += '    ' + rows.slice(i, i + 6).map((r) => `{${r[0]},${r[1]},${r[2]}}`).join(', ') + ',\n';
fs.writeFileSync(require('path').join(__dirname, '..', 'core', 'src', 'ora_types.inc'), out);
console.log(rows.length + ' tipos');
