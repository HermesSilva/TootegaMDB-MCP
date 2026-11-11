/* Gera o ícone da extensão (PNG, exigência do Marketplace) a partir de um SVG.
 * Uso:  node make-icon.js */
'use strict';
const path = require('path');
const { launch } = require('./browser');

/* Um cilindro de banco em quatro camadas — uma cor por banco suportado. */
const COLORS = ['#3d7ab8', '#d98a1f', '#c8413b', '#b5532f'];
const layer = (i) => {
  const y = 66 + i * 34;
  return `<path d="M56 ${y}v22c0 9 32 16 72 16s72-7 72-16V${y}c0 9-32 16-72 16S56 ${y + 9} 56 ${y}z" fill="${COLORS[i]}"/>
          <path d="M56 ${y}c0 9 32 16 72 16s72-7 72-16" fill="none" stroke="rgba(255,255,255,.28)" stroke-width="2"/>`;
};
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#1b2636"/><stop offset="1" stop-color="#0d131c"/></linearGradient></defs>
  <rect width="256" height="256" rx="52" fill="url(#bg)"/>
  ${[3, 2, 1, 0].map(layer).join('\n')}
  <ellipse cx="128" cy="66" rx="72" ry="16" fill="#5b95cf"/>
  <ellipse cx="128" cy="66" rx="72" ry="16" fill="none" stroke="rgba(255,255,255,.35)" stroke-width="2"/>
</svg>`;

(async () => {
  const browser = await launch();
  const context = await browser.newContext({ viewport: { width: 256, height: 256 } });
  const page = await context.newPage();
  await page.setContent(`<body style="margin:0;background:transparent">${svg}</body>`);
  await page.screenshot({ path: path.join(__dirname, '..', '..', 'extension', 'media', 'icon.png'), omitBackground: true });
  await browser.close();
  console.log('icon.png gerado');
})();
