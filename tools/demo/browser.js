/* Abre a bancada da tela de configuração num navegador já instalado (Edge ou Chrome). */
'use strict';
const path = require('path');
const { pathToFileURL } = require('url');
const { chromium } = require('playwright-core');

async function launch() {
  let lastError;
  for (const channel of ['msedge', 'chrome']) {
    try {
      return await chromium.launch({ channel, headless: true });
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

/** Abre a bancada. opts: { lang, theme, data, width, height, scale } */
async function openHarness(browser, opts) {
  const o = Object.assign({ lang: 'en', theme: 'dark', data: 'empty', width: 1180, height: 760, scale: 1 }, opts);
  const context = await browser.newContext({
    viewport: { width: o.width, height: o.height },
    deviceScaleFactor: o.scale,
  });
  const page = await context.newPage();
  const url = pathToFileURL(path.join(__dirname, 'harness.html')).href +
    `?lang=${o.lang}&theme=${o.theme}&data=${o.data}`;
  await page.goto(url);
  await page.waitForSelector('.tabs .tab');
  return page;
}

module.exports = { launch, openHarness };
