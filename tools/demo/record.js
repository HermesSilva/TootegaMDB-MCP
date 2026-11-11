/* Grava as animações da página do Marketplace.
 *
 * Dirige a tela REAL de configuração (os mesmos arquivos da extensão, na bancada
 * harness.html), captura os quadros e monta GIFs animados — um por banco e por
 * idioma. Reprodutível: rode de novo sempre que a tela mudar.
 *
 * Uso:  node record.js            (gera tudo em extension/media/)
 *       node record.js postgres   (só um roteiro)  */
'use strict';
const fs = require('fs');
const path = require('path');
const { PNG } = require('pngjs');
const { GIFEncoder, quantize, applyPalette } = require('gifenc');
const { launch, openHarness } = require('./browser');

const OUT = path.join(__dirname, '..', '..', 'extension', 'media');
const SIZE = { width: 1000, height: 640 };

/* Um "diretor": executa ações na página e guarda quadros com sua duração. */
class Director {
  constructor(page) {
    this.page = page;
    this.frames = [];
    this.cursor = { x: SIZE.width / 2, y: SIZE.height / 2 };
  }

  async init() {
    await this.page.addStyleTag({ content: `
      #demo-cursor { position: fixed; z-index: 99999; width: 22px; height: 22px; pointer-events: none;
                     left: 0; top: 0; filter: drop-shadow(0 1px 2px rgba(0,0,0,.6)); }
      #demo-cursor.down::after { content: ''; position: absolute; left: -9px; top: -9px; width: 26px; height: 26px;
                                 border-radius: 50%; border: 2px solid #4daafc; opacity: .9; }
      * { caret-color: #4daafc; }` });
    await this.page.evaluate(() => {
      const el = document.createElement('div');
      el.id = 'demo-cursor';
      el.innerHTML = '<svg viewBox="0 0 22 22" width="22" height="22"><path d="M3 2l15 8-6.5 1.8L9 18z" ' +
        'fill="#fff" stroke="#111" stroke-width="1.2" stroke-linejoin="round"/></svg>';
      document.body.appendChild(el);
    });
    await this.place();
  }

  async place(down) {
    await this.page.evaluate(([x, y, d]) => {
      const el = document.getElementById('demo-cursor');
      el.style.transform = `translate(${x}px, ${y}px)`;
      el.classList.toggle('down', !!d);
    }, [this.cursor.x, this.cursor.y, down]);
  }

  async shot(ms) {
    const png = await this.page.screenshot({ type: 'png' });
    this.frames.push({ png, delay: ms });
  }

  async hold(ms) {
    await this.shot(ms);
  }

  /* Move o ponteiro até o elemento, em poucos quadros, e clica. */
  async click(selector, opts) {
    const box = await this.page.locator(selector).first().boundingBox();
    const to = { x: box.x + Math.min(box.width / 2, 60), y: box.y + box.height / 2 };
    const from = Object.assign({}, this.cursor);
    const steps = 6;
    for (let i = 1; i <= steps; i++) {
      const k = i / steps;
      const ease = k * k * (3 - 2 * k);
      this.cursor = { x: from.x + (to.x - from.x) * ease, y: from.y + (to.y - from.y) * ease };
      await this.place();
      await this.shot(45);
    }
    await this.place(true);
    await this.shot(160);
    await this.page.locator(selector).first().click();
    await this.place(false);
    await this.shot((opts && opts.after) || 350);
  }

  /* Digita com cadência humana, um quadro a cada dois caracteres. */
  async type(selector, text, opts) {
    await this.click(selector, { after: 120 });
    const el = this.page.locator(selector).first();
    await el.fill('');
    for (let i = 0; i < text.length; i += 2) {
      await el.pressSequentially(text.slice(i, i + 2));
      await this.shot(70);
    }
    await this.shot((opts && opts.after) || 300);
  }

  async select(selector, value) {
    await this.click(selector, { after: 120 });
    await this.page.selectOption(selector, value);
    await this.shot(450);
  }

  async scrollTo(selector) {
    await this.page.locator(selector).first().scrollIntoViewIfNeeded();
    await this.shot(250);
  }

  save(file) {
    const gif = GIFEncoder();
    for (const f of this.frames) {
      const img = PNG.sync.read(f.png);
      const palette = quantize(img.data, 256);
      gif.writeFrame(applyPalette(img.data, palette), img.width, img.height, { palette, delay: f.delay });
    }
    gif.finish();
    fs.writeFileSync(file, Buffer.from(gif.bytes()));
    const kb = Math.round(fs.statSync(file).size / 1024);
    console.log(`  ${path.basename(file)}  ${this.frames.length} quadros  ${kb} KB`);
  }
}

const TEXT = {
  en: { pgName: 'sales-prod', pgDb: 'sales', pgUser: 'reports_ro', msName: 'billing-legacy', oraName: 'erp-finance' },
  pt: { pgName: 'vendas-prod', pgDb: 'vendas', pgUser: 'relatorios_ro', msName: 'faturamento-legado', oraName: 'erp-financeiro' },
};

const SCENARIOS = {
  /* PostgreSQL: incluir, preencher campo a campo, testar e salvar. */
  async postgres(d, t) {
    await d.hold(1200);
    await d.click('#btn-add');
    await d.type('#f-name', t.pgName);
    await d.select('#f-environment', 'production');
    await d.type('#f-host', 'db.acme.internal');
    await d.type('#f-database', t.pgDb);
    await d.scrollTo('#f-password');
    await d.type('#f-user', t.pgUser);
    await d.type('#f-password', 'S3cr3t-k3y!', { after: 500 });
    await d.click('#btn-test', { after: 500 });
    await d.page.waitForSelector('.result.ok');
    await d.hold(1600);
    await d.click('#btn-save', { after: 400 });
    await d.page.waitForSelector('.state.saved');
    await d.hold(2600);
  },

  /* SQL Server: outra aba, e o formulário preenchido colando a string de conexão. */
  async mssql(d, t) {
    await d.hold(1200);
    await d.click('.tab[data-flavor="mssql"]', { after: 600 });
    await d.click('#btn-add');
    await d.type('#f-name', t.msName);
    await d.click('#btn-paste', { after: 500 });
    await d.type('.paste textarea',
      'Server=sql01.acme.internal\\FIN,1444;Database=Billing;User Id=svc_reader;Password=P@ssw0rd;Encrypt=True', { after: 600 });
    await d.click('#btn-paste-apply', { after: 1500 });
    await d.click('#btn-test', { after: 500 });
    await d.page.waitForSelector('.result.ok');
    await d.hold(1600);
    await d.click('#btn-save', { after: 400 });
    await d.page.waitForSelector('.state.saved');
    await d.hold(2600);
  },

  /* Oracle: service name e liberação de escrita, com o aviso correspondente. */
  async oracle(d, t) {
    await d.hold(1200);
    await d.click('.tab[data-flavor="oracle"]', { after: 600 });
    await d.click('#btn-add');
    await d.type('#f-name', t.oraName);
    await d.select('#f-environment', 'staging');
    await d.type('#f-host', 'ora19.acme.internal');
    await d.type('#f-serviceName', 'FINPDB1');
    await d.scrollTo('#f-password');
    await d.type('#f-user', 'APP_FIN');
    await d.type('#f-password', 'S3cr3t-k3y!', { after: 400 });
    await d.scrollTo('#f-readOnly');
    await d.click('#f-readOnly', { after: 1800 });
    await d.click('#f-readOnly', { after: 900 });
    await d.click('#btn-test', { after: 500 });
    await d.page.waitForSelector('.result.ok');
    await d.hold(1600);
    await d.click('#btn-save', { after: 400 });
    await d.page.waitForSelector('.state.saved');
    await d.hold(2600);
  },
};

(async () => {
  const only = process.argv[2];
  const browser = await launch();
  try {
    for (const name of Object.keys(SCENARIOS)) {
      if (only && only !== name) continue;
      for (const lang of ['en', 'pt']) {
        const page = await openHarness(browser, Object.assign({ lang, theme: 'dark', data: name === 'postgres' ? 'empty' : 'sample' }, SIZE));
        const d = new Director(page);
        await d.init();
        await SCENARIOS[name](d, TEXT[lang]);
        d.save(path.join(OUT, `demo-${name}-${lang}.gif`));
        await page.context().close();
      }
    }

    /* Capturas estáticas para a página: visão geral em tema claro e escuro. */
    if (!only) {
      for (const lang of ['en', 'pt']) {
        for (const theme of ['dark', 'light']) {
          const page = await openHarness(browser, Object.assign({ lang, theme, data: 'sample' }, SIZE, { scale: 2 }));
          await page.screenshot({ path: path.join(OUT, `screenshot-${theme}-${lang}.png`) });
          await page.context().close();
        }
      }
      console.log('  capturas estáticas geradas');
    }
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
