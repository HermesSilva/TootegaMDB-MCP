/* Teste de interação da tela de configuração: dirige a tela real pelo navegador.
 * Uso:  node ui-test.js */
'use strict';
const { launch, openHarness } = require('./browser');

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

(async () => {
  const browser = await launch();
  try {
    const page = await openHarness(browser, { lang: 'pt' });
    const text = (sel) => page.locator(sel).first().innerText();
    const value = (sel) => page.locator(sel).inputValue();
    const posted = (type) => page.evaluate((ty) => window.__posted.filter((m) => m.type === ty), type);
    await page.evaluate(() => { window.__testDelay = 50; });

    console.log('== estado inicial');
    check('quatro abas', (await page.locator('.tab').count()) === 4);
    check('idioma português', (await text('.list-title')).toUpperCase() === 'CONEXÕES');
    check('lista vazia com atalho', (await text('.list-empty')).includes('Nenhuma conexão PostgreSQL'));
    check('Remover desabilitado sem seleção', await page.locator('#btn-remove').isDisabled());
    check('Salvar desabilitado sem alterações', await page.locator('#btn-save').isDisabled());

    console.log('== incluir e preencher (PostgreSQL)');
    await page.click('#btn-add');
    check('nome recebe foco', await page.evaluate(() => document.activeElement.id === 'f-name'));
    check('porta padrão 5432', (await value('#f-port')) === '5432');
    check('somente leitura marcado', await page.locator('#f-readOnly').isChecked());
    await page.fill('#f-name', 'vendas');
    check('lista acompanha a digitação', (await text('.item.active .item-name')) === 'vendas');
    check('foco não se perde ao digitar', await page.evaluate(() => document.activeElement.id === 'f-name'));
    check('Testar bloqueado com campo obrigatório vazio', await page.locator('#btn-test').isDisabled());
    check('erro de obrigatório no usuário', (await text('[data-err="user"]')) === 'Obrigatório');
    await page.fill('#f-user', 'leitor');
    await page.fill('#f-password', 'segredo');
    await page.fill('#f-database', 'loja');
    check('contador da aba', (await text('.tab.active .count')) === '1');
    check('indica alterações não salvas', (await text('.state')).includes('não salvas'));

    console.log('== testar');
    await page.click('#btn-test');
    await page.waitForSelector('.result.ok');
    check('resultado do teste', (await text('.result.ok')).includes('PostgreSQL 17'));
    const tests = await posted('test');
    check('teste leva a senha digitada', tests[0].password === 'segredo' && tests[0].connection.password === undefined, tests[0]);
    await page.fill('#f-host', 'db.exemplo.com');
    check('resultado some ao editar', (await page.locator('.result').count()) === 0);
    await page.evaluate(() => { window.__failTest = 'senha incorreta'; });
    await page.click('#btn-test');
    await page.waitForSelector('.result.fail');
    check('falha de teste aparece', (await text('.result.fail')).includes('senha incorreta'));
    await page.evaluate(() => { window.__failTest = null; });

    console.log('== salvar');
    await page.click('#btn-save');
    await page.waitForSelector('.state.saved');
    const saves = await posted('save');
    const c0 = saves[0].connections[0];
    check('salvou os campos', c0.name === 'vendas' && c0.host === 'db.exemplo.com' && c0.port === 5432 &&
      c0.database === 'loja' && c0.user === 'leitor' && c0.readOnly === true && c0.type === 'postgres', c0);
    check('senha vai separada, nunca na conexão', c0.password === undefined && saves[0].passwords[c0.id] === 'segredo');
    check('campos vazios não são gravados', !('schema' in c0) && !('applicationName' in c0), c0);
    check('Salvar volta a desabilitar', await page.locator('#btn-save').isDisabled());
    check('senha salva vira marcador', (await page.locator('#f-password').getAttribute('placeholder')).includes('salva'));

    console.log('== validação de nome duplicado');
    await page.click('#btn-duplicate');
    check('duplicata ganha nome novo', (await value('#f-name')) === 'vendas cópia');
    await page.fill('#f-name', 'VENDAS');
    check('duplicado é recusado (sem diferenciar maiúsculas)', (await text('[data-err="name"]')).includes('já usa'));
    check('Salvar bloqueado com erro', await page.locator('#btn-save').isDisabled());
    check('item marcado como inválido', (await page.locator('.item.invalid').count()) === 2);
    await page.click('#btn-remove');
    check('remover seleciona o vizinho', (await text('.item.active .item-name')) === 'vendas');
    check('sem alterações após remover a cópia', await page.locator('#btn-save').isDisabled());

    console.log('== SQL Server com string de conexão');
    await page.click('.tab[data-flavor="mssql"]');
    check('aba troca a lista', (await text('.list-empty')).includes('SQL Server'));
    await page.click('#btn-add');
    check('porta padrão 1433', (await value('#f-port')) === '1433');
    await page.click('#btn-paste');
    await page.fill('.paste textarea',
      'Server=tcp:sql01.corp\\FIN,1444;Database=Faturamento;User Id=svc_leitura;Password=P@ss;Encrypt=True;TrustServerCertificate=True');
    await page.click('#btn-paste-apply');
    check('host da string', (await value('#f-host')) === 'sql01.corp');
    check('instância da string', (await value('#f-instance')) === 'FIN');
    check('porta da string', (await value('#f-port')) === '1444');
    check('banco da string', (await value('#f-database')) === 'Faturamento');
    check('usuário da string', (await value('#f-user')) === 'svc_leitura');
    check('senha da string', (await value('#f-password')) === 'P@ss');
    check('TLS da string', (await value('#f-sslMode')) === 'require');
    await page.click('#btn-paste');
    await page.fill('.paste textarea', 'isto não é uma string');
    await page.click('#btn-paste-apply');
    check('string inválida avisa', (await text('.paste .err')).includes('Não foi possível'));

    console.log('== Oracle: service name x SID');
    await page.click('.tab[data-flavor="oracle"]');
    await page.click('#btn-add');
    check('service name visível por padrão', (await page.locator('#f-serviceName').count()) === 1 &&
      (await page.locator('#f-sid').count()) === 0);
    await page.selectOption('#f-oracleTarget', 'sid');
    check('troca para SID', (await page.locator('#f-sid').count()) === 1 && (await page.locator('#f-serviceName').count()) === 0);
    await page.click('#btn-paste');
    await page.fill('.paste textarea', 'jdbc:oracle:thin:@//ora.corp:1522/VENDASPDB');
    await page.click('#btn-paste-apply');
    check('JDBC Oracle preenche o serviço', (await value('#f-serviceName')) === 'VENDASPDB' && (await value('#f-port')) === '1522');

    console.log('== MySQL com URL');
    await page.click('.tab[data-flavor="mysql"]');
    await page.click('#btn-add');
    await page.click('#btn-paste');
    await page.fill('.paste textarea', 'mysql://app:s%40nha@mysql.corp:3307/loja?ssl-mode=REQUIRED');
    await page.click('#btn-paste-apply');
    check('URL MySQL', (await value('#f-host')) === 'mysql.corp' && (await value('#f-port')) === '3307' &&
      (await value('#f-user')) === 'app' && (await value('#f-password')) === 's@nha' && (await value('#f-sslMode')) === 'require');

    console.log('== escrita liberada e descartar');
    await page.uncheck('#f-readOnly');
    check('aviso de escrita liberada', (await text('.field.check.warn .hint')).includes('Escrita liberada'));
    check('ícone de escrita na lista', (await page.locator('.item.active .mode.rw').count()) === 1);
    await page.click('#btn-discard');
    check('descartar volta ao salvo', (await page.locator('.tab[data-flavor="mysql"] .count').innerText()) === '0' &&
      (await page.locator('.tab[data-flavor="postgres"] .count').innerText()) === '1');

    console.log('== inglês');
    const en = await openHarness(browser, { lang: 'en', data: 'sample' });
    check('textos em inglês', (await en.locator('.list-title').innerText()).toUpperCase() === 'CONNECTIONS' &&
      (await en.locator('#btn-test').innerText()).trim() === 'Test');
    check('abre na aba com conexões', (await en.locator('.tab.active').getAttribute('data-flavor')) === 'postgres');
    check('ambiente traduzido', (await en.locator('#f-environment option:checked').innerText()) === 'Production');

    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    check('sem erros de script', errors.length === 0, errors);
  } finally {
    await browser.close();
  }
  console.log(`\npassou: ${pass}   falhou: ${fail}`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
