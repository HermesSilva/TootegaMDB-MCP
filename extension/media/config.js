/* Tela de configuração de conexões (webview).
 * Abas por banco, lista de conexões à esquerda, formulário à direita.
 * Edita um rascunho em memória; nada vai para o disco até Salvar. */
(function () {
  'use strict';

  const vscode = acquireVsCodeApi();
  const { FLAVORS, ORDER, defaults, fields, parseConnectionString } = window.TMDB_FLAVORS;
  let t = window.TMDB_STRINGS.translator('en');

  const S = {
    conns: [],       // rascunho
    baseline: '[]',  // retrato do que está salvo, para saber se há alterações
    flavor: ORDER[0],
    sel: {},         // sabor -> id selecionado
    pw: {},          // id -> senha digitada nesta sessão
    pwClear: {},     // id -> esquecer a senha salva
    hasPw: {},       // id -> existe senha salva
    tests: {},       // id -> { state: 'running' | 'ok' | 'fail', text }
    open: {},        // grupo recolhível -> aberto?
    paste: null,     // { text, error } enquanto o painel de colar está aberto
    notice: '',
    flash: '',
  };

  /* ---------- utilitários de DOM ---------- */

  function h(tag, attrs) {
    const el = document.createElement(tag);
    for (const k in attrs || {}) {
      const v = attrs[k];
      if (v === false || v === null || v === undefined) continue;
      if (k === 'class') el.className = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else if (k === 'style') el.style.cssText = v; // via CSSOM: a CSP barra o atributo style
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (let i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function append(el, kid) {
    if (kid === null || kid === undefined || kid === false) return;
    if (Array.isArray(kid)) kid.forEach((k) => append(el, k));
    else el.appendChild(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }

  const ICONS = {
    add: '<path d="M8 3v10M3 8h10"/>',
    remove: '<path d="M3 5h10M6.5 5V3.5h3V5M5 5l.6 8h4.8L11 5"/>',
    copy: '<rect x="5.5" y="5.5" width="7.5" height="7.5" rx="1"/><path d="M10.5 5.5V4a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v5.5a1 1 0 0 0 1 1h1.5"/>',
    lock: '<rect x="4" y="7.5" width="8" height="5.5" rx="1"/><path d="M5.8 7.5V5.6a2.2 2.2 0 0 1 4.4 0v1.9"/>',
    pencil: '<path d="M3 13l.6-2.8L10.9 3a1.1 1.1 0 0 1 1.6 0l.5.5a1.1 1.1 0 0 1 0 1.6L5.8 12.4 3 13z"/>',
    plug: '<path d="M6 2.5v3M10 2.5v3M4.5 5.5h7v2.2a3.5 3.5 0 0 1-7 0V5.5zM8 11.2v2.3"/>',
    paste: '<rect x="4" y="3.5" width="8" height="10" rx="1"/><path d="M6.5 3.5V2.6h3v.9M6.3 7.5h3.4M6.3 10h3.4"/>',
    chevron: '<path d="M6 4l4 4-4 4"/>',
    check: '<path d="M3.5 8.5l3 3 6-7"/>',
    alert: '<path d="M8 2.5l6 10.5H2L8 2.5zM8 6.5v3.2M8 11.4v.2"/>',
  };

  function icon(name) {
    const span = document.createElement('span');
    span.className = 'icon';
    span.innerHTML = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" ' +
      'stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICONS[name] + '</svg>';
    return span;
  }

  /* ---------- modelo ---------- */

  function uid() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
    return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  }

  const ofFlavor = (f) => S.conns.filter((c) => c.type === f);
  const byId = (id) => S.conns.find((c) => c.id === id);

  function current() {
    const list = ofFlavor(S.flavor);
    const c = byId(S.sel[S.flavor]);
    if (c && c.type === S.flavor) return c;
    S.sel[S.flavor] = list.length ? list[0].id : null;
    return list[0] || null;
  }

  function uniqueName(base) {
    const taken = (n) => S.conns.some((c) => (c.name || '').toLowerCase() === n.toLowerCase());
    if (!taken(base)) return base;
    for (let i = 2; ; i++) if (!taken(base + ' ' + i)) return base + ' ' + i;
  }

  /* O que vai para o disco: sem campos escondidos nem vazios. */
  function clean(c) {
    const out = { id: c.id, type: c.type };
    fields(c.type).forEach((f) => {
      if (f.key === 'password') return;
      if (f.showIf && !f.showIf(c)) return;
      let v = c[f.key];
      if (typeof v === 'string') v = v.trim();
      if (v === '' || v === undefined || v === null) return;
      out[f.key] = v;
    });
    if (c.readOnly === false) out.readOnly = false;
    else out.readOnly = true;
    return out;
  }

  const snapshot = () => JSON.stringify(S.conns.map(clean));

  function isDirty() {
    return snapshot() !== S.baseline || Object.keys(S.pw).some((k) => S.pw[k]) || Object.keys(S.pwClear).length > 0;
  }

  function validate(c) {
    const errors = {};
    fields(c.type).forEach((f) => {
      if (f.showIf && !f.showIf(c)) return;
      const v = c[f.key];
      const empty = v === undefined || v === null || String(v).trim() === '';
      if (f.required && empty) {
        errors[f.key] = t('v.required');
        return;
      }
      if (f.type === 'number' && !empty) {
        const n = Number(v);
        if (!Number.isInteger(n) || n < f.min || n > f.max)
          errors[f.key] = f.key === 'port' ? t('v.port') : t('v.number', f.min, f.max);
      }
    });
    const name = (c.name || '').trim().toLowerCase();
    if (name && S.conns.some((o) => o !== c && (o.name || '').trim().toLowerCase() === name))
      errors.name = t('v.duplicate');
    return errors;
  }

  const hasErrors = (c) => Object.keys(validate(c)).length > 0;
  const allValid = () => S.conns.every((c) => !hasErrors(c));

  /* ---------- ações ---------- */

  function addConnection() {
    const c = defaults(S.flavor);
    c.id = uid();
    c.name = uniqueName(t('list.newName'));
    S.conns.push(c);
    S.sel[S.flavor] = c.id;
    S.paste = null;
    render();
    focusName(true);
  }

  function duplicateConnection() {
    const src = current();
    if (!src) return;
    const c = JSON.parse(JSON.stringify(src));
    c.id = uid();
    c.name = uniqueName(t('list.copyOf', src.name || t('list.newName')));
    S.conns.splice(S.conns.indexOf(src) + 1, 0, c);
    S.sel[S.flavor] = c.id;
    render();
    focusName(true);
  }

  function removeConnection() {
    const c = current();
    if (!c) return;
    const list = ofFlavor(S.flavor);
    const at = list.indexOf(c);
    const next = list[at + 1] || list[at - 1] || null;
    S.conns.splice(S.conns.indexOf(c), 1);
    delete S.pw[c.id];
    delete S.tests[c.id];
    if (S.hasPw[c.id]) S.pwClear[c.id] = true; // a senha salva some junto, ao salvar
    S.sel[S.flavor] = next ? next.id : null;
    S.paste = null;
    render();
  }

  function select(id) {
    if (S.sel[S.flavor] === id) return;
    S.sel[S.flavor] = id;
    S.paste = null;
    S.notice = '';
    render();
  }

  function switchFlavor(f) {
    if (S.flavor === f) return;
    S.flavor = f;
    S.paste = null;
    S.notice = '';
    render();
  }

  function save() {
    if (!isDirty() || !allValid()) return;
    const passwords = {};
    Object.keys(S.pw).forEach((id) => {
      if (S.pw[id] && byId(id)) passwords[id] = S.pw[id];
    });
    vscode.postMessage({
      type: 'save',
      connections: S.conns.map(clean),
      passwords,
      cleared: Object.keys(S.pwClear).filter((id) => !passwords[id]),
    });
  }

  function discard() {
    S.conns = JSON.parse(S.baseline);
    S.pw = {};
    Object.keys(S.pwClear).forEach((id) => { S.hasPw[id] = true; });
    S.pwClear = {};
    S.paste = null;
    S.notice = '';
    render();
  }

  function test() {
    const c = current();
    if (!c || (S.tests[c.id] && S.tests[c.id].state === 'running')) return;
    S.tests[c.id] = { state: 'running' };
    vscode.postMessage({
      type: 'test',
      connection: clean(c),
      password: S.pw[c.id] || undefined,
      useStored: !S.pw[c.id] && !S.pwClear[c.id] && !!S.hasPw[c.id],
    });
    renderChrome();
  }

  function applyPaste() {
    const c = current();
    if (!c || !S.paste) return;
    const got = parseConnectionString(c.type, S.paste.text);
    if (!got) {
      S.paste.error = t('form.pasteBad', FLAVORS[c.type].label);
      renderForm();
      const ta = document.querySelector('.paste textarea');
      if (ta) ta.focus();
      return;
    }
    if (got.password !== undefined) {
      if (got.password) S.pw[c.id] = got.password;
      delete got.password;
    }
    Object.assign(c, got);
    S.paste = null;
    S.notice = t('form.pasteDone');
    render();
  }

  function setField(c, f, raw) {
    if (f.type === 'checkbox') c[f.key] = !!raw;
    else if (f.type === 'number') c[f.key] = raw === '' ? '' : Number(raw);
    else c[f.key] = raw;
    delete S.tests[c.id]; // o resultado do teste valia para os valores anteriores
    S.notice = '';
  }

  /* ---------- desenho ---------- */

  const $app = document.getElementById('app');
  let $tabs, $list, $form, $bar;

  function build() {
    $app.textContent = '';
    $tabs = h('nav', { class: 'tabs', role: 'tablist' });
    $list = h('aside', { class: 'list' });
    $form = h('div', { class: 'form-scroll' });
    $bar = h('footer', { class: 'bar' });
    append($app, [
      h('header', { class: 'top' }, h('h1', {}, t('app.title')), h('p', {}, t('app.subtitle'))),
      $tabs,
      h('main', { class: 'split' }, $list, h('section', { class: 'detail' }, $form, $bar)),
    ]);
  }

  function render() {
    renderTabs();
    renderList();
    renderForm();
    renderBar();
  }

  /* Tudo menos o formulário: usado enquanto se digita, para não perder o foco. */
  function renderChrome() {
    renderTabs();
    renderList();
    renderBar();
    refreshErrors();
  }

  function renderTabs() {
    $tabs.textContent = '';
    ORDER.forEach((f) => {
      const meta = FLAVORS[f];
      const count = ofFlavor(f).length;
      const active = f === S.flavor;
      $tabs.appendChild(h('button', {
        class: 'tab' + (active ? ' active' : ''), role: 'tab', 'aria-selected': active ? 'true' : 'false',
        tabindex: active ? '0' : '-1', 'data-flavor': f, style: '--flavor:' + meta.color,
        onclick: () => switchFlavor(f),
        onkeydown: (e) => {
          const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
          if (!dir) return;
          e.preventDefault();
          switchFlavor(ORDER[(ORDER.indexOf(f) + dir + ORDER.length) % ORDER.length]);
          const el = $tabs.querySelector('.tab.active');
          if (el) el.focus();
        },
      }, h('span', { class: 'chip' }, meta.short), h('span', { class: 'tab-label' }, meta.label),
        h('span', { class: 'count' + (count ? '' : ' zero') }, count)));
    });
  }

  function subtitle(c) {
    const where = (c.host || '') + (c.port ? ':' + c.port : '');
    const what = c.type === 'oracle' ? (c.oracleTarget === 'sid' ? c.sid : c.serviceName) : c.database;
    return where + (what ? ' / ' + what : '');
  }

  function renderList() {
    const list = ofFlavor(S.flavor);
    const cur = current();
    $list.textContent = '';
    $list.appendChild(h('div', { class: 'list-head' },
      h('span', { class: 'list-title' }, t('list.title')),
      h('span', { class: 'list-tools' },
        h('button', { class: 'tool', id: 'btn-add', title: t('list.add'), 'aria-label': t('list.add'), onclick: addConnection },
          icon('add')),
        h('button', { class: 'tool', id: 'btn-duplicate', title: t('list.duplicate'), 'aria-label': t('list.duplicate'),
                      disabled: !cur, onclick: duplicateConnection }, icon('copy')),
        h('button', { class: 'tool', id: 'btn-remove', title: t('list.remove'), 'aria-label': t('list.remove'),
                      disabled: !cur, onclick: removeConnection }, icon('remove')))));

    if (!list.length) {
      $list.appendChild(h('div', { class: 'list-empty' },
        h('p', {}, t('list.empty', FLAVORS[S.flavor].label)),
        h('button', { class: 'link', onclick: addConnection }, t('list.emptyAction'))));
      return;
    }
    const ul = h('ul', { class: 'items', role: 'listbox', 'aria-label': t('list.title') });
    list.forEach((c) => {
      const active = cur && c.id === cur.id;
      const test = S.tests[c.id];
      ul.appendChild(h('li', {
        class: 'item' + (active ? ' active' : '') + (hasErrors(c) ? ' invalid' : ''),
        role: 'option', 'aria-selected': active ? 'true' : 'false', tabindex: active ? '0' : '-1', 'data-id': c.id,
        onclick: () => select(c.id),
        onkeydown: (e) => {
          const dir = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0;
          if (!dir) return;
          e.preventDefault();
          const next = list[list.indexOf(c) + dir];
          if (!next) return;
          select(next.id);
          const el = $list.querySelector('.item.active');
          if (el) el.focus();
        },
      },
        h('span', { class: 'env env-' + (c.environment || 'none'), title: c.environment ? t('env.' + c.environment) : null }),
        h('span', { class: 'item-text' },
          h('span', { class: 'item-name' }, c.name || t('list.newName')),
          h('span', { class: 'item-sub' }, subtitle(c))),
        test && test.state !== 'running' ? h('span', { class: 'dot ' + test.state }) : null,
        h('span', { class: 'mode' + (c.readOnly === false ? ' rw' : ''),
                    title: t(c.readOnly === false ? 'list.writable' : 'list.readOnly') },
          icon(c.readOnly === false ? 'pencil' : 'lock'))));
    });
    $list.appendChild(ul);
  }

  function fieldLabel(f) {
    return t(f.label || 'f.' + f.key);
  }

  function control(c, f) {
    const id = 'f-' + f.key;
    const onInput = (e) => {
      setField(c, f, f.type === 'checkbox' ? e.target.checked : e.target.value);
      /* Campos de que outros dependem redesenham o formulário; os demais, só o entorno. */
      if (f.type === 'select' || f.type === 'checkbox') {
        render();
        const again = document.getElementById(id);
        if (again) again.focus();
      } else {
        renderChrome();
      }
    };

    if (f.type === 'checkbox') {
      const off = c[f.key] === false;
      return h('div', { class: 'field check' + (off ? ' warn' : ''), style: 'grid-column: span ' + f.w },
        h('label', { class: 'check-label', for: id },
          h('input', { type: 'checkbox', id, checked: !off, onchange: onInput }),
          h('span', {}, fieldLabel(f))),
        h('p', { class: 'hint' }, off ? [icon('alert'), ' ', t('h.readOnlyOff')] : t('h.readOnly')),
        h('p', { class: 'hint subtle' }, t('h.readOnlyTip')));
    }

    let input;
    if (f.type === 'select') {
      input = h('select', { id, onchange: onInput },
        f.options.map((o) => h('option', { value: o.value, selected: (c[f.key] || '') === o.value }, t(o.label))));
    } else if (f.type === 'password') {
      const saved = S.hasPw[c.id] && !S.pwClear[c.id];
      const field = h('input', {
        type: 'password', id, autocomplete: 'off', spellcheck: 'false',
        value: S.pw[c.id] || '',
        placeholder: saved ? '•••••••• ' + t('form.passwordSaved') : '',
        oninput: (e) => {
          S.pw[c.id] = e.target.value;
          delete S.tests[c.id];
          renderChrome();
        },
      });
      const toggle = h('button', { class: 'ghost', type: 'button', onclick: () => {
        const show = field.type === 'password';
        field.type = show ? 'text' : 'password';
        toggle.textContent = t(show ? 'form.hide' : 'form.show');
      } }, t('form.show'));
      input = h('div', { class: 'with-button' }, field, toggle);
      if (saved)
        return wrap(f, id, input, h('button', { class: 'link small', type: 'button', onclick: () => {
          S.pwClear[c.id] = true;
          render();
        } }, t('form.passwordClear')));
    } else if (f.type === 'file') {
      const field = h('input', { type: 'text', id, value: c[f.key] || '', spellcheck: 'false', oninput: onInput });
      input = h('div', { class: 'with-button' }, field,
        h('button', { class: 'ghost', type: 'button',
                      onclick: () => vscode.postMessage({ type: 'pickFile', id: c.id, key: f.key }) },
          t('form.browse')));
    } else {
      input = h('input', {
        type: f.type === 'number' ? 'number' : 'text', id, spellcheck: 'false', autocomplete: 'off',
        value: c[f.key] === undefined || c[f.key] === null ? '' : c[f.key],
        placeholder: f.placeholder || null, min: f.min, max: f.max, oninput: onInput,
      });
    }
    return wrap(f, id, input);
  }

  function wrap(f, id, input, extra) {
    return h('div', { class: 'field', style: 'grid-column: span ' + f.w, 'data-key': f.key },
      h('label', { for: id }, fieldLabel(f), f.required ? h('span', { class: 'req', 'aria-hidden': 'true' }, ' *') : null),
      input,
      h('p', { class: 'err', 'data-err': f.key }),
      f.hint ? h('p', { class: 'hint' }, t(f.hint)) : null,
      extra || null);
  }

  function renderForm() {
    const c = current();
    $form.textContent = '';
    if (!c) {
      $form.appendChild(h('div', { class: 'placeholder' }, icon('plug'), h('p', {}, t('form.none'))));
      return;
    }
    const meta = FLAVORS[c.type];

    $form.appendChild(h('div', { class: 'form-head', style: '--flavor:' + meta.color },
      h('span', { class: 'chip big' }, meta.short),
      h('div', { class: 'form-title' },
        h('h2', {}, c.name || t('list.newName')),
        h('span', { class: 'form-flavor' }, meta.label)),
      h('button', { class: 'ghost', id: 'btn-paste', type: 'button', onclick: () => {
        S.paste = S.paste ? null : { text: '', error: '' };
        renderForm();
        const ta = document.querySelector('.paste textarea');
        if (ta) ta.focus();
      } }, icon('paste'), ' ', t('form.paste'))));

    if (S.paste) {
      $form.appendChild(h('div', { class: 'paste' },
        h('p', { class: 'hint' }, t('form.pasteHint')),
        h('textarea', { rows: '2', spellcheck: 'false', value: S.paste.text,
                        oninput: (e) => { S.paste.text = e.target.value; },
                        onkeydown: (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); applyPaste(); } } }),
        S.paste.error ? h('p', { class: 'err show' }, S.paste.error) : null,
        h('div', { class: 'paste-actions' },
          h('button', { class: 'primary', id: 'btn-paste-apply', type: 'button', onclick: applyPaste }, t('form.pasteApply')),
          h('button', { class: 'ghost', type: 'button', onclick: () => { S.paste = null; renderForm(); } },
            t('form.pasteCancel')))));
    }
    if (S.notice) $form.appendChild(h('div', { class: 'notice' }, icon('check'), ' ', S.notice));

    meta.groups.forEach((g) => {
      const visible = g.fields.filter((f) => !f.showIf || f.showIf(c));
      if (!visible.length) return;
      const key = c.type + '.' + g.id;
      const collapsible = !!g.collapsed;
      const open = !collapsible || !!S.open[key];
      const head = collapsible
        ? h('button', { class: 'group-head toggle' + (open ? ' open' : ''), type: 'button', 'aria-expanded': String(open),
                        onclick: () => { S.open[key] = !open; renderForm(); } },
            icon('chevron'), t('group.' + g.id))
        : h('div', { class: 'group-head' }, t('group.' + g.id));
      $form.appendChild(h('section', { class: 'group' }, head,
        open ? h('div', { class: 'grid' }, visible.map((f) => control(c, f))) : null));
    });
    refreshErrors();
  }

  function refreshErrors() {
    const c = current();
    if (!c) return;
    const errors = validate(c);
    $form.querySelectorAll('[data-err]').forEach((el) => {
      const msg = errors[el.getAttribute('data-err')] || '';
      el.textContent = msg;
      el.classList.toggle('show', !!msg);
      const field = el.closest('.field');
      if (field) field.classList.toggle('bad', !!msg);
    });
    const title = $form.querySelector('.form-title h2');
    if (title) title.textContent = c.name || t('list.newName');
  }

  function renderBar() {
    const c = current();
    const dirty = isDirty();
    const valid = allValid();
    const test = c ? S.tests[c.id] : null;
    const running = !!test && test.state === 'running';
    $bar.textContent = '';

    let result = null;
    if (test && test.state === 'ok') result = h('span', { class: 'result ok', role: 'status' }, icon('check'), ' ', test.text);
    else if (test && test.state === 'fail') result = h('span', { class: 'result fail', role: 'alert' }, icon('alert'), ' ', test.text);
    else if (running) result = h('span', { class: 'result running', role: 'status' }, h('span', { class: 'spinner' }));

    let state = null;
    if (dirty && !valid) state = h('span', { class: 'state invalid' }, t('state.invalid'));
    else if (dirty) state = h('span', { class: 'state dirty' }, t('state.dirty'));
    else if (S.flash) state = h('span', { class: 'state saved' }, icon('check'), ' ', S.flash);

    append($bar, [
      h('div', { class: 'bar-left' },
        h('button', { class: 'secondary', id: 'btn-test', type: 'button', disabled: !c || running || (c && hasErrors(c)),
                      onclick: test_ }, icon('plug'), ' ', t(running ? 'btn.testing' : 'btn.test')),
        result),
      h('div', { class: 'bar-right' }, state,
        h('button', { class: 'ghost', id: 'btn-discard', type: 'button', disabled: !dirty, onclick: discard }, t('btn.discard')),
        h('button', { class: 'primary', id: 'btn-save', type: 'button', disabled: !dirty || !valid, onclick: save },
          t('btn.save'))),
    ]);
  }
  const test_ = () => test();

  function focusName(selectAll) {
    const el = document.getElementById('f-name');
    if (!el) return;
    el.focus();
    if (selectAll) el.select();
  }

  /* ---------- mensagens do host ---------- */

  window.addEventListener('message', (ev) => {
    const m = ev.data || {};
    if (m.type === 'init' || m.type === 'saved') {
      if (m.lang) t = window.TMDB_STRINGS.translator(m.lang);
      document.documentElement.lang = m.lang === 'pt' ? 'pt-BR' : 'en';
      S.conns = (m.connections || []).map((c) => Object.assign(defaults(c.type), c,
        c.type === 'oracle' ? { oracleTarget: c.sid && !c.serviceName ? 'sid' : 'serviceName' } : {}));
      S.baseline = snapshot();
      S.hasPw = m.hasPassword || {};
      S.pw = {};
      S.pwClear = {};
      S.flash = m.type === 'saved' ? t('state.saved') : '';
      if (m.type === 'init') {
        /* Abre na primeira aba que tem conexões. */
        const withData = ORDER.find((f) => ofFlavor(f).length);
        if (withData) S.flavor = withData;
        build();
      }
      render();
      if (S.flash) setTimeout(() => { S.flash = ''; renderBar(); }, 2500);
    } else if (m.type === 'testResult') {
      if (!byId(m.id)) return;
      S.tests[m.id] = m.ok
        ? { state: 'ok', text: t('test.ok', m.version, m.elapsedMs) }
        : { state: 'fail', text: t('test.fail', m.error) };
      renderChrome();
    } else if (m.type === 'filePicked') {
      const c = byId(m.id);
      if (!c) return;
      c[m.key] = m.path;
      render();
    }
  });

  window.addEventListener('keydown', (e) => {
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === 's') {
      e.preventDefault();
      save();
    } else if (mod && e.key === 'Enter') {
      e.preventDefault();
      test();
    }
  });

  build();
  render();
  vscode.postMessage({ type: 'ready' });
})();
