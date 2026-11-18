// OwlAuth Twin panel: copy buttons and live refresh by long-poll.
(function () {
  const live = document.getElementById('live');
  const toast = document.getElementById('toast');
  let version = 0;

  function say(msg) {
    toast.textContent = msg;
    toast.classList.add('on');
    clearTimeout(say.t);
    say.t = setTimeout(() => toast.classList.remove('on'), 1800);
  }

  function copy(text) {
    const done = () => say('Copied');
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, () => say('Copy failed'));
      return;
    }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    document.execCommand('copy') ? done() : say('Copy failed');
    ta.remove();
  }

  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-copy]');
    if (b) { e.preventDefault(); copy(b.getAttribute('data-copy')); }
  });

  // Don't swap the page under a text selection or a field you are typing in. A focused radio or
  // checkbox does not count: on Setup nearly everything is one, and its choice is kept across the swap.
  const CLICKABLE = ['radio', 'checkbox', 'button', 'submit', 'reset'];
  function busy() {
    const el = document.activeElement;
    if (String(window.getSelection()) !== '') return true;
    if (live.querySelector('details.pick[open], details.hmore[open]')) return true;   // a menu is open
    if (!el) return false;
    if (el.tagName === 'INPUT') return !CLICKABLE.includes(el.type);
    return el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable;
  }

  // A swap skipped while busy runs as soon as you are done, not only at the next server change.
  let pending = false;
  function catchUp() {
    if (pending && !busy()) { pending = false; rerender(); }
  }
  document.addEventListener('selectionchange', () => setTimeout(catchUp, 300));
  document.addEventListener('focusout', () => setTimeout(catchUp, 0));

  // New requests flash once, so you see what just happened without hunting for it.
  const seen = new Set([...live.querySelectorAll('[data-ex]')].map((el) => el.dataset.ex));
  function markFresh() {
    live.querySelectorAll('[data-ex]').forEach((el) => {
      if (!seen.has(el.dataset.ex)) { el.classList.add('fresh'); seen.add(el.dataset.ex); }
    });
  }

  // Token lifetimes count down here, so the page is not re-sent every second.
  function tick() {
    const now = Date.now() / 1000;
    live.querySelectorAll('[data-until]').forEach((el) => {
      const left = Math.max(0, Math.round(+el.dataset.until - now));
      const txt = left ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} left` : 'expired';
      if (el.textContent !== txt) el.textContent = txt;
    });
  }
  tick();
  setInterval(tick, 1000);

  // Form fields you changed (checkboxes, text) by name and value, put back after a swap.
  const edits = new Map();
  const fieldKey = (el) => (el.type === 'checkbox' ? `${el.name}=${el.value}` : el.name);
  document.addEventListener('input', (e) => {
    const el = e.target;
    if (!el.name || !live.contains(el) || el.type === 'radio') return;
    edits.set(fieldKey(el), el.type === 'checkbox' ? el.checked : el.value);
  });
  function restoreEdits() {
    live.querySelectorAll('input[name]').forEach((el) => {
      const k = fieldKey(el);
      if (!edits.has(k)) return;
      if (el.type === 'checkbox') el.checked = edits.get(k);
      else el.value = edits.get(k);
    });
  }

  // Setup and Session settings: the flag card follows its switch; Setup's mode picks the switch's
  // default until you touch it; the Start line says what Start session does.
  const MODES = { full: 'Full stack', twin_only: 'Twin only' };
  function syncFlags(card) {
    const sw = card.querySelector('input[name=flags]');
    const on = sw.checked;
    card.querySelectorAll('input[name=org], input[name=flag], input[name=flag_add]').forEach((i) => { i.disabled = !on; });
    card.querySelector('.flags')?.classList.toggle('off', !on);
    card.querySelector('input[name=org]')?.closest('.srow')?.classList.toggle('dim', !on);
    const hint = card.querySelector('[data-off-hint]');
    if (hint) hint.hidden = on;
    let changes = 0;
    card.querySelectorAll('input[name=flag][data-was]').forEach((i) => {
      const now = on && i.checked;
      const changed = now !== (i.dataset.was === '1');
      const st = i.closest('.flag').querySelector('.s');
      st.textContent = changed ? `changed · ${now ? 'on' : 'off'}` : (now ? 'on' : '');
      st.classList.toggle('chg', changed);
      if (changed) changes += 1;
    });
    const org = card.querySelector('input[name=org]');
    if (org && card.dataset.orgWas && on && org.value.trim() !== card.dataset.orgWas) changes += 1;
    // Turning the whole card on or off is one change, whatever it does to each flag.
    if (card.dataset.enabledWas && String(on) !== card.dataset.enabledWas) changes = 1;
    const add = card.querySelector('input[name=flag_add]');
    if (add && on && add.value.trim()) changes += 1;
    const note = card.closest('form')?.querySelector('[data-changes]');
    if (note && card.dataset.enabledWas) {
      const n = changes ? `${changes} change${changes === 1 ? '' : 's'}. ` : 'No changes. ';
      note.textContent = n + 'Runs in the background; you can close this. The health bar shows when it is done.';
    }
  }
  function syncSetup() {
    const form = live.querySelector('#setup');
    if (!form) return;
    const mode = form.querySelector('input[name=mode]:checked')?.value || 'full';
    form.querySelectorAll('[data-show]').forEach((el) => { el.hidden = el.dataset.show !== mode; });
    const sw = form.querySelector('input[name=flags]');
    if (sw && !edits.has(fieldKey(sw))) sw.checked = mode === 'full';
    const box = form.querySelector('input[name=devbox]:checked')?.value || 'no devbox';
    const prov = form.querySelector('input[name=provider]:checked')?.dataset.name || '?';
    const org = form.querySelector('input[name=org]')?.value.trim();
    const anyFlag = [...form.querySelectorAll('input[name=flag]')].some((i) => i.checked)
      || !!form.querySelector('input[name=flag_add]')?.value.trim();
    const flags = sw && sw.checked && anyFlag ? `flags for org ${org}` : 'no flags';
    const short = prov.replace(/ connector$/, '').replace(' connector (', ' (');
    const line = form.querySelector('[data-summary]');
    if (line) line.textContent = `Start: ${box} · ${MODES[mode]} · ${short} first · ${flags}. Stop undoes all of it.`;
  }
  function syncForms() {
    syncSetup();
    live.querySelectorAll('[data-flags]').forEach(syncFlags);
  }
  document.addEventListener('change', (e) => { if (live.contains(e.target)) syncForms(); });
  document.addEventListener('input', (e) => { if (live.contains(e.target)) syncForms(); });
  // Enter in "Add flag" adds a row (a new switch, on) instead of submitting the form. Added rows
  // are put back after a swap, like the fields you changed.
  const added = [];
  function addFlagRow(card, name) {
    const addRow = card.querySelector('.flag.addf');
    if (!addRow || [...card.querySelectorAll('input[name=flag]')].some((i) => i.value === name)) return;
    const div = document.createElement('div');
    div.className = 'flag';
    div.innerHTML = '<label class="sw"><input type="checkbox" name="flag" checked><i></i></label><span class="n"></span><span class="s"></span>';
    const box = div.querySelector('input');
    box.value = name;
    box.setAttribute('aria-label', name);
    if (card.dataset.enabledWas) box.dataset.was = '0';
    div.querySelector('.n').textContent = name;
    addRow.before(div);
  }
  document.addEventListener('keydown', (e) => {
    const el = e.target;
    if (e.key !== 'Enter' || el.name !== 'flag_add') return;
    e.preventDefault();
    const name = el.value.trim();
    if (!name) return;
    if (!/^[A-Za-z0-9._-]{1,120}$/.test(name)) { say('Not a flag name'); return; }
    if (!added.includes(name)) added.push(name);
    addFlagRow(el.closest('[data-flags]'), name);
    el.value = '';
    edits.delete('flag_add');
    syncForms();
  });
  // A form posts once: a second click while the first is on its way does nothing. The button is
  // disabled after the submit has picked it up, so its formaction and value still count.
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.dataset.sent) { e.preventDefault(); return; }
    form.dataset.sent = '1';
    const b = e.submitter;
    setTimeout(() => {
      form.querySelectorAll('button[type=submit]:not([disabled])').forEach((x) => {
        x.disabled = true;
        x.dataset.sentOff = '1';
      });
      if (b) b.setAttribute('aria-busy', 'true');
    }, 0);
  });
  // Back from the browser's page cache: the buttons work again.
  window.addEventListener('pageshow', (e) => {
    if (!e.persisted) return;
    document.querySelectorAll('form[data-sent]').forEach((f) => {
      delete f.dataset.sent;
      f.querySelectorAll('button[data-sent-off]').forEach((x) => {
        x.disabled = false;
        delete x.dataset.sentOff;
        x.removeAttribute('aria-busy');
      });
    });
  });
  // The connector menu and the health bar's "+N" close on a click outside them.
  document.addEventListener('click', (e) => {
    live.querySelectorAll('details.pick[open], details.hmore[open]').forEach((d) => {
      if (!d.contains(e.target)) d.open = false;
    });
  });
  syncForms();

  let lastHtml = '';
  async function rerender() {
    const r = await fetch(location.href, { headers: { 'X-Fragment': '1' } });
    if (!r.ok) return;
    const data = await r.json();
    document.title = data.title;
    if (data.html === lastHtml) return;   // nothing visible changed: keep the DOM, keep hover
    lastHtml = data.html;
    // Fresh nodes under the pointer would replay hover transitions; skip them for this swap.
    document.documentElement.classList.add('swap');
    // Columns scroll on their own; keep each one where you left it.
    const keep = ['.acts', '.side', '.drawer'].map((sel) => [sel, live.querySelector(sel)?.scrollTop || 0]);
    // Keep what you picked on Setup (devbox, provider) when the list under it changes.
    const picked = [...live.querySelectorAll('input[type=radio]:checked')].map((el) => [el.name, el.value]);
    live.innerHTML = data.html;
    keep.forEach(([sel, top]) => { const el = live.querySelector(sel); if (el) el.scrollTop = top; });
    picked.forEach(([name, value]) => {
      const el = [...live.querySelectorAll('input[type=radio]')].find((r) => r.name === name && r.value === value);
      if (el && !el.disabled) el.checked = true;
    });
    live.querySelectorAll('[data-flags]').forEach((card) => added.forEach((n) => addFlagRow(card, n)));
    restoreEdits();
    syncForms();
    markFresh();
    tick();
    requestAnimationFrame(() => requestAnimationFrame(() => document.documentElement.classList.remove('swap')));
  }

  async function loop() {
    for (;;) {
      try {
        const r = await fetch('/api/wait?v=' + version);
        const data = await r.json();
        if (data.v !== version) {
          const first = version === 0;
          version = data.v;
          if (!first) {
            if (busy()) pending = true;
            else { pending = false; await rerender(); }
          }
        }
      } catch (err) {
        await new Promise((res) => setTimeout(res, 2000));
      }
    }
  }
  loop();
})();
