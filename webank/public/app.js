(() => {
'use strict';

/* ---------- tiny safe-HTML templating: every interpolation is escaped unless wrapped in raw() ---------- */
class Raw { constructor(v) { this.v = v; } }
const raw = (v) => new Raw(v);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const val = (v) => (v instanceof Raw ? v.v : Array.isArray(v) ? v.map(val).join('') : v == null || v === false ? '' : esc(v));
const html = (s, ...v) => raw(s.reduce((a, x, i) => a + x + (i < v.length ? val(v[i]) : ''), ''));
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const root = $('#app');

/* ---------- state, api, helpers ---------- */
const state = { user: null, csrf: '' };
const money = (c) => new Intl.NumberFormat('en-IE', { style: 'currency', currency: 'EUR' }).format(c / 100);
const when = (value) => {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  const text = String(value).trim();
  if (!text) return null;
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(text)
    ? text.replace(' ', 'T') + (/[zZ]|[+-]\d{2}:?\d{2}$/.test(text) ? '' : 'Z')
    : text;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
};
const fmtDate = (value) => {
  const date = when(value);
  return date ? date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
};
const fmtDateTime = (value) => {
  const date = when(value);
  return date ? date.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';
};
const CATS = {
  housing: ['🏠', 'Housing'], groceries: ['🛒', 'Groceries'], dining: ['🍽️', 'Dining'], transport: ['🚆', 'Transport'],
  utilities: ['💡', 'Utilities'], entertainment: ['🎬', 'Entertainment'], health: ['💪', 'Health'], shopping: ['🛍️', 'Shopping'],
  income: ['💶', 'Income'], transfer: ['↗️', 'Transfers'], savings: ['🐖', 'Savings'], other: ['•', 'Other'],
};
const cat = (k) => CATS[k] || CATS.other;
const go = (p) => { location.hash = '#' + p; };
let toastTimer;
function toast(msg, isErr = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show' + (isErr ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 3500);
}
async function api(method, url, body, idempotencyKey) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (method !== 'GET') {
    opts.headers['content-type'] = 'application/json';
    opts.headers['x-csrf-token'] = state.csrf;
    if (idempotencyKey) opts.headers['idempotency-key'] = idempotencyKey;
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(url, opts);
  let data = {};
  try { data = await r.json(); } catch { /* empty */ }
  if (r.status === 401 && state.user && !url.startsWith('/api/auth/')) {
    state.user = null;
    await loadMe();
    toast('Your session expired. Please sign in again.', true);
    go('/login');
    throw new Error('session');
  }
  if (!r.ok) { const e = new Error(data.error || 'Request failed'); e.status = r.status; throw e; }
  return data;
}
async function loadMe() {
  const d = await (await fetch('/api/me', { credentials: 'same-origin' })).json();
  state.user = d.user;
  state.csrf = d.csrf;
}
function csvCell(v) {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formula injection
  return '"' + s.replace(/"/g, '""') + '"';
}
function download(name, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- icons & logo ---------- */
const ic = (d) => raw(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`);
const icons = {
  home: ic('<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>'),
  bank: ic('<path d="M3 10l9-6 9 6"/><path d="M5 10v8M10 10v8M14 10v8M19 10v8M3 20h18"/>'),
  list: ic('<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>'),
  send: ic('<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4z"/>'),
  card: ic('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>'),
  user: ic('<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>'),
  shield: ic('<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z"/>'),
};
const logo = raw(`<span class="logo"><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#0f5a55"/><path d="M6 11l4.5 11L16 13l5.5 9L26 11" fill="none" stroke="#3ee6b5" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>WeBank</span>`);

/* ---------- modal ---------- */
function modal(content, bind) {
  const back = document.createElement('div');
  back.className = 'modal-back';
  back.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${val(content)}</div>`;
  const close = () => { back.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  back.addEventListener('mousedown', (e) => { if (e.target === back) close(); });
  document.body.appendChild(back);
  $$('[data-close]', back).forEach((b) => b.addEventListener('click', close));
  bind && bind(back, close);
  const first = $('input,select,button', back);
  first && first.focus();
  return close;
}

/* ---------- charts (inline SVG, colours from CSS classes so they obey the CSP) ---------- */
function lineChart(series) {
  const W = 600, H = 170, p = 8;
  const vals = series.map((s) => s.balance_cents);
  const min = Math.min(...vals), max = Math.max(...vals), span = max - min || 1;
  const pts = series.map((s, i) => [p + (i * (W - 2 * p)) / (series.length - 1), H - 12 - ((s.balance_cents - min) / span) * (H - 36)]);
  const d = pts.map((q, i) => (i ? 'L' : 'M') + q[0].toFixed(1) + ' ' + q[1].toFixed(1)).join(' ');
  return html`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Total balance over the last 30 days, from ${money(vals[0])} to ${money(vals[vals.length - 1])}">
    <path class="area" d="${d} L${W - p} ${H} L${p} ${H} Z"/><path class="line" d="${d}"/></svg>`;
}
function donut(cats) {
  const total = cats.reduce((a, c) => a + c.total, 0) || 1;
  let off = 25;
  const segs = cats.map((c, i) => {
    const pct = (c.total / total) * 100;
    const s = `<circle class="s${i % 8}" cx="21" cy="21" r="15.9155" fill="none" stroke-width="6" stroke-dasharray="${pct.toFixed(2)} ${(100 - pct).toFixed(2)}" stroke-dashoffset="${off.toFixed(2)}"/>`;
    off -= pct;
    return s;
  });
  return html`<svg viewBox="0 0 42 42" role="img" aria-label="Spending by category, total ${money(total)}" style="max-width:190px;margin:auto"><circle cx="21" cy="21" r="15.9155" fill="none" class="donut-bg" stroke-width="6"/>${raw(segs.join(''))}
    <text x="21" y="20.5" text-anchor="middle" class="donut-t" font-size="3.4" font-weight="700">${money(total)}</text><text x="21" y="25" text-anchor="middle" class="donut-s" font-size="2.4">30 days</text></svg>`;
}
function bars(monthly) {
  const W = 600, H = 190, base = H - 24;
  const max = Math.max(1, ...monthly.flatMap((m) => [m.income, m.spending]));
  const step = W / monthly.length, bw = Math.min(34, step / 3);
  const out = monthly.map((m, i) => {
    const x = i * step + step / 2;
    const h1 = (m.income / max) * (base - 10), h2 = (m.spending / max) * (base - 10);
    return `<rect class="bar-in" x="${x - bw - 2}" y="${base - h1}" width="${bw}" height="${h1}" rx="4"/><rect class="bar-out" x="${x + 2}" y="${base - h2}" width="${bw}" height="${h2}" rx="4"/><text class="axis" x="${x}" y="${H - 6}" text-anchor="middle" font-size="12">${esc(m.month.slice(2))}</text>`;
  });
  return html`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Monthly income versus spending">${raw(out.join(''))}</svg>`;
}

/* ---------- reusable view pieces ---------- */
function txRows(rows, withAccount = false) {
  if (!rows.length) return html`<div class="empty">No transactions found.</div>`;
  return html`<div class="scroll-x"><table><thead><tr><th>Transaction</th>${withAccount ? html`<th>Account</th>` : ''}<th>Date</th><th class="right">Amount</th></tr></thead><tbody>
    ${rows.map((t) => html`<tr>
      <td><div class="tx-main"><span class="tx-icon" aria-hidden="true">${cat(t.category)[0]}</span><div><b>${t.counterparty || '—'}</b><div class="muted small">${t.description} · ${cat(t.category)[1]}</div></div></div></td>
      ${withAccount ? html`<td class="muted small">${t.account_name}</td>` : ''}
      <td class="muted small">${fmtDateTime(t.created_at)}<div class="mono">${t.reference}</div></td>
      <td class="right"><span class="${t.kind === 'credit' ? 'pos' : 'neg'}">${t.kind === 'credit' ? '+' : '−'}${money(t.amount_cents)}</span></td>
    </tr>`)}</tbody></table></div>`;
}
function pwStrength(p) {
  let n = 0;
  if (p.length >= 10) n++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) n++;
  if (/\d/.test(p)) n++;
  if (/[^A-Za-z0-9]/.test(p)) n++;
  return n;
}
function bindMeter(input, meter) {
  input.addEventListener('input', () => {
    const n = pwStrength(input.value);
    meter.firstElementChild.style.width = n * 25 + '%';
    meter.firstElementChild.style.background = ['#c23b3b', '#c23b3b', '#b7791f', '#1a8f63', '#1a8f63'][n];
  });
}
const pwRules = 'At least 10 characters with upper & lower case, a number and a symbol.';
function formSubmit(form, fn) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('button[type=submit]', form);
    const err = $('.error', form);
    err && (err.textContent = '');
    btn && (btn.disabled = true);
    try { await fn(Object.fromEntries(new FormData(form)), form); }
    catch (ex) { if (ex.message !== 'session') { err ? (err.textContent = ex.message) : toast(ex.message, true); } }
    finally { btn && (btn.disabled = false); }
  });
}

/* ---------- shell ---------- */
function shell(path, title, sub, content, actions = '') {
  if (state.user.role === 'employee') {
    const items = [['/employee', 'Employee home', icons.home], ['/profile', 'Profile', icons.user]];
    root.innerHTML = val(html`<div class="shell"><aside class="side">${logo}
      <nav class="nav" aria-label="Main">${items.map(([p, l, i]) => html`<a href="#${p}" class="${p === path ? 'active' : ''}">${i}<span>${l}</span></a>`)}</nav>
      <div class="user"><b>${state.user.full_name}</b><div class="muted">${state.user.email}</div><p><button class="btn small" id="logout">Sign out</button></p></div>
    </aside><main class="main"><div class="page-head"><div><h2>${title}</h2><div class="muted">${sub}</div></div></div>${content}</main></div>`);
    $('#logout').onclick = logout;
    return;
  }
  if (state.user.role === 'admin') {
    const items = [['/admin', 'Admin console', icons.shield], ['/profile', 'Profile', icons.user]];
    root.innerHTML = val(html`<div class="shell"><aside class="side">${logo}
      <nav class="nav" aria-label="Main">${items.map(([p, l, i]) => html`<a href="#${p}" class="${p === path ? 'active' : ''}">${i}<span>${l}</span></a>`)}</nav>
      <div class="user"><b>${state.user.full_name}</b><div class="muted">${state.user.email}</div><p><button class="btn small" id="logout">Sign out</button></p></div>
    </aside><main class="main"><div class="page-head"><div><h2>${title}</h2><div class="muted">${sub}</div></div></div>${content}</main></div>`);
    $('#logout').onclick = logout;
    return;
  }
  const items = [['/dashboard', 'Home', icons.home], ['/accounts', 'Accounts', icons.bank], ['/transactions', 'Activity', icons.list],
    ['/transfer', 'Send', icons.send], ['/budgets', 'Budgets', icons.list], ['/cards', 'Cards', icons.card], ['/profile', 'Profile', icons.user]];
  if (state.user.role === 'admin') items.push(['/admin', 'Admin', icons.shield]);
  root.innerHTML = val(html`<div class="shell">
    <aside class="side">${logo}
      <nav class="nav" aria-label="Main">${items.map(([p, l, i]) => html`<a href="#${p}" class="${p === path ? 'active' : ''}" ${p === path ? raw('aria-current="page"') : ''}>${i}<span>${l}</span></a>`)}</nav>
      <div class="user"><b>${state.user.full_name}</b><div class="muted">${state.user.email}</div><p><button class="btn small" id="logout">Sign out</button></p></div>
    </aside>
    <main class="main" id="main">
      <div class="page-head"><div><h2>${title}</h2><div class="muted">${sub}</div></div><div>${actions}</div></div>
      ${content}
    </main></div>`);
  $('#logout').onclick = logout;
}
async function logout() {
  await api('POST', '/api/auth/logout');
  state.user = null;
  await loadMe();
  toast('Signed out. See you soon!');
  go('/');
}

/* ---------- public pages ---------- */
function totpSetupHtml(totp) {
  return html`<div class="card" style="text-align:center;margin:1rem 0">
    <img src="${totp.qr_code}" alt="QR code for authenticator app setup" style="width:220px;height:220px;image-rendering:pixelated">
    <p class="small">If scanning is unavailable, enter this secret manually:</p>
    <code class="mono">${totp.secret}</code>
  </div>`;
}
function landing() {
  root.innerHTML = val(html`<div class="landing"><div class="wrap">
    <div class="topbar">${logo}<div class="cta" style="margin:0"><a class="btn" href="#/login">Sign in</a><a class="btn primary" href="#/register">Open an account</a></div></div>
    <section class="hero">
      <div><h1>Banking that moves <span class="accent">with you</span>.</h1>
        <p class="lead">Open an account in minutes, send money instantly, freeze your card in a tap and see exactly where every euro goes.</p>
        <div class="cta"><a class="btn primary" href="#/register">Get started - it’s free</a></div></div>
      <div class="mock-card" aria-hidden="true"><div class="chip"></div><div class="num mono">•••• •••• •••• 4417</div>
        <div class="row" style="margin-top:1.4rem;justify-content:space-between"><div><div class="small" style="opacity:.7">CARDHOLDER</div>SARA </div><div class="right"><div class="small" style="opacity:.7">VALID THRU</div>11/30</div></div></div>
    </section>
    <section class="features">
      <div class="feature"><b>Instant transfers</b><p>Send to any IBAN with a clear confirmation step and a unique reference.</p></div>
      <div class="feature"><b>Smart insights</b><p>Spending by category, monthly trends and a 30-day balance chart.</p></div>
      <div class="feature"><b>Card control</b><p>Freeze or unfreeze your card and set monthly limits instantly.</p></div>
    </section>
    </div></div>`);
}
function loginPage() {
  root.innerHTML = val(html`<div class="auth"><div class="panel">${logo}<h2>Welcome back</h2><p class="muted">Sign in to your WeBank account.</p>
    <form id="f" novalidate>
      <div class="field"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required></div>
      <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>
      <div class="error" role="alert"></div>
      <button class="btn dark" style="width:100%" type="submit">Sign in</button>
    </form>
    <p class="small">New here? <a href="#/register">Open an account</a> · <a href="#/">Home</a></p>
    <div class="demo-box"><b>Demo login</b><br>Customer: demo@webank.demo / Demo#WeBank2026</div>
  </div></div>`);
  formSubmit($('#f'), async (d) => {
    const r = await api('POST', '/api/auth/login', d);
    if (r.requires_2fa) {
      root.innerHTML = val(html`<div class="auth"><div class="panel">${logo}<h2>Verification required</h2>
        <p class="muted">Enter the 6-digit code from your authenticator app.</p>
        <form id="twofa" novalidate><div class="field"><label for="code">Authenticator code</label>
          <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,}" maxlength="12" required></div>
          <div class="error" role="alert"></div><button class="btn dark" style="width:100%" type="submit">Verify code</button></form>
        <p class="small"><a href="#/login">Use a different account</a></p></div></div>`);
      formSubmit($('#twofa'), async (code) => {
        const verified = await api('POST', '/api/auth/2fa', code);
        state.csrf = verified.csrf; state.user = verified.user; go('/dashboard');
      });
      return;
    }
    state.csrf = r.csrf; state.user = r.user;
    go('/dashboard');
  });
}
function registerPage() {
  root.innerHTML = val(html`<div class="auth"><div class="panel">${logo}<h2>Open your account</h2><p class="muted">Takes about a minute. You get €100 of demo money.</p>
    <form id="f" novalidate>
      <div class="field"><label for="full_name">Full name</label><input id="full_name" name="full_name" autocomplete="name" required maxlength="80"></div>
      <div class="field"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required></div>
      <div class="field"><label for="role">Account type</label><select id="role" name="role"><option value="customer">Customer</option><option value="employee">Bank employee (requires admin approval)</option></select></div>
      <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" required>
        <div class="meter" id="meter"><i></i></div><div class="hint">${pwRules}</div></div>
      <div class="error" role="alert"></div>
      <button class="btn dark" style="width:100%" type="submit">Create account</button>
    </form>
    <p class="small">Already a customer? <a href="#/login">Sign in</a></p>
  </div></div>`);
  bindMeter($('#password'), $('#meter'));
  formSubmit($('#f'), async (d) => {
    const r = await api('POST', '/api/auth/register', d);
    if (r.pending_approval) {
      root.innerHTML = val(html`<div class="auth"><div class="panel">${logo}<h2>Application received</h2>
        <p>Your employee account was created and is awaiting administrator approval.</p>
        ${totpSetupHtml(r.totp)}
        <p><a href="#/login">Return to sign in</a></p></div></div>`);
      return;
    }
    state.csrf = r.csrf; state.user = r.user;
    root.innerHTML = val(html`<div class="auth"><div class="panel">${logo}<h2>Secure your account</h2>
      <p>Scan this QR code with an authenticator app. You will need the code when signing in.</p>
      ${totpSetupHtml(r.totp)}
      <button class="btn dark" id="continue" style="width:100%">Continue to dashboard</button></div></div>`);
    $('#continue').onclick = () => go('/dashboard');
  });
}
/* ---------- dashboard ---------- */
async function dashboard() {
  const [a, ins, tx] = await Promise.all([api('GET', '/api/accounts'), api('GET', '/api/insights'), api('GET', '/api/transactions?limit=6')]);
  const first = state.user.full_name.split(' ')[0];
  shell('/dashboard', `Hello, ${first} 👋`, new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' }),
    html`<div class="grid cols-2">
      <div class="card hero-card"><div class="muted">Total balance</div><div class="balance">${money(ins.total_cents)}</div>
        <div class="chart" style="margin-top:.8rem">${lineChart(ins.balanceSeries)}</div></div>
      <div class="card"><h3>Your accounts</h3>${a.accounts.map((x) => html`<div class="acct"><div><b>${x.nickname}</b><div class="muted small mono">${x.iban}</div></div><div class="right"><b>${money(x.balance_cents)}</b><div><span class="pill">${x.type}</span></div></div></div>`)}
        <div class="toolbar" style="margin:1rem 0 0"><a class="btn primary" href="#/transfer">Send money</a><a class="btn" href="#/accounts">Manage</a></div></div>
    </div>
    <div class="grid cols-2" style="margin-top:1rem">
      <div class="card"><h3>Spending · last 30 days</h3>${ins.byCategory.length ? html`<div class="chart">${donut(ins.byCategory)}</div>
        <div class="legend">${ins.byCategory.slice(0, 8).map((c, i) => html`<div><span><i class="dot c${i % 8}"></i>${cat(c.category)[1]}</span><b>${money(c.total)}</b></div>`)}</div>` : html`<div class="empty">No spending yet.</div>`}</div>
      <div class="card"><h3>Income vs spending</h3><div class="chart">${bars(ins.monthly)}</div>
        <div class="legend"><div><span><i class="dot c1"></i>Income</span><span><i class="dot c3"></i>Spending</span></div></div></div>
    </div>
    <div class="card" style="margin-top:1rem"><div class="row" style="justify-content:space-between;align-items:center"><h3>Recent activity</h3><a class="small" href="#/transactions" style="flex:none">View all</a></div>${txRows(tx.transactions, true)}</div>`);
}

/* ---------- accounts ---------- */
async function accountsPage() {
  const { accounts } = await api('GET', '/api/accounts');
  shell('/accounts', 'Accounts', 'Your WeBank accounts and balances',
    html`<div class="grid cols-2">${accounts.map((x) => html`<div class="card"><div class="row" style="justify-content:space-between;align-items:flex-start"><div><span class="pill">${x.type}</span><h3 style="margin-top:.5rem">${x.nickname}</h3></div><div class="balance" style="font-size:1.6rem">${money(x.balance_cents)}</div></div>
      <p class="mono small" style="word-break:break-all">${x.iban}</p><p class="muted small">Opened ${fmtDate(x.created_at)}</p>
      <div class="toolbar"><button class="btn small" data-copy="${x.iban}">Copy IBAN</button><button class="btn small" data-rename="${x.id}" data-name="${x.nickname}">Rename</button></div></div>`)}</div>`,
    html`<button class="btn primary" id="open">+ Open account</button>`);
  $('#open').onclick = () => modal(html`<h3>Open a new account</h3><form id="mf"><div class="field"><label>Type</label><select name="type"><option value="checking">Checking</option><option value="savings">Savings</option></select></div>
    <div class="field"><label>Nickname</label><input name="nickname" maxlength="40" placeholder="e.g. Holiday fund"></div><div class="error" role="alert"></div>
    <div class="toolbar"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit">Open</button></div></form>`,
  (m, close) => formSubmit($('#mf', m), async (d) => { await api('POST', '/api/accounts', d); close(); toast('Account opened'); accountsPage(); }));
  $$('[data-copy]').forEach((b) => (b.onclick = async () => { try { await navigator.clipboard.writeText(b.dataset.copy); toast('IBAN copied'); } catch { toast('Copy failed', true); } }));
  $$('[data-rename]').forEach((b) => (b.onclick = () => modal(html`<h3>Rename account</h3><form id="mf"><div class="field"><input name="nickname" maxlength="40" value="${b.dataset.name}"></div><div class="error" role="alert"></div>
    <div class="toolbar"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit">Save</button></div></form>`,
  (m, close) => formSubmit($('#mf', m), async (d) => { await api('PATCH', '/api/accounts/' + b.dataset.rename, d); close(); accountsPage(); }))));
}

/* ---------- transactions ---------- */
const txFilter = { account_id: '', kind: '', category: '', q: '', offset: 0 };
async function txPage() {
  const { accounts } = await api('GET', '/api/accounts');
  const qs = (extra = {}) => new URLSearchParams(Object.entries({ ...txFilter, limit: 20, ...extra }).filter(([, v]) => v !== '' && v != null)).toString();
  shell('/transactions', 'Activity', 'Search and filter every transaction', html`
    <div class="card"><form class="toolbar" id="flt">
      <input class="grow" name="q" placeholder="Search name, description or reference" value="${txFilter.q}" aria-label="Search">
      <select name="account_id" aria-label="Account"><option value="">All accounts</option>${accounts.map((a) => html`<option value="${a.id}" ${String(a.id) === txFilter.account_id ? raw('selected') : ''}>${a.nickname}</option>`)}</select>
      <select name="kind" aria-label="Type"><option value="">In & out</option><option value="credit" ${txFilter.kind === 'credit' ? raw('selected') : ''}>Money in</option><option value="debit" ${txFilter.kind === 'debit' ? raw('selected') : ''}>Money out</option></select>
      <select name="category" aria-label="Category"><option value="">All categories</option>${Object.entries(CATS).map(([k, v]) => html`<option value="${k}" ${txFilter.category === k ? raw('selected') : ''}>${v[1]}</option>`)}</select>
      <button class="btn dark" type="submit">Apply</button><button class="btn" type="button" id="csv">Export CSV</button></form>
      <div id="list"><div class="spinner">Loading…</div></div></div>`);
  const draw = async () => {
    const r = await api('GET', '/api/transactions?' + qs());
    $('#list').innerHTML = val(html`${txRows(r.transactions, true)}<div class="pager"><span class="muted small">${r.total} result${r.total === 1 ? '' : 's'}</span>
      <span><button class="btn small" id="prev" ${txFilter.offset === 0 ? raw('disabled') : ''}>← Newer</button> <button class="btn small" id="next" ${txFilter.offset + 20 >= r.total ? raw('disabled') : ''}>Older →</button></span></div>`);
    $('#prev').onclick = () => { txFilter.offset = Math.max(0, txFilter.offset - 20); draw(); };
    $('#next').onclick = () => { txFilter.offset += 20; draw(); };
  };
  $('#flt').addEventListener('submit', (e) => { e.preventDefault(); Object.assign(txFilter, Object.fromEntries(new FormData(e.target)), { offset: 0 }); draw(); });
  $('#csv').onclick = async () => {
    const r = await api('GET', '/api/transactions?' + qs({ limit: 100, offset: 0 }));
    const lines = [['Date', 'Reference', 'Account', 'Counterparty', 'Description', 'Category', 'Type', 'Amount EUR'].map(csvCell).join(',')];
    r.transactions.forEach((t) => lines.push([t.created_at, t.reference, t.account_name, t.counterparty, t.description, t.category, t.kind,
      ((t.kind === 'credit' ? 1 : -1) * t.amount_cents / 100).toFixed(2)].map(csvCell).join(',')));
    download('webank-transactions.csv', lines.join('\r\n'));
  };
  draw();
}

/* ---------- transfer ---------- */
async function transferPage() {
  const [{ accounts }, { beneficiaries }] = await Promise.all([api('GET', '/api/accounts'), api('GET', '/api/beneficiaries')]);
  shell('/transfer', 'Send money', 'Transfer to your own accounts or to anyone with an IBAN', html`
    <div class="grid cols-2"><div class="card"><form id="tf" novalidate>
      <div class="field"><label for="from">From</label><select id="from" name="from_account_id">${accounts.map((a) => html`<option value="${a.id}">${a.nickname} · ${money(a.balance_cents)}</option>`)}</select></div>
      <div class="field"><label for="who">Quick fill</label><select id="who"><option value="">Choose a beneficiary or your own account…</option>
        <optgroup label="My accounts">${accounts.map((a) => html`<option value="own:${a.id}">${a.nickname}</option>`)}</optgroup>
        ${beneficiaries.length ? html`<optgroup label="Beneficiaries">${beneficiaries.map((b) => html`<option value="ben:${b.id}">${b.name}</option>`)}</optgroup>` : ''}</select></div>
      <div class="row"><div class="field"><label for="to_name">Recipient name</label><input id="to_name" name="to_name" maxlength="80" required></div>
        <div class="field"><label for="to_iban">IBAN</label><input id="to_iban" name="to_iban" class="mono" maxlength="40" autocomplete="off" required></div></div>
      <div class="row"><div class="field"><label for="amount">Amount (€)</label><input id="amount" name="amount" inputmode="decimal" placeholder="0.00" required></div>
        <div class="field"><label for="description">Reference</label><input id="description" name="description" maxlength="100" placeholder="Optional"></div></div>
      <div class="field"><label><input type="checkbox" name="save_beneficiary" value="1" style="width:auto"> Save as beneficiary</label></div>
      <div class="error" role="alert"></div>
      <button class="btn primary" type="submit">Review transfer</button></form></div>
    <div class="card"><h3>Beneficiaries</h3>${beneficiaries.length ? beneficiaries.map((b) => html`<div class="acct"><div><b>${b.name}</b><div class="muted small mono">${b.iban}</div></div><button class="btn small danger" data-del="${b.id}">Remove</button></div>`) : html`<div class="empty">No saved beneficiaries yet.</div>`}
      <p class="hint">Daily transfer limit: €5,000. Savings accounts can only move money to your own accounts.</p></div></div>`);
  $('#who').onchange = (e) => {
    const [kind, id] = e.target.value.split(':');
    if (kind === 'own') { const a = accounts.find((x) => String(x.id) === id); $('#to_name').value = state.user.full_name; $('#to_iban').value = a.iban; }
    if (kind === 'ben') { const b = beneficiaries.find((x) => String(x.id) === id); $('#to_name').value = b.name; $('#to_iban').value = b.iban; }
  };
  $$('[data-del]').forEach((b) => (b.onclick = async () => { await api('DELETE', '/api/beneficiaries/' + b.dataset.del); toast('Beneficiary removed'); transferPage(); }));
  formSubmit($('#tf'), (d) => {
    const from = accounts.find((a) => String(a.id) === d.from_account_id);
    modal(html`<h3>Confirm transfer</h3>
      <div class="acct"><span class="muted">From</span><b>${from.nickname}</b></div><div class="acct"><span class="muted">To</span><b>${d.to_name}</b></div>
      <div class="acct"><span class="muted">IBAN</span><span class="mono small">${d.to_iban}</span></div><div class="acct"><span class="muted">Amount</span><b>€${d.amount}</b></div>
      <div class="error" role="alert"></div>
      <div class="toolbar"><button class="btn" data-close id="no">Cancel</button><button class="btn primary" id="yes">Confirm & send</button></div>`,
    (m, close) => {
      $('#yes', m).onclick = async () => {
        $('#yes', m).disabled = true;
        try {
          const r = await api('POST', '/api/transfers', { ...d, save_beneficiary: !!d.save_beneficiary }, crypto.randomUUID());
          close();
          $('#main').innerHTML = val(html`<div class="card" style="max-width:520px;margin:2rem auto;text-align:center"><div style="font-size:3rem">✅</div><h2>Transfer sent</h2>
            <p class="muted">€${d.amount} to ${d.to_name}</p><p class="mono">Ref ${r.reference}</p><p class="muted small">${r.internal ? 'Delivered instantly inside WeBank.' : 'Sent to an external bank (simulated).'}</p>
            <div class="toolbar"><a class="btn" href="#/transactions">View activity</a><a class="btn primary" href="#/dashboard">Done</a></div></div>`);
        } catch (ex) { $('.error', m).textContent = ex.message; $('#yes', m).disabled = false; }
      };
    });
  });
}

/* ---------- cards ---------- */
async function cardsPage() {
  const { cards } = await api('GET', '/api/cards');
  shell('/cards', 'Cards', 'Freeze, unfreeze and set spending limits', html`<div class="grid cols-2">${cards.map((c) => html`<div class="card">
    <div class="bcard ${c.status === 'frozen' ? 'frozen' : ''}"><div class="row" style="justify-content:space-between;flex-wrap:nowrap"><b>WeBank</b><span class="pill ${c.status === 'active' ? 'ok' : 'bad'}">${c.status}</span></div>
      <div><div class="chip"></div></div><div class="num mono">•••• •••• •••• ${c.last4}</div>
      <div class="row" style="justify-content:space-between;flex-wrap:nowrap"><span>${state.user.full_name.toUpperCase()}</span><span>${c.expires}</span></div></div>
    <p class="muted small">Linked to ${c.account_name} · Monthly limit <b>${money(c.monthly_limit_cents)}</b></p>
    <div class="toolbar"><button class="btn ${c.status === 'active' ? 'danger' : 'primary'}" data-toggle="${c.id}">${c.status === 'active' ? 'Freeze card' : 'Unfreeze card'}</button><button class="btn" data-limit="${c.id}">Change limit</button></div></div>`)}
    ${cards.length ? '' : html`<div class="empty">No cards yet.</div>`}</div>`);
  $$('[data-toggle]').forEach((b) => (b.onclick = async () => { const r = await api('POST', `/api/cards/${b.dataset.toggle}/toggle`); toast('Card ' + r.status); cardsPage(); }));
  $$('[data-limit]').forEach((b) => (b.onclick = () => modal(html`<h3>Monthly card limit</h3><form id="mf"><div class="field"><label>Limit (€, max 10,000)</label><input name="limit" inputmode="decimal" required></div><div class="error" role="alert"></div>
    <div class="toolbar"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit">Save</button></div></form>`,
  (m, close) => formSubmit($('#mf', m), async (d) => { await api('PATCH', `/api/cards/${b.dataset.limit}/limit`, d); close(); toast('Limit updated'); cardsPage(); }))));
}

/* ---------- profile ---------- */
async function profilePage() {
  shell('/profile', 'Profile & security', 'Your details and password', html`<div class="grid cols-2">
    <div class="card"><h3>Personal details</h3><form id="pf"><div class="field"><label>Full name</label><input name="full_name" value="${state.user.full_name}" maxlength="80" required></div>
      <div class="field"><label>Email</label><input value="${state.user.email}" disabled></div><div class="field"><label>Phone</label><input name="phone" value="${state.user.phone}" maxlength="30"></div>
      <div class="error" role="alert"></div><button class="btn dark" type="submit">Save changes</button></form></div>
    <div class="card"><h3>Change password</h3><form id="pw"><div class="field"><label>Current password</label><input type="password" name="current" autocomplete="current-password" required></div>
      <div class="field"><label>New password</label><input id="np" type="password" name="next" autocomplete="new-password" required><div class="meter" id="meter"><i></i></div><div class="hint">${pwRules}</div></div>
      <div class="error" role="alert"></div><button class="btn dark" type="submit">Update password</button></form>
      ${state.user.role !== 'admin' ? html`<hr style="border:none;border-top:1px solid var(--line);margin:1.4rem 0">
        <h3>Two-factor authentication</h3><p class="muted small">Authenticator app codes are required when you sign in.</p>
        <button class="btn" id="reset-2fa">Generate new QR code</button>` : ''}
      ${state.user.role === 'customer' ? html`<hr style="border:none;border-top:1px solid var(--line);margin:1.4rem 0">
        <h3>Close account</h3><p class="muted small">Your account will be deleted only after an administrator reviews your request.</p>
        <button class="btn danger" id="close-account">Request account closure</button>` : ''}
      <hr style="border:none;border-top:1px solid var(--line);margin:1.4rem 0"><p class="muted small">Sessions end automatically after 15 minutes of inactivity.</p><button class="btn" id="lo">Sign out</button></div></div>`);
  bindMeter($('#np'), $('#meter'));
  $('#lo').onclick = logout;
  formSubmit($('#pf'), async (d) => { await api('PATCH', '/api/profile', d); await loadMe(); toast('Profile saved'); });
  formSubmit($('#pw'), async (d, f) => { await api('POST', '/api/profile/password', d); f.reset(); toast('Password updated'); });
  if (state.user.role !== 'admin') {
    $('#reset-2fa').onclick = () => modal(
      html`<h3>Generate new authenticator QR code</h3><p class="muted small">Enter your current password to replace the existing secret.</p>
        <form id="twofa-reset"><div class="field"><label>Current password</label><input type="password" name="current" autocomplete="current-password" required></div>
        <div class="error" role="alert"></div><button class="btn dark" type="submit">Generate QR code</button></form>`,
      (back, close) => formSubmit($('#twofa-reset', back), async (d) => {
        const result = await api('POST', '/api/profile/2fa/reset', d);
        close();
        modal(html`<h3>Scan your new QR code</h3><p class="muted small">Your previous authenticator code is no longer valid.</p>${totpSetupHtml(result.totp)}`);
      }),
    );
  }
  if (state.user.role === 'customer') {
    $('#close-account').onclick = async () => {
      if (!confirm('Request permanent deletion of your customer account? An administrator must approve it.')) return;
      await api('POST', '/api/profile/close-account');
      toast('Account closure request sent to an administrator.');
      profilePage();
    };
  }
  await securityActivity();
}

/* ---------- admin ---------- */
async function adminPage() {
  const [s, u, a, pending, deposits, workerActivity, closures] = await Promise.all([api('GET', '/api/admin/stats'), api('GET', '/api/admin/users'), api('GET', '/api/admin/audit'), api('GET', '/api/admin/pending-employees'), api('GET', '/api/admin/pending-deposits'), api('GET', '/api/admin/worker-activity'), api('GET', '/api/admin/account-closures')]);
  shell('/admin', 'Admin console', 'Customers, risk signals and audit trail', html`
    <div class="grid cols-3"><div class="card"><div class="muted">Customers</div><div class="balance">${s.customers}</div></div>
      <div class="card"><div class="muted">Deposits held</div><div class="balance">${money(s.deposits_cents)}</div></div>
      <div class="card"><div class="muted">Transactions (24h)</div><div class="balance">${s.transactions_24h}</div></div>
      <div class="card"><div class="muted">Failed logins (24h)</div><div class="balance">${s.failed_logins_24h}</div></div></div>
    <div class="card" style="margin-top:1rem"><h3>Users</h3><div class="scroll-x"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th class="right">Balance</th><th></th></tr></thead><tbody>
      ${u.users.map((x) => html`<tr><td>${x.full_name}</td><td class="muted">${x.email}</td><td>${x.role}</td><td><span class="pill ${x.status === 'active' ? 'ok' : 'bad'}">${x.status}</span></td><td class="right">${money(x.balance_cents)}</td>
        <td class="right">${x.id === state.user.id ? '' : html`<button class="btn small" data-st="${x.id}" data-to="${x.status === 'active' ? 'locked' : 'active'}">${x.status === 'active' ? 'Lock' : 'Unlock'}</button>`}</td></tr>`)}</tbody></table></div></div>
    <div class="card" style="margin-top:1rem"><h3>Pending employee applications</h3>${pending.registrations.length ? html`<div class="scroll-x"><table><thead><tr><th>Name</th><th>Email</th><th>Requested</th><th></th></tr></thead><tbody>${pending.registrations.map((x) => html`<tr><td>${x.full_name}</td><td>${x.email}</td><td class="muted">${fmtDateTime(x.created_at)}</td><td class="right"><button class="btn small primary" data-approve="${x.id}">Approve</button> <button class="btn small danger" data-reject="${x.id}">Refuse</button></td></tr>`)}</tbody></table></div>` : html`<div class="empty">No pending employee applications.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Pending worker cash deposits</h3>${deposits.requests.length ? html`<div class="scroll-x"><table><thead><tr><th>Worker</th><th>Customer</th><th>Account</th><th class="right">Amount</th><th></th></tr></thead><tbody>${deposits.requests.map((x) => html`<tr><td>${x.worker_name}</td><td>${x.customer_name}</td><td>${x.account_name}</td><td class="right">${money(x.amount_cents)}</td><td class="right"><button class="btn small primary" data-deposit-decision="${x.id}" data-decision="approved">Approve</button> <button class="btn small danger" data-deposit-decision="${x.id}" data-decision="rejected">Reject</button></td></tr>`)}</tbody></table></div>` : html`<div class="empty">No pending deposits.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Pending account closures</h3>${closures.requests.length ? html`<div class="scroll-x"><table><thead><tr><th>Customer</th><th>Email</th><th>Balance</th><th>Requested</th><th></th></tr></thead><tbody>${closures.requests.map((x) => html`<tr><td>${x.full_name}</td><td>${x.email}</td><td class="right">${money(x.balance_cents)}</td><td class="muted small">${fmtDateTime(x.requested_at)}</td><td class="right"><button class="btn small primary" data-closure-decision="${x.id}" data-decision="approved">Approve deletion</button> <button class="btn small danger" data-closure-decision="${x.id}" data-decision="rejected">Reject</button></td></tr>`)}</tbody></table></div>` : html`<div class="empty">No pending account closures.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Worker operation trace</h3>${workerActivity.operations.length ? html`<div class="scroll-x"><table><thead><tr><th>Time</th><th>Worker</th><th>Customer</th><th>Account</th><th class="right">Amount</th><th>Status</th></tr></thead><tbody>${workerActivity.operations.map((e) => html`<tr><td class="muted small">${fmtDateTime(e.created_at)}</td><td>${e.worker_name}</td><td>${e.customer_name}</td><td>${e.account_name}</td><td class="right">${money(e.amount_cents)}</td><td><span class="pill">${e.status}</span></td></tr>`)}</tbody></table></div>` : html`<div class="empty">No worker operations.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Audit log</h3><div class="scroll-x"><table><thead><tr><th>Time</th><th>User</th><th>Event</th><th>Detail</th><th>IP</th></tr></thead><tbody>
      ${a.events.map((e) => html`<tr><td class="muted small">${fmtDateTime(e.created_at)}</td><td class="small">${e.email || '—'}</td><td><span class="pill ${/failed|blocked/.test(e.action) ? 'bad' : ''}">${e.action}</span></td><td class="small">${e.detail}</td><td class="small mono">${e.ip}</td></tr>`)}</tbody></table></div></div>`);
  $$('[data-st]').forEach((b) => (b.onclick = async () => { await api('POST', `/api/admin/users/${b.dataset.st}/status`, { status: b.dataset.to }); toast('User updated'); adminPage(); }));
  $$('[data-approve]').forEach((b) => (b.onclick = async () => { await api('POST', `/api/admin/pending-employees/${b.dataset.approve}/approve`); toast('Employee approved'); adminPage(); }));
  $$('[data-reject]').forEach((b) => (b.onclick = async () => { if (!confirm('Refuse this employee account creation?')) return; await api('POST', `/api/admin/pending-employees/${b.dataset.reject}/reject`); toast('Employee application refused'); adminPage(); }));
  $$('[data-closure-decision]').forEach((b) => (b.onclick = async () => {
    if (b.dataset.decision === 'approved' && !confirm('Permanently delete this customer account and its data?')) return;
    await api('POST', `/api/admin/account-closures/${b.dataset.closureDecision}/decision`, { decision: b.dataset.decision });
    toast(b.dataset.decision === 'approved' ? 'Customer account deleted' : 'Account closure rejected');
    adminPage();
  }));
  $$('[data-deposit-decision]').forEach((b) => (b.onclick = async () => { await api('POST', `/api/admin/deposit-requests/${b.dataset.depositDecision}/decision`, { decision: b.dataset.decision }); toast(`Deposit ${b.dataset.decision}`); adminPage(); }));
  await adminExtras();
}
async function employeePage() {
  const [overview, customers, requests] = await Promise.all([api('GET', '/api/employee/overview'), api('GET', '/api/employee/customers'), api('GET', '/api/employee/deposit-requests')]);
  let visibleCustomers = customers.customers;
  const renderCustomers = () => {
    const query = ($('#customer-search')?.value || '').trim().toLowerCase();
    visibleCustomers = customers.customers.filter((x) => `${x.full_name} ${x.email}`.toLowerCase().includes(query));
    const list = $('#customer-list');
    if (list) list.innerHTML = val(visibleCustomers.length
      ? html`${visibleCustomers.map((x) => html`<tr><td>${x.full_name}</td><td class="muted">${x.email}</td><td>${x.type} · ${x.nickname || 'Account'}</td><td class="right">${money(x.balance_cents)}</td></tr>`)}`
      : html`<tr><td colspan="4" class="empty">No customers found.</td></tr>`);
    const customer = $('#deposit-customer');
    if (customer) {
      const customerOptions = visibleCustomers.filter((x, index, rows) =>
        rows.findIndex((candidate) => candidate.customer_id === x.customer_id) === index
      );
      customer.innerHTML = val(visibleCustomers.length
        ? html`${customerOptions.map((x) => html`<option value="${x.customer_id}">${x.full_name} — ${x.email}</option>`)}`
        : html`<option value="">No matching customers</option>`);
      customer.dispatchEvent(new Event('change'));
    }
  };
  shell('/employee', 'Employee workspace', 'Find a customer and submit a cash deposit for admin approval', html`<div class="grid cols-2">
    <div class="card"><h3>Customers</h3><div class="field"><label for="customer-search">Search by name or email</label><input id="customer-search" type="search" placeholder="Search customers"></div><div class="scroll-x"><table><thead><tr><th>Name</th><th>Email</th><th>Account</th><th class="right">Balance</th></tr></thead><tbody id="customer-list"></tbody></table></div></div>
    <div class="card"><h3>Customer cash deposit</h3><form id="cash-deposit">
      <div class="field"><label for="deposit-customer">1. Customer</label><select id="deposit-customer" name="customer_id" required></select></div>
      <div class="field"><label for="deposit-account">2. Account type</label><select id="deposit-account" name="account_id" required></select></div>
      <div class="field"><label for="deposit-amount">3. Amount (€)</label><input id="deposit-amount" name="amount" inputmode="decimal" max="1000" placeholder="250.00" required></div>
      <div class="field"><label for="deposit-note">Reference or note (optional)</label><textarea id="deposit-note" name="note" maxlength="240" rows="3" placeholder="Cash receipt or branch reference"></textarea></div>
      <div class="error" role="alert"></div><button class="btn primary" type="submit">Submit for admin approval</button>
    </form></div>
    <div class="card"><h3>Worker status</h3><p>Customers: <b>${overview.customers}</b></p><p>Employee applications awaiting approval: <b>${overview.verified_employee_requests}</b></p></div>
  </div><div class="card" style="margin-top:1rem"><h3>My deposit requests</h3>${requests.requests.length ? html`<div class="scroll-x"><table><thead><tr><th>Customer</th><th>Account</th><th class="right">Amount</th><th>Status</th><th>Note</th></tr></thead><tbody>${requests.requests.map((x) => html`<tr><td>${x.customer_name}</td><td>${x.account_name}</td><td class="right">${money(x.amount_cents)}</td><td><span class="pill">${x.status}</span></td><td class="small">${x.worker_note || '—'}</td></tr>`)}</tbody></table></div>` : html`<div class="empty">No deposit requests.</div>`}</div>`);
  $('#customer-search').addEventListener('input', renderCustomers);
  $('#deposit-customer').addEventListener('change', () => {
    const customerId = Number($('#deposit-customer').value);
    const accounts = visibleCustomers.filter((x) => x.customer_id === customerId);
    $('#deposit-account').innerHTML = val(html`${accounts.map((x) => html`<option value="${x.account_id}">${x.type} — ${x.nickname || 'Account'} (${money(x.balance_cents)})</option>`)}`);
  });
  renderCustomers();
  formSubmit($('#cash-deposit'), async (d) => { await api('POST', '/api/deposit', d); toast('Deposit submitted for admin approval'); employeePage(); });
}

/* ---------- budgets ---------- */
const BUDGET_CATS = ['housing', 'groceries', 'dining', 'transport', 'utilities', 'entertainment', 'health', 'shopping', 'other'];
async function budgetsPage() {
  const { budgets } = await api('GET', '/api/budgets');
  shell('/budgets', 'Budgets', 'Monthly spending limits by category',
    html`${budgets.length ? html`<div class="grid cols-2">${budgets.map((b) => {
      const pct = Math.min(100, Math.round((b.spent_cents / b.limit_cents) * 100));
      const over = b.spent_cents > b.limit_cents;
      return html`<div class="card"><div class="row" style="justify-content:space-between"><h3>${cat(b.category)[0]} ${cat(b.category)[1]}</h3>
        <span class="pill ${over ? 'bad' : pct >= 80 ? '' : 'ok'}">${over ? 'Over budget' : pct + '%'}</span></div>
        <div style="height:10px;border-radius:99px;background:var(--line);margin:.8rem 0;overflow:hidden"><div style="height:100%;width:${pct}%;background:${over ? 'var(--danger)' : 'var(--ok)'}"></div></div>
        <div class="muted small">${money(b.spent_cents)} of ${money(b.limit_cents)} this month${over ? '' : ' · ' + money(b.limit_cents - b.spent_cents) + ' left'}</div>
        <div class="toolbar"><button class="btn small" data-bedit="${b.category}">Change</button><button class="btn small danger" data-bdel="${b.id}">Remove</button></div></div>`;
    })}</div>` : html`<div class="card"><div class="empty">No budgets yet. Set a monthly limit to track your spending.</div></div>`}`,
    html`<button class="btn primary" id="addb">+ Set budget</button>`);
  const edit = (category = '') => modal(html`<h3>Set a monthly budget</h3><form id="mf"><div class="field"><label>Category</label><select name="category">${BUDGET_CATS.map((c) => html`<option value="${c}" ${c === category ? raw('selected') : ''}>${cat(c)[1]}</option>`)}</select></div>
    <div class="field"><label>Monthly limit (EUR)</label><input name="limit" inputmode="decimal" placeholder="250.00" required></div><div class="error" role="alert"></div>
    <div class="toolbar"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit">Save</button></div></form>`,
  (m, close) => formSubmit($('#mf', m), async (d) => { await api('PUT', '/api/budgets', d); close(); toast('Budget saved'); budgetsPage(); }));
  $('#addb').onclick = () => edit();
  $$('[data-bedit]').forEach((b) => (b.onclick = () => edit(b.dataset.bedit)));
  $$('[data-bdel]').forEach((b) => (b.onclick = async () => { await api('DELETE', '/api/budgets/' + b.dataset.bdel); toast('Budget removed'); budgetsPage(); }));
}

/* ---------- profile: recent security activity ---------- */
async function securityActivity() {
  const { events } = await api('GET', '/api/profile/activity');
  const main = $('.main');
  if (!main) return;
  main.insertAdjacentHTML('beforeend', val(html`<div class="card" style="margin-top:1rem"><h3>Recent security activity</h3>${events.length ? html`<div class="scroll-x"><table><thead><tr><th>Time</th><th>Event</th><th>IP</th></tr></thead><tbody>
    ${events.map((e) => html`<tr><td class="muted small">${fmtDateTime(e.created_at)}</td><td><span class="pill ${/failed/.test(e.action) ? 'bad' : ''}">${e.action.replace(/_/g, ' ')}</span></td><td class="small mono">${e.ip}</td></tr>`)}</tbody></table></div>` : html`<div class="empty">No recent activity.</div>`}</div>`));
}

/* ---------- admin: monitoring, card cases, audit search ---------- */
async function adminExtras() {
  const [m, rep, req] = await Promise.all([api('GET', '/api/admin/monitor'), api('GET', '/api/admin/card-reports'), api('GET', '/api/admin/card-requests')]);
  const c = m.counts;
  const kpi = (l, v) => html`<div class="card"><div class="muted">${l}</div><div class="balance">${v}</div></div>`;
  $('.main').insertAdjacentHTML('beforeend', val(html`
    <h3 style="margin-top:1.6rem">Monitoring</h3>
    <div class="grid cols-3">${kpi('DB latency', m.db_latency_ms + ' ms')}${kpi('Volume out (24h)', money(c.volume_24h_cents))}${kpi('New users (7d)', c.new_users_7d)}
      ${kpi('Locked users', c.locked_users)}${kpi('Frozen / blocked cards', c.frozen_cards)}${kpi('Open card cases', c.open_card_reports + c.open_card_requests)}</div>
    <div class="card" style="margin-top:1rem"><h3>Large transactions (≥ ${money(m.large_threshold_cents)}, 7d)</h3>${m.large_transactions.length ? html`<div class="scroll-x"><table><thead><tr><th>Time</th><th>User</th><th>Counterparty</th><th>Ref</th><th class="right">Amount</th></tr></thead><tbody>
      ${m.large_transactions.map((t) => html`<tr><td class="muted small">${fmtDateTime(t.created_at)}</td><td class="small">${t.email}</td><td>${t.counterparty}</td><td class="mono small">${t.reference}</td><td class="right">${t.kind === 'debit' ? '−' : '+'}${money(t.amount_cents)}</td></tr>`)}</tbody></table></div>` : html`<div class="empty">None.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Suspicious IPs (3+ failed logins, 24h)</h3>${m.suspicious_ips.length ? html`<div class="scroll-x"><table><thead><tr><th>IP</th><th class="right">Failures</th><th class="right">Accounts</th></tr></thead><tbody>
      ${m.suspicious_ips.map((x) => html`<tr><td class="mono small">${x.ip || '—'}</td><td class="right">${x.failures}</td><td class="right">${x.accounts}</td></tr>`)}</tbody></table></div>` : html`<div class="empty">None.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Unauthorized transaction reports</h3>${rep.reports.length ? html`<div class="scroll-x"><table><thead><tr><th>Customer</th><th>Card</th><th>Merchant</th><th class="right">Amount</th><th>Status</th><th></th></tr></thead><tbody>
      ${rep.reports.map((r) => html`<tr><td class="small">${r.email}</td><td class="mono">•••• ${r.last4}</td><td>${r.merchant}</td><td class="right">${money(r.amount_cents)}</td><td><span class="pill">${r.status.replace('_', ' ')}</span></td>
        <td class="right">${['submitted', 'under_review'].includes(r.status) ? html`<button class="btn small" data-rep="${r.id}" data-to="under_review">Review</button> <button class="btn small primary" data-rep="${r.id}" data-to="resolved">Resolve</button> <button class="btn small danger" data-rep="${r.id}" data-to="rejected">Reject</button>` : ''}</td></tr>`)}</tbody></table></div>` : html`<div class="empty">No reports.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Card requests</h3>${req.requests.length ? html`<div class="scroll-x"><table><thead><tr><th>Customer</th><th>Type</th><th>Reason</th><th>Status</th><th></th></tr></thead><tbody>
      ${req.requests.map((r) => html`<tr><td class="small">${r.email}</td><td>${r.request_type.replace('_', ' ')}</td><td class="small">${r.reason}</td><td><span class="pill">${r.status}</span></td>
        <td class="right">${r.status === 'submitted' ? html`<button class="btn small primary" data-creq="${r.id}" data-to="approved">Approve</button> <button class="btn small danger" data-creq="${r.id}" data-to="rejected">Reject</button>` : r.status === 'approved' ? html`<button class="btn small" data-creq="${r.id}" data-to="completed">Mark completed</button>` : ''}</td></tr>`)}</tbody></table></div>` : html`<div class="empty">No requests.</div>`}</div>
    <div class="card" style="margin-top:1rem"><h3>Audit search</h3><form id="af" class="toolbar"><input name="q" placeholder="Email, detail or IP" maxlength="50"><input name="action" placeholder="Exact event, e.g. login_failed" maxlength="40">
      <button class="btn dark" type="submit">Search</button><button class="btn" type="button" id="aexp">Export CSV</button></form><div id="ares" class="scroll-x"></div></div>
    <div class="card" style="margin-top:1rem"><h3>Active customers</h3><form id="acf" class="toolbar">
      <input name="q" placeholder="Search by name or email" maxlength="80"><select name="period"><option value="daily">Daily active customers</option><option value="monthly">Monthly active customers</option></select>
      <button class="btn dark" type="submit">Search</button></form><div id="ac-count" class="muted small"></div><div id="ac-res" class="scroll-x"></div></div>`));
  $$('[data-rep]').forEach((b) => (b.onclick = async () => { await api('POST', `/api/admin/card-reports/${b.dataset.rep}/status`, { status: b.dataset.to }); toast('Report updated'); adminPage(); }));
  $$('[data-creq]').forEach((b) => (b.onclick = async () => { await api('POST', `/api/admin/card-requests/${b.dataset.creq}/status`, { status: b.dataset.to }); toast('Request updated'); adminPage(); }));
  const qs = () => new URLSearchParams(Object.fromEntries([...new FormData($('#af'))].filter(([, v]) => v))).toString();
  $('#af').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const { events } = await api('GET', '/api/admin/audit/search?' + qs());
      $('#ares').innerHTML = val(events.length ? html`<table><thead><tr><th>Time</th><th>User</th><th>Event</th><th>Detail</th><th>IP</th></tr></thead><tbody>${events.map((x) => html`<tr><td class="muted small">${fmtDateTime(x.created_at)}</td><td class="small">${x.email || '—'}</td><td><span class="pill ${/failed|blocked/.test(x.action) ? 'bad' : ''}">${x.action}</span></td><td class="small">${x.detail}</td><td class="small mono">${x.ip}</td></tr>`)}</tbody></table>` : html`<div class="empty">No matching events.</div>`);
    } catch (ex) { if (ex.message !== 'session') toast(ex.message, true); }
  });
  $('#aexp').onclick = async () => {
    try {
      const r = await fetch('/api/admin/audit/export?' + qs(), { credentials: 'same-origin' });
      if (!r.ok) throw new Error('Export failed');
      download('audit-log.csv', await r.text());
    } catch (ex) { toast(ex.message, true); }
  };
  const searchActiveCustomers = async () => {
    const params = new URLSearchParams(Object.fromEntries([...new FormData($('#acf'))].filter(([, v]) => v)));
    const result = await api('GET', '/api/admin/active-customers?' + params);
    $('#ac-count').textContent = `${result.count} ${result.period === 'daily' ? 'daily' : 'monthly'} active customer${result.count === 1 ? '' : 's'}`;
    $('#ac-res').innerHTML = val(result.active_customers.length
      ? html`<table><thead><tr><th>Name</th><th>Email</th><th>Last active</th></tr></thead><tbody>${result.active_customers.map((x) => html`<tr><td>${x.full_name}</td><td class="muted">${x.email}</td><td class="muted small">${fmtDateTime(x.last_active_at)}</td></tr>`)}</tbody></table>`
      : html`<div class="empty">No active customers found.</div>`);
  };
  $('#acf').addEventListener('submit', async (e) => {
    e.preventDefault();
    try { await searchActiveCustomers(); } catch (ex) { if (ex.message !== 'session') toast(ex.message, true); }
  });
  await searchActiveCustomers();
}

/* ---------- router ---------- */
const routes = { '/': landing, '/login': loginPage, '/register': registerPage, '/dashboard': dashboard, '/employee': employeePage, '/accounts': accountsPage,
  '/transactions': txPage, '/transfer': transferPage, '/cards': cardsPage, '/profile': profilePage, '/admin': adminPage, '/budgets': budgetsPage };
const publicPaths = new Set(['/','/login','/register']);
async function route() {
  const path = location.hash.slice(1) || '/';
  if (!routes[path]) return go('/');
  if (!publicPaths.has(path) && !state.user) return go('/login');
  if (['/login', '/register'].includes(path) && state.user) return go('/dashboard');
  if (state.user) {
    if (['/dashboard', '/budgets'].includes(path) && state.user.role === 'employee') return go('/employee');
    if (path === '/employee' && state.user.role !== 'employee') return go(state.user.role === 'admin' ? '/admin' : '/dashboard');
    if (state.user.role === 'admin' && ['/dashboard', '/accounts', '/transactions', '/transfer', '/cards', '/budgets'].includes(path)) return go('/admin');
    if (path === '/admin' && state.user.role !== 'admin') return go('/dashboard');
  }
  if (!publicPaths.has(path)) root.innerHTML = '<div class="spinner">Loading…</div>';
  window.scrollTo(0, 0);
  try { await routes[path](); } catch (e) { if (e.message !== 'session') { toast(e.message, true); } }
}
window.addEventListener('hashchange', route);
loadMe().then(route);
})();
