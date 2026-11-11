const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { db, audit, createAccount, createCard, newRef } = require('./db');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
app.disable('x-powered-by');
if (isProd) app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'"],
      'style-src': ["'self'"],
      'style-src-attr': ["'unsafe-inline'"], // inline style attributes only; no inline <style> or scripts
      'img-src': ["'self'", 'data:'],
      'object-src': ["'none'"],
      'frame-ancestors': ["'none'"],
      'form-action': ["'self'"],
      'upgrade-insecure-requests': isProd ? [] : null,
    },
  },
}));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'wb.sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, sameSite: 'strict', secure: isProd, maxAge: 15 * 60 * 1000 },
  rolling: true, // idle timeout: 15 minutes
}));

// ---------- helpers ----------
const ip = (req) => req.ip || '';
const euros = (c) => (c / 100).toFixed(2);
const wrap = (fn) => (req, res, next) => { try { fn(req, res, next); } catch (e) { next(e); } };
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

function parseAmount(v) {
  const s = String(v ?? '').trim().replace(',', '.');
  if (!/^\d{1,7}(\.\d{1,2})?$/.test(s)) return null;
  const cents = Math.round(parseFloat(s) * 100);
  return cents > 0 ? cents : null;
}
function strongPassword(p) {
  return typeof p === 'string' && p.length >= 10 && p.length <= 128 &&
    /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
}
const emailOk = (e) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);

// CSRF: token bound to session, required on every state-changing request
app.use((req, res, next) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = req.get('x-csrf-token') || '';
  const a = Buffer.from(sent), b = Buffer.from(req.session.csrf);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return bad(res, 'Invalid CSRF token', 403);
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
app.use('/api', apiLimiter);

function requireAuth(req, res, next) {
  if (!req.session.userId) return bad(res, 'Authentication required', 401);
  const u = db.prepare('SELECT id, role, status FROM users WHERE id = ?').get(req.session.userId);
  if (!u || u.status !== 'active') { req.session.destroy(() => {}); return bad(res, 'Authentication required', 401); }
  req.user = u;
  next();
}
const requireAdmin = (req, res, next) => (req.user.role === 'admin' ? next() : bad(res, 'Forbidden', 403));

const publicUser = (u) => ({ id: u.id, full_name: u.full_name, email: u.email, phone: u.phone, role: u.role, created_at: u.created_at });
const ownAccount = (userId, id) => db.prepare('SELECT * FROM accounts WHERE id = ? AND user_id = ?').get(id, userId);

// ---------- auth ----------
app.get('/api/csrf', (req, res) => res.json({ token: req.session.csrf }));

app.get('/api/me', wrap((req, res) => {
  if (!req.session.userId) return res.json({ user: null, csrf: req.session.csrf });
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user: u ? publicUser(u) : null, csrf: req.session.csrf });
}));

app.post('/api/auth/register', authLimiter, wrap((req, res) => {
  const full_name = clean(req.body.full_name, 80);
  const email = clean(req.body.email, 254).toLowerCase();
  const password = req.body.password;
  if (full_name.length < 2) return bad(res, 'Please enter your full name.');
  if (!emailOk(email)) return bad(res, 'Please enter a valid email address.');
  if (!strongPassword(password)) return bad(res, 'Password needs 10+ characters with upper, lower, a digit and a symbol.');
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return bad(res, 'An account with this email already exists.', 409);
  const hash = bcrypt.hashSync(password, 12);
  const tx = db.transaction(() => {
    const info = db.prepare('INSERT INTO users (full_name,email,password_hash) VALUES (?,?,?)').run(full_name, email, hash);
    const accId = createAccount(info.lastInsertRowid, 'checking', 'Main account', 0);
    createCard(accId);
    audit(info.lastInsertRowid, 'register', email, ip(req));
    return info.lastInsertRowid;
  });
  const userId = tx();
  req.session.regenerate((err) => {
    if (err) return bad(res, 'Session error', 500);
    req.session.userId = userId;
    req.session.csrf = crypto.randomBytes(24).toString('hex');
    res.status(201).json({ ok: true, csrf: req.session.csrf });
  });
}));

const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 12);
app.post('/api/auth/login', authLimiter, wrap((req, res) => {
  const email = clean(req.body.email, 254).toLowerCase();
  const password = String(req.body.password ?? '');
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  const now = Date.now();
  if (u && u.locked_until > now) {
    audit(u.id, 'login_blocked', 'account temporarily locked', ip(req));
    return bad(res, 'Account temporarily locked. Try again in a few minutes.', 423);
  }
  const ok = bcrypt.compareSync(password, u ? u.password_hash : DUMMY_HASH) && u && u.status === 'active';
  if (!ok) {
    if (u) {
      const fails = u.failed_logins + 1;
      const lock = fails >= 5 ? now + 15 * 60 * 1000 : 0;
      db.prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?').run(lock ? 0 : fails, lock, u.id);
      audit(u.id, 'login_failed', `attempt ${fails}`, ip(req));
    }
    return bad(res, 'Invalid email or password.', 401);
  }
  db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(u.id);
  audit(u.id, 'login', '', ip(req));
  req.session.regenerate((err) => {
    if (err) return bad(res, 'Session error', 500);
    req.session.userId = u.id;
    req.session.csrf = crypto.randomBytes(24).toString('hex');
    res.json({ ok: true, csrf: req.session.csrf, user: publicUser(u) });
  });
}));

app.post('/api/auth/logout', wrap((req, res) => {
  const uid = req.session.userId;
  req.session.destroy(() => {
    if (uid) audit(uid, 'logout', '', ip(req));
    res.clearCookie('wb.sid');
    res.json({ ok: true });
  });
}));

// ---------- everything below needs a session ----------
app.use('/api', (req, res, next) => (req.path.startsWith('/auth/') || req.path === '/csrf' || req.path === '/me' ? next() : requireAuth(req, res, next)));

// ---------- profile ----------
app.patch('/api/profile', wrap((req, res) => {
  const full_name = clean(req.body.full_name, 80);
  const phone = clean(req.body.phone, 30);
  if (full_name.length < 2) return bad(res, 'Please enter your full name.');
  db.prepare('UPDATE users SET full_name = ?, phone = ? WHERE id = ?').run(full_name, phone, req.user.id);
  audit(req.user.id, 'profile_update', '', ip(req));
  res.json({ ok: true });
}));

app.post('/api/profile/password', wrap((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(String(req.body.current ?? ''), u.password_hash)) return bad(res, 'Current password is incorrect.', 403);
  if (!strongPassword(req.body.next)) return bad(res, 'Password needs 10+ characters with upper, lower, a digit and a symbol.');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(req.body.next, 12), u.id);
  audit(u.id, 'password_change', '', ip(req));
  res.json({ ok: true });
}));

// ---------- accounts ----------
app.get('/api/accounts', wrap((req, res) => {
  const rows = db.prepare('SELECT id, iban, type, nickname, balance_cents, currency, created_at FROM accounts WHERE user_id = ? ORDER BY id').all(req.user.id);
  res.json({ accounts: rows });
}));

app.post('/api/accounts', wrap((req, res) => {
  const type = req.body.type === 'savings' ? 'savings' : 'checking';
  const count = db.prepare('SELECT COUNT(*) c FROM accounts WHERE user_id = ?').get(req.user.id).c;
  if (count >= 5) return bad(res, 'Account limit reached (5).');
  const id = createAccount(req.user.id, type, clean(req.body.nickname, 40));
  audit(req.user.id, 'account_open', `${type} #${id}`, ip(req));
  res.status(201).json({ id });
}));

app.patch('/api/accounts/:id', wrap((req, res) => {
  const acc = ownAccount(req.user.id, Number(req.params.id));
  if (!acc) return bad(res, 'Account not found.', 404);
  db.prepare('UPDATE accounts SET nickname = ? WHERE id = ?').run(clean(req.body.nickname, 40), acc.id);
  res.json({ ok: true });
}));

// ---------- transactions ----------
app.get('/api/transactions', wrap((req, res) => {
  const where = ['a.user_id = ?'];
  const args = [req.user.id];
  if (req.query.account_id) { where.push('t.account_id = ?'); args.push(Number(req.query.account_id) || 0); }
  if (['credit', 'debit'].includes(req.query.kind)) { where.push('t.kind = ?'); args.push(req.query.kind); }
  if (req.query.category) { where.push('t.category = ?'); args.push(clean(req.query.category, 30)); }
  if (req.query.q) {
    const q = '%' + clean(req.query.q, 50).replace(/[%_\\]/g, (m) => '\\' + m) + '%';
    where.push("(t.counterparty LIKE ? ESCAPE '\\' OR t.description LIKE ? ESCAPE '\\' OR t.reference LIKE ? ESCAPE '\\')");
    args.push(q, q, q);
  }
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 25, 1), 100);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const base = `FROM transactions t JOIN accounts a ON a.id = t.account_id WHERE ${where.join(' AND ')}`;
  const total = db.prepare(`SELECT COUNT(*) c ${base}`).get(...args).c;
  const rows = db.prepare(`SELECT t.id, t.account_id, a.nickname AS account_name, t.kind, t.amount_cents, t.balance_after_cents,
      t.counterparty, t.description, t.category, t.reference, t.created_at ${base}
      ORDER BY t.created_at DESC, t.id DESC LIMIT ? OFFSET ?`).all(...args, limit, offset);
  res.json({ total, transactions: rows });
}));

// ---------- transfers ----------
const DAILY_LIMIT_CENTS = 500000;
app.post('/api/transfers', wrap((req, res) => {
  const from = ownAccount(req.user.id, Number(req.body.from_account_id));
  if (!from) return bad(res, 'Source account not found.', 404);
  const amount = parseAmount(req.body.amount);
  if (!amount) return bad(res, 'Enter a valid amount (max 2 decimals).');
  const toIban = clean(req.body.to_iban, 34).replace(/\s+/g, '').toUpperCase();
  const toName = clean(req.body.to_name, 80);
  const note = clean(req.body.description, 100);
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(toIban)) return bad(res, 'Enter a valid IBAN.');
  if (toIban === from.iban) return bad(res, 'Source and destination must differ.');
  if (toName.length < 2) return bad(res, 'Enter the recipient name.');

  const result = db.transaction(() => {
    const src = db.prepare('SELECT * FROM accounts WHERE id = ?').get(from.id);
    if (src.balance_cents < amount) return { err: 'Insufficient funds.' };
    const dest = db.prepare('SELECT * FROM accounts WHERE iban = ?').get(toIban);
    if (src.type === 'savings' && !(dest && dest.user_id === req.user.id)) return { err: 'Savings accounts can only move money to your own accounts.' };
    const spent = db.prepare(`SELECT COALESCE(SUM(t.amount_cents),0) s FROM transactions t JOIN accounts a ON a.id = t.account_id
      WHERE a.user_id = ? AND t.kind = 'debit' AND t.category = 'transfer' AND t.created_at >= datetime('now','-1 day')`).get(req.user.id).s;
    if (spent + amount > DAILY_LIMIT_CENTS) return { err: `Daily transfer limit of €${euros(DAILY_LIMIT_CENTS)} exceeded.` };

    const ref = newRef();
    const newBal = src.balance_cents - amount;
    db.prepare('UPDATE accounts SET balance_cents = ? WHERE id = ?').run(newBal, src.id);
    const ownDest = dest && dest.user_id === req.user.id;
    db.prepare(`INSERT INTO transactions (account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
      VALUES (?,?,?,?,?,?,?,?)`).run(src.id, 'debit', amount, newBal, toName, note || 'Transfer', ownDest ? 'savings' : 'transfer', ref);
    if (dest) {
      const destBal = dest.balance_cents + amount;
      db.prepare('UPDATE accounts SET balance_cents = ? WHERE id = ?').run(destBal, dest.id);
      const sender = db.prepare('SELECT full_name FROM users WHERE id = ?').get(req.user.id).full_name;
      db.prepare(`INSERT INTO transactions (account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
        VALUES (?,?,?,?,?,?,?,?)`).run(dest.id, 'credit', amount, destBal, sender, note || 'Transfer received', ownDest ? 'savings' : 'income', ref);
    }
    if (req.body.save_beneficiary && !ownDest) {
      db.prepare('INSERT OR IGNORE INTO beneficiaries (user_id,name,iban) VALUES (?,?,?)').run(req.user.id, toName, toIban);
    }
    audit(req.user.id, 'transfer', `${ref} €${euros(amount)} -> ${toIban}`, ip(req));
    return { ok: true, reference: ref, internal: !!dest, balance_cents: newBal };
  })();
  if (result.err) return bad(res, result.err);
  res.status(201).json(result);
}));

// Demo-only top-up so testers can get money without a real payment rail
app.post('/api/deposit', wrap((req, res) => {
  const acc = ownAccount(req.user.id, Number(req.body.account_id));
  const amount = parseAmount(req.body.amount);
  if (!acc) return bad(res, 'Account not found.', 404);
  if (!amount || amount > 100000) return bad(res, 'Enter an amount up to €1000.');
  db.transaction(() => {
    const bal = acc.balance_cents + amount;
    db.prepare('UPDATE accounts SET balance_cents = ? WHERE id = ?').run(bal, acc.id);
    db.prepare(`INSERT INTO transactions (account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
      VALUES (?,?,?,?,?,?,?,?)`).run(acc.id, 'credit', amount, bal, 'WeBank Demo Top-up', 'Demo deposit', 'income', newRef());
  })();
  audit(req.user.id, 'deposit', `€${euros(amount)}`, ip(req));
  res.status(201).json({ ok: true });
}));

// ---------- beneficiaries ----------
app.get('/api/beneficiaries', wrap((req, res) => {
  res.json({ beneficiaries: db.prepare('SELECT id, name, iban FROM beneficiaries WHERE user_id = ? ORDER BY name').all(req.user.id) });
}));
app.post('/api/beneficiaries', wrap((req, res) => {
  const name = clean(req.body.name, 80);
  const iban = clean(req.body.iban, 34).replace(/\s+/g, '').toUpperCase();
  if (name.length < 2) return bad(res, 'Enter a name.');
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(iban)) return bad(res, 'Enter a valid IBAN.');
  try { db.prepare('INSERT INTO beneficiaries (user_id,name,iban) VALUES (?,?,?)').run(req.user.id, name, iban); }
  catch { return bad(res, 'This beneficiary already exists.', 409); }
  res.status(201).json({ ok: true });
}));
app.delete('/api/beneficiaries/:id', wrap((req, res) => {
  db.prepare('DELETE FROM beneficiaries WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.user.id);
  res.json({ ok: true });
}));

// ---------- cards ----------
app.get('/api/cards', wrap((req, res) => {
  const rows = db.prepare(`SELECT c.id, c.last4, c.brand, c.expires, c.status, c.monthly_limit_cents, a.nickname AS account_name, a.iban
    FROM cards c JOIN accounts a ON a.id = c.account_id WHERE a.user_id = ?`).all(req.user.id);
  res.json({ cards: rows });
}));
app.post('/api/cards/:id/toggle', wrap((req, res) => {
  const c = db.prepare('SELECT c.* FROM cards c JOIN accounts a ON a.id = c.account_id WHERE c.id = ? AND a.user_id = ?').get(Number(req.params.id), req.user.id);
  if (!c) return bad(res, 'Card not found.', 404);
  const status = c.status === 'active' ? 'frozen' : 'active';
  db.prepare('UPDATE cards SET status = ? WHERE id = ?').run(status, c.id);
  audit(req.user.id, 'card_' + status, `card ****${c.last4}`, ip(req));
  res.json({ status });
}));
app.patch('/api/cards/:id/limit', wrap((req, res) => {
  const limit = parseAmount(req.body.limit);
  if (!limit || limit > 1000000) return bad(res, 'Enter a limit up to €10,000.');
  const r = db.prepare('UPDATE cards SET monthly_limit_cents = ? WHERE id = ? AND account_id IN (SELECT id FROM accounts WHERE user_id = ?)')
    .run(limit, Number(req.params.id), req.user.id);
  if (!r.changes) return bad(res, 'Card not found.', 404);
  res.json({ ok: true });
}));

// ---------- insights ----------
app.get('/api/insights', wrap((req, res) => {
  const uid = req.user.id;
  const byCategory = db.prepare(`SELECT t.category, SUM(t.amount_cents) total FROM transactions t JOIN accounts a ON a.id = t.account_id
    WHERE a.user_id = ? AND t.kind = 'debit' AND t.category NOT IN ('savings') AND t.created_at >= datetime('now','-30 days')
    GROUP BY t.category ORDER BY total DESC`).all(uid);
  const monthly = db.prepare(`SELECT strftime('%Y-%m', t.created_at) month,
      SUM(CASE WHEN t.kind='credit' AND t.category <> 'savings' THEN t.amount_cents ELSE 0 END) income,
      SUM(CASE WHEN t.kind='debit' AND t.category <> 'savings' THEN t.amount_cents ELSE 0 END) spending
    FROM transactions t JOIN accounts a ON a.id = t.account_id WHERE a.user_id = ? GROUP BY month ORDER BY month DESC LIMIT 6`).all(uid).reverse();
  const total = db.prepare('SELECT COALESCE(SUM(balance_cents),0) s FROM accounts WHERE user_id = ?').get(uid).s;
  // balance history of all accounts, reconstructed by walking back from today's balance
  const flows = db.prepare(`SELECT date(t.created_at) d, SUM(CASE WHEN t.kind='credit' THEN t.amount_cents ELSE -t.amount_cents END) net
    FROM transactions t JOIN accounts a ON a.id = t.account_id WHERE a.user_id = ? AND t.created_at >= datetime('now','-30 days')
    GROUP BY d`).all(uid);
  const netByDay = Object.fromEntries(flows.map((f) => [f.d, f.net]));
  const series = [];
  let running = total;
  for (let i = 0; i < 30; i++) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    series.push({ date: d, balance_cents: running });
    running -= netByDay[d] || 0;
  }
  res.json({ byCategory, monthly, total_cents: total, balanceSeries: series.reverse() });
}));

// ---------- admin ----------
const admin = express.Router();
admin.use(requireAdmin);
admin.get('/stats', wrap((req, res) => {
  const one = (sql) => db.prepare(sql).get();
  res.json({
    customers: one("SELECT COUNT(*) c FROM users WHERE role='customer'").c,
    accounts: one('SELECT COUNT(*) c FROM accounts').c,
    deposits_cents: one('SELECT COALESCE(SUM(balance_cents),0) s FROM accounts').s,
    transactions_24h: one("SELECT COUNT(*) c FROM transactions WHERE created_at >= datetime('now','-1 day')").c,
    failed_logins_24h: one("SELECT COUNT(*) c FROM audit_log WHERE action IN ('login_failed','login_blocked') AND created_at >= datetime('now','-1 day')").c,
  });
}));
admin.get('/users', wrap((req, res) => {
  res.json({ users: db.prepare(`SELECT u.id, u.full_name, u.email, u.role, u.status, u.created_at,
    COALESCE((SELECT SUM(balance_cents) FROM accounts WHERE user_id = u.id),0) balance_cents FROM users u ORDER BY u.id`).all() });
}));
admin.post('/users/:id/status', wrap((req, res) => {
  const id = Number(req.params.id);
  const status = req.body.status === 'locked' ? 'locked' : 'active';
  if (id === req.user.id) return bad(res, 'You cannot change your own status.');
  db.prepare('UPDATE users SET status = ?, failed_logins = 0, locked_until = 0 WHERE id = ?').run(status, id);
  audit(req.user.id, 'admin_status', `user ${id} -> ${status}`, ip(req));
  res.json({ ok: true });
}));
admin.get('/audit', wrap((req, res) => {
  res.json({ events: db.prepare(`SELECT l.id, l.action, l.detail, l.ip, l.created_at, u.email FROM audit_log l
    LEFT JOIN users u ON u.id = l.user_id ORDER BY l.id DESC LIMIT 100`).all() });
}));
app.use('/api/admin', admin);

app.use('/api', (req, res) => bad(res, 'Not found', 404));

// ---------- static frontend ----------
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: 0 }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our side.' });
});

module.exports = app;
