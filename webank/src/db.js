const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const dbFile = process.env.DB_FILE || path.join(__dirname, '..', 'webank.db');
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','locked')),
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  iban TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK (type IN ('checking','savings')),
  nickname TEXT DEFAULT '',
  balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
  currency TEXT NOT NULL DEFAULT 'EUR',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('credit','debit')),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  balance_after_cents INTEGER NOT NULL,
  counterparty TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'other',
  reference TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions(account_id, created_at DESC);
CREATE TABLE IF NOT EXISTS beneficiaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  iban TEXT NOT NULL,
  UNIQUE(user_id, iban)
);
CREATE TABLE IF NOT EXISTS cards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  last4 TEXT NOT NULL,
  brand TEXT NOT NULL DEFAULT 'WeBank Debit',
  expires TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','frozen')),
  monthly_limit_cents INTEGER NOT NULL DEFAULT 200000
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

function randDigits(n) {
  let s = '';
  while (s.length < n) s += crypto.randomInt(0, 10);
  return s;
}
function newIban() {
  for (;;) {
    const iban = `WB${randDigits(2)}${randDigits(4)}${randDigits(12)}`;
    if (!db.prepare('SELECT 1 FROM accounts WHERE iban = ?').get(iban)) return iban;
  }
}
function newRef() {
  return 'WB-' + crypto.randomBytes(5).toString('hex').toUpperCase();
}
function audit(userId, action, detail = '', ip = '') {
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?,?,?,?)')
    .run(userId || null, action, detail, ip);
}

function createAccount(userId, type, nickname = '', openingCents = 0) {
  const iban = newIban();
  const info = db.prepare(
    'INSERT INTO accounts (user_id, iban, type, nickname, balance_cents) VALUES (?,?,?,?,?)'
  ).run(userId, iban, type, nickname || (type === 'checking' ? 'Main account' : 'Savings'), openingCents);
  if (openingCents > 0) {
    db.prepare(`INSERT INTO transactions
      (account_id, kind, amount_cents, balance_after_cents, counterparty, description, category, reference)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(info.lastInsertRowid, 'credit', openingCents, openingCents, 'WeBank', 'Welcome bonus', 'income', newRef());
  }
  return info.lastInsertRowid;
}

function createCard(accountId) {
  const exp = new Date();
  exp.setFullYear(exp.getFullYear() + 4);
  const mm = String(exp.getMonth() + 1).padStart(2, '0');
  db.prepare('INSERT INTO cards (account_id, last4, expires) VALUES (?,?,?)')
    .run(accountId, randDigits(4), `${mm}/${String(exp.getFullYear()).slice(2)}`);
}

function seed() {
  if (db.prepare('SELECT COUNT(*) c FROM users').get().c > 0) return;
  const adminPw = process.env.ADMIN_PASSWORD || 'Admin#WeBank2026';
  const demoPw = 'Demo#WeBank2026';
  const admin = db.prepare('INSERT INTO users (full_name,email,password_hash,role) VALUES (?,?,?,?)')
    .run('WeBank Admin', 'admin@webank.demo', bcrypt.hashSync(adminPw, 12), 'admin');
  const demo = db.prepare('INSERT INTO users (full_name,email,phone,password_hash) VALUES (?,?,?,?)')
    .run('Sara Demo', 'demo@webank.demo', '+39 000 000 0000', bcrypt.hashSync(demoPw, 12));
  const uid = demo.lastInsertRowid;
  const chk = createAccount(uid, 'checking', 'Main account', 0);
  const sav = createAccount(uid, 'savings', 'Rainy day fund', 0);
  createCard(chk);

  // Backfill 90 days of realistic history (oldest first so running balance is consistent)
  const items = [
    ['credit', 320000, 'Acme Corp', 'Salary', 'income', 62],
    ['debit', 85000, 'Landlord', 'Rent', 'housing', 60],
    ['debit', 5420, 'Coop Supermarket', 'Groceries', 'groceries', 58],
    ['debit', 1299, 'StreamFlix', 'Subscription', 'entertainment', 55],
    ['debit', 3800, 'Trenitalia', 'Train ticket', 'transport', 51],
    ['debit', 6790, 'Pizzeria Roma', 'Dinner', 'dining', 47],
    ['debit', 4410, 'Coop Supermarket', 'Groceries', 'groceries', 44],
    ['debit', 9200, 'Energy Co', 'Electricity bill', 'utilities', 40],
    ['credit', 320000, 'Acme Corp', 'Salary', 'income', 32],
    ['debit', 85000, 'Landlord', 'Rent', 'housing', 30],
    ['debit', 2250, 'Cafe Centrale', 'Coffee & brunch', 'dining', 27],
    ['debit', 7340, 'Coop Supermarket', 'Groceries', 'groceries', 23],
    ['debit', 1299, 'StreamFlix', 'Subscription', 'entertainment', 25],
    ['debit', 12000, 'FitClub', 'Gym membership', 'health', 21],
    ['debit', 4600, 'Shell', 'Fuel', 'transport', 17],
    ['debit', 8900, 'Zara', 'Clothing', 'shopping', 12],
    ['credit', 320000, 'Acme Corp', 'Salary', 'income', 2],
    ['debit', 85000, 'Landlord', 'Rent', 'housing', 0],
    ['debit', 3150, 'Coop Supermarket', 'Groceries', 'groceries', 1],
  ];
  items.sort((a, b) => b[5] - a[5]);
  let bal = 0;
  const ins = db.prepare(`INSERT INTO transactions
    (account_id, kind, amount_cents, balance_after_cents, counterparty, description, category, reference, created_at)
    VALUES (?,?,?,?,?,?,?,?, datetime('now', ?))`);
  for (const [kind, amt, cp, desc, cat, daysAgo] of items) {
    bal += kind === 'credit' ? amt : -amt;
    if (bal < 0) { bal += amt; continue; }
    ins.run(chk, kind, amt, bal, cp, desc, cat, newRef(), `-${daysAgo} days`);
  }
  db.prepare('UPDATE accounts SET balance_cents = ? WHERE id = ?').run(bal, chk);
  db.prepare('UPDATE accounts SET balance_cents = ? WHERE id = ?').run(150000, sav);
  ins.run(sav, 'credit', 150000, 150000, 'Sara Demo', 'Initial savings', 'savings', newRef(), '-70 days');
  db.prepare('INSERT INTO beneficiaries (user_id,name,iban) VALUES (?,?,?)').run(uid, 'Landlord', 'IT60X0542811101000000123456');
  audit(admin.lastInsertRowid, 'seed', 'database seeded');
}
seed();

module.exports = { db, audit, createAccount, createCard, newRef };
