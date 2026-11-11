CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT DEFAULT '',
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','employee','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','locked')),
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ,
  totp_secret TEXT, totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ALTER COLUMN totp_enabled SET DEFAULT FALSE;
UPDATE users SET totp_enabled=FALSE WHERE totp_secret IS NULL;
DO $$
BEGIN
  ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
  ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('customer', 'employee', 'admin'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS pending_registrations (
  id SERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  requested_role TEXT NOT NULL CHECK (requested_role IN ('customer','employee')),
  totp_secret TEXT,
  totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  otp_hash TEXT,
  otp_expires_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','verified','approved','rejected','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE pending_registrations ALTER COLUMN otp_hash DROP NOT NULL;
ALTER TABLE pending_registrations ALTER COLUMN otp_expires_at DROP NOT NULL;
ALTER TABLE pending_registrations ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE pending_registrations ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pending_registrations ALTER COLUMN totp_enabled SET DEFAULT FALSE;
DO $$
BEGIN
  ALTER TABLE pending_registrations DROP CONSTRAINT IF EXISTS pending_registrations_status_check;
  ALTER TABLE pending_registrations ADD CONSTRAINT pending_registrations_status_check
    CHECK (status IN ('pending', 'verified', 'approved', 'rejected', 'expired'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS accounts (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  iban TEXT UNIQUE NOT NULL, type TEXT NOT NULL CHECK (type IN ('checking','savings')), nickname TEXT DEFAULT '',
  balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0), currency TEXT NOT NULL DEFAULT 'EUR',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('credit','debit')), amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  balance_after_cents INTEGER NOT NULL, counterparty TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'other', reference TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions(account_id, created_at DESC);
CREATE TABLE IF NOT EXISTS cash_deposit_requests (
  id BIGSERIAL PRIMARY KEY,
  worker_id INTEGER NOT NULL REFERENCES users(id),
  customer_id INTEGER NOT NULL REFERENCES users(id),
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0 AND amount_cents <= 100000),
  reference TEXT NOT NULL UNIQUE,
  worker_note TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by INTEGER REFERENCES users(id),
  review_note TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ
);
ALTER TABLE cash_deposit_requests ADD COLUMN IF NOT EXISTS worker_note TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_cash_deposit_requests_status
  ON cash_deposit_requests(status, created_at DESC);
CREATE TABLE IF NOT EXISTS transfer_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'processing'
    CHECK (status IN ('processing', 'completed', 'failed')),
  reference TEXT,
  response JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  UNIQUE(user_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_transfer_requests_user
  ON transfer_requests(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS beneficiaries (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, iban TEXT NOT NULL, UNIQUE(user_id, iban)
);
CREATE TABLE IF NOT EXISTS cards (
  id SERIAL PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  last4 TEXT NOT NULL, brand TEXT NOT NULL DEFAULT 'WeBank Debit', expires TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','frozen')), monthly_limit_cents INTEGER NOT NULL DEFAULT 200000
);
ALTER TABLE cards ADD COLUMN IF NOT EXISTS card_type TEXT NOT NULL DEFAULT 'debit';
ALTER TABLE cards ADD COLUMN IF NOT EXISTS credit_limit_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS credit_balance_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS available_credit_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS pin_hash TEXT;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS online_payments_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS international_payments_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS contactless_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS atm_limit_cents INTEGER NOT NULL DEFAULT 50000;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS daily_purchase_limit_cents INTEGER NOT NULL DEFAULT 200000;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS blocked_reason TEXT;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
DO $$
BEGIN
  ALTER TABLE cards DROP CONSTRAINT IF EXISTS cards_status_check;
  ALTER TABLE cards ADD CONSTRAINT cards_status_check
    CHECK (status IN ('active', 'frozen', 'blocked', 'pending_activation'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
  ALTER TABLE cards ADD CONSTRAINT cards_type_check CHECK (card_type IN ('debit', 'credit'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS card_transactions (
  id SERIAL PRIMARY KEY, card_id INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  kind TEXT NOT NULL CHECK (kind IN ('purchase', 'refund', 'cash_withdrawal', 'fee', 'payment')),
  status TEXT NOT NULL DEFAULT 'posted' CHECK (status IN ('pending', 'posted', 'reversed')),
  merchant TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'EUR', reference TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_card_transactions_card ON card_transactions(card_id, created_at DESC);
CREATE TABLE IF NOT EXISTS unauthorized_card_reports (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  card_id INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
  card_transaction_id INTEGER NOT NULL REFERENCES card_transactions(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted'
    CHECK (status IN ('submitted', 'under_review', 'resolved', 'rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, card_transaction_id)
);
CREATE INDEX IF NOT EXISTS idx_unauthorized_reports_user
  ON unauthorized_card_reports(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS card_requests (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  card_id INTEGER REFERENCES cards(id) ON DELETE SET NULL,
  request_type TEXT NOT NULL CHECK (request_type IN ('new_debit', 'new_credit', 'replacement')),
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'approved', 'rejected', 'completed')),
  reason TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS virtual_cards (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_card_id INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
  last4 TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deactivated')),
  expires TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS card_wallets (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  card_id INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('apple_pay', 'google_pay')),
  status TEXT NOT NULL DEFAULT 'provisioning' CHECK (status IN ('provisioning', 'active', 'removed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(card_id, provider)
);
CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, detail TEXT DEFAULT '',
  ip TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS account_closure_requests (
  id BIGSERIAL PRIMARY KEY,
  customer_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'rejected')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_by INTEGER REFERENCES users(id),
  reviewed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_account_closure_requests_status
  ON account_closure_requests(status, requested_at DESC);
CREATE TABLE IF NOT EXISTS budgets (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL, limit_cents INTEGER NOT NULL CHECK (limit_cents > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(user_id, category)
);
