# WeBank — demo online banking app

A full-stack, dynamic web app: Flask + PostgreSQL on the back end, a no-framework single-page app on the front end.
**Demo only — sandbox money, no real banking rails.** External providers and bank-specific integrations must be added later through a reviewed adapter.

## Run it
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d postgres
python app.py        # http://localhost:3000
```
Demo login (seeded on first run):

| Role     | Email               | Password           |
|----------|---------------------|--------------------|
| Customer | demo@webank.demo    | Demo#WeBank2026    |

The seeded demo customer uses authenticator secret `JBSWY3DPEHPK3PXP`.
For a real account, scan the QR code shown after registration.
Admins are not created by the application. Create them directly in PostgreSQL:

```bash
docker exec -it webank-postgres-1 psql -U webank -d webank
```

```sql
INSERT INTO users (full_name, email, password_hash, role)
VALUES (
  'Bank Admin',
  'admin@example.com',
  crypt('YourStrongPassword#1', gen_salt('bf', 12)),
  'admin'
);
```

If `crypt` is unavailable, enable it once with `CREATE EXTENSION IF NOT EXISTS pgcrypto;`.

Environment variables: `PORT`, `SESSION_SECRET`, `DATABASE_URL`, `NODE_ENV=production`.
To reset the PostgreSQL data, run `docker compose down -v` and start it again.

Employee cash deposits are submitted as pending operations and require admin
approval before the customer's balance and transaction history are updated.
Customers cannot create deposits themselves. The admin workspace includes
pending deposits and the worker operation trace.

## Features
- Registration / login / logout, password change, profile
- Customer account closure requests with administrator approval and permanent deletion
- Authenticator-app two-factor authentication for customers and employees, with QR setup and reset
- Immediate customer registration; employee registration requires admin approval
- Customer, employee, and SQL-created admin roles with separate interfaces
- Provider-neutral sandbox transfers with database-backed idempotency protection
- Multiple accounts (checking & savings), IBAN-style numbers, rename, open new
- Transfers between own accounts, to other WeBank customers (instant) or external IBANs (simulated), with confirm step, references, daily limit
- Beneficiaries, transaction search / filters / pagination, CSV export
- Debit cards: freeze/unfreeze, monthly limit
- Customer-scoped card APIs: debit/credit card views, balances, card transactions, blocking, replacement and new-card requests, activation, PIN, ATM/purchase limits, payment controls, virtual cards, Apple Pay/Google Pay provisioning, and unauthorized-transaction reports
- Insights: 30-day balance chart, spending by category, income vs spending
- Admin console: KPIs, lock/unlock customers, employee approval, cash-deposit approval, worker operation trace, audit log
- Admins can refuse pending employee applications; pending, rejected, expired, and legacy verification requests older than 24 hours are automatically deleted.
- Monthly category budgets with progress bars (customers)
- Recent security activity (logins, failed attempts, password changes) on the profile page
- Admin monitoring: DB latency, 24h volume, large transactions, suspicious IPs, unauthorized-transaction reports and card requests review, searchable/exportable audit log
- Responsive, light/dark mode, accessible (labels, focus rings, ARIA)

## Security design (useful talking points)
- Passwords hashed with bcrypt (cost 12); strong-password policy enforced server-side
- Session cookie `HttpOnly`, `SameSite=Strict`, `Secure` in production; 15-minute idle timeout
- CSRF token required on every state-changing request (timing-safe compare)
- Brute-force defences: per-account lockout after 5 failures and generic error messages
- All SQL parameterised (no string concatenation); `LIKE` wildcards escaped
- Output escaped by default in the front-end templating (XSS); strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`) via Helmet
- Object-level authorisation on every account/card/beneficiary lookup (IDOR-safe); role check on admin routes
- Money stored as integer cents; transfers run in a single DB transaction; CHECK constraints prevent negative balances
- CSV export neutralises spreadsheet-formula injection
- Audit log of logins, failures, transfers, card and admin actions
- Failed authenticator codes are recorded in the administrator audit log

## Known limits (before any real use)
- In-memory session store (use Redis/SQLite store when deploying multiple instances)
- Administrator accounts do not use MFA; there is no password reset flow
- CSP allows inline `style` attributes (`style-src-attr`) for convenience; scripts are fully locked down
- Not a real payment system: external transfers are simulated and employee deposits use sandbox balances

## Layout
```
app.py             Flask entry point, REST API, and seed logic
schema.sql         PostgreSQL schema
requirements.txt   Python dependencies
docker-compose.yml local PostgreSQL service
server.js          legacy Node entry point (kept for reference)
src/               legacy Node/SQLite implementation (kept for reference)
public/            index.html, style.css, app.js (SPA)
```
