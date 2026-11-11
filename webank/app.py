import csv
import base64
import hashlib
import io
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import psycopg
import pyotp
import qrcode
from flask import Flask, has_request_context, jsonify, request, send_from_directory, session
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://webank:webank@localhost:5432/webank")
DAILY_LIMIT_CENTS = 500000

app = Flask(__name__, static_folder="public", static_url_path="")
app.config.update(
    SECRET_KEY=os.getenv("SESSION_SECRET", secrets.token_hex(32)),
    SESSION_COOKIE_NAME="wb.sid",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.getenv("NODE_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)
pool = ConnectionPool(DATABASE_URL, kwargs={"row_factory": dict_row}, open=True)


def db():
    return pool.connection()


def cleanup_pending_registrations(conn):
    conn.execute(
        """DELETE FROM pending_registrations
           WHERE created_at < now() - interval '1 day'
             AND status IN ('pending', 'verified', 'rejected', 'expired')"""
    )


def clean(value, maximum):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(value or "")).strip()[:maximum]


def parse_amount(value):
    text = str(value or "").strip().replace(",", ".")
    if not re.fullmatch(r"\d{1,7}(\.\d{1,2})?", text):
        return None
    cents = round(float(text) * 100)
    return cents if cents > 0 else None


def strong_password(value):
    return isinstance(value, str) and 10 <= len(value) <= 128 and all(
        re.search(pattern, value) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )


def new_ref():
    return "WB-" + secrets.token_hex(5).upper()


def error(message, status=400):
    return jsonify(error=message), status


def public_user(user):
    return {key: user[key] for key in ("id", "full_name", "email", "phone", "role", "created_at")}


def totp_setup(secret, email):
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="WeBank")
    image = io.BytesIO()
    qrcode.make(uri).save(image, format="PNG")
    return {
        "secret": secret,
        "qr_code": "data:image/png;base64,"
        + base64.b64encode(image.getvalue()).decode("ascii"),
    }


def complete_login(user):
    session.clear()
    session["user_id"] = user["id"]
    session["csrf"] = secrets.token_hex(24)
    return jsonify(ok=True, csrf=session["csrf"], user=public_user(user))


def audit(conn, user_id, action, detail=""):
    conn.execute(
        "INSERT INTO audit_log (user_id, action, detail, ip) VALUES (%s, %s, %s, %s)",
        (user_id, action, detail, request.remote_addr or "" if has_request_context() else ""),
    )


def auth_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return error("Authentication required", 401)
        with db() as conn:
            user = conn.execute(
                "SELECT id, role, status FROM users WHERE id = %s", (user_id,)
            ).fetchone()
        if not user or user["status"] != "active":
            session.clear()
            return error("Authentication required", 401)
        return function(user, *args, **kwargs)

    return wrapped


def admin_required(function):
    @wraps(function)
    @auth_required
    def wrapped(user, *args, **kwargs):
        if user["role"] != "admin":
            return error("Forbidden", 403)
        return function(user, *args, **kwargs)

    return wrapped


def csrf_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf", "")
            if not expected or not secrets.compare_digest(supplied, expected):
                return error("Invalid CSRF token", 403)
        return function(*args, **kwargs)

    return wrapped


@app.before_request
def prepare_request():
    session.permanent = True
    session.setdefault("csrf", secrets.token_hex(24))


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "style-src-attr 'unsafe-inline'; img-src 'self' data:"
    )
    return response


@app.get("/api/csrf")
def csrf():
    return jsonify(token=session["csrf"])


@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify(user=None, csrf=session["csrf"])
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()
    return jsonify(user=public_user(user) if user else None, csrf=session["csrf"])


@app.post("/api/auth/register")
@csrf_required
def register():
    full_name = clean(request.json.get("full_name"), 80)
    email = clean(request.json.get("email"), 254).lower()
    password = request.json.get("password")
    requested_role = request.json.get("role", "customer")
    if len(full_name) < 2:
        return error("Please enter your full name.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return error("Please enter a valid email address.")
    if not strong_password(password):
        return error("Password needs 10+ characters with upper, lower, a digit and a symbol.")
    if requested_role not in {"customer", "employee"}:
        return error("Choose a valid account type.")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    totp_secret = pyotp.random_base32()
    with db() as conn:
        try:
            cleanup_pending_registrations(conn)
            if conn.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
                return error("An account with this email already exists.", 409)
            if conn.execute(
                """SELECT 1 FROM pending_registrations
                   WHERE email=%s AND status IN ('pending','verified')""",
                (email,),
            ).fetchone():
                return error("A registration request with this email is already awaiting review.", 409)
            if requested_role == "employee":
                pending = conn.execute(
                    """INSERT INTO pending_registrations
                       (full_name,email,password_hash,requested_role,totp_secret,totp_enabled,status)
                       VALUES (%s,%s,%s,'employee',%s,TRUE,'pending') RETURNING id""",
                    (full_name, email, password_hash, totp_secret),
                ).fetchone()
                audit(conn, None, "employee_registration_requested", email)
            else:
                user = conn.execute(
                    """INSERT INTO users
                       (full_name,email,password_hash,role,totp_secret,totp_enabled)
                       VALUES (%s,%s,%s,'customer',%s,TRUE)
                       RETURNING id,full_name,email,phone,role,created_at""",
                    (full_name, email, password_hash, totp_secret),
                ).fetchone()
                account = create_account(conn, user["id"], "checking", "Main account", 0)
                create_card(conn, account)
                audit(conn, user["id"], "register", email)
        except psycopg.errors.UniqueViolation:
            conn.rollback()
            return error("An account or registration request with this email already exists.", 409)
    if requested_role == "employee":
        return jsonify(
            ok=True,
            pending_approval=True,
            registration_id=pending["id"],
            totp=totp_setup(totp_secret, email),
        ), 201
    session.clear()
    session["user_id"] = user["id"]
    session["csrf"] = secrets.token_hex(24)
    return jsonify(
        ok=True,
        csrf=session["csrf"],
        user=public_user(user),
        totp=totp_setup(totp_secret, email),
    ), 201


@app.post("/api/auth/login")
@csrf_required
def login():
    body = request.json
    email = clean(body.get("email"), 254).lower()
    password = str(body.get("password") or "")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = %s", (email,)).fetchone()
        valid = user and bcrypt.checkpw(password.encode(), user["password_hash"].encode())
        if user and user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc):
            return (
                jsonify(
                    error="Account temporarily locked. Try again in a few minutes.",
                    message="Please wait before attempting to sign in again.",
                ),
                423,
            )
        if not valid or user["status"] != "active":
            if user:
                fails = user["failed_logins"] + 1
                lock = datetime.now(timezone.utc) + timedelta(minutes=15) if fails >= 5 else None
                conn.execute(
                    "UPDATE users SET failed_logins = %s, locked_until = %s WHERE id = %s",
                    (0 if lock else fails, lock, user["id"]),
                )
                audit(conn, user["id"], "login_failed", f"attempt {fails}")
            if not user:
                message = "The username or email address is incorrect."
            elif not valid:
                message = "The password is incorrect."
            else:
                message = "The account is inactive."
            return (
                jsonify(
                    error="Invalid email or password.",
                    message=message,
                ),
                401,
            )
        if user["role"] != "admin" and user["totp_enabled"] and user["totp_secret"]:
            session.pop("user_id", None)
            session["pending_2fa_user_id"] = user["id"]
            return jsonify(ok=True, requires_2fa=True)
        conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (user["id"],))
        audit(conn, user["id"], "login")
    return complete_login(user)


@app.post("/api/auth/2fa")
@csrf_required
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    code = clean(request.json.get("code"), 12).replace(" ", "")
    if not user_id or not code:
        return error("A verification code is required.", 401)
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=%s", (user_id,)).fetchone()
        if (
            not user
            or user["role"] == "admin"
            or not user["totp_enabled"]
            or not user["totp_secret"]
            or not pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1)
        ):
            if user:
                audit(conn, user["id"], "login_2fa_failed", "invalid authenticator code")
            return error("The verification code is incorrect or expired.", 401)
        session.pop("pending_2fa_user_id", None)
        conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (user_id,))
        audit(conn, user_id, "login")
    return complete_login(user)


@app.post("/api/auth/logout")
@csrf_required
def logout():
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        with db() as conn:
            audit(conn, user_id, "logout")
    return jsonify(ok=True)


@app.patch("/api/profile")
@auth_required
@csrf_required
def profile(user):
    full_name = clean(request.json.get("full_name"), 80)
    phone = clean(request.json.get("phone"), 30)
    if len(full_name) < 2:
        return error("Please enter your full name.")
    with db() as conn:
        conn.execute("UPDATE users SET full_name=%s, phone=%s WHERE id=%s", (full_name, phone, user["id"]))
        audit(conn, user["id"], "profile_update")
    return jsonify(ok=True)


@app.post("/api/profile/password")
@auth_required
@csrf_required
def change_password(user):
    current = str(request.json.get("current") or "")
    next_password = request.json.get("next")
    with db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id=%s", (user["id"],)).fetchone()
        if not bcrypt.checkpw(current.encode(), row["password_hash"].encode()):
            return error("Current password is incorrect.", 403)
        if not strong_password(next_password):
            return error("Password needs 10+ characters with upper, lower, a digit and a symbol.")
        conn.execute(
            "UPDATE users SET password_hash=%s WHERE id=%s",
            (bcrypt.hashpw(next_password.encode(), bcrypt.gensalt()).decode(), user["id"]),
        )
        audit(conn, user["id"], "password_change")
    return jsonify(ok=True)


@app.post("/api/profile/close-account")
@auth_required
@csrf_required
def request_account_closure(user):
    if user["role"] != "customer":
        return error("Only customer accounts can be closed.", 403)
    with db() as conn:
        existing = conn.execute(
            "SELECT status FROM account_closure_requests WHERE customer_id=%s",
            (user["id"],),
        ).fetchone()
        if existing and existing["status"] == "pending":
            return error("An account closure request is already pending.", 409)
        if existing:
            conn.execute("DELETE FROM account_closure_requests WHERE customer_id=%s", (user["id"],))
        conn.execute(
            "INSERT INTO account_closure_requests(customer_id) VALUES(%s)",
            (user["id"],),
        )
        audit(conn, user["id"], "account_closure_requested")
    return jsonify(ok=True, status="pending")


@app.post("/api/profile/2fa/reset")
@auth_required
@csrf_required
def reset_2fa(user):
    if user["role"] == "admin":
        return error("Two-factor authentication is not used for administrator accounts.", 403)
    current = str(request.json.get("current") or "")
    with db() as conn:
        row = conn.execute("SELECT password_hash,email FROM users WHERE id=%s", (user["id"],)).fetchone()
        if not bcrypt.checkpw(current.encode(), row["password_hash"].encode()):
            return error("Current password is incorrect.", 403)
        secret = pyotp.random_base32()
        conn.execute(
            "UPDATE users SET totp_secret=%s,totp_enabled=TRUE WHERE id=%s",
            (secret, user["id"]),
        )
        audit(conn, user["id"], "two_factor_reset")
    return jsonify(ok=True, totp=totp_setup(secret, row["email"]))


@app.get("/api/accounts")
@auth_required
def accounts(user):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, iban, type, nickname, balance_cents, currency, created_at FROM accounts WHERE user_id=%s ORDER BY id",
            (user["id"],),
        ).fetchall()
    return jsonify(accounts=rows)


@app.post("/api/accounts")
@auth_required
@csrf_required
def open_account(user):
    with db() as conn:
        count = conn.execute("SELECT count(*) AS count FROM accounts WHERE user_id=%s", (user["id"],)).fetchone()["count"]
        if count >= 5:
            return error("Account limit reached (5).")
        account_id = create_account(conn, user["id"], request.json.get("type"), clean(request.json.get("nickname"), 40), 0)
        audit(conn, user["id"], "account_open", str(account_id))
    return jsonify(id=account_id), 201


@app.patch("/api/accounts/<int:account_id>")
@auth_required
@csrf_required
def rename_account(user, account_id):
    with db() as conn:
        result = conn.execute(
            "UPDATE accounts SET nickname=%s WHERE id=%s AND user_id=%s",
            (clean(request.json.get("nickname"), 40), account_id, user["id"]),
        )
    return (jsonify(ok=True), 200) if result.rowcount else error("Account not found.", 404)


@app.get("/api/transactions")
@auth_required
def transactions(user):
    filters = ["a.user_id = %s"]
    args = [user["id"]]
    for key, column in (("account_id", "t.account_id"), ("kind", "t.kind"), ("category", "t.category")):
        if request.args.get(key):
            filters.append(f"{column} = %s")
            args.append(request.args[key])
    if request.args.get("q"):
        filters.append("(t.counterparty ILIKE %s OR t.description ILIKE %s OR t.reference ILIKE %s)")
        q = "%" + clean(request.args["q"], 50) + "%"
        args.extend([q, q, q])
    limit = min(max(request.args.get("limit", 25, type=int), 1), 100)
    offset = max(request.args.get("offset", 0, type=int), 0)
    where = " AND ".join(filters)
    with db() as conn:
        total = conn.execute(f"SELECT count(*) AS count FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE {where}", args).fetchone()["count"]
        rows = conn.execute(
            f"""SELECT t.*, a.nickname AS account_name FROM transactions t JOIN accounts a ON a.id=t.account_id
                WHERE {where} ORDER BY t.created_at DESC, t.id DESC LIMIT %s OFFSET %s""",
            args + [limit, offset],
        ).fetchall()
    return jsonify(total=total, transactions=rows)


@app.post("/api/transfers")
@auth_required
@csrf_required
def transfer(user):
    source_id = request.json.get("from_account_id")
    amount = parse_amount(request.json.get("amount"))
    iban = re.sub(r"\s+", "", clean(request.json.get("to_iban"), 34)).upper()
    name = clean(request.json.get("to_name"), 80)
    description = clean(request.json.get("description"), 100) or "Transfer"
    idempotency_key = clean(request.headers.get("Idempotency-Key"), 100)
    if not idempotency_key:
        return error("Idempotency-Key header is required.", 400)
    if not amount:
        return error("Enter a valid amount (max 2 decimals).")
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", iban) or len(name) < 2:
        return error("Enter a valid IBAN and recipient name.")
    request_hash = hashlib.sha256(json.dumps({
        "source_id": source_id,
        "amount": amount,
        "iban": iban,
        "name": name,
        "description": description,
    }, sort_keys=True).encode()).hexdigest()
    with db() as conn:
        existing = conn.execute(
            "SELECT request_hash,status,response FROM transfer_requests WHERE user_id=%s AND idempotency_key=%s",
            (user["id"], idempotency_key),
        ).fetchone()
        if existing:
            if existing["request_hash"] != request_hash:
                return error("Idempotency-Key was already used for a different transfer.", 409)
            if existing["status"] == "completed":
                return jsonify(**existing["response"])
            return error("This transfer is already being processed.", 409)
        source = conn.execute("SELECT * FROM accounts WHERE id=%s AND user_id=%s FOR UPDATE", (source_id, user["id"])).fetchone()
        destination = conn.execute("SELECT * FROM accounts WHERE iban=%s FOR UPDATE", (iban,)).fetchone()
        if not source:
            return error("Source account not found.", 404)
        if source["iban"] == iban:
            return error("Source and destination must differ.")
        if source["balance_cents"] < amount:
            return error("Insufficient funds.")
        if source["type"] == "savings" and not (destination and destination["user_id"] == user["id"]):
            return error("Savings accounts can only move money to your own accounts.")
        spent = conn.execute(
            """SELECT coalesce(sum(t.amount_cents),0) AS total FROM transactions t JOIN accounts a ON a.id=t.account_id
               WHERE a.user_id=%s AND t.kind='debit' AND t.category='transfer' AND t.created_at >= now()-interval '1 day'""",
            (user["id"],),
        ).fetchone()["total"]
        if spent + amount > DAILY_LIMIT_CENTS:
            return error("Daily transfer limit of €5000.00 exceeded.")
        request_row = conn.execute(
            """INSERT INTO transfer_requests(user_id,idempotency_key,request_hash)
               VALUES(%s,%s,%s)
               ON CONFLICT(user_id,idempotency_key) DO NOTHING
               RETURNING id""",
            (user["id"], idempotency_key, request_hash),
        ).fetchone()
        if not request_row:
            existing = conn.execute(
                "SELECT request_hash,status,response FROM transfer_requests WHERE user_id=%s AND idempotency_key=%s",
                (user["id"], idempotency_key),
            ).fetchone()
            if existing["request_hash"] != request_hash:
                return error("Idempotency-Key was already used for a different transfer.", 409)
            if existing["status"] == "completed":
                return jsonify(**existing["response"])
            return error("This transfer is already being processed.", 409)
        reference = new_ref()
        new_balance = source["balance_cents"] - amount
        own = destination and destination["user_id"] == user["id"]
        conn.execute("UPDATE accounts SET balance_cents=%s WHERE id=%s", (new_balance, source["id"]))
        conn.execute(
            """INSERT INTO transactions(account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
               VALUES(%s,'debit',%s,%s,%s,%s,%s,%s)""",
            (source["id"], amount, new_balance, name, description, "savings" if own else "transfer", reference),
        )
        if destination:
            destination_balance = destination["balance_cents"] + amount
            conn.execute("UPDATE accounts SET balance_cents=%s WHERE id=%s", (destination_balance, destination["id"]))
            sender = conn.execute("SELECT full_name FROM users WHERE id=%s", (user["id"],)).fetchone()["full_name"]
            conn.execute(
                """INSERT INTO transactions(account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
                   VALUES(%s,'credit',%s,%s,%s,%s,%s,%s)""",
                (destination["id"], amount, destination_balance, sender, description, "savings" if own else "income", reference),
            )
        if request.json.get("save_beneficiary") and not own:
            conn.execute(
                "INSERT INTO beneficiaries(user_id,name,iban) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
                (user["id"], name, iban),
            )
        audit(conn, user["id"], "transfer", f"{reference} -> {iban}")
        response = {"ok": True, "reference": reference, "internal": bool(destination), "balance_cents": new_balance}
        conn.execute(
            """UPDATE transfer_requests
               SET status='completed',reference=%s,response=%s,completed_at=now()
               WHERE id=%s""",
            (reference, json.dumps(response), request_row["id"]),
        )
    return jsonify(**response), 201


@app.post("/api/deposit")
@auth_required
@csrf_required
def deposit(user):
    if user["role"] != "employee":
        return error("Only bank employees can submit cash deposits.", 403)
    return create_cash_deposit_request(user)


def create_cash_deposit_request(user):
    amount = parse_amount(request.json.get("amount"))
    worker_note = clean(request.json.get("note"), 240)
    with db() as conn:
        account = conn.execute(
            """SELECT a.id,a.user_id,a.iban,a.nickname,u.full_name
               FROM accounts a JOIN users u ON u.id=a.user_id
               WHERE a.id=%s AND u.role='customer'""",
            (request.json.get("account_id"),),
        ).fetchone()
        if not account:
            return error("Customer account not found.", 404)
        if not amount or amount > 100000:
            return error("Enter an amount up to €1000.")
        reference = new_ref()
        conn.execute(
            """INSERT INTO cash_deposit_requests
               (worker_id,customer_id,account_id,amount_cents,reference,worker_note)
               VALUES(%s,%s,%s,%s,%s,%s)""",
            (user["id"], account["user_id"], account["id"], amount, reference, worker_note),
        )
        audit(conn, user["id"], "cash_deposit_requested", f"{reference} account {account['id']} €{amount / 100:.2f}")
    return jsonify(ok=True, status="pending", reference=reference), 201


@app.get("/api/employee/customers")
@auth_required
def employee_customers(user):
    if user["role"] != "employee":
        return error("Forbidden", 403)
    with db() as conn:
        rows = conn.execute(
            """SELECT u.id AS customer_id,u.full_name,u.email,a.id AS account_id,
                      a.type,a.nickname,a.iban,a.balance_cents,a.currency
               FROM users u JOIN accounts a ON a.user_id=u.id
               WHERE u.role='customer' AND u.status='active'
               ORDER BY u.full_name,a.id"""
        ).fetchall()
    return jsonify(customers=rows)


@app.get("/api/employee/deposit-requests")
@auth_required
def employee_deposit_requests(user):
    if user["role"] != "employee":
        return error("Forbidden", 403)
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.amount_cents,r.reference,r.status,r.created_at,
                      u.full_name AS customer_name,a.nickname AS account_name
               FROM cash_deposit_requests r
               JOIN users u ON u.id=r.customer_id JOIN accounts a ON a.id=r.account_id
               WHERE r.worker_id=%s ORDER BY r.created_at DESC LIMIT 100""",
            (user["id"],),
        ).fetchall()
    return jsonify(requests=rows)


@app.get("/api/beneficiaries")
@auth_required
def beneficiaries(user):
    with db() as conn:
        rows = conn.execute("SELECT id,name,iban FROM beneficiaries WHERE user_id=%s ORDER BY name", (user["id"],)).fetchall()
    return jsonify(beneficiaries=rows)


@app.post("/api/beneficiaries")
@auth_required
@csrf_required
def add_beneficiary(user):
    name = clean(request.json.get("name"), 80)
    iban = re.sub(r"\s+", "", clean(request.json.get("iban"), 34)).upper()
    if len(name) < 2 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", iban):
        return error("Enter a name and valid IBAN.")
    with db() as conn:
        try:
            conn.execute("INSERT INTO beneficiaries(user_id,name,iban) VALUES(%s,%s,%s)", (user["id"], name, iban))
        except psycopg.errors.UniqueViolation:
            conn.rollback()
            return error("This beneficiary already exists.", 409)
    return jsonify(ok=True), 201


@app.delete("/api/beneficiaries/<int:beneficiary_id>")
@auth_required
@csrf_required
def delete_beneficiary(user, beneficiary_id):
    with db() as conn:
        conn.execute("DELETE FROM beneficiaries WHERE id=%s AND user_id=%s", (beneficiary_id, user["id"]))
    return jsonify(ok=True)


@app.get("/api/cards")
@auth_required
def cards(user):
    card_type = request.args.get("type")
    if card_type not in {None, "debit", "credit"}:
        return error("Card type must be debit or credit.")
    return list_cards(user, card_type)


def list_cards(user, card_type=None):
    type_filter = " AND c.card_type=%s" if card_type else ""
    query_args = [user["id"]] + ([card_type] if card_type else [])
    with db() as conn:
        rows = conn.execute(
            f"""SELECT c.id,c.card_type,c.last4,c.brand,c.expires,c.status,
                      c.credit_limit_cents,c.credit_balance_cents,c.available_credit_cents,
                      c.monthly_limit_cents,c.atm_limit_cents,c.daily_purchase_limit_cents,
                      c.online_payments_enabled,c.international_payments_enabled,c.contactless_enabled,
                      c.activated_at,a.nickname AS account_name,a.iban,
                      CASE WHEN c.card_type='debit' THEN a.balance_cents ELSE c.credit_balance_cents END AS balance_cents
                      FROM cards c JOIN accounts a ON a.id=c.account_id
                      WHERE a.user_id=%s{type_filter}""",
            query_args,
        ).fetchall()
    return jsonify(cards=rows)


@app.get("/api/cards/debit")
@auth_required
def debit_cards(user):
    return list_cards(user, "debit")


@app.get("/api/cards/credit")
@auth_required
def credit_cards(user):
    return list_cards(user, "credit")


def owned_card(conn, user_id, card_id, lock=False):
    suffix = " FOR UPDATE" if lock else ""
    return conn.execute(
        f"""SELECT c.*, a.nickname AS account_name, a.iban, a.balance_cents AS account_balance
            FROM cards c JOIN accounts a ON a.id=c.account_id
            WHERE c.id=%s AND a.user_id=%s{suffix}""",
        (card_id, user_id),
    ).fetchone()


@app.get("/api/cards/<int:card_id>")
@auth_required
def card_details(user, card_id):
    with db() as conn:
        card = owned_card(conn, user["id"], card_id)
    if not card:
        return error("Card not found.", 404)
    card["balance_cents"] = card["account_balance"] if card["card_type"] == "debit" else card["credit_balance_cents"]
    card["available_credit_cents"] = (
        card["account_balance"] if card["card_type"] == "debit" else card["available_credit_cents"]
    )
    card.pop("account_balance", None)
    card.pop("pin_hash", None)
    return jsonify(card=card)


@app.get("/api/cards/<int:card_id>/transactions")
@auth_required
def card_transactions(user, card_id):
    limit = min(max(request.args.get("limit", 25, type=int), 1), 100)
    offset = max(request.args.get("offset", 0, type=int), 0)
    with db() as conn:
        if not owned_card(conn, user["id"], card_id):
            return error("Card not found.", 404)
        total = conn.execute("SELECT count(*) AS count FROM card_transactions WHERE card_id=%s", (card_id,)).fetchone()["count"]
        rows = conn.execute(
            """SELECT id,amount_cents,kind,status,merchant,description,currency,reference,created_at
               FROM card_transactions WHERE card_id=%s ORDER BY created_at DESC,id DESC LIMIT %s OFFSET %s""",
            (card_id, limit, offset),
        ).fetchall()
    return jsonify(total=total, transactions=rows)


@app.post("/api/cards/<int:card_id>/transactions/<int:transaction_id>/unauthorized")
@auth_required
@csrf_required
def report_unauthorized_transaction(user, card_id, transaction_id):
    reason = clean(request.json.get("reason"), 500)
    if len(reason) < 5:
        return error("Please provide a reason for this report.")
    with db() as conn:
        card = owned_card(conn, user["id"], card_id)
        if not card:
            return error("Card not found.", 404)
        transaction = conn.execute(
            "SELECT id FROM card_transactions WHERE id=%s AND card_id=%s",
            (transaction_id, card_id),
        ).fetchone()
        if not transaction:
            return error("Card transaction not found.", 404)
        try:
            report = conn.execute(
                """INSERT INTO unauthorized_card_reports
                   (user_id,card_id,card_transaction_id,reason)
                   VALUES(%s,%s,%s,%s)
                   RETURNING id,card_id,card_transaction_id,reason,status,created_at""",
                (user["id"], card_id, transaction_id, reason),
            ).fetchone()
        except psycopg.errors.UniqueViolation:
            conn.rollback()
            return error("This transaction has already been reported.", 409)
        audit(conn, user["id"], "unauthorized_card_transaction", f"card transaction {transaction_id}")
    return jsonify(report=report), 201


@app.get("/api/card-transaction-reports")
@auth_required
def unauthorized_transaction_reports(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.card_id,r.card_transaction_id,r.reason,r.status,r.created_at,
                      t.amount_cents,t.kind,t.merchant,t.description,t.reference,t.created_at AS transaction_created_at
               FROM unauthorized_card_reports r
               JOIN card_transactions t ON t.id=r.card_transaction_id
               WHERE r.user_id=%s ORDER BY r.created_at DESC""",
            (user["id"],),
        ).fetchall()
    return jsonify(reports=rows)


@app.post("/api/cards/<int:card_id>/toggle")
@auth_required
@csrf_required
def toggle_card(user, card_id):
    with db() as conn:
        card = owned_card(conn, user["id"], card_id, lock=True)
        if not card:
            return error("Card not found.", 404)
        if card["status"] == "blocked":
            return error("A blocked card cannot be unfrozen.", 409)
        status = "frozen" if card["status"] == "active" else "active"
        conn.execute("UPDATE cards SET status=%s WHERE id=%s", (status, card_id))
        audit(conn, user["id"], f"card_{status}", f"card ****{card['last4']}")
    return jsonify(status=status)


@app.post("/api/cards/<int:card_id>/block")
@auth_required
@csrf_required
def block_card(user, card_id):
    reason = clean(request.json.get("reason"), 120) or "lost_or_stolen"
    with db() as conn:
        card = owned_card(conn, user["id"], card_id, lock=True)
        if not card:
            return error("Card not found.", 404)
        conn.execute("UPDATE cards SET status='blocked', blocked_reason=%s WHERE id=%s", (reason, card_id))
        audit(conn, user["id"], "card_blocked", f"card ****{card['last4']}: {reason}")
    return jsonify(status="blocked")


def create_card_request(user_id, card_id, request_type, reason=""):
    with db() as conn:
        row = conn.execute(
            """INSERT INTO card_requests(user_id,card_id,request_type,reason)
               VALUES(%s,%s,%s,%s) RETURNING id,request_type,status,reason,created_at""",
            (user_id, card_id, request_type, clean(reason, 120)),
        ).fetchone()
        audit(conn, user_id, "card_request", request_type)
    return row


@app.post("/api/cards/<int:card_id>/replacement")
@auth_required
@csrf_required
def replacement_request(user, card_id):
    with db() as conn:
        if not owned_card(conn, user["id"], card_id):
            return error("Card not found.", 404)
    return jsonify(request=create_card_request(user["id"], card_id, "replacement", request.json.get("reason"))), 201


@app.post("/api/cards/request")
@auth_required
@csrf_required
def new_card_request(user):
    request_type = request.json.get("card_type")
    if request_type not in {"debit", "credit"}:
        return error("Card type must be debit or credit.")
    return jsonify(request=create_card_request(user["id"], None, f"new_{request_type}")), 201


@app.get("/api/card-requests")
@auth_required
def card_requests(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT id,card_id,request_type,status,reason,created_at FROM card_requests
               WHERE user_id=%s ORDER BY created_at DESC""",
            (user["id"],),
        ).fetchall()
    return jsonify(requests=rows)


@app.post("/api/cards/<int:card_id>/activate")
@auth_required
@csrf_required
def activate_card(user, card_id):
    with db() as conn:
        card = owned_card(conn, user["id"], card_id, lock=True)
        if not card:
            return error("Card not found.", 404)
        if card["status"] == "blocked":
            return error("A blocked card cannot be activated.", 409)
        conn.execute("UPDATE cards SET status='active', activated_at=now() WHERE id=%s", (card_id,))
        audit(conn, user["id"], "card_activated", f"card ****{card['last4']}")
    return jsonify(status="active")


@app.post("/api/cards/<int:card_id>/pin")
@auth_required
@csrf_required
def set_card_pin(user, card_id):
    pin = str(request.json.get("pin") or "")
    if not re.fullmatch(r"\d{4}", pin):
        return error("PIN must be exactly 4 digits.")
    with db() as conn:
        card = owned_card(conn, user["id"], card_id, lock=True)
        if not card:
            return error("Card not found.", 404)
        conn.execute("UPDATE cards SET pin_hash=%s WHERE id=%s", (bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode(), card_id))
        audit(conn, user["id"], "card_pin_change", f"card ****{card['last4']}")
    return jsonify(ok=True)


@app.patch("/api/cards/<int:card_id>/limit")
@auth_required
@csrf_required
def card_limit(user, card_id):
    body = request.json
    fields = {
        "monthly_limit_cents": ("limit", 1000000),
        "atm_limit_cents": ("atm_limit", 1000000),
        "daily_purchase_limit_cents": ("daily_purchase_limit", 1000000),
    }
    updates, values = [], []
    for column, (key, maximum) in fields.items():
        if key in body:
            value = parse_amount(body[key])
            if not value or value > maximum:
                return error("Enter a valid card limit.")
            updates.append(f"{column}=%s")
            values.append(value)
    if not updates:
        return error("Provide at least one card limit.")
    values.extend([card_id, user["id"]])
    with db() as conn:
        result = conn.execute(
            f"UPDATE cards SET {', '.join(updates)} WHERE id=%s AND account_id IN (SELECT id FROM accounts WHERE user_id=%s)",
            values,
        )
    return (jsonify(ok=True), 200) if result.rowcount else error("Card not found.", 404)


@app.patch("/api/cards/<int:card_id>/controls")
@auth_required
@csrf_required
def card_controls(user, card_id):
    allowed = {
        "online_payments_enabled": "online_payments_enabled",
        "international_payments_enabled": "international_payments_enabled",
        "contactless_enabled": "contactless_enabled",
    }
    updates, values = [], []
    for key, column in allowed.items():
        if key in request.json:
            if not isinstance(request.json[key], bool):
                return error(f"{key} must be true or false.")
            updates.append(f"{column}=%s")
            values.append(request.json[key])
    if not updates:
        return error("Provide at least one payment control.")
    values.extend([card_id, user["id"]])
    with db() as conn:
        result = conn.execute(
            f"UPDATE cards SET {', '.join(updates)} WHERE id=%s AND account_id IN (SELECT id FROM accounts WHERE user_id=%s)",
            values,
        )
    return (jsonify(ok=True), 200) if result.rowcount else error("Card not found.", 404)


@app.get("/api/virtual-cards")
@auth_required
def virtual_cards(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT v.id,v.source_card_id,v.last4,v.status,v.expires,v.created_at
               FROM virtual_cards v WHERE v.user_id=%s ORDER BY v.created_at DESC""",
            (user["id"],),
        ).fetchall()
    return jsonify(virtual_cards=rows)


@app.post("/api/virtual-cards")
@auth_required
@csrf_required
def create_virtual_card(user):
    with db() as conn:
        source = owned_card(conn, user["id"], request.json.get("card_id"), lock=True)
        if not source or source["status"] != "active":
            return error("An active card is required.", 400)
        expires = (datetime.now(timezone.utc) + timedelta(days=365 * 3)).strftime("%m/%y")
        row = conn.execute(
            """INSERT INTO virtual_cards(user_id,source_card_id,last4,expires)
               VALUES(%s,%s,%s,%s) RETURNING id,source_card_id,last4,status,expires,created_at""",
            (user["id"], source["id"], str(secrets.randbelow(10000)).zfill(4), expires),
        ).fetchone()
        audit(conn, user["id"], "virtual_card_create", str(row["id"]))
    return jsonify(virtual_card=row), 201


@app.delete("/api/virtual-cards/<int:virtual_card_id>")
@auth_required
@csrf_required
def deactivate_virtual_card(user, virtual_card_id):
    with db() as conn:
        result = conn.execute(
            "UPDATE virtual_cards SET status='deactivated' WHERE id=%s AND user_id=%s",
            (virtual_card_id, user["id"]),
        )
    return (jsonify(ok=True), 200) if result.rowcount else error("Virtual card not found.", 404)


@app.get("/api/cards/<int:card_id>/wallets")
@auth_required
def wallets(user, card_id):
    with db() as conn:
        if not owned_card(conn, user["id"], card_id):
            return error("Card not found.", 404)
        rows = conn.execute("SELECT id,provider,status,created_at FROM card_wallets WHERE card_id=%s AND user_id=%s", (card_id, user["id"])).fetchall()
    return jsonify(wallets=rows)


@app.post("/api/cards/<int:card_id>/wallets")
@auth_required
@csrf_required
def add_wallet(user, card_id):
    provider = request.json.get("provider")
    if provider not in {"apple_pay", "google_pay"}:
        return error("Provider must be apple_pay or google_pay.")
    with db() as conn:
        if not owned_card(conn, user["id"], card_id):
            return error("Card not found.", 404)
        row = conn.execute(
            """INSERT INTO card_wallets(user_id,card_id,provider,status) VALUES(%s,%s,%s,'active')
               ON CONFLICT(card_id,provider) DO UPDATE SET status='active'
               RETURNING id,provider,status,created_at""",
            (user["id"], card_id, provider),
        ).fetchone()
        audit(conn, user["id"], "wallet_add", f"{provider} card {card_id}")
    return jsonify(wallet=row), 201


@app.get("/api/insights")
@auth_required
def insights(user):
    with db() as conn:
        total = conn.execute("SELECT coalesce(sum(balance_cents),0) AS total FROM accounts WHERE user_id=%s", (user["id"],)).fetchone()["total"]
        by_category = conn.execute(
            """SELECT t.category, sum(t.amount_cents) AS total FROM transactions t JOIN accounts a ON a.id=t.account_id
               WHERE a.user_id=%s AND t.kind='debit' AND t.category <> 'savings' AND t.created_at >= now()-interval '30 days'
               GROUP BY t.category ORDER BY total DESC""", (user["id"],)).fetchall()
        monthly = conn.execute(
            """SELECT to_char(t.created_at,'YYYY-MM') AS month,
               sum(CASE WHEN t.kind='credit' AND t.category <> 'savings' THEN t.amount_cents ELSE 0 END) AS income,
               sum(CASE WHEN t.kind='debit' AND t.category <> 'savings' THEN t.amount_cents ELSE 0 END) AS spending
               FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE a.user_id=%s
               GROUP BY month ORDER BY month DESC LIMIT 6""", (user["id"],)).fetchall()[::-1]
        flows = conn.execute(
            """SELECT date(t.created_at) AS day, sum(CASE WHEN t.kind='credit' THEN t.amount_cents ELSE -t.amount_cents END) AS net
               FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE a.user_id=%s AND t.created_at >= now()-interval '30 days'
               GROUP BY day""", (user["id"],)).fetchall()
    net = {str(row["day"]): row["net"] for row in flows}
    series, running = [], total
    for days in range(29, -1, -1):
        day = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
        running -= net.get(day, 0)
        series.append({"date": day, "balance_cents": running})
    return jsonify(byCategory=by_category, monthly=monthly, total_cents=total, balanceSeries=series)


@app.get("/api/admin/stats")
@admin_required
def admin_stats(user):
    with db() as conn:
        values = {
            "customers": conn.execute("SELECT count(*) AS value FROM users WHERE role='customer'").fetchone()["value"],
            "accounts": conn.execute("SELECT count(*) AS value FROM accounts").fetchone()["value"],
            "deposits_cents": conn.execute("SELECT coalesce(sum(balance_cents),0) AS value FROM accounts").fetchone()["value"],
            "transactions_24h": conn.execute("SELECT count(*) AS value FROM transactions WHERE created_at >= now()-interval '1 day'").fetchone()["value"],
            "failed_logins_24h": conn.execute("SELECT count(*) AS value FROM audit_log WHERE action IN ('login_failed','login_blocked') AND created_at >= now()-interval '1 day'").fetchone()["value"],
        }
    return jsonify(**values)


@app.get("/api/employee/overview")
@auth_required
def employee_overview(user):
    if user["role"] != "employee":
        return error("Forbidden", 403)
    with db() as conn:
        customers = conn.execute("SELECT count(*) AS value FROM users WHERE role='customer'").fetchone()["value"]
        verified = conn.execute(
            "SELECT count(*) AS value FROM pending_registrations WHERE requested_role='employee' AND status='pending'"
        ).fetchone()["value"]
    return jsonify(customers=customers, verified_employee_requests=verified)


@app.get("/api/admin/users")
@admin_required
def admin_users(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT u.id,u.full_name,u.email,u.role,u.status,u.created_at,
               coalesce((SELECT sum(balance_cents) FROM accounts WHERE user_id=u.id),0) AS balance_cents
               FROM users u ORDER BY u.id"""
        ).fetchall()
    return jsonify(users=rows)


@app.get("/api/admin/pending-employees")
@admin_required
def admin_pending_employees(user):
    with db() as conn:
        cleanup_pending_registrations(conn)
        rows = conn.execute(
            """SELECT id,full_name,email,created_at FROM pending_registrations
               WHERE requested_role='employee' AND status='pending' ORDER BY created_at"""
        ).fetchall()
    return jsonify(registrations=rows)


@app.get("/api/admin/pending-deposits")
@admin_required
def admin_pending_deposits(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.amount_cents,r.reference,r.worker_note,r.created_at,
                      w.full_name AS worker_name,u.full_name AS customer_name,
                      a.nickname AS account_name,a.iban
               FROM cash_deposit_requests r
               JOIN users w ON w.id=r.worker_id JOIN users u ON u.id=r.customer_id
               JOIN accounts a ON a.id=r.account_id
               WHERE r.status='pending' ORDER BY r.created_at"""
        ).fetchall()
    return jsonify(requests=rows)


@app.get("/api/admin/account-closures")
@admin_required
def admin_account_closures(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.customer_id,r.requested_at,u.full_name,u.email,
                      coalesce((SELECT sum(balance_cents) FROM accounts WHERE user_id=u.id),0) AS balance_cents
               FROM account_closure_requests r
               JOIN users u ON u.id=r.customer_id
               WHERE r.status='pending' AND u.role='customer'
               ORDER BY r.requested_at"""
        ).fetchall()
    return jsonify(requests=rows)


@app.post("/api/admin/account-closures/<int:request_id>/decision")
@admin_required
@csrf_required
def decide_account_closure(user, request_id):
    decision = request.json.get("decision")
    if decision not in {"approved", "rejected"}:
        return error("Decision must be approved or rejected.")
    with db() as conn:
        request_row = conn.execute(
            """SELECT r.*,u.email,u.role FROM account_closure_requests r
               JOIN users u ON u.id=r.customer_id
               WHERE r.id=%s FOR UPDATE""",
            (request_id,),
        ).fetchone()
        if not request_row or request_row["status"] != "pending":
            return error("Account closure request is not pending.", 404)
        if request_row["role"] != "customer":
            return error("Only customer accounts can be closed.", 403)
        if decision == "rejected":
            conn.execute(
                """UPDATE account_closure_requests
                   SET status='rejected',reviewed_by=%s,reviewed_at=now() WHERE id=%s""",
                (user["id"], request_id),
            )
            audit(conn, user["id"], "account_closure_rejected", request_row["email"])
            return jsonify(ok=True, status="rejected")
        conn.execute(
            "DELETE FROM cash_deposit_requests WHERE customer_id=%s",
            (request_row["customer_id"],),
        )
        conn.execute(
            "UPDATE audit_log SET user_id=NULL WHERE user_id=%s",
            (request_row["customer_id"],),
        )
        conn.execute(
            "DELETE FROM users WHERE id=%s AND role='customer'",
            (request_row["customer_id"],),
        )
        audit(conn, user["id"], "account_closed", request_row["email"])
    return jsonify(ok=True, status="approved")


@app.post("/api/admin/deposit-requests/<int:request_id>/decision")
@admin_required
@csrf_required
def decide_cash_deposit(user, request_id):
    decision = request.json.get("decision")
    note = clean(request.json.get("note"), 200)
    if decision not in {"approved", "rejected"}:
        return error("Decision must be approved or rejected.")
    with db() as conn:
        request_row = conn.execute(
            """SELECT r.*,w.full_name AS worker_name
               FROM cash_deposit_requests r JOIN users w ON w.id=r.worker_id
               WHERE r.id=%s FOR UPDATE""", (request_id,)
        ).fetchone()
        if not request_row or request_row["status"] != "pending":
            return error("Deposit request is not pending.", 404)
        if decision == "approved":
            account = conn.execute(
                "SELECT balance_cents FROM accounts WHERE id=%s AND user_id=%s FOR UPDATE",
                (request_row["account_id"], request_row["customer_id"]),
            ).fetchone()
            if not account:
                return error("Customer account not found.", 404)
            balance = account["balance_cents"] + request_row["amount_cents"]
            conn.execute("UPDATE accounts SET balance_cents=%s WHERE id=%s", (balance, request_row["account_id"]))
            conn.execute(
                """INSERT INTO transactions
                   (account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
                   VALUES(%s,'credit',%s,%s,%s,'Cash deposit','income',%s)""",
                (request_row["account_id"], request_row["amount_cents"], balance,
                 request_row["worker_name"], request_row["reference"]),
            )
        conn.execute(
            """UPDATE cash_deposit_requests
               SET status=%s,reviewed_by=%s,review_note=%s,reviewed_at=now()
               WHERE id=%s""",
            (decision, user["id"], note, request_id),
        )
        audit(conn, user["id"], f"cash_deposit_{decision}", f"{request_row['reference']} by worker {request_row['worker_id']}")
    return jsonify(ok=True, status=decision)


@app.get("/api/admin/worker-activity")
@admin_required
def admin_worker_activity(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.amount_cents,r.reference,r.status,r.created_at,r.reviewed_at,
                      w.full_name AS worker_name,u.full_name AS customer_name,
                      a.nickname AS account_name
               FROM cash_deposit_requests r
               JOIN users w ON w.id=r.worker_id JOIN users u ON u.id=r.customer_id
               JOIN accounts a ON a.id=r.account_id
               ORDER BY r.created_at DESC LIMIT 200"""
        ).fetchall()
    return jsonify(operations=rows)


@app.post("/api/admin/pending-employees/<int:registration_id>/approve")
@admin_required
@csrf_required
def approve_employee(user, registration_id):
    with db() as conn:
        cleanup_pending_registrations(conn)
        pending = conn.execute(
            "SELECT * FROM pending_registrations WHERE id=%s AND requested_role='employee' AND status='pending' FOR UPDATE",
            (registration_id,),
        ).fetchone()
        if not pending:
            return error("Employee registration not found.", 404)
        if conn.execute("SELECT 1 FROM users WHERE email=%s", (pending["email"],)).fetchone():
            return error("An account with this email already exists.", 409)
        employee = conn.execute(
            """INSERT INTO users(full_name,email,password_hash,role,totp_secret,totp_enabled)
               VALUES(%s,%s,%s,'employee',%s,%s) RETURNING id""",
            (
                pending["full_name"],
                pending["email"],
                pending["password_hash"],
                pending["totp_secret"],
                pending["totp_enabled"],
            ),
        ).fetchone()
        conn.execute("UPDATE pending_registrations SET status='approved' WHERE id=%s", (registration_id,))
        audit(conn, user["id"], "employee_approved", pending["email"])
    return jsonify(ok=True, user_id=employee["id"])


@app.post("/api/admin/pending-employees/<int:registration_id>/reject")
@admin_required
@csrf_required
def reject_employee(user, registration_id):
    with db() as conn:
        cleanup_pending_registrations(conn)
        pending = conn.execute(
            """SELECT id,email FROM pending_registrations
               WHERE id=%s AND requested_role='employee' AND status='pending'
               FOR UPDATE""",
            (registration_id,),
        ).fetchone()
        if not pending:
            return error("Employee registration not found.", 404)
        conn.execute(
            "UPDATE pending_registrations SET status='rejected' WHERE id=%s",
            (registration_id,),
        )
        audit(conn, user["id"], "employee_rejected", pending["email"])
    return jsonify(ok=True, status="rejected")


@app.post("/api/admin/users/<int:user_id>/status")
@admin_required
@csrf_required
def admin_status(user, user_id):
    status = "locked" if request.json.get("status") == "locked" else "active"
    if user_id == user["id"]:
        return error("You cannot change your own status.")
    with db() as conn:
        conn.execute("UPDATE users SET status=%s,failed_logins=0,locked_until=NULL WHERE id=%s", (status, user_id))
        audit(conn, user["id"], "admin_status", f"user {user_id} -> {status}")
    return jsonify(ok=True)


@app.get("/api/admin/audit")
@admin_required
def admin_audit(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT l.id,l.action,l.detail,l.ip,l.created_at,u.email FROM audit_log l
               LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 100"""
        ).fetchall()
    return jsonify(events=rows)


# ---------- additions: budgets, security activity, admin monitoring ----------
BUDGET_CATEGORIES = {"housing", "groceries", "dining", "transport", "utilities", "entertainment", "health", "shopping", "other"}
LARGE_TX_CENTS = 100000


@app.get("/api/budgets")
@auth_required
def list_budgets(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT b.id, b.category, b.limit_cents,
                      coalesce((SELECT sum(t.amount_cents) FROM transactions t JOIN accounts a ON a.id=t.account_id
                                WHERE a.user_id=b.user_id AND t.kind='debit' AND t.category=b.category
                                  AND t.created_at >= date_trunc('month', now())), 0) AS spent_cents
               FROM budgets b WHERE b.user_id=%s ORDER BY b.category""",
            (user["id"],),
        ).fetchall()
    return jsonify(budgets=rows)


@app.put("/api/budgets")
@auth_required
@csrf_required
def set_budget(user):
    category = clean(request.json.get("category"), 30)
    limit = parse_amount(request.json.get("limit"))
    if category not in BUDGET_CATEGORIES:
        return error("Choose a valid category.")
    if not limit or limit > 100000000:
        return error("Enter a valid monthly limit.")
    with db() as conn:
        conn.execute(
            """INSERT INTO budgets(user_id, category, limit_cents) VALUES(%s,%s,%s)
               ON CONFLICT (user_id, category) DO UPDATE SET limit_cents=EXCLUDED.limit_cents""",
            (user["id"], category, limit),
        )
        audit(conn, user["id"], "budget_set", f"{category} {limit}")
    return jsonify(ok=True)


@app.delete("/api/budgets/<int:budget_id>")
@auth_required
@csrf_required
def delete_budget(user, budget_id):
    with db() as conn:
        result = conn.execute("DELETE FROM budgets WHERE id=%s AND user_id=%s", (budget_id, user["id"]))
        if result.rowcount:
            audit(conn, user["id"], "budget_delete", str(budget_id))
    return (jsonify(ok=True), 200) if result.rowcount else error("Budget not found.", 404)


@app.get("/api/profile/activity")
@auth_required
def security_activity(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT action, detail, ip, created_at FROM audit_log
               WHERE user_id=%s AND action IN
                 ('login','login_failed','login_2fa_failed','password_change','profile_update','logout')
               ORDER BY id DESC LIMIT 15""",
            (user["id"],),
        ).fetchall()
    return jsonify(events=rows)


@app.get("/api/admin/monitor")
@admin_required
def admin_monitor(user):
    started = datetime.now(timezone.utc)
    with db() as conn:
        conn.execute("SELECT 1")
        latency_ms = round((datetime.now(timezone.utc) - started).total_seconds() * 1000, 1)
        one = lambda sql, *a: conn.execute(sql, a).fetchone()["v"]
        counts = {
            "locked_users": one("SELECT count(*) AS v FROM users WHERE status='locked'"),
            "frozen_cards": one("SELECT count(*) AS v FROM cards WHERE status IN ('frozen','blocked')"),
            "open_card_reports": one("SELECT count(*) AS v FROM unauthorized_card_reports WHERE status IN ('submitted','under_review')"),
            "open_card_requests": one("SELECT count(*) AS v FROM card_requests WHERE status='submitted'"),
            "new_users_7d": one("SELECT count(*) AS v FROM users WHERE created_at >= now()-interval '7 days'"),
            "volume_24h_cents": one("SELECT coalesce(sum(amount_cents),0) AS v FROM transactions WHERE kind='debit' AND created_at >= now()-interval '1 day'"),
        }
        large = conn.execute(
            """SELECT t.id, t.amount_cents, t.kind, t.counterparty, t.reference, t.created_at, u.email
               FROM transactions t JOIN accounts a ON a.id=t.account_id JOIN users u ON u.id=a.user_id
               WHERE t.amount_cents >= %s AND t.created_at >= now()-interval '7 days'
               ORDER BY t.created_at DESC LIMIT 20""",
            (LARGE_TX_CENTS,),
        ).fetchall()
        suspicious = conn.execute(
            """SELECT ip, count(*) AS failures, count(DISTINCT user_id) AS accounts
               FROM audit_log WHERE action IN ('login_failed','login_blocked') AND created_at >= now()-interval '1 day'
               GROUP BY ip HAVING count(*) >= 3 ORDER BY failures DESC LIMIT 10"""
        ).fetchall()
    return jsonify(db_latency_ms=latency_ms, counts=counts, large_transactions=large,
                   suspicious_ips=suspicious, large_threshold_cents=LARGE_TX_CENTS)


@app.get("/api/admin/card-reports")
@admin_required
def admin_card_reports(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id, r.reason, r.status, r.created_at, u.email, c.last4, t.amount_cents, t.merchant
               FROM unauthorized_card_reports r JOIN users u ON u.id=r.user_id
               JOIN cards c ON c.id=r.card_id JOIN card_transactions t ON t.id=r.card_transaction_id
               ORDER BY (r.status IN ('submitted','under_review')) DESC, r.created_at DESC LIMIT 50"""
        ).fetchall()
    return jsonify(reports=rows)


@app.post("/api/admin/card-reports/<int:report_id>/status")
@admin_required
@csrf_required
def admin_card_report_status(user, report_id):
    status = request.json.get("status")
    if status not in {"under_review", "resolved", "rejected"}:
        return error("Invalid status.")
    with db() as conn:
        result = conn.execute("UPDATE unauthorized_card_reports SET status=%s WHERE id=%s", (status, report_id))
        if not result.rowcount:
            return error("Report not found.", 404)
        audit(conn, user["id"], "admin_card_report", f"report {report_id} -> {status}")
    return jsonify(ok=True)


@app.get("/api/admin/card-requests")
@admin_required
def admin_card_requests(user):
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id, r.request_type, r.status, r.reason, r.created_at, u.email
               FROM card_requests r JOIN users u ON u.id=r.user_id
               ORDER BY (r.status='submitted') DESC, r.created_at DESC LIMIT 50"""
        ).fetchall()
    return jsonify(requests=rows)


@app.post("/api/admin/card-requests/<int:request_id>/status")
@admin_required
@csrf_required
def admin_card_request_status(user, request_id):
    status = request.json.get("status")
    if status not in {"approved", "rejected", "completed"}:
        return error("Invalid status.")
    with db() as conn:
        result = conn.execute("UPDATE card_requests SET status=%s WHERE id=%s", (status, request_id))
        if not result.rowcount:
            return error("Request not found.", 404)
        audit(conn, user["id"], "admin_card_request", f"request {request_id} -> {status}")
    return jsonify(ok=True)


def _audit_filtered(conn, limit):
    filters, args = ["1=1"], []
    if request.args.get("action"):
        filters.append("l.action = %s")
        args.append(clean(request.args["action"], 40))
    if request.args.get("q"):
        like = "%" + clean(request.args["q"], 50).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        filters.append("(u.email ILIKE %s OR l.detail ILIKE %s OR l.ip ILIKE %s)")
        args.extend([like, like, like])
    return conn.execute(
        f"""SELECT l.id,l.action,l.detail,l.ip,l.created_at,u.email FROM audit_log l
            LEFT JOIN users u ON u.id=l.user_id WHERE {' AND '.join(filters)} ORDER BY l.id DESC LIMIT %s""",
        args + [limit],
    ).fetchall()


@app.get("/api/admin/audit/search")
@admin_required
def admin_audit_search(user):
    with db() as conn:
        return jsonify(events=_audit_filtered(conn, 200))


@app.get("/api/admin/active-customers")
@admin_required
def admin_active_customers(user):
    period = request.args.get("period", "daily")
    query = clean(request.args.get("q"), 80)

    # VULNERABLE: period is no longer checked against a whitelist,
    # and is interpolated straight into the interval literal
    window = f"1 {period}"

    with db() as conn:
        # VULNERABLE: query is concatenated directly into the WHERE clause
        # instead of being passed as a bound parameter
        sql = f"""SELECT u.id, u.full_name, u.email, max(l.created_at) AS last_active_at
                FROM users u
                JOIN audit_log l ON l.user_id=u.id
                WHERE u.role='customer'
                  AND l.action='login'
                  AND l.created_at >= now() - interval '{window}'
                  AND (u.full_name ILIKE '%{query}%' OR u.email ILIKE '%{query}%')
                GROUP BY u.id, u.full_name, u.email
                ORDER BY last_active_at DESC, u.id
                LIMIT 200"""
        rows = conn.execute(sql).fetchall()

    return jsonify(period=period, active_customers=rows, count=len(rows))
@app.get("/api/admin/audit/export")
@admin_required
def admin_audit_export(user):
    with db() as conn:
        rows = _audit_filtered(conn, 5000)
        audit(conn, user["id"], "admin_audit_export", f"{len(rows)} rows")
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "time", "user", "action", "detail", "ip"])
    for r in rows:
        cells = [str(c) if c is not None else "" for c in (r["id"], r["created_at"], r["email"], r["action"], r["detail"], r["ip"])]
        writer.writerow(["'" + c if c[:1] in "=+-@" and c else c for c in cells])
    return app.response_class(out.getvalue(), mimetype="text/csv",
                              headers={"Content-Disposition": "attachment; filename=audit-log.csv"})


def create_account(conn, user_id, account_type, nickname, opening):
    account_type = "savings" if account_type == "savings" else "checking"
    iban = "WB" + str(secrets.randbelow(100)).zfill(2) + secrets.token_hex(8).upper()
    row = conn.execute(
        "INSERT INTO accounts (user_id,iban,type,nickname,balance_cents) VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (user_id, iban, account_type, nickname or ("Savings" if account_type == "savings" else "Main account"), opening),
    ).fetchone()
    if opening:
        conn.execute(
            """INSERT INTO transactions(account_id,kind,amount_cents,balance_after_cents,counterparty,description,category,reference)
               VALUES(%s,'credit',%s,%s,'WeBank','Welcome bonus','income',%s)""",
            (row["id"], opening, opening, new_ref()),
        )
    return row["id"]


def create_card(conn, account_id):
    expires = datetime.now(timezone.utc) + timedelta(days=365 * 4)
    conn.execute("INSERT INTO cards(account_id,last4,expires) VALUES(%s,%s,%s)", (account_id, str(secrets.randbelow(10000)).zfill(4), expires.strftime("%m/%y")))


@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def frontend(path):
    return send_from_directory(app.static_folder, path or "index.html")


def init_db():
    schema = open(os.path.join(BASE_DIR, "schema.sql"), encoding="utf-8").read()
    with db() as conn:
        conn.execute(schema)
        cleanup_pending_registrations(conn)
        if conn.execute("SELECT count(*) AS count FROM users").fetchone()["count"] == 0:
            totp_secret = "JBSWY3DPEHPK3PXP"
            demo = conn.execute(
                """INSERT INTO users(full_name,email,phone,password_hash,totp_secret,totp_enabled)
                   VALUES(%s,%s,%s,%s,%s,TRUE) RETURNING id""",
                (
                    "Sara Demo",
                    "demo@webank.demo",
                    "+39 000 000 0000",
                    bcrypt.hashpw(b"Demo#WeBank2026", bcrypt.gensalt()).decode(),
                    totp_secret,
                ),
            ).fetchone()
            checking = create_account(conn, demo["id"], "checking", "Main account", 0)
            savings = create_account(conn, demo["id"], "savings", "Rainy day fund", 150000)
            create_card(conn, checking)
            conn.execute("INSERT INTO beneficiaries(user_id,name,iban) VALUES(%s,%s,%s)", (demo["id"], "Landlord", "IT60X0542811101000000123456"))
            audit(conn, None, "seed", "database seeded")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "3000")))
