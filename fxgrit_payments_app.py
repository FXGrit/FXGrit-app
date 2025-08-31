# fxgrit_payments_app.py
# FXGrit - Users/Login, Free Family (max 20 by Admin), Manual Payments with Screenshot,
# Admin Approve/Reject, Profile (change username/password), Optional Telegram notifications,
# Fixed QR support (if provided), otherwise dynamic UPI QR. SQLite DB auto-init.
#
# Default admin: username=admin, password=admin123  (override via env)

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, send_from_directory, session, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FXGRIT_SECRET_KEY", "fxgrit_secret_key_change_me")

# File uploads
UPLOAD_FOLDER = os.environ.get("FXGRIT_UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

# UPI & pricing
UPI_ID = os.environ.get("FXGRIT_UPI_ID", "7669980001@upi")
DEFAULT_AMOUNT = int(os.environ.get("FXGRIT_DEFAULT_AMOUNT", "999"))  # ₹999

# Admin defaults (only for bootstrap)
DEFAULT_ADMIN_USER = os.environ.get("FXGRIT_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("FXGRIT_ADMIN_PASS", "admin123")

# Optional Telegram notify
TG_BOT = os.environ.get("FXGRIT_TG_BOT_TOKEN")     # e.g., 123456:ABC-xyz
TG_CHAT = os.environ.get("FXGRIT_TG_CHAT_ID")      # e.g., -100123456 or 123456

# Database
DB_PATH = os.environ.get("FXGRIT_DB_PATH", "fxgrit_payments.db")

# Fixed QR file (if you want to FORCE your given QR image)
QR_FILE = os.environ.get("FXGRIT_QR_FILE")  # e.g. "uploads/fxgrit_qr.png"


# -----------------------------------------------------------------------------
# DB Helpers & Init
# -----------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',  -- 'admin' or 'user'
                is_free INTEGER NOT NULL DEFAULT 0, -- 1 = free family
                phone TEXT,
                email TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                amount INTEGER NOT NULL,
                utr TEXT NOT NULL,
                screenshot TEXT,
                status TEXT NOT NULL,      -- Pending | Approved | Rejected
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

        # Bootstrap admin if not exists
        row = conn.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, is_free, created_at) VALUES (?, ?, 'admin', 1, ?)",
                (DEFAULT_ADMIN_USER, generate_password_hash(DEFAULT_ADMIN_PASS), datetime.now().isoformat(timespec="seconds"))
            )
            conn.commit()

# Initialize DB at import
init_db()


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file_storage):
    """Save uploaded screenshot/PDF securely and return stored filename (not full path)."""
    if not file_storage or file_storage.filename == "":
        return ""
    if not allowed_file(file_storage.filename):
        raise ValueError("Only png, jpg, jpeg, gif, pdf allowed.")
    safe_name = secure_filename(file_storage.filename)
    ts = datetime.now().strftime("%Y%m%d%H%M%S%f")
    root, ext = os.path.splitext(safe_name)
    stored = f"{root}_{ts}{ext}"
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
    return stored

def send_telegram(msg: str):
    """Optional Telegram notification; ignore failures."""
    if not TG_BOT or not TG_CHAT:
        return
    try:
        import urllib.parse, urllib.request
        api = f"https://api.telegram.org/bot{TG_BOT}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": msg}).encode()
        req = urllib.request.Request(api, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=8):
            pass
    except Exception:
        pass

def login_required(f):
    @wraps(f)
    def _w(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return _w

def admin_required(f):
    @wraps(f)
    def _w(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return _w

def current_user():
    if not session.get("user_id"):
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

# -----------------------------------------------------------------------------
# Styles (Dark)
# -----------------------------------------------------------------------------
BASE_CSS = """
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:0;background:#0d1117;color:#e6edf3}
  .wrap{max-width:980px;margin:0 auto;padding:28px}
  .card{background:#161b22;border-radius:16px;padding:24px}
  a{color:#58a6ff;text-decoration:none}
  input,button,select{width:100%;padding:12px;margin:8px 0;border-radius:10px;border:1px solid #30363d;background:#0d1117;color:#e6edf3}
  button{cursor:pointer}
  .btn{display:inline-block;padding:10px 16px;border-radius:10px;background:#1f6feb;color:#fff;border:0}
  .btn.success{background:#238636}
  .btn.danger{background:#a40e26}
  .btn.gray{background:#6e7681}
  .pill{padding:4px 8px;border-radius:999px}
  .Pending{background:#3d2c15}
  .Approved{background:#132d18}
  .Rejected{background:#3b1212}
  .muted{color:#9da7b1}
  .msg{margin:8px 0;padding:10px;border-radius:8px}
  .ok{background:#132d18}
  .err{background:#3b1212}
  table{width:100%;border-collapse:collapse}
  th,td{border:1px solid #30363d;padding:8px;text-align:center}
  th{background:#161b22}
  img.qr{display:block;margin:10px auto;border-radius:12px;max-width:240px}
  .topbar{display:flex;gap:10px;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap}
"""

# -----------------------------------------------------------------------------
# Home
# -----------------------------------------------------------------------------
@app.route("/")
@login_required
def home():
    user = current_user
    return render_template_string("""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>FXGrit</title>
<style>{BASE_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>FXGrit</h1>
    <p>Login/Registration • Free Family (Admin only)</p>
    <div class="topbar">
      <div>
        <a class="btn" href="{{ url_for('payment') }}">Payment</a>
        <a class="btn" href="{{ url_for('profile') }}">Profile</a>
      </div>
      <div>
        {% if user.is_authenticated %}
          <span class="muted">Logged in as <b>{{ user.username }}</b></span>
          <a class="btn gray" href="{{ url_for('logout') }}">Logout</a>
          {% if getattr(user, 'role', '') == 'admin' %}
            <a class="btn" href="{{ url_for('admin_dashboard') }}">Admin Dashboard</a>
            <a class="btn" href="{{ url_for('admin_payments') }}">Admin Payments</a>
          {% endif %}
        {% else %}
          <a class="btn" href="{{ url_for('login') }}">Login</a>
          <a class="btn" href="{{ url_for('register') }}">Register</a>
        {% endif %}
      </div>
    </div>
  </div>
</div>
</body>
</html>
""", user=user)

# -----------------------------------------------------------------------------
# Auth: Register / Login / Logout
# -----------------------------------------------------------------------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm  = request.form.get("confirm") or ""
        phone    = (request.form.get("phone") or "").strip()
        email    = (request.form.get("email") or "").strip()

        if not username or not password or password != confirm:
            flash("Invalid input or passwords do not match.", "error")
            return redirect(url_for("register"))

        with db() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, is_free, phone, email, created_at) VALUES (?, ?, 'user', 0, ?, ?, ?)",
                    (username, generate_password_hash(password), phone, email, datetime.now().isoformat(timespec="seconds"))
                )
                conn.commit()
            except sqlite3.IntegrityError:
                flash("Username already taken.", "error")
                return redirect(url_for("register"))

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template_string("""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Register</title>
<style>{{ BASE_CSS }}</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h2>Register</h2>
    {% with messages = get_flashed_messages(with_categories=True) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <p class="{{ cat }}">{{ msg }}</p>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <form method="POST">
      <input name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <input type="password" name="confirm" placeholder="Confirm Password" required>
      <input name="phone" placeholder="Phone (optional)">
      <input type="email" name="email" placeholder="Email (optional)">
      <button class="btn success">Create Account</button>
    </form>
    <p><a href="{{ url_for('login') }}">Already have an account? Login</a></p>
  </div>
</div>
</body>
</html>
""")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
        session["user_id"] = row["id"]
        session["role"] = row["role"]
        flash("Logged in successfully.", "success")
        return redirect(url_for("home"))

    return render_template_string("""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login</title>
  <style>{{ BASE_CSS }}</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2>Login</h2>
      {% with messages = get_flashed_messages(with_categories=True) %}
        {% if messages %}
          {% for cat, m in messages %}
            <div class="flash {{ cat }}">{{ m }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      <form method="POST">
        <input name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button class="btn">Login</button>
      </form>

      <p><a href="{{ url_for('register') }}">Create new account</a></p>
    </div>
  </div>
</body>
</html>
""")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -----------------------------------------------------------------------------
# Profile (Change username/password)
# -----------------------------------------------------------------------------
@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        new_username = (request.form.get("username") or "").strip()
        old_password = request.form.get("old_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm      = request.form.get("confirm") or ""

        if new_username and new_username != user["username"]:
            with db() as conn:
                try:
                    conn.execute("UPDATE users SET username=? WHERE id=?", (new_username, user["id"]))
                    conn.commit()
                    # update session username if desired (we only store user_id and role)
                except sqlite3.IntegrityError:
                    flash("Username already in use.", "error")
                    return redirect(url_for("profile"))
            flash("Username updated.", "success")

        if new_password:
            if new_password != confirm:
                flash("New password mismatch.", "error")
                return redirect(url_for("profile"))
            # admin can bypass old password check
            if session.get("role") != "admin":
                if not check_password_hash(user["password_hash"], old_password):
                    flash("Old password incorrect.", "error")
                    return redirect(url_for("profile"))
            with db() as conn:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(new_password), user["id"]))
                conn.commit()
            flash("Password updated.", "success")
        return redirect(url_for("profile"))

    return render_template_string("""
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Profile</title>
    <style>{BASE_CSS}</style>
</head>
<body>
<div class="wrap">
    <div class="card">
        <h2>My Profile</h2>
        {% with messages = get_flashed_messages(with_categories=True) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST">
            <label class="muted">Change Username</label>
            <input name="username" value="{{ user['username'] }}" required>

            <label class="muted">Change Password</label>
            <input type="password" name="old_password" placeholder="Old Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <input type="password" name="confirm" placeholder="Confirm Password" required>

            <button class="btn success">Save Changes</button>
        </form>
    </div>
</div>
</body>
</html>
""", user=user)

# -----------------------------------------------------------------------------
# Payment (requires login) - Free family bypass
# -----------------------------------------------------------------------------
@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    user = current_user()

    if request.method == "POST":
        # Get form values safely
        name = (request.form.get("name") or "").strip()
        utr = (request.form.get("utr") or "").strip()
        amount = (request.form.get("amount") or "").strip()

        # Validate inputs
        if not name or not utr or not amount:
            flash("Please enter valid Name, UTR, and Amount", "error")
            return redirect(url_for("payment"))

        # Validate amount is number
        try:
            amount_value = float(amount)
        except ValueError:
            flash("Amount must be a number", "error")
            return redirect(url_for("payment"))

        # Handle screenshot file (optional)
        screenshot_file = request.files.get("screenshot")
        stored_name = None
        if screenshot_file:
            try:
                stored_name = save_upload(screenshot_file)
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("payment"))

        # Insert into DB
        with db() as conn:
            conn.execute(
                "INSERT INTO payments (user_id, name, amount, utr, screenshot) VALUES (?, ?, ?, ?, ?)",
                (user["id"], name, amount_value, utr, stored_name)
            )
            conn.commit()

        flash("✅ Payment submitted! Admin will verify shortly.", "success")
        return redirect(url_for("payment"))

    # GET request: show the form
    return render_template_string("""
        <!doctype html>
        <html>
        <head><meta charset="utf-8"><title>Payment</title>
        <style>{BASE_CSS}</style></head>
        <body>
        <div class="wrap"><div class="card">
          <h2>Payment</h2>
          {% with messages = get_flashed_messages(with_categories=True) %}
            {% if messages %}
              {% for cat, msg in messages %}
                <p class="{{ cat }}">{{ msg }}</p>
              {% endfor %}
            {% endif %}
          {% endwith %}
          <form method="POST" enctype="multipart/form-data">
            <input name="name" placeholder="Enter Name" required>
            <input name="utr" placeholder="Enter UTR" required>
            <input name="amount" placeholder="Enter Amount" required>
            <input type="file" name="screenshot">
            <button class="btn">Submit Payment</button>
          </form>
        </div></div>
        </body>
        </html>
    """, user=user)

    # Show QR (fixed file or dynamic UPI link)
    fixed_qr_exists = bool(QR_FILE) and os.path.isfile(QR_FILE)
    if fixed_qr_exists:
        # if QR_FILE points inside upload folder, serve via uploaded_file route
        try:
            qr_src = url_for('uploaded_file', filename=os.path.basename(QR_FILE)) if os.path.dirname(QR_FILE) == UPLOAD_FOLDER \
                     else f"/{QR_FILE.lstrip('/')}"
        except Exception:
            qr_src = f"/{QR_FILE.lstrip('/')}"
    else:
        qr_src = (
            "https://api.qrserver.com/v1/create-qr-code/?"
            f"data=upi://pay?pa={UPI_ID}&pn=FXGrit&am={DEFAULT_AMOUNT}&cu=INR&size=220x220"
        )

    return render_template_string("""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>FXGrit - Payment</title>
    <style>{BASE_CSS}</style></head>
    <body><div class="wrap">
      <div class="card">
        <h2>💳 FXGrit Payment</h2>
        <p>Pay via UPI: <b>{{{{ upi }}}}</b> &nbsp; | &nbsp; Amount: <b>₹{{{{ default_amount }}}}</b></p>
        <img class="qr" src="{{{{ qr_url }}}}" alt="UPI QR Code">
        <p class="muted">Scan & Pay using BHIM/PhonePe/GPay/Paytm. Then submit details below.</p>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for cat, m in messages %}
              <div class="msg {{ 'ok' if cat=='success' else 'err' }}">{{ m }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="POST" enctype="multipart/form-data">
          <input type="text" name="name" placeholder="Your Name" value="{{ user['username'] }}" required>
          <input type="number" name="amount" placeholder="Amount Paid (₹)" required min="1" value="{{ default_amount }}">
          <input type="text" name="utr" placeholder="Transaction ID / UTR Number" required>
          <input type="file" name="screenshot" accept=".png,.jpg,.jpeg,.gif,.pdf" required>
          <button class="btn success" type="submit">Submit Payment</button>
        </form>
      </div>
    </div></body></html>
    """, upi=UPI_ID, default_amount=DEFAULT_AMOUNT, qr_url=qr_src, user=user)

# User payments history
@app.route("/payments/history")
@login_required
def payments_history():
    user = current_user()
    with db() as conn:
        rows = conn.execute("SELECT * FROM payments WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return render_template_string("""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>My Payments</title>
    <style>{BASE_CSS}</style></head>
    <body><div class="wrap"><div class="card">
      <h2>My Payments</h2>
      <table>
        <tr><th>ID</th><th>Amount (₹)</th><th>UTR</th><th>Screenshot</th><th>Created</th><th>Status</th></tr>
        {% for r in rows %}
          <tr>
            <td>{{ r.id }}</td>
            <td>{{ r.amount }}</td>
            <td>{{ r.utr }}</td>
            <td>
              {% if r.screenshot %}
                <a href="{{ url_for('uploaded_file', filename=r.screenshot) }}" target="_blank">
                  {% if r.screenshot.lower().endswith('.pdf') %}📄 PDF{% else %}📷 Image{% endif %}
                </a>
              {% else %} — {% endif %}
            </td>
            <td class="muted">{{ r.created_at }}</td>
            <td><span class="pill {{ r.status }}">{{ r.status }}</span></td>
          </tr>
        {% endfor %}
      </table>
    </div></div></body></html>
    """, rows=rows)

# -----------------------------------------------------------------------------
# Serve Uploads (basic)
# -----------------------------------------------------------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# -----------------------------------------------------------------------------
# Admin: Payments
# -----------------------------------------------------------------------------
@app.route("/admin/payments")
@admin_required
def admin_payments():
    with db() as conn:
        rows = conn.execute("""
            SELECT p.*, u.username AS uname
            FROM payments p LEFT JOIN users u ON p.user_id=u.id
            ORDER BY p.id DESC
        """).fetchall()
    return render_template_string("""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Admin - Payments</title>
    <style>{BASE_CSS}</style></head>
    <body><div class="wrap">
      <div class="topbar">
        <h2>📋 Payment Requests</h2>
        <div>
          <a class="btn gray" href="{{ url_for('home') }}">Home</a>
          <a class="btn" href="{{ url_for('admin_users') }}">Manage Users</a>
          <a class="btn danger" href="{{ url_for('logout') }}">Logout</a>
        </div>
      </div>
      <table>
        <tr>
          <th>ID</th><th>User</th><th>Name</th><th>Amount (₹)</th><th>UTR</th><th>Screenshot</th><th>Created</th><th>Status</th><th>Action</th>
        </tr>
        {% for r in rows %}
        <tr>
          <td>{{ r.id }}</td>
          <td>{{ r.uname or '—' }}</td>
          <td>{{ r.name }}</td>
          <td>{{ r.amount }}</td>
          <td>{{ r.utr }}</td>
          <td>
            {% if r.screenshot %}
              <a href="{{ url_for('uploaded_file', filename=r.screenshot) }}" target="_blank">
                {% if r.screenshot.lower().endswith('.pdf') %}
                  📄 PDF
                {% else %}
                  📷 Image
                {% endif %}
              </a>
            {% else %} — {% endif %}
          </td>
          <td class="muted">{{ r.created_at }}</td>
          <td><span class="pill {{ r.status }}">{{ r.status }}</span></td>
          <td>
            {% if r.status == 'Pending' %}
              <form method="POST" action="{{ url_for('admin_action') }}">
                <input type="hidden" name="id" value="{{ r.id }}">
                <button class="btn success" name="action" value="approve">Approve</button>
                <button class="btn danger"  name="action" value="reject">Reject</button>
              </form>
            {% else %} — {% endif %}
          </td>
        </tr>
        {% endfor %}
      </table>
    </div></body></html>
    """, rows=rows)

@app.route("/admin/action", methods=["POST"])
@admin_required
def admin_action():
    rid = request.form.get("id")
    action = request.form.get("action")
    if not rid or action not in ("approve", "reject"):
        abort(400)
    new_status = "Approved" if action == "approve" else "Rejected"
    with db() as conn:
        row = conn.execute("SELECT * FROM payments WHERE id = ?", (rid,)).fetchone()
        if not row:
            flash("Record not found.", "error")
            return redirect(url_for("admin_payments"))
        conn.execute("UPDATE payments SET status = ? WHERE id = ?", (new_status, rid))
        conn.commit()
    # Telegram notify
    try:
        msg = f"FXGrit Payment {new_status}\nID: {row['id']}\nUserID: {row['user_id']}\nName: {row['name']}\nAmount: ₹{row['amount']}\nUTR: {row['utr']}"
        send_telegram(msg)
    except Exception:
        pass
    flash(f"Marked as {new_status}.", "success")
    return redirect(url_for("admin_payments"))

# -----------------------------------------------------------------------------
# Admin: Users + Free Family (max 20)
# -----------------------------------------------------------------------------
@app.route("/admin/users", methods=["GET","POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        action = request.form.get("action")
        uid = request.form.get("user_id")
        if not uid:
            abort(400)

        with db() as conn:
            u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not u:
                flash("User not found.", "error")
                return redirect(url_for("admin_users"))

            if action == "toggle_free":
                # enforce max 20 free users
                if u["is_free"] == 0:
                    cnt = conn.execute("SELECT COUNT(*) AS c FROM users WHERE is_free=1").fetchone()["c"]
                    if cnt >= 20:
                        flash("Free family limit reached (20).", "error")
                        return redirect(url_for("admin_users"))
                    conn.execute("UPDATE users SET is_free=1 WHERE id=?", (uid,))
                    flash(f"User '{u['username']}' marked as FREE.", "success")
                else:
                    conn.execute("UPDATE users SET is_free=0 WHERE id=?", (uid,))
                    flash(f"User '{u['username']}' removed from FREE list.", "success")
                conn.commit()

            elif action == "make_admin":
                conn.execute("UPDATE users SET role='admin' WHERE id=?", (uid,))
                conn.commit()
                flash(f"User '{u['username']}' promoted to Admin.", "success")

            elif action == "make_user":
                conn.execute("UPDATE users SET role='user' WHERE id=?", (uid,))
                conn.commit()
                flash(f"User '{u['username']}' set to User.", "success")

            elif action == "reset_password":
                newp = request.form.get("new_password") or ""
                if len(newp) < 4:
                    flash("Password too short.", "error")
                else:
                    conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                                 (generate_password_hash(newp), uid))
                    conn.commit()
                    flash("Password reset.", "success")

        return redirect(url_for("admin_users"))

    # GET
    with db() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY role DESC, id DESC").fetchall()
        free_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE is_free=1").fetchone()["c"]

    return render_template_string("""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Admin - Users</title>
    <style>{BASE_CSS}</style></head>
    <body><div class="wrap">
      <div class="topbar">
        <h2>👥 Users (Free used: {{ free_count }}/20)</h2>
        <div>
          <a class="btn gray" href="{{ url_for('home') }}">Home</a>
          <a class="btn" href="{{ url_for('admin_payments') }}">Payments</a>
          <a class="btn danger" href="{{ url_for('logout') }}">Logout</a>
        </div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}{% for cat,m in messages %}<div class="msg {{ 'ok' if cat=='success' else 'err' }}">{{ m }}</div>{% endfor %}{% endif %}
      {% endwith %}

      <table>
        <tr>
          <th>ID</th><th>Username</th><th>Role</th><th>Free?</th><th>Phone</th><th>Email</th><th>Created</th><th>Actions</th>
        </tr>
        {% for u in users %}
          <tr>
            <td>{{ u.id }}</td>
            <td>{{ u.username }}</td>
            <td>{{ u.role }}</td>
            <td>{{ 'Yes' if u.is_free else 'No' }}</td>
            <td>{{ u.phone or '—' }}</td>
            <td>{{ u.email or '—' }}</td>
            <td class="muted">{{ u.created_at }}</td>
            <td>
              <form method="POST" style="display:inline">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <button class="btn {{ 'danger' if u.is_free else 'success' }}" name="action" value="toggle_free">
                  {{ 'Remove Free' if u.is_free else 'Make Free' }}
                </button>
              </form>
              {% if u.role != 'admin' %}
              <form method="POST" style="display:inline">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <button class="btn" name="action" value="make_admin">Make Admin</button>
              </form>
              {% else %}
              <form method="POST" style="display:inline">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <button class="btn" name="action" value="make_user">Make User</button>
              </form>
              {% endif %}
              <form method="POST" style="display:inline">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <input type="password" name="new_password" placeholder="New Password" required>
                <button class="btn" name="action" value="reset_password">Reset Password</button>
              </form>
            </td>
          </tr>
        {% endfor %}
      </table>
    </div></body></html>
    """, users=users, free_count=free_count)

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # For Termux/local dev
    # If you set FXGRIT_QR_FILE to a file under uploads>
    app.run(host="0.0.0.0", port=5000, debug=True)

