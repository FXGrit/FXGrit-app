import os, sqlite3, secrets, hmac, hashlib, base64, json
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    session, flash
)

# -------------------
# CONFIG
# -------------------
app = Flask(__name__)
app.secret_key = "fxgrit_super_secret"  
DB_FILE = "fxgrit_users.db"
MPIN_LENGTH = 4

# -------------------
# DB INIT
# -------------------
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            mpin_hash TEXT NOT NULL,
            reset_code TEXT,
            reset_expiry DATETIME
        )
        """)

def hash_mpin(mpin: str) -> str:
    return hashlib.sha256(mpin.encode()).hexdigest()

init_db()

# -------------------
# HELPERS
# -------------------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

# -------------------
# HTML TEMPLATES
# -------------------
TEMPLATE_LOGIN = """<!doctype html><html><head><meta charset="utf-8"><title>FXGrit - Login</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head>
<body class="p-4"><div class="container" style="max-width:480px">
<h3 class="mb-3">FXGrit - Login</h3>
{% with messages = get_flashed_messages() %}{% if messages %}<div>{% for m in messages %}<div class="alert alert-info">{{ m }}</div>{% endfor %}</div>{% endif %}{% endwith %}
<form method="post" action="{{ url_for('login') }}">
  <div class="mb-2"><label class="form-label">Username</label><input name="username" class="form-control" required></div>
  <div class="mb-2"><label class="form-label">MPIN ({{ mpin_length }} digits)</label>
    <input name="mpin" type="password" inputmode="numeric" pattern="\\d{{{{ mpin_length }}}}" maxlength="{{ mpin_length }}" class="form-control" required>
  </div>
  <button class="btn btn-primary">Login</button>
  <a href="{{ url_for('set_mpin') }}" class="btn btn-link">Set MPIN</a>
  <a href="{{ url_for('reset_request') }}" class="btn btn-link">Reset MPIN</a>
</form>
</div></body></html>"""

TEMPLATE_SET_MPIN = """<!doctype html><html><head><meta charset="utf-8"><title>Set MPIN</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head>
<body class="p-4"><div class="container" style="max-width:480px">
<h3>Set MPIN</h3>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="alert alert-info">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<form method="post">
  <div class="mb-2"><label>Username</label><input name="username" class="form-control" required></div>
  <div class="mb-2"><label>New MPIN ({{ mpin_length }} digits)</label><input name="new_mpin" type="password" maxlength="{{ mpin_length }}" class="form-control" required></div>
  <button class="btn btn-success">Save</button>
</form>
</div></body></html>"""

TEMPLATE_RESET_REQUEST = """<!doctype html><html><head><meta charset="utf-8"><title>Reset MPIN</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head>
<body class="p-4"><div class="container" style="max-width:480px">
<h3>Reset MPIN (Demo OTP)</h3>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="alert alert-info">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<form method="post">
  <div class="mb-2"><label>Username</label><input name="username" class="form-control" required></div>
  <button class="btn btn-primary">Send Reset Code</button>
</form>
</div></body></html>"""

TEMPLATE_VERIFY_RESET = """<!doctype html><html><head><meta charset="utf-8"><title>Verify Reset Code</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head>
<body class="p-4"><div class="container" style="max-width:480px">
<h3>Enter Reset Code & New MPIN</h3>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="alert alert-info">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<form method="post">
  <div class="mb-2"><label>Username</label><input name="username" class="form-control" required></div>
  <div class="mb-2"><label>Code</label><input name="code" class="form-control" required></div>
  <div class="mb-2"><label>New MPIN ({{ mpin_length }} digits)</label><input name="new_mpin" type="password" maxlength="{{ mpin_length }}" class="form-control" required></div>
  <div class="mb-2"><label>Confirm MPIN</label><input name="confirm_mpin" type="password" maxlength="{{ mpin_length }}" class="form-control" required></div>
  <button class="btn btn-success">Reset MPIN</button>
</form>
</div></body></html>"""

TEMPLATE_DASHBOARD = """<!doctype html><html><head><meta charset="utf-8"><title>Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head>
<body class="p-4"><div class="container" style="max-width:720px">
<h3>Welcome, {{ username }}</h3>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="alert alert-info">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<p>यहाँ से आप अपने app के अंदर की features जोड़ सकते हैं — trading signals, profile, आदि।</p>
<a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
</div></body></html>"""

# -------------------
# ROUTES
# -------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        mpin = request.form["mpin"]
        with sqlite3.connect(DB_FILE) as conn:
            row = conn.execute("SELECT mpin_hash FROM users WHERE username=?", (username,)).fetchone()
        if row and row[0] == hash_mpin(mpin):
            session["username"] = username
            flash("Login successful ✅")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or MPIN ❌")
    return render_template_string(TEMPLATE_LOGIN, mpin_length=MPIN_LENGTH)

@app.route("/set_mpin", methods=["GET", "POST"])
def set_mpin():
    if request.method == "POST":
        username = request.form["username"]
        new_mpin = request.form["new_mpin"]
        if len(new_mpin) != MPIN_LENGTH:
            flash("MPIN must be {} digits".format(MPIN_LENGTH))
            return redirect(url_for("set_mpin"))
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("REPLACE INTO users (username, mpin_hash) VALUES (?, ?)",
                         (username, hash_mpin(new_mpin)))
        flash("MPIN set successfully ✅")
        return redirect(url_for("login"))
    return render_template_string(TEMPLATE_SET_MPIN, mpin_length=MPIN_LENGTH)

@app.route("/reset_request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        username = request.form["username"]
        code = secrets.token_hex(3)  
        expiry = datetime.now() + timedelta(minutes=5)
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE users SET reset_code=?, reset_expiry=? WHERE username=?",
                         (code, expiry.isoformat(), username))
        flash(f"Reset code for {username}: {code} (valid 5 min)")
        return redirect(url_for("verify_reset"))
    return render_template_string(TEMPLATE_RESET_REQUEST)

@app.route("/verify_reset", methods=["GET", "POST"])
def verify_reset():
    if request.method == "POST":
        username = request.form["username"]
        code = request.form["code"]
        new_mpin = request.form["new_mpin"]
        confirm_mpin = request.form["confirm_mpin"]

        with sqlite3.connect(DB_FILE) as conn:
            row = conn.execute("SELECT reset_code, reset_expiry FROM users WHERE username=?",
                               (username,)).fetchone()
        if not row:
            flash("User not found ❌")
            return redirect(url_for("verify_reset"))

        db_code, db_expiry = row
        if db_code != code:
            flash("Invalid code ❌")
            return redirect(url_for("verify_reset"))
        if datetime.now() > datetime.fromisoformat(db_expiry):
            flash("Code expired ❌")
            return redirect(url_for("verify_reset"))
        if new_mpin != confirm_mpin:
            flash("MPIN mismatch ❌")
            return redirect(url_for("verify_reset"))
        if len(new_mpin) != MPIN_LENGTH:
            flash("MPIN must be {} digits".format(MPIN_LENGTH))
            return redirect(url_for("verify_reset"))

        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE users SET mpin_hash=?, reset_code=NULL, reset_expiry=NULL WHERE username=?",
                         (hash_mpin(new_mpin), username))
        flash("MPIN reset successful ✅")
        return redirect(url_for("login"))

    return render_template_string(TEMPLATE_VERIFY_RESET, mpin_length=MPIN_LENGTH)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(TEMPLATE_DASHBOARD, username=session["username"])

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out ✅")
    return redirect(url_for("login"))

# -------------------
if __name__ == "__main__":
    app.run(debug=True)
