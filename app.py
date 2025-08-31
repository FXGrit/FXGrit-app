# app.py
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os

# ---------- Config ----------
DB_PATH = "users.db"
SECRET_KEY = os.environ.get("FXGRIT_SECRET_KEY", "change_this_secret_in_prod")
MPIN_LENGTH = 6                # adjust if you want 4 or 6
MAX_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=5)
REMEMBER_DEVICE_DAYS = 30
OTP_EXPIRY = timedelta(minutes=5)
# ----------------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ---------- DB helpers ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        mpin_hash TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT DEFAULT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS trusted_devices (
        username TEXT,
        device_token TEXT PRIMARY KEY,
        created_at TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reset_codes (
        username TEXT,
        code TEXT,
        expires_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, mpin_hash, failed_attempts, locked_until FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "username": row[0],
            "mpin_hash": row[1],
            "failed_attempts": row[2],
            "locked_until": datetime.fromisoformat(row[3]) if row[3] else None
        }
    return None

def create_or_update_user(username, mpin_hash):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO users (username, mpin_hash, failed_attempts, locked_until) VALUES (?, ?, 0, NULL)",
                (username, mpin_hash))
    conn.commit()
    conn.close()

def update_failed_attempts(username, attempts, locked_until=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    locked_iso = locked_until.isoformat() if locked_until else None
    cur.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?", (attempts, locked_iso, username))
    conn.commit()
    conn.close()

def add_trusted_device(username, device_token):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO trusted_devices (username, device_token, created_at) VALUES (?, ?, ?)",
                (username, device_token, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def is_trusted_device(token):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username FROM trusted_devices WHERE device_token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def create_reset_code(username, code):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    expires = (datetime.now() + OTP_EXPIRY).isoformat()
    cur.execute("INSERT INTO reset_codes (username, code, expires_at) VALUES (?, ?, ?)", (username, code, expires))
    conn.commit()
    conn.close()

def verify_reset_code(username, code):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT code, expires_at FROM reset_codes WHERE username = ? ORDER BY rowid DESC LIMIT 1", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, "No code found"
    stored_code, expires_at = row
    if stored_code != code:
        return False, "Invalid code"
    if datetime.fromisoformat(expires_at) < datetime.now():
        return False, "Code expired"
    return True, "OK"

# initialize DB on first run
init_db()


# ---------- Routes ----------
@app.route('/')
def index():
    if session.get('username'):
        return redirect(url_for('dashboard'))
    # check remember-device cookie
    device_token = request.cookies.get('fxgrit_device')
    if device_token:
        username = is_trusted_device(device_token)
        if username:
            session['username'] = username
            flash("Logged in via trusted device.")
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        mpin = request.form.get('mpin', '').strip()
        remember = request.form.get('remember') == 'on'
        if not username or not mpin:
            flash("Username और MPIN दोनों चाहिए")
            return redirect(url_for('login'))

        user = get_user(username)
        if not user:
            flash("User not found. पहले MPIN सेट करें (Set MPIN).")
            return redirect(url_for('set_mpin'))

        # locked check
        if user['locked_until'] and datetime.now() < user['locked_until']:
            remaining = user['locked_until'] - datetime.now()
            flash(f"Account locked. Try after {int(remaining.total_seconds()//60)} minute(s).")
            return redirect(url_for('login'))

        # check mpin length
        if len(mpin) != MPIN_LENGTH or not mpin.isdigit():
            flash(f"MPIN should be {MPIN_LENGTH} digits.")
            return redirect(url_for('login'))

        if check_password_hash(user['mpin_hash'], mpin):
            # success
            update_failed_attempts(username, 0, None)
            session['username'] = username
            flash("MPIN Verified — Login Successful ✅")
            resp = make_response(redirect(url_for('dashboard')))
            if remember:
                # create device token and set cookie
                token = secrets.token_urlsafe(32)
                add_trusted_device(username, token)
                resp.set_cookie('fxgrit_device', token, max_age=REMEMBER_DEVICE_DAYS*24*3600, httponly=True, samesite='Lax')
            return resp
        else:
            # failed
            attempts = user['failed_attempts'] + 1
            locked_until = None
            if attempts >= MAX_ATTEMPTS:
                locked_until = datetime.now() + LOCK_DURATION
                update_failed_attempts(username, attempts, locked_until)
                flash(f"Account temporarily locked due to {MAX_ATTEMPTS} wrong attempts.")
            else:
                update_failed_attempts(username, attempts, None)
                flash(f"Wrong MPIN — Attempt {attempts} of {MAX_ATTEMPTS}")
            return redirect(url_for('login'))

    return render_template('login.html', mpin_length=MPIN_LENGTH)


@app.route('/set-mpin', methods=['GET', 'POST'])
def set_mpin():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        mpin = request.form.get('mpin', '').strip()
        mpin_confirm = request.form.get('mpin_confirm', '').strip()
        if not username or not mpin or not mpin_confirm:
            flash("All fields required")
            return redirect(url_for('set_mpin'))
        if mpin != mpin_confirm:
            flash("MPIN और Confirm MPIN match नहीं करते")
            return redirect(url_for('set_mpin'))
        if len(mpin) != MPIN_LENGTH or not mpin.isdigit():
            flash(f"MPIN should be {MPIN_LENGTH} digits.")
            return redirect(url_for('set_mpin'))
        mpin_hash = generate_password_hash(mpin)
        create_or_update_user(username, mpin_hash)
        flash("MPIN सेट हो गया — अब आप login कर सकते हैं")
        return redirect(url_for('login'))
    return render_template('set_mpin.html', mpin_length=MPIN_LENGTH)


@app.route('/dashboard')
def dashboard():
    if not session.get('username'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('fxgrit_device')
    flash("Logged out")
    return resp


# ---- Reset MPIN flow (demo OTP) ----
@app.route('/reset-request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = get_user(username)
        if not user:
            flash("User not found")
            return redirect(url_for('reset_request'))
        code = secrets.choice([str(secrets.randbelow(900000)+100000) for _ in range(1)])[0] if False else f"{secrets.randbelow(900000)+100000:06d}"
        # create_code
        create_reset_code(username, code)
        # In real app -> send code via email/SMS. For demo we will flash it (or print)
        flash(f"Reset code (demo): {code} — valid for {OTP_EXPIRY.seconds//60} min")
        # For production: send via email/SMS here
        return redirect(url_for('reset_verify'))
    return render_template('reset_request.html')

@app.route('/reset-verify', methods=['GET', 'POST'])
def reset_verify():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        code = request.form.get('code', '').strip()
        new_mpin = request.form.get('new_mpin', '').strip()
        confirm_mpin = request.form.get('confirm_mpin', '').strip()
        ok, msg = verify_reset_code(username, code)
        if not ok:
            flash(msg)
            return redirect(url_for('reset_verify'))
        if new_mpin != confirm_mpin:
            flash("MPIN और Confirm MPIN match नहीं करते")
            return redirect(url_for('reset_verify'))
        if len(new_mpin) != MPIN_LENGTH or not new_mpin.isdigit():
            flash(f"MPIN should be {MPIN_LENGTH} digits.")
            return redirect(url_for('reset_verify'))
        mpin_hash = generate_password_hash(new_mpin)
        create_or_update_user(username, mpin_hash)
        flash("MPIN reset हो गया — अब login करें")
        return redirect(url_for('login'))
    return render_template('reset_verify.html', mpin_length=MPIN_LENGTH)


# Biometric placeholder route (front-end will handle device biometric)
@app.route('/biometric-setup', methods=['POST'])
def biometric_setup():
    # Placeholder endpoint: in real mobile app, you'd register device biometric token / platform-specific key
    if not session.get('username'):
        return {"error": "not authenticated"}, 401
    # This is intentionally simple because biometric handling is platform-specific
    return {"status": "ok", "msg": "Biometric setup placeholder"}, 200

app = Flask(__name__)

# ✅ Home route
@app.route("/")
def home():
    return "<h1>✅ FXGrit App Running Successfully!</h1><p>Welcome to FXGrit.</p>"

# ✅ Login route (template optional)
@app.route("/login")
def login():
    try:
        return render_template("login.html")  # agar template available hai
    except:
        return "<h1>Login Page</h1><p>Template missing, but route working.</p>"

# ✅ 404 Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404 - Page Not Found</h1><p>URL galat hai ya exist nahi karta.</p>", 404

# ✅ 500 Error Handling
@app.errorhandler(500)
def server_error(e):
    return "<h1>500 - Server Error</h1><p>Kuch galat ho gaya, please check logs.</p>", 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
