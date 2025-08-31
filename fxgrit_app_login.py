import os, sqlite3, secrets, hmac, hashlib, base64, json
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template,
    session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

# Optional (only for Binance auto-exec demo). Safe to leave installed but not required for login flows.
try:
    from binance.client import Client as BinanceClient
except Exception:
    BinanceClient = None

# ====== App/Paths ======
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "fxgrit_app.db")
SECRET_PATH = os.path.join(APP_DIR, "secret.key")  # for encrypting API keys

app = Flask(__name__)
app.secret_key = os.environ.get("FXGRIT_FLASK_SECRET", "fxgrit_dev_secret_change_me")

# ====== AES-Fernet style simple helper (cryptography-free fallback) ======
# We'll use hashlib+HMAC based symmetric scheme (not full Fernet but good local-at-rest).
# If you prefer cryptography.fernet you can swap these two funcs with Fernet usage.

def _load_or_create_secret():
    if not os.path.exists(SECRET_PATH):
        key = secrets.token_bytes(32)
        with open(SECRET_PATH, "wb") as f:
            f.write(key)
    else:
        with open(SECRET_PATH, "rb") as f:
            key = f.read()
    return key

SECRET_KEY = _load_or_create_secret()

def _prf(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def enc_str(plain: str) -> str:
    salt = secrets.token_bytes(16)
    keystream = _prf(SECRET_KEY, salt)
    pt = plain.encode()
    ct = bytes(a ^ b for a, b in zip(pt, keystream[:len(pt)]))
    out = base64.urlsafe_b64encode(salt + ct).decode()
    return out

def dec_str(cipher: str) -> str:
    raw = base64.urlsafe_b64decode(cipher.encode())
    salt, ct = raw[:16], raw[16:]
    keystream = _prf(SECRET_KEY, salt)
    pt = bytes(a ^ b for a, b in zip(ct, keystream[:len(ct)])).decode()
    return pt

# ====== DB Setup ======
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()
    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      mpin_hash TEXT NOT NULL,
      biometric_enabled INTEGER DEFAULT 0,
      twofa_secret TEXT,               -- base32 shared secret for TOTP (or NULL)
      created_at TEXT,
      last_login_at TEXT,
      last_login_ip TEXT
    );
    """)
    # sessions (multi-device control; we invalidate old on new login)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      session_id TEXT NOT NULL,
      device_id TEXT,
      created_at TEXT,
      is_active INTEGER DEFAULT 1,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    # brokers
    cur.execute("""
    CREATE TABLE IF NOT EXISTS brokers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      broker_name TEXT NOT NULL,          -- e.g., Binance, Exness, ICMarkets, FXGritPaper
      api_key_enc TEXT,
      api_secret_enc TEXT,
      is_default INTEGER DEFAULT 0,
      risk_daily_max_loss REAL DEFAULT 0, -- 0 = off
      risk_max_position_size REAL DEFAULT 0, -- 0 = off
      created_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    # login logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      event TEXT,          -- LOGIN / LOGOUT / OTP_FAIL etc
      ip TEXT,
      at TEXT
    );
    """)

    con.commit()
    con.close()

init_db()

# ====== Helpers ======
def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def log_event(user_id, username, event, ip):
    con = db()
    con.execute("INSERT INTO login_logs (user_id, username, event, ip, at) VALUES (?,?,?,?,?)",
                (user_id, username, event, ip, now_iso()))
    con.commit()
    con.close()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    con = db()
    user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    return user

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def only_one_session_active(user_id, new_session_id):
    con = db()
    con.execute("UPDATE sessions SET is_active=0 WHERE user_id=?", (user_id,))
    con.execute("UPDATE sessions SET is_active=1 WHERE session_id=?", (new_session_id,))
    con.commit()
    con.close()

# ====== TOTP (2FA) without external lib ======
# Compatible with Google Authenticator if you set a Base32 secret
def _base32_decode(s: str) -> bytes:
    s = s.strip().replace(" ", "")
    # pad
    missing = (-len(s)) % 8
    s += "=" * missing
    return base64.b32decode(s, casefold=True)

def totp_now(secret_b32: str, digits=6, period=30) -> str:
    key = _base32_decode(secret_b32)
    counter = int(datetime.utcnow().timestamp() // period)
    msg = counter.to_bytes(8, "big")
    hs = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hs[-1] & 0x0F
    code = (int.from_bytes(hs[offset:offset+4], "big") & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)

def verify_totp(secret_b32: str, code: str, window=1) -> bool:
    try:
        for w in range(-window, window+1):
            counter = int(datetime.utcnow().timestamp() // 30) + w
            key = _base32_decode(secret_b32)
            msg = counter.to_bytes(8, "big")
            hs = hmac.new(key, msg, hashlib.sha1).digest()
            offset = hs[-1] & 0x0F
            calc = (int.from_bytes(hs[offset:offset+4], "big") & 0x7FFFFFFF) % (10**6)
            if str(calc).zfill(6) == str(code).zfill(6):
                return True
        return False
    except Exception:
        return False

def gen_base32_secret(length=20) -> str:
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode().replace("=", "")

# ====== Broker detection (basic) ======
def detect_broker(api_key: str) -> str:
    k = api_key.strip()
    if len(k) >= 32 and len(k) <= 128 and any(c.isalpha() for c in k) and any(c.isdigit() for c in k):
        return "Binance"
    return "Custom"

# ====== Routes ======

@app.route("/")
@login_required
def dashboard():
    u = current_user()
    con = db()
    brokers = con.execute("SELECT * FROM brokers WHERE user_id=? ORDER BY is_default DESC, id DESC", (u["id"],)).fetchall()
    last_logs = con.execute("SELECT * FROM login_logs WHERE user_id=? ORDER BY id DESC LIMIT 10", (u["id"],)).fetchall()
    con.close()
    return render_template("dashboard.html", username=u["username"], brokers=brokers, logs=last_logs)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    confirm_password = request.form.get("confirm_password","")
    mpin = request.form.get("mpin","").strip()
    confirm_mpin = request.form.get("confirm_mpin","").strip()
    biometric = 1 if request.form.get("biometric") == "on" else 0

    if not username or not password or not mpin:
        flash("All fields are required.", "danger")
        return redirect(url_for("register"))

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("register"))

    if not (mpin.isdigit() and len(mpin) == 4):
        flash("MPIN must be exactly 4 digits.", "danger")
        return redirect(url_for("register"))

    con = db()
    try:
        twofa_secret = gen_base32_secret()
        con.execute(
            "INSERT INTO users (username, password_hash, mpin_hash, biometric_enabled, twofa_secret, created_at) VALUES (?,?,?,?,?,?)",
            (username, generate_password_hash(password), generate_password_hash(mpin), biometric, twofa_secret, now_iso())
        )
        con.commit()
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))
    except sqlite3.IntegrityError:
        flash("Username already exists.", "warning")
        return redirect(url_for("register"))
    finally:
        con.close()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    mpin = request.form.get("mpin","").strip()
    otp = request.form.get("otp","").strip()  # 2FA code

    con = db()
    user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    # Password + MPIN both required (as you asked)
    ok_pass = check_password_hash(user["password_hash"], password) if password else False
    ok_mpin = (mpin.isdigit() and len(mpin)==4 and check_password_hash(user["mpin_hash"], mpin))
    if not (ok_pass and ok_mpin):
        flash("Password or MPIN incorrect.", "danger")
        log_event(user["id"], username, "LOGIN_FAIL", request.remote_addr)
        return redirect(url_for("login"))

    # 2FA required if secret present
    if user["twofa_secret"]:
        if not otp or not verify_totp(user["twofa_secret"], otp):
            flash("Invalid 2FA code.", "danger")
            log_event(user["id"], username, "OTP_FAIL", request.remote_addr)
            return redirect(url_for("login"))

    # login success
    session.clear()
    session["uid"] = user["id"]
    session["sid"] = secrets.token_urlsafe(24)
    device_id = request.headers.get("X-Device-Id") or request.cookies.get("fxgrit_device") or "web"
    con.execute("INSERT INTO sessions (user_id, session_id, device_id, created_at, is_active) VALUES (?,?,?,?,1)",
                (user["id"], session["sid"], device_id, now_iso()))
    con.execute("UPDATE users SET last_login_at=?, last_login_ip=? WHERE id=?",
                (now_iso(), request.remote_addr, user["id"]))
    con.commit()
    con.close()

    # multi-device control: keep latest session only
    only_one_session_active(user["id"], session["sid"])

    log_event(user["id"], username, "LOGIN", request.remote_addr)
    flash("Welcome back!", "success")
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    u = current_user()
    sid = session.get("sid")
    con = db()
    con.execute("UPDATE sessions SET is_active=0 WHERE session_id=?", (sid,))
    con.commit()
    con.close()

    log_event(u["id"], u["username"], "LOGOUT", request.remote_addr)
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# === TOTP QR provisioning (optional) ===
@app.route("/2fa")
@login_required
def show_2fa():
    u = current_user()
    # otpauth url (user can scan in Google Authenticator)
    issuer = "FXGrit"
    con = db()
    r = con.execute("SELECT twofa_secret FROM users WHERE id=?", (u["id"],)).fetchone()
    con.close()
    secret = r["twofa_secret"] or gen_base32_secret()
    # Ensure saved
    if not r["twofa_secret"]:
        con = db()
        con.execute("UPDATE users SET twofa_secret=? WHERE id=?", (secret, u["id"]))
        con.commit()
        con.close()
    label = f"{issuer}:{u['username']}"
    otpauth = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6&period=30"
    return jsonify({"secret": secret, "otpauth": otpauth})

# === Broker Setup ===
@app.route("/broker", methods=["GET","POST"])
@login_required
def broker():
    u = current_user()
    con = db()
    if request.method == "GET":
        brokers = con.execute("SELECT * FROM brokers WHERE user_id=? ORDER BY is_default DESC, id DESC", (u["id"],)).fetchall()
        con.close()
        return render_template("broker.html", username=u["username"], brokers=brokers)

    broker_name = request.form.get("broker_name","").strip()
    api_key = request.form.get("api_key","").strip()
    api_secret = request.form.get("api_secret","").strip()
    risk_daily_max_loss = float(request.form.get("risk_daily_max_loss","0") or 0)
    risk_max_position_size = float(request.form.get("risk_max_position_size","0") or 0)
    is_default = 1 if request.form.get("is_default") == "on" else 0

    if not broker_name:
        # auto detect from key if possible
        if api_key:
            broker_name = detect_broker(api_key)
        else:
            flash("Choose a broker or provide API key.", "warning")
            return redirect(url_for("broker"))

    api_key_enc = enc_str(api_key) if api_key else None
    api_secret_enc = enc_str(api_secret) if api_secret else None

    if is_default:
        con.execute("UPDATE brokers SET is_default=0 WHERE user_id=?", (u["id"],))
    con.execute("""
        INSERT INTO brokers (user_id, broker_name, api_key_enc, api_secret_enc, is_default, risk_daily_max_loss, risk_max_position_size, created_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (u["id"], broker_name, api_key_enc, api_secret_enc, is_default, risk_daily_max_loss, risk_max_position_size, now_iso()))
    con.commit()
    con.close()
    flash("Broker saved.", "success")
    return redirect(url_for("broker"))

@app.route("/broker/set_default/<int:broker_id>")
@login_required
def set_default_broker(broker_id):
    u = current_user()
    con = db()
    con.execute("UPDATE brokers SET is_default=0 WHERE user_id=?", (u["id"],))
    con.execute("UPDATE brokers SET is_default=1 WHERE id=? AND user_id=?", (broker_id, u["id"]))
    con.commit()
    con.close()
    flash("Default broker changed.", "success")
    return redirect(url_for("broker"))

@app.route("/broker/delete/<int:broker_id>")
@login_required
def delete_broker(broker_id):
    u = current_user()
    con = db()
    con.execute("DELETE FROM brokers WHERE id=? AND user_id=?", (broker_id, u["id"]))
    con.commit()
    con.close()
    flash("Broker removed.", "info")
    return redirect(url_for("broker"))

# === Signal Auto-Sync webhook (simple demo; Binance only if keys present) ===
@app.route("/webhook/signal", methods=["POST"])
def webhook_signal():
    # Expect JSON: { "username": "...", "symbol":"BTCUSDT", "side":"BUY/SELL", "qty":0.001 }
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    symbol = data.get("symbol")
    side = data.get("side","").upper()
    qty = float(data.get("qty", 0))

    if not all([username, symbol, side in ("BUY","SELL"), qty > 0]):
        return jsonify({"ok": False, "err": "invalid payload"}), 400

    con = db()
    user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        return jsonify({"ok": False, "err": "user not found"}), 404

    br = con.execute("SELECT * FROM brokers WHERE user_id=? AND is_default=1", (user["id"],)).fetchone()
    con.close()
    if not br:
        return jsonify({"ok": False, "err": "no default broker"}), 400

    broker_name = br["broker_name"]
    api_key = dec_str(br["api_key_enc"]) if br["api_key_enc"] else None
    api_secret = dec_str(br["api_secret_enc"]) if br["api_secret_enc"] else None

    # risk checks (placeholders)
    if br["risk_max_position_size"] and qty > br["risk_max_position_size"]:
        return jsonify({"ok": False, "err": "qty exceeds risk limit"}), 400

    # Execute (Binance example)
    if broker_name == "Binance" and BinanceClient and api_key and api_secret:
        try:
            client = BinanceClient(api_key, api_secret)
            if side == "BUY":
                # market buy
                client.create_order(symbol=symbol, side="BUY", type="MARKET", quantity=qty)
            else:
                client.create_order(symbol=symbol, side="SELL", type="MARKET", quantity=qty)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "err": str(e)}), 500

    # For non-Binance brokers, integrate their API here.
    return jsonify({"ok": True, "note": f"Executed placeholder for {broker_name}."})

# ====== Run ======
if __name__ == "__main__":
    # ensure templates path exists
    tdir = os.path.join(APP_DIR, "templates")
    os.makedirs(tdir, exist_ok=True)
    print("FXGrit App starting…")
    app.run(host="0.0.0.0", port=5001)
