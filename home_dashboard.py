import os
from flask import Flask, request, redirect, url_for, flash, render_template_string, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
STATIC_FOLDER = os.path.join(BASE_DIR, "static")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "fxgrit_secret_key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["STATIC_FOLDER"] = STATIC_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DB_FILE = os.path.join(BASE_DIR, "fxgrit.db")

# --- Database helpers ---
def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_free INTEGER DEFAULT 0,
            role TEXT DEFAULT 'user'
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            amount INTEGER,
            utr TEXT,
            screenshot TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()

init_db()

# --- User class ---
class User(UserMixin):
    def __init__(self, id, username, is_free=0, role='user'):
        self.id = id
        self.username = username
        self.is_free = is_free
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            return User(user["id"], user["username"], user["is_free"], user["role"])
    return None

# --- Save uploaded file ---
def save_upload(file):
    if not file:
        raise ValueError("No file uploaded")
    filename = secure_filename(file.filename)
    if filename == "":
        raise ValueError("Invalid file")
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    return filename

# --- Routes ---
@app.route("/")
@login_required
def home():
    return render_template_string("""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>FXGrit Dashboard</title>
      <style>
        body { font-family: Arial; background: #f0f2f5; margin:0; padding:0; }
        .wrap { display:flex; justify-content:center; align-items:center; height:100vh; }
        .card { background:#fff; padding:30px; border-radius:12px; box-shadow:0 5px 25px rgba(0,0,0,0.1); text-align:center; width:400px; }
        img.logo { width:120px; margin-bottom:20px; }
        img.admin { width:60px; border-radius:50%; position:absolute; top:20px; right:20px; }
        a.btn { display:inline-block; margin:5px; padding:10px 20px; background:#007bff; color:#fff; text-decoration:none; border-radius:8px; }
        a.btn.gray { background:#6c757d; }
        h1,h2 { margin:10px 0; }
      </style>
    </head>
    <body>
      <img class="admin" src="{{ url_for('static', filename='admin_pic.png') }}">
      <div class="wrap">
        <div class="card">
          <img class="logo" src="{{ url_for('static', filename='fxgrit_logo.png') }}">
          <h1>FXGrit</h1>
          <h2>Welcome, {{ current_user.username }}!</h2>
          {% if current_user.is_free %}
            <p>✅ You are in FREE FAMILY list.</p>
          {% endif %}
          <div>
            <a class="btn" href="{{ url_for('payment') }}">Payment</a>
            <a class="btn" href="{{ url_for('profile') }}">Profile</a>
            <a class="btn gray" href="{{ url_for('logout') }}">Logout</a>
          </div>
          {% if current_user.role=='admin' %}
            <div>
              <a class="btn" href="#">Admin Dashboard</a>
              <a class="btn" href="#">Admin Payments</a>
            </div>
          {% endif %}
        </div>
      </div>
    </body>
    </html>
    """)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        confirm = (request.form.get("confirm") or "").strip()
        if not username or not password or password != confirm:
            flash("Username and password required / mismatch", "error")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password)
        try:
            with db() as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
                conn.commit()
            flash("Registration successful! Login now.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "error")
            return redirect(url_for("register"))
    return render_template_string("""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Register</title></head>
    <body>
      <div class="wrap"><div class="card">
      <h2>Register</h2>
      {% with messages = get_flashed_messages(with_categories=True) %}
        {% if messages %}
          {% for cat, msg in messages %}
            <p class="{{ cat }}">{{ msg }}</p>
          {% endfor %}
        {% endif %}
      {% endwith %}
      <form method="POST">
        <input name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <input type="password" name="confirm" placeholder="Confirm Password" required><br><br>
        <button class="btn">Create Account</button>
      </form>
      <p><a href="{{ url_for('login') }}">Already have an account? Login</a></p>
      </div></div>
    </body></html>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password"], password):
                login_user(User(user["id"], user["username"], user["is_free"], user["role"]))
                return redirect(url_for("home"))
        flash("Invalid username or password", "error")
        return redirect(url_for("login"))
    return render_template_string("""
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Login</title></head>
    <body>
      <div class="wrap"><div class="card">
      <h2>Login</h2>
      {% with messages = get_flashed_messages(with_categories=True) %}
        {% if messages %}
          {% for cat, msg in messages %}
            <p class="{{ cat }}">{{ msg }}</p>
          {% endfor %}
        {% endif %}
      {% endwith %}
      <form method="POST">
        <input name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button class="btn">Login</button>
      </form>
      <p><a href="{{ url_for('register') }}">Create new account</a></p>
      </div></div>
    </body></html>
    """)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        old_password = (request.form.get("old_password") or "").strip()
        new_password = (request.form.get("new_password") or "").strip()
        confirm = (request.form.get("confirm") or "").strip()
        if username:
            with db() as conn:
                conn.execute("UPDATE users SET username=? WHERE id=?", (username, current_user.id))
                conn.commit()
        if old_password and new_password and new_password == confirm:
            with db() as conn:
                user = conn.execute("SELECT * FROM users WHERE id=?", (current_user.id,)).fetchone()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
