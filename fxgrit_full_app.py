from flask import Flask, request, redirect, url_for, render_template_string, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import sqlite3, os

app = Flask(__name__)
app.secret_key = "supersecretfxgrit"

DB_FILE = "fxgrit_users.db"

# ------------------ DB Helpers ------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, mobile TEXT, email TEXT, dob TEXT,
        nominee_name TEXT, nominee_dob TEXT,
        password_hash TEXT, mpin TEXT
    )''')
    conn.commit()
    conn.close()

def get_user_by_mobile(mobile):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE mobile=?", (mobile,))
    user = c.fetchone()
    conn.close()
    return user

# ------------------ Routes ------------------
@app.route("/")
def home():
    if "user" in session:
        user = session["user"]
        # Birthday check
        today = date.today().strftime("%m-%d")
        dob = user[4]  # dob in db
        wish = ""
        if dob and dob[5:] == today:
            wish = f"<div style='padding:10px;background:#fffae6;border:1px solid #ffcc00;'>🎉 Happy Birthday, {user[1]}! 🎂</div>"
        return f"""
        <h2>Welcome {user[1]} 👋</h2>
        {wish}
        <p>👉 <a href='/broker'>Add Broker</a></p>
        <p>👉 <a href='/payment'>Payment</a></p>
        <p>👉 <a href='/strategies'>Bot Strategies</a></p>
        <p><a href='/logout'>Logout</a></p>
        """
    return redirect(url_for("login"))

# ------------------ Register ------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        mobile = request.form["mobile"]
        email = request.form["email"]
        dob = request.form["dob"]
        nominee_name = request.form["nominee_name"]
        nominee_dob = request.form["nominee_dob"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        mpin = request.form["mpin"]

        if password != confirm_password:
            flash("❌ Passwords do not match!")
            return redirect(url_for("register"))

        if get_user_by_mobile(mobile):
            flash("❌ Mobile already registered!")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (name,mobile,email,dob,nominee_name,nominee_dob,password_hash,mpin) VALUES (?,?,?,?,?,?,?,?)",
                  (name, mobile, email, dob, nominee_name, nominee_dob, password_hash, mpin))
        conn.commit()
        conn.close()
        flash("✅ Registration successful! Please login.")
        return redirect(url_for("login"))

    return render_template_string("""
    <h2>FXGrit Registration</h2>
    <form method="post">
        Name: <input type="text" name="name" required><br>
        Mobile: <input type="text" name="mobile" required><br>
        Email: <input type="email" name="email" required><br>
        DOB: <input type="date" name="dob" required><br>
        Nominee Name: <input type="text" name="nominee_name" required><br>
        Nominee DOB: <input type="date" name="nominee_dob" required><br>
        Password: <input type="password" id="pwd" name="password" required>
        <input type="checkbox" onclick="togglePwd()"> Show<br>
        Confirm Password: <input type="password" name="confirm_password" required><br>
        MPIN (4 digit): <input type="password" pattern="\\d{4}" maxlength="4" name="mpin" required><br>
        <input type="submit" value="Register">
    </form>
    <script>
    function togglePwd(){
        var p = document.getElementById("pwd");
        p.type = (p.type === "password") ? "text" : "password";
    }
    </script>
    <p>Already have account? <a href='/login'>Login</a></p>
    """)

# ------------------ Login ------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        mobile = request.form["mobile"]
        password = request.form.get("password")
        mpin = request.form.get("mpin")

        user = get_user_by_mobile(mobile)
        if not user:
            flash("❌ User not found!")
            return redirect(url_for("login"))

        if password and check_password_hash(user[7], password):
            session["user"] = user
            return redirect(url_for("home"))
        elif mpin and mpin == user[8]:
            session["user"] = user
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid credentials")
            return redirect(url_for("login"))

    return render_template_string("""
    <h2>FXGrit Login</h2>
    <form method="post">
        Mobile: <input type="text" name="mobile" required><br>
        Password: <input type="password" name="password"><br>
        OR MPIN: <input type="password" pattern="\\d{4}" maxlength="4" name="mpin"><br>
        <button type="submit">Login</button>
    </form>
    <p>🔒 Fingerprint/FaceID authentication coming soon...</p>
    <p>No account? <a href='/register'>Register</a></p>
    """)

# ------------------ Logout ------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# ------------------ Placeholder Pages ------------------
@app.route("/broker")
def broker():
    return "<h2>🔗 Broker Integration Coming Soon...</h2>"

@app.route("/payment")
def payment():
    return "<h2>💳 Payment Gateway Coming Soon...</h2>"

@app.route("/strategies")
def strategies():
    return "<h2>🤖 Multiple Trading Strategies Coming Soon...</h2>"

# ------------------ Main ------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
