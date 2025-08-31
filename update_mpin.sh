from flask import Flask, request, render_template, redirect, url_for, flash, session
from datetime import datetime, timedelta
import hashlib

app = Flask(__name__)
app.secret_key = "YOUR_SECRET_KEY"

# 🔹 Simulated database
users_db = {
    "user1": {
        "mpin_hash": hashlib.sha256("1234".encode()).hexdigest(),  # Default MPIN = 1234
        "failed_attempts": 0,
        "locked_until": None
    }
}

MAX_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=5)  # Lock 5 minutes after max attempts


# 🔹 MPIN Update Route
@app.route('/update_mpin', methods=['GET', 'POST'])
def update_mpin():
    if 'username' not in session:
        flash("Please login first")
        return redirect(url_for('login'))

    username = session['username']
    user = users_db.get(username)

    if request.method == 'POST':
        old_mpin = request.form.get('old_mpin')
        new_mpin = request.form.get('new_mpin')

        # ✅ Account Lock Check
        if user['locked_until'] and datetime.now() < user['locked_until']:
            flash(f"Account locked. Try again after {user['locked_until'].strftime('%H:%M:%S')}")
            return redirect(url_for('update_mpin'))

        # ✅ Verify Old MPIN
        old_hash = hashlib.sha256(old_mpin.encode()).hexdigest()
        if old_hash == user['mpin_hash']:
            # Update with new MPIN
            user['mpin_hash'] = hashlib.sha256(new_mpin.encode()).hexdigest()
            user['failed_attempts'] = 0  # Reset wrong attempts
            flash("MPIN updated successfully ✅")
            return redirect(url_for('dashboard'))
        else:
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= MAX_ATTEMPTS:
                user['locked_until'] = datetime.now() + LOCK_DURATION
                flash("Account locked due to 5 wrong attempts ⛔")
            else:
                flash(f"Wrong MPIN! Attempt {user['failed_attempts']} of {MAX_ATTEMPTS}")
            return redirect(url_for('update_mpin'))

    return render_template("update_mpin.html")


# 🔹 Dummy Login Route (for testing)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        mpin = request.form.get("mpin")

        user = users_db.get(username)
        if not user:
            flash("User not found")
            return redirect(url_for('login'))

        # Account lock check
        if user['locked_until'] and datetime.now() < user['locked_until']:
            flash(f"Account locked. Try after {user['locked_until'].strftime('%H:%M:%S')}")
            return redirect(url_for('login'))

        mpin_hash = hashlib.sha256(mpin.encode()).hexdigest()
        if mpin_hash == user['mpin_hash']:
            session['username'] = username
            user['failed_attempts'] = 0
            flash("Login successful ✅")
            return redirect(url_for('dashboard'))
        else:
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= MAX_ATTEMPTS:
                user['locked_until'] = datetime.now() + LOCK_DURATION
                flash("Account temporarily locked ⛔")
            else:
                flash(f"Wrong MPIN attempt {user['failed_attempts']} of {MAX_ATTEMPTS}")
            return redirect(url_for('login'))

    return render_template("login.html")


# 🔹 Dummy Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return f"Welcome {session['username']} 🎉 | <a href='/update_mpin'>Update MPIN</a>"


if __name__ == "__main__":
    app.run(debug=True)
