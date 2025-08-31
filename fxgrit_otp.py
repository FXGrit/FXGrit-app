from flask import Flask, request, send_file
import pyotp, qrcode, io

app = Flask(__name__)

# Ek fixed secret (ya phir DB me per-user save karo)
SECRET_KEY = pyotp.random_base32()

@app.route("/")
def home():
    return "✅ FXGrit OTP System Running!"

# QR Code Generate
@app.route("/2fa")
def generate_2fa():
    totp = pyotp.TOTP(SECRET_KEY)
    uri = totp.provisioning_uri(name="fxgrit_user", issuer_name="FXGrit")

    # QR Code banao
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return send_file(buf, mimetype="image/png")

# OTP Verify
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    otp = request.form.get("otp")
    totp = pyotp.TOTP(SECRET_KEY)

    if totp.verify(otp):
        return "✅ OTP Verified Successfully!"
    else:
        return "❌ Invalid OTP!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
