import os
import sqlite3
import secrets
import smtplib
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file
)
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ---- Configuration ----
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

if os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

# Folders
UPLOAD_FOLDER = "encrypted_files"
DECRYPTED_FOLDER = "decrypted_files"
TEMPLATE_FOLDER = "templates"
DB_NAME = "advanced_encryption.db"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(TEMPLATE_FOLDER, exist_ok=True)

# AES constants
CHUNK_SIZE = 64 * 1024
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 200_000

# Email configuration
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")

# Security controls
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 900
OTP_TTL_MIN = 10
OTP_REQUEST_COOLDOWN_SEC = 60

# File size/type limits
MAX_UPLOAD_MB = 25
ALLOWED_DECRYPT_EXT = {".enc"}

# ---- Utilities ----
def db():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            mobile TEXT,
            is_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_used INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            purpose TEXT DEFAULT 'login',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT,
            stored_filename TEXT,
            operation TEXT,
            ip TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_otp_user ON otp_codes(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_hist_user ON file_history(user_id)")
    conn.commit()
    conn.close()

init_db()

# Password hashing
def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()

def verify_password(stored_hash: str, salt: bytes, password: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_password(password, salt))

# OTP sending
def send_otp(email: str, otp: str, purpose: str = "login") -> bool:
    if not EMAIL_USER or not EMAIL_PASS:
        print("[ERROR] EMAIL_USER or EMAIL_PASS not configured.")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = EMAIL_USER
        msg["To"] = email
        msg["Subject"] = "Your OTP Code - Advanced Encryption Tool"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Advanced Encryption Tool</h2>
            <p>Your OTP code for {purpose}:</p>
            <h1 style="color: #06b6d4; letter-spacing: 5px;">{otp}</h1>
            <p>This code will expire in {OTP_TTL_MIN} minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, email, msg.as_string())
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send OTP: {e}")
        return False

def create_otp(user_id: int, purpose: str = "login") -> str:
    otp = str(secrets.randbelow(1_000_000)).zfill(6)
    expires_at = datetime.now() + timedelta(minutes=OTP_TTL_MIN)

    conn = db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO otp_codes (user_id, otp_code, expires_at, purpose) VALUES (?, ?, ?, ?)",
        (user_id, otp, expires_at, purpose)
    )
    conn.commit()
    conn.close()
    return otp

def verify_otp(user_id: int, otp: str, purpose: str = "login") -> bool:
    conn = db()
    c = conn.cursor()
    c.execute("""
        SELECT id, otp_code, expires_at, is_used, attempts 
        FROM otp_codes 
        WHERE user_id = ? AND purpose = ? AND is_used = 0
        ORDER BY created_at DESC LIMIT 1
    """, (user_id, purpose))
    row = c.fetchone()

    if not row:
        conn.close()
        return False

    otp_id, stored_otp, expires_at, is_used, attempts = row
    expires_at = datetime.fromisoformat(expires_at)

    if datetime.now() > expires_at:
        conn.close()
        return False

    if attempts >= 3:
        conn.close()
        return False

    c.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", (otp_id,))
    conn.commit()

    if hmac.compare_digest(stored_otp, otp):
        c.execute("UPDATE otp_codes SET is_used = 1 WHERE id = ?", (otp_id,))
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

# AES Encryption
def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        outfile.write(salt)
        outfile.write(iv)

        while True:
            chunk = infile.read(CHUNK_SIZE)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - len(chunk) % 16)
            outfile.write(cipher.encrypt(chunk))

# AES Decryption
def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as infile:
        salt = infile.read(SALT_SIZE)
        iv = infile.read(IV_SIZE)
        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(output_path, "wb") as outfile:
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                if len(chunk) < CHUNK_SIZE:
                    decrypted_chunk = decrypted_chunk.rstrip(b' ')
                outfile.write(decrypted_chunk)

def log_file_operation(user_id: int, original_filename: str, stored_filename: str, operation: str) -> None:
    conn = db()
    c = conn.cursor()
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    c.execute("""
        INSERT INTO file_history (user_id, original_filename, stored_filename, operation, ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, original_filename, stored_filename, operation, ip, user_agent))
    conn.commit()
    conn.close()

# ---- Routes ----

@app.route("/")
def index():
    if "user_id" in session and session.get("verified"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        mobile = request.form.get("mobile", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("signup.html")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if c.fetchone():
            flash("Username or email already exists.", "error")
            conn.close()
            return render_template("signup.html")

        salt = secrets.token_bytes(32)
        pwd_hash = hash_password(password, salt)

        try:
            c.execute("""
                INSERT INTO users (username, email, password_hash, salt, mobile)
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, pwd_hash, salt, mobile))
            conn.commit()
            user_id = c.lastrowid
            conn.close()

            otp = create_otp(user_id, "signup")
            send_otp(email, otp, "signup verification")

            session["pending_user_id"] = user_id
            session["pending_email"] = email
            flash("Account created! Check your email for OTP.", "success")
            return redirect(url_for("verify_otp_route"))
        except Exception as err:
            conn.close()
            flash(f"Error creating account: {err}", "error")
            return render_template("signup.html")

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT id, email, password_hash, salt FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            flash("Invalid credentials.", "error")
            return render_template("login.html")

        user_id, email, stored_hash, salt = row

        if not verify_password(stored_hash, salt, password):
            flash("Invalid credentials.", "error")
            return render_template("login.html")

        otp = create_otp(user_id, "login")
        send_otp(email, otp, "login")

        session["pending_user_id"] = user_id
        session["pending_email"] = email
        flash("OTP sent to your email.", "info")
        return redirect(url_for("verify_otp_route"))

    return render_template("login.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_route():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        user_id = session["pending_user_id"]

        if verify_otp(user_id, otp, "login") or verify_otp(user_id, otp, "signup"):
            conn = db()
            c = conn.cursor()
            c.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (user_id,))
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            username = c.fetchone()[0]
            conn.commit()
            conn.close()

            session.pop("pending_user_id", None)
            session.pop("pending_email", None)
            session["user_id"] = user_id
            session["username"] = username
            session["verified"] = True
            session.permanent = True

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired OTP.", "error")
            return render_template("verify-otp.html")

    return render_template("verify-otp.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session.get("username", "User")

    conn = db()
    c = conn.cursor()
    c.execute("""
        SELECT original_filename, operation, timestamp 
        FROM file_history 
        WHERE user_id = ? 
        ORDER BY timestamp DESC LIMIT 10
    """, (user_id,))
    history = c.fetchall()
    conn.close()

    return render_template("dashboard.html", username=username, history=history)

@app.route("/encrypt", methods=["POST"])
def encrypt():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("dashboard"))

    file = request.files["file"]
    password = request.form.get("password", "")

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("dashboard"))

    if not password:
        flash("Password is required for encryption.", "error")
        return redirect(url_for("dashboard"))

    if file.content_length and file.content_length > MAX_UPLOAD_MB * 1024 * 1024:
        flash(f"File too large. Max size: {MAX_UPLOAD_MB}MB.", "error")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(file.filename)
    timestamp = int(time.time())
    temp_filename = f"temp_{timestamp}_{original_filename}"
    encrypted_filename = f"enc_{timestamp}_{original_filename}.enc"

    temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)
    encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

    try:
        file.save(temp_path)
        encrypt_file(temp_path, encrypted_path, password)
        os.remove(temp_path)

        log_file_operation(session["user_id"], original_filename, encrypted_filename, "encrypt")

        flash("File encrypted successfully!", "success")
        return send_file(encrypted_path, as_attachment=True, download_name=f"{original_filename}.enc")
    except Exception as err:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        flash(f"Encryption failed: {err}", "error")
        return redirect(url_for("dashboard"))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("dashboard"))

    file = request.files["file"]
    password = request.form.get("password", "")

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("dashboard"))

    if not password:
        flash("Password is required for decryption.", "error")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(file.filename)

    if not any(original_filename.endswith(ext) for ext in ALLOWED_DECRYPT_EXT):
        flash("Only .enc files can be decrypted.", "error")
        return redirect(url_for("dashboard"))

    user_id = session["user_id"]
    conn = db()
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    email = c.fetchone()[0]
    conn.close()

    otp = create_otp(user_id, "decrypt")
    send_otp(email, otp, "decryption")

    timestamp = int(time.time())
    temp_enc_filename = f"temp_enc_{timestamp}_{original_filename}"
    temp_enc_path = os.path.join(DECRYPTED_FOLDER, temp_enc_filename)

    file.save(temp_enc_path)

    session["decrypt_file_path"] = temp_enc_path
    session["decrypt_password"] = password
    session["decrypt_original_filename"] = original_filename

    flash("OTP sent to your email for decryption verification.", "info")
    return redirect(url_for("verify_decrypt"))


# In your app.py
from flask import send_from_directory


@app.route('/verify-decrypt', methods=['GET', 'POST'])
def verify_decrypt():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))
    if "decrypt_file_path" not in session:
        flash("No decryption request found.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        user_id = session["user_id"]
        if verify_otp(user_id, otp, "decrypt"):
            temp_enc_path = session["decrypt_file_path"]
            password = session["decrypt_password"]
            original_filename = session["decrypt_original_filename"]

            decrypted_filename = original_filename.replace(".enc", "")
            timestamp = int(time.time())
            final_decrypted_filename = f"dec_{timestamp}_{decrypted_filename}"
            decrypted_path = os.path.join(DECRYPTED_FOLDER, final_decrypted_filename)

            try:
                decrypt_file(temp_enc_path, decrypted_path, password)
                os.remove(temp_enc_path)
                log_file_operation(
                    session["user_id"], original_filename, final_decrypted_filename, "decrypt"
                )
                session.pop("decrypt_file_path", None)
                session.pop("decrypt_password", None)
                session.pop("decrypt_original_filename", None)

                # Show download page
                flash("File decrypted successfully! Click below to download.", "success")
                return render_template("download_decrypted.html", download_filename=final_decrypted_filename)
            except Exception as err:
                if os.path.exists(temp_enc_path):
                    os.remove(temp_enc_path)
                flash(f"Decryption failed: {err}", "error")
                return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired OTP.", "error")
            return render_template("verify-decrypt.html")

    return render_template("verify-decrypt.html")


@app.route("/download/<filename>")
def download_file(filename):
    # After download, redirect to dashboard
    response = send_from_directory(DECRYPTED_FOLDER, filename, as_attachment=True)
    # Optional: schedule deletion of file after download
    return response


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your registered email.', 'error')
            return render_template('forgot_password.html')

        conn = db()
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        row = c.fetchone()
        if not row:
            flash('Email not found.', 'error')
            conn.close()
            return render_template('forgot_password.html')

        user_id = row[0]
        otp = create_otp(user_id, 'forgot_password')
        send_otp(email, otp, 'password reset')
        session['forgot_user_id'] = user_id
        session['forgot_email'] = email
        flash('OTP sent to your email.', 'info')
        conn.close()
        return redirect(url_for('verify_forgot_password_otp'))

    return render_template('forgot_password.html')

@app.route('/verify-forgot-password-otp', methods=['GET', 'POST'])
def verify_forgot_password_otp():
    if 'forgot_user_id' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        user_id = session['forgot_user_id']
        if verify_otp(user_id, otp, 'forgot_password'):
            flash('OTP verified! You can now reset your password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid or expired OTP.', 'error')
            return render_template('verify_forgot_password_otp.html')

    return render_template('verify_forgot_password_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'forgot_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not new_password or not confirm_password:
            flash('Enter and confirm your new password.', 'error')
            return render_template('reset_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        user_id = session['forgot_user_id']
        salt = secrets.token_bytes(32)
        pwd_hash = hash_password(new_password, salt)
        conn = db()
        c = conn.cursor()
        c.execute('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?', (pwd_hash, salt, user_id))
        conn.commit()
        conn.close()
        session.pop('forgot_user_id')
        session.pop('forgot_email')
        flash('Password reset successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


if __name__ == "__main__":
    print("=" * 80)
    print("🚀 ADVANCED ENCRYPTION TOOL")
    print("=" * 80)
    print("✓ Database initialized")
    print("✓ Starting Flask development server...")
    print("✓ Open your browser to: http://localhost:5000")
    print("=" * 80)
    app.run(host="0.0.0.0", port=5000, debug=True)