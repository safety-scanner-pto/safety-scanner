"""
Safety Scanner - Flask backend
================================
Serves safety-scanner.html and powers:
  GET  /vt?url=...   -> VirusTotal verdict (VT_API_KEY env)
  GET  /ai-scan?url=...-> Gemini AI verdict (GEMINI_KEY env)
  POST /qr           -> decode QR image (pyzbar, falls back to OpenCV)
  POST /apk          -> analyze APK permissions/signature
  /admin             -> login-protected dashboard: scan totals, logs, block URLs

Developer API:
  A logged-in visitor can call GET /dev/api-key to get a personal key, then
  call the scan endpoints from their own code with header "X-API-Key: <key>"
  (or ?api_key=<key>) instead of a browser session/cookie. Example:
    curl -H "X-API-Key: sk_xxx" "https://your-app.onrender.com/vt?url=https://example.com"

Env vars:
  VT_API_KEY     VirusTotal API key (https://www.virustotal.com/gui/my-apikey)
  ADMIN_USER     admin panel username        (default: admin)
  ADMIN_PASS     admin panel password        (default: changeme)
  SECRET_KEY     Flask session secret        (default: random, set one in prod)
  PORT           port to bind                (Render sets this automatically)

Local run:
  pip install -r requirements.txt
  export VT_API_KEY=xxx ADMIN_USER=admin ADMIN_PASS=secret SECRET_KEY=xxx
  python app.py

Render:
  Build command: pip install -r requirements.txt
  Start command: gunicorn app:app
  (Procfile with "web: gunicorn app:app" also works)

Security notes (added):
  - MAX_CONTENT_LENGTH caps upload size so a huge file can't be used for a
    denial-of-service upload.
  - /admin/login is rate-limited (Flask-Limiter) to slow down password
    brute-forcing.
  - Set a strong, unique ADMIN_PASS in Render's environment - do not leave
    it as "changeme".
"""

import base64
import os
import io
import re
import time
import sqlite3
import hashlib
import zipfile
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, jsonify, send_from_directory, session,
    redirect, url_for, render_template_string, g
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# ------------------------------------------------------------------ #
# Config
# ------------------------------------------------------------------ #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")

VT_API_KEY = os.environ.get("VT_API_KEY", "") or os.environ.get("VIRUS_API_KEY", "")
GEMINI_KEY = os.environ.get("GEMINI_KEY", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
PORT = int(os.environ.get("PORT", 5000))
VT_BASE = "https://www.virustotal.com/api/v3"
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent"
)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = SECRET_KEY
CORS(app)

# Cap request body size (uploads) at 20 MB - blocks huge-file DoS attempts.
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],  # no global limit, only on routes we mark below
    storage_uri="memory://",
)


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large (max 20 MB)"}), 413


# ------------------------------------------------------------------ #
# DB helpers
# ------------------------------------------------------------------ #
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            target TEXT,
            result TEXT,
            risk INTEGER,
            ip TEXT,
            created_at TEXT NOT NULL,
            user_id INTEGER
        )
    """)
    # migrate older DBs that don't have user_id yet
    try:
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_scan(scan_type, target, result, risk):
    try:
        db = get_db()
        user_id = session.get("user_id")
        db.execute(
            "INSERT INTO scans (type, target, result, risk, ip, created_at, user_id) VALUES (?,?,?,?,?,?,?)",
            (scan_type, (target or "")[:500], (result or "")[:300], risk,
             request.remote_addr, datetime.utcnow().isoformat(), user_id)
        )
        db.commit()
    except Exception:
        pass  # logging must never break a scan


def is_blocked(url_str):
    db = get_db()
    rows = db.execute("SELECT pattern FROM blocked_urls").fetchall()
    u = url_str.lower()
    for row in rows:
        if row["pattern"].lower() in u:
            return True
    return False


# ------------------------------------------------------------------ #
# Frontend
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "safety-scanner.html")


@app.route("/manifest.json")
def manifest():
    return send_from_directory(BASE_DIR, "manifest.json", mimetype="application/manifest+json")


@app.route("/service-worker.js")
def service_worker():
    return send_from_directory(BASE_DIR, "service-worker.js", mimetype="application/javascript")


@app.route("/icon-192.png")
def icon_192():
    return send_from_directory(BASE_DIR, "icon-192.png", mimetype="image/png")


@app.route("/icon-512.png")
def icon_512():
    return send_from_directory(BASE_DIR, "icon-512.png", mimetype="image/png")

@app.route("/api/antivirus/scan")
def antivirus_api():
    return vt_check()

# ------------------------------------------------------------------ #
# /vt - VirusTotal URL check
# ------------------------------------------------------------------ #
@app.route("/vt")
def vt_check():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url missing"}), 400

    if is_blocked(url):
        log_scan("vt", url, "blocked", 10)
        return jsonify({"blocked": True, "message": "This URL is blocked by admin"}), 200

    if not VT_API_KEY:
        log_scan("vt", url, "no_api_key", None)
        return jsonify({"error": "VT_API_KEY not configured on server"}), 200

    headers = {"x-apikey": VT_API_KEY}
    try:
        sub = requests.post(f"{VT_BASE}/urls", data={"url": url}, headers=headers)
        # 409 matlab URL pehle se scan hai
        if sub.status_code == 409:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            rep = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
            rep.raise_for_status()
            data = rep.json()["data"]
            stats = data["attributes"]["last_analysis_stats"]
            return jsonify({"blocked": False, "stats": stats, "cached": True})

        sub.raise_for_status()
        analysis_id = sub.json()["data"]["id"]

        for _ in range(6):
            rep = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
            rep.raise_for_status()
            data = rep.json()["data"]
            if data["attributes"]["status"] == "completed":
                stats = data["attributes"]["stats"]
                result_text = (
                    f"malicious={stats.get('malicious',0)} "
                    f"suspicious={stats.get('suspicious',0)} "
                    f"harmless={stats.get('harmless',0)}"
                )
                log_scan("vt", url, result_text, stats.get("malicious", 0))
                return jsonify({"result": result_text, "stats": stats})
            time.sleep(2)

        log_scan("vt", url, "pending", None)
        return jsonify({"result": "Analysis still pending, try again shortly"})
    except requests.RequestException as e:
        log_scan("vt", url, f"error: {e}", None)
        return jsonify({"error": f"VirusTotal error: {e}"}), 200


# ------------------------------------------------------------------ #
# /ai-scan - Gemini-powered link analysis (uses server's GEMINI_KEY,
# so visitors never need their own key)
# ------------------------------------------------------------------ #
@app.route("/ai-scan")
@limiter.limit("20 per minute")
def ai_scan():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url missing"}), 400

    if is_blocked(url):
        log_scan("ai", url, "blocked", 10)
        return jsonify({"blocked": True, "message": "This URL is blocked by admin"}), 200

    if not GEMINI_KEY:
        log_scan("ai", url, "no_api_key", None)
        return jsonify({"error": "GEMINI_KEY server par set nahi hai"}), 200

    prompt = (
        "You are a cybersecurity assistant. Analyze this URL for phishing, "
        "scam or malware risk signs. Give a short verdict (Safe / Suspicious / "
        "Dangerous) with 2-3 bullet reasons. Keep it under 60 words.\n\n"
        f"URL: {url}"
    )

    try:
        resp = requests.post(
            f"{GEMINI_URL}?key={GEMINI_KEY}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "No response from AI")
        )
        log_scan("ai", url, "analyzed", None)
        return jsonify({"analysis": text})
    except requests.RequestException as e:
        log_scan("ai", url, f"error: {e}", None)
        return jsonify({"error": f"Gemini error: {e}"}), 200
    except (KeyError, IndexError):
        log_scan("ai", url, "parse_error", None)
        return jsonify({"error": "Gemini se response samajh nahi aaya"}), 200


# ------------------------------------------------------------------ #
# /qr - decode QR image (pyzbar primary, OpenCV fallback, never crash)
# ------------------------------------------------------------------ #
def decode_qr_pyzbar(img_bytes):
    from PIL import Image
    from pyzbar.pyzbar import decode as pyzbar_decode
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    results = pyzbar_decode(img)
    if results:
        return results[0].data.decode("utf-8", errors="replace")
    return None


def decode_qr_opencv(img_bytes):
    import numpy as np
    import cv2
    arr = np.frombuffer(img_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return None
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    return data or None


@app.route("/qr", methods=["POST"])
def qr_scan():
    file = request.files.get("image")
    if not file:
        return jsonify({"error": "no image uploaded"}), 400

    img_bytes = file.read()
    text = None
    errors = []

    try:
        text = decode_qr_pyzbar(img_bytes)
    except Exception as e:
        errors.append(f"pyzbar: {e}")

    if not text:
        try:
            text = decode_qr_opencv(img_bytes)
        except Exception as e:
            errors.append(f"opencv: {e}")

    if not text:
        log_scan("qr", file.filename, "no_qr_found", None)
        return jsonify({"error": "No QR code found in image"}), 200

    log_scan("qr", text, "decoded", None)
    return jsonify({"text": text})


# ------------------------------------------------------------------ #
# /apk - analyze APK permissions & signature
# ------------------------------------------------------------------ #
RISKY_PERMS = {
    "SEND_SMS": 3, "RECEIVE_SMS": 2, "READ_SMS": 3,
    "BIND_ACCESSIBILITY_SERVICE": 4, "SYSTEM_ALERT_WINDOW": 2,
    "REQUEST_INSTALL_PACKAGES": 2, "BIND_DEVICE_ADMIN": 3,
    "READ_CONTACTS": 1, "READ_CALL_LOG": 2, "RECORD_AUDIO": 1,
    "READ_PHONE_STATE": 1, "QUERY_ALL_PACKAGES": 1,
    "RECEIVE_BOOT_COMPLETED": 1, "ACCESS_FINE_LOCATION": 1,
    "CAMERA": 1, "MANAGE_EXTERNAL_STORAGE": 2,
    "BIND_NOTIFICATION_LISTENER_SERVICE": 3, "CALL_PHONE": 1,
    "PROCESS_OUTGOING_CALLS": 2,
}
PERM_RE = re.compile(r"android\.permission\.([A-Z_]+)")


@app.route("/apk", methods=["POST"])
def apk_scan():
    file = request.files.get("apk")
    if not file:
        return jsonify({"error": "no apk uploaded"}), 400

    try:
        raw = file.read()
        sha256 = hashlib.sha256(raw).hexdigest()

        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile:
            log_scan("apk", file.filename, "invalid_zip", None)
            return jsonify({"error": "Not a valid APK/zip file"}), 200

        names = zf.namelist()
        if "AndroidManifest.xml" not in names:
            log_scan("apk", file.filename, "no_manifest", None)
            return jsonify({"error": "AndroidManifest.xml not found - invalid APK"}), 200

        manifest_bytes = zf.read("AndroidManifest.xml")
        text_utf16 = manifest_bytes.decode("utf-16le", errors="ignore")
        text_latin = manifest_bytes.decode("latin1", errors="ignore")
        perms = set(PERM_RE.findall(text_utf16)) | set(PERM_RE.findall(text_latin))

        signed = any(re.match(r"^META-INF/.+\.(RSA|DSA|EC)$", n, re.I) for n in names)
        dex_count = sum(1 for n in names if re.match(r"^classes\d*\.dex$", n))
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and "/" in n[4:]})

        risk = 0
        risky_found = []
        for p in perms:
            w = RISKY_PERMS.get(p, 0)
            risk += w
            if w >= 2:
                risky_found.append(p)
        if not signed:
            risk += 2
        if dex_count > 3:
            risk += 1
        risk = min(risk, 10)

        verdict = "High risk" if risk >= 6 else "Medium risk" if risk >= 3 else "Low risk"
        pkg_match = re.search(r"([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)", text_latin)
        package = pkg_match.group(1) if pkg_match else file.filename

        log_scan("apk", package, verdict, risk)
        return jsonify({
            "package": package,
            "verdict": verdict,
            "risk_score": risk,
            "permissions": sorted(perms),
            "risky_permissions": risky_found,
            "signed": signed,
            "dex_files": dex_count,
            "native_libs": abis,
            "sha256": sha256,
            "size_bytes": len(raw),
        })
    except Exception as e:
        log_scan("apk", getattr(file, "filename", ""), f"error: {e}", None)
        return jsonify({"error": f"Could not analyze APK: {e}"}), 200


# ------------------------------------------------------------------ #
# Visitor accounts (sign up / login) - separate from admin login above
# ------------------------------------------------------------------ #
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


@app.route("/signup", methods=["POST"])
@limiter.limit("10 per minute")
def signup():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not USERNAME_RE.match(username):
        return jsonify({"error": "Username 3-20 characters, letters/numbers/underscore only"}), 200
    if len(password) < 6:
        return jsonify({"error": "Password kam se kam 6 characters ka ho"}), 200

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
            (username, generate_password_hash(password), datetime.utcnow().isoformat())
        )
        db.commit()
        session["user_id"] = cur.lastrowid
        session["username"] = username
        return jsonify({"ok": True, "username": username})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ye username pehle se liya gaya hai"}), 200


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Username ya password galat hai"}), 200

    session["user_id"] = row["id"]
    session["username"] = row["username"]
    return jsonify({"ok": True, "username": row["username"]})


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return jsonify({"ok": True})


@app.route("/me")
def me():
    if session.get("user_id"):
        return jsonify({"logged_in": True, "username": session.get("username")})
    return jsonify({"logged_in": False})


@app.route("/my-scans")
def my_scans():
    if not session.get("user_id"):
        return jsonify({"error": "Login required"}), 200
    db = get_db()
    rows = db.execute(
        "SELECT type, target, result, risk, created_at FROM scans "
        "WHERE user_id=? ORDER BY id DESC LIMIT 50",
        (session["user_id"],)
    ).fetchall()
    return jsonify({"scans": [dict(r) for r in rows]})


# ------------------------------------------------------------------ #
# Admin panel
# ------------------------------------------------------------------ #
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


LOGIN_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#1e293b;padding:32px;border-radius:14px;width:280px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
h2{margin:0 0 18px;text-align:center}
input{width:100%;padding:10px;margin:6px 0;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff;box-sizing:border-box}
button{width:100%;padding:10px;margin-top:10px;border:0;border-radius:8px;background:#6366f1;color:#fff;font-weight:700;cursor:pointer}
.err{color:#fca5a5;font-size:13px;text-align:center;margin-top:8px}
</style></head><body>
<form method="post">
<h2>🛡️ Admin Login</h2>
<input name="username" placeholder="Username" autofocus required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Login</button>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
</form></body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
.top{display:flex;justify-content:space-between;align-items:cente
