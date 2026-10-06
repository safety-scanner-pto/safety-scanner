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
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
a.logout{color:#fca5a5;text-decoration:none}
.stats{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.stat{background:#1e293b;padding:16px 22px;border-radius:12px;min-width:120px}
.stat b{display:block;font-size:26px}
.stat span{color:#94a3b8;font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.box{background:#1e293b;border-radius:12px;padding:18px}
.box h3{margin-top:0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #334155}
th{color:#94a3b8;font-weight:600}
.risk-high{color:#fca5a5}.risk-mid{color:#fcd34d}.risk-low{color:#6ee7b7}
form.inline{display:flex;gap:8px;margin-bottom:14px}
input[type=text]{flex:1;padding:8px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff}
button{padding:8px 14px;border:0;border-radius:8px;background:#6366f1;color:#fff;cursor:pointer;font-weight:600}
button.del{background:#ef4444;padding:4px 10px;font-size:12px}
.scroll{max-height:420px;overflow:auto}
</style></head><body>
<div class="top"><h2>🛡️ Safety Scanner Admin</h2><a class="logout" href="{{ url_for('admin_logout') }}">Logout</a></div>

<div class="stats">
<div class="stat"><b>{{ total }}</b><span>Total scans</span></div>
<div class="stat"><b>{{ counts.get('vt',0) }}</b><span>Link scans</span></div>
<div class="stat"><b>{{ counts.get('qr',0) }}</b><span>QR scans</span></div>
<div class="stat"><b>{{ counts.get('apk',0) }}</b><span>APK scans</span></div>
<div class="stat"><b>{{ blocked|length }}</b><span>Blocked URLs</span></div>
</div>

<div class="grid">
<div class="box">
<h3>Block a URL / domain</h3>
<form class="inline" method="post" action="{{ url_for('admin_block') }}">
<input type="text" name="pattern" placeholder="e.g. bad-site.com" required>
<button type="submit">Block</button>
</form>
<div class="scroll">
<table><tr><th>Pattern</th><th>Added</th><th></th></tr>
{% for b in blocked %}
<tr><td>{{ b['pattern'] }}</td><td>{{ b['created_at'][:16] }}</td>
<td><form method="post" action="{{ url_for('admin_unblock', block_id=b['id']) }}">
<button class="del" type="submit">Remove</button></form></td></tr>
{% endfor %}
</table>
</div>
</div>

<div class="box">
<h3>Recent scans</h3>
<div class="scroll">
<table><tr><th>Type</th><th>Target</th><th>Result</th><th>Risk</th><th>Time</th></tr>
{% for s in logs %}
<tr>
<td>{{ s['type'] }}</td>
<td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ s['target'] }}</td>
<td>{{ s['result'] }}</td>
<td class="{{ 'risk-high' if (s['risk'] or 0) >= 6 else 'risk-mid' if (s['risk'] or 0) >= 3 else 'risk-low' }}">{{ s['risk'] if s['risk'] is not none else '-' }}</td>
<td>{{ s['created_at'][:16] }}</td>
</tr>
{% endfor %}
</table>
</div>
</div>
</div>
</body></html>
"""


@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if secrets.compare_digest(u, ADMIN_USER) and secrets.compare_digest(p, ADMIN_PASS):
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        return render_template_string(LOGIN_HTML, error="Invalid username or password")
    return render_template_string(LOGIN_HTML, error=None)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@login_required
def admin_dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
    rows = db.execute("SELECT type, COUNT(*) c FROM scans GROUP BY type").fetchall()
    counts = {r["type"]: r["c"] for r in rows}
    logs = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    blocked = db.execute("SELECT * FROM blocked_urls ORDER BY id DESC").fetchall()
    return render_template_string(
        DASHBOARD_HTML, total=total, counts=counts, logs=logs, blocked=blocked
    )


@app.route("/admin/block", methods=["POST"])
@login_required
def admin_block():
    pattern = request.form.get("pattern", "").strip().lower()
    if pattern:
        db = get_db()
        try:
            db.execute(
                "INSERT INTO blocked_urls (pattern, created_at) VALUES (?,?)",
                (pattern, datetime.utcnow().isoformat())
            )
            db.commit()
        except sqlite3.IntegrityError:
            pass  # already blocked
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/unblock/<int:block_id>", methods=["POST"])
@login_required
def admin_unblock(block_id):
    db = get_db()
    db.execute("DELETE FROM blocked_urls WHERE id=?", (block_id,))
    db.commit()
    return redirect(url_for("admin_dashboard"))


# ====================================================================== #
# NEW FEATURE (added below, old code above is untouched): Developer API
# Key - lets a logged-in visitor call /vt, /ai-scan, /qr, /apk from their
# own code using header "X-API-Key: <key>" instead of a browser session.
# ====================================================================== #

def migrate_api_key_column():
    """Adds the api_key column to an existing users table if missing."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("ALTER TABLE users ADD COLUMN api_key TEXT UNIQUE")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.close()


@app.before_request
def resolve_api_key():
    """Sets g.api_user_id if a valid X-API-Key header/param is present."""
    g.api_user_id = None
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if key:
        db = get_db()
        row = db.execute("SELECT id FROM users WHERE api_key=?", (key,)).fetchone()
        if row:
            g.api_user_id = row["id"]


def current_user_id():
    """Session login takes priority; falls back to API-key auth."""
    return session.get("user_id") or g.get("api_user_id")


def log_scan(scan_type, target, result, risk):
    """
    Overrides the earlier log_scan (above) so scans made via a developer
    API key also get attributed to that user, not just browser logins.
    """
    try:
        db = get_db()
        user_id = current_user_id()
        db.execute(
            "INSERT INTO scans (type, target, result, risk, ip, created_at, user_id) VALUES (?,?,?,?,?,?,?)",
            (scan_type, (target or "")[:500], (result or "")[:300], risk,
             request.remote_addr, datetime.utcnow().isoformat(), user_id)
        )
        db.commit()
    except Exception:
        pass


@app.route("/dev/api-key")
def dev_api_key():
    if not session.get("user_id"):
        return jsonify({"error": "Login required"}), 200
    db = get_db()
    row = db.execute("SELECT api_key FROM users WHERE id=?", (session["user_id"],)).fetchone()
    key = row["api_key"] if row else None
    if not key:
        key = "sk_" + secrets.token_hex(20)
        db.execute("UPDATE users SET api_key=? WHERE id=?", (key, session["user_id"]))
        db.commit()
    return jsonify({"api_key": key})


@app.route("/dev/api-key/regenerate", methods=["POST"])
@limiter.limit("5 per hour")
def dev_regenerate_key():
    if not session.get("user_id"):
        return jsonify({"error": "Login required"}), 200
    db = get_db()
    key = "sk_" + secrets.token_hex(20)
    db.execute("UPDATE users SET api_key=? WHERE id=?", (key, session["user_id"]))
    db.commit()
    return jsonify({"api_key": key})


# ====================================================================== #
# NEW FEATURE (added below, old code above is untouched): Sign in with
# Google / Sign in with GitHub. Users no longer need to invent a password -
# they log in with an account they already have, and we create/find a
# matching row in the same `users` table (password_hash is filled with an
# unusable random hash so the existing NOT NULL column is still satisfied).
#
# Setup needed (you do this once, outside the code):
#   Google: console.cloud.google.com -> APIs & Services -> Credentials ->
#     Create OAuth client ID (Web application). Authorized redirect URI:
#     https://<your-render-domain>/auth/google/callback
#     Set env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
#   GitHub: github.com/settings/developers -> New OAuth App.
#     Authorization callback URL:
#     https://<your-render-domain>/auth/github/callback
#     Set env vars: GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
# ====================================================================== #

from urllib.parse import urlencode

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")


def migrate_oauth_columns():
    """Adds oauth_provider/oauth_id/email columns to users if missing."""
    conn = sqlite3.connect(DB_PATH)
    for stmt in [
        "ALTER TABLE users ADD COLUMN oauth_provider TEXT",
        "ALTER TABLE users ADD COLUMN oauth_id TEXT",
        "ALTER TABLE users ADD COLUMN email TEXT",
    ]:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    conn.close()


def find_or_create_oauth_user(provider, provider_id, username_hint, email):
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?",
        (provider, provider_id)
    ).fetchone()
    if row:
        return row

    base = re.sub(r"[^a-zA-Z0-9_]", "", username_hint or provider)[:15] or provider
    candidate = base
    i = 1
    while db.execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
        candidate = f"{base}{i}"
        i += 1

    db.execute(
        "INSERT INTO users (username, password_hash, created_at, oauth_provider, oauth_id, email) "
        "VALUES (?,?,?,?,?,?)",
        (candidate, generate_password_hash(secrets.token_hex(32)),
         datetime.utcnow().isoformat(), provider, provider_id, email)
    )
    db.commit()
    return db.execute("SELECT * FROM users WHERE username=?", (candidate,)).fetchone()


# ---- Google ----
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


@app.route("/auth/google")
def auth_google():
    if not GOOGLE_CLIENT_ID:
        return "Google sign-in abhi configure nahi hai (GOOGLE_CLIENT_ID missing)", 200
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": url_for("auth_google_callback", _external=True),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    return redirect(GOOGLE_AUTH_URL + "?" + urlencode(params))


@app.route("/auth/google/callback")
def auth_google_callback():
    if request.args.get("state") != session.get("oauth_state"):
        return redirect("/")
    code = request.args.get("code")
    if not code:
        return redirect("/")
    try:
        token_resp = requests.post(GOOGLE_TOKEN_URL, data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": url_for("auth_google_callback", _external=True),
        }, timeout=15)
        access_token = token_resp.json().get("access_token")
        if not access_token:
            return redirect("/")
        info = requests.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"}, timeout=15
        ).json()
        user = find_or_create_oauth_user(
            "google", info.get("sub"), info.get("name") or (info.get("email") or "user").split("@")[0],
            info.get("email")
        )
        session["user_id"] = user["id"]
        session["username"] = user["username"]
    except requests.RequestException:
        pass
    return redirect("/")


# ---- GitHub ----
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@app.route("/auth/github")
def auth_github():
    if not GITHUB_CLIENT_ID:
        return "GitHub sign-in abhi configure nahi hai (GITHUB_CLIENT_ID missing)", 200
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": url_for("auth_github_callback", _external=True),
        "scope": "read:user user:email",
        "state": state,
    }
    return redirect(GITHUB_AUTH_URL + "?" + urlencode(params))


@app.route("/auth/github/callback")
def auth_github_callback():
    if request.args.get("state") != session.get("oauth_state"):
        return redirect("/")
    code = request.args.get("code")
    if not code:
        return redirect("/")
    try:
        token_resp = requests.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": url_for("auth_github_callback", _external=True),
            },
            headers={"Accept": "application/json"}, timeout=15
        )
        access_token = token_resp.json().get("access_token")
        if not access_token:
            return redirect("/")
        headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github+json"}
        info = requests.get(GITHUB_USER_URL, headers=headers, timeout=15).json()
        email = info.get("email")
        if not email:
            emails = requests.get(GITHUB_EMAILS_URL, headers=headers, timeout=15).json()
            primary = next((e for e in emails if e.get("primary")), None)
            email = (primary or {}).get("email")
        user = find_or_create_oauth_user(
            "github", str(info.get("id")), info.get("login"), email
        )
        session["user_id"] = user["id"]
        session["username"] = user["username"]
    except requests.RequestException:
        pass
    return redirect("/")


# ====================================================================== #
# NEW FEATURE (added below, old code above is untouched): the login form
# now says "Username or Gmail", so this overrides the /login route to also
# match on the stored email (from Google sign-in) in addition to username.
# ====================================================================== #
@limiter.limit("10 per minute")
def login_or_email():
    data = request.get_json(silent=True) or request.form
    identifier = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username=? OR email=?",
        (identifier, identifier)
    ).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Username/Gmail ya password galat hai"}), 200

    session["user_id"] = row["id"]
    session["username"] = row["username"]
    return jsonify({"ok": True, "username": row["username"]})


app.view_functions["login"] = login_or_email


# ====================================================================== #
# NEW FEATURE (added below, old code above is untouched): /me now also
# returns the user's numeric id, so the frontend can show it as a personal
# identification number next to the Developer API key.
# ====================================================================== #
def me_with_id():
    if session.get("user_id"):
        return jsonify({
            "logged_in": True,
            "username": session.get("username"),
            "id": session.get("user_id"),
        })
    return jsonify({"logged_in": False})


app.view_functions["me"] = me_with_id


# ====================================================================== #
# NEW FEATURE (added below, old code above is untouched): a richer admin
# dashboard at /admin/v2 (the old /admin now redirects here) with:
#   1. CSV export of all scans
#   2. User management (list, ban/unban, delete)
#   3. Date filter (today / this week / all time)
#   4. Search box (by URL / username in results)
#   5. Telegram alert on every high-risk (>=6) scan
#   6. 7-day scan trend bar chart
#   7. IP blocking (in addition to the existing URL blocking)
#   8. Dark / Light theme toggle (saved in the browser via localStorage)
#
# New env vars (optional):
#   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID  -> for the high-risk alert
# ====================================================================== #

import csv
from io import StringIO
from datetime import timedelta
from flask import Response

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


def migrate_admin_v2():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def send_telegram_alert(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=5
        )
    except requests.RequestException:
        pass


def log_scan(scan_type, target, result, risk):
    """
    Overrides log_scan again: same behaviour as before, plus a Telegram
    alert whenever a high-risk (>=6) scan is logged.
    """
    try:
        db = get_db()
        user_id = current_user_id()
        db.execute(
            "INSERT INTO scans (type, target, result, risk, ip, created_at, user_id) VALUES (?,?,?,?,?,?,?)",
            (scan_type, (target or "")[:500], (result or "")[:300], risk,
             request.remote_addr, datetime.utcnow().isoformat(), user_id)
        )
        db.commit()
        if risk is not None and risk >= 6:
            send_telegram_alert(
                f"⚠️ High risk {scan_type.upper()} scan!\n"
                f"Target: {(target or '')[:200]}\n"
                f"Risk: {risk}/10\n"
                f"Result: {(result or '')[:200]}"
            )
    except Exception:
        pass


def is_blocked_ip(ip):
    db = get_db()
    return bool(db.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)).fetchone())


@app.before_request
def check_blocked_ip_and_banned_user():
    # Block requests from a blocked IP (whole site, including admin login).
    if is_blocked_ip(request.remote_addr):
        return jsonify({"error": "Access blocked"}), 403
    # Force-logout a banned visitor account on their very next request.
    uid = session.get("user_id")
    if uid:
        db = get_db()
        row = db.execute("SELECT banned FROM users WHERE id=?", (uid,)).fetchone()
        if row and row["banned"]:
            session.pop("user_id", None)
            session.pop("username", None)


NEW_DASHBOARD_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--mut:#94a3b8;--border:#334155;--accent:#6366f1;--danger:#ef4444}
:root[data-theme="light"]{--bg:#f1f5f9;--card:#ffffff;--fg:#0f172a;--mut:#475569;--border:#e2e8f0}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:20px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.top-actions{display:flex;gap:10px;align-items:center}
a.logout{color:var(--danger);text-decoration:none;font-size:13px}
.theme-btn{background:var(--card);border:1px solid var(--border);color:var(--fg);padding:6px 12px;border-radius:8px;cursor:pointer;font-size:13px}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.stat{background:var(--card);padding:14px 20px;border-radius:12px;min-width:110px;border:1px solid var(--border)}
.stat b{display:block;font-size:24px}
.stat span{color:var(--mut);font-size:12px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;align-items:center}
.toolbar a.range{padding:6px 12px;border-radius:8px;border:1px solid var(--border);color:var(--mut);text-decoration:none;font-size:12px}
.toolbar a.range.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.toolbar input[type=text]{padding:7px 10px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--fg);font-size:13px}
.toolbar button,.toolbar a.csv{padding:7px 12px;border-radius:8px;border:0;background:var(--accent);color:#fff;font-size:12px;cursor:pointer;text-decoration:none}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.box{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:18px}
.box h3{margin-top:0;font-size:15px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)}
th{color:var(--mut);font-weight:600}
.risk-high{color:#fca5a5}.risk-mid{color:#fcd34d}.risk-low{color:#6ee7b7}
form.inline{display:flex;gap:8px;margin-bottom:12px}
input[type=text]{flex:1;padding:7px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--fg)}
button{padding:7px 12px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600;font-size:12px}
button.del{background:var(--danger);padding:4px 10px;font-size:11px}
button.ban{background:#f59e0b;padding:4px 10px;font-size:11px}
.scroll{max-height:380px;overflow:auto}
.chart{display:flex;align-items:flex-end;gap:8px;height:110px;padding:10px 0}
.chart .bar{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.chart .bar-fill{width:100%;background:var(--accent);border-radius:4px 4px 0 0;min-height:2px}
.chart .lbl{font-size:10px;color:var(--mut)}
.badge{font-size:10px;padding:2px 6px;border-radius:6px;background:var(--border);color:var(--mut)}
</style>
<script>
(function(){ document.documentElement.setAttribute('data-theme', localStorage.getItem('adminTheme')||'dark'); })();
function toggleTheme(){
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur==='dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('adminTheme', next);
}
</script>
</head><body>
<div class="top">
  <h2 style="margin:0">🛡️ Safety Scanner Admin</h2>
  <div class="top-actions">
    <button class="theme-btn" onclick="toggleTheme()">🌓 Theme</button>
    <a class="logout" href="{{ url_for('admin_logout') }}">Logout</a>
  </div>
</div>

<div class="stats">
<div class="stat"><b>{{ total }}</b><span>Total scans</span></div>
<div class="stat"><b>{{ counts.get('vt',0) + counts.get('ai',0) }}</b><span>Link scans</span></div>
<div class="stat"><b>{{ counts.get('qr',0) }}</b><span>QR scans</span></div>
<div class="stat"><b>{{ counts.get('apk',0) }}</b><span>APK scans</span></div>
<div class="stat"><b>{{ users|length }}</b><span>Users</span></div>
<div class="stat"><b>{{ blocked|length }}</b><span>Blocked URLs</span></div>
<div class="stat"><b>{{ blocked_ips|length }}</b><span>Blocked IPs</span></div>
</div>

<div class="box">
<h3>📈 Last 7 days</h3>
<div class="chart">
{% for d in trend_data %}
<div class="bar">
  <div class="bar-fill" style="height:{{ (d.count / max_count * 90)|round(0,'floor')|int }}px"></div>
  <div class="lbl">{{ d.count }}</div>
  <div class="lbl">{{ d.day }}</div>
</div>
{% endfor %}
</div>
</div>

<form class="toolbar" method="get" action="{{ url_for('admin_dashboard_v2') }}">
  <a class="range {{ 'active' if rng=='today' }}" href="{{ url_for('admin_dashboard_v2', range='today', q=q) }}">Today</a>
  <a class="range {{ 'active' if rng=='week' }}" href="{{ url_for('admin_dashboard_v2', range='week', q=q) }}">This week</a>
  <a class="range {{ 'active' if rng=='all' or not rng }}" href="{{ url_for('admin_dashboard_v2', range='all', q=q) }}">All time</a>
  <input type="hidden" name="range" value="{{ rng }}">
  <input type="text" name="q" placeholder="Search URL / result..." value="{{ q }}">
  <button type="submit">Search</button>
  <a class="csv" href="{{ url_for('admin_export_csv') }}">⬇️ Export CSV</a>
</form>

<div class="grid">
<div class="box">
<h3>🚫 Block a URL / domain</h3>
<form class="inline" method="post" action="{{ url_for('admin_block') }}">
<input type="text" name="pattern" placeholder="e.g. bad-site.com" required>
<button type="submit">Block</button>
</form>
<div class="scroll">
<table><tr><th>Pattern</th><th>Added</th><th></th></tr>
{% for b in blocked %}
<tr><td>{{ b['pattern'] }}</td><td>{{ b['created_at'][:16] }}</td>
<td><form method="post" action="{{ url_for('admin_unblock', block_id=b['id']) }}">
<button class="del" type="submit">Remove</button></form></td></tr>
{% endfor %}
</table>
</div>
</div>

<div class="box">
<h3>🌐 Block an IP address</h3>
<form class="inline" method="post" action="{{ url_for('admin_block_ip') }}">
<input type="text" name="ip" placeholder="e.g. 203.0.113.5" required>
<button type="submit">Block</button>
</form>
<div class="scroll">
<table><tr><th>IP</th><th>Added</th><th></th></tr>
{% for b in blocked_ips %}
<tr><td>{{ b['ip'] }}</td><td>{{ b['created_at'][:16] }}</td>
<td><form method="post" action="{{ url_for('admin_unblock_ip', ip_id=b['id']) }}">
<button class="del" type="submit">Remove</button></form></td></tr>
{% endfor %}
</table>
</div>
</div>
</div>

<div class="box">
<h3>👤 Users</h3>
<div class="scroll">
<table><tr><th>ID</th><th>Username</th><th>Email</th><th>Via</th><th>Joined</th><th>Status</th><th></th></tr>
{% for u in users %}
<tr>
<td>#{{ u['id'] }}</td>
<td>{{ u['username'] }}</td>
<td>{{ u['email'] or '-' }}</td>
<td><span class="badge">{{ u['oauth_provider'] or 'password' }}</span></td>
<td>{{ u['created_at'][:10] }}</td>
<td>{{ 'Banned' if u['banned'] else 'Active' }}</td>
<td style="white-space:nowrap">
<form style="display:inline" method="post" action="{{ url_for('admin_ban_user' if not u['banned'] else 'admin_unban_user', user_id=u['id']) }}">
<button class="ban" type="submit">{{ 'Unban' if u['banned'] else 'Ban' }}</button>
</form>
<form style="display:inline" method="post" action="{{ url_for('admin_delete_user', user_id=u['id']) }}" onsubmit="return confirm('Delete this user?')">
<button class="del" type="submit">Delete</button>
</form>
</td>
</tr>
{% endfor %}
</table>
</div>
</div>

<div class="box">
<h3>📜 Recent scans {% if q %}(matching "{{ q }}"){% endif %}</h3>
<div class="scroll">
<table><tr><th>Type</th><th>Target</th><th>Result</th><th>Risk</th><th>Time</th></tr>
{% for s in logs %}
<tr>
<td>{{ s['type'] }}</td>
<td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ s['target'] }}</td>
<td>{{ s['result'] }}</td>
<td class="{{ 'risk-high' if (s['risk'] or 0) >= 6 else 'risk-mid' if (s['risk'] or 0) >= 3 else 'risk-low' }}">{{ s['risk'] if s['risk'] is not none else '-' }}</td>
<td>{{ s['created_at'][:16] }}</td>
</tr>
{% endfor %}
</table>
</div>
</div>
</body></html>
"""


@app.route("/admin/v2")
@login_required
def admin_dashboard_v2():
    db = get_db()
    q = request.args.get("q", "").strip()
    rng = request.args.get("range", "all")

    where = "1=1"
    params = []
    if rng == "today":
        where += " AND date(created_at) = date('now')"
    elif rng == "week":
        where += " AND date(created_at) >= date('now','-7 days')"
    if q:
        where += " AND (target LIKE ? OR result LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]

    total = db.execute(f"SELECT COUNT(*) c FROM scans WHERE {where}", params).fetchone()["c"]
    counts = {r["type"]: r["c"] for r in db.execute(
        f"SELECT type, COUNT(*) c FROM scans WHERE {where} GROUP BY type", params).fetchall()}
    logs = db.execute(
        f"SELECT * FROM scans WHERE {where} ORDER BY id DESC LIMIT 100", params).fetchall()
    blocked = db.execute("SELECT * FROM blocked_urls ORDER BY id DESC").fetchall()
    blocked_ips = db.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
    users = db.execute(
        "SELECT id, username, email, oauth_provider, created_at, COALESCE(banned,0) as banned "
        "FROM users ORDER BY id DESC"
    ).fetchall()

    trend_rows = db.execute(
        "SELECT date(created_at) d, COUNT(*) c FROM scans "
        "WHERE created_at >= datetime('now','-7 days') GROUP BY d"
    ).fetchall()
    trend = {r["d"]: r["c"] for r in trend_rows}
    days = [(datetime.utcnow().date() - timedelta(days=i)) for i in range(6, -1, -1)]
    trend_data = [{"day": d.strftime("%d %b"), "count": trend.get(d.isoformat(), 0)} for d in days]
    max_count = max([t["count"] for t in trend_data] + [1])

    return render_template_string(
        NEW_DASHBOARD_HTML, total=total, counts=counts, logs=logs,
        blocked=blocked, blocked_ips=blocked_ips, users=users, q=q, rng=rng,
        trend_data=trend_data, max_count=max_count
    )


def admin_dashboard_redirect():
    return redirect(url_for("admin_dashboard_v2"))


app.view_functions["admin_dashboard"] = admin_dashboard_redirect


@app.route("/admin/export-csv")
@login_required
def admin_export_csv():
    db = get_db()
    rows = db.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "type", "target", "result", "risk", "ip", "created_at", "user_id"])
    for r in rows:
        writer.writerow([r["id"], r["type"], r["target"], r["result"], r["risk"],
                          r["ip"], r["created_at"], r["user_id"]])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=scans_export.csv"}
    )


@app.route("/admin/user/<int:user_id>/ban", methods=["POST"])
@login_required
def admin_ban_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET banned=1 WHERE id=?", (user_id,))
    db.commit()
    return redirect(url_for("admin_dashboard_v2"))


@app.route("/admin/user/<int:user_id>/unban", methods=["POST"])
@login_required
def admin_unban_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET banned=0 WHERE id=?", (user_id,))
    db.commit()
    return redirect(url_for("admin_dashboard_v2"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return redirect(url_for("admin_dashboard_v2"))


@app.route("/admin/block-ip", methods=["POST"])
@login_required
def admin_block_ip():
    ip = request.form.get("ip", "").strip()
    if ip:
        db = get_db()
        try:
            db.execute(
                "INSERT INTO blocked_ips (ip, created_at) VALUES (?,?)",
                (ip, datetime.utcnow().isoformat())
            )
            db.commit()
        except sqlite3.IntegrityError:
            pass
    return redirect(url_for("admin_dashboard_v2"))


@app.route("/admin/unblock-ip/<int:ip_id>", methods=["POST"])
@login_required
def admin_unblock_ip(ip_id):
    db = get_db()
    db.execute("DELETE FROM blocked_ips WHERE id=?", (ip_id,))
    db.commit()
    return redirect(url_for("admin_dashboard_v2"))


# ------------------------------------------------------------------ #
# Entrypoint
# ------------------------------------------------------------------ #
init_db()
migrate_api_key_column()
migrate_oauth_columns()
migrate_admin_v2()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
