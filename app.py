"""
Safety Scanner - Flask backend
================================
Serves safety-scanner.html and powers:
  GET  /vt?url=...   -> VirusTotal verdict (VT_API_KEY env)
  POST /qr           -> decode QR image (pyzbar, falls back to OpenCV)
  POST /apk          -> analyze APK permissions/signature
  /admin             -> login-protected dashboard: scan totals, logs, block URLs

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
import requests

# ------------------------------------------------------------------ #
# Config
# ------------------------------------------------------------------ #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")

VT_API_KEY = os.environ.get("VT_API_KEY", "") or os.environ.get("VIRUS_API_KEY", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
PORT = int(os.environ.get("PORT", 5000))
VT_BASE = "https://www.virustotal.com/api/v3"

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = SECRET_KEY
CORS(app)

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
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_scan(scan_type, target, result, risk):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO scans (type, target, result, risk, ip, created_at) VALUES (?,?,?,?,?,?)",
            (scan_type, (target or "")[:500], (result or "")[:300], risk,
             request.remote_addr, datetime.utcnow().isoformat())
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


# ------------------------------------------------------------------ #
# Entrypoint
# ------------------------------------------------------------------ #
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
