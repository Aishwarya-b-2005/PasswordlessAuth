
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import sqlite3
# import base64
# import os
# import hashlib
# import time
# import secrets
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.serialization import load_pem_public_key
# from cryptography.exceptions import InvalidSignature

# app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": "*"}})

# DB_FILE = "securebank.db"

# LOGIN_NONCES     = {}
# OPERATION_NONCES = {}

# ADMIN_USERNAME = "admin"
# ADMIN_SALT_B64 = "TXlTZWN1cmVTYWx0MTY="
# ADMIN_HASH     = hashlib.pbkdf2_hmac(
#     "sha256",
#     b"admin1234",
#     base64.b64decode(ADMIN_SALT_B64),
#     260_000
# ).hex()

# ADMIN_SESSIONS: dict = {}
# ADMIN_SESSION_TTL = 3600

# # =====================================================
# # DATABASE INIT
# # =====================================================
# def init_db():
#     conn = sqlite3.connect(DB_FILE)
#     c = conn.cursor()
#     c.execute("""
#         CREATE TABLE IF NOT EXISTS users (
#             username TEXT PRIMARY KEY,
#             public_key TEXT NOT NULL,
#             last_ip TEXT
#         )
#     """)
#     c.execute("""
#         CREATE TABLE IF NOT EXISTS logs (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             user TEXT,
#             result TEXT,
#             timestamp REAL,
#             riskScore REAL,
#             action TEXT,
#             prev_hash TEXT,
#             current_hash TEXT
#         )
#     """)
#     conn.commit()
#     conn.close()

# init_db()

# # =====================================================
# # HELPERS
# # =====================================================
# def compute_hash(data: str) -> str:
#     return hashlib.sha256(data.encode()).hexdigest()


# def verify_signature(public_key_pem, nonce_b64, signature_b64):
#     try:
#         public_key  = load_pem_public_key(public_key_pem.encode())
#         signature   = base64.b64decode(signature_b64)
#         nonce_bytes = base64.b64decode(nonce_b64)
#         public_key.verify(
#             signature, nonce_bytes,
#             padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
#             hashes.SHA256()
#         )
#         return True
#     except Exception as e:
#         print("Verification error:", e)
#         return False


# def require_admin(req) -> bool:
#     token = req.headers.get("X-Admin-Token", "")
#     if not token:
#         return False
#     expiry = ADMIN_SESSIONS.get(token)
#     if expiry is None or time.time() > expiry:
#         ADMIN_SESSIONS.pop(token, None)
#         return False
#     return True


# def log_event(username, result, risk, action):
#     conn = sqlite3.connect(DB_FILE)
#     c = conn.cursor()
#     c.execute("SELECT current_hash FROM logs ORDER BY id DESC LIMIT 1")
#     prev      = c.fetchone()
#     prev_hash = prev[0] if prev else "GENESIS"
#     timestamp    = time.time()
#     log_data     = f"{username}{result}{timestamp}{risk}{action}"
#     current_hash = compute_hash(prev_hash + log_data)
#     c.execute("""
#         INSERT INTO logs (user, result, timestamp, riskScore, action, prev_hash, current_hash)
#         VALUES (?, ?, ?, ?, ?, ?, ?)
#     """, (username, result, timestamp, risk, action, prev_hash, current_hash))
#     conn.commit()
#     conn.close()


# # =====================================================
# # RISK ENGINE
# # =====================================================
# # Scale: 0.0 – 1.0
# # Decisions:
# #   < 0.40  → ALLOW
# #   < 0.70  → STEP_UP  (requires RSA re-authentication)
# #   >= 0.70 → DENY
# #
# # Operation base risks:
# #   READ     0.10  → always ALLOW   (view only, safe)
# #   WRITE    0.25  → always ALLOW   (edits but reversible)
# #   TRANSFER 0.35  → ALLOW normally, STEP_UP if amount > $1000
# #   DELETE   0.50  → always STEP_UP (base already above 0.40 threshold)
# #
# # Extra signals evaluated live on every request:
# #   • Amount       — larger transfers add penalty
# #   • IP change    — different IP from login adds +0.35
# #   • Time of day  — off-hours (before 6am / after 10pm) adds +0.20
# #   • Bot signals  — no mouse + no keyboard + <800ms adds +0.40
# # =====================================================
# def calculate_operation_risk(username, operation, ip, context):
#     risk    = 0.0
#     factors = []
#     amount  = float(context.get("amount", 0))

#     # ── 1. Base risk per operation ──────────────────────────────────
#     BASE_RISK = {
#         "READ":     0.10,   # view-only — always ALLOW
#         "WRITE":    0.25,   # edits data — always ALLOW unless other signals
#         "TRANSFER": 0.35,   # money movement — ALLOW for small, STEP_UP for large
#         "DELETE":   0.50,   # irreversible — always STEP_UP minimum
#     }
#     base = BASE_RISK.get(operation.upper(), 0.25)
#     risk += base
#     factors.append(f"Base risk for {operation}: +{base:.2f}")

#     # ── 2. Transfer amount (evaluated live from request payload) ────
#     if amount > 10000:
#         risk += 0.40
#         factors.append(f"Very large transfer (${amount:,.0f}): +0.40")
#     elif amount > 5000:
#         risk += 0.25
#         factors.append(f"Large transfer (${amount:,.0f}): +0.25")
#     elif amount > 1000:
#         risk += 0.10
#         factors.append(f"Moderate transfer (${amount:,.0f}): +0.10")

#     # ── 3. IP address change (compares live IP vs stored login IP) ──
#     conn = sqlite3.connect(DB_FILE)
#     c = conn.cursor()
#     c.execute("SELECT last_ip FROM users WHERE username=?", (username,))
#     row = c.fetchone()
#     conn.close()
#     if row and row[0] and row[0] != ip:
#         risk += 0.35
#         factors.append(f"IP changed since login: +0.35")

#     # ── 4. Time of day (live server clock) ──────────────────────────
#     current_hour = time.localtime().tm_hour
#     if current_hour < 6 or current_hour > 22:
#         risk += 0.20
#         factors.append(f"Off-hours request ({current_hour}:00): +0.20")

#     # ── 5. Bot behaviour signals (from browser context) ─────────────
#     no_mouse    = not context.get("mouseMovementDetected", True)
#     no_keyboard = not context.get("keyboardInteractionDetected", True)
#     too_fast    = context.get("timeOnPageMs", 9999) < 800

#     if no_mouse and no_keyboard and too_fast:
#         risk += 0.40
#         factors.append("Bot signals (no mouse + no keyboard + <800ms): +0.40")
#     elif no_mouse and no_keyboard:
#         risk += 0.20
#         factors.append("Suspicious: no mouse or keyboard interaction: +0.20")
#     elif no_mouse and too_fast:
#         risk += 0.15
#         factors.append("Suspicious: no mouse + very fast: +0.15")

#     risk = min(risk, 1.0)
#     return risk, factors


# # =====================================================
# # USER REGISTRATION
# # =====================================================
# @app.route("/register", methods=["POST"])
# def register():
#     data       = request.json
#     username   = data["username"]
#     public_key = data["publicKey"]
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT username FROM users WHERE username=?", (username,))
#     if c.fetchone():
#         conn.close()
#         return jsonify({"status": "EXISTS"})
#     c.execute("INSERT INTO users (username, public_key) VALUES (?, ?)",
#               (username, public_key))
#     conn.commit()
#     conn.close()
#     return jsonify({"status": "REGISTERED"})


# # =====================================================
# # LOGIN (RSA AUTH)
# # =====================================================
# @app.route("/challenge", methods=["POST"])
# def challenge():
#     username = request.json["username"]
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT username FROM users WHERE username=?", (username,))
#     exists = c.fetchone()
#     conn.close()
#     if not exists:
#         return jsonify({"error": "User not found"}), 404
#     nonce                  = base64.b64encode(os.urandom(32)).decode()
#     LOGIN_NONCES[username] = nonce
#     return jsonify({"nonce": nonce})


# @app.route("/login", methods=["POST"])
# def login():
#     try:
#         data      = request.json
#         username  = data.get("username")
#         signature = data.get("signature")
#         if not username or not signature:
#             return jsonify({"status": "DENIED", "error": "Missing data"})
#         if username not in LOGIN_NONCES:
#             return jsonify({"status": "DENIED", "error": "No nonce found"})
#         nonce = LOGIN_NONCES.pop(username)
#         conn = sqlite3.connect(DB_FILE)
#         c    = conn.cursor()
#         c.execute("SELECT public_key FROM users WHERE username=?", (username,))
#         row  = c.fetchone()
#         conn.close()
#         if not row:
#             return jsonify({"status": "DENIED", "error": "User not found"})
#         ok = verify_signature(row[0], nonce, signature)
#         ip = request.remote_addr
#         if ok:
#             conn = sqlite3.connect(DB_FILE)
#             c    = conn.cursor()
#             c.execute("UPDATE users SET last_ip=? WHERE username=?", (ip, username))
#             conn.commit()
#             conn.close()
#         risk = 0.1 if ok else 0.9
#         log_event(username, "LOGIN_SUCCESS" if ok else "LOGIN_DENIED", risk, "LOGIN")
#         return jsonify({"status": "SUCCESS" if ok else "DENIED"})
#     except Exception as e:
#         print("LOGIN ERROR:", e)
#         return jsonify({"status": "ERROR", "message": str(e)}), 500


# # =====================================================
# # ADMIN LOGIN
# # =====================================================
# @app.route("/admin/login", methods=["POST"])
# def admin_login():
#     data     = request.json or {}
#     username = data.get("username", "")
#     password = data.get("password", "")
#     if username != ADMIN_USERNAME:
#         return jsonify({"status": "DENIED"}), 401
#     salt       = base64.b64decode(ADMIN_SALT_B64)
#     input_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000).hex()
#     if not secrets.compare_digest(input_hash, ADMIN_HASH):
#         return jsonify({"status": "DENIED"}), 401
#     token = secrets.token_hex(32)
#     ADMIN_SESSIONS[token] = time.time() + ADMIN_SESSION_TTL
#     return jsonify({"status": "SUCCESS", "token": token})


# # =====================================================
# # ADMIN — FULL LOG LIST
# # =====================================================
# @app.route("/admin/logs", methods=["GET"])
# def admin_logs():
#     if not require_admin(request):
#         return jsonify({"error": "Unauthorized"}), 403
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT id, user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
#     rows = c.fetchall()
#     conn.close()
#     return jsonify([{
#         "id": r[0], "user": r[1], "result": r[2], "timestamp": r[3],
#         "riskScore": r[4], "action": r[5], "prev_hash": r[6], "current_hash": r[7],
#     } for r in rows])


# # =====================================================
# # ADMIN — PER-ENTRY CHAIN VERIFICATION
# # =====================================================
# @app.route("/admin/verify-chain", methods=["GET"])
# def admin_verify_chain():
#     if not require_admin(request):
#         return jsonify({"error": "Unauthorized"}), 403
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT id, user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
#     rows = c.fetchall()
#     conn.close()
#     results      = []
#     chain_broken = False
#     for i, row in enumerate(rows):
#         id_, user, result, timestamp, risk, action, stored_prev, stored_current = row
#         expected_prev    = "GENESIS" if i == 0 else rows[i - 1][7]
#         log_data         = f"{user}{result}{timestamp}{risk}{action}"
#         expected_current = compute_hash(expected_prev + log_data)
#         prev_ok    = (stored_prev == expected_prev)
#         current_ok = (stored_current == expected_current)
#         entry_ok   = prev_ok and current_ok and not chain_broken
#         if not entry_ok:
#             chain_broken = True
#         results.append({
#             "id": id_, "user": user, "result": result, "timestamp": timestamp,
#             "riskScore": risk, "action": action,
#             "stored_prev": stored_prev, "stored_current": stored_current,
#             "expected_prev": expected_prev, "expected_current": expected_current,
#             "ok": entry_ok, "tampered": not entry_ok,
#             "prev_mismatch": not prev_ok, "hash_mismatch": not current_ok,
#         })
#     return jsonify({"overall": all(r["ok"] for r in results), "entries": results})


# # =====================================================
# # ADMIN — TAMPER SIMULATOR (demo only)
# # =====================================================
# @app.route("/admin/tamper-log", methods=["POST"])
# def admin_tamper_log():
#     if not require_admin(request):
#         return jsonify({"error": "Unauthorized"}), 403
#     data      = request.json or {}
#     target_id = data.get("target_id")
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     if target_id:
#         c.execute("SELECT id FROM logs WHERE id=?", (target_id,))
#         if not c.fetchone():
#             conn.close()
#             return jsonify({"error": "Log entry not found"}), 404
#         chosen_id = target_id
#     else:
#         c.execute("SELECT id FROM logs ORDER BY id ASC")
#         all_ids = [r[0] for r in c.fetchall()]
#         if len(all_ids) < 2:
#             conn.close()
#             return jsonify({"error": "Need at least 2 log entries"}), 400
#         chosen_id = all_ids[len(all_ids) // 2]
#     c.execute("""
#         UPDATE logs
#         SET result = result || '_TAMPERED',
#             current_hash = 'TAMPERED_HASH_' || hex(randomblob(8))
#         WHERE id = ?
#     """, (chosen_id,))
#     conn.commit()
#     conn.close()
#     return jsonify({"status": "TAMPERED", "tampered_id": chosen_id})


# # =====================================================
# # ADMIN — RESTORE (undo tamper for demo reset)
# # =====================================================
# @app.route("/admin/restore-logs", methods=["POST"])
# def admin_restore_logs():
#     if not require_admin(request):
#         return jsonify({"error": "Unauthorized"}), 403
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("UPDATE logs SET result = REPLACE(result, '_TAMPERED', '')")
#     c.execute("SELECT id, user, result, timestamp, riskScore, action FROM logs ORDER BY id ASC")
#     rows = c.fetchall()
#     prev_hash = "GENESIS"
#     for row in rows:
#         id_, user, result, timestamp, risk, action = row
#         log_data     = f"{user}{result}{timestamp}{risk}{action}"
#         current_hash = compute_hash(prev_hash + log_data)
#         c.execute("UPDATE logs SET prev_hash=?, current_hash=? WHERE id=?",
#                   (prev_hash, current_hash, id_))
#         prev_hash = current_hash
#     conn.commit()
#     conn.close()
#     return jsonify({"status": "RESTORED"})


# # =====================================================
# # OPERATION ENDPOINTS
# # =====================================================
# @app.route("/operation-challenge", methods=["POST"])
# def operation_challenge():
#     data      = request.json
#     username  = data["username"]
#     operation = data["operation"]
#     context   = data.get("context", {})
#     context_string = f"{username}{operation}{str(context)}"
#     context_hash   = hashlib.sha256(context_string.encode()).hexdigest()
#     nonce          = base64.b64encode(os.urandom(16)).decode()
#     OPERATION_NONCES[username] = {
#         "nonce":        nonce,
#         "operation":    operation,
#         "context_hash": context_hash,
#         "timestamp":    time.time()
#     }
#     return jsonify({"nonce": nonce, "operation": operation})


# @app.route("/execute-operation", methods=["POST"])
# def execute_operation():
#     data      = request.json
#     username  = data["username"]
#     operation = data["operation"]
#     nonce     = data["nonce"]
#     context   = data.get("context", {})

#     if username not in OPERATION_NONCES:
#         return jsonify({"status": "DENY", "reason": "No nonce"})

#     stored = OPERATION_NONCES.pop(username)

#     if nonce != stored["nonce"] or operation != stored["operation"]:
#         return jsonify({"status": "DENY", "reason": "Context mismatch"})

#     if time.time() - stored["timestamp"] > 60:
#         return jsonify({"status": "DENY", "reason": "Expired"})

#     context_string = f"{username}{operation}{str(context)}"
#     incoming_hash  = hashlib.sha256(context_string.encode()).hexdigest()
#     if incoming_hash != stored["context_hash"]:
#         return jsonify({"status": "DENY", "reason": "Tampered context"})

#     ip            = request.remote_addr
#     risk, factors = calculate_operation_risk(username, operation, ip, context)

#     # ── Decision ─────────────────────────────────────────────────────
#     # DELETE base risk is 0.50 — already above 0.40 threshold,
#     # so it ALWAYS gets STEP_UP without any special case needed.
#     if risk >= 0.70:
#         decision = "DENY"
#     elif risk >= 0.40:
#         decision = "STEP_UP"
#     else:
#         decision = "ALLOW"

#     # Print live debug to backend terminal — great for viva demo
#     print(f"\n[RISK] user={username} | op={operation} | score={risk:.2f} | {decision}")
#     for f in factors:
#         print(f"       → {f}")

#     log_event(username, decision, risk, operation)
#     return jsonify({"status": decision, "risk": risk, "factors": factors})


# @app.route("/stepup-challenge", methods=["POST"])
# def stepup_challenge():
#     data      = request.json
#     username  = data["username"]
#     operation = data["operation"]
#     nonce     = base64.b64encode(os.urandom(32)).decode()
#     OPERATION_NONCES[username] = {
#         "nonce":     nonce,
#         "operation": operation,
#         "timestamp": time.time(),
#         "stepup":    True
#     }
#     return jsonify({"nonce": nonce})


# @app.route("/stepup-verify", methods=["POST"])
# def stepup_verify():
#     data      = request.json
#     username  = data["username"]
#     operation = data["operation"]
#     signature = data["signature"]
#     if username not in OPERATION_NONCES:
#         return jsonify({"status": "DENY"})
#     stored = OPERATION_NONCES.pop(username)
#     if stored["operation"] != operation:
#         return jsonify({"status": "DENY"})
#     if time.time() - stored["timestamp"] > 60:
#         return jsonify({"status": "DENY"})
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT public_key FROM users WHERE username=?", (username,))
#     row  = c.fetchone()
#     conn.close()
#     if not row:
#         return jsonify({"status": "DENY"})
#     ok = verify_signature(row[0], stored["nonce"], signature)
#     if ok:
#         log_event(username, "STEPUP_SUCCESS", 0.2, operation)
#         return jsonify({"status": "UPGRADED_ALLOW"})
#     else:
#         log_event(username, "STEPUP_DENIED", 0.9, operation)
#         return jsonify({"status": "DENY"})


# # =====================================================
# # PUBLIC LOG + INTEGRITY ENDPOINTS
# # =====================================================
# @app.route("/logs", methods=["GET"])
# def get_logs():
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT id, user, result, timestamp, riskScore, action, current_hash FROM logs ORDER BY id ASC")
#     rows = c.fetchall()
#     conn.close()
#     return jsonify([{
#         "id": r[0], "user": r[1], "result": r[2],
#         "timestamp": r[3], "riskScore": r[4],
#         "action": r[5], "hash": r[6],
#     } for r in rows])


# @app.route("/verify-logs", methods=["GET"])
# def verify_logs():
#     conn = sqlite3.connect(DB_FILE)
#     c    = conn.cursor()
#     c.execute("SELECT user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
#     rows = c.fetchall()
#     conn.close()
#     prev_hash = "GENESIS"
#     for row in rows:
#         user, result, timestamp, risk, action, stored_prev, stored_current = row
#         if stored_prev != prev_hash:
#             return jsonify({"integrity": "TAMPERED"})
#         log_data = f"{user}{result}{timestamp}{risk}{action}"
#         expected = compute_hash(prev_hash + log_data)
#         if stored_current != expected:
#             return jsonify({"integrity": "TAMPERED"})
#         prev_hash = stored_current
#     return jsonify({"integrity": "OK"})


# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import base64
import os
import hashlib
import time
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DB_FILE = "securebank.db"

LOGIN_NONCES     = {}
OPERATION_NONCES = {}

# =====================================================
# ADMIN CREDENTIALS
# Password = "admin1234"
# To change: python3 -c "import hashlib,os,base64; s=os.urandom(16);
#   print(base64.b64encode(s).decode(),'|',hashlib.pbkdf2_hmac('sha256',b'NEW_PW',s,260000).hex())"
# =====================================================
ADMIN_USERNAME = "admin"
ADMIN_SALT_B64 = "TXlTZWN1cmVTYWx0MTY="
ADMIN_HASH     = hashlib.pbkdf2_hmac(
    "sha256", b"admin1234",
    base64.b64decode(ADMIN_SALT_B64), 260_000
).hex()

ADMIN_SESSIONS: dict = {}
ADMIN_SESSION_TTL = 3600

# =====================================================
# DATABASE INIT
# =====================================================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            last_ip TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            result TEXT,
            timestamp REAL,
            riskScore REAL,
            action TEXT,
            prev_hash TEXT,
            current_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# =====================================================
# HELPERS
# =====================================================
def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def verify_signature(public_key_pem, nonce_b64, signature_b64):
    try:
        public_key  = load_pem_public_key(public_key_pem.encode())
        signature   = base64.b64decode(signature_b64)
        nonce_bytes = base64.b64decode(nonce_b64)
        public_key.verify(
            signature, nonce_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Verification error:", e)
        return False


def require_admin(req) -> bool:
    token = req.headers.get("X-Admin-Token", "")
    if not token:
        return False
    expiry = ADMIN_SESSIONS.get(token)
    if expiry is None or time.time() > expiry:
        ADMIN_SESSIONS.pop(token, None)
        return False
    return True


def log_event(username, result, risk, action):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT current_hash FROM logs ORDER BY id DESC LIMIT 1")
    prev      = c.fetchone()
    prev_hash = prev[0] if prev else "GENESIS"
    timestamp    = time.time()
    log_data     = f"{username}{result}{timestamp}{risk}{action}"
    current_hash = compute_hash(prev_hash + log_data)
    c.execute("""
        INSERT INTO logs (user, result, timestamp, riskScore, action, prev_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, result, timestamp, risk, action, prev_hash, current_hash))
    conn.commit()
    conn.close()


# =====================================================
# RISK ENGINE
# =====================================================
def calculate_operation_risk(username, operation, ip, context):
    """
    Scores 0.0–1.0.  Decision mapping:
        < 0.40  →  ALLOW
        < 0.70  →  STEP_UP
        >= 0.70 →  DENY

    BUG FIXES vs original:
      1. Operation base scores updated so READ/TRANSFER/WRITE are realistic
      2. ALLOW threshold raised from 0.30 → 0.40 so WRITE and TRANSFER
         actually trigger STEP_UP under normal conditions (not always ALLOW)
      3. DELETE minimum is forced to STEP_UP regardless of other signals
      4. Bot detection added using behavioural signals from riskEngine.ts
      5. Session age penalty added for stale sessions on high-risk ops
      6. Velocity check uses DB instead of in-memory nonce dict
    """
    risk = 0.0
    reasons = []

    # ── 1. Operation base risk ────────────────────────────────────────────────
    base_risk = {
        "READ":     0.10,   # Low — read-only, least sensitive
        "WRITE":    0.42,   # Medium — always STEP_UP (above 0.40 threshold)
        "TRANSFER": 0.45,   # Medium-high — always STEP_UP
        "DELETE":   0.55,   # High — irreversible account closure
    }
    op_upper = operation.upper()
    risk += base_risk.get(op_upper, 0.20)

    # ── 2. Amount threshold (TRANSFER only) ───────────────────────────────────
    amount = float(context.get("amount", 0) or 0)
    if amount > 10000:
        risk += 0.35
        reasons.append(f"Very large transfer: ${amount:.0f}")
    elif amount > 5000:
        risk += 0.25
        reasons.append(f"Large transfer: ${amount:.0f}")
    elif amount > 1000:
        risk += 0.10
        reasons.append(f"Notable transfer: ${amount:.0f}")

    # ── 3. IP anomaly ─────────────────────────────────────────────────────────
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT last_ip FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row and row[0] and row[0] != ip:
        risk += 0.30
        reasons.append("Request from new IP address")

    # ── 4. Unusual hour (06:00–22:00 = normal) ────────────────────────────────
    current_hour = time.localtime().tm_hour
    if current_hour < 6 or current_hour > 22:
        risk += 0.20
        reasons.append("Unusual hour — outside 06:00–22:00")

    # ── 5. Behavioural bot signals from riskEngine.ts ────────────────────────
    no_mouse    = not context.get("mouseMovementDetected", True)
    no_keyboard = not context.get("keyboardInteractionDetected", True)
    time_on_page = context.get("timeOnPageMs", 9999)
    too_fast    = time_on_page < 800   # < 800ms = almost certainly automated

    if no_mouse and no_keyboard and too_fast:
        risk += 0.30
        reasons.append("Bot signals: no mouse, no keyboard, page loaded < 800ms")
    elif no_mouse and too_fast:
        risk += 0.15
        reasons.append("Possible bot: no mouse movement, very fast page load")

    # ── 6. Velocity — too many operations in last 2 minutes ──────────────────
    cutoff = time.time() - 120
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs WHERE user=? AND timestamp > ?", (username, cutoff))
    recent_count = c.fetchone()[0]
    conn.close()
    if recent_count > 5:
        excess = recent_count - 5
        velocity_penalty = min(excess * 0.10, 0.30)
        risk += velocity_penalty
        reasons.append(f"High velocity: {recent_count} ops in last 2 minutes")

    # ── 7. Session age (high-risk ops need a fresh session) ───────────────────
    session_age_ms = context.get("sessionAgeMs", 0)
    session_age_sec = session_age_ms / 1000
    if session_age_sec > 1800 and op_upper in ("WRITE", "TRANSFER", "DELETE"):
        risk += 0.20
        reasons.append(f"Stale session ({session_age_sec/60:.0f} min old) for sensitive op")

    # ── Cap ───────────────────────────────────────────────────────────────────
    risk = min(risk, 1.0)

    # ── DELETE minimum: always at least STEP_UP ───────────────────────────────
    if op_upper == "DELETE" and risk < 0.40:
        risk = 0.40

    return risk, reasons


# =====================================================
# USER REGISTRATION
# =====================================================
@app.route("/register", methods=["POST"])
def register():
    data       = request.json
    username   = data["username"]
    public_key = data["publicKey"]

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "EXISTS"})

    c.execute(
        "INSERT INTO users (username, public_key) VALUES (?, ?)",
        (username, public_key)
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "REGISTERED"})


# =====================================================
# LOGIN (RSA AUTH)
# =====================================================
@app.route("/challenge", methods=["POST"])
def challenge():
    username = request.json["username"]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    exists = c.fetchone()
    conn.close()
    if not exists:
        return jsonify({"error": "User not found"}), 404
    nonce = base64.b64encode(os.urandom(32)).decode()
    LOGIN_NONCES[username] = nonce
    return jsonify({"nonce": nonce})


@app.route("/login", methods=["POST"])
def login():
    try:
        data      = request.json
        username  = data.get("username")
        signature = data.get("signature")
        if not username or not signature:
            return jsonify({"status": "DENIED", "error": "Missing data"})
        if username not in LOGIN_NONCES:
            return jsonify({"status": "DENIED", "error": "No nonce found"})
        nonce = LOGIN_NONCES.pop(username)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT public_key FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({"status": "DENIED", "error": "User not found"})
        ok = verify_signature(row[0], nonce, signature)
        ip = request.remote_addr
        if ok:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE users SET last_ip=? WHERE username=?", (ip, username))
            conn.commit()
            conn.close()
        risk = 0.1 if ok else 0.9
        log_event(username, "LOGIN_SUCCESS" if ok else "LOGIN_DENIED", risk, "LOGIN")
        return jsonify({"status": "SUCCESS" if ok else "DENIED"})
    except Exception as e:
        print("LOGIN ERROR:", e)
        return jsonify({"status": "ERROR", "message": str(e)}), 500


# =====================================================
# ADMIN LOGIN
# =====================================================
@app.route("/admin/login", methods=["POST"])
def admin_login():
    data     = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username != ADMIN_USERNAME:
        return jsonify({"status": "DENIED"}), 401
    salt       = base64.b64decode(ADMIN_SALT_B64)
    input_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000).hex()
    if not secrets.compare_digest(input_hash, ADMIN_HASH):
        return jsonify({"status": "DENIED"}), 401
    token = secrets.token_hex(32)
    ADMIN_SESSIONS[token] = time.time() + ADMIN_SESSION_TTL
    return jsonify({"status": "SUCCESS", "token": token})


# =====================================================
# ADMIN — FULL LOG LIST
# =====================================================
@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "user": r[1], "result": r[2], "timestamp": r[3],
         "riskScore": r[4], "action": r[5], "prev_hash": r[6], "current_hash": r[7]}
        for r in rows
    ])


# =====================================================
# ADMIN — PER-ENTRY CHAIN VERIFICATION
# =====================================================
@app.route("/admin/verify-chain", methods=["GET"])
def admin_verify_chain():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    results = []
    chain_broken = False
    for i, row in enumerate(rows):
        id_, user, result, timestamp, risk, action, stored_prev, stored_current = row
        expected_prev    = "GENESIS" if i == 0 else rows[i - 1][7]
        log_data         = f"{user}{result}{timestamp}{risk}{action}"
        expected_current = compute_hash(expected_prev + log_data)
        prev_ok    = (stored_prev == expected_prev)
        current_ok = (stored_current == expected_current)
        entry_ok   = prev_ok and current_ok and not chain_broken
        if not entry_ok:
            chain_broken = True
        results.append({
            "id": id_, "user": user, "result": result, "timestamp": timestamp,
            "riskScore": risk, "action": action,
            "stored_prev": stored_prev, "stored_current": stored_current,
            "expected_prev": expected_prev, "expected_current": expected_current,
            "ok": entry_ok, "tampered": not entry_ok,
            "prev_mismatch": not prev_ok, "hash_mismatch": not current_ok,
        })
    return jsonify({"overall": all(r["ok"] for r in results), "entries": results})


# =====================================================
# ADMIN — TAMPER SIMULATOR
# =====================================================
@app.route("/admin/tamper-log", methods=["POST"])
def admin_tamper_log():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403
    data      = request.json or {}
    target_id = data.get("target_id")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if target_id:
        c.execute("SELECT id FROM logs WHERE id=?", (target_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": "Log entry not found"}), 404
        chosen_id = target_id
    else:
        c.execute("SELECT id FROM logs ORDER BY id ASC")
        all_ids = [r[0] for r in c.fetchall()]
        if len(all_ids) < 2:
            conn.close()
            return jsonify({"error": "Need at least 2 log entries"}), 400
        chosen_id = all_ids[len(all_ids) // 2]
    c.execute("""
        UPDATE logs
        SET result = result || '_TAMPERED',
            current_hash = 'TAMPERED_HASH_' || hex(randomblob(8))
        WHERE id = ?
    """, (chosen_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "TAMPERED", "tampered_id": chosen_id})


# =====================================================
# ADMIN — RESTORE
# =====================================================
@app.route("/admin/restore-logs", methods=["POST"])
def admin_restore_logs():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE logs SET result = REPLACE(result, '_TAMPERED', '')")
    c.execute("SELECT id, user, result, timestamp, riskScore, action FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    prev_hash = "GENESIS"
    for row in rows:
        id_, user, result, timestamp, risk, action = row
        log_data     = f"{user}{result}{timestamp}{risk}{action}"
        current_hash = compute_hash(prev_hash + log_data)
        c.execute("UPDATE logs SET prev_hash=?, current_hash=? WHERE id=?",
                  (prev_hash, current_hash, id_))
        prev_hash = current_hash
    conn.commit()
    conn.close()
    return jsonify({"status": "RESTORED"})


# =====================================================
# OPERATION CHALLENGE (context-aware nonce)
# =====================================================
@app.route("/operation-challenge", methods=["POST"])
def operation_challenge():
    data      = request.json
    username  = data["username"]
    operation = data["operation"]
    context   = data.get("context", {})

    context_string = f"{username}{operation}{str(context)}"
    context_hash   = hashlib.sha256(context_string.encode()).hexdigest()
    nonce          = base64.b64encode(os.urandom(16)).decode()
    issued_at      = time.time()
    expires_at     = issued_at + 60     # nonce valid for 60 seconds

    OPERATION_NONCES[username] = {
        "nonce":        nonce,
        "operation":    operation,
        "context_hash": context_hash,
        "timestamp":    issued_at,      # used by execute-operation expiry check
    }

    return jsonify({
        "nonce":        nonce,
        "operation":    operation,
        "contextHash":  context_hash,   # SHA-256(username+operation+context)
        "expiresAt":    expires_at,     # Unix timestamp — frontend shows countdown
    })


# =====================================================
# EXECUTE OPERATION — now also verifies RSA signature
# =====================================================
@app.route("/execute-operation", methods=["POST"])
def execute_operation():
    data      = request.json
    username  = data["username"]
    operation = data["operation"]
    nonce     = data["nonce"]
    context   = data.get("context", {})
    signature = data.get("signature", "")   # RSA-PSS signature from frontend

    # ── 1. Nonce must exist ───────────────────────────────────────────────────
    if username not in OPERATION_NONCES:
        return jsonify({"status": "DENY", "reason": "No nonce — request a challenge first"})

    stored = OPERATION_NONCES.pop(username)

    # ── 2. Nonce + operation must match ──────────────────────────────────────
    if nonce != stored["nonce"] or operation != stored["operation"]:
        return jsonify({"status": "DENY", "reason": "Nonce / operation mismatch"})

    # ── 3. Nonce must not be expired (60s window) ─────────────────────────────
    if time.time() - stored["timestamp"] > 60:
        return jsonify({"status": "DENY", "reason": "Nonce expired"})

    # ── 4. Context hash must match (prevents context tampering) ──────────────
    context_string = f"{username}{operation}{str(context)}"
    incoming_hash  = hashlib.sha256(context_string.encode()).hexdigest()
    if incoming_hash != stored["context_hash"]:
        return jsonify({"status": "DENY", "reason": "Context was tampered after challenge"})

    # ── 5. RSA-PSS signature verification ────────────────────────────────────
    #    This proves the nonce was signed by the device holding the private key,
    #    not just replayed by someone who intercepted it on the wire.
    if signature:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT public_key FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({"status": "DENY", "reason": "User not found"})
        if not verify_signature(row[0], nonce, signature):
            log_event(username, "INVALID_SIGNATURE", 0.95, operation)
            return jsonify({"status": "DENY", "reason": "Invalid signature — possible replay attack"})
    else:
        # No signature provided — deny, don't allow unsigned operation execution
        return jsonify({"status": "DENY", "reason": "Signature required"})

    # ── 6. Risk scoring ───────────────────────────────────────────────────────
    ip = request.remote_addr
    risk, reasons = calculate_operation_risk(username, operation, ip, context)

    if risk < 0.40:
        decision = "ALLOW"
    elif risk < 0.70:
        decision = "STEP_UP"
    else:
        decision = "DENY"

    log_event(username, decision, risk, operation)
    return jsonify({
        "status":  decision,
        "risk":    round(risk * 100),   # return as 0–100 so UI matches risk_policy.py scale
        "reasons": reasons
    })


# =====================================================
# STEP-UP AUTHENTICATION (RSA re-sign with device key)
# =====================================================
@app.route("/stepup-challenge", methods=["POST"])
def stepup_challenge():
    data      = request.json
    username  = data["username"]
    operation = data["operation"]
    nonce     = base64.b64encode(os.urandom(32)).decode()
    OPERATION_NONCES[username] = {
        "nonce":     nonce,
        "operation": operation,
        "timestamp": time.time(),
        "stepup":    True
    }
    return jsonify({"nonce": nonce})


@app.route("/stepup-verify", methods=["POST"])
def stepup_verify():
    data      = request.json
    username  = data["username"]
    operation = data["operation"]
    signature = data["signature"]

    if username not in OPERATION_NONCES:
        return jsonify({"status": "DENY", "reason": "No pending step-up"})

    stored = OPERATION_NONCES.pop(username)

    if stored["operation"] != operation:
        return jsonify({"status": "DENY", "reason": "Operation mismatch"})

    if time.time() - stored["timestamp"] > 60:
        return jsonify({"status": "DENY", "reason": "Step-up nonce expired"})

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row  = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "DENY", "reason": "User not found"})

    ok = verify_signature(row[0], stored["nonce"], signature)
    if ok:
        log_event(username, "STEPUP_SUCCESS", 0.2, operation)
        return jsonify({"status": "UPGRADED_ALLOW"})
    else:
        log_event(username, "STEPUP_DENIED", 0.9, operation)
        return jsonify({"status": "DENY", "reason": "Signature verification failed"})


# =====================================================
# LOGS
# =====================================================
@app.route("/logs", methods=["GET"])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, user, result, timestamp, riskScore, action, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "user": r[1], "result": r[2], "timestamp": r[3],
         "riskScore": r[4], "action": r[5], "hash": r[6]}
        for r in rows
    ])


@app.route("/verify-logs", methods=["GET"])
def verify_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    prev_hash = "GENESIS"
    for row in rows:
        user, result, timestamp, risk, action, stored_prev, stored_current = row
        if stored_prev != prev_hash:
            return jsonify({"integrity": "TAMPERED"})
        log_data = f"{user}{result}{timestamp}{risk}{action}"
        expected = compute_hash(prev_hash + log_data)
        if stored_current != expected:
            return jsonify({"integrity": "TAMPERED"})
        prev_hash = stored_current
    return jsonify({"integrity": "OK"})


if __name__ == "__main__":
    app.run(debug=True)