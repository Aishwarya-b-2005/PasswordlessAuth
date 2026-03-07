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
# Password = "admin1234" hashed with PBKDF2-HMAC-SHA256
# To change the password, run:
#   python3 -c "import hashlib,os,base64; s=os.urandom(16); print(base64.b64encode(s).decode(),'|',hashlib.pbkdf2_hmac('sha256',b'YOUR_NEW_PASSWORD',s,260000).hex())"
# then update ADMIN_SALT and ADMIN_HASH below.
# =====================================================
ADMIN_USERNAME = "admin"
ADMIN_SALT_B64 = "TXlTZWN1cmVTYWx0MTY="          # base64 of a fixed 16-byte salt
ADMIN_HASH     = hashlib.pbkdf2_hmac(
    "sha256",
    b"admin1234",
    base64.b64decode(ADMIN_SALT_B64),
    260_000
).hex()

# In-memory admin sessions  { token -> expiry_timestamp }
ADMIN_SESSIONS: dict = {}
ADMIN_SESSION_TTL = 3600   # 1 hour

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
    """Return True if the request carries a valid admin session token."""
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


def calculate_operation_risk(username, operation, ip, context):
    risk   = 0.0
    amount = context.get("amount", 0)

    if operation == "TRANSFER":
        risk += 0.2
    elif operation == "CLOSE_ACCOUNT":
        risk += 0.6
    elif operation == "ACCOUNT_DETAILS":
        risk += 0.3
    elif operation == "SENSITIVE_RECORDS":
        risk += 0.1

    if amount > 10000:
        risk += 0.5
    elif amount > 5000:
        risk += 0.3
    elif amount > 1000:
        risk += 0.1

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT last_ip FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if row and row[0] and row[0] != ip:
        risk += 0.3

    current_hour = time.localtime().tm_hour
    if current_hour < 6 or current_hour > 22:
        risk += 0.2

    if username in OPERATION_NONCES:
        risk += 0.1

    return min(risk, 1.0)


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

    c.execute("INSERT INTO users (username, public_key) VALUES (?, ?)",
              (username, public_key))
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
    c    = conn.cursor()
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    exists = c.fetchone()
    conn.close()

    if not exists:
        return jsonify({"error": "User not found"}), 404

    nonce                 = base64.b64encode(os.urandom(32)).decode()
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
        c    = conn.cursor()
        c.execute("SELECT public_key FROM users WHERE username=?", (username,))
        row  = c.fetchone()
        conn.close()

        if not row:
            return jsonify({"status": "DENIED", "error": "User not found"})

        ok = verify_signature(row[0], nonce, signature)
        ip = request.remote_addr

        if ok:
            conn = sqlite3.connect(DB_FILE)
            c    = conn.cursor()
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
    """
    Password-based admin authentication.
    Verifies with PBKDF2-HMAC-SHA256 (same KDF used in the frontend deviceKey).
    Returns a short-lived session token on success.
    """
    data     = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if username != ADMIN_USERNAME:
        return jsonify({"status": "DENIED"}), 401

    salt        = base64.b64decode(ADMIN_SALT_B64)
    input_hash  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000).hex()

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
    c    = conn.cursor()
    c.execute("SELECT id, user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    logs = [
        {
            "id":           r[0],
            "user":         r[1],
            "result":       r[2],
            "timestamp":    r[3],
            "riskScore":    r[4],
            "action":       r[5],
            "prev_hash":    r[6],
            "current_hash": r[7],
        }
        for r in rows
    ]
    return jsonify(logs)


# =====================================================
# ADMIN — PER-ENTRY CHAIN VERIFICATION
# =====================================================
@app.route("/admin/verify-chain", methods=["GET"])
def admin_verify_chain():
    """
    Re-computes each entry's expected hash from scratch and compares
    it to the stored current_hash.

    Returns a list of per-entry results so the frontend can highlight
    exactly which row is broken and every row after it.
    """
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("""
        SELECT id, user, result, timestamp, riskScore, action, prev_hash, current_hash
        FROM logs ORDER BY id ASC
    """)
    rows = c.fetchall()
    conn.close()

    results      = []
    chain_broken = False   # once True, all subsequent rows are also flagged

    for i, row in enumerate(rows):
        id_, user, result, timestamp, risk, action, stored_prev, stored_current = row

        # What prev_hash SHOULD be
        if i == 0:
            expected_prev = "GENESIS"
        else:
            expected_prev = rows[i - 1][7]  # current_hash of previous row

        # Recompute current_hash
        log_data          = f"{user}{result}{timestamp}{risk}{action}"
        expected_current  = compute_hash(expected_prev + log_data)

        prev_ok    = (stored_prev == expected_prev)
        current_ok = (stored_current == expected_current)
        entry_ok   = prev_ok and current_ok and not chain_broken

        if not entry_ok:
            chain_broken = True

        results.append({
            "id":               id_,
            "user":             user,
            "result":           result,
            "timestamp":        timestamp,
            "riskScore":        risk,
            "action":           action,
            "stored_prev":      stored_prev,
            "stored_current":   stored_current,
            "expected_prev":    expected_prev,
            "expected_current": expected_current,
            "ok":               entry_ok,
            "tampered":         not entry_ok,
            # More specific flags for the UI
            "prev_mismatch":    not prev_ok,
            "hash_mismatch":    not current_ok,
        })

    overall = all(r["ok"] for r in results)
    return jsonify({"overall": overall, "entries": results})


# =====================================================
# ADMIN — TAMPER SIMULATOR (demo only)
# =====================================================
@app.route("/admin/tamper-log", methods=["POST"])
def admin_tamper_log():
    """
    Corrupts one log entry to simulate a database tampering attack.
    Picks the entry whose id is specified in the request body,
    or a random middle entry if none is given.

    This deliberately breaks the hash chain so the verify endpoint
    will detect it — for demo purposes only.
    """
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403

    data         = request.json or {}
    target_id    = data.get("target_id")   # optional: specific row id to tamper

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()

    if target_id:
        c.execute("SELECT id FROM logs WHERE id=?", (target_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Log entry not found"}), 404
        chosen_id = target_id
    else:
        # Pick a random entry that is not the very last one
        # (breaking a middle entry is more visually interesting)
        c.execute("SELECT id FROM logs ORDER BY id ASC")
        all_ids = [r[0] for r in c.fetchall()]
        if len(all_ids) < 2:
            conn.close()
            return jsonify({"error": "Need at least 2 log entries to simulate tampering"}), 400
        # Choose a middle entry (not the last)
        chosen_id = all_ids[len(all_ids) // 2]

    # Corrupt the result field and current_hash of the chosen entry
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
# ADMIN — RESTORE (undo tamper for demo reset)
# =====================================================
@app.route("/admin/restore-logs", methods=["POST"])
def admin_restore_logs():
    """
    Recomputes all hashes in sequence from GENESIS and writes them back.
    Effectively 'heals' the chain — call this after the tamper demo.
    """
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()

    # Strip _TAMPERED suffix from any result fields first
    c.execute("UPDATE logs SET result = REPLACE(result, '_TAMPERED', '')")

    # Re-read all rows in order
    c.execute("""
        SELECT id, user, result, timestamp, riskScore, action
        FROM logs ORDER BY id ASC
    """)
    rows = c.fetchall()

    prev_hash = "GENESIS"
    for row in rows:
        id_, user, result, timestamp, risk, action = row
        log_data     = f"{user}{result}{timestamp}{risk}{action}"
        current_hash = compute_hash(prev_hash + log_data)

        c.execute("""
            UPDATE logs
            SET prev_hash=?, current_hash=?
            WHERE id=?
        """, (prev_hash, current_hash, id_))

        prev_hash = current_hash

    conn.commit()
    conn.close()

    return jsonify({"status": "RESTORED"})


# =====================================================
# EXISTING: OPERATION ENDPOINTS (unchanged)
# =====================================================
@app.route("/operation-challenge", methods=["POST"])
def operation_challenge():
    data     = request.json
    username = data["username"]
    operation = data["operation"]
    context  = data.get("context", {})

    context_string = f"{username}{operation}{str(context)}"
    context_hash   = hashlib.sha256(context_string.encode()).hexdigest()
    nonce          = base64.b64encode(os.urandom(16)).decode()

    OPERATION_NONCES[username] = {
        "nonce":        nonce,
        "operation":    operation,
        "context_hash": context_hash,
        "timestamp":    time.time()
    }
    return jsonify({"nonce": nonce, "operation": operation})


@app.route("/execute-operation", methods=["POST"])
def execute_operation():
    data      = request.json
    username  = data["username"]
    operation = data["operation"]
    nonce     = data["nonce"]
    context   = data.get("context", {})

    if username not in OPERATION_NONCES:
        return jsonify({"status": "DENY", "reason": "No nonce"})

    stored = OPERATION_NONCES.pop(username)

    if nonce != stored["nonce"] or operation != stored["operation"]:
        return jsonify({"status": "DENY", "reason": "Context mismatch"})

    if time.time() - stored["timestamp"] > 60:
        return jsonify({"status": "DENY", "reason": "Expired"})

    context_string = f"{username}{operation}{str(context)}"
    incoming_hash  = hashlib.sha256(context_string.encode()).hexdigest()

    if incoming_hash != stored["context_hash"]:
        return jsonify({"status": "DENY", "reason": "Tampered context"})

    ip   = request.remote_addr
    risk = calculate_operation_risk(username, operation, ip, context)

    if risk < 0.3:
        decision = "ALLOW"
    elif risk < 0.7:
        decision = "STEP_UP"
    else:
        decision = "DENY"

    log_event(username, decision, risk, operation)
    return jsonify({"status": decision, "risk": risk})


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
        return jsonify({"status": "DENY"})

    stored = OPERATION_NONCES.pop(username)

    if stored["operation"] != operation:
        return jsonify({"status": "DENY"})

    if time.time() - stored["timestamp"] > 60:
        return jsonify({"status": "DENY"})

    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row  = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "DENY"})

    ok = verify_signature(row[0], stored["nonce"], signature)

    if ok:
        log_event(username, "STEPUP_SUCCESS", 0.2, operation)
        return jsonify({"status": "UPGRADED_ALLOW"})
    else:
        log_event(username, "STEPUP_DENIED", 0.9, operation)
        return jsonify({"status": "DENY"})


# =====================================================
# EXISTING: PUBLIC LOG + INTEGRITY ENDPOINTS
# =====================================================
@app.route("/logs", methods=["GET"])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT id, user, result, timestamp, riskScore, action, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    return jsonify([
        {
            "id":        r[0],
            "user":      r[1],
            "result":    r[2],
            "timestamp": r[3],
            "riskScore": r[4],
            "action":    r[5],
            "hash":      r[6],
        }
        for r in rows
    ])


@app.route("/verify-logs", methods=["GET"])
def verify_logs():
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute("SELECT user, result, timestamp, riskScore, action, prev_hash, current_hash FROM logs ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    prev_hash = "GENESIS"
    for row in rows:
        user, result, timestamp, risk, action, stored_prev, stored_current = row
        if stored_prev != prev_hash:
            return jsonify({"integrity": "TAMPERED"})
        log_data  = f"{user}{result}{timestamp}{risk}{action}"
        expected  = compute_hash(prev_hash + log_data)
        if stored_current != expected:
            return jsonify({"integrity": "TAMPERED"})
        prev_hash = stored_current

    return jsonify({"integrity": "OK"})


if __name__ == "__main__":
    app.run(debug=True)