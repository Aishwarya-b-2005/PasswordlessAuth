from flask import Flask, render_template, request, jsonify
import os, base64, sqlite3
import time, hashlib
from security.audit_log import add_log_entry, verify_log_integrity
from security.auth import verify_signature

app = Flask(__name__)
challenges = {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    public_key = request.form["public_key"]

    conn = sqlite3.connect("database/database.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, public_key) VALUES (?, ?)",
            (username, public_key)
        )
        conn.commit()
        status = "REGISTERED"
    except sqlite3.IntegrityError:
        status = "USER_EXISTS"
    conn.close()

    return jsonify({"status": status})

NONCE_EXPIRY_SECONDS = 30


def cleanup_expired_nonces():
    now = time.time()
    expired = [
        user for user, data in challenges.items()
        if now - data["timestamp"] > NONCE_EXPIRY_SECONDS
    ]
    for user in expired:
        del challenges[user]


@app.route("/challenge/<username>")
def challenge(username):
    cleanup_expired_nonces()

    nonce = os.urandom(32)

    challenges[username] = {
        "nonce": nonce,
        "timestamp": time.time()
    }

    return jsonify({"nonce": base64.b64encode(nonce).decode()})

@app.route("/request-access", methods=["POST"])
def request_access():
    data = request.json
    username = data["username"]
    signature = base64.b64decode(data["signature"])

    challenge_data = challenges.get(username)

    # ❌ No challenge
    if not challenge_data:
        add_log_entry(username, "LOGIN_FAILED_NO_CHALLENGE", "DENIED")
        return jsonify({"status": "DENIED"})

    # ⏱️ Expiry check
    if time.time() - challenge_data["timestamp"] > NONCE_EXPIRY_SECONDS:
        del challenges[username]
        add_log_entry(username, "LOGIN_FAILED_EXPIRED_NONCE", "DENIED")
        return jsonify({"status": "DENIED"})

    nonce = challenge_data["nonce"]

    # 🔐 Verify signature
    valid = verify_signature(username, signature, nonce)

    if valid:
        # ✅ Single-use nonce → delete after success
        del challenges[username]
        add_log_entry(username, "LOGIN_SUCCESS", "GRANTED")
        return jsonify({"status": "GRANTED"})

    # ❌ Invalid signature
    add_log_entry(username, "LOGIN_FAILED_INVALID_SIGNATURE", "DENIED")
    return jsonify({"status": "DENIED"})

@app.route("/verify-logs")
def verify_logs():
    return jsonify({
        "integrity": "OK" if verify_log_integrity() else "TAMPERED"
    })

@app.route("/get-logs")
def get_logs():
    conn = sqlite3.connect("database/database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user, action, result, timestamp
        FROM audit_log ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    app.run(debug=True)
