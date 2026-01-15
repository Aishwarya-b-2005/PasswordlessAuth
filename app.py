# from flask import Flask, render_template, request, jsonify
# from security.audit_log import add_log_entry, verify_log_integrity
# import sqlite3

# app = Flask(__name__)

# @app.route("/")
# def index():
#     return render_template("index.html")

# @app.route("/admin")
# def admin():
#     return render_template("admin.html")

# @app.route("/request-access", methods=["POST"])
# def request_access():
#     user = request.form.get("username")

#     # Temporary access logic
#     access_granted = True

#     add_log_entry(
#         user=user,
#         action="ACCESS_REQUEST",
#         result="GRANTED" if access_granted else "DENIED"
#     )

#     return jsonify({"status": "GRANTED" if access_granted else "DENIED"})

# @app.route("/verify-logs")
# def verify_logs():
#     integrity = verify_log_integrity()
#     return jsonify({"integrity": "OK" if integrity else "TAMPERED"})

# @app.route("/get-logs")
# def get_logs():
#     conn = sqlite3.connect("database/database.db")
#     cursor = conn.cursor()
#     cursor.execute("""
#         SELECT user, action, result, timestamp
#         FROM audit_log ORDER BY id DESC
#     """)
#     logs = cursor.fetchall()
#     conn.close()

#     return jsonify(logs)

# if __name__ == "__main__":
#     app.run(debug=True)
from flask import Flask, render_template, request, jsonify
import os, base64, sqlite3

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

@app.route("/challenge/<username>")
def challenge(username):
    nonce = os.urandom(32)
    challenges[username] = nonce
    return jsonify({"nonce": base64.b64encode(nonce).decode()})

@app.route("/request-access", methods=["POST"])
def request_access():
    data = request.json
    username = data["username"]
    signature = base64.b64decode(data["signature"])

    nonce = challenges.get(username)
    if not nonce:
        return jsonify({"status": "DENIED"})

    valid = verify_signature(username, signature, nonce)
    result = "GRANTED" if valid else "DENIED"

    add_log_entry(username, "ACCESS_REQUEST", result)
    return jsonify({"status": result})

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
