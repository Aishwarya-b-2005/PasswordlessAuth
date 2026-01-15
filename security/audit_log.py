# import hashlib
# import sqlite3
# import time

# DB_NAME = "database/database.db"

# def init_db():
#     conn = sqlite3.connect(DB_NAME)
#     cursor = conn.cursor()
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS audit_log (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             user TEXT,
#             action TEXT,
#             result TEXT,
#             timestamp TEXT,
#             prev_hash TEXT,
#             curr_hash TEXT
#         )
#     """)
#     conn.commit()
#     conn.close()

# def get_last_hash():
#     conn = sqlite3.connect(DB_NAME)
#     cursor = conn.cursor()
#     cursor.execute("SELECT curr_hash FROM audit_log ORDER BY id DESC LIMIT 1")
#     row = cursor.fetchone()
#     conn.close()
#     return row[0] if row else "0"

# def add_log_entry(user, action, result):
#     timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
#     prev_hash = get_last_hash()

#     data = f"{user}{action}{result}{timestamp}{prev_hash}"
#     curr_hash = hashlib.sha256(data.encode()).hexdigest()

#     conn = sqlite3.connect(DB_NAME)
#     cursor = conn.cursor()
#     cursor.execute("""
#         INSERT INTO audit_log
#         (user, action, result, timestamp, prev_hash, curr_hash)
#         VALUES (?, ?, ?, ?, ?, ?)
#     """, (user, action, result, timestamp, prev_hash, curr_hash))
#     conn.commit()
#     conn.close()

# def verify_log_integrity():
#     conn = sqlite3.connect(DB_NAME)
#     cursor = conn.cursor()
#     cursor.execute("""
#         SELECT user, action, result, timestamp, prev_hash, curr_hash
#         FROM audit_log ORDER BY id
#     """)
#     logs = cursor.fetchall()
#     conn.close()

#     previous_hash = "0"
#     for log in logs:
#         data = f"{log[0]}{log[1]}{log[2]}{log[3]}{previous_hash}"
#         expected = hashlib.sha256(data.encode()).hexdigest()
#         if expected != log[5]:
#             return False
#         previous_hash = log[5]

#     return True

# init_db()
import hashlib
import sqlite3
import time

DB_NAME = "database/database.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            result TEXT,
            timestamp TEXT,
            prev_hash TEXT,
            curr_hash TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            public_key TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_last_hash():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT curr_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "0"

def add_log_entry(user, action, result):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    prev_hash = get_last_hash()
    data = f"{user}{action}{result}{timestamp}{prev_hash}"
    curr_hash = hashlib.sha256(data.encode()).hexdigest()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_log
        (user, action, result, timestamp, prev_hash, curr_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user, action, result, timestamp, prev_hash, curr_hash))
    conn.commit()
    conn.close()

def verify_log_integrity():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user, action, result, timestamp, prev_hash, curr_hash
        FROM audit_log ORDER BY id
    """)
    logs = cursor.fetchall()
    conn.close()

    prev = "0"
    for log in logs:
        data = f"{log[0]}{log[1]}{log[2]}{log[3]}{prev}"
        expected = hashlib.sha256(data.encode()).hexdigest()
        if expected != log[5]:
            return False
        prev = log[5]

    return True

init_db()
