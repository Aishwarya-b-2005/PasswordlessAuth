import sqlite3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

DB_NAME = "database/database.db"

def get_public_key(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT public_key FROM users WHERE username=?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    # row[0] is base64 DER
    public_key_der = base64.b64decode(row[0])

    return serialization.load_der_public_key(public_key_der)

def verify_signature(username, signature, nonce):
    public_key = get_public_key(username)
    if not public_key:
        return False

    try:
        public_key.verify(
            signature,
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("[VERIFY ERROR]", e)
        return False
