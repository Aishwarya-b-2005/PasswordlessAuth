"""
simulate_risk.py

Offline risk score distribution simulation using RiskPolicyEngine.
Generates normal vs attack distributions and prints mean/stddev.

Usage:
  cd backend
  python simulate_risk.py
"""

from __future__ import annotations

import sqlite3
import statistics

from risk_policy import RiskPolicyEngine


def setup_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute(
        """
        CREATE TABLE audit_logs (
            user TEXT,
            action TEXT,
            result TEXT,
            risk_score INTEGER,
            timestamp REAL,
            hash TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE sessions (
            username TEXT,
            login_timestamp REAL,
            fingerprint TEXT
        )
        """
    )
    db.execute("INSERT INTO sessions VALUES ('alice', 9999999999, 'fp_alice')")
    db.commit()
    return db


def run() -> None:
    engine = RiskPolicyEngine()
    db = setup_db()

    scores_normal: list[int] = []
    for op in ["READ", "WRITE", "TRANSFER", "DELETE"]:
        ctx = {
            "deviceFingerprint": "fp_alice",
            "mouseMovementDetected": True,
            "keyboardInteractionDetected": True,
            "timeOnPageMs": 5000,
            "amount": 100,
        }
        d = engine.evaluate("alice", op, ctx, db)
        scores_normal.append(d.score)
        print(f"normal  {op:8s}: score={d.score:3d} -> {d.status}")

    scores_attack: list[int] = []
    for op in ["READ", "WRITE", "TRANSFER", "DELETE"]:
        ctx = {
            "deviceFingerprint": "fp_attacker",
            "mouseMovementDetected": False,
            "keyboardInteractionDetected": False,
            "timeOnPageMs": 300,
            "amount": 9000,
        }
        d = engine.evaluate("alice", op, ctx, db)
        scores_attack.append(d.score)
        print(f"attack  {op:8s}: score={d.score:3d} -> {d.status}")

    print(
        f"\nNormal -> mean={statistics.mean(scores_normal):.1f}, "
        f"std={statistics.stdev(scores_normal):.1f}"
    )
    print(
        f"Attack -> mean={statistics.mean(scores_attack):.1f}, "
        f"std={statistics.stdev(scores_attack):.1f}"
    )


if __name__ == "__main__":
    run()
