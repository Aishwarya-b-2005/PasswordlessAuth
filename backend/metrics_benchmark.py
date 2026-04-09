"""
metrics_benchmark.py

Runs reproducible security and risk-engine metric trials against the live backend.

Usage:
  cd backend
  python metrics_benchmark.py --base-url http://127.0.0.1:5000 --trials 30 --output metrics_summary.json
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3
import statistics
import time
from dataclasses import dataclass
from typing import Any

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass
class BenchConfig:
    base_url: str
    trials: int
    user_prefix: str
    db_path: str
    output: str
    nonce_expiry_attempts: int
    nonce_wait_seconds: int


def make_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def sign_nonce(private_key: rsa.RSAPrivateKey, nonce_b64: str) -> str:
    signature = private_key.sign(
        base64.b64decode(nonce_b64),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def cleanup_user(db_path: str, username: str) -> None:
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM logs WHERE user=?", (username,))
        conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()


def clear_user_logs(db_path: str, username: str) -> None:
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM logs WHERE user=?", (username,))
        conn.commit()
    finally:
        conn.close()


def register_user(base_url: str, username: str, public_key: str) -> dict[str, Any]:
    return requests.post(
        f"{base_url}/register",
        json={"username": username, "publicKey": public_key},
        timeout=15,
    ).json()


def get_login_nonce(base_url: str, username: str) -> str:
    payload = requests.post(
        f"{base_url}/challenge",
        json={"username": username},
        timeout=15,
    ).json()
    return payload["nonce"]


def verify_login(base_url: str, username: str, signature: str) -> dict[str, Any]:
    return requests.post(
        f"{base_url}/login",
        json={"username": username, "signature": signature},
        timeout=15,
    ).json()


def issue_operation_challenge(base_url: str, username: str, operation: str, context: dict[str, Any]) -> dict[str, Any]:
    return requests.post(
        f"{base_url}/operation-challenge",
        json={"username": username, "operation": operation, "context": context},
        timeout=15,
    ).json()


def execute_operation(
    base_url: str,
    username: str,
    operation: str,
    nonce: str,
    context: dict[str, Any],
    signature: str,
) -> dict[str, Any]:
    return requests.post(
        f"{base_url}/execute-operation",
        json={
            "username": username,
            "operation": operation,
            "nonce": nonce,
            "context": context,
            "signature": signature,
        },
        timeout=15,
    ).json()


def run_far_and_frr(config: BenchConfig, username: str, private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    legit_denied = 0
    replay_accepted = 0

    for _ in range(config.trials):
        nonce = get_login_nonce(config.base_url, username)
        signature = sign_nonce(private_key, nonce)

        legit_resp = verify_login(config.base_url, username, signature)
        if legit_resp.get("status") != "SUCCESS":
            legit_denied += 1

        replay_resp = verify_login(config.base_url, username, signature)
        if replay_resp.get("status") == "SUCCESS":
            replay_accepted += 1

    frr = (legit_denied / config.trials) * 100.0 if config.trials else 0.0
    far = (replay_accepted / config.trials) * 100.0 if config.trials else 0.0

    return {
        "trials": config.trials,
        "legitimateDenied": legit_denied,
        "replayAccepted": replay_accepted,
        "frrPercent": round(frr, 3),
        "farPercent": round(far, 3),
    }


def _operation_with_context(
    config: BenchConfig,
    username: str,
    private_key: rsa.RSAPrivateKey,
    context: dict[str, Any],
    operation: str = "TRANSFER",
) -> dict[str, Any]:
    challenge = issue_operation_challenge(config.base_url, username, operation, context)
    nonce = challenge["nonce"]
    signature = sign_nonce(private_key, nonce)
    return execute_operation(config.base_url, username, operation, nonce, context, signature)


def run_device_binding_violation_rate(config: BenchConfig, username: str, private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    accepted_on_other_device = 0
    denied_or_stepup = 0

    wrong_device_context = {
        "deviceFingerprint": "DIFFERENT_DEVICE_FINGERPRINT_HASH",
        "mouseMovementDetected": True,
        "keyboardInteractionDetected": True,
        "timeOnPageMs": 5000,
        "sessionAgeMs": 5000,
        "amount": 100,
        "timezone": "Asia/Kolkata",
        "connectionType": "wifi",
    }

    for _ in range(config.trials):
        resp = _operation_with_context(config, username, private_key, wrong_device_context)
        status = resp.get("status", "")
        if status == "ALLOW":
            accepted_on_other_device += 1
        else:
            denied_or_stepup += 1

    violation_rate = (accepted_on_other_device / config.trials) * 100.0 if config.trials else 0.0
    return {
        "trials": config.trials,
        "acceptedFromDifferentDevice": accepted_on_other_device,
        "blockedOrEscalated": denied_or_stepup,
        "deviceBindingViolationRatePercent": round(violation_rate, 3),
    }


def run_bot_detection_accuracy(config: BenchConfig, username: str, private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    tp = fp = tn = fn = 0

    bot_context = {
        "deviceFingerprint": "fp_valid",
        "mouseMovementDetected": False,
        "keyboardInteractionDetected": False,
        "timeOnPageMs": 300,
        "sessionAgeMs": 4000,
        "amount": 100,
        "timezone": "Asia/Kolkata",
        "connectionType": "wifi",
    }
    human_context = {
        "deviceFingerprint": "fp_valid",
        "mouseMovementDetected": True,
        "keyboardInteractionDetected": True,
        "timeOnPageMs": 5000,
        "sessionAgeMs": 4000,
        "amount": 100,
        "timezone": "Asia/Kolkata",
        "connectionType": "wifi",
    }

    def is_flagged(status: str) -> bool:
        return status in ("STEP_UP", "DENY")

    for _ in range(config.trials):
        # Keep velocity signal from dominating classification across many back-to-back trials.
        clear_user_logs(config.db_path, username)
        bot_resp = _operation_with_context(config, username, private_key, bot_context)
        if is_flagged(bot_resp.get("status", "")):
            tp += 1
        else:
            fn += 1

        clear_user_logs(config.db_path, username)
        human_resp = _operation_with_context(config, username, private_key, human_context)
        if is_flagged(human_resp.get("status", "")):
            fp += 1
        else:
            tn += 1

    total = tp + tn + fp + fn
    accuracy = ((tp + tn) / total) * 100.0 if total else 0.0

    return {
        "trialsPerClass": config.trials,
        "confusionMatrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "botDetectionAccuracyPercent": round(accuracy, 3),
    }


def run_risk_distribution(config: BenchConfig, username: str, private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    statuses: list[str] = []
    scores: list[float] = []
    risk_times: list[float] = []
    legit_statuses: list[str] = []
    attack_statuses: list[str] = []

    scenarios = [
        {
            "name": "normal",
            "context": {
                "deviceFingerprint": "fp_valid",
                "mouseMovementDetected": True,
                "keyboardInteractionDetected": True,
                "timeOnPageMs": 5000,
                "sessionAgeMs": 5000,
                "amount": 100,
                "timezone": "Asia/Kolkata",
                "connectionType": "wifi",
            },
        },
        {
            "name": "attack",
            "context": {
                "deviceFingerprint": "fp_attacker",
                "mouseMovementDetected": False,
                "keyboardInteractionDetected": False,
                "timeOnPageMs": 300,
                "sessionAgeMs": 300000,
                "amount": 9000,
                "timezone": "Asia/Kolkata",
                "connectionType": "unknown",
            },
        },
    ]

    for i in range(max(config.trials, 100)):
        scenario = scenarios[i % len(scenarios)]
        resp = _operation_with_context(config, username, private_key, scenario["context"])
        status = resp.get("status", "UNKNOWN")
        statuses.append(status)
        scores.append(float(resp.get("risk", 0)))
        risk_times.append(float(resp.get("riskComputationMs", 0.0)))

        if scenario["name"] == "normal":
            legit_statuses.append(status)
        else:
            attack_statuses.append(status)

    step_up_rate = (statuses.count("STEP_UP") / len(statuses)) * 100.0 if statuses else 0.0
    deny_rate = (statuses.count("DENY") / len(statuses)) * 100.0 if statuses else 0.0

    deny_rate_legit = (legit_statuses.count("DENY") / len(legit_statuses)) * 100.0 if legit_statuses else 0.0
    deny_rate_attack = (attack_statuses.count("DENY") / len(attack_statuses)) * 100.0 if attack_statuses else 0.0
    stepup_rate_legit = (legit_statuses.count("STEP_UP") / len(legit_statuses)) * 100.0 if legit_statuses else 0.0
    stepup_rate_attack = (attack_statuses.count("STEP_UP") / len(attack_statuses)) * 100.0 if attack_statuses else 0.0

    spread = statistics.stdev(scores) if len(scores) > 1 else 0.0
    risk_mean = statistics.mean(scores) if scores else 0.0

    risk_time_mean = statistics.mean(risk_times) if risk_times else 0.0
    risk_time_std = statistics.stdev(risk_times) if len(risk_times) > 1 else 0.0

    return {
        "samples": len(scores),
        "legitimateSamples": len(legit_statuses),
        "attackSamples": len(attack_statuses),
        "riskScoreMean": round(risk_mean, 3),
        "riskScoreStdDev": round(spread, 3),
        "stepUpTriggerRatePercent": round(step_up_rate, 3),
        "denyRateAttackMixPercent": round(deny_rate, 3),
        "denyRateLegitimatePercent": round(deny_rate_legit, 3),
        "denyRateAttackPercent": round(deny_rate_attack, 3),
        "stepUpRateLegitimatePercent": round(stepup_rate_legit, 3),
        "stepUpRateAttackPercent": round(stepup_rate_attack, 3),
        "riskComputationMsMean": round(risk_time_mean, 3),
        "riskComputationMsStdDev": round(risk_time_std, 3),
    }


def run_nonce_expiry_violation(config: BenchConfig, username: str, private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    context = {
        "deviceFingerprint": "fp_valid",
        "mouseMovementDetected": True,
        "keyboardInteractionDetected": True,
        "timeOnPageMs": 5000,
        "sessionAgeMs": 5000,
        "amount": 100,
    }
    attempts = max(config.nonce_expiry_attempts, 1)
    violations = 0
    last_response: dict[str, Any] = {}

    for i in range(attempts):
        challenge = issue_operation_challenge(config.base_url, username, "TRANSFER", context)
        nonce = challenge["nonce"]
        signature = sign_nonce(private_key, nonce)

        # Nonce lifetime is 60s in backend policy.
        time.sleep(config.nonce_wait_seconds)
        resp = execute_operation(config.base_url, username, "TRANSFER", nonce, context, signature)
        last_response = resp
        if resp.get("reason") == "Nonce expired":
            violations += 1

        # Keep runs independent from velocity signal side effects.
        if i < attempts - 1:
            clear_user_logs(config.db_path, username)

    return {
        "attempts": attempts,
        "nonceWaitSeconds": config.nonce_wait_seconds,
        "nonceExpiryViolations": violations,
        "nonceExpiryViolationRatePercent": round((violations / attempts) * 100.0, 3),
        "lastResponse": last_response,
    }


def run_audit_integrity_detection(config: BenchConfig) -> dict[str, Any]:
    verify_before = requests.get(f"{config.base_url}/verify-logs", timeout=15).json()

    conn = sqlite3.connect(config.db_path)
    try:
        row = conn.execute("SELECT id FROM logs ORDER BY id ASC LIMIT 1").fetchone()
        tamper_id = int(row[0]) if row else None
        if tamper_id is not None:
            tag = f"_TAMPER_{int(time.time() * 1000)}"
            conn.execute("UPDATE logs SET result = result || ? WHERE id=?", (tag, tamper_id))
            conn.commit()
    finally:
        conn.close()

    verify_after = requests.get(f"{config.base_url}/verify-logs", timeout=15).json()

    # Restore via admin API so chain is usable for subsequent experiments.
    admin_login = requests.post(
        f"{config.base_url}/admin/login",
        json={"username": "admin", "password": "admin1234"},
        timeout=15,
    ).json()
    token = admin_login.get("token")
    restore_resp: dict[str, Any] = {"status": "SKIPPED"}
    if token:
        restore_resp = requests.post(
            f"{config.base_url}/admin/restore-logs",
            headers={"X-Admin-Token": token},
            timeout=15,
        ).json()

    detection = 1 if verify_after.get("integrity") == "TAMPERED" else 0
    return {
        "integrityBefore": verify_before.get("integrity"),
        "integrityAfterTamper": verify_after.get("integrity"),
        "auditLogIntegrityRatePercent": float(detection * 100),
        "restore": restore_resp,
    }


def build_config() -> BenchConfig:
    parser = argparse.ArgumentParser(description="Run security and risk metrics benchmarks.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000", help="Backend base URL")
    parser.add_argument("--trials", type=int, default=30, help="Trials for rate metrics")
    parser.add_argument("--user-prefix", default="metrics_user", help="Test user prefix")
    parser.add_argument("--db-path", default="securebank.db", help="Path to sqlite DB file")
    parser.add_argument("--output", default="metrics_summary.json", help="Output JSON file")
    parser.add_argument(
        "--include-nonce-expiry",
        action="store_true",
        help="Run nonce-expiry test (adds 61s wait)",
    )
    parser.add_argument(
        "--nonce-expiry-attempts",
        type=int,
        default=1,
        help="How many nonce-expiry checks to run when --include-nonce-expiry is enabled",
    )
    parser.add_argument(
        "--nonce-wait-seconds",
        type=int,
        default=61,
        help="Sleep duration before execute-operation in nonce-expiry test; must be > 60",
    )
    args = parser.parse_args()

    return BenchConfig(
        base_url=args.base_url,
        trials=max(args.trials, 1),
        user_prefix=args.user_prefix,
        db_path=args.db_path,
        output=args.output,
        nonce_expiry_attempts=max(args.nonce_expiry_attempts, 1),
        nonce_wait_seconds=max(args.nonce_wait_seconds, 61),
    ), args.include_nonce_expiry


def main() -> None:
    config, include_nonce_expiry = build_config()
    username = f"{config.user_prefix}_{int(time.time())}"

    private_key, public_key = make_keypair()

    cleanup_user(config.db_path, username)
    reg = register_user(config.base_url, username, public_key)
    if reg.get("status") not in {"REGISTERED", "EXISTS"}:
        raise RuntimeError(f"Unable to register user: {reg}")

    # Seed session/IP baseline by performing one successful login.
    first_nonce = get_login_nonce(config.base_url, username)
    first_signature = sign_nonce(private_key, first_nonce)
    verify_login(config.base_url, username, first_signature)

    summary: dict[str, Any] = {
        "meta": {
            "baseUrl": config.base_url,
            "trials": config.trials,
            "username": username,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "nonceExpiryAttempts": config.nonce_expiry_attempts,
            "nonceWaitSeconds": config.nonce_wait_seconds,
        },
        "security": {},
        "riskEngine": {},
    }

    summary["security"]["farFrr"] = run_far_and_frr(config, username, private_key)
    summary["security"]["deviceBinding"] = run_device_binding_violation_rate(config, username, private_key)
    summary["security"]["botDetection"] = run_bot_detection_accuracy(config, username, private_key)
    summary["security"]["auditIntegrity"] = run_audit_integrity_detection(config)

    if include_nonce_expiry:
        summary["security"]["nonceExpiry"] = run_nonce_expiry_violation(config, username, private_key)

    summary["riskEngine"]["distribution"] = run_risk_distribution(config, username, private_key)

    with open(config.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"\nSaved metrics summary to: {config.output}")


if __name__ == "__main__":
    main()
