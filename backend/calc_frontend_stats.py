import json
import re
import statistics
from pathlib import Path

text = Path("backend/frontend_metrics_raw.txt").read_text(encoding="utf-8")

patterns = {
    "keygen_ms": r"\[METRIC\] Key Generation: ([0-9.]+) ms",
    "pbkdf2_ms": r"\[METRIC\] PBKDF2 Derivation: ([0-9.]+) ms",
    "registration_sec": r"\[METRIC\] Registration Time: ([0-9.]+) sec",
    "login_ms": r"\[METRIC\] Total Login Latency: ([0-9.]+) ms",
}

out = {}
for key, pattern in patterns.items():
    values = [float(v) for v in re.findall(pattern, text)]
    out[key] = {
        "n": len(values),
        "mean": round(statistics.mean(values), 3) if values else None,
        "stddev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        "min": round(min(values), 3) if values else None,
        "max": round(max(values), 3) if values else None,
    }

print(json.dumps(out, indent=2))
