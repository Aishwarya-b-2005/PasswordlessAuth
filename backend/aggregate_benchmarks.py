"""
aggregate_benchmarks.py

Aggregate multiple metrics_summary JSON files and report mean +- stddev.

Usage:
  cd backend
  python3 aggregate_benchmarks.py metrics_run1.json metrics_run2.json metrics_run3.json --output aggregate_summary.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def pull_metric(doc: dict[str, Any], dotted: str) -> float:
    cur: Any = doc
    for key in dotted.split("."):
        cur = cur[key]
    return float(cur)


def summarize(values: list[float]) -> dict[str, float]:
    mean = statistics.mean(values) if values else 0.0
    stddev = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "mean": round(mean, 4),
        "stddev": round(stddev, 4),
        "n": len(values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate benchmark run JSON files.")
    parser.add_argument("inputs", nargs="+", help="Input metrics_summary*.json files")
    parser.add_argument("--output", default="aggregate_summary.json", help="Output aggregate JSON")
    args = parser.parse_args()

    files = [Path(p) for p in args.inputs]
    docs = [load_json(p) for p in files]

    metrics = {
        "security.farFrr.farPercent": "farPercent",
        "security.farFrr.frrPercent": "frrPercent",
        "security.deviceBinding.deviceBindingViolationRatePercent": "deviceBindingViolationRatePercent",
        "security.botDetection.botDetectionAccuracyPercent": "botDetectionAccuracyPercent",
        "security.auditIntegrity.auditLogIntegrityRatePercent": "auditLogIntegrityRatePercent",
        "riskEngine.distribution.stepUpTriggerRatePercent": "stepUpTriggerRatePercent",
        "riskEngine.distribution.denyRateAttackMixPercent": "denyRateAttackMixPercent",
        "riskEngine.distribution.denyRateLegitimatePercent": "denyRateLegitimatePercent",
        "riskEngine.distribution.denyRateAttackPercent": "denyRateAttackPercent",
        "riskEngine.distribution.stepUpRateLegitimatePercent": "stepUpRateLegitimatePercent",
        "riskEngine.distribution.stepUpRateAttackPercent": "stepUpRateAttackPercent",
        "riskEngine.distribution.riskScoreMean": "riskScoreMean",
        "riskEngine.distribution.riskScoreStdDev": "riskScoreStdDev",
        "riskEngine.distribution.riskComputationMsMean": "riskComputationMsMean",
        "riskEngine.distribution.riskComputationMsStdDev": "riskComputationMsStdDev",
    }

    out: dict[str, Any] = {
        "inputs": [str(p) for p in files],
        "summary": {},
    }

    for dotted, label in metrics.items():
        values = [pull_metric(doc, dotted) for doc in docs]
        out["summary"][label] = summarize(values)

    with Path(args.output).open("w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(json.dumps(out, indent=2))
    print(f"\nSaved aggregate summary to: {args.output}")


if __name__ == "__main__":
    main()
