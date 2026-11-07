"""Train the risk model (logistic regression, plain-Python gradient descent, no new dependencies).

Reads the SYNTHETIC training set, holds out 20% (seeded shuffle), fits on the rest, and writes:
  models/risk_model_v1.json    model_version, features, coefficients, intercept,
                               young_account_days, trained_at, training_data_sha256, metrics
  models/risk_model_v1.sha256  SHA-256 of the JSON file (checked by scamcheck.model at load time)

Features come from scamcheck.model.extract_features, the same code the service uses to score.
PR-AUC is approximated by average precision on the held-out split.

Usage:
    python scripts/train_model.py [--data PATH] [--out-dir DIR] [--trained-at ISO_TIMESTAMP]
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from scamcheck.model import FEATURES, extract_features, sha256_hex, sigmoid
from scamcheck.policy import load_policy
from scamcheck.signals import NameMatch, Signals

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "sample-data" / "training" / "training_data.csv"
DEFAULT_OUT_DIR = ROOT / "models"
MODEL_VERSION = "risk_model_v1"
SEED = 42
HELD_OUT_SHARE = 0.20
LEARNING_RATE = 2.0
EPOCHS = 3000
L2 = 1e-3
TOLERANCE = 1e-6  # stop early when the largest gradient component falls below this
NOTE = "SYNTHETIC - trained on synthetic data only, not real customers or payments"


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        lines = [line for line in handle if not line.startswith("#")]
    return list(csv.DictReader(lines))


def row_to_signals(row: dict[str, str]) -> Signals:
    return Signals(
        new_payee=row["new_payee"] == "1",
        amount_ratio=Decimal(row["amount_ratio"]),
        payee_account_age_days=int(row["payee_account_age_days"]),
        payee_name_match=NameMatch[row["name_match"]],
        payee_on_mule_list=False,
        on_active_call=row["on_active_call"] == "1",
        remote_access_detected=row["remote_access_detected"] == "1",
        new_device=row["new_device"] == "1",
        data_complete=True,
    )


def build_dataset(
    rows: list[dict[str, str]], young_account_days: int
) -> tuple[list[list[float]], list[int]]:
    features = [extract_features(row_to_signals(r), young_account_days) for r in rows]
    return features, [int(r["label"]) for r in rows]


def split_indices(
    n: int, seed: int = SEED, held_out: float = HELD_OUT_SHARE
) -> tuple[list[int], list[int]]:
    order = list(range(n))
    random.Random(seed).shuffle(order)
    cut = int(n * held_out)
    return order[cut:], order[:cut]  # train, held-out


def fit(
    x: list[list[float]],
    y: list[int],
    *,
    learning_rate: float = LEARNING_RATE,
    epochs: int = EPOCHS,
    l2: float = L2,
) -> tuple[list[float], float, int]:
    """Batch gradient descent on L2-regularised log-loss. Returns (weights, intercept, epochs)."""
    n, d = len(x), len(x[0])
    w, b = [0.0] * d, 0.0
    for epoch in range(1, epochs + 1):
        grad, grad_b = [0.0] * d, 0.0
        for row, label in zip(x, y, strict=True):
            err = sigmoid(b + sum(wi * xi for wi, xi in zip(w, row, strict=True))) - label
            grad_b += err
            for j in range(d):
                grad[j] += err * row[j]
        grad = [g / n + l2 * wj for g, wj in zip(grad, w, strict=True)]
        grad_b /= n
        w = [wj - learning_rate * g for wj, g in zip(w, grad, strict=True)]
        b -= learning_rate * grad_b
        if max(max(abs(g) for g in grad), abs(grad_b)) < TOLERANCE:
            return w, b, epoch
    return w, b, epochs


def predict(w: list[float], b: float, x: list[list[float]]) -> list[float]:
    return [sigmoid(b + sum(wi * xi for wi, xi in zip(w, row, strict=True))) for row in x]


def precision_recall(
    scores: list[float], labels: list[int], threshold: float
) -> tuple[float, float]:
    predicted = [s >= threshold for s in scores]
    true_pos = sum(1 for p, y in zip(predicted, labels, strict=True) if p and y)
    flagged, positives = sum(predicted), sum(labels)
    precision = true_pos / flagged if flagged else 0.0
    recall = true_pos / positives if positives else 0.0
    return precision, recall


def average_precision(scores: list[float], labels: list[int]) -> float:
    """Approximate PR-AUC: mean of the precision at each true positive, ranking by score."""
    ranked = sorted(zip(scores, labels, strict=True), key=lambda pair: -pair[0])
    positives = sum(labels)
    if not positives:
        return 0.0
    seen_pos, total = 0, 0.0
    for rank, (_, label) in enumerate(ranked, start=1):
        if label:
            seen_pos += 1
            total += seen_pos / rank
    return total / positives


def compute_metrics(scores: list[float], labels: list[int], train_size: int) -> dict[str, Any]:
    policy = load_policy()
    metrics: dict[str, Any] = {
        "train_size": train_size,
        "held_out_size": len(labels),
        "held_out_positives": sum(labels),
        "pr_auc_approx": round(average_precision(scores, labels), 4),
    }
    for name, threshold in (
        ("at_0.50", 0.5),
        ("at_score_warn", policy.score_warn),
        ("at_score_hold", policy.score_hold),
    ):
        precision, recall = precision_recall(scores, labels, threshold)
        metrics[name] = {
            "threshold": threshold,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        }
    return metrics


def train(data_path: Path, trained_at: str) -> tuple[dict[str, Any], int]:
    """Train and return (artifact dict, epochs used)."""
    raw = data_path.read_bytes()
    young_days = load_policy().young_account_days
    x, y = build_dataset(read_rows(data_path), young_days)
    train_idx, held_idx = split_indices(len(x))
    w, b, epochs = fit([x[i] for i in train_idx], [y[i] for i in train_idx])
    scores = predict(w, b, [x[i] for i in held_idx])
    artifact = {
        "_note": NOTE,
        "model_version": MODEL_VERSION,
        "features": list(FEATURES),
        "coefficients": w,
        "intercept": b,
        "young_account_days": young_days,
        "trained_at": trained_at,
        "training_data_sha256": sha256_hex(raw),
        "metrics": compute_metrics(scores, [y[i] for i in held_idx], len(train_idx)),
    }
    return artifact, epochs


def write_artifact(artifact: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / f"{MODEL_VERSION}.json"
    body = (json.dumps(artifact, indent=2) + "\n").encode("utf-8")
    model_path.write_bytes(body)
    checksum_path = out_dir / f"{MODEL_VERSION}.sha256"
    checksum_path.write_text(f"{sha256_hex(body)}  {model_path.name}\n", encoding="utf-8")
    return model_path, checksum_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the SYNTHETIC risk model.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--trained-at", default=datetime.now(UTC).isoformat(timespec="seconds"))
    args = parser.parse_args()

    started = time.perf_counter()
    artifact, epochs = train(args.data, args.trained_at)
    model_path, checksum_path = write_artifact(artifact, args.out_dir)
    print(f"trained in {time.perf_counter() - started:.1f}s ({epochs} epochs)")
    print(f"wrote {model_path}\nwrote {checksum_path}")
    print("coefficients:")
    for name, coef in zip(FEATURES, artifact["coefficients"], strict=True):
        print(f"  {name:<24}{coef:+.4f}")
    print(f"  {'intercept':<24}{artifact['intercept']:+.4f}")
    print("held-out metrics:")
    print(json.dumps(artifact["metrics"], indent=2))


if __name__ == "__main__":
    main()
