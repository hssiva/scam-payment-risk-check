import csv
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from scamcheck.model import FEATURES, ModelRuntime, load_model

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "sample-data" / "training" / "training_data.csv"
MODEL_DIR = ROOT / "models"


def load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses with postponed annotations need this
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    return load_script("generate_training_data")


@pytest.fixture(scope="module")
def trainer() -> ModuleType:
    return load_script("train_model")


def data_rows() -> list[dict[str, str]]:
    lines = [line for line in DATA.read_text().splitlines(keepends=True) if line[0] != "#"]
    return list(csv.DictReader(lines))


# --- training data generator --------------------------------------------------------------


def test_generator_reproduces_committed_data_exactly(gen: ModuleType, tmp_path: Path) -> None:
    out = gen.generate(tmp_path / "t.csv")
    assert out.read_bytes() == DATA.read_bytes()


def test_generator_is_seeded(gen: ModuleType) -> None:
    assert gen.generate_rows(200, seed=42) == gen.generate_rows(200, seed=42)
    assert gen.generate_rows(200, seed=42) != gen.generate_rows(200, seed=43)
    assert gen.SEED == 42


def test_committed_data_is_labelled_synthetic_and_sized() -> None:
    assert DATA.read_text().startswith("# SYNTHETIC")
    assert len(data_rows()) == 5000


def test_scam_share_and_patterns() -> None:
    rows = data_rows()
    share = sum(int(r["label"]) for r in rows) / len(rows)
    assert 0.12 <= share <= 0.18
    patterns = {r["pattern"] for r in rows}
    assert {"genuine", "coached_scam", "impersonation", "investment"} <= patterns
    assert all(r["label"] == "0" for r in rows if r["pattern"] == "genuine")
    assert all(r["label"] == "1" for r in rows if r["pattern"] != "genuine")


def test_scams_look_riskier_than_genuine_payments() -> None:
    rows = data_rows()

    def rate(column: str, label: str) -> float:
        subset = [r for r in rows if r["label"] == label]
        return sum(r[column] == "1" for r in subset) / len(subset)

    for column in ("new_payee", "on_active_call", "remote_access_detected"):
        assert rate(column, "1") > rate(column, "0")


def test_generated_values_are_in_range() -> None:
    for row in data_rows():
        assert float(row["amount_ratio"]) > 0
        assert int(row["payee_account_age_days"]) >= 1
        assert row["name_match"] in {"MATCH", "CLOSE", "MISMATCH"}


def test_training_data_does_not_overlap_evaluation_scenarios() -> None:
    assert DATA.parent.name == "training"
    assert DATA.parent != ROOT / "sample-data" / "scenarios"


# --- trainer ------------------------------------------------------------------------------


def test_precision_recall(trainer: ModuleType) -> None:
    scores = [0.9, 0.8, 0.4, 0.2]
    labels = [1, 0, 1, 0]
    assert trainer.precision_recall(scores, labels, 0.5) == (0.5, 0.5)
    assert trainer.precision_recall(scores, labels, 0.3) == (pytest.approx(2 / 3), 1.0)
    assert trainer.precision_recall(scores, labels, 0.95) == (0.0, 0.0)  # nothing flagged


def test_average_precision(trainer: ModuleType) -> None:
    assert trainer.average_precision([0.9, 0.8, 0.7, 0.6], [1, 0, 1, 0]) == pytest.approx(
        (1 / 1 + 2 / 3) / 2
    )
    assert trainer.average_precision([0.9, 0.8, 0.1], [1, 1, 0]) == 1.0
    assert trainer.average_precision([0.5], [0]) == 0.0


def test_split_is_disjoint_complete_and_seeded(trainer: ModuleType) -> None:
    train, held = trainer.split_indices(1000)
    assert len(held) == 200
    assert sorted(train + held) == list(range(1000))
    assert (train, held) == trainer.split_indices(1000)


def test_fit_learns_the_direction_of_each_feature(trainer: ModuleType) -> None:
    # Feature 0 predicts the label, feature 1 is noise-free but inverted.
    x = [[1.0, 0.0], [1.0, 0.0], [0.0, 1.0], [0.0, 1.0]] * 10
    y = [1, 1, 0, 0] * 10
    w, b, _ = trainer.fit(x, y, epochs=500)
    assert w[0] > 0 > w[1]
    scores = trainer.predict(w, b, x)
    assert all((s > 0.5) == bool(label) for s, label in zip(scores, y, strict=True))


def test_training_is_deterministic_and_round_trips_through_the_model_loader(
    trainer: ModuleType, tmp_path: Path
) -> None:
    small = tmp_path / "small.csv"
    small.write_text("".join(DATA.read_text().splitlines(keepends=True)[:402]))  # note+header+400
    first, _ = trainer.train(small, "2026-01-01T00:00:00+00:00")
    second, _ = trainer.train(small, "2026-01-01T00:00:00+00:00")
    assert first == second
    assert first["features"] == list(FEATURES)
    assert first["training_data_sha256"] == hashlib.sha256(small.read_bytes()).hexdigest()
    model_path, checksum_path = trainer.write_artifact(first, tmp_path / "models")
    assert (
        checksum_path.read_text().split()[0] == hashlib.sha256(model_path.read_bytes()).hexdigest()
    )
    assert ModelRuntime.from_path(model_path).health().status == "ok"


def test_trainer_output_changes_if_the_data_changes(trainer: ModuleType, tmp_path: Path) -> None:
    lines = DATA.read_text().splitlines(keepends=True)
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    a.write_text("".join(lines[:402]))
    b.write_text("".join(lines[:452]))
    art_a, _ = trainer.train(a, "t")
    art_b, _ = trainer.train(b, "t")
    assert art_a["training_data_sha256"] != art_b["training_data_sha256"]
    assert art_a["coefficients"] != art_b["coefficients"]


# --- the committed artifact ---------------------------------------------------------------


def test_committed_artifact_and_checksum_are_consistent() -> None:
    body = (MODEL_DIR / "risk_model_v1.json").read_bytes()
    recorded = (MODEL_DIR / "risk_model_v1.sha256").read_text().split()[0]
    assert recorded == hashlib.sha256(body).hexdigest()
    assert load_model(MODEL_DIR / "risk_model_v1.json").version == "risk_model_v1"


def test_committed_artifact_was_trained_on_the_committed_data() -> None:
    artifact = json.loads((MODEL_DIR / "risk_model_v1.json").read_text())
    assert artifact["training_data_sha256"] == hashlib.sha256(DATA.read_bytes()).hexdigest()
    assert artifact["metrics"]["held_out_size"] == 1000
    assert artifact["metrics"]["train_size"] == 4000


def test_committed_model_is_directionally_sensible() -> None:
    model = load_model(MODEL_DIR / "risk_model_v1.json")
    by_name = dict(zip(FEATURES, model.coefficients, strict=True))
    assert all(coef > 0 for coef in by_name.values())  # every risk feature raises risk
    assert model.intercept < 0  # most payments are genuine
