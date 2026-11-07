import hashlib
import json
import logging
import math
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from scamcheck import model as model_module
from scamcheck.model import (
    FEATURE_REASONS,
    FEATURES,
    ModelError,
    ModelRuntime,
    RiskModel,
    default_model_path,
    extract_features,
    load_model,
    sigmoid,
)
from scamcheck.signals import NameMatch, Signals

ROOT = Path(__file__).resolve().parents[1]


def signals(**overrides: Any) -> Signals:
    base: dict[str, Any] = {
        "new_payee": False,
        "amount_ratio": Decimal("1.0000"),
        "payee_account_age_days": 1000,
        "payee_name_match": NameMatch.MATCH,
        "payee_on_mule_list": False,
        "on_active_call": False,
        "remote_access_detected": False,
        "new_device": False,
        "data_complete": True,
    }
    base.update(overrides)
    return Signals(**base)


def artifact_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "model_version": "test_v1",
        "features": list(FEATURES),
        "coefficients": [1.0, 0.5, 2.0, 1.5, 3.0, 2.5, 0.25],
        "intercept": -4.0,
        "young_account_days": 30,
    }
    data.update(overrides)
    return data


def write_model(directory: Path, data: dict[str, Any] | bytes | None = None) -> Path:
    """Write an artifact and its matching checksum file; return the artifact path."""
    body = data if isinstance(data, bytes) else json.dumps(data or artifact_dict()).encode()
    path = directory / "risk_model_v1.json"
    path.write_bytes(body)
    (directory / "risk_model_v1.sha256").write_text(
        f"{hashlib.sha256(body).hexdigest()}  {path.name}\n"
    )
    return path


# --- the committed artifact -------------------------------------------------------------


def test_committed_model_loads_and_is_healthy() -> None:
    runtime = ModelRuntime.from_path()
    assert runtime.health().status == "ok"
    assert runtime.health().reason is None
    assert runtime.model is not None
    assert runtime.model.version == "risk_model_v1"
    assert len(runtime.model.coefficients) == len(FEATURES)


def test_committed_artifact_records_its_training_data_and_metrics() -> None:
    artifact = json.loads(default_model_path().read_text())
    data = (ROOT / "sample-data" / "training" / "training_data.csv").read_bytes()
    assert artifact["training_data_sha256"] == hashlib.sha256(data).hexdigest()
    assert artifact["features"] == list(FEATURES)
    assert artifact["trained_at"]
    assert {"precision", "recall"} <= artifact["metrics"]["at_0.50"].keys()
    assert 0 < artifact["metrics"]["pr_auc_approx"] <= 1
    assert "SYNTHETIC" in artifact["_note"]


# --- integrity, missing and mismatched artifacts ----------------------------------------


def test_valid_artifact_loads(tmp_path: Path) -> None:
    loaded = load_model(write_model(tmp_path))
    assert loaded.version == "test_v1"
    assert loaded.intercept == -4.0
    assert loaded.young_account_days == 30


def test_path_may_be_a_string(tmp_path: Path) -> None:
    assert load_model(str(write_model(tmp_path))).version == "test_v1"


def test_tampered_artifact_degrades_with_integrity_failure(tmp_path: Path) -> None:
    path = write_model(tmp_path)
    path.write_text(path.read_text().replace("-4.0", "-0.5"))  # edit after checksum was written
    with pytest.raises(ModelError) as info:
        load_model(path)
    assert info.value.code == "MODEL_INTEGRITY_FAILED"
    health = ModelRuntime.from_path(path).health()
    assert (health.status, health.reason) == ("degraded", "MODEL_INTEGRITY_FAILED")


def test_wrong_checksum_file_degrades(tmp_path: Path) -> None:
    path = write_model(tmp_path)
    (tmp_path / "risk_model_v1.sha256").write_text("0" * 64 + "\n")
    assert ModelRuntime.from_path(path).health().reason == "MODEL_INTEGRITY_FAILED"


def test_empty_checksum_file_degrades(tmp_path: Path) -> None:
    path = write_model(tmp_path)
    (tmp_path / "risk_model_v1.sha256").write_text("")
    assert ModelRuntime.from_path(path).health().reason == "MODEL_INTEGRITY_FAILED"


def test_checksum_may_be_bare_or_upper_case(tmp_path: Path) -> None:
    path = write_model(tmp_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "risk_model_v1.sha256").write_text(digest.upper())
    assert load_model(path).version == "test_v1"


def test_missing_model_file_degrades(tmp_path: Path) -> None:
    health = ModelRuntime.from_path(tmp_path / "risk_model_v1.json").health()
    assert (health.status, health.reason) == ("degraded", "MODEL_FILE_MISSING")


def test_missing_checksum_file_degrades(tmp_path: Path) -> None:
    path = write_model(tmp_path)
    (tmp_path / "risk_model_v1.sha256").unlink()
    assert ModelRuntime.from_path(path).health().reason == "MODEL_FILE_MISSING"


@pytest.mark.parametrize(
    "features",
    [
        list(reversed(FEATURES)),  # same names, different order
        [*FEATURES, "extra_feature"],
        list(FEATURES[:-1]),
        ["a", "b", "c", "d", "e", "f", "g"],
    ],
)
def test_feature_mismatch_degrades_even_with_valid_checksum(
    tmp_path: Path, features: list[str]
) -> None:
    path = write_model(tmp_path, artifact_dict(features=features))
    with pytest.raises(ModelError) as info:
        load_model(path)
    assert info.value.code == "MODEL_FEATURES_MISMATCH"
    assert ModelRuntime.from_path(path).health().reason == "MODEL_FEATURES_MISMATCH"


def test_missing_features_key_is_a_mismatch(tmp_path: Path) -> None:
    data = artifact_dict()
    del data["features"]
    assert ModelRuntime.from_path(write_model(tmp_path, data)).health().reason == (
        "MODEL_FEATURES_MISMATCH"
    )


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[1, 2, 3]",
        b"\xff\xfe\x00",
        json.dumps(artifact_dict(coefficients=[1.0, 2.0])).encode(),  # wrong count
        json.dumps(artifact_dict(coefficients=["1"] * 7)).encode(),  # strings
        json.dumps(artifact_dict(coefficients=[True] * 7)).encode(),  # booleans
        json.dumps(artifact_dict(intercept="low")).encode(),
        json.dumps(artifact_dict(young_account_days=-1)).encode(),
        json.dumps(artifact_dict(model_version="")).encode(),
        b'{"features": %s, "coefficients": [NaN, 1, 1, 1, 1, 1, 1], "intercept": 0, '
        b'"model_version": "x", "young_account_days": 30}' % json.dumps(list(FEATURES)).encode(),
    ],
)
def test_malformed_artifact_degrades(tmp_path: Path, body: bytes) -> None:
    runtime = ModelRuntime.from_path(write_model(tmp_path, body))
    assert runtime.model is None
    assert runtime.health().reason in {"MODEL_MALFORMED", "MODEL_FEATURES_MISMATCH"}


def test_unexpected_error_while_loading_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(model_module, "load_model", boom)
    assert ModelRuntime.from_path().health().reason == "MODEL_LOAD_ERROR"


def test_degrade_is_logged_once_at_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="scamcheck.model"):
        runtime = ModelRuntime.from_path(tmp_path / "missing.json")
        runtime.health()
        runtime.health()
    records = [r for r in caplog.records if r.name == "scamcheck.model"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert "MODEL_FILE_MISSING" in records[0].getMessage()


def test_healthy_load_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="scamcheck.model"):
        ModelRuntime.from_path()
    assert caplog.records == []


def test_default_path_can_be_overridden(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(model_module.MODEL_PATH_ENV, str(tmp_path / "x.json"))
    assert default_model_path() == tmp_path / "x.json"


# --- features -----------------------------------------------------------------------------


def feature(name: str, sig: Signals, young_days: int = 30) -> float:
    return extract_features(sig, young_days)[FEATURES.index(name)]


def test_feature_vector_has_one_value_per_feature() -> None:
    assert len(extract_features(signals(), 30)) == len(FEATURES)


def test_boolean_features() -> None:
    assert feature("new_payee", signals(new_payee=True)) == 1.0
    assert feature("new_payee", signals()) == 0.0
    assert feature("on_active_call", signals(on_active_call=True)) == 1.0
    assert feature("remote_access_detected", signals(remote_access_detected=True)) == 1.0
    assert feature("new_device", signals(new_device=True)) == 1.0


def test_log_amount_ratio() -> None:
    assert feature("log_amount_ratio", signals(amount_ratio=Decimal("1"))) == 0.0
    assert feature("log_amount_ratio", signals(amount_ratio=Decimal("5"))) == pytest.approx(
        math.log(5)
    )


def test_unknown_or_zero_ratio_is_safe() -> None:
    assert feature("log_amount_ratio", signals(amount_ratio=None)) == 0.0
    assert math.isfinite(feature("log_amount_ratio", signals(amount_ratio=Decimal("0"))))


def test_young_account_boundary_and_unknown_age() -> None:
    assert feature("young_account", signals(payee_account_age_days=29)) == 1.0
    assert feature("young_account", signals(payee_account_age_days=30)) == 0.0
    assert feature("young_account", signals(payee_account_age_days=None)) == 0.0
    assert feature("young_account", signals(payee_account_age_days=40), young_days=60) == 1.0


@pytest.mark.parametrize(
    ("match", "expected"),
    [
        (NameMatch.MISMATCH, 1.0),
        (NameMatch.MATCH, 0.0),
        (NameMatch.CLOSE, 0.0),
        (NameMatch.UNAVAILABLE, 0.0),
    ],
)
def test_name_mismatch_feature(match: NameMatch, expected: float) -> None:
    assert feature("name_mismatch", signals(payee_name_match=match)) == expected


# --- scoring ------------------------------------------------------------------------------


def make_model(**overrides: Any) -> RiskModel:
    data: dict[str, Any] = {
        "version": "t",
        "coefficients": (1.0, 0.5, 2.0, 1.5, 3.0, 2.5, 0.25),
        "intercept": -4.0,
        "young_account_days": 30,
    }
    data.update(overrides)
    return RiskModel(**data)


def test_sigmoid_is_stable_at_extremes() -> None:
    assert sigmoid(0) == 0.5
    assert sigmoid(1000) == 1.0
    assert sigmoid(-1000) == 0.0
    assert 0 < sigmoid(-30) < 1e-12


def test_probability_matches_manual_calculation() -> None:
    sig = signals(new_payee=True, on_active_call=True)
    z = -4.0 + 1.0 * 1 + 3.0 * 1  # log ratio is 0, other features 0
    assert make_model().score(sig).probability == pytest.approx(1 / (1 + math.exp(-z)))


def test_scoring_is_deterministic() -> None:
    model = make_model()
    sig = signals(new_payee=True, amount_ratio=Decimal("3.1416"), new_device=True)
    first = model.score(sig)
    assert all(model.score(sig) == first for _ in range(50))
    assert ModelRuntime.from_path().model.score(sig) == (  # type: ignore[union-attr]
        ModelRuntime.from_path().model.score(sig)  # type: ignore[union-attr]
    )


def test_top_two_contributions_become_reasons_in_order() -> None:
    sig = signals(on_active_call=True, remote_access_detected=True, new_payee=True)
    reasons = make_model().score(sig).reasons
    # contributions: on_active_call 3.0, remote_access 2.5, new_payee 1.0
    assert [r.code for r in reasons] == ["M_ON_ACTIVE_CALL", "M_REMOTE_ACCESS"]


def test_single_contribution_gives_one_reason() -> None:
    assert [r.code for r in make_model().score(signals(new_device=True)).reasons] == [
        "M_NEW_DEVICE"
    ]


def test_no_positive_contribution_gives_no_reasons() -> None:
    assert make_model().score(signals()).reasons == []


def test_risk_lowering_features_are_not_reasons() -> None:
    sig = signals(amount_ratio=Decimal("0.1"), new_device=True)  # log ratio < 0
    assert [r.code for r in make_model().score(sig).reasons] == ["M_NEW_DEVICE"]


def test_equal_contributions_break_ties_by_feature_order() -> None:
    model = make_model(coefficients=(1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0))
    sig = signals(new_payee=True, payee_account_age_days=1, on_active_call=True)
    assert [r.code for r in model.score(sig).reasons] == ["M_NEW_PAYEE", "M_YOUNG_PAYEE_ACCOUNT"]


def test_model_uses_its_own_young_account_days() -> None:
    sig = signals(payee_account_age_days=40)
    assert make_model(young_account_days=30).score(sig).probability < (
        make_model(young_account_days=60).score(sig).probability
    )


def test_every_feature_has_a_reason_code_without_values() -> None:
    assert set(FEATURE_REASONS) == set(FEATURES)
    for code, detail in FEATURE_REASONS.values():
        assert code.startswith("M_")
        assert detail and not any(ch.isdigit() for ch in detail)
