"""Engine behaviour with the risk model: score bands, mode, and degraded (rules-only) mode."""

import copy
import logging
import shutil
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from scamcheck import engine
from scamcheck.engine import _score_band
from scamcheck.model import (
    MODEL_PATH_ENV,
    ModelRuntime,
    RiskModel,
    default_model_path,
    default_runtime,
)
from scamcheck.policy import load_policy
from scamcheck.reference import load_reference
from scamcheck.schemas import Decision, DecisionResponse, Mode

REF = load_reference()
POLICY = load_policy()
CENT = Decimal("0.01")
REAL = ModelRuntime.from_path()
DEGRADED = ModelRuntime(model=None, reason="MODEL_FILE_MISSING")


def fixed_model(intercept: float) -> ModelRuntime:
    """A model whose probability is the same for every request: sigmoid(intercept)."""
    return ModelRuntime(model=RiskModel("fixed-test", (0.0,) * 7, intercept, 30))


def payee_named(name: str) -> dict[str, str]:
    for key, record in REF.payees.items():
        if record.name_on_account == name:
            bsb, account = key.split("-")
            return {"name": name, "bsb": bsb, "account_number": account}
    raise AssertionError(name)


def money(value: Decimal) -> str:
    return f"{value:.2f}"


def raw_request(
    customer: str, payee: dict[str, str], amount: str, **session: bool
) -> dict[str, Any]:
    return {
        "request_id": "req-m",
        "timestamp": "2026-03-01T10:00:00+11:00",
        "customer_id": customer,
        "amount": amount,
        "currency": "AUD",
        "payee": copy.deepcopy(payee),
        "channel": "web",
        "session": {"on_active_call": False, "remote_access_detected": False, "new_device": False}
        | session,
    }


def codes(response: DecisionResponse) -> list[str]:
    return [r.code for r in response.reasons]


KNOWN_001 = payee_named("Jordan Examplesmith")  # cust-001 (typical 150) already pays this payee
KNOWN_009 = payee_named("Skyler Synthetic")  # cust-009 (typical 2000) already pays this payee
NEW_OLD = payee_named("Casey Samplewood")  # established account, new to cust-009
YOUNG = payee_named("Invest Example Markets")  # 5 days old
MULE = payee_named("Robin Newaccount")
ABSTAIN = money(POLICY.abstain_amount)


@pytest.fixture(autouse=True)
def fresh_default_runtime() -> Iterator[None]:
    default_runtime.cache_clear()
    yield
    default_runtime.cache_clear()


# --- NORMAL mode --------------------------------------------------------------------------


def test_clean_payment_is_allowed_with_a_score() -> None:
    response = engine.assess(raw_request("cust-001", KNOWN_001, "150.00"), model=REAL)
    assert response.decision is Decision.ALLOW
    assert response.mode is Mode.NORMAL
    assert response.model_version == "risk_model_v1"
    assert response.risk_score is not None
    assert 0 < response.risk_score < POLICY.score_warn
    assert codes(response) == ["NO_RISK_SIGNALS"]  # no model reasons for an ALLOW band


def test_default_runtime_is_the_committed_model() -> None:
    response = engine.assess(raw_request("cust-001", KNOWN_001, "150.00"))
    assert response.mode is Mode.NORMAL
    assert response.model_version == "risk_model_v1"


def test_risky_payment_is_escalated_by_the_model_with_top_two_reasons() -> None:
    # New, young payee while on a call, at the customer's usual amount (rules alone say WARN).
    raw = raw_request("cust-009", YOUNG, "2000.00", on_active_call=True)
    response = engine.assess(raw, model=REAL)
    assert response.decision is Decision.HOLD
    assert response.risk_score is not None
    assert response.risk_score >= POLICY.score_hold
    assert "R06_YOUNG_PAYEE_ACCOUNT" in codes(response)
    model_reasons = [c for c in codes(response) if c.startswith("M_")]
    assert len(model_reasons) == 2
    assert response.mode is Mode.NORMAL


@pytest.mark.parametrize(
    ("probability_just_at", "expected"),
    [
        (POLICY.score_hold, Decision.HOLD),
        (POLICY.score_hold - 1e-9, Decision.WARN),
        (POLICY.score_warn, Decision.WARN),
        (POLICY.score_warn - 1e-9, Decision.ALLOW),
        (0.0, Decision.ALLOW),
        (1.0, Decision.HOLD),
    ],
)
def test_score_bands_follow_policy_thresholds(
    probability_just_at: float, expected: Decision
) -> None:
    assert _score_band(probability_just_at, POLICY) is expected


def test_score_band_thresholds_come_from_the_policy_object() -> None:
    strict = POLICY.model_copy(update={"score_warn": 0.01, "score_hold": 0.02})
    assert _score_band(0.5, strict) is Decision.HOLD
    assert _score_band(0.5, POLICY) is Decision.WARN


def test_model_alone_can_warn_or_hold_a_payment_the_rules_allow() -> None:
    clean = raw_request("cust-001", KNOWN_001, "150.00")
    warn = engine.assess(clean, model=fixed_model(0.0))  # probability 0.5
    assert warn.decision is Decision.WARN
    assert warn.risk_score == 0.5
    assert codes(warn) == ["M_SCORE_ELEVATED"]
    hold = engine.assess(clean, model=fixed_model(3.0))  # probability ~0.95
    assert hold.decision is Decision.HOLD
    assert hold.risk_score == pytest.approx(0.9526, abs=1e-4)


def test_final_decision_is_the_most_severe_of_rules_and_model() -> None:
    mule = raw_request("cust-001", MULE, "50.00")  # rule floor: HOLD
    assert engine.assess(mule, model=fixed_model(-20.0)).decision is Decision.HOLD
    young = raw_request("cust-009", YOUNG, "100.00")  # rule floor: WARN
    assert engine.assess(young, model=fixed_model(-20.0)).decision is Decision.WARN
    assert engine.assess(young, model=fixed_model(3.0)).decision is Decision.HOLD


def test_model_cannot_lower_a_rule_hold() -> None:
    response = engine.assess(raw_request("cust-001", MULE, "50.00"), model=fixed_model(-20.0))
    assert response.decision is Decision.HOLD
    assert "R01_MULE_PAYEE" in codes(response)


def test_scoring_is_deterministic_through_the_engine() -> None:
    raw = raw_request("cust-009", NEW_OLD, "1500.00", new_device=True)
    a, b = engine.assess(raw, model=REAL), engine.assess(raw, model=REAL)
    assert (a.decision, a.risk_score, a.reasons) == (b.decision, b.risk_score, b.reasons)


def test_rejected_request_has_no_score() -> None:
    response = engine.assess({"nope": 1}, model=REAL)
    assert response.decision is Decision.REJECT
    assert response.risk_score is None
    assert response.model_version is None


def test_every_decision_has_a_reason_in_both_modes() -> None:
    for runtime in (REAL, DEGRADED, fixed_model(0.0), fixed_model(-20.0)):
        for raw in (
            raw_request("cust-001", KNOWN_001, "150.00"),
            raw_request("cust-009", YOUNG, "2000.00", on_active_call=True),
            raw_request("ghost", KNOWN_001, ABSTAIN),
        ):
            assert len(engine.assess(raw, model=runtime).reasons) >= 1


def test_unexpected_scoring_error_fails_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("secret detail")

    monkeypatch.setattr(RiskModel, "score", boom)
    response = engine.assess(raw_request("cust-001", KNOWN_001, "150.00"), model=REAL)
    assert response.decision is Decision.HOLD
    assert codes(response) == ["INTERNAL_ERROR"]


# --- DEGRADED_RULES_ONLY mode -------------------------------------------------------------


def test_degraded_mode_is_reported_with_no_score() -> None:
    response = engine.assess(raw_request("cust-001", KNOWN_001, "150.00"), model=DEGRADED)
    assert response.mode is Mode.DEGRADED_RULES_ONLY
    assert response.risk_score is None
    assert response.model_version is None
    assert response.policy_version == POLICY.policy_version


# One risk signal at a time on an otherwise clean payment of exactly abstain_amount.
RISKY_HIGH_VALUE: list[tuple[str, str, dict[str, str], dict[str, bool]]] = [
    ("new payee", "cust-009", NEW_OLD, {}),
    ("young new payee", "cust-009", YOUNG, {}),
    ("mule payee", "cust-009", MULE, {}),
    ("remote access", "cust-009", KNOWN_009, {"remote_access_detected": True}),
    ("active call", "cust-009", KNOWN_009, {"on_active_call": True}),
    ("new device", "cust-009", KNOWN_009, {"new_device": True}),
    ("name mismatch", "cust-009", KNOWN_009 | {"name": "Somebody Else Entirely"}, {}),
    ("unusual amount", "cust-001", KNOWN_001, {}),  # abstain_amount is >5x cust-001's typical
]


@pytest.mark.parametrize(
    ("label", "customer", "payee", "session"),
    RISKY_HIGH_VALUE,
    ids=[case[0] for case in RISKY_HIGH_VALUE],
)
@pytest.mark.parametrize("multiple", [1, 2, 10])
def test_degraded_mode_never_allows_a_risky_high_value_payment(
    label: str, customer: str, payee: dict[str, str], session: dict[str, bool], multiple: int
) -> None:
    amount = min(POLICY.abstain_amount * multiple, POLICY.max_amount)
    response = engine.assess(raw_request(customer, payee, money(amount), **session), model=DEGRADED)
    assert response.decision is not Decision.ALLOW, label
    assert response.decision is Decision.HOLD, label
    assert "DEGRADED_FAILSAFE_HOLD" in codes(response)
    assert response.mode is Mode.DEGRADED_RULES_ONLY


def test_degraded_failsafe_starts_exactly_at_abstain_amount() -> None:
    below = raw_request("cust-009", NEW_OLD, money(POLICY.abstain_amount - CENT))
    at = raw_request("cust-009", NEW_OLD, ABSTAIN)
    assert "DEGRADED_FAILSAFE_HOLD" not in codes(engine.assess(below, model=DEGRADED))
    assert engine.assess(below, model=DEGRADED).decision is Decision.ALLOW  # rules found nothing
    assert engine.assess(at, model=DEGRADED).decision is Decision.HOLD


def test_degraded_mode_does_not_hold_a_payment_with_no_risk_signal() -> None:
    response = engine.assess(raw_request("cust-009", KNOWN_009, ABSTAIN), model=DEGRADED)
    assert response.decision is Decision.ALLOW
    assert codes(response) == ["NO_RISK_SIGNALS"]


def test_degraded_mode_still_applies_the_rules() -> None:
    response = engine.assess(raw_request("cust-001", MULE, "50.00"), model=DEGRADED)
    assert response.decision is Decision.HOLD
    assert "R01_MULE_PAYEE" in codes(response)
    young = engine.assess(raw_request("cust-009", YOUNG, "100.00"), model=DEGRADED)
    assert young.decision is Decision.WARN


def test_degraded_failsafe_uses_the_policy_abstain_amount() -> None:
    raw = raw_request("cust-009", NEW_OLD, "100.00")
    assert engine.assess(raw, model=DEGRADED).decision is Decision.ALLOW
    strict = POLICY.model_copy(update={"abstain_amount": Decimal("100")})
    assert engine.assess(raw, policy=strict, model=DEGRADED).decision is Decision.HOLD


# --- degrade through the real load path ---------------------------------------------------


def copy_model(tmp_path: Path) -> Path:
    source = default_model_path()
    shutil.copy(source, tmp_path / source.name)
    shutil.copy(source.with_suffix(".sha256"), tmp_path / source.with_suffix(".sha256").name)
    return tmp_path / source.name


def test_tampered_model_file_puts_the_service_in_degraded_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = copy_model(tmp_path)
    path.write_text(path.read_text().replace('"intercept": -', '"intercept": '))
    monkeypatch.setenv(MODEL_PATH_ENV, str(path))
    response = engine.assess(raw_request("cust-009", NEW_OLD, ABSTAIN))
    assert response.mode is Mode.DEGRADED_RULES_ONLY
    assert response.decision is Decision.HOLD


def test_missing_model_file_puts_the_service_in_degraded_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "gone.json"))
    response = engine.assess(raw_request("cust-009", NEW_OLD, ABSTAIN))
    assert response.mode is Mode.DEGRADED_RULES_ONLY
    assert response.risk_score is None


def test_degrade_is_logged_once_across_many_requests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "gone.json"))
    with caplog.at_level(logging.DEBUG, logger="scamcheck"):
        for _ in range(5):
            engine.assess(raw_request("cust-001", KNOWN_001, "150.00"))
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].name == "scamcheck.model"
    assert "DEGRADED_RULES_ONLY" in warnings[0].getMessage()


def test_degrade_log_contains_no_request_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "gone.json"))
    raw = raw_request("cust-001", KNOWN_001, "123.45")
    with caplog.at_level(logging.DEBUG, logger="scamcheck"):
        engine.assess(raw)
    text = " ".join(r.getMessage() for r in caplog.records)
    for secret in ("123.45", KNOWN_001["account_number"], KNOWN_001["name"], "cust-001"):
        assert secret not in text


def test_healthy_default_runtime_is_loaded_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    original = ModelRuntime.from_path

    def counting(path: object = None) -> ModelRuntime:
        calls.append(path)
        return original(path)

    monkeypatch.setattr(ModelRuntime, "from_path", staticmethod(counting))
    for _ in range(3):
        engine.assess(raw_request("cust-001", KNOWN_001, "150.00"))
    assert len(calls) == 1
