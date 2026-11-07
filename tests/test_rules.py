from decimal import Decimal
from typing import Any

import pytest

from scamcheck.policy import EvaluationGates, Policy
from scamcheck.rules import (
    SEVERITY,
    any_risk_signal,
    evaluate_rules,
    most_severe,
    r01_mule_payee,
    r02_remote_access_new_payee,
    r03_on_call_new_payee_high_value,
    r04_payee_name_mismatch,
    r05_unusual_amount,
    r06_young_payee_account,
    r07_young_payee_high_value,
)
from scamcheck.schemas import Decision
from scamcheck.signals import NameMatch, Signals

POLICY = Policy(
    policy_version="test",
    high_value_amount=Decimal("5000"),
    abstain_amount=Decimal("1000"),
    unusual_ratio=Decimal("5"),
    young_account_days=30,
    score_warn=0.35,
    score_hold=0.70,
    max_amount=Decimal("1000000"),
    evaluation=EvaluationGates(min_scam_warn_or_hold_rate=0.9, max_genuine_hold_rate=0.1),
)
SMALL = Decimal("100")
HIGH = POLICY.high_value_amount
CENT = Decimal("0.01")


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


def test_clean_signals_trigger_nothing() -> None:
    assert evaluate_rules(signals(), SMALL, POLICY) == []


def test_r01_mule_payee_holds() -> None:
    hit = r01_mule_payee(signals(payee_on_mule_list=True), SMALL, POLICY)
    assert hit is not None
    assert hit.floor is Decision.HOLD
    assert hit.reason.code == "R01_MULE_PAYEE"
    assert r01_mule_payee(signals(), SMALL, POLICY) is None


def test_r02_remote_access_new_payee_holds() -> None:
    hit = r02_remote_access_new_payee(
        signals(remote_access_detected=True, new_payee=True), SMALL, POLICY
    )
    assert hit is not None
    assert hit.floor is Decision.HOLD
    assert hit.reason.code == "R02_REMOTE_ACCESS_NEW_PAYEE"


@pytest.mark.parametrize(
    "overrides",
    [{"remote_access_detected": True}, {"new_payee": True}, {}],
)
def test_r02_needs_both_conditions(overrides: dict[str, Any]) -> None:
    assert r02_remote_access_new_payee(signals(**overrides), SMALL, POLICY) is None


def test_r03_on_call_new_payee_high_value_holds_at_threshold() -> None:
    sig = signals(on_active_call=True, new_payee=True)
    hit = r03_on_call_new_payee_high_value(sig, HIGH, POLICY)
    assert hit is not None
    assert hit.floor is Decision.HOLD
    assert hit.reason.code == "R03_ON_CALL_NEW_PAYEE_HIGH_VALUE"
    assert r03_on_call_new_payee_high_value(sig, HIGH - CENT, POLICY) is None


@pytest.mark.parametrize(
    "overrides",
    [{"on_active_call": True}, {"new_payee": True}, {}],
)
def test_r03_needs_all_conditions(overrides: dict[str, Any]) -> None:
    assert r03_on_call_new_payee_high_value(signals(**overrides), HIGH, POLICY) is None


def test_r04_name_mismatch_warns_below_high_value() -> None:
    sig = signals(payee_name_match=NameMatch.MISMATCH)
    hit = r04_payee_name_mismatch(sig, HIGH - CENT, POLICY)
    assert hit is not None
    assert hit.floor is Decision.WARN
    assert hit.reason.code == "R04_PAYEE_NAME_MISMATCH"


def test_r04_name_mismatch_holds_at_high_value() -> None:
    hit = r04_payee_name_mismatch(signals(payee_name_match=NameMatch.MISMATCH), HIGH, POLICY)
    assert hit is not None
    assert hit.floor is Decision.HOLD


@pytest.mark.parametrize("match", [NameMatch.MATCH, NameMatch.CLOSE, NameMatch.UNAVAILABLE])
def test_r04_only_fires_on_mismatch(match: NameMatch) -> None:
    assert r04_payee_name_mismatch(signals(payee_name_match=match), HIGH, POLICY) is None


def test_r05_unusual_amount_warns_at_threshold() -> None:
    hit = r05_unusual_amount(signals(amount_ratio=Decimal("5.0000")), SMALL, POLICY)
    assert hit is not None
    assert hit.floor is Decision.WARN
    assert hit.reason.code == "R05_UNUSUAL_AMOUNT"
    assert r05_unusual_amount(signals(amount_ratio=Decimal("4.9999")), SMALL, POLICY) is None


def test_r05_ignores_unknown_ratio() -> None:
    assert r05_unusual_amount(signals(amount_ratio=None), SMALL, POLICY) is None


def test_r06_young_payee_account_warns_under_threshold() -> None:
    hit = r06_young_payee_account(signals(new_payee=True, payee_account_age_days=29), SMALL, POLICY)
    assert hit is not None
    assert hit.floor is Decision.WARN
    assert hit.reason.code == "R06_YOUNG_PAYEE_ACCOUNT"


@pytest.mark.parametrize(
    "overrides",
    [
        {"new_payee": True, "payee_account_age_days": 30},  # exactly at threshold
        {"new_payee": True, "payee_account_age_days": None},  # unknown age
        {"new_payee": False, "payee_account_age_days": 1},  # known payee
    ],
)
def test_r06_does_not_fire(overrides: dict[str, Any]) -> None:
    assert r06_young_payee_account(signals(**overrides), SMALL, POLICY) is None


def test_evaluate_rules_returns_hits_in_rule_order() -> None:
    sig = signals(
        payee_on_mule_list=True,
        new_payee=True,
        payee_account_age_days=1,
        amount_ratio=Decimal("9"),
    )
    codes = [h.reason.code for h in evaluate_rules(sig, SMALL, POLICY)]
    assert codes == ["R01_MULE_PAYEE", "R05_UNUSUAL_AMOUNT", "R06_YOUNG_PAYEE_ACCOUNT"]


def test_severity_ordering() -> None:
    assert SEVERITY[Decision.ALLOW] < SEVERITY[Decision.WARN] < SEVERITY[Decision.HOLD]
    assert most_severe([Decision.WARN, Decision.HOLD, Decision.ALLOW]) is Decision.HOLD
    assert most_severe([Decision.ALLOW, Decision.WARN]) is Decision.WARN
    assert most_severe([Decision.WARN, Decision.WARN]) is Decision.WARN
    assert most_severe([]) is Decision.ALLOW


def test_reason_text_has_no_amounts_or_identifiers() -> None:
    sig = signals(
        payee_on_mule_list=True,
        new_payee=True,
        remote_access_detected=True,
        on_active_call=True,
        payee_name_match=NameMatch.MISMATCH,
        payee_account_age_days=1,
        amount_ratio=Decimal("9"),
    )
    for hit in evaluate_rules(sig, Decimal("7777.77"), POLICY):
        assert "7777" not in hit.reason.detail


@pytest.mark.parametrize(
    "overrides",
    [
        {"payee_on_mule_list": True},
        {"new_payee": True},
        {"new_device": True},
        {"on_active_call": True},
        {"remote_access_detected": True},
        {"payee_name_match": NameMatch.MISMATCH},
        {"payee_account_age_days": 29},
        {"amount_ratio": Decimal("5")},
    ],
)
def test_any_risk_signal_detects_each_signal(overrides: dict[str, Any]) -> None:
    assert any_risk_signal(signals(**overrides), POLICY) is True


def test_any_risk_signal_is_false_for_clean_signals_and_boundaries() -> None:
    assert any_risk_signal(signals(), POLICY) is False
    assert any_risk_signal(signals(payee_account_age_days=30), POLICY) is False
    assert any_risk_signal(signals(amount_ratio=Decimal("4.9999")), POLICY) is False
    assert any_risk_signal(signals(payee_name_match=NameMatch.CLOSE), POLICY) is False
    assert any_risk_signal(signals(payee_account_age_days=None, amount_ratio=None), POLICY) is False


def test_r07_young_new_payee_high_value_holds_at_both_boundaries() -> None:
    sig = signals(new_payee=True, payee_account_age_days=29)
    hit = r07_young_payee_high_value(sig, HIGH, POLICY)  # exactly the high-value amount
    assert hit is not None
    assert hit.floor is Decision.HOLD
    assert hit.reason.code == "R07_YOUNG_PAYEE_HIGH_VALUE"
    assert r07_young_payee_high_value(sig, HIGH - CENT, POLICY) is None  # just below
    older = signals(new_payee=True, payee_account_age_days=30)
    assert r07_young_payee_high_value(older, HIGH, POLICY) is None  # exactly young_account_days


@pytest.mark.parametrize(
    "overrides",
    [
        {"new_payee": False, "payee_account_age_days": 1},  # payee the customer already pays
        {"new_payee": True, "payee_account_age_days": None},  # unknown account age
        {"new_payee": True, "payee_account_age_days": 400},  # established account
    ],
)
def test_r07_needs_new_payee_and_a_known_young_account(overrides: dict[str, Any]) -> None:
    assert r07_young_payee_high_value(signals(**overrides), HIGH * 10, POLICY) is None


def test_r07_does_not_depend_on_the_customers_usual_amount() -> None:
    sig = signals(new_payee=True, payee_account_age_days=5, amount_ratio=Decimal("0.5"))
    assert r07_young_payee_high_value(sig, HIGH, POLICY) is not None
    assert r05_unusual_amount(sig, HIGH, POLICY) is None  # the ratio-based rule stays quiet


def test_r07_reads_both_thresholds_from_the_policy() -> None:
    sig = signals(new_payee=True, payee_account_age_days=40)
    assert r07_young_payee_high_value(sig, HIGH, POLICY) is None
    looser = POLICY.model_copy(update={"young_account_days": 60})
    assert r07_young_payee_high_value(sig, HIGH, looser) is not None
    cheaper = POLICY.model_copy(update={"high_value_amount": Decimal("100")})
    assert r07_young_payee_high_value(
        signals(new_payee=True, payee_account_age_days=5), SMALL, cheaper
    )
