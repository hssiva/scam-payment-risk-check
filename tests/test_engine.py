import copy
from decimal import Decimal
from typing import Any

import pytest

from scamcheck import engine
from scamcheck.engine import assess
from scamcheck.policy import POLICY_PATH_ENV, load_policy
from scamcheck.reference import REFERENCE_DIR_ENV, load_reference
from scamcheck.schemas import ID_MAX_LENGTH, Decision, DecisionResponse, Mode

# Synthetic sample data (see sample-data/reference/): cust-001 typical payment is 150.00 and
# knows "Jordan Examplesmith"; cust-009 typical is 2000.00 and knows "Skyler Synthetic".
REF = load_reference()
# Thresholds come from the real policy file, so these tests follow policy changes.
POLICY = load_policy()
CENT = Decimal("0.01")
# Scenarios assume the sample customers' typical payments (150.00 and 2000.00) leave the
# amounts below as not unusual; they only need the policy thresholds to be of the same order.
TYPICAL_001 = REF.customer("cust-001").typical_payment_amount  # type: ignore[union-attr]


def money(value: Decimal) -> str:
    return f"{value:.2f}"


def payee_named(name: str) -> dict[str, str]:
    for key, record in REF.payees.items():
        if record.name_on_account == name:
            bsb, account = key.split("-")
            return {"name": name, "bsb": bsb, "account_number": account}
    raise AssertionError(f"no sample payee named {name}")


def raw_request(
    customer: str,
    payee: dict[str, str],
    amount: str,
    **session: bool,
) -> dict[str, Any]:
    return {
        "request_id": "req-1",
        "timestamp": "2026-03-01T10:00:00+11:00",
        "customer_id": customer,
        "amount": amount,
        "currency": "AUD",
        "payee": copy.deepcopy(payee),
        "channel": "mobile",
        "session": {
            "on_active_call": False,
            "remote_access_detected": False,
            "new_device": False,
        }
        | session,
    }


def codes(response: DecisionResponse) -> list[str]:
    return [r.code for r in response.reasons]


KNOWN_001 = payee_named("Jordan Examplesmith")
KNOWN_009 = payee_named("Skyler Synthetic")
NEW_OLD = payee_named("Casey Samplewood")  # established account (900 days), not known to 009
YOUNG = payee_named("Invest Example Markets")  # 5 days old
MULE = payee_named("Robin Newaccount")  # on the mule list, 3 days old


def test_clean_allow() -> None:
    response = assess(raw_request("cust-001", KNOWN_001, "150.00"))
    assert response.decision is Decision.ALLOW
    assert codes(response) == ["NO_RISK_SIGNALS"]
    assert response.mode is Mode.NORMAL
    assert response.policy_version == "2026.11.1"
    assert response.model_version is None
    assert response.risk_score is None
    assert response.request_id == "req-1"
    assert response.latency_ms >= 0


def test_r01_mule_payee_holds() -> None:
    response = assess(raw_request("cust-001", MULE, "50.00"))
    assert response.decision is Decision.HOLD
    assert "R01_MULE_PAYEE" in codes(response)


def test_r02_remote_access_new_payee_holds() -> None:
    response = assess(raw_request("cust-009", NEW_OLD, "100.00", remote_access_detected=True))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["R02_REMOTE_ACCESS_NEW_PAYEE"]


def test_r02_does_not_fire_for_known_payee() -> None:
    response = assess(raw_request("cust-009", KNOWN_009, "100.00", remote_access_detected=True))
    assert response.decision is Decision.ALLOW


def test_r03_on_call_new_payee_high_value_holds() -> None:
    response = assess(
        raw_request("cust-009", NEW_OLD, money(POLICY.high_value_amount), on_active_call=True)
    )
    assert response.decision is Decision.HOLD
    assert codes(response) == ["R03_ON_CALL_NEW_PAYEE_HIGH_VALUE"]


def test_r03_just_below_high_value_does_not_fire() -> None:
    response = assess(
        raw_request(
            "cust-009", NEW_OLD, money(POLICY.high_value_amount - CENT), on_active_call=True
        )
    )
    assert "R03_ON_CALL_NEW_PAYEE_HIGH_VALUE" not in codes(response)
    assert response.decision is Decision.ALLOW


def test_r04_name_mismatch_warns() -> None:
    payee = KNOWN_009 | {"name": "Totally Different Person"}
    response = assess(raw_request("cust-009", payee, "100.00"))
    assert response.decision is Decision.WARN
    assert codes(response) == ["R04_PAYEE_NAME_MISMATCH"]


def test_r04_name_mismatch_holds_at_high_value() -> None:
    payee = KNOWN_009 | {"name": "Totally Different Person"}
    response = assess(raw_request("cust-009", payee, money(POLICY.high_value_amount)))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["R04_PAYEE_NAME_MISMATCH"]


def test_r05_unusual_amount_warns_at_five_times() -> None:
    at_threshold = TYPICAL_001 * POLICY.unusual_ratio
    response = assess(raw_request("cust-001", KNOWN_001, money(at_threshold)))
    assert response.decision is Decision.WARN
    assert codes(response) == ["R05_UNUSUAL_AMOUNT"]
    below = assess(raw_request("cust-001", KNOWN_001, money(at_threshold - CENT)))
    assert below.decision is Decision.ALLOW


def test_r06_young_payee_account_warns() -> None:
    response = assess(raw_request("cust-009", YOUNG, "100.00"))
    assert response.decision is Decision.WARN
    assert codes(response) == ["R06_YOUNG_PAYEE_ACCOUNT"]


def test_r06_does_not_fire_for_known_payee_even_if_young() -> None:
    # A payee the customer already knows is not "new", whatever its age.
    assert "R06_YOUNG_PAYEE_ACCOUNT" not in codes(
        assess(raw_request("cust-009", KNOWN_009, "100.00"))
    )


def test_most_severe_floor_wins_and_all_reasons_are_listed() -> None:
    response = assess(raw_request("cust-001", MULE, "50.00"))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["R01_MULE_PAYEE", "R06_YOUNG_PAYEE_ACCOUNT"]


def test_two_warns_stay_warn() -> None:
    payee = YOUNG | {"name": "Someone Else Entirely"}
    response = assess(raw_request("cust-009", payee, "100.00"))
    assert response.decision is Decision.WARN
    assert codes(response) == ["R04_PAYEE_NAME_MISMATCH", "R06_YOUNG_PAYEE_ACCOUNT"]


def test_abstain_unknown_customer_at_threshold() -> None:
    response = assess(raw_request("ghost", KNOWN_001, money(POLICY.abstain_amount)))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["ABSTAIN_INSUFFICIENT_DATA"]


def test_abstain_unknown_payee_at_threshold() -> None:
    unknown = {"name": "Nobody Known", "bsb": "000150", "account_number": "11112222"}
    response = assess(raw_request("cust-001", unknown, money(POLICY.abstain_amount)))
    assert response.decision is Decision.HOLD
    assert "ABSTAIN_INSUFFICIENT_DATA" in codes(response)


def test_missing_data_below_abstain_amount_does_not_abstain() -> None:
    response = assess(raw_request("ghost", KNOWN_001, money(POLICY.abstain_amount - CENT)))
    assert "ABSTAIN_INSUFFICIENT_DATA" not in codes(response)
    assert response.decision is Decision.ALLOW


def test_complete_data_never_abstains() -> None:
    response = assess(raw_request("cust-009", KNOWN_009, "1500.00"))
    assert "ABSTAIN_INSUFFICIENT_DATA" not in codes(response)


def test_abstain_and_rule_reasons_are_combined() -> None:
    mule_only = {"name": "Unlisted Mule", "bsb": "000199", "account_number": "99887766"}
    # cust-009's typical payment is 2000, so the amount itself is not unusual (no R05).
    response = assess(raw_request("cust-009", mule_only, money(POLICY.abstain_amount)))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["ABSTAIN_INSUFFICIENT_DATA", "R01_MULE_PAYEE"]


def test_invalid_input_is_rejected_with_codes() -> None:
    raw = raw_request("cust-001", KNOWN_001, "-5")
    raw["payee"]["bsb"] = "12"
    response = assess(raw)
    assert response.decision is Decision.REJECT
    assert set(codes(response)) == {"AMOUNT_NOT_POSITIVE", "INVALID_BSB"}
    assert response.request_id == "req-1"
    assert response.risk_score is None
    assert response.model_version is None


def test_amount_above_policy_max_is_rejected() -> None:
    response = assess(raw_request("cust-001", KNOWN_001, money(POLICY.max_amount + CENT)))
    assert response.decision is Decision.REJECT
    assert codes(response) == ["AMOUNT_TOO_LARGE"]


@pytest.mark.parametrize("raw", [None, [], "text", {}, {"request_id": 5}, {"request_id": ""}])
def test_unparseable_input_is_rejected_without_request_id(raw: Any) -> None:
    response = assess(raw)
    assert response.decision is Decision.REJECT
    assert response.request_id is None
    assert len(response.reasons) >= 1


def test_reject_reasons_do_not_leak_values() -> None:
    raw = raw_request("cust-001", KNOWN_001, "123.456")
    raw["payee"]["account_number"] = "55555"
    text = " ".join(r.detail for r in assess(raw).reasons)
    assert "123.456" not in text
    assert "55555" not in text


def test_every_non_reject_decision_has_a_reason_and_versions() -> None:
    scenarios = [
        raw_request("cust-001", KNOWN_001, "150.00"),
        raw_request("cust-001", MULE, "50.00"),
        raw_request("cust-009", YOUNG, "100.00"),
        raw_request("ghost", KNOWN_001, money(POLICY.high_value_amount)),
        raw_request("ghost", KNOWN_001, "10.00"),
    ]
    for raw in scenarios:
        response = assess(raw)
        assert response.decision is not Decision.REJECT
        assert len(response.reasons) >= 1
        assert response.policy_version
        assert response.mode is Mode.NORMAL


def test_decisions_are_deterministic_and_ids_unique() -> None:
    raw = raw_request("cust-001", MULE, "50.00")
    a, b = assess(raw), assess(raw)
    assert (a.decision, a.reasons) == (b.decision, b.reasons)
    assert a.decision_id != b.decision_id


def test_assess_does_not_mutate_input() -> None:
    raw = raw_request("cust-001", KNOWN_001, "150.00")
    before = copy.deepcopy(raw)
    assess(raw)
    assert raw == before


def test_fail_safe_when_policy_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setenv(POLICY_PATH_ENV, str(tmp_path / "missing.toml"))
    response = assess(raw_request("cust-001", KNOWN_001, "150.00"))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["POLICY_UNAVAILABLE"]
    assert response.policy_version == "UNKNOWN"


def test_fail_safe_when_reference_data_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setenv(REFERENCE_DIR_ENV, str(tmp_path))
    response = assess(raw_request("cust-001", KNOWN_001, "150.00"))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["REFERENCE_DATA_UNAVAILABLE"]
    assert response.policy_version == "2026.11.1"


def test_invalid_input_is_still_rejected_when_reference_data_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setenv(REFERENCE_DIR_ENV, str(tmp_path))
    assert assess({"bad": 1}).decision is Decision.REJECT


def test_fail_safe_on_unexpected_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("secret detail 12345678")

    monkeypatch.setattr(engine, "build_signals", boom)
    response = assess(raw_request("cust-001", KNOWN_001, "150.00"))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["INTERNAL_ERROR"]
    assert "12345678" not in response.reasons[0].detail


def test_engine_uses_the_policy_it_is_given() -> None:
    raw = raw_request("cust-009", NEW_OLD, "100.00", on_active_call=True)
    assert assess(raw).decision is Decision.ALLOW  # 100 is below the real high-value amount
    strict = POLICY.model_copy(update={"high_value_amount": Decimal("100")})
    response = assess(raw, policy=strict)
    assert response.decision is Decision.HOLD
    assert codes(response) == ["R03_ON_CALL_NEW_PAYEE_HIGH_VALUE"]


def test_abstain_amount_comes_from_policy() -> None:
    raw = raw_request("ghost", KNOWN_001, "100.00")
    assert assess(raw).decision is Decision.ALLOW
    strict = POLICY.model_copy(update={"abstain_amount": Decimal("100")})
    assert codes(assess(raw, policy=strict)) == ["ABSTAIN_INSUFFICIENT_DATA"]


def test_max_amount_comes_from_policy() -> None:
    raw = raw_request("cust-001", KNOWN_001, "150.00")
    tight = POLICY.model_copy(update={"max_amount": Decimal("149.99")})
    response = assess(raw, policy=tight)
    assert response.decision is Decision.REJECT
    assert codes(response) == ["AMOUNT_TOO_LARGE"]


def test_policy_version_comes_from_policy() -> None:
    other = POLICY.model_copy(update={"policy_version": "test-version"})
    assert assess(raw_request("cust-001", KNOWN_001, "150.00"), policy=other).policy_version == (
        "test-version"
    )


def test_request_id_echo_follows_schema_length_limit() -> None:
    at_limit = {"request_id": "r" * ID_MAX_LENGTH}
    over_limit = {"request_id": "r" * (ID_MAX_LENGTH + 1)}
    assert assess(at_limit).request_id == "r" * ID_MAX_LENGTH
    assert assess(over_limit).request_id is None
