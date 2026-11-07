import copy
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from scamcheck.schemas import (
    Decision,
    DecisionResponse,
    Mode,
    PaymentRequest,
    Reason,
    ValidationIssue,
    validate_request,
)


def valid_raw() -> dict[str, Any]:
    # SYNTHETIC example
    return {
        "request_id": "req-0001",
        "timestamp": "2026-03-01T10:15:00+11:00",
        "customer_id": "cust-001",
        "amount": "250.50",
        "currency": "AUD",
        "payee": {"name": "Example Payee Pty Ltd", "bsb": "123456", "account_number": "12345678"},
        "channel": "mobile",
        "session": {"on_active_call": False, "remote_access_detected": False, "new_device": True},
    }


def mutated(path: str, value: Any) -> dict[str, Any]:
    raw = copy.deepcopy(valid_raw())
    target = raw
    *parents, leaf = path.split(".")
    for p in parents:
        target = target[p]
    if value is _DELETE:
        del target[leaf]
    else:
        target[leaf] = value
    return raw


_DELETE = object()


def codes(result: object) -> set[str]:
    assert isinstance(result, list)
    return {i.code for i in result}


def test_valid_request_parses() -> None:
    result = validate_request(valid_raw())
    assert isinstance(result, PaymentRequest)
    assert result.amount == Decimal("250.50")
    assert result.timestamp.tzinfo is not None
    assert result.payee.bsb == "123456"


@pytest.mark.parametrize("amount", ["0.01", "1000000", 1000000, 12.5])
def test_valid_amount_boundaries(amount: Any) -> None:
    assert isinstance(validate_request(mutated("amount", amount)), PaymentRequest)


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        ("payee.bsb", "12345", "INVALID_BSB"),
        ("payee.bsb", "12345a", "INVALID_BSB"),
        ("payee.bsb", "١٢٣٤٥٦", "INVALID_BSB"),  # non-ASCII digits
        ("payee.account_number", "12345", "INVALID_ACCOUNT_NUMBER"),
        ("payee.account_number", "1234567890", "INVALID_ACCOUNT_NUMBER"),
        ("payee.name", "", "INVALID_PAYEE_NAME"),
        ("payee.name", "x" * 141, "INVALID_PAYEE_NAME"),
        ("amount", 0, "AMOUNT_NOT_POSITIVE"),
        ("amount", "-5.00", "AMOUNT_NOT_POSITIVE"),
        ("amount", "1000000.01", "AMOUNT_TOO_LARGE"),
        ("amount", "10.001", "AMOUNT_TOO_PRECISE"),
        ("amount", "abc", "AMOUNT_INVALID"),
        ("amount", "NaN", "AMOUNT_INVALID"),
        ("amount", "Infinity", "AMOUNT_INVALID"),
        ("timestamp", "2026-03-01T10:15:00", "NAIVE_TIMESTAMP"),
        ("timestamp", "not-a-date", "INVALID_TIMESTAMP"),
        ("currency", "USD", "UNSUPPORTED_CURRENCY"),
        ("channel", "atm", "INVALID_CHANNEL"),
        ("request_id", "", "INVALID_REQUEST_ID"),
        ("request_id", "r" * 65, "INVALID_REQUEST_ID"),
        ("request_id", 123, "INVALID_REQUEST_ID"),
        ("customer_id", "", "INVALID_CUSTOMER_ID"),
        ("session.new_device", "yes", "INVALID_SESSION_FLAG"),
        ("session.on_active_call", 1, "INVALID_SESSION_FLAG"),
        ("payee", "someone", "INVALID_PAYEE"),
        ("session", None, "INVALID_SESSION"),
        ("surprise", "x", "UNKNOWN_FIELD"),
        ("payee.nickname", "x", "UNKNOWN_FIELD"),
        ("session.extra_flag", True, "UNKNOWN_FIELD"),
        ("amount", _DELETE, "MISSING_FIELD"),
        ("payee.bsb", _DELETE, "MISSING_FIELD"),
    ],
)
def test_invalid_input_maps_to_code(path: str, value: Any, expected: str) -> None:
    assert codes(validate_request(mutated(path, value))) == {expected}


def test_issue_field_paths_are_reported() -> None:
    result = validate_request(mutated("payee.bsb", "1"))
    assert isinstance(result, list)
    assert result[0].field == "payee.bsb"


def test_multiple_issues_all_reported_and_deterministic() -> None:
    raw = mutated("amount", "-1")
    raw["payee"]["bsb"] = "1"
    raw["currency"] = "USD"
    first = validate_request(raw)
    assert codes(first) == {"AMOUNT_NOT_POSITIVE", "INVALID_BSB", "UNSUPPORTED_CURRENCY"}
    assert first == validate_request(raw)


@pytest.mark.parametrize("raw", [None, [], "text", 42, {}])
def test_non_object_or_empty_input_never_raises(raw: Any) -> None:
    result = validate_request(raw)
    assert isinstance(result, list)
    assert result
    assert all(isinstance(i, ValidationIssue) for i in result)


def test_issues_do_not_leak_input_values() -> None:
    raw = mutated("payee.account_number", "99999")
    raw["amount"] = "7777.123"
    raw["payee"]["name"] = ""
    dumped = " ".join(i.model_dump_json() for i in validate_request(raw))  # type: ignore[union-attr]
    for secret in ("99999", "7777", "12345678"):
        assert secret not in dumped


def make_response(**overrides: Any) -> DecisionResponse:
    data: dict[str, Any] = {
        "decision_id": "d-1",
        "request_id": "req-0001",
        "decision": Decision.WARN,
        "risk_score": 0.42,
        "reasons": [Reason(code="NEW_PAYEE", detail="First payment to this payee")],
        "mode": Mode.NORMAL,
        "model_version": "m-1",
        "policy_version": "p-1",
        "latency_ms": 1.5,
    }
    data.update(overrides)
    return DecisionResponse(**data)


def test_decision_response_serialises_enums_as_strings() -> None:
    dumped = make_response().model_dump(mode="json")
    assert dumped["decision"] == "WARN"
    assert dumped["mode"] == "NORMAL"


def test_decision_response_allows_nullable_fields() -> None:
    resp = make_response(request_id=None, risk_score=None, model_version=None)
    assert resp.request_id is None
    assert resp.risk_score is None
    assert resp.model_version is None


def test_decision_response_requires_a_reason() -> None:
    with pytest.raises(ValidationError):
        make_response(reasons=[])


def test_decision_response_rejects_unknown_field_and_bad_enum() -> None:
    with pytest.raises(ValidationError):
        make_response(unexpected=1)
    with pytest.raises(ValidationError):
        make_response(decision="APPROVE")
    with pytest.raises(ValidationError):
        make_response(mode="FAST")


def test_enums_have_expected_members() -> None:
    assert {d.value for d in Decision} == {"ALLOW", "WARN", "HOLD", "REJECT"}
    assert {m.value for m in Mode} == {"NORMAL", "DEGRADED_RULES_ONLY"}
