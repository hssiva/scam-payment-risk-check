"""Input and output contracts for scamcheck (pydantic v2).

All data handled here is SYNTHETIC. Validation issues never echo input values, so account
numbers, payee names and amounts cannot leak into responses or logs.
"""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
)

# TODO: move to config/policy.toml once the policy loader exists.
MAX_AMOUNT = Decimal("1000000")

_Id = Annotated[str, Field(min_length=1, max_length=64, strict=True)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Payee(_Strict):
    name: Annotated[str, Field(min_length=1, max_length=140, strict=True)]
    bsb: Annotated[str, Field(pattern=r"^[0-9]{6}$", strict=True)]
    account_number: Annotated[str, Field(pattern=r"^[0-9]{6,9}$", strict=True)]


class Session(_Strict):
    on_active_call: StrictBool
    remote_access_detected: StrictBool
    new_device: StrictBool


class PaymentRequest(_Strict):
    request_id: _Id
    timestamp: AwareDatetime
    customer_id: _Id
    amount: Annotated[Decimal, Field(gt=0, le=MAX_AMOUNT, decimal_places=2)]
    currency: Literal["AUD"]
    payee: Payee
    channel: Literal["mobile", "web", "branch"]
    session: Session


class Decision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    HOLD = "HOLD"
    REJECT = "REJECT"


class Mode(StrEnum):
    NORMAL = "NORMAL"
    DEGRADED_RULES_ONLY = "DEGRADED_RULES_ONLY"


class Reason(_Strict):
    code: str
    detail: str


class DecisionResponse(_Strict):
    decision_id: str
    request_id: str | None
    decision: Decision
    risk_score: float | None
    reasons: Annotated[list[Reason], Field(min_length=1)]
    mode: Mode
    model_version: str | None
    policy_version: str
    latency_ms: float


class ValidationIssue(_Strict):
    code: str
    field: str
    message: str


_MESSAGES: dict[str, str] = {
    "INVALID_REQUEST": "Request is not a valid payment request object.",
    "UNKNOWN_FIELD": "Field is not part of the contract.",
    "MISSING_FIELD": "Required field is missing.",
    "NAIVE_TIMESTAMP": "Timestamp must include a timezone offset.",
    "INVALID_TIMESTAMP": "Timestamp is not a valid ISO 8601 datetime.",
    "AMOUNT_NOT_POSITIVE": "Amount must be greater than zero.",
    "AMOUNT_TOO_LARGE": "Amount exceeds the maximum allowed.",
    "AMOUNT_TOO_PRECISE": "Amount must have at most 2 decimal places.",
    "AMOUNT_INVALID": "Amount is not a valid finite decimal number.",
    "INVALID_REQUEST_ID": "request_id must be a string of 1-64 characters.",
    "INVALID_CUSTOMER_ID": "customer_id must be a string of 1-64 characters.",
    "UNSUPPORTED_CURRENCY": "Only AUD is supported.",
    "INVALID_CHANNEL": "channel must be one of mobile, web, branch.",
    "INVALID_PAYEE": "payee must be an object.",
    "INVALID_PAYEE_NAME": "Payee name must be a string of 1-140 characters.",
    "INVALID_BSB": "BSB must be exactly 6 digits.",
    "INVALID_ACCOUNT_NUMBER": "Account number must be 6-9 digits.",
    "INVALID_SESSION": "session must be an object.",
    "INVALID_SESSION_FLAG": "Session flags must be true or false.",
}

_AMOUNT_CODES: dict[str, str] = {
    "greater_than": "AMOUNT_NOT_POSITIVE",
    "less_than_equal": "AMOUNT_TOO_LARGE",
    "decimal_max_places": "AMOUNT_TOO_PRECISE",
}

_FIELD_CODES: dict[str, str] = {
    "request_id": "INVALID_REQUEST_ID",
    "timestamp": "INVALID_TIMESTAMP",
    "customer_id": "INVALID_CUSTOMER_ID",
    "currency": "UNSUPPORTED_CURRENCY",
    "channel": "INVALID_CHANNEL",
    "payee": "INVALID_PAYEE",
    "name": "INVALID_PAYEE_NAME",
    "bsb": "INVALID_BSB",
    "account_number": "INVALID_ACCOUNT_NUMBER",
    "session": "INVALID_SESSION",
    "on_active_call": "INVALID_SESSION_FLAG",
    "remote_access_detected": "INVALID_SESSION_FLAG",
    "new_device": "INVALID_SESSION_FLAG",
}


def _issue(code: str, field: str) -> ValidationIssue:
    return ValidationIssue(code=code, field=field, message=_MESSAGES[code])


def _code_for(error_type: str, field: str) -> str:
    if error_type == "extra_forbidden":
        return "UNKNOWN_FIELD"
    if error_type == "missing":
        return "MISSING_FIELD"
    if error_type == "timezone_aware":
        return "NAIVE_TIMESTAMP"
    if field == "amount":
        return _AMOUNT_CODES.get(error_type, "AMOUNT_INVALID")
    return _FIELD_CODES.get(field, "INVALID_REQUEST")


def _issues_from(exc: ValidationError) -> list[ValidationIssue]:
    seen: set[tuple[str, str]] = set()
    issues: list[ValidationIssue] = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = err["loc"]
        path = ".".join(str(part) for part in loc)
        last = str(loc[-1]) if loc else ""
        code = _code_for(err["type"], last)
        if (code, path) not in seen:
            seen.add((code, path))
            issues.append(_issue(code, path))
    return sorted(issues, key=lambda i: (i.field, i.code))


def validate_request(raw: dict[str, Any]) -> PaymentRequest | list[ValidationIssue]:
    """Validate raw input. Never raises; returns a request or a non-empty list of issues."""
    if not isinstance(raw, dict):
        return [_issue("INVALID_REQUEST", "")]
    try:
        return PaymentRequest.model_validate(raw)
    except ValidationError as exc:
        return _issues_from(exc) or [_issue("INVALID_REQUEST", "")]
    except Exception:  # contract: validation must never raise
        return [_issue("INVALID_REQUEST", "")]
