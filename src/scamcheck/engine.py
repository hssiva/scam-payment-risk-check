"""Decision engine: validate -> signals -> abstain check -> rules -> decision.

Fail safe: if the engine cannot decide reliably (policy or reference data unavailable, or any
unexpected error) it returns HOLD, never ALLOW. Reasons never contain amounts, payee names or
account numbers.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from scamcheck.policy import Policy, PolicyError, load_policy
from scamcheck.reference import ReferenceData, ReferenceDataError, load_reference
from scamcheck.rules import evaluate_rules, most_severe
from scamcheck.schemas import (
    ID_MAX_LENGTH,
    Decision,
    DecisionResponse,
    Mode,
    PaymentRequest,
    Reason,
    ValidationIssue,
    validate_request,
)
from scamcheck.signals import build_signals

UNKNOWN_POLICY_VERSION = "UNKNOWN"


class _Meta:
    """Per-call values shared by every response built for one request."""

    def __init__(self, raw: object) -> None:
        self.started = time.perf_counter()
        self.decision_id = str(uuid.uuid4())
        self.request_id = _request_id_of(raw)


def _request_id_of(raw: object) -> str | None:
    if isinstance(raw, dict):
        value = raw.get("request_id")
        if isinstance(value, str) and 1 <= len(value) <= ID_MAX_LENGTH:
            return value
    return None


def _respond(
    meta: _Meta,
    decision: Decision,
    reasons: list[Reason],
    policy_version: str,
    *,
    risk_score: float | None = None,
    model_version: str | None = None,
    mode: Mode = Mode.NORMAL,
) -> DecisionResponse:
    return DecisionResponse(
        decision_id=meta.decision_id,
        request_id=meta.request_id,
        decision=decision,
        risk_score=risk_score,
        reasons=reasons,
        mode=mode,
        model_version=model_version,
        policy_version=policy_version,
        latency_ms=round((time.perf_counter() - meta.started) * 1000, 3),
    )


def _fail_safe(meta: _Meta, code: str, detail: str, policy_version: str) -> DecisionResponse:
    return _respond(meta, Decision.HOLD, [Reason(code=code, detail=detail)], policy_version)


def _reject_reasons(issues: list[ValidationIssue]) -> list[Reason]:
    return [
        Reason(code=i.code, detail=f"{i.field}: {i.message}" if i.field else i.message)
        for i in issues
    ]


def _decide(
    meta: _Meta, raw: dict[str, Any], policy: Policy, reference: ReferenceData | None
) -> DecisionResponse:
    validated = validate_request(raw, max_amount=policy.max_amount)
    if not isinstance(validated, PaymentRequest):
        return _respond(meta, Decision.REJECT, _reject_reasons(validated), policy.policy_version)
    request = validated

    signals = build_signals(request, reference if reference is not None else load_reference())

    floors: list[Decision] = []
    reasons: list[Reason] = []

    # Abstain: not enough reference data to judge a payment of this size.
    if not signals.data_complete and request.amount >= policy.abstain_amount:
        floors.append(Decision.HOLD)
        reasons.append(
            Reason(
                code="ABSTAIN_INSUFFICIENT_DATA",
                detail="Customer or payee is missing from reference data; cannot assess safely.",
            )
        )

    for hit in evaluate_rules(signals, request.amount, policy):
        floors.append(hit.floor)
        reasons.append(hit.reason)

    # ---------------------------------------------------------------------------------
    # P5 HOOK: model scoring plugs in here. It should set risk_score / model_version,
    # may add a floor (using policy.score_warn / policy.score_hold) and reasons, and set
    # mode to DEGRADED_RULES_ONLY if the model artifact cannot be used.
    # Until then the decision comes from rules only.
    risk_score: float | None = None
    model_version: str | None = None
    mode = Mode.NORMAL
    # ---------------------------------------------------------------------------------

    decision = most_severe(floors)
    if not reasons:
        reasons.append(Reason(code="NO_RISK_SIGNALS", detail="No risk signals were triggered."))
    return _respond(
        meta,
        decision,
        reasons,
        policy.policy_version,
        risk_score=risk_score,
        model_version=model_version,
        mode=mode,
    )


def assess(
    raw: dict[str, Any],
    policy: Policy | None = None,
    reference: ReferenceData | None = None,
) -> DecisionResponse:
    """Assess one raw payment request. Never raises.

    ``policy`` and ``reference`` are loaded from disk when omitted; long-running callers should
    load them once and pass them in.
    """
    meta = _Meta(raw)
    try:
        if policy is None:
            policy = load_policy()
    except PolicyError:
        return _fail_safe(
            meta, "POLICY_UNAVAILABLE", "Policy could not be loaded.", UNKNOWN_POLICY_VERSION
        )
    except Exception:  # fail safe: any unexpected error means HOLD
        return _fail_safe(
            meta, "INTERNAL_ERROR", "Unexpected error; payment held.", UNKNOWN_POLICY_VERSION
        )

    try:
        return _decide(meta, raw, policy, reference)
    except ReferenceDataError:
        return _fail_safe(
            meta,
            "REFERENCE_DATA_UNAVAILABLE",
            "Reference data could not be loaded.",
            policy.policy_version,
        )
    except Exception:  # fail safe: any unexpected error means HOLD
        return _fail_safe(
            meta, "INTERNAL_ERROR", "Unexpected error; payment held.", policy.policy_version
        )
