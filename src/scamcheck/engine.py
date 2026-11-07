"""Decision engine: validate -> signals -> abstain check -> rules -> model -> decision.

NORMAL mode: the decision is the most severe of the rule floors and the model score band.
DEGRADED_RULES_ONLY mode (model unavailable): rules only, plus a fail-safe HOLD for any risk
signal on a payment at or above ``abstain_amount``.

Fail safe: if the engine cannot decide reliably (policy or reference data unavailable, or any
unexpected error) it returns HOLD, never ALLOW. Reasons never contain amounts, payee names or
account numbers.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from scamcheck.audit import AuditLog, build_entry
from scamcheck.model import ModelRuntime, default_runtime
from scamcheck.policy import Policy, PolicyError, load_policy
from scamcheck.reference import ReferenceData, ReferenceDataError, load_reference
from scamcheck.rules import any_risk_signal, evaluate_rules, most_severe
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
from scamcheck.signals import Signals, build_signals

UNKNOWN_POLICY_VERSION = "UNKNOWN"
logger = logging.getLogger(__name__)


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


@dataclass
class _ModelOutcome:
    floors: list[Decision] = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)
    risk_score: float | None = None
    model_version: str | None = None
    mode: Mode = Mode.NORMAL


def _score_band(probability: float, policy: Policy) -> Decision:
    if probability >= policy.score_hold:
        return Decision.HOLD
    if probability >= policy.score_warn:
        return Decision.WARN
    return Decision.ALLOW


def _degraded_outcome(signals: Signals, amount: Decimal, policy: Policy) -> _ModelOutcome:
    """No model: fail safe by holding any risky payment at or above the abstain amount."""
    outcome = _ModelOutcome(mode=Mode.DEGRADED_RULES_ONLY)
    if amount >= policy.abstain_amount and any_risk_signal(signals, policy):
        outcome.floors.append(Decision.HOLD)
        outcome.reasons.append(
            Reason(
                code="DEGRADED_FAILSAFE_HOLD",
                detail="Risk signal present while the risk model is unavailable; payment held.",
            )
        )
    return outcome


def _model_outcome(
    runtime: ModelRuntime, signals: Signals, amount: Decimal, policy: Policy
) -> _ModelOutcome:
    model = runtime.model
    if model is None:
        return _degraded_outcome(signals, amount, policy)
    score = model.score(signals)
    band = _score_band(score.probability, policy)
    reasons = score.reasons if band is not Decision.ALLOW else []
    if band is not Decision.ALLOW and not reasons:
        reasons = [Reason(code="M_SCORE_ELEVATED", detail="Model risk score is elevated.")]
    return _ModelOutcome(
        floors=[band],
        reasons=reasons,
        risk_score=round(score.probability, 4),
        model_version=model.version,
    )


def _decide(
    meta: _Meta,
    raw: dict[str, Any],
    policy: Policy,
    reference: ReferenceData | None,
    runtime: ModelRuntime,
) -> DecisionResponse:
    validated = validate_request(raw, max_amount=policy.max_amount)
    if not isinstance(validated, PaymentRequest):
        return _respond(meta, Decision.REJECT, _reject_reasons(validated), policy.policy_version)
    request = validated

    signals = build_signals(
        request,
        reference if reference is not None else load_reference(),
        policy.name_close_threshold,
    )

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

    model_outcome = _model_outcome(runtime, signals, request.amount, policy)
    floors.extend(model_outcome.floors)
    reasons.extend(model_outcome.reasons)

    decision = most_severe(floors)
    if not reasons:
        reasons.append(Reason(code="NO_RISK_SIGNALS", detail="No risk signals were triggered."))
    return _respond(
        meta,
        decision,
        reasons,
        policy.policy_version,
        risk_score=model_outcome.risk_score,
        model_version=model_outcome.model_version,
        mode=model_outcome.mode,
    )


def assess(
    raw: dict[str, Any],
    policy: Policy | None = None,
    reference: ReferenceData | None = None,
    model: ModelRuntime | None = None,
) -> DecisionResponse:
    """Assess one raw payment request. Never raises.

    ``policy`` and ``reference`` are loaded from disk when omitted (every call); ``model``
    defaults to the process-wide runtime, loaded once. Long-running callers should load
    everything once and pass it in.
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
        return _decide(meta, raw, policy, reference, model or default_runtime())
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


def assess_and_record(
    raw: dict[str, Any],
    audit: AuditLog,
    policy: Policy | None = None,
    reference: ReferenceData | None = None,
    model: ModelRuntime | None = None,
) -> DecisionResponse:
    """``assess`` plus a tamper-evident audit record. Fails closed.

    Every request, including rejected ones, is recorded. If the record cannot be written the
    payment is held (reason ``AUDIT_UNAVAILABLE``, followed by the original reasons): a decision
    that cannot be audited is never released. ``assess`` itself does not write the audit trail.
    """
    response = assess(raw, policy=policy, reference=reference, model=model)
    try:
        audit.append(build_entry(raw, response))
    except Exception as exc:  # fail closed: any audit problem means HOLD
        logger.error("Audit write failed (%s); decision forced to HOLD", type(exc).__name__)
        unavailable = Reason(
            code="AUDIT_UNAVAILABLE",
            detail="The audit trail could not be written; payment held.",
        )
        return response.model_copy(
            update={"decision": Decision.HOLD, "reasons": [unavailable, *response.reasons]}
        )
    return response
