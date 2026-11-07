"""Service health, shared by the API (/health) and the CLI (``scamcheck health``)."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from scamcheck.audit import AuditLog
from scamcheck.model import ModelRuntime
from scamcheck.policy import Policy, PolicyError, load_policy
from scamcheck.reference import ReferenceData, ReferenceDataError, load_reference
from scamcheck.schemas import Mode


@dataclass(frozen=True)
class Health:
    status: str  # "ok" or "degraded"
    mode: str
    model_version: str | None
    policy_version: str | None
    reasons: list[str]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def check_health(
    policy: Policy | None, reference: ReferenceData | None, runtime: ModelRuntime, audit: AuditLog
) -> Health:
    """Status is ``ok`` only when the model, policy, reference data and audit trail are usable."""
    reasons: list[str] = []
    model_health = runtime.health()
    if model_health.status != "ok":
        reasons.append(model_health.reason or "MODEL_UNAVAILABLE")
    if policy is None:
        try:
            policy = load_policy()
        except PolicyError:
            reasons.append("POLICY_UNAVAILABLE")
    if reference is None:
        try:
            load_reference()
        except ReferenceDataError:
            reasons.append("REFERENCE_DATA_UNAVAILABLE")
    if not audit.writable():
        reasons.append("AUDIT_UNAVAILABLE")
    return Health(
        status="ok" if not reasons else "degraded",
        mode=(Mode.NORMAL if runtime.model is not None else Mode.DEGRADED_RULES_ONLY).value,
        model_version=runtime.model.version if runtime.model is not None else None,
        policy_version=policy.policy_version if policy is not None else None,
        reasons=reasons,
    )
