"""FastAPI service: assess payments, inspect the audit trail, run the evaluation.

Run: ``uvicorn scamcheck.api:app`` (use a single worker: the demo switch and the loaded model
live in process memory).

Logs are JSON on stdout. Decision lines carry only decision_id, decision, mode and latency_ms;
never amounts, account numbers, payee names or customer ids.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError
from starlette.concurrency import run_in_threadpool

from scamcheck.audit import MAX_READ_LIMIT, AuditError, AuditLog
from scamcheck.engine import assess_and_record
from scamcheck.evaluate import (
    DEFAULT_SCENARIOS,
    EvaluationResult,
    EvaluationUnavailable,
    ScenarioError,
    _expected_label,
    load_scenarios,
    run_evaluation,
)
from scamcheck.health import check_health
from scamcheck.model import ModelRuntime
from scamcheck.policy import Policy, PolicyError, load_policy
from scamcheck.reference import ReferenceData, ReferenceDataError, load_reference
from scamcheck.schemas import Decision, DecisionResponse, Mode

DEMO_MODE_ENV = "SCAMCHECK_DEMO_MODE"
MAX_BODY_BYTES = 64 * 1024
DEFAULT_AUDIT_LIMIT = 20
LOGGED_FIELDS = ("decision_id", "decision", "mode", "latency_ms")
DEMO_FAILURE_RUNTIME = ModelRuntime(model=None, reason="DEMO_MODEL_FAILURE")
logger = logging.getLogger("scamcheck.api")


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Only whitelisted structured fields are ever included."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name in LOGGED_FIELDS:
            if hasattr(record, name):
                payload[name] = getattr(record, name)
        return json.dumps(payload)


class _StdoutHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Writes to whatever sys.stdout is at emit time (so redirection and tests work)."""

    def __init__(self) -> None:
        super().__init__(sys.stdout)

    @property  # type: ignore[override]
    def stream(self) -> Any:
        return sys.stdout

    @stream.setter
    def stream(self, value: Any) -> None:
        pass


def configure_logging() -> None:
    root = logging.getLogger("scamcheck")
    if any(isinstance(h, _StdoutHandler) for h in root.handlers):
        return
    handler = _StdoutHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(logging.INFO)


class DemoModelFailure(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


@dataclass
class AppState:
    audit: AuditLog
    policy: Policy | None
    reference: ReferenceData | None
    real_runtime: ModelRuntime
    demo_mode: bool
    demo_failure: bool = False
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def runtime(self) -> ModelRuntime:
        return DEMO_FAILURE_RUNTIME if self.demo_failure else self.real_runtime


def _load_or_none[T](loader: Any, error: type[Exception], what: str) -> T | None:
    """Preload at startup; if it fails the engine reloads per request and fails safe (HOLD)."""
    try:
        return loader()  # type: ignore[no-any-return]
    except error:
        logger.error("%s could not be loaded at startup; decisions will be held", what)
        return None


def _parse_body(body: bytes) -> object:
    if len(body) > MAX_BODY_BYTES:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None  # reported as a REJECT (INVALID_REQUEST)


def _unavailable(detail: str) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": detail})


def _outcome_dict(outcome: Any) -> dict[str, Any]:
    r = outcome.response
    return {
        "id": outcome.scenario.id,
        "typology": outcome.scenario.typology,
        "description": outcome.scenario.description,
        "is_scam": outcome.scenario.is_scam,
        "must_hold": outcome.scenario.must_hold,
        "expected": _expected_label(outcome.scenario),
        "actual": r.decision.value,
        "risk_score": r.risk_score,
        "reason_codes": outcome.codes,
        "passed": outcome.passed,
    }


def evaluation_payload(result: EvaluationResult) -> dict[str, Any]:
    return {
        "overall_pass": all(g.passed for g in result.gates),
        "policy_version": result.policy.policy_version,
        "model_version": result.outcomes[0].response.model_version,
        "gates": [asdict(g) for g in result.gates],
        "scenarios": [_outcome_dict(o) for o in result.outcomes],
        "known_limitations": {
            "non_gating": True,
            "matching_correct_answer": sum(1 for o in result.hard if o.decision_ok),
            "total": len(result.hard),
            "scenarios": [_outcome_dict(o) for o in result.hard],
        },
    }


def create_app(
    *,
    audit_path: str | os.PathLike[str] | None = None,
    demo_mode: bool | None = None,
    model_path: str | os.PathLike[str] | None = None,
) -> FastAPI:
    configure_logging()
    state = AppState(
        audit=AuditLog(audit_path),
        policy=_load_or_none(load_policy, PolicyError, "Policy"),
        reference=_load_or_none(load_reference, ReferenceDataError, "Reference data"),
        real_runtime=ModelRuntime.from_path(model_path),
        demo_mode=(os.environ.get(DEMO_MODE_ENV) == "1") if demo_mode is None else demo_mode,
    )
    app = FastAPI(title="scamcheck", version="0.1.0", description="SYNTHETIC data only.")
    app.state.scamcheck = state

    @app.post(
        "/v1/assess",
        responses={200: {"model": DecisionResponse}, 422: {"model": DecisionResponse}},
    )
    async def assess_payment(request: Request) -> JSONResponse:
        raw = _parse_body(await request.body())
        response = await run_in_threadpool(
            assess_and_record, raw, state.audit, state.policy, state.reference, state.runtime
        )
        logger.info(
            "decision",
            extra={
                "decision_id": response.decision_id,
                "decision": response.decision.value,
                "mode": response.mode.value,
                "latency_ms": response.latency_ms,
            },
        )
        status = 422 if response.decision is Decision.REJECT else 200
        return JSONResponse(status_code=status, content=response.model_dump(mode="json"))

    @app.get("/health")
    def health() -> dict[str, object]:
        return check_health(state.policy, state.reference, state.runtime, state.audit).as_dict()

    @app.get("/v1/scenarios")
    def scenarios() -> Any:
        try:
            loaded = load_scenarios(DEFAULT_SCENARIOS)
        except ScenarioError:
            return _unavailable("scenarios are unavailable")
        return [
            {"id": s.id, "typology": s.typology, "description": s.description, "request": s.request}
            for s in loaded
        ]

    @app.get("/v1/audit")
    def audit_records(
        limit: int = Query(DEFAULT_AUDIT_LIMIT, ge=1, le=MAX_READ_LIMIT),
    ) -> Any:
        try:
            records = state.audit.read_recent(limit)
        except AuditError:
            return _unavailable("audit log cannot be read")
        return {"count": len(records), "records": records}

    @app.post("/v1/audit/verify")
    def audit_verify() -> dict[str, object]:
        return asdict(state.audit.verify())

    @app.post("/v1/eval")
    async def run_eval() -> Any:
        try:
            result = await run_in_threadpool(run_evaluation)
        except EvaluationUnavailable as exc:
            return _unavailable(f"evaluation unavailable: {exc}")
        return evaluation_payload(result)

    @app.post("/v1/demo/model-failure")
    async def demo_model_failure(request: Request) -> JSONResponse:
        if not state.demo_mode:
            return JSONResponse(
                status_code=403,
                content={"detail": f"Demo mode is off. Set {DEMO_MODE_ENV}=1 to enable it."},
            )
        try:
            body = DemoModelFailure.model_validate(_parse_body(await request.body()))
        except ValidationError:
            return JSONResponse(status_code=422, content={"detail": 'expected {"enabled": bool}'})
        state.demo_failure = body.enabled
        if body.enabled:
            logger.warning("Demo: simulated model failure on; running in DEGRADED_RULES_ONLY mode")
        else:
            logger.warning("Demo: simulated model failure off")
        mode = Mode.NORMAL if state.runtime.model is not None else Mode.DEGRADED_RULES_ONLY
        return JSONResponse(content={"enabled": state.demo_failure, "mode": mode.value})

    return app


app = create_app()
