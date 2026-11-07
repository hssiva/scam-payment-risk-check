"""Evaluation gate: run labelled SYNTHETIC scenarios through the engine and enforce the gates.

Gates (thresholds for 2 and 3 live in ``config/policy.toml`` under ``[evaluation]``):
  1. every ``must_hold`` scenario is held
  2. at least ``min_scam_warn_or_hold_rate`` of scam scenarios end in WARN or HOLD
  3. at most ``max_genuine_hold_rate`` of genuine scenarios end in HOLD
  4. every non-REJECT decision carries at least one reason
  5. running everything twice gives identical decisions
  6. with a tampered model artifact (a temporary copy), every ``must_hold`` scenario still holds

Scenarios with ``is_scam: null`` (missing data, invalid requests) have no ground-truth label, so
they are excluded from gates 2 and 3 but are still checked against their expected decision.

``sample-data/scenarios_hard.jsonl`` holds realistic cases the system is known or expected to get
wrong (labelled with the correct answer from a fraud perspective). They are run and reported on
every evaluation but never affect the gates or the exit code.

Usage: python -m scamcheck.evaluate [--scenarios PATH] [--hard PATH] [--report PATH]
       (exit 1 if a gate fails, 2 if it cannot run)
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from scamcheck.engine import assess
from scamcheck.model import CHECKSUM_SUFFIX, ModelRuntime, default_model_path
from scamcheck.policy import Policy, PolicyError, load_policy
from scamcheck.reference import ReferenceData, ReferenceDataError, load_reference
from scamcheck.schemas import Decision, DecisionResponse

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIOS = ROOT / "sample-data" / "scenarios.jsonl"
DEFAULT_HARD = ROOT / "sample-data" / "scenarios_hard.jsonl"
DEFAULT_REPORT = ROOT / "evidence" / "eval-report.md"
MODEL_LOGGER = "scamcheck.model"


class ScenarioError(Exception):
    """The scenario file is missing or invalid."""


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    typology: str = Field(min_length=1)
    description: str = Field(min_length=1)
    request: Any
    expected_decision: Decision | list[Decision]
    must_hold: bool
    is_scam: bool | None
    expected_codes: list[str] = Field(default_factory=list)

    @property
    def allowed(self) -> frozenset[Decision]:
        value = self.expected_decision
        return frozenset(value if isinstance(value, list) else [value])

    @model_validator(mode="after")
    def _consistent(self) -> Scenario:
        if self.must_hold and self.allowed != {Decision.HOLD}:
            raise ValueError("must_hold scenarios must expect exactly HOLD")
        if not self.allowed:
            raise ValueError("expected_decision must not be empty")
        return self


def load_scenarios(path: Path) -> list[Scenario]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ScenarioError(f"{path}: scenario file is missing or unreadable") from exc
    scenarios: list[Scenario] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            scenarios.append(Scenario.model_validate(json.loads(line)))
        except (ValueError, ValidationError) as exc:
            raise ScenarioError(f"{path}: line {number} is not a valid scenario") from exc
    ids = [s.id for s in scenarios]
    if not scenarios:
        raise ScenarioError(f"{path}: no scenarios found")
    if len(set(ids)) != len(ids):
        raise ScenarioError(f"{path}: duplicate scenario ids")
    return scenarios


def load_hard_scenarios(path: Path, gated: list[Scenario]) -> list[Scenario]:
    """Load the non-gating known-limitation scenarios (must not duplicate gated ids)."""
    hard = load_scenarios(path)
    if any(s.must_hold for s in hard):
        raise ScenarioError(f"{path}: known-limitation scenarios cannot be must_hold")
    clash = {s.id for s in hard} & {s.id for s in gated}
    if clash:
        raise ScenarioError(f"{path}: ids also used in the gated scenarios: {sorted(clash)}")
    return hard


@dataclass(frozen=True)
class Outcome:
    scenario: Scenario
    response: DecisionResponse

    @property
    def codes(self) -> list[str]:
        return [r.code for r in self.response.reasons]

    @property
    def decision_ok(self) -> bool:
        return self.response.decision in self.scenario.allowed

    @property
    def codes_ok(self) -> bool:
        return set(self.scenario.expected_codes) <= set(self.codes)

    @property
    def passed(self) -> bool:
        return self.decision_ok and self.codes_ok


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    detail: str


def run_all(
    scenarios: list[Scenario], policy: Policy, reference: ReferenceData, runtime: ModelRuntime
) -> list[Outcome]:
    return [
        Outcome(s, assess(s.request, policy=policy, reference=reference, model=runtime))
        for s in scenarios
    ]


def _fmt_ids(items: list[str]) -> str:
    return ", ".join(items) if items else "none"


def _describe(outcomes: list[Outcome]) -> str:
    return "; ".join(
        f"{o.scenario.id} -> {o.response.decision} [{', '.join(o.codes)}]" for o in outcomes
    )


def gate_must_hold(outcomes: list[Outcome]) -> GateResult:
    required = [o for o in outcomes if o.scenario.must_hold]
    missed = [o for o in required if o.response.decision is not Decision.HOLD]
    held = len(required) - len(missed)
    detail = f"{held}/{len(required)} must-hold scenarios held"
    if missed:
        detail += f". Not held: {_describe(missed)}"
    return GateResult("1. All must-hold scenarios are HOLD", bool(required) and not missed, detail)


def gate_scam_catch(outcomes: list[Outcome], min_rate: float) -> GateResult:
    scams = [o for o in outcomes if o.scenario.is_scam is True]
    missed = [o for o in scams if o.response.decision not in (Decision.WARN, Decision.HOLD)]
    rate = (len(scams) - len(missed)) / len(scams) if scams else 0.0
    detail = (
        f"{len(scams) - len(missed)}/{len(scams)} scams warned or held ({rate:.1%}); "
        f"need >= {min_rate:.0%}"
    )
    if missed:
        detail += f". Missed: {_describe(missed)}"
    return GateResult("2. Scams caught (WARN or HOLD)", bool(scams) and rate >= min_rate, detail)


def gate_genuine_friction(outcomes: list[Outcome], max_rate: float) -> GateResult:
    genuine = [o for o in outcomes if o.scenario.is_scam is False]
    held = [o for o in genuine if o.response.decision is Decision.HOLD]
    rate = len(held) / len(genuine) if genuine else 1.0
    detail = (
        f"{len(held)}/{len(genuine)} genuine scenarios held ({rate:.1%}); allow <= {max_rate:.0%}"
    )
    if held:
        detail += f". Held: {_describe(held)}"
    return GateResult(
        "3. Genuine payments held within budget", bool(genuine) and rate <= max_rate, detail
    )


def gate_reasons(outcomes: list[Outcome]) -> GateResult:
    checked = [o for o in outcomes if o.response.decision is not Decision.REJECT]
    bare = [o for o in checked if not o.response.reasons]
    detail = f"{len(checked) - len(bare)}/{len(checked)} non-REJECT decisions have a reason"
    if bare:
        detail += f". Without reasons: {_fmt_ids([o.scenario.id for o in bare])}"
    return GateResult("4. Every non-REJECT decision has a reason", not bare, detail)


def _fingerprint(outcome: Outcome) -> tuple[Any, ...]:
    r = outcome.response
    return (
        r.decision,
        r.risk_score,
        tuple((x.code, x.detail) for x in r.reasons),
        r.mode,
        r.model_version,
        r.policy_version,
        r.request_id,
    )


def gate_determinism(first: list[Outcome], second: list[Outcome]) -> GateResult:
    differing = [
        a.scenario.id
        for a, b in zip(first, second, strict=True)
        if _fingerprint(a) != _fingerprint(b)
    ]
    detail = f"{len(first) - len(differing)}/{len(first)} scenarios identical across two runs"
    if differing:
        detail += f". Differ: {_fmt_ids(differing)}"
    return GateResult("5. Two runs give identical decisions", not differing, detail)


class _Collector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def tampered_runtime(
    model_path: Path | None = None,
) -> tuple[ModelRuntime, list[logging.LogRecord]]:
    """Load a tampered temporary copy of the model artifact (the real files are never touched).

    The tampering is an edit that would make the model allow everything, made without updating
    the checksum file, which is what an attacker who cannot rewrite the checksum would do.
    """
    source = model_path or default_model_path()
    logger = logging.getLogger(MODEL_LOGGER)
    collector = _Collector()
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / source.name
        checksum = source.with_name(source.stem + CHECKSUM_SUFFIX)
        shutil.copy(checksum, Path(tmp) / checksum.name)
        artifact = json.loads(source.read_text(encoding="utf-8"))
        artifact["intercept"] = -50.0
        copy.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        logger.addHandler(collector)
        propagate = logger.propagate
        logger.propagate = False  # the deliberate degrade must not reach service logs
        try:
            runtime = ModelRuntime.from_path(copy)
        finally:
            logger.propagate = propagate
            logger.removeHandler(collector)
    return runtime, collector.records


def gate_tampered_model(
    scenarios: list[Scenario], policy: Policy, reference: ReferenceData
) -> GateResult:
    runtime, records = tampered_runtime()
    health = runtime.health()
    name = "6. Must-hold scenarios still HOLD with a tampered model"
    if health.status != "degraded" or health.reason != "MODEL_INTEGRITY_FAILED":
        return GateResult(name, False, f"tampering was NOT detected (health: {health.status})")
    outcomes = run_all(scenarios, policy, reference, runtime)
    required = [o for o in outcomes if o.scenario.must_hold]
    missed = [o for o in required if o.response.decision is not Decision.HOLD]
    warnings = [r for r in records if r.levelno >= logging.WARNING]
    detail = (
        f"tamper detected ({health.reason}); {len(required) - len(missed)}/{len(required)} "
        f"must-hold scenarios held in {outcomes[0].response.mode}; degrade warnings logged: "
        f"{len(warnings)}"
    )
    if missed:
        detail += f". Not held: {_describe(missed)}"
    return GateResult(name, bool(required) and not missed and len(warnings) == 1, detail)


def evaluate(
    scenarios: list[Scenario], policy: Policy, reference: ReferenceData, runtime: ModelRuntime
) -> tuple[list[Outcome], list[GateResult]]:
    first = run_all(scenarios, policy, reference, runtime)
    second = run_all(scenarios, policy, reference, runtime)
    gates = [
        gate_must_hold(first),
        gate_scam_catch(first, policy.evaluation.min_scam_warn_or_hold_rate),
        gate_genuine_friction(first, policy.evaluation.max_genuine_hold_rate),
        gate_reasons(first),
        gate_determinism(first, second),
        gate_tampered_model(scenarios, policy, reference),
    ]
    return first, gates


# --- report -----------------------------------------------------------------------------------


def _cell(text: object) -> str:
    return str(text).replace("|", "/").replace("\n", " ")


def _expected_label(scenario: Scenario) -> str:
    ordered = sorted(scenario.allowed, key=list(Decision).index)
    label = "/".join(d.value for d in ordered)
    return f"{label} (must hold)" if scenario.must_hold else label


def _metrics(outcomes: list[Outcome]) -> list[tuple[str, str]]:
    def count(pred: Callable[[Outcome], bool]) -> int:
        return sum(1 for o in outcomes if pred(o))

    scams = [o for o in outcomes if o.scenario.is_scam is True]
    genuine = [o for o in outcomes if o.scenario.is_scam is False]
    unlabelled = [o for o in outcomes if o.scenario.is_scam is None]
    caught = sum(1 for o in scams if o.response.decision in (Decision.WARN, Decision.HOLD))
    held = sum(1 for o in genuine if o.response.decision is Decision.HOLD)
    must_total = count(lambda o: o.scenario.must_hold)
    must_held = count(lambda o: o.scenario.must_hold and o.response.decision is Decision.HOLD)
    return [
        ("Scenarios", str(len(outcomes))),
        ("Scam scenarios warned or held", f"{caught}/{len(scams)}"),
        ("Genuine scenarios held", f"{held}/{len(genuine)}"),
        ("Unlabelled (missing data / invalid), excluded from the two rates", str(len(unlabelled))),
        (
            "Must-hold scenarios held",
            f"{must_held}/{must_total}",
        ),
        (
            "Scenarios matching their expected decision",
            f"{count(lambda o: o.decision_ok)}/{len(outcomes)}",
        ),
        (
            "Scenarios passing (decision and expected reason codes)",
            f"{count(lambda o: o.passed)}/{len(outcomes)}",
        ),
    ]


def _hard_section(hard: list[Outcome]) -> list[str]:
    matching = sum(1 for o in hard if o.decision_ok)
    lines = [
        "",
        "## Known limitations (non-gating)",
        "",
        "Realistic cases the system is expected to get wrong, labelled with the correct answer",
        "from a fraud perspective. They are run on every evaluation but never affect the gates",
        "or the exit code.",
        "",
        f"**{matching} of {len(hard)} match the correct answer.**",
        "",
        "| ID | Typology | Scam? | Correct answer | Actual | Score | Reason codes | Matches? |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for o in hard:
        score = "-" if o.response.risk_score is None else f"{o.response.risk_score:.4f}"
        label = {True: "yes", False: "no", None: "n/a"}[o.scenario.is_scam]
        lines.append(
            f"| {o.scenario.id} | {_cell(o.scenario.typology)} | {label} | "
            f"{_cell(_expected_label(o.scenario))} | {o.response.decision} | {score} | "
            f"{_cell(', '.join(o.codes))} | {'yes' if o.decision_ok else 'NO'} |"
        )
    lines += ["", "Descriptions of the cases the system gets wrong:", ""]
    wrong = [o for o in hard if not o.decision_ok]
    lines += [f"- **{o.scenario.id}**: {o.scenario.description}" for o in wrong] or ["- None."]
    return lines


def render_report(
    outcomes: list[Outcome],
    gates: list[GateResult],
    policy: Policy,
    hard: list[Outcome] | None = None,
) -> str:
    first = outcomes[0].response
    lines = [
        "# Evaluation report",
        "",
        "SYNTHETIC scenarios only (`sample-data/scenarios.jsonl`).",
        "Generated by `make eval`; do not edit.",
        "",
        f"- Policy version: `{policy.policy_version}`",
        f"- Model version: `{first.model_version}` (mode `{first.mode}`)",
        f"- Overall: **{'PASS' if all(g.passed for g in gates) else 'FAIL'}**",
        "",
        "## Gate results",
        "",
        "| Gate | Result | Detail |",
        "|---|---|---|",
    ]
    lines += [
        f"| {_cell(g.name)} | {'PASS' if g.passed else 'FAIL'} | {_cell(g.detail)} |" for g in gates
    ]
    lines += ["", "## Summary metrics", "", "| Metric | Value |", "|---|---|"]
    lines += [f"| {_cell(name)} | {_cell(value)} |" for name, value in _metrics(outcomes)]
    lines += [
        "",
        "## Scenarios",
        "",
        "| ID | Typology | Scam? | Expected | Actual | Score | Reason codes | Result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for o in outcomes:
        score = "-" if o.response.risk_score is None else f"{o.response.risk_score:.4f}"
        label = {True: "yes", False: "no", None: "n/a"}[o.scenario.is_scam]
        lines.append(
            f"| {o.scenario.id} | {_cell(o.scenario.typology)} | {label} | "
            f"{_cell(_expected_label(o.scenario))} | {o.response.decision} | {score} | "
            f"{_cell(', '.join(o.codes))} | {'PASS' if o.passed else 'FAIL'} |"
        )
    failing = [o for o in outcomes if not o.passed]
    lines += ["", "## Scenarios that did not match", ""]
    if not failing:
        lines.append("None.")
    for o in failing:
        wanted = (
            f"; expected codes {o.scenario.expected_codes}" if o.scenario.expected_codes else ""
        )
        lines.append(
            f"- **{o.scenario.id}** ({o.scenario.typology}): expected {_expected_label(o.scenario)}"
            f"{wanted}; got {o.response.decision} with {o.codes}. {o.scenario.description}"
        )
    if hard:
        lines += _hard_section(hard)
    return "\n".join(lines) + "\n"


class EvaluationUnavailable(Exception):
    """The evaluation cannot run (scenario file, policy, reference data or model unavailable)."""


@dataclass(frozen=True)
class EvaluationResult:
    outcomes: list[Outcome]
    gates: list[GateResult]
    hard: list[Outcome]
    policy: Policy


def run_evaluation(
    scenarios_path: Path = DEFAULT_SCENARIOS, hard_path: Path = DEFAULT_HARD
) -> EvaluationResult:
    """Load everything and evaluate (no report is written). Used by the API."""
    try:
        scenarios = load_scenarios(scenarios_path)
        hard_scenarios = load_hard_scenarios(hard_path, scenarios)
        policy = load_policy()
        reference = load_reference()
    except (ScenarioError, PolicyError, ReferenceDataError) as exc:
        raise EvaluationUnavailable(str(exc)) from exc
    runtime = ModelRuntime.from_path()
    if runtime.health().status != "ok":
        raise EvaluationUnavailable(f"the risk model is unavailable ({runtime.health().reason})")
    outcomes, gates = evaluate(scenarios, policy, reference, runtime)
    return EvaluationResult(
        outcomes, gates, run_all(hard_scenarios, policy, reference, runtime), policy
    )


# --- command line -----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the evaluation gate on SYNTHETIC scenarios.")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--hard", type=Path, default=DEFAULT_HARD)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    try:
        scenarios = load_scenarios(args.scenarios)
        hard_scenarios = load_hard_scenarios(args.hard, scenarios)
        policy = load_policy()
        reference = load_reference()
    except (ScenarioError, PolicyError, ReferenceDataError) as exc:
        print(f"eval: cannot run: {exc}", file=sys.stderr)
        return 2
    runtime = ModelRuntime.from_path()
    if runtime.health().status != "ok":
        print(f"eval: the risk model is unavailable ({runtime.health().reason})", file=sys.stderr)
        return 2

    outcomes, gates = evaluate(scenarios, policy, reference, runtime)
    hard = run_all(hard_scenarios, policy, reference, runtime)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(outcomes, gates, policy, hard), encoding="utf-8")

    for gate in gates:
        print(f"{'PASS' if gate.passed else 'FAIL'}  {gate.name}: {gate.detail}")
    for o in outcomes:
        if not o.passed:
            expected = _expected_label(o.scenario)
            got = f"{o.response.decision} {o.codes}"
            print(f"MISMATCH  {o.scenario.id}: expected {expected}, got {got}")
    matching = sum(1 for o in hard if o.decision_ok)
    print(f"known limitations (non-gating): {matching}/{len(hard)} match the correct answer")
    print(f"report: {args.report}")
    return 0 if all(g.passed for g in gates) else 1


if __name__ == "__main__":
    sys.exit(main())
