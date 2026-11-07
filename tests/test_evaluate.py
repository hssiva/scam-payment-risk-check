import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import pytest

from scamcheck import evaluate as ev
from scamcheck.evaluate import (
    DEFAULT_HARD,
    DEFAULT_SCENARIOS,
    Fingerprint,
    Outcome,
    Scenario,
    ScenarioError,
    evaluate,
    gate_determinism,
    gate_genuine_friction,
    gate_must_hold,
    gate_reasons,
    gate_scam_catch,
    gate_tampered_model,
    inputs_fingerprint,
    load_hard_scenarios,
    load_scenarios,
    main,
    render_report,
    tampered_runtime,
)
from scamcheck.model import ModelRuntime, default_model_path
from scamcheck.policy import load_policy
from scamcheck.reference import load_reference
from scamcheck.schemas import Decision, DecisionResponse, Mode, Reason

POLICY = load_policy()
REFERENCE = load_reference()
REQUIRED_TYPOLOGIES = {
    "impersonation",
    "remote_access",
    "mule_payee",
    "investment",
    "invoice_redirection",
    "romance",
    "genuine_rent",
    "genuine_house_deposit",
    "genuine_small_new_payee",
    "missing_data",
    "invalid_request",
}


def scenario(
    sid: str = "X1",
    expected: Any = "HOLD",
    *,
    must_hold: bool = False,
    is_scam: bool | None = True,
    codes: list[str] | None = None,
    request: Any = None,
) -> Scenario:
    return Scenario.model_validate(
        {
            "id": sid,
            "typology": "test",
            "description": "test scenario",
            "request": request or {},
            "expected_decision": expected,
            "must_hold": must_hold,
            "is_scam": is_scam,
            "expected_codes": codes or [],
        }
    )


def response(decision: Decision, codes: list[str] | None = None) -> DecisionResponse:
    reasons = [Reason(code=c, detail="d") for c in (codes or ["R_TEST"])]
    return DecisionResponse(
        decision_id="d",
        request_id="r",
        decision=decision,
        risk_score=0.5,
        reasons=reasons,
        mode=Mode.NORMAL,
        model_version="m",
        policy_version="p",
        latency_ms=1.0,
    )


def outcome(decision: Decision, **kwargs: Any) -> Outcome:
    codes = kwargs.pop("response_codes", None)
    return Outcome(scenario(**kwargs), response(decision, codes))


def write_lines(path: Path, rows: list[Any]) -> Path:
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows))
    return path


# --- scenario file ------------------------------------------------------------------------


def test_committed_scenarios_cover_the_required_typologies() -> None:
    scenarios = load_scenarios(DEFAULT_SCENARIOS)
    assert 30 <= len(scenarios) <= 40
    assert REQUIRED_TYPOLOGIES <= {s.typology for s in scenarios}
    assert len({s.id for s in scenarios}) == len(scenarios)


def test_committed_scenarios_have_both_scams_and_genuine_and_must_holds() -> None:
    scenarios = load_scenarios(DEFAULT_SCENARIOS)
    assert sum(s.is_scam is True for s in scenarios) >= 10
    assert sum(s.is_scam is False for s in scenarios) >= 10
    assert sum(s.must_hold for s in scenarios) >= 5
    assert any(s.expected_decision == Decision.REJECT for s in scenarios)
    assert all(s.allowed == {Decision.HOLD} for s in scenarios if s.must_hold)


def test_committed_scenarios_are_synthetic_and_use_only_000_bsbs() -> None:
    text = DEFAULT_SCENARIOS.read_text()
    bsbs = set(re.findall(r'"bsb": "(\d+)"', text))
    assert bsbs
    assert all(b.startswith("000") or len(b) != 6 for b in bsbs)  # bad-length BSB is a REJECT case


def test_loader_accepts_blank_and_comment_lines(tmp_path: Path) -> None:
    row = scenario().model_dump(mode="json")
    path = write_lines(tmp_path / "s.jsonl", ["", "# a comment", row])
    assert [s.id for s in load_scenarios(path)] == ["X1"]


def test_allowed_set_accepts_a_single_decision_or_a_list() -> None:
    assert scenario(expected="WARN").allowed == {Decision.WARN}
    assert scenario(expected=["WARN", "HOLD"]).allowed == {Decision.WARN, Decision.HOLD}


@pytest.mark.parametrize(
    "rows",
    [
        ["{not json"],
        [{"id": "A"}],  # missing fields
        [{**scenario().model_dump(mode="json"), "surprise": 1}],  # unknown field
        [{**scenario().model_dump(mode="json"), "expected_decision": "APPROVE"}],
        [{**scenario().model_dump(mode="json"), "expected_decision": []}],
        [{**scenario().model_dump(mode="json"), "must_hold": True, "expected_decision": "WARN"}],
        [scenario("A").model_dump(mode="json"), scenario("A").model_dump(mode="json")],
        [],
    ],
)
def test_invalid_scenario_files_are_rejected(tmp_path: Path, rows: list[Any]) -> None:
    with pytest.raises(ScenarioError):
        load_scenarios(write_lines(tmp_path / "s.jsonl", rows))


def test_missing_scenario_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ScenarioError):
        load_scenarios(tmp_path / "none.jsonl")


# --- outcomes and gates -------------------------------------------------------------------


def test_outcome_checks_decision_and_expected_codes() -> None:
    ok = outcome(Decision.HOLD, expected="HOLD", codes=["R_TEST"])
    assert ok.passed
    assert not outcome(Decision.WARN, expected="HOLD").passed
    wrong_code = outcome(Decision.HOLD, expected="HOLD", codes=["R_OTHER"])
    assert wrong_code.decision_ok
    assert not wrong_code.codes_ok
    assert not wrong_code.passed


def test_gate_must_hold() -> None:
    held = outcome(Decision.HOLD, must_hold=True)
    assert gate_must_hold([held, held]).passed
    missed = outcome(Decision.WARN, sid="M9", expected="HOLD", must_hold=True)
    result = gate_must_hold([held, missed])
    assert not result.passed
    assert "M9" in result.detail
    assert not gate_must_hold([outcome(Decision.HOLD)]).passed  # no must-hold scenarios at all


def scam_batch(caught: int, total: int) -> list[Outcome]:
    return [
        outcome(
            Decision.WARN if i < caught else Decision.ALLOW,
            sid=f"S{i}",
            expected=["WARN", "HOLD"],
            is_scam=True,
        )
        for i in range(total)
    ]


def test_gate_scam_catch_threshold_is_inclusive() -> None:
    assert gate_scam_catch(scam_batch(9, 10), 0.9).passed
    result = gate_scam_catch(scam_batch(8, 10), 0.9)
    assert not result.passed
    assert "S8" in result.detail
    assert gate_scam_catch(scam_batch(10, 10), 0.9).passed


def test_gate_scam_catch_ignores_unlabelled_and_needs_scams() -> None:
    unlabelled = outcome(Decision.ALLOW, expected="ALLOW", is_scam=None)
    assert gate_scam_catch([*scam_batch(10, 10), unlabelled], 0.9).passed
    assert not gate_scam_catch([unlabelled], 0.9).passed


def genuine_batch(held: int, total: int) -> list[Outcome]:
    return [
        outcome(
            Decision.HOLD if i < held else Decision.ALLOW,
            sid=f"G{i}",
            expected=["ALLOW", "WARN"],
            is_scam=False,
        )
        for i in range(total)
    ]


def test_gate_genuine_friction_threshold_is_inclusive() -> None:
    assert gate_genuine_friction(genuine_batch(1, 10), 0.1).passed
    result = gate_genuine_friction(genuine_batch(2, 10), 0.1)
    assert not result.passed
    assert "G0" in result.detail
    assert gate_genuine_friction(genuine_batch(0, 10), 0.1).passed


def test_gate_genuine_friction_ignores_unlabelled_and_needs_genuine() -> None:
    unlabelled = outcome(Decision.HOLD, is_scam=None)
    assert gate_genuine_friction([*genuine_batch(0, 5), unlabelled], 0.1).passed
    assert not gate_genuine_friction([unlabelled], 0.1).passed


def test_gate_reasons_flags_missing_reasons_but_not_rejects() -> None:
    good = outcome(Decision.ALLOW, expected="ALLOW")
    assert gate_reasons([good]).passed
    bare = Outcome(
        scenario("B1", "ALLOW"), response(Decision.ALLOW).model_copy(update={"reasons": []})
    )
    result = gate_reasons([good, bare])
    assert not result.passed
    assert "B1" in result.detail
    reject_without = Outcome(
        scenario("R1", "REJECT"), response(Decision.REJECT).model_copy(update={"reasons": []})
    )
    assert gate_reasons([reject_without]).passed  # REJECT is outside this gate


def test_gate_determinism() -> None:
    a = [outcome(Decision.HOLD, sid="A"), outcome(Decision.WARN, sid="B")]
    assert gate_determinism(a, list(a)).passed
    changed = [a[0], outcome(Decision.ALLOW, sid="B")]
    result = gate_determinism(a, changed)
    assert not result.passed
    assert "B" in result.detail
    rescored = Outcome(a[0].scenario, a[0].response.model_copy(update={"risk_score": 0.51}))
    assert not gate_determinism([a[0]], [rescored]).passed


# --- real engine --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def committed() -> list[Scenario]:
    return load_scenarios(DEFAULT_SCENARIOS)


def test_all_gates_run_on_the_committed_scenarios(committed: list[Scenario]) -> None:
    outcomes, gates = evaluate(committed, POLICY, REFERENCE, ModelRuntime.from_path())
    assert len(outcomes) == len(committed)
    assert len(gates) == 6
    assert [g.name[0] for g in gates] == list("123456")


def test_tampered_gate_detects_tamper_and_holds_must_hold(committed: list[Scenario]) -> None:
    result = gate_tampered_model(committed, POLICY, REFERENCE)
    assert result.passed, result.detail
    assert "MODEL_INTEGRITY_FAILED" in result.detail
    assert "DEGRADED_RULES_ONLY" in result.detail


def test_tampered_gate_fails_if_tampering_is_not_detected(
    committed: list[Scenario], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ev, "tampered_runtime", lambda: (ModelRuntime.from_path(), []))
    result = gate_tampered_model(committed, POLICY, REFERENCE)
    assert not result.passed
    assert "NOT detected" in result.detail


def test_tampering_uses_a_copy_and_never_touches_the_real_artifact() -> None:
    path = default_model_path()
    sidecar = path.with_name(path.stem + ".sha256")
    before = (hashlib.sha256(path.read_bytes()), sidecar.read_bytes())
    logger = logging.getLogger("scamcheck.model")
    handlers = list(logger.handlers)
    runtime, records = tampered_runtime()
    assert runtime.health().reason == "MODEL_INTEGRITY_FAILED"
    assert len([r for r in records if r.levelno >= logging.WARNING]) == 1
    assert hashlib.sha256(path.read_bytes()).digest() == before[0].digest()
    assert sidecar.read_bytes() == before[1]
    assert logger.handlers == handlers  # the capture handler was removed


# --- report and command line --------------------------------------------------------------


def test_report_is_deterministic_and_complete(committed: list[Scenario]) -> None:
    runtime = ModelRuntime.from_path()
    out1, gates1 = evaluate(committed, POLICY, REFERENCE, runtime)
    out2, gates2 = evaluate(committed, POLICY, REFERENCE, runtime)
    report = render_report(out1, gates1, POLICY)
    assert report == render_report(out2, gates2, POLICY)
    for s in committed:
        assert f"| {s.id} |" in report
    for gate in gates1:
        assert gate.name in report
    assert "## Gate results" in report
    assert "## Summary metrics" in report
    assert not re.search(r"\d{6,}", report)  # no account numbers or long identifiers


def test_main_passes_on_committed_scenarios_and_writes_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.md"
    assert main(["--report", str(report)]) == 0
    assert "Overall: **PASS**" in report.read_text()
    assert "FAIL  " not in capsys.readouterr().out


def failing_scenarios(tmp_path: Path) -> Path:
    """Committed scenarios, but a clean genuine payment is (wrongly) labelled must-hold."""
    rows = [json.loads(line) for line in DEFAULT_SCENARIOS.read_text().splitlines()]
    for row in rows:
        if row["id"] == "G01":
            row["must_hold"] = True
            row["expected_decision"] = "HOLD"
    return write_lines(tmp_path / "failing.jsonl", rows)


def test_main_exits_non_zero_and_reports_when_a_gate_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.md"
    code = main(["--scenarios", str(failing_scenarios(tmp_path)), "--report", str(report)])
    out = capsys.readouterr().out
    assert code == 1
    assert "FAIL  1. All must-hold scenarios are HOLD" in out
    assert "G01" in out
    text = report.read_text()
    assert "Overall: **FAIL**" in text
    assert "| 1. All must-hold scenarios are HOLD | FAIL |" in text


def test_main_exits_non_zero_when_too_many_genuine_payments_are_held(tmp_path: Path) -> None:
    rows = [json.loads(line) for line in DEFAULT_SCENARIOS.read_text().splitlines()]
    scams = [r for r in rows if r["is_scam"] is True]
    for row in scams[:3]:  # relabel three held scams as genuine: friction budget blown
        row["is_scam"] = False
    path = write_lines(tmp_path / "friction.jsonl", rows)
    assert main(["--scenarios", str(path), "--report", str(tmp_path / "r.md")]) == 1


def test_main_cannot_run_without_scenarios(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--scenarios", str(tmp_path / "none.jsonl"), "--report", str(tmp_path / "r.md")])
    assert code == 2
    assert "cannot run" in capsys.readouterr().err
    assert not (tmp_path / "r.md").exists()


def test_main_cannot_run_when_the_model_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SCAMCHECK_MODEL_PATH", str(tmp_path / "gone.json"))
    assert main(["--report", str(tmp_path / "r.md")]) == 2
    assert "model is unavailable" in capsys.readouterr().err


# --- known-limitation (non-gating) scenarios ----------------------------------------------


def test_committed_hard_scenarios_load_and_never_clash_with_gated_ids() -> None:
    gated = load_scenarios(DEFAULT_SCENARIOS)
    hard = load_hard_scenarios(DEFAULT_HARD, gated)
    assert {"X01", "X02", "X03", "X04", "X05", "X06"} <= {s.id for s in hard}
    assert not any(s.must_hold for s in hard)
    assert any(s.is_scam is True for s in hard)
    assert any(s.is_scam is False for s in hard)


def test_hard_scenarios_cannot_be_must_hold_or_reuse_gated_ids(tmp_path: Path) -> None:
    gated = load_scenarios(DEFAULT_SCENARIOS)
    must = write_lines(
        tmp_path / "a.jsonl", [scenario("H1", "HOLD", must_hold=True).model_dump(mode="json")]
    )
    with pytest.raises(ScenarioError):
        load_hard_scenarios(must, gated)
    clash = write_lines(
        tmp_path / "b.jsonl", [scenario(gated[0].id, "WARN").model_dump(mode="json")]
    )
    with pytest.raises(ScenarioError):
        load_hard_scenarios(clash, gated)


def hard_file_the_system_gets_wrong(tmp_path: Path) -> Path:
    rows = [json.loads(line) for line in DEFAULT_HARD.read_text().splitlines()]
    x01 = next(r for r in rows if r["id"] == "X01")  # a scam the system ALLOWs
    return write_lines(tmp_path / "hard.jsonl", [{**x01, "id": "Z1"}])


def test_wrong_answers_in_the_hard_file_never_affect_the_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "r.md"
    hard = hard_file_the_system_gets_wrong(tmp_path)
    assert main(["--hard", str(hard), "--report", str(report)]) == 0
    text = report.read_text()
    assert "## Known limitations (non-gating)" in text
    assert "**0 of 1 match the correct answer.**" in text
    assert "Overall: **PASS**" in text
    assert "known limitations (non-gating): 0/1" in capsys.readouterr().out


def test_hard_scenarios_are_not_counted_in_the_gates(committed: list[Scenario]) -> None:
    _, gates = evaluate(committed, POLICY, REFERENCE, ModelRuntime.from_path())
    assert "X0" not in " ".join(g.detail for g in gates)


def test_report_has_a_known_limitations_section_only_when_given_hard_outcomes(
    committed: list[Scenario],
) -> None:
    runtime = ModelRuntime.from_path()
    outcomes, gates = evaluate(committed, POLICY, REFERENCE, runtime)
    hard = ev.run_all(load_hard_scenarios(DEFAULT_HARD, committed), POLICY, REFERENCE, runtime)
    assert "Known limitations" not in render_report(outcomes, gates, POLICY)
    with_hard = render_report(outcomes, gates, POLICY, hard)
    assert "Known limitations (non-gating)" in with_hard
    for s in hard:
        assert f"| {s.scenario.id} |" in with_hard
    assert not re.search(r"\d{6,}", with_hard)


def test_main_cannot_run_with_a_missing_or_invalid_hard_file(tmp_path: Path) -> None:
    report = tmp_path / "r.md"
    assert main(["--hard", str(tmp_path / "none.jsonl"), "--report", str(report)]) == 2
    bad = write_lines(tmp_path / "bad.jsonl", ["{not json"])
    assert main(["--hard", str(bad), "--report", str(report)]) == 2


# --- inputs fingerprint ---------------------------------------------------------------------------


def make_tree(root: Path) -> tuple[Path, Path]:
    """A tiny stand-in for the repository: the fingerprinted folders plus two scenario files."""
    for rel, text in {
        "src/pkg/a.py": "print('a')\n",
        "src/pkg/b.py": "print('b')\n",
        "config/policy.toml": "x = 1\n",
        "models/m.json": "{}\n",
        "sample-data/reference/c.json": "[]\n",
    }.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    scenarios = root / "sample-data" / "scenarios.jsonl"
    hard = root / "sample-data" / "scenarios_hard.jsonl"
    scenarios.write_text("one\n")
    hard.write_text("two\n")
    return scenarios, hard


def digest(root: Path, scenarios: Path, hard: Path) -> str:
    return inputs_fingerprint(root, (scenarios, hard)).digest


def test_fingerprint_of_the_real_repository_is_stable_and_well_formed() -> None:
    first, second = inputs_fingerprint(), inputs_fingerprint()
    assert first == second
    assert re.fullmatch(r"[0-9a-f]{64}", first.digest)
    assert len(first.short) == 16
    assert first.digest.startswith(first.short)
    assert first.files >= 20


@pytest.mark.parametrize(
    "change",
    [
        lambda r: (r / "src/pkg/a.py").write_text("print('changed')\n"),
        lambda r: (r / "config/policy.toml").write_text("x = 2\n"),
        lambda r: (r / "models/m.json").write_text('{"a": 1}\n'),
        lambda r: (r / "sample-data/reference/c.json").write_text("[1]\n"),
        lambda r: (r / "src/pkg/new.py").write_text("x\n"),  # a file added
        lambda r: (r / "src/pkg/b.py").unlink(),  # a file removed
        lambda r: (r / "src/pkg/b.py").rename(r / "src/pkg/renamed.py"),  # same bytes, new name
        lambda r: (r / "src/pkg/a.py").write_text((r / "src/pkg/b.py").read_text()),
    ],
    ids=[
        "src edit",
        "config edit",
        "model edit",
        "reference edit",
        "file added",
        "file removed",
        "file renamed",
        "content moved between files",
    ],
)
def test_fingerprint_changes_when_any_input_changes(tmp_path: Path, change: Any) -> None:
    scenarios, hard = make_tree(tmp_path)
    before = digest(tmp_path, scenarios, hard)
    change(tmp_path)
    assert digest(tmp_path, scenarios, hard) != before


def test_fingerprint_changes_when_a_scenario_file_changes(tmp_path: Path) -> None:
    scenarios, hard = make_tree(tmp_path)
    before = digest(tmp_path, scenarios, hard)
    hard.write_text("two, edited\n")
    assert digest(tmp_path, scenarios, hard) != before
    scenarios.write_text("one, edited\n")
    assert digest(tmp_path, scenarios, hard) != before


def test_fingerprint_ignores_caches_editor_files_and_other_folders(tmp_path: Path) -> None:
    scenarios, hard = make_tree(tmp_path)
    before = digest(tmp_path, scenarios, hard)
    for rel in (
        "src/pkg/__pycache__/a.cpython-312.pyc",
        "src/pkg/stray.pyc",
        "src/scamcheck.egg-info/PKG-INFO",
        "src/.DS_Store",
        "models/.DS_Store",
        "tests/test_x.py",
        "evidence/design.md",
        "README.md",
        "scripts/tool.py",
        "audit/decisions.jsonl",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("noise")
    assert digest(tmp_path, scenarios, hard) == before


def test_fingerprint_does_not_depend_on_file_times(tmp_path: Path) -> None:
    scenarios, hard = make_tree(tmp_path)
    before = digest(tmp_path, scenarios, hard)
    os.utime(tmp_path / "src/pkg/a.py", (1, 1))
    os.utime(scenarios, (2, 2))
    assert digest(tmp_path, scenarios, hard) == before


def test_fingerprint_is_the_same_for_an_identical_copy_in_another_place(tmp_path: Path) -> None:
    first, second = tmp_path / "one", tmp_path / "two"
    first.mkdir()
    second.mkdir()
    scenarios_a, hard_a = make_tree(first)
    scenarios_b, hard_b = make_tree(second)
    assert digest(first, scenarios_a, hard_a) == digest(second, scenarios_b, hard_b)


def test_a_scenario_file_outside_the_repository_is_included_under_its_name(tmp_path: Path) -> None:
    scenarios, hard = make_tree(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-custom.jsonl"
    outside.write_text("custom\n")
    default = digest(tmp_path, scenarios, hard)
    custom = inputs_fingerprint(tmp_path, (outside, hard))
    assert custom.digest != default
    outside.write_text("custom, edited\n")
    assert inputs_fingerprint(tmp_path, (outside, hard)).digest != custom.digest


def test_fingerprint_counts_the_files_it_hashed(tmp_path: Path) -> None:
    scenarios, hard = make_tree(tmp_path)
    assert inputs_fingerprint(tmp_path, (scenarios, hard)).files == 7


def test_report_shows_the_fingerprint_only_when_given_one(committed: list[Scenario]) -> None:
    runtime = ModelRuntime.from_path()
    outcomes, gates = evaluate(committed, POLICY, REFERENCE, runtime)
    assert "Inputs fingerprint" not in render_report(outcomes, gates, POLICY)
    fingerprint = Fingerprint("ab" * 32, 26)
    report = render_report(outcomes, gates, POLICY, None, fingerprint)
    assert "- Inputs fingerprint: `abababababababab` (SHA-256 over 26 files" in report
    assert report == render_report(outcomes, gates, POLICY, None, fingerprint)  # deterministic


def test_main_writes_the_fingerprint_of_the_current_inputs(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    assert main(["--report", str(report)]) == 0
    assert f"Inputs fingerprint: `{inputs_fingerprint().short}`" in report.read_text()


def test_main_fingerprints_the_scenario_file_it_was_given(tmp_path: Path) -> None:
    rows = DEFAULT_SCENARIOS.read_text().splitlines()
    custom = write_lines(tmp_path / "custom.jsonl", [json.loads(r) for r in rows])
    default_report, custom_report = tmp_path / "a.md", tmp_path / "b.md"
    main(["--report", str(default_report)])
    main(["--scenarios", str(custom), "--report", str(custom_report)])

    def line(path: Path) -> str:
        return next(x for x in path.read_text().splitlines() if "Inputs fingerprint" in x)

    assert line(default_report) != line(custom_report)  # same content, different file name
