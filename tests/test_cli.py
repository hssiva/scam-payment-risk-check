import io
import json
import logging
import tomllib
from collections.abc import Iterator
from pathlib import Path

import pytest

from scamcheck.audit import AUDIT_PATH_ENV, AuditLog
from scamcheck.cli import main
from scamcheck.evaluate import DEFAULT_SCENARIOS, load_scenarios
from scamcheck.model import MODEL_PATH_ENV

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = {s.id: s.request for s in load_scenarios(DEFAULT_SCENARIOS)}


@pytest.fixture(autouse=True)
def like_a_real_cli_process() -> Iterator[None]:
    """Importing scamcheck.api installs a JSON-to-stdout log handler for the whole test
    session; the real CLI does not import it, so detach it while these tests run."""
    logger = logging.getLogger("scamcheck")
    removed = [h for h in logger.handlers if type(h).__name__ == "_StdoutHandler"]
    for handler in removed:
        logger.removeHandler(handler)
    yield
    for handler in removed:
        logger.addHandler(handler)


@pytest.fixture(autouse=True)
def audit_in_tmp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "audit" / "decisions.jsonl"
    monkeypatch.setenv(AUDIT_PATH_ENV, str(path))
    return path


def write_request(tmp_path: Path, raw: object, name: str = "request.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(raw))
    return path


def test_the_scamcheck_entry_point_is_declared() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["scripts"]["scamcheck"] == "scamcheck.cli:main"


def test_assess_prints_the_decision_and_writes_the_audit_trail(
    tmp_path: Path, audit_in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["assess", "--file", str(write_request(tmp_path, SCENARIOS["G01"]))]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["decision"] == "ALLOW"
    assert body["request_id"] == "G01"
    assert AuditLog(audit_in_tmp).verify().records == 1


def test_assess_a_scam_is_held(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["assess", "--file", str(write_request(tmp_path, SCENARIOS["S01"]))]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "HOLD"


def test_assess_reads_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(SCENARIOS["G01"])))
    assert main(["assess", "--file", "-"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "ALLOW"


def test_assess_invalid_request_exits_1_and_is_audited(
    tmp_path: Path, audit_in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["assess", "--file", str(write_request(tmp_path, SCENARIOS["V01"]))]) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["decision"] == "REJECT"
    assert AuditLog(audit_in_tmp).read_recent(1)[0]["decision"] == "REJECT"


def test_assess_invalid_json_is_a_reject(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    assert main(["assess", "--file", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["reasons"][0]["code"] == "INVALID_REQUEST"


def test_assess_missing_file_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["assess", "--file", str(tmp_path / "nope.json")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_assess_holds_when_the_audit_trail_cannot_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    monkeypatch.setenv(AUDIT_PATH_ENV, str(blocker / "decisions.jsonl"))
    assert main(["assess", "--file", str(write_request(tmp_path, SCENARIOS["G01"]))]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["decision"] == "HOLD"
    assert body["reasons"][0]["code"] == "AUDIT_UNAVAILABLE"


def test_verify_audit_ok_and_tampered(
    tmp_path: Path, audit_in_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request_file = write_request(tmp_path, SCENARIOS["S01"])
    for _ in range(3):
        main(["assess", "--file", str(request_file)])
    capsys.readouterr()
    assert main(["verify-audit"]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 3

    rows = audit_in_tmp.read_text().splitlines()
    record = json.loads(rows[1])
    record["decision"] = "ALLOW"
    rows[1] = json.dumps(record)
    audit_in_tmp.write_text("\n".join(rows) + "\n")
    assert main(["verify-audit"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert (result["ok"], result["first_bad_line"]) == (False, 2)


def test_verify_audit_on_an_empty_trail_is_ok(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify-audit"]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 0


def test_health_ok(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["health"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "ok"
    assert body["model_version"] == "risk_model_v1"


def test_health_degraded_exits_1(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "gone.json"))
    assert main(["health"]) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["mode"] == "DEGRADED_RULES_ONLY"
    assert "MODEL_FILE_MISSING" in body["reasons"]


def test_eval_runs_the_gate_and_passes_options_through(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.md"
    assert main(["eval", "--report", str(report)]) == 0
    assert "Overall: **PASS**" in report.read_text()
    assert "PASS  6." in capsys.readouterr().out


def test_eval_exit_code_reports_cannot_run(tmp_path: Path) -> None:
    assert main(["eval", "--scenarios", str(tmp_path / "none.jsonl")]) == 2


def test_a_command_is_required() -> None:
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2


def test_unknown_options_are_rejected_for_the_other_commands() -> None:
    with pytest.raises(SystemExit) as info:
        main(["health", "--surprise"])
    assert info.value.code == 2
