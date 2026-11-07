import json
import logging
from pathlib import Path
from typing import Any

import pytest

from scamcheck import engine
from scamcheck.audit import AUDIT_PATH_ENV, AuditError, AuditLog
from scamcheck.evaluate import DEFAULT_SCENARIOS, load_scenarios
from scamcheck.schemas import Decision, Mode

SCENARIOS = {s.id: s.request for s in load_scenarios(DEFAULT_SCENARIOS)}
GENUINE = SCENARIOS["G01"]  # clean ALLOW
SCAM = SCENARIOS["S01"]  # HOLD
INVALID = SCENARIOS["V01"]  # REJECT


def codes(response: Any) -> list[str]:
    return [r.code for r in response.reasons]


def test_every_request_including_rejects_is_recorded(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "a.jsonl")
    decisions = [engine.assess_and_record(raw, audit).decision for raw in (GENUINE, SCAM, INVALID)]
    assert decisions == [Decision.ALLOW, Decision.HOLD, Decision.REJECT]
    recorded = [r["decision"] for r in reversed(audit.read_recent(10))]
    assert recorded == ["ALLOW", "HOLD", "REJECT"]
    assert audit.verify().ok


def test_audited_decision_matches_the_pure_decision(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "a.jsonl")
    plain = engine.assess(SCAM)
    audited = engine.assess_and_record(SCAM, audit)
    assert (audited.decision, audited.reasons, audited.risk_score) == (
        plain.decision,
        plain.reasons,
        plain.risk_score,
    )
    record = audit.read_recent(1)[0]
    assert record["decision_id"] == audited.decision_id
    assert record["risk_score"] == audited.risk_score
    assert record["policy_version"] == audited.policy_version


def test_the_pure_assess_does_not_touch_the_audit_trail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(AUDIT_PATH_ENV, str(tmp_path / "should-not-exist.jsonl"))
    engine.assess(GENUINE)
    assert not (tmp_path / "should-not-exist.jsonl").exists()


@pytest.mark.parametrize("raw", [GENUINE, SCAM, INVALID, None, "garbage"])
def test_audit_failure_fails_closed_with_hold(tmp_path: Path, raw: Any) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    response = engine.assess_and_record(raw, AuditLog(blocker / "audit.jsonl"))
    assert response.decision is Decision.HOLD
    assert codes(response)[0] == "AUDIT_UNAVAILABLE"


def test_audit_failure_keeps_the_original_context(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    plain = engine.assess(GENUINE)
    held = engine.assess_and_record(GENUINE, AuditLog(blocker / "audit.jsonl"))
    assert held.decision is Decision.HOLD  # a clean ALLOW is no longer released
    assert codes(held) == ["AUDIT_UNAVAILABLE", *codes(plain)]
    assert held.request_id == "G01"
    assert held.mode is Mode.NORMAL
    assert held.risk_score == plain.risk_score
    assert held.model_version == plain.model_version


def test_rejected_input_also_becomes_hold_when_the_audit_is_down(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    response = engine.assess_and_record(INVALID, AuditLog(blocker / "audit.jsonl"))
    assert response.decision is Decision.HOLD
    assert codes(response) == ["AUDIT_UNAVAILABLE", "AMOUNT_NOT_POSITIVE"]


@pytest.mark.parametrize("error", [AuditError("x"), OSError("disk full"), RuntimeError("boom")])
def test_any_exception_from_the_audit_means_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def fail(self: AuditLog, entry: dict[str, Any]) -> None:
        raise error

    monkeypatch.setattr(AuditLog, "append", fail)
    response = engine.assess_and_record(GENUINE, AuditLog(tmp_path / "a.jsonl"))
    assert response.decision is Decision.HOLD
    assert codes(response)[0] == "AUDIT_UNAVAILABLE"


def test_a_damaged_audit_tail_blocks_decisions_until_fixed(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "a.jsonl")
    engine.assess_and_record(GENUINE, audit)
    with audit.path.open("a") as handle:
        handle.write('{"torn')
    response = engine.assess_and_record(GENUINE, audit)
    assert response.decision is Decision.HOLD
    assert codes(response)[0] == "AUDIT_UNAVAILABLE"


def test_nothing_is_recorded_when_the_write_fails(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    engine.assess_and_record(GENUINE, AuditLog(blocker / "audit.jsonl"))
    assert blocker.read_text() == "x"


def test_failure_log_names_the_error_type_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fail(self: AuditLog, entry: dict[str, Any]) -> None:
        raise RuntimeError("secret 70001117 detail")

    monkeypatch.setattr(AuditLog, "append", fail)
    with caplog.at_level(logging.ERROR, logger="scamcheck.engine"):
        engine.assess_and_record(GENUINE, AuditLog(tmp_path / "a.jsonl"))
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "RuntimeError" in text
    assert "70001117" not in text
    assert "secret" not in text


def test_records_written_by_the_engine_contain_no_names_or_full_accounts(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "a.jsonl")
    engine.assess_and_record(SCAM, audit)
    text = audit.path.read_text()
    payee = SCAM["payee"]
    assert payee["account_number"] not in text
    assert payee["name"] not in text
    assert SCAM["amount"] not in text
    assert '"amount"' not in text
    assert json.loads(text)["payee_account_masked"].endswith(payee["account_number"][-3:])
