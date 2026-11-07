import json
import multiprocessing
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from scamcheck.audit import (
    AUDIT_PATH_ENV,
    GENESIS_HASH,
    RECORD_FIELDS,
    AuditError,
    AuditLog,
    build_entry,
    canonical_json,
    compute_record_hash,
    default_audit_path,
    mask_account,
)
from scamcheck.schemas import Decision, DecisionResponse, Mode, Reason


def fcntl_missing() -> bool:
    try:
        import fcntl  # noqa: F401
    except ImportError:
        return True
    return False


def response(decision: Decision = Decision.ALLOW, decision_id: str = "d-1") -> DecisionResponse:
    return DecisionResponse(
        decision_id=decision_id,
        request_id="r-1",
        decision=decision,
        risk_score=0.25 if decision is not Decision.REJECT else None,
        reasons=[Reason(code="R_TEST", detail="fixed text")],
        mode=Mode.NORMAL,
        model_version="m-1",
        policy_version="p-1",
        latency_ms=1.5,
    )


def raw_request() -> dict[str, Any]:
    return {
        "request_id": "r-1",
        "customer_id": "cust-001",
        "amount": "250.50",
        "payee": {"name": "Example Payee Pty Ltd", "bsb": "000123", "account_number": "70001117"},
    }


def log_with(tmp_path: Path, n: int) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(n):
        log.append(build_entry(raw_request(), response(decision_id=f"d-{i}")))
    return log


def lines(log: AuditLog) -> list[str]:
    return log.path.read_text().splitlines()


def rewrite(log: AuditLog, new_lines: list[str]) -> None:
    log.path.write_text("\n".join(new_lines) + "\n")


# --- the chain ----------------------------------------------------------------------------


def test_records_have_exactly_the_specified_fields(tmp_path: Path) -> None:
    record = log_with(tmp_path, 1).read_recent(1)[0]
    assert set(record) == set(RECORD_FIELDS)


def test_chain_links_each_record_to_the_previous_one(tmp_path: Path) -> None:
    log = log_with(tmp_path, 3)
    first, second, third = (json.loads(x) for x in lines(log))
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["record_hash"]
    assert third["prev_hash"] == second["record_hash"]
    assert first["record_hash"] == compute_record_hash(first)


def test_record_hash_is_sha256_of_prev_hash_plus_canonical_json(tmp_path: Path) -> None:
    import hashlib

    record = json.loads(lines(log_with(tmp_path, 1))[0])
    body = {k: v for k, v in record.items() if k != "record_hash"}
    expected = hashlib.sha256((record["prev_hash"] + canonical_json(body)).encode()).hexdigest()
    assert record["record_hash"] == expected


def test_verify_accepts_an_intact_chain_and_an_empty_log(tmp_path: Path) -> None:
    result = log_with(tmp_path, 5).verify()
    assert (result.ok, result.records, result.first_bad_line) == (True, 5, None)
    assert AuditLog(tmp_path / "none.jsonl").verify().ok
    assert AuditLog(tmp_path / "none.jsonl").verify().records == 0


def test_verify_survives_a_restart(tmp_path: Path) -> None:
    log_with(tmp_path, 2)
    again = AuditLog(tmp_path / "audit.jsonl")  # new object, same file
    again.append(build_entry(raw_request(), response(decision_id="d-new")))
    assert again.verify().records == 3
    assert again.verify().ok


# --- tamper detection ---------------------------------------------------------------------


def test_editing_a_record_is_detected(tmp_path: Path) -> None:
    log = log_with(tmp_path, 4)
    rows = lines(log)
    edited = json.loads(rows[1])
    edited["decision"] = "ALLOW" if edited["decision"] != "ALLOW" else "HOLD"
    edited["customer_id"] = "cust-999"
    rows[1] = json.dumps(edited)
    rewrite(log, rows)
    result = log.verify()
    assert not result.ok
    assert result.first_bad_line == 2
    assert "edited" in result.message


def test_removing_a_middle_record_is_detected(tmp_path: Path) -> None:
    log = log_with(tmp_path, 4)
    rows = lines(log)
    del rows[1]
    rewrite(log, rows)
    result = log.verify()
    assert not result.ok
    assert result.first_bad_line == 2
    assert "prev_hash" in result.message


def test_inserting_a_forged_record_is_detected(tmp_path: Path) -> None:
    log = log_with(tmp_path, 3)
    rows = lines(log)
    forged = json.loads(rows[0])
    forged["decision_id"] = "forged"
    rows.insert(1, json.dumps(forged))
    rewrite(log, rows)
    assert not log.verify().ok


def test_reordering_records_is_detected(tmp_path: Path) -> None:
    log = log_with(tmp_path, 3)
    rows = lines(log)
    rows[1], rows[2] = rows[2], rows[1]
    rewrite(log, rows)
    assert not log.verify().ok


def test_removing_the_first_record_is_detected(tmp_path: Path) -> None:
    log = log_with(tmp_path, 3)
    rewrite(log, lines(log)[1:])
    result = log.verify()
    assert not result.ok
    assert result.first_bad_line == 1


@pytest.mark.parametrize(
    "bad_line", ["{not json", "[1, 2]", json.dumps({"decision_id": "x"}), '"text"']
)
def test_garbage_lines_are_detected(tmp_path: Path, bad_line: str) -> None:
    log = log_with(tmp_path, 2)
    rewrite(log, [*lines(log), bad_line])
    result = log.verify()
    assert not result.ok
    assert result.first_bad_line == 3


def test_an_extra_unhashed_field_is_detected(tmp_path: Path) -> None:
    log = log_with(tmp_path, 2)
    rows = lines(log)
    record = json.loads(rows[0])
    record["note"] = "added later"
    rows[0] = json.dumps(record)
    rewrite(log, rows)
    assert not log.verify().ok


# --- masking and privacy ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("70001117", "*****117"),
        ("123456", "***456"),
        ("123456789", "******789"),
        ("12345", None),  # too short to be a valid account number
        ("1234567890", None),
        ("12345a78", None),
        ("١٢٣٤٥٦٧٨", None),  # non-ASCII digits
        (70001117, None),
        (None, None),
    ],
)
def test_mask_account_keeps_only_the_last_three_digits(value: object, expected: str | None) -> None:
    assert mask_account(value) == expected


def test_entry_has_no_payee_name_or_full_account_number(tmp_path: Path) -> None:
    log = log_with(tmp_path, 1)
    text = log.path.read_text()
    assert "70001117" not in text
    assert "Example Payee" not in text
    assert "000123" not in text
    record = json.loads(text)
    assert record["payee_account_masked"] == "*****117"
    assert record["customer_id"] == "cust-001"


def test_rejected_requests_mask_only_valid_accounts() -> None:
    raw = {**raw_request(), "amount": "-5", "payee": {"account_number": "55555", "name": "N"}}
    entry = build_entry(raw, response(Decision.REJECT))
    assert entry["payee_account_masked"] is None
    assert entry["decision"] == "REJECT"


@pytest.mark.parametrize("raw", [None, [], "text", 5, {}, {"customer_id": 5}, {"payee": "x"}])
def test_build_entry_copes_with_any_input(raw: object) -> None:
    entry = build_entry(raw, response(Decision.REJECT))
    assert entry["customer_id"] is None
    assert entry["payee_account_masked"] is None
    assert len(entry["request_hash"]) == 64


def test_request_hash_identifies_the_request_without_storing_it() -> None:
    a = build_entry(raw_request(), response())
    b = build_entry(raw_request(), response(decision_id="other"))
    changed = build_entry({**raw_request(), "amount": "250.51"}, response())
    assert a["request_hash"] == b["request_hash"]
    assert a["request_hash"] != changed["request_hash"]
    assert "request" not in a


# --- writing failures, concurrency, reading ------------------------------------------------


def test_unwritable_location_raises_audit_error(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    with pytest.raises(AuditError):
        AuditLog(blocker / "audit.jsonl").append(build_entry(raw_request(), response()))


def test_directory_in_place_of_the_file_raises_audit_error(tmp_path: Path) -> None:
    (tmp_path / "audit.jsonl").mkdir()
    with pytest.raises(AuditError):
        AuditLog(tmp_path / "audit.jsonl").append(build_entry(raw_request(), response()))


def test_an_incomplete_last_record_makes_append_refuse(tmp_path: Path) -> None:
    log = log_with(tmp_path, 2)
    with log.path.open("a") as handle:
        handle.write('{"decision_id": "torn')  # simulated crash mid-write
    with pytest.raises(AuditError):
        log.append(build_entry(raw_request(), response()))
    assert not log.verify().ok


def test_a_corrupt_last_record_makes_append_refuse(tmp_path: Path) -> None:
    log = log_with(tmp_path, 1)
    with log.path.open("a") as handle:
        handle.write("not json at all\n")
    with pytest.raises(AuditError):
        log.append(build_entry(raw_request(), response()))


def _append_from_another_process(args: tuple[str, int, int]) -> int:
    path, worker, count = args
    log = AuditLog(path)
    for i in range(count):
        log.append(build_entry(raw_request(), response(decision_id=f"p{worker}-{i}")))
    return count


@pytest.mark.skipif(fcntl_missing(), reason="needs POSIX file locking")
def test_several_processes_on_one_host_keep_the_chain_valid(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    jobs = [(str(path), worker, 25) for worker in range(4)]
    with multiprocessing.get_context("spawn").Pool(4) as pool:
        assert sum(pool.map(_append_from_another_process, jobs)) == 100
    result = AuditLog(path).verify()
    assert (result.ok, result.records) == (True, 100)
    assert len({json.loads(x)["decision_id"] for x in path.read_text().splitlines()}) == 100


def test_concurrent_appends_keep_the_chain_valid(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")

    def write(i: int) -> None:
        log.append(build_entry(raw_request(), response(decision_id=f"d-{i}")))

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(write, range(200)))
    result = AuditLog(log.path).verify()
    assert (result.ok, result.records) == (True, 200)
    ids = {json.loads(x)["decision_id"] for x in lines(log)}
    assert len(ids) == 200


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_audit_file_is_private_to_the_owner(tmp_path: Path) -> None:
    log = log_with(tmp_path, 1)
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600


def test_read_recent_returns_newest_first_and_caps_the_limit(tmp_path: Path) -> None:
    log = log_with(tmp_path, 130)
    recent = log.read_recent(5)
    assert [r["decision_id"] for r in recent] == ["d-129", "d-128", "d-127", "d-126", "d-125"]
    assert len(log.read_recent(1000)) == 100
    assert len(log.read_recent(0)) == 1
    assert AuditLog(tmp_path / "none.jsonl").read_recent(10) == []


def test_read_recent_raises_on_unparseable_data(tmp_path: Path) -> None:
    log = log_with(tmp_path, 1)
    with log.path.open("a") as handle:
        handle.write("garbage\n")
    with pytest.raises(AuditError):
        log.read_recent(5)


def test_writable_probe(tmp_path: Path) -> None:
    assert AuditLog(tmp_path / "new-dir" / "audit.jsonl").writable()
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    assert not AuditLog(blocker / "audit.jsonl").writable()
    assert not (tmp_path / "new-dir").exists()  # the probe creates nothing


def test_default_path_and_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(AUDIT_PATH_ENV, raising=False)
    assert default_audit_path() == Path("audit/decisions.jsonl")
    monkeypatch.setenv(AUDIT_PATH_ENV, str(tmp_path / "x.jsonl"))
    assert AuditLog().path == tmp_path / "x.jsonl"


@pytest.mark.parametrize("amount", ["250.50", "0.01", "999999.99", 4800, 12.5, "-5", "abc", None])
def test_the_amount_is_never_recorded(tmp_path: Path, amount: object) -> None:
    assert "amount" not in RECORD_FIELDS
    log = AuditLog(tmp_path / "audit.jsonl")
    entry = build_entry({**raw_request(), "amount": amount}, response())
    assert "amount" not in entry
    log.append(entry)
    text = log.path.read_text()
    assert '"amount"' not in text
    if isinstance(amount, str) and amount.replace(".", "").isdigit():
        assert amount not in text
