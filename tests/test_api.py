import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from scamcheck.api import DEMO_MODE_ENV, JsonFormatter, create_app
from scamcheck.audit import RECORD_FIELDS, AuditLog
from scamcheck.evaluate import DEFAULT_SCENARIOS, load_scenarios
from scamcheck.model import MODEL_PATH_ENV

SCENARIOS = {s.id: s.request for s in load_scenarios(DEFAULT_SCENARIOS)}
GENUINE = SCENARIOS["G01"]
SCAM = SCENARIOS["S01"]
RESPONSE_FIELDS = {
    "decision_id",
    "request_id",
    "decision",
    "risk_score",
    "reasons",
    "mode",
    "model_version",
    "policy_version",
    "latency_ms",
}


def make_client(tmp_path: Path, **kwargs: Any) -> TestClient:
    kwargs.setdefault("demo_mode", False)
    return TestClient(create_app(audit_path=tmp_path / "audit.jsonl", **kwargs))


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return make_client(tmp_path)


@pytest.fixture
def demo_client(tmp_path: Path) -> TestClient:
    return make_client(tmp_path, demo_mode=True)


def audit_path(client: TestClient) -> Path:
    return client.app.state.scamcheck.audit.path  # type: ignore[no-any-return,attr-defined]


# --- assess -------------------------------------------------------------------------------


def test_genuine_payment_is_allowed(client: TestClient) -> None:
    response = client.post("/v1/assess", json=GENUINE)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == RESPONSE_FIELDS
    assert body["decision"] == "ALLOW"
    assert body["request_id"] == "G01"
    assert body["mode"] == "NORMAL"
    assert body["model_version"] == "risk_model_v1"
    assert isinstance(body["risk_score"], float)
    assert len(body["reasons"]) >= 1


def test_scam_payment_is_held_with_reasons(client: TestClient) -> None:
    response = client.post("/v1/assess", json=SCAM)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "HOLD"
    assert "R03_ON_CALL_NEW_PAYEE_HIGH_VALUE" in [r["code"] for r in body["reasons"]]


def test_invalid_request_returns_422_with_a_reject_body(client: TestClient) -> None:
    response = client.post("/v1/assess", json=SCENARIOS["V02"])
    assert response.status_code == 422
    body = response.json()
    assert set(body) == RESPONSE_FIELDS
    assert body["decision"] == "REJECT"
    assert body["risk_score"] is None
    assert [r["code"] for r in body["reasons"]] == ["INVALID_BSB"]


@pytest.mark.parametrize(
    "content",
    [b"{not json", b"", b"[1, 2, 3]", b'"just text"', b"null", b"x" * 70_000],
)
def test_unparseable_bodies_are_rejected_not_errors(client: TestClient, content: bytes) -> None:
    response = client.post("/v1/assess", content=content)
    assert response.status_code == 422
    assert response.json()["decision"] == "REJECT"
    assert response.json()["reasons"][0]["code"] == "INVALID_REQUEST"


def test_rejected_requests_are_audited_too(client: TestClient) -> None:
    client.post("/v1/assess", json=SCENARIOS["V01"])
    records = client.get("/v1/audit").json()["records"]
    assert [r["decision"] for r in records] == ["REJECT"]


# --- health -------------------------------------------------------------------------------


def test_health_when_everything_works(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body == {
        "status": "ok",
        "mode": "NORMAL",
        "model_version": "risk_model_v1",
        "policy_version": "2026.11.1",
        "reasons": [],
        "demo_mode": False,
        "demo_model_failure": False,
    }


def test_health_reports_degraded_mode_when_the_model_is_unavailable(tmp_path: Path) -> None:
    client = make_client(tmp_path, model_path=tmp_path / "missing-model.json")
    response = client.get("/health")
    assert response.status_code == 200  # still serving decisions
    body = response.json()
    assert body["status"] == "degraded"
    assert body["mode"] == "DEGRADED_RULES_ONLY"
    assert body["model_version"] is None
    assert body["policy_version"] == "2026.11.1"
    assert "MODEL_FILE_MISSING" in body["reasons"]
    decision = client.post("/v1/assess", json=GENUINE).json()
    assert decision["mode"] == "DEGRADED_RULES_ONLY"
    assert decision["risk_score"] is None


def test_health_reports_an_unwritable_audit_trail(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    client = TestClient(create_app(audit_path=blocker / "audit.jsonl", demo_mode=False))
    body = client.get("/health").json()
    assert body["status"] == "degraded"
    assert "AUDIT_UNAVAILABLE" in body["reasons"]


# --- audit --------------------------------------------------------------------------------


def test_audit_verify_on_a_fresh_service(client: TestClient) -> None:
    assert client.post("/v1/audit/verify").json()["ok"] is True
    assert client.get("/v1/audit").json() == {"count": 0, "records": []}


def test_audit_chain_verifies_then_detects_tampering(client: TestClient) -> None:
    for raw in (GENUINE, SCAM, SCENARIOS["G02"]):
        client.post("/v1/assess", json=raw)
    ok = client.post("/v1/audit/verify").json()
    assert (ok["ok"], ok["records"], ok["first_bad_line"]) == (True, 3, None)

    path = audit_path(client)
    rows = path.read_text().splitlines()
    record = json.loads(rows[1])
    record["decision"] = "ALLOW"  # the scam hold quietly becomes an ALLOW
    rows[1] = json.dumps(record)
    path.write_text("\n".join(rows) + "\n")

    bad = client.post("/v1/audit/verify").json()
    assert bad["ok"] is False
    assert bad["first_bad_line"] == 2
    assert "edited" in bad["message"]


def test_audit_write_failure_returns_hold(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    client = TestClient(create_app(audit_path=blocker / "audit.jsonl", demo_mode=False))
    response = client.post("/v1/assess", json=GENUINE)  # would be a clean ALLOW
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "HOLD"
    assert body["reasons"][0]["code"] == "AUDIT_UNAVAILABLE"


def test_audit_endpoint_exposes_no_unmasked_account_numbers_or_names(client: TestClient) -> None:
    for raw in (GENUINE, SCAM, SCENARIOS["S09"]):
        client.post("/v1/assess", json=raw)
    response = client.get("/v1/audit")
    text = response.text
    for raw in (GENUINE, SCAM, SCENARIOS["S09"]):
        assert raw["payee"]["account_number"] not in text
        assert raw["payee"]["name"] not in text
        assert raw["payee"]["bsb"] not in text
        assert raw["amount"] not in text
    assert '"amount"' not in text
    records = response.json()["records"]
    assert len(records) == 3
    for record in records:
        assert set(record) == set(RECORD_FIELDS)
        assert record["payee_account_masked"].startswith("*****")
        assert len(record["payee_account_masked"].lstrip("*")) == 3


def test_audit_limit_default_maximum_and_order(client: TestClient) -> None:
    for i in range(25):
        client.post("/v1/assess", json={**GENUINE, "request_id": f"r-{i}"})
    default = client.get("/v1/audit").json()
    assert default["count"] == 20
    ids = [r["decision_id"] for r in default["records"]]
    assert len(set(ids)) == 20
    assert client.get("/v1/audit?limit=3").json()["count"] == 3
    assert client.get("/v1/audit?limit=100").status_code == 200
    assert client.get("/v1/audit?limit=101").status_code == 422
    assert client.get("/v1/audit?limit=0").status_code == 422
    newest = client.get("/v1/audit?limit=1").json()["records"][0]
    assert (
        newest["decision_id"] == client.get("/v1/audit?limit=2").json()["records"][0]["decision_id"]
    )


def test_unreadable_audit_log_returns_503(client: TestClient) -> None:
    client.post("/v1/assess", json=GENUINE)
    with audit_path(client).open("a") as handle:
        handle.write("garbage\n")
    assert client.get("/v1/audit").status_code == 503


# --- demo switch --------------------------------------------------------------------------


def test_demo_endpoint_is_forbidden_when_demo_mode_is_off(client: TestClient) -> None:
    for body in ({"enabled": True}, {"enabled": False}, {"nonsense": 1}):
        response = client.post("/v1/demo/model-failure", json=body)
        assert response.status_code == 403
        assert "Demo mode is off" in response.json()["detail"]
    assert client.get("/health").json()["mode"] == "NORMAL"  # nothing changed


def test_demo_mode_requires_exactly_the_value_1(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for value, expected in (("1", 200), ("true", 403), ("0", 403), ("", 403)):
        monkeypatch.setenv(DEMO_MODE_ENV, value)
        client = TestClient(create_app(audit_path=tmp_path / "audit.jsonl"))
        assert (
            client.post("/v1/demo/model-failure", json={"enabled": False}).status_code == expected
        )
    monkeypatch.delenv(DEMO_MODE_ENV)
    client = TestClient(create_app(audit_path=tmp_path / "audit.jsonl"))
    assert client.post("/v1/demo/model-failure", json={"enabled": False}).status_code == 403


def test_demo_switch_degrades_and_restores_the_service(demo_client: TestClient) -> None:
    on = demo_client.post("/v1/demo/model-failure", json={"enabled": True})
    assert on.json() == {"enabled": True, "mode": "DEGRADED_RULES_ONLY"}
    health = demo_client.get("/health").json()
    assert (health["status"], health["mode"], health["model_version"]) == (
        "degraded",
        "DEGRADED_RULES_ONLY",
        None,
    )
    degraded = demo_client.post("/v1/assess", json=SCAM).json()
    assert degraded["mode"] == "DEGRADED_RULES_ONLY"
    assert degraded["decision"] == "HOLD"

    off = demo_client.post("/v1/demo/model-failure", json={"enabled": False})
    assert off.json() == {"enabled": False, "mode": "NORMAL"}
    assert demo_client.get("/health").json()["mode"] == "NORMAL"
    assert demo_client.post("/v1/assess", json=GENUINE).json()["mode"] == "NORMAL"


@pytest.mark.parametrize(
    "body", [{}, {"enabled": "yes"}, {"enabled": 1}, {"enabled": True, "x": 1}]
)
def test_demo_switch_rejects_bad_bodies(demo_client: TestClient, body: dict[str, Any]) -> None:
    assert demo_client.post("/v1/demo/model-failure", json=body).status_code == 422
    assert demo_client.get("/health").json()["mode"] == "NORMAL"


def test_demo_switch_applies_when_the_real_model_is_also_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "gone.json"))
    client = make_client(tmp_path, demo_mode=True)
    assert client.get("/health").json()["mode"] == "DEGRADED_RULES_ONLY"


# --- scenarios and evaluation -------------------------------------------------------------


def test_scenarios_endpoint_lists_ready_to_send_requests_without_labels(client: TestClient) -> None:
    response = client.get("/v1/scenarios")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == len(SCENARIOS)
    assert all(set(item) == {"id", "typology", "description", "request"} for item in items)
    for label_field in ('"expected_decision"', '"is_scam"', '"must_hold"', '"expected_codes"'):
        assert label_field not in response.text
    sample = next(i for i in items if i["id"] == "G01")
    assert client.post("/v1/assess", json=sample["request"]).json()["decision"] == "ALLOW"


def test_eval_endpoint_returns_gates_and_scenario_results(client: TestClient) -> None:
    response = client.post("/v1/eval")
    assert response.status_code == 200
    body = response.json()
    assert body["overall_pass"] is True
    assert len(body["gates"]) == 6
    assert all(g["passed"] for g in body["gates"])
    assert {"name", "passed", "detail"} == set(body["gates"][0])
    assert len(body["scenarios"]) == len(SCENARIOS)
    first = body["scenarios"][0]
    assert {"id", "expected", "actual", "risk_score", "reason_codes", "passed"} <= set(first)
    assert body["known_limitations"]["non_gating"] is True
    assert body["known_limitations"]["total"] >= 6
    assert body["policy_version"] == "2026.11.1"


def test_eval_endpoint_writes_nothing_to_the_audit_trail(client: TestClient) -> None:
    client.post("/v1/eval")
    assert not audit_path(client).exists()


def test_eval_endpoint_is_unaffected_by_the_demo_model_failure(demo_client: TestClient) -> None:
    demo_client.post("/v1/demo/model-failure", json={"enabled": True})
    assert demo_client.post("/v1/eval").json()["overall_pass"] is True


def test_eval_endpoint_returns_503_when_the_model_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client(tmp_path)
    monkeypatch.setenv(MODEL_PATH_ENV, str(tmp_path / "gone.json"))
    response = client.post("/v1/eval")
    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]


# --- logging ------------------------------------------------------------------------------


def test_logs_are_json_with_only_the_allowed_fields_and_no_pii(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    client.post("/v1/assess", json=SCAM)
    client.post("/v1/assess", json=GENUINE)
    client.post("/v1/assess", json=SCENARIOS["V01"])
    out = capsys.readouterr().out
    lines = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    decisions = [entry for entry in lines if entry["message"] == "decision"]
    assert [d["decision"] for d in decisions] == ["HOLD", "ALLOW", "REJECT"]
    for entry in decisions:
        assert set(entry) == {
            "ts",
            "level",
            "logger",
            "message",
            "decision_id",
            "decision",
            "mode",
            "latency_ms",
        }
    assert SCAM["amount"] not in out
    assert SCAM["customer_id"] not in out
    assert SCAM["payee"]["account_number"] not in out
    assert SCAM["payee"]["name"] not in out


def test_json_formatter_drops_unlisted_extra_fields() -> None:
    import logging

    record = logging.LogRecord("scamcheck.x", logging.INFO, __file__, 1, "hello", None, None)
    record.amount = "999.00"  # type: ignore[attr-defined]
    record.decision = "ALLOW"  # type: ignore[attr-defined]
    payload = json.loads(JsonFormatter().format(record))
    assert "amount" not in payload
    assert payload["decision"] == "ALLOW"
    assert payload["message"] == "hello"


def test_audit_log_object_is_the_one_the_api_writes(client: TestClient) -> None:
    client.post("/v1/assess", json=GENUINE)
    assert AuditLog(audit_path(client)).verify().records == 1
