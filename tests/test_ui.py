import re
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scamcheck.api import CONTENT_SECURITY_POLICY, STATIC_DIR, create_app

ROOT = Path(__file__).resolve().parents[1]
APP_JS = (STATIC_DIR / "app.js").read_text()
INDEX_HTML = (STATIC_DIR / "index.html").read_text()
STYLES_CSS = (STATIC_DIR / "styles.css").read_text()


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(audit_path=tmp_path / "audit.jsonl", demo_mode=False))


# --- the page and its headers -------------------------------------------------------------


def test_root_serves_the_page_with_a_strict_csp(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    csp = response.headers["content-security-policy"]
    assert csp == CONTENT_SECURITY_POLICY
    assert "default-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "<title>scamcheck</title>" in response.text


def test_page_has_the_four_panels_and_loads_only_local_files(client: TestClient) -> None:
    html = client.get("/").text
    for heading in ("Assess a payment", "Audit trail", "Evaluation"):
        assert heading in html
    assert 'id="health-banner"' in html  # the health banner is the fourth element
    assert "/static/app.js" in html
    assert "/static/styles.css" in html


def test_static_files_are_served_with_the_right_types_and_headers(client: TestClient) -> None:
    expected = {
        "/static/app.js": "javascript",
        "/static/styles.css": "text/css",
        "/static/index.html": "text/html",
    }
    for path, content_type in expected.items():
        response = client.get(path)
        assert response.status_code == 200, path
        assert content_type in response.headers["content-type"], path
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'self'" in response.headers["content-security-policy"]
    assert client.get("/static/app.js").text == APP_JS


@pytest.mark.parametrize(
    "path", ["/static/missing.js", "/static/%2e%2e/pyproject.toml", "/static/../pyproject.toml"]
)
def test_static_files_cannot_escape_their_folder(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404


def test_api_responses_get_nosniff_and_referrer_policy_but_not_the_page_csp(
    client: TestClient,
) -> None:
    for path in ("/health", "/v1/scenarios", "/docs"):
        response = client.get(path)
        assert response.headers["x-content-type-options"] == "nosniff", path
        assert response.headers["referrer-policy"] == "no-referrer", path
    # /docs (Swagger UI) loads assets from a CDN, so the strict page policy must not apply.
    assert "content-security-policy" not in client.get("/docs").headers


def test_same_origin_only_no_cors(client: TestClient) -> None:
    origin = {"Origin": "https://evil.example"}
    for path in ("/", "/health", "/static/app.js"):
        assert "access-control-allow-origin" not in client.get(path, headers=origin).headers
    preflight = client.options(
        "/v1/assess",
        headers={**origin, "Access-Control-Request-Method": "POST"},
    )
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers


def test_favicon_request_is_answered_quietly(client: TestClient) -> None:
    response = client.get("/favicon.ico")
    assert response.status_code == 204
    assert response.content == b""
    assert "/favicon.ico" not in client.get("/openapi.json").json()["paths"]


def test_the_page_is_not_part_of_the_api_schema(client: TestClient) -> None:
    assert "/" not in client.get("/openapi.json").json()["paths"]


# --- the JavaScript must never build HTML from data ---------------------------------------


def test_app_js_never_uses_innerhtml() -> None:
    assert "innerHTML" not in APP_JS


@pytest.mark.parametrize(
    "forbidden",
    [
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "document.write",
        "eval(",
        "new function",
        "setattribute('style'",
        'setattribute("style"',
        "srcdoc",
        "createcontextualfragment",
        "dangerouslyset",
    ],
)
def test_app_js_has_no_html_or_code_injection_sinks(forbidden: str) -> None:
    assert forbidden not in APP_JS.lower()


def test_app_js_renders_server_data_with_text_apis() -> None:
    assert "textContent" in APP_JS
    assert "createElement" in APP_JS


# --- nothing external, nothing inline ------------------------------------------------------


@pytest.mark.parametrize("name", ["app.js", "index.html", "styles.css"])
def test_no_external_urls_cdn_or_remote_fonts(name: str) -> None:
    text = (STATIC_DIR / name).read_text()
    assert not re.search(r"https?://", text), name
    assert not re.search(r"(src|href)=[\"']//", text), name
    assert "@import" not in text
    assert "@font-face" not in text


def test_html_has_no_inline_scripts_styles_or_event_handlers() -> None:
    for script in re.findall(r"<script\b[^>]*>(.*?)</script>", INDEX_HTML, flags=re.S):
        assert script.strip() == ""
    assert not re.search(r"<script\b(?![^>]*\bsrc=)", INDEX_HTML)
    assert "<style" not in INDEX_HTML
    assert not re.search(r"\sstyle=", INDEX_HTML)
    assert not re.search(r"\son[a-z]+=", INDEX_HTML, flags=re.I)
    assert "javascript:" not in INDEX_HTML.lower()


# --- accessibility and wiring --------------------------------------------------------------


def test_every_form_control_has_a_label() -> None:
    controls = re.findall(r"<(?:input|select|textarea)\b[^>]*\bid=\"([^\"]+)\"", INDEX_HTML)
    assert {"scenario-select", "request-json"} <= set(controls)
    for control_id in controls:
        assert f'for="{control_id}"' in INDEX_HTML, control_id


def test_page_language_viewport_and_live_regions() -> None:
    assert '<html lang="en">' in INDEX_HTML
    assert 'name="viewport"' in INDEX_HTML
    assert 'id="health-banner"' in INDEX_HTML
    assert 'role="status"' in INDEX_HTML
    assert 'role="alert"' in INDEX_HTML
    assert INDEX_HTML.count("<h1") == 1


def test_decisions_are_shown_as_text_not_only_colour() -> None:
    assert '"Decision: " + data.decision' in APP_JS  # the card title carries the word
    assert "decisionTag" in APP_JS  # table cells carry the word too
    for decision in ("allow", "warn", "hold", "reject"):
        assert f".decision-{decision}" in STYLES_CSS
        assert f".tag-{decision}" in STYLES_CSS


def test_every_element_id_used_by_app_js_exists_in_the_page() -> None:
    used = set(re.findall(r"byId\(\"([^\"]+)\"\)", APP_JS))
    used |= set(re.findall(r"(?:showError|runAction)\([^,\"]*\"([a-z-]+)\"", APP_JS))
    used |= set(re.findall(r"\"([a-z-]+-error)\"", APP_JS))
    assert len(used) >= 10
    for element_id in used:
        assert f'id="{element_id}"' in INDEX_HTML, element_id


def test_app_js_calls_only_existing_api_endpoints(client: TestClient) -> None:
    api_paths = set(client.get("/openapi.json").json()["paths"]) | {"/health"}
    called = {p.split("?")[0] for p in re.findall(r"\"(/(?:v1/[a-z/-]+|health)[^\"]*)\"", APP_JS)}
    assert called, "the script should call the API"
    assert called <= api_paths, called - api_paths


def test_dropdown_scenarios_and_other_endpoints_the_page_needs_exist(client: TestClient) -> None:
    assert len(client.get("/v1/scenarios").json()) > 30
    assert client.get("/v1/audit?limit=20").status_code == 200
    assert client.post("/v1/audit/verify").status_code == 200


# --- demo mode in /health drives the toggle ------------------------------------------------


def test_health_reports_demo_mode_and_the_simulated_failure(tmp_path: Path) -> None:
    off = TestClient(create_app(audit_path=tmp_path / "a.jsonl", demo_mode=False)).get("/health")
    assert off.json()["demo_mode"] is False
    client = TestClient(create_app(audit_path=tmp_path / "b.jsonl", demo_mode=True))
    assert client.get("/health").json()["demo_mode"] is True
    assert client.get("/health").json()["demo_model_failure"] is False
    client.post("/v1/demo/model-failure", json={"enabled": True})
    body = client.get("/health").json()
    assert (body["demo_mode"], body["demo_model_failure"]) == (True, True)
    assert body["mode"] == "DEGRADED_RULES_ONLY"
    assert "DEMO_MODEL_FAILURE" in body["reasons"]


# --- packaging -----------------------------------------------------------------------------


def test_static_files_are_listed_as_package_data_and_copied_into_the_image() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["tool"]["setuptools"]["package-data"]["scamcheck"] == ["static/*"]
    assert "COPY src/ src/" in (ROOT / "Dockerfile").read_text()
    for name in ("index.html", "app.js", "styles.css"):
        assert (STATIC_DIR / name).is_file()
