"""Static checks on the container and CI files (the build itself is exercised by hand)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(name: str) -> str:
    return (ROOT / name).read_text()


def test_dockerfile_basics() -> None:
    text = read("Dockerfile")
    assert text.startswith("FROM python:3.12-slim")
    assert "USER app" in text
    assert text.index("USER app") < text.index("CMD [")
    assert "EXPOSE 8000" in text
    assert "HEALTHCHECK" in text
    assert "/health" in text
    assert "uvicorn" in text
    assert "scamcheck.api:app" in text


def test_dockerfile_copies_only_what_the_service_needs() -> None:
    copies = [line for line in read("Dockerfile").splitlines() if line.startswith("COPY ")]
    sources = " ".join(copies)
    for needed in ("requirements.txt", "src/", "config/policy.toml", "models/"):
        assert needed in sources
    for not_needed in ("tests", "evidence", "scripts", "training", ".git", "COPY . "):
        assert not_needed not in sources


def test_dockerfile_does_not_run_as_root_or_embed_secrets() -> None:
    text = read("Dockerfile")
    assert "USER root" not in text
    for word in ("PASSWORD", "SECRET", "API_KEY", "TOKEN"):
        assert word not in text.upper()


def test_compose_builds_and_publishes_port_8000_with_demo_mode_off() -> None:
    text = read("docker-compose.yml")
    assert "build: ." in text
    assert ":8000:8000" in text
    uncommented = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
    assert not any("SCAMCHECK_DEMO_MODE" in ln for ln in uncommented)
    assert any(ln.strip().startswith("# SCAMCHECK_DEMO_MODE") for ln in text.splitlines())
    assert "docker compose up --build" in text


def test_dockerignore_keeps_secrets_and_junk_out_of_the_build_context() -> None:
    entries = read(".dockerignore").split()
    for entry in (".git", ".venv", "audit", ".env", "tests", "**/*.egg-info", "**/__pycache__"):
        assert entry in entries


def test_ci_workflow_runs_make_setup_and_make_verify_on_python_312() -> None:
    text = read(".github/workflows/ci.yml")
    assert "push:" in text
    assert "pull_request:" in text
    assert 'python-version: "3.12"' in text
    assert text.index("make setup") < text.index("make verify")
    assert "contents: read" in text
