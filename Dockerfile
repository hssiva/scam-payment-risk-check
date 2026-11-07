FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Unprivileged user; the app never runs as root.
RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only what the service needs at runtime (no tests, scripts, training data or evidence).
COPY src/ src/
COPY config/policy.toml config/policy.toml
COPY models/ models/
COPY sample-data/reference/ sample-data/reference/
COPY sample-data/scenarios.jsonl sample-data/scenarios_hard.jsonl sample-data/

# The audit trail is written here (mounted as a volume by docker-compose).
RUN mkdir -p /app/audit && chown app:app /app/audit

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import sys, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2); sys.exit(0 if r.status == 200 else 1)"

# One worker: the loaded model and the demo switch live in process memory.
CMD ["uvicorn", "scamcheck.api:app", "--host", "0.0.0.0", "--port", "8000"]
