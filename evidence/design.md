# Design

What is built is described in the first six sections. "Production shape and CI/CD path" is a
**proposal; none of it is built**.

## Architecture

```
  payment system / analyst
        |  JSON over HTTP                    browser (same origin)        terminal
        v                                          v                         v
  +----------------------------------------------------------------+   +-----------+
  | FastAPI app (api.py)  /v1/assess  /health  /v1/audit  /v1/eval |   | scamcheck |
  | static UI at /        one worker, JSON logs to stdout          |   | CLI       |
  +----------------------------------------------------------------+   +-----+-----+
                              v                                              |
                   assess_and_record (engine.py)  <--------------------------+
                      |                         |
                      v                         v
          assess (pure decision)        AuditLog (audit.py)
                      |                 append-only JSONL, hash chain
   validate -> signals -> abstain -> rules R01-R07 -> model score -> most severe wins
   (schemas)   (reference) (policy)    (policy)       (models/*.json)
        ^          ^           ^            ^               ^
        |          |           +-- config/policy.toml       +-- risk_model_v1.json + .sha256
        |          +-- sample-data/reference/*.json (SYNTHETIC)
        +-- strict pydantic models, stable error codes
```

## Data flow

1. A request arrives (API, UI or CLI). The API parses the body; anything unparseable is treated as invalid.
2. `validate_request` checks every field and returns stable error codes, or a typed `PaymentRequest`. Invalid input becomes `REJECT` (HTTP 422).
3. `build_signals` joins the request with reference data: new payee, amount versus the customer's typical amount, payee account age, name match, mule list, session flags, and `data_complete`. The name match is MATCH (same words after normalising case, punctuation and spacing), CLOSE (initials instead of full words, the same words in another order such as "Smith, John", or a spelling at or above `name_close_threshold`), MISMATCH (anything else) or UNAVAILABLE (payee not in reference data).
4. If reference data is missing and the amount is at or above `abstain_amount`, the engine adds a `HOLD` floor (`ABSTAIN_INSUFFICIENT_DATA`).
5. Seven rules (R01 to R07) each return a floor (`WARN` or `HOLD`) and a reason.
6. The logistic-regression model scores the request; the score maps to a band (`>= score_hold` HOLD, `>= score_warn` WARN) and adds its top two contributions as reasons.
7. The decision is the most severe floor. Every non-REJECT decision has at least one reason, plus `policy_version`, `model_version`, mode and latency.
8. `assess_and_record` appends a hash-chained audit record. If that fails, the answer becomes `HOLD` (`AUDIT_UNAVAILABLE`).

## Components

| Module | Responsibility |
|---|---|
| `schemas.py` | Request and response contracts, error-code mapping (`extra="forbid"`, strict types) |
| `reference.py`, `signals.py` | Load and validate synthetic reference data; derive explainable signals |
| `policy.py`, `config/policy.toml` | Rule, abstain, score, name-match and evaluation thresholds and `policy_version`; validated at load |
| `rules.py` | Pure rules R01 to R07, severity ordering |
| `model.py`, `models/` | JSON artifact loader: SHA-256 and feature-list checks, scoring, health, degrade |
| `engine.py` | `assess` (pure), `assess_and_record` (audited, fails closed) |
| `audit.py` | Append-only hash-chained log, `verify()`, masking |
| `api.py`, `static/`, `cli.py`, `health.py` | HTTP service and same-origin web UI; command line; shared health check |
| `evaluate.py`, `sample-data/scenarios*.jsonl` | Labelled scenarios, six gates, report |
| `scripts/` | Seeded generators for reference and training data; model training; `check_evidence.py` (the evidence gate) |

## Trade-offs

- **Rules plus a small model, not a large model.** Decisions are deterministic, reproducible and explainable line by line. The cost is lower recall on patterns the seven features and rules cannot see (six known misses, see `verify.md`).
- **Integrity over availability for the audit trail.** An audit failure, or a damaged last line, holds payments instead of releasing unrecorded ones.
- **Degraded mode is deliberately broad.** With no model, any risk signal on a payment at or above `abstain_amount` is held, including a plain new payee. Safe, but it adds friction.
- **Absolute and relative amount signals.** Most amount signals are relative to the customer's typical payment; R07 uses the absolute amount for young payee accounts. Accepted cost: genuine high-value payments to accounts under 30 days old are held.
- **Files instead of a database.** Simple, inspectable, no services to run; not scalable and not multi-host safe.
- **Policy and model are loaded at startup.** Predictable behaviour; a restart is needed to pick up a change.
- **Evaluation is self-authored.** Thresholds are not tuned to make gates pass; mismatches are listed, and hard cases the system gets wrong are kept outside the gates but reported every run.

## Security and privacy

- Synthetic data only; BSBs are in the `000xxx` range. No credentials, API keys, secrets or runtime network calls. No `pickle` or `eval`.
- Audit records hold no amounts, payee names or full account numbers (last three digits only); `request_hash` is a SHA-256. Logs carry only `decision_id`, `decision`, `mode`, `latency_ms`. Error messages never echo input values.
- Model artifact checked by SHA-256 and exact feature list before use; a mismatch degrades rather than crashes. (Someone who can rewrite both the artifact and its checksum can still swap the model.)
- Web UI: DOM built with `textContent` only, strict Content-Security-Policy (`default-src 'self'`), nosniff, no-referrer, no CORS. Container runs as non-root and is published on `127.0.0.1` only.
- Known gap: no authentication on the API or UI.

## Technology choices

Python 3.12; FastAPI, uvicorn and pydantic v2 as the only direct runtime dependencies (pinned exactly; transitive packages such as starlette are not locked); pytest, httpx and ruff for development. Everything else is the standard library: `tomllib` for policy, `hashlib`, `json`, `fcntl`. The model is trained with plain-Python gradient descent, so there is no numerical library. The UI is three static files with no build step. Docker (`python:3.12-slim`), GitHub Actions and a Makefile for delivery.

## Production shape and CI/CD path (proposal, not built)

**Shape.** Stateless containers behind an authenticated gateway, scaled horizontally, with health-based rollout. Reference data from a managed store or feature service instead of JSON files. Audit records written to WORM or object-lock storage or an append-only ledger database, with the latest chain hash anchored off the box. Model artifacts signed in a model registry. Policy as versioned configuration. Secrets, if ever needed, from the platform's secret manager. Logs and metrics (decision mix, hold rate, latency, degrade events) to central observability.

**Path to production.**
1. *Pull request:* `make verify`, which includes the evidence gate (already runs in GitHub Actions on every push and pull request, with the full commit history).
2. *Pipeline (to add):* build the image, scan it and its dependencies, deploy to a staging environment, run `scamcheck eval` and the browser checks against it.
3. *Model-risk sign-off:* a new model or policy version is promoted only with the evaluation report, metrics, known limitations and the diff from the current version, approved by model risk.
4. *Shadow mode:* the new version scores live traffic with no effect on decisions; compare its decisions and score distributions with production.
5. *Champion/challenger:* route a small share of traffic to the challenger and compare hold, warn and confirmed-fraud rates.
6. *Canary:* roll out in steps with automatic stop and rollback on guardrails (error rate, degrade events, hold rate, latency).
7. *Rollback:* redeploy the previous image, model artifact and policy version. Both versions are already in every response and audit record, so any decision can be traced to what produced it.
