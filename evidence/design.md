# Design

## Components

### schemas (`src/scamcheck/schemas.py`)
- Pydantic v2 models `PaymentRequest` (with `Payee`, `Session`), `DecisionResponse`, `Reason`, `ValidationIssue`; all use `extra="forbid"`. `Decision` and `Mode` are `StrEnum`s.
- `validate_request(raw)` never raises. It maps pydantic errors to stable codes (e.g. `INVALID_BSB`, `AMOUNT_NOT_POSITIVE`, `UNKNOWN_FIELD`, `NAIVE_TIMESTAMP`) using fixed messages that never echo input values.
- The maximum amount is not defined here: `validate_request(raw, max_amount)` takes it as an argument (the engine passes `policy.max_amount`). `ID_MAX_LENGTH` (64) is the single definition of the identifier length limit, shared by `schemas`, `reference` and `engine`.

### reference (`src/scamcheck/reference.py`)
- Loads `customers.json`, `payees.json` and `mule_accounts.json` into frozen dataclasses (`ReferenceData` with `customer()`, `payee()`, `is_mule()` lookups). Payees are keyed `"bsb-account"`.
- Files are validated strictly with pydantic: `_note` must contain `SYNTHETIC`, BSBs must be in the `000xxx` range, unknown fields are rejected, and amounts are parsed as `Decimal` (no floats).
- Typed errors: `ReferenceFileMissingError` and `ReferenceFileMalformedError` (both `ReferenceDataError`, with `.path`). Messages give the file and field path, never data values.

### signals (`src/scamcheck/signals.py`)
- `build_signals(request, reference)` returns a frozen `Signals` dataclass: `new_payee`, `amount_ratio`, `payee_account_age_days`, `payee_name_match`, `payee_on_mule_list`, the three session flags and `data_complete`.
- Name match: normalise (case, punctuation, spaces, apostrophes), then `MATCH` for equal tokens or initials, `CLOSE` if the difflib ratio is at least 0.80, else `MISMATCH`; `UNAVAILABLE` when the payee is not in reference data.
- Unknown customer: `amount_ratio` is `None`, `new_payee` is `True`, `data_complete` is `False`. Unknown payee: age is `None`, name match is `UNAVAILABLE`, `data_complete` is `False`.

### policy (`src/scamcheck/policy.py`, `config/policy.toml`)
- `load_policy()` reads `config/policy.toml` (stdlib `tomllib`) into a frozen, validated `Policy` (amounts as `Decimal`, `score_warn < score_hold`, unknown keys rejected). Failure raises `PolicyError`.

### rules (`src/scamcheck/rules.py`)
- Six pure rules R01-R06, each `(signals, amount, policy) -> RuleHit(floor, reason) | None`, run in a fixed order. Severity is `ALLOW < WARN < HOLD`; `most_severe()` picks the final decision. Reason text contains no amounts, names or account numbers.

### engine (`src/scamcheck/engine.py`)
- `assess(raw, policy=None, reference=None) -> DecisionResponse`: validate (REJECT with codes) -> signals -> abstain check -> rules -> most severe floor. Clean requests get the reason `NO_RISK_SIGNALS`. `latency_ms` is measured with `time.perf_counter`.
- Model step (P5): in NORMAL mode the decision is the most severe of the rule floors and the score band (`>= score_hold` HOLD, `>= score_warn` WARN, else ALLOW). If the model is unavailable the response is `DEGRADED_RULES_ONLY` with `risk_score` and `model_version` `None`, and any risk signal on a payment at or above `abstain_amount` is held (`DEGRADED_FAILSAFE_HOLD`).
- Fail safe: an unloadable policy, unloadable reference data or any unexpected exception returns HOLD (`POLICY_UNAVAILABLE`, `REFERENCE_DATA_UNAVAILABLE`, `INTERNAL_ERROR`), never ALLOW.

### model (`src/scamcheck/model.py`, `models/`)
- Logistic regression stored as JSON (`models/risk_model_v1.json`) with a SHA-256 sidecar (`risk_model_v1.sha256`). `load_model()` checks the checksum, that `features` equals the code's `FEATURES` exactly (order included), and the field types; failures raise `ModelError` with a code (`MODEL_FILE_MISSING`, `MODEL_INTEGRITY_FAILED`, `MODEL_MALFORMED`, `MODEL_FEATURES_MISMATCH`).
- `ModelRuntime.from_path()` never raises: it returns a healthy runtime or a degraded one, and logs the degrade once at WARNING (error code only, no request data). `health()` returns `ok` or `degraded` plus the code. `default_runtime()` is cached, so the process loads the model once.
- Features (`extract_features`, shared with training): `new_payee`, `log_amount_ratio` (0 when the customer is unknown), `young_account` (age below the artifact's `young_account_days`), `name_mismatch`, `on_active_call`, `remote_access_detected`, `new_device`. `score()` returns the probability and up to two reasons (`M_*` codes) from the largest positive coefficient x value contributions.

### training (`scripts/generate_training_data.py`, `scripts/train_model.py`)
- The generator writes 5000 SYNTHETIC labelled payments (seed 42) to `sample-data/training/training_data.csv`; its generating assumptions are in the script's header. The trainer fits by batch gradient descent (lr 2.0, L2 0.001, stops at gradient tolerance) on a seeded 80/20 split and writes the artifact with the training data hash and held-out metrics.

### evaluation gate (`src/scamcheck/evaluate.py`, `sample-data/scenarios.jsonl`)
- 39 gated SYNTHETIC labelled scenarios (`id, typology, description, request, expected_decision` (one decision or an allowed set), `must_hold`, `is_scam`, optional `expected_codes`): 19 scams, 12 genuine, 3 missing-data, 5 invalid. `is_scam` is `null` for missing-data and invalid scenarios, which are excluded from the scam-catch and genuine-friction rates.
- `python -m scamcheck.evaluate` (`make eval`) runs every scenario through `assess`, enforces six gates, writes `evidence/eval-report.md` (no timestamps, so it only changes when results change) and exits 1 if any gate fails, 2 if it cannot run (missing scenario file, policy, reference data or model).
- Gate thresholds (`min_scam_warn_or_hold_rate` 0.90, `max_genuine_hold_rate` 0.10) are in `config/policy.toml` under `[evaluation]`. The tamper gate edits a temporary copy of the model artifact (intercept set to -50 without updating the checksum), checks the service degrades and logs one warning, and re-runs the must-hold scenarios.

### R07 and the known-limitations file
- `R07_YOUNG_PAYEE_HIGH_VALUE` (rules.py): new payee, account age below `young_account_days`, amount at or above `high_value_amount` -> HOLD. Fraud reason: scam proceeds go to freshly opened accounts (mules, purpose-built investment accounts), and the ratio-based signals (R05, model ratio feature) are quiet for customers whose usual payments are large. It adds no new threshold; it reuses two existing policy values and is independent of the model, so it also applies in degraded mode.
- `sample-data/scenarios_hard.jsonl` holds realistic cases the system is expected to get wrong, labelled with the correct fraud answer. `make eval` runs them and reports them under "Known limitations (non-gating)"; they cannot affect the gates or the exit code, cannot be `must_hold`, and must not reuse gated scenario ids.

### audit (`src/scamcheck/audit.py`)
- Append-only JSON Lines at `SCAMCHECK_AUDIT_PATH` (default `audit/decisions.jsonl`, created 0600). Record: `decision_id, ts, request_hash, customer_id, payee_account_masked, decision, reasons, risk_score, mode, model_version, policy_version, latency_ms, prev_hash, record_hash`. `record_hash = sha256(prev_hash + canonical JSON of the record without record_hash)`; the first record's `prev_hash` is 64 zeros.
- `verify()` recomputes the chain and reports the first bad line (edited, removed, inserted, reordered or malformed records). It cannot detect records removed from the end, or a whole file rewritten with a recomputed chain.
- Appends take a thread lock and an `flock`, fsync, and refuse to append if the last line is incomplete or unreadable. Amounts, payee names and full account numbers are never stored (CLAUDE.md); only the last three digits of a valid account number are kept (`*****117`). `request_hash` is a SHA-256 of the request: it covers the amount but is not the amount or the request.

### engine, API, CLI (P7)
- `assess` stays a pure function (no audit side effects; used by `make eval` and tests). `assess_and_record(raw, audit, ...)` calls it, writes the audit record, and fails closed: any audit error returns HOLD with `AUDIT_UNAVAILABLE` followed by the original reasons (also for requests that would have been REJECT).
- `api.py` (`create_app()`, module-level `app`): `POST /v1/assess` (200, or 422 with the REJECT body; unparseable or oversized bodies are REJECTs and are audited), `GET /health`, `GET /v1/scenarios`, `GET /v1/audit?limit=` (1-100, default 20, newest first), `POST /v1/audit/verify`, `POST /v1/eval` (no audit writes, uses the real model even when the demo switch is on), `POST /v1/demo/model-failure` (403 unless `SCAMCHECK_DEMO_MODE=1`; the switch is in process memory, so run one worker).
- `health.py` is shared by `/health` and `scamcheck health`: status `ok` only when the model, policy, reference data and audit location are usable, otherwise `degraded` with reason codes; mode is `DEGRADED_RULES_ONLY` when there is no model. `/health` returns 200 either way so the container is not restarted for running in degraded mode.
- Logs are JSON on stdout through a formatter that only emits `ts, level, logger, message` plus the whitelisted `decision_id, decision, mode, latency_ms`.
- `cli.py` (`scamcheck assess --file | eval | verify-audit | health`): exit 0 success, 1 rejected / chain broken / degraded / gate failed, 2 cannot read input or run.
- `Dockerfile` (python:3.12-slim, user `app` uid 10001, copies only `src/`, `config/policy.toml`, `models/`, `sample-data/reference/` and the two scenario files, HEALTHCHECK on `/health`, port 8000), `docker-compose.yml` (builds, publishes `127.0.0.1:8000`, audit volume, demo mode off with a commented line), `.dockerignore`, `.github/workflows/ci.yml` (Python 3.12, `make setup`, `make verify`).

### web UI (`src/scamcheck/static/`, served by `api.py`)
- `index.html`, `app.js`, `styles.css` (plain files, no build step, no new dependency, no external CDN or fonts), served at `/` and `/static/`. The page calls only existing same-origin endpoints: `/health`, `/v1/scenarios`, `/v1/assess`, `/v1/audit`, `/v1/audit/verify`, `/v1/eval`, `/v1/demo/model-failure`.
- Panels: health banner (NORMAL or DEGRADED with the reason codes; "Simulate model failure" checkbox only when `/health` reports `demo_mode`), assess (scenario dropdown fills an editable JSON box that is sent exactly as typed, so malformed JSON shows the API's REJECT), audit (last 20 records, "Verify chain"), evaluation (six gates and a per-scenario table, known limitations folded away).
- Decision card: ALLOW green, WARN amber, HOLD red, REJECT grey, always with the word as text; reason codes with details, risk score ("n/a" with no model), mode, model and policy versions, latency. For REJECT the list is headed "Error codes".
- Security: `app.js` builds the DOM with `createElement` and `textContent` only (no `innerHTML`); class names come from a fixed lookup, never from server data. Responses get `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; `/` and `/static/` also get `Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`. No CORS middleware. `/docs` (Swagger UI, assets from a CDN) is deliberately not given the strict policy.
- `/health` now also returns `demo_mode` and `demo_model_failure`; `/favicon.ico` answers 204 so browsers do not log a 404.
