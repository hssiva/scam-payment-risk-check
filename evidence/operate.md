# Operations

## Run

- **Docker:** `docker compose up --build`, then http://localhost:8000 (UI) and `/docs` (API reference). One uvicorn worker; published on `127.0.0.1` only; audit trail on the named volume `audit-data`.
- **Local:** `make setup`, then `make run-api` (http://127.0.0.1:8000). CLI: `scamcheck assess|eval|verify-audit|health` (exit 0 success; 1 rejected, chain broken, degraded or gate failed; 2 cannot read input or run).
- **Demo switch:** `SCAMCHECK_DEMO_MODE=1` (exactly `1`) enables `POST /v1/demo/model-failure` and the UI toggle. Off by default; the compose file has the line commented out.

## Configuration and secrets

| What | Where | Override |
|---|---|---|
| Thresholds, `policy_version`, evaluation gate limits | `config/policy.toml` | `SCAMCHECK_POLICY_PATH` |
| Reference data (SYNTHETIC) | `sample-data/reference/*.json` | `SCAMCHECK_REFERENCE_DIR` |
| Risk model and its `.sha256` | `models/risk_model_v1.json` | `SCAMCHECK_MODEL_PATH` |
| Audit trail | `audit/decisions.jsonl` (working directory) | `SCAMCHECK_AUDIT_PATH` |

There are no secrets: no credentials, keys or tokens exist anywhere, and the service makes no network calls. Configuration is plain files and these environment variables. Policy, reference data and the model are read at startup; **restart to apply a change**. If a policy change alters decisions, bump `policy_version`.

## Logs and health

- **Logs:** JSON on stdout, one object per line. Decision lines carry only `decision_id`, `decision`, `mode`, `latency_ms` (plus `ts`, `level`, `logger`, `message`). Never amounts, account numbers, payee names or customer ids. A model degrade is logged once at WARNING with its error code. The audit trail is a separate file.
- **Health:** `GET /health` and `scamcheck health` return `status` (`ok` or `degraded`), `mode`, `model_version`, `policy_version` and reason codes. It returns 200 even when degraded, so a container that is still deciding safely is not restarted. The Docker `HEALTHCHECK` calls it.

## Failure modes

| Failure | Detected by | Behaviour | Operator action |
|---|---|---|---|
| Model missing, checksum mismatch, wrong feature list, or malformed | load-time checks | **Degrade:** `DEGRADED_RULES_ONLY`, no score; rules still run; any risk signal on a payment at or above `abstain_amount` is HOLD (`DEGRADED_FAILSAFE_HOLD`); one WARNING logged | restore the artifact and its `.sha256`, restart |
| Customer or payee not in reference data | `data_complete` false | **Abstain:** HOLD (`ABSTAIN_INSUFFICIENT_DATA`) at or above `abstain_amount`, otherwise normal rules | add the reference data |
| Reference files unreadable or invalid at startup | load error | HOLD (`REFERENCE_DATA_UNAVAILABLE`); invalid requests are still REJECTed | fix the files (picked up without restart; files that break after a good start are not re-read until restart) |
| Policy file unreadable or invalid at startup | load error | HOLD (`POLICY_UNAVAILABLE`, `policy_version` is `UNKNOWN`) | fix `policy.toml` (picked up without restart; a file that breaks after a good start is not re-read until restart) |
| Audit write fails | exception on append | **Fail closed:** HOLD (`AUDIT_UNAVAILABLE`, original reasons kept), also for would-be REJECTs | fix disk, permissions or path |
| Audit file ends in a partial or unreadable line (crash mid-write) | append refuses | every decision HOLD until repaired; `verify-audit` shows the line | repair or archive the file |
| Audit file edited, records removed, inserted or reordered | `verify` (UI, API `POST /v1/audit/verify`, `scamcheck verify-audit`) | reports the first broken line | investigate; restore from backup |
| Invalid input | validation | `REJECT` with error codes (HTTP 422), audited | fix the caller |
| Unexpected exception | catch-all | HOLD (`INTERNAL_ERROR`), logged by type only | investigate |
| Port 8000 already in use | uvicorn error `address already in use` | service does not start | stop the other process or use another port |

## Audit trail

Verify regularly. **Concurrency:** appends are serialised by a thread lock plus a POSIX `flock`, so several threads, or several processes on the same host and a local filesystem, can share one audit file (tested with 200 threaded appends and 4 processes x 25 appends). It is not safe across hosts or on network or shared filesystems. The single-file log is for the demo and local use only: production needs a proper store (WORM or object-lock storage, or a database with append-only guarantees) and the latest `record_hash` kept off the box. Removal of the newest records is not detectable from the file alone.

## Rollback

Everything that shapes a decision is versioned and visible: `policy_version` and `model_version` are in every response and audit record. To roll back, restore the previous `policy.toml`, `models/` files or image tag and restart. `git revert` plus redeploy is the mechanism today; there is no automated rollback.

## Evidence gate

`make evidence-check` (also part of `make verify` and CI) checks the evidence notes, the decision records, the commit-subject format and that `evidence/eval-report.md` is as recent as the code; see `verify.md`. If check 4 fails ("source changed in ... after the report's last change"): run `make eval` and commit `evidence/eval-report.md` with the change. If checks 3 or 4 say "shallow clone": fetch the full history (`git fetch --unshallow`; in GitHub Actions the checkout uses `fetch-depth: 0`). Use a Conventional Commit subject (`feat|fix|test|docs|chore|ci|refactor`, optional scope, `: description`).

## Local to cloud (proposal, not built)

Run the same image on a managed container platform behind an authenticated gateway; replace file reference data with a managed store; write the audit trail to WORM or ledger storage; supply configuration through the platform's config and secret services; send JSON logs to central logging; add alerts on degrade events, hold rate and latency. Rollout and rollback practice (shadow, champion/challenger, canary) is in `design.md`.

### Policy version history
- `2026.11.1`: the first policy (rules R01 to R06, abstain, score and evaluation-gate thresholds). R07 and the removal of amounts from the audit were added under this version without a bump.
- `2026.11.2`: adds `name_close_threshold`; name matching changed (initials and reordered words are now CLOSE), so decisions for some names changed. Bump `policy_version` whenever a change to `policy.toml` or to decision logic changes decisions.
