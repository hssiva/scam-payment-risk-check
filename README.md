# scamcheck

A local, explainable payment scam risk check. You give it one payment request (JSON); it returns
`ALLOW`, `WARN` or `HOLD` (or `REJECT` for invalid input) with reason codes, and writes a
tamper-evident audit record. It combines seven transparent rules with a small logistic-regression
model, is deterministic, and fails safe: if it cannot decide reliably it holds the payment.

**Synthetic data only.** No real customers, banks, credentials, network calls or LLMs. This is a
demonstration, not a production fraud system (see [Known limitations](#known-limitations)).

## Prerequisites

- **Docker** with Compose (quickest), **or**
- **Python 3.12** (`python3.12` on your PATH) and **make**, on macOS or Linux.
- Internet access for the Docker build or `make setup` (pinned packages are downloaded once). The
  running service makes no network calls.

## Quick start (Docker)

```bash
docker compose up --build
```

Then open the web UI at **http://localhost:8000**. (API reference: http://localhost:8000/docs.)
Port 8000 must be free; it is published on `127.0.0.1` only. Stop with Ctrl+C, then
`docker compose down` (add `-v` to also delete the audit volume).

## Run locally (Python)

```bash
make setup      # creates .venv, installs pinned dependencies, installs the package and the CLI
make verify     # ruff, format check, tests and the evaluation gate (see below)
make run-api    # web UI and API on http://127.0.0.1:8000 (one worker)
```

**CLI** (installed by `make setup`; audit goes to `audit/decisions.jsonl`, or `SCAMCHECK_AUDIT_PATH`):

```bash
.venv/bin/scamcheck assess --file /tmp/request.json   # one decision as JSON; exit 1 if REJECT
.venv/bin/scamcheck eval                              # evaluation gate; writes evidence/eval-report.md
.venv/bin/scamcheck verify-audit                      # recompute the audit hash chain
.venv/bin/scamcheck health                            # model, policy, reference data, audit
```

**API** (with the service running):

| Endpoint | Purpose |
|---|---|
| `POST /v1/assess` | assess a payment (200, or 422 with a `REJECT` body for invalid input) |
| `GET /health` | status, mode (`NORMAL` or `DEGRADED_RULES_ONLY`), model and policy versions |
| `GET /v1/scenarios` | the labelled sample requests (ids, typologies, descriptions, requests) |
| `GET /v1/audit?limit=20` | latest audit records (1 to 100), masked fields only |
| `POST /v1/audit/verify` | verify the hash chain; reports the first broken line |
| `POST /v1/eval` | run the evaluation: six gates plus per-scenario results |
| `POST /v1/demo/model-failure` | demo only (403 unless `SCAMCHECK_DEMO_MODE=1`) |

## Demo walkthrough (web UI, six steps)

1. **Scam.** Scenario `S01 – impersonation`, click **Submit**: a red **HOLD** card with the score
   (0.9626), reason codes and details, mode, model and policy versions, and latency.
2. **Genuine.** Scenario `G01 – genuine_rent`, **Submit**: a green **ALLOW** card (`NO_RISK_SIGNALS`).
3. **Invalid request.** Scenario `V01 – invalid_request` (or type `{ not json` in the box),
   **Submit**: a grey **REJECT** card headed "Error codes".
4. **Verify the audit trail.** In "Audit trail", click **Verify chain**: `OK: chain intact`
   (3 records on a fresh start). Editing any line of the audit file makes it report `BROKEN` at that line.
5. **Evaluation.** Click **Run evaluation**: six gates, all PASS, and a table of the 39 labelled
   scenarios (the known limitations are folded below it).
6. **Degrade (needs demo mode).** Turn demo mode on, then tick **Simulate model failure** in the top
   banner: the banner turns amber ("DEGRADED (rules only, no risk model)"); submit `S01` again and the
   payment is still HELD, with no score and mode `DEGRADED_RULES_ONLY`. Untick to go back.
   - Docker: uncomment `SCAMCHECK_DEMO_MODE: "1"` in `docker-compose.yml`, then `docker compose up --build`.
     Revert that edit afterwards: a test in `make verify` checks the committed file has demo mode off.
   - Local: `SCAMCHECK_DEMO_MODE=1 make run-api`.

## Example input and output

Save this as `/tmp/request.json` (`S01`: a "bank fraud team" caller, new payee, high value, on a call):

```json
{
  "request_id": "demo-001",
  "timestamp": "2026-11-07T10:30:00+11:00",
  "customer_id": "cust-002",
  "amount": "4800.00",
  "currency": "AUD",
  "payee": { "name": "Sam Mockwell", "bsb": "000102", "account_number": "70025691" },
  "channel": "mobile",
  "session": { "on_active_call": true, "remote_access_detected": false, "new_device": true }
}
```

```bash
.venv/bin/scamcheck assess --file /tmp/request.json
# or, with the service running:
curl -s -X POST localhost:8000/v1/assess -H 'content-type: application/json' -d @/tmp/request.json
```

Output (`decision_id` is random and `latency_ms` varies per call):

```json
{
  "decision_id": "cefc984e-127f-49d4-b84f-857977d616ed",
  "request_id": "demo-001",
  "decision": "HOLD",
  "risk_score": 0.9626,
  "reasons": [
    { "code": "R03_ON_CALL_NEW_PAYEE_HIGH_VALUE", "detail": "High-value payment to a new payee during an active call (high value is 3000 AUD or more)." },
    { "code": "R05_UNUSUAL_AMOUNT", "detail": "Amount is at least 5 times the customer's typical payment." },
    { "code": "M_AMOUNT_ABOVE_TYPICAL", "detail": "Amount is high compared with typical payments." },
    { "code": "M_NEW_PAYEE", "detail": "Payment to a payee the customer has not paid before." }
  ],
  "mode": "NORMAL",
  "model_version": "risk_model_v1",
  "policy_version": "2026.11.2",
  "latency_ms": 3.074
}
```

`R*` codes come from rules, `M_*` codes from the model's top contributions. The decision is the most
severe of the rule results and the model's score band.

## `make verify`

One command runs everything CI runs: `ruff check`, `ruff format --check`, the full `pytest` suite,
and the evaluation gate (`make eval`: 39 labelled scenarios, six gates, exit code 1 if any fails).
At the time of writing: 534 tests pass and all six gates pass. Details in
[evidence/verify.md](evidence/verify.md); the per-scenario report is
[evidence/eval-report.md](evidence/eval-report.md).

## Known limitations

- **Synthetic everything.** The training data, reference data, scenarios and labels were all written
  for this project by the same author. Metrics measure how well the system matches patterns we
  invented, not real fraud performance.
- **Known misses.** Six realistic cases (`sample-data/scenarios_hard.jsonl`) are reported but not
  gated, and the system gets all six wrong: three scams slip through (a low-signal marketplace scam,
  a romance scam to a payee the customer already pays, a payment just under the 1,000 AUD abstain
  amount) and three genuine payments are held. One genuine scenario in the gated set is also held, so
  the friction gate (at most 10% of genuine held) has little headroom (1 of 12).
- **Rules are blunt.** For example, rule R03 treats "on a call + new payee + high value" as
  impersonation even when the call is the customer verifying the details.
- **Demo-grade operations.** No authentication; one worker; the audit log is a single local file
  (removing its newest records is not detectable); reference data is JSON files; domestic AUD only.
- **Not built:** database, streaming ingestion, case management, cloud deployment, real data, LLM
  features. See [evidence/decisions.md](evidence/decisions.md).

## Documentation

All design and evidence notes are in [`evidence/`](evidence/): [intent](evidence/intent.md),
[design](evidence/design.md), [verification](evidence/verify.md), [operations](evidence/operate.md),
[decisions](evidence/decisions.md), [evaluation report](evidence/eval-report.md) and
[agentic workflow](evidence/agentic-workflow.md). Agent instructions for this repo are in `CLAUDE.md`.
