# Operations

## Configuration

## Logs

## Failure modes

### Reference data
- Files live in `sample-data/reference/` (SYNTHETIC). Set `SCAMCHECK_REFERENCE_DIR` to load them from another directory.
- A missing or malformed file raises `ReferenceDataError` at load time (callers must treat that as "cannot decide", i.e. HOLD).

### Policy and failure modes
- `config/policy.toml` sets `policy_version` ("2026.11.1") and the thresholds; `SCAMCHECK_POLICY_PATH` overrides the file. `policy_version` appears in every response.
- Fail-safe HOLD reason codes: `POLICY_UNAVAILABLE` (policy file missing/invalid; response `policy_version` is `UNKNOWN`), `REFERENCE_DATA_UNAVAILABLE`, `INTERNAL_ERROR`. `ABSTAIN_INSUFFICIENT_DATA` means the customer or payee is missing from reference data and the amount is at or above `abstain_amount`.

### Risk model and degraded mode
- Files: `models/risk_model_v1.json` and `models/risk_model_v1.sha256`; set `SCAMCHECK_MODEL_PATH` to use another artifact (its `.sha256` must sit beside it). Retrain with `python scripts/train_model.py` after any change to the feature code or training data.
- If the model is missing, fails the checksum, does not match the feature list or is malformed, the service keeps deciding in `DEGRADED_RULES_ONLY` mode and logs one WARNING (logger `scamcheck.model`, message includes the error code) when the process first loads it. The model is loaded once per process, so a restart is needed to pick up a repaired or replaced model.
- In degraded mode `risk_score` and `model_version` are null, and a payment at or above `abstain_amount` with any risk signal is held with reason `DEGRADED_FAILSAFE_HOLD`.
- The checksum catches accidental damage and edits to the artifact alone; anyone who can rewrite both files can replace the model.

### Running the evaluation gate
- `make eval` (also part of `make verify`) rewrites `evidence/eval-report.md`; commit the report with the change that caused it. Exit codes: 0 all gates pass, 1 a gate failed, 2 evaluation could not run (scenario file, policy, reference data or model unavailable; the model must be healthy for the normal-mode run).
- `python -m scamcheck.evaluate --scenarios PATH --report PATH` evaluates a different scenario file or writes the report elsewhere.

### Known-limitation scenarios
- `python -m scamcheck.evaluate --hard PATH` uses another known-limitation file (default `sample-data/scenarios_hard.jsonl`). The file must exist and be valid or evaluation exits 2; its results appear in the report only and never change the exit code.
- New rule `R07_YOUNG_PAYEE_HIGH_VALUE` appears in reason codes. It is controlled by the existing `young_account_days` and `high_value_amount` policy values.
