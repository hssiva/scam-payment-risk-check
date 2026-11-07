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
