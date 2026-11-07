# Verification

## Tests and results

### schemas tests (`tests/test_schemas.py`)
- Covers one valid request, amount boundaries, 31 invalid-input cases each mapped to its error code, multi-issue determinism, non-dict input, no value leakage in issues, and `DecisionResponse` rules.
- `make verify` run after this change: ruff check and format check clean, 50 tests passed (eval gate is still a placeholder).

### reference and signals tests
- `tests/test_reference.py`: sample files load (10 customers, 30 payees, 3 mules, all `000xxx`, all labelled SYNTHETIC), lookups, missing file, directory-instead-of-file, 9 malformed-file cases, duplicate customer IDs, no data values in error messages, env-var directory override.
- `tests/test_signals.py`: each signal, unknown customer, unknown payee, mule account absent from payee data, and 16 name-matching cases plus an adjustable threshold.
- `make verify` after this change: ruff check and format check clean, 99 tests passed (eval gate is still a placeholder).

### policy, rules and engine tests
- `tests/test_policy.py` (13): real policy values, missing file, invalid TOML, 8 invalid-value cases, env override.
- `tests/test_rules.py` (24): each rule fires at its boundary and not just below it, severity ordering, rule order, no amounts in reason text.
- `tests/test_engine.py` (39): clean ALLOW, one test per rule through `assess`, severity ordering, abstain (unknown customer, unknown payee, below threshold, complete data), REJECT cases, fail-safe HOLD for policy/reference/unexpected errors, determinism, input not mutated. Threshold amounts are derived from the loaded policy (not literals), and tests with modified policies show that `high_value_amount`, `abstain_amount`, `max_amount` and `policy_version` really come from the policy.
- `make verify` after this change: ruff check and format check clean, 179 tests passed (eval gate is still a placeholder).

### model, degraded mode and training tests
- `tests/test_model.py` (48): committed artifact loads and records its data hash; tampered artifact, wrong/empty/missing checksum, missing model file, 4 feature-mismatch variants and 10 malformed-artifact cases all degrade with the right code; degrade logged once at WARNING; feature extraction; probability, determinism, top-2 reasons and tie-breaks.
- `tests/test_engine_model.py` (51): score bands against policy thresholds, model-only WARN/HOLD, most severe of rules and model, degraded-mode HOLD for 8 risk signals x 3 amounts (never ALLOW), exact `abstain_amount` boundary, tamper/missing model end to end, one WARNING across 5 requests, no request data in the log.
- `tests/test_training_scripts.py` (16): generator is seeded and reproduces the committed CSV byte for byte; trainer metrics, split and determinism; artifact round-trips through the model loader; committed artifact matches the committed data.
- Existing rule-focused tests in `tests/test_engine.py` now run with a neutral model (zero weights) so they still test the rules alone.
- Held-out metrics for `risk_model_v1` (1000 payments, 150 scams, SYNTHETIC data): PR-AUC (average precision) 0.9127; at 0.50 precision 0.8626, recall 0.7533; at `score_warn` 0.35 precision 0.7987, recall 0.7933; at `score_hold` 0.70 precision 0.9794, recall 0.6333. Retraining twice gave identical coefficients.
- `make verify` after this change: ruff check and format check clean, 304 tests passed (eval gate is still a placeholder).
