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
