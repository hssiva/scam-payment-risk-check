# Verification

## Tests and results

### schemas tests (`tests/test_schemas.py`)
- Covers one valid request, amount boundaries, 31 invalid-input cases each mapped to its error code, multi-issue determinism, non-dict input, no value leakage in issues, and `DecisionResponse` rules.
- `make verify` run after this change: ruff check and format check clean, 50 tests passed (eval gate is still a placeholder).
