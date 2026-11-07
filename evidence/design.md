# Design

## Components

### schemas (`src/scamcheck/schemas.py`)
- Pydantic v2 models `PaymentRequest` (with `Payee`, `Session`), `DecisionResponse`, `Reason`, `ValidationIssue`; all use `extra="forbid"`. `Decision` and `Mode` are `StrEnum`s.
- `validate_request(raw)` never raises. It maps pydantic errors to stable codes (e.g. `INVALID_BSB`, `AMOUNT_NOT_POSITIVE`, `UNKNOWN_FIELD`, `NAIVE_TIMESTAMP`) using fixed messages that never echo input values.
- Max amount is the constant `MAX_AMOUNT = 1_000_000` for now; it moves to `config/policy.toml` later.
