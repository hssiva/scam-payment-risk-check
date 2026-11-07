# Design

## Components

### schemas (`src/scamcheck/schemas.py`)
- Pydantic v2 models `PaymentRequest` (with `Payee`, `Session`), `DecisionResponse`, `Reason`, `ValidationIssue`; all use `extra="forbid"`. `Decision` and `Mode` are `StrEnum`s.
- `validate_request(raw)` never raises. It maps pydantic errors to stable codes (e.g. `INVALID_BSB`, `AMOUNT_NOT_POSITIVE`, `UNKNOWN_FIELD`, `NAIVE_TIMESTAMP`) using fixed messages that never echo input values.
- Max amount is the constant `MAX_AMOUNT = 1_000_000` for now; it moves to `config/policy.toml` later.

### reference (`src/scamcheck/reference.py`)
- Loads `customers.json`, `payees.json` and `mule_accounts.json` into frozen dataclasses (`ReferenceData` with `customer()`, `payee()`, `is_mule()` lookups). Payees are keyed `"bsb-account"`.
- Files are validated strictly with pydantic: `_note` must contain `SYNTHETIC`, BSBs must be in the `000xxx` range, unknown fields are rejected, and amounts are parsed as `Decimal` (no floats).
- Typed errors: `ReferenceFileMissingError` and `ReferenceFileMalformedError` (both `ReferenceDataError`, with `.path`). Messages give the file and field path, never data values.

### signals (`src/scamcheck/signals.py`)
- `build_signals(request, reference)` returns a frozen `Signals` dataclass: `new_payee`, `amount_ratio`, `payee_account_age_days`, `payee_name_match`, `payee_on_mule_list`, the three session flags and `data_complete`.
- Name match: normalise (case, punctuation, spaces, apostrophes), then `MATCH` for equal tokens or initials, `CLOSE` if the difflib ratio is at least 0.80, else `MISMATCH`; `UNAVAILABLE` when the payee is not in reference data.
- Unknown customer: `amount_ratio` is `None`, `new_payee` is `True`, `data_complete` is `False`. Unknown payee: age is `None`, name match is `UNAVAILABLE`, `data_complete` is `False`.
