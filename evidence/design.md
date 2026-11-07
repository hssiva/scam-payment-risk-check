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
