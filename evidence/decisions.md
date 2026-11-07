# Decisions

## D1: Strict typing and stable error codes for input validation
- Strings, booleans use strict mode (no coercion of `1` to `True`, or `123` to a string); amounts accept str, int, float or Decimal.
- Digit fields use `[0-9]` rather than `\d`, so non-ASCII digits are rejected.
- Issue messages are fixed text per code and never include input values (no account numbers, names or amounts in responses or logs).
- `DecisionResponse.reasons` must have at least one item (intent success criterion 4), including for `REJECT`.

## D2: Missing reference data is explicit, not guessed
- `amount_ratio` is `None` (not 0 or 1) when the customer is unknown, because any number would look like a real signal.
- An unknown customer counts as `new_payee=True` (no history means the payee cannot be known); `data_complete=False` lets later steps abstain with HOLD.
- Mule-list matching does not depend on `payees.json`, so a mule account missing from payee data is still flagged.
- The name-match close threshold (0.80) is a parameter with a TODO to move it into `config/policy.toml` once the policy loader exists.

## D3: Engine behaviour choices (P4)
- Abstain is a HOLD floor added alongside rule results, not an early exit, so the response lists every reason (e.g. abstain plus a mule hit).
- `max_amount` now comes from policy through a pydantic validation context; `validate_request` requires it as an argument and there is no default copy of the value in code. `schemas.ID_MAX_LENGTH` is the single source for the 64-character identifier limit (previously repeated in `schemas`, `reference` and `engine`).
- On REJECT, `request_id` is echoed only if the raw value is a string of 1-64 characters, otherwise `null`.
- Invalid input is rejected even when reference data is down (reference is loaded after validation); if the policy cannot load, even invalid input gets a fail-safe HOLD because `max_amount` is unknown.
- `decision_id` is a random UUID per call; decisions are deterministic, ids are not.
