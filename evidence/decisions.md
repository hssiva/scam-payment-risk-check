# Decisions

## D1: Strict typing and stable error codes for input validation
- Strings, booleans use strict mode (no coercion of `1` to `True`, or `123` to a string); amounts accept str, int, float or Decimal.
- Digit fields use `[0-9]` rather than `\d`, so non-ASCII digits are rejected.
- Issue messages are fixed text per code and never include input values (no account numbers, names or amounts in responses or logs).
- `DecisionResponse.reasons` must have at least one item (intent success criterion 4), including for `REJECT`.
