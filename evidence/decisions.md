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

## D4: Risk model and degraded mode (P5)
- Reasons from the model are only attached when the score band is WARN or HOLD, so a clean ALLOW still reports `NO_RISK_SIGNALS`. If a band above ALLOW has no positive contribution, the reason is `M_SCORE_ELEVATED`.
- "Risk signal" in degraded mode means any signal the model weighs: mule payee, new payee, new device, active call, remote access, name mismatch, payee account younger than `young_account_days`, or amount ratio at or above `unusual_ratio`. This is deliberately broad (fail safe), and it holds every new-payee payment of `abstain_amount` or more while the model is down.
- The artifact stores `young_account_days` (value used at training) and the model uses that, not the live policy value, so a policy change cannot silently change what the model was trained on. Retraining picks up the policy value.
- Unknown customer gives `log_amount_ratio = 0` (ratio 1), and a missing payee age means not young; `data_complete=False` is handled by the abstain rule, not the model.
- The model is cached per process (`default_runtime`), unlike policy and reference data which `assess` still loads per call when not passed in.
- Training uses learning rate 2.0: at 0.5 the rare `remote_access_detected` coefficient had not converged after 800 epochs (1.56 vs 2.10 at convergence).

## D5: Evaluation gate (P6)
- Gate thresholds (0.90 scam catch, 0.10 genuine hold) live in `config/policy.toml` `[evaluation]` and in the `Policy` model (required keys), not in `evaluate.py`. `policy_version` was not changed because decisions are unaffected.
- Missing-data and invalid-request scenarios have `is_scam: null`: there is no ground truth, and counting deliberate abstain HOLDs as genuine payments held would fail the friction budget by construction. They still must match their expected decision, and the abstain ones are `must_hold`.
- A scenario that misses its label does not by itself fail the gate; only the six gates set the exit code. Mismatches are listed in the report ("Scenarios that did not match").
- Scenario labels were written before the first run and were not changed afterwards. G04 (genuine car purchase from a new dealer) is held (score 0.7284 against `score_hold` 0.70); it stays labelled ALLOW/WARN and shows as a mismatch.
- `expected_codes` is an optional extra field on scenarios, used for invalid-request and rule-driven cases so a scenario cannot pass for the wrong reason.

## D6: R07 and the known-limitations file (P6 follow-up)
- Hard cases the system gets wrong live in `scenarios_hard.jsonl`, outside the gates, so the gates keep measuring regressions on cases we expect to pass and the weaknesses stay visible in every report. Gate thresholds (0.90, 0.10) were not changed.
- R07 was chosen because it addresses a real gap (high-value payment to a young account for customers with large usual payments) without new thresholds. It does not fix any of X01-X06: those need different information (payee history depth, confirmation of payee, call context), not another threshold on the existing signals.
- Accepted cost: genuine high-value payments to accounts under 30 days old are now held (X06). Revisit if the friction budget gets tight; the thresholds involved are `young_account_days` and `high_value_amount`.
- Side finding: before R07, S19 was held in degraded mode (fail-safe) but only warned in normal mode, i.e. the service was stricter without its model. R07 removes that inconsistency for this case.
- S19 was added test-first: it failed gate 1 before the rule and passes after it. Existing labels were not touched.

## D8: Audit, API and deployment choices (P7)
- **No amounts in the audit trail (CLAUDE.md, confirmed by the reviewer):** the P7 brief listed `amount` in the audit record, but CLAUDE.md says never to log amounts, so the record does not contain it. It keeps `customer_id`, the masked account (last three digits), the decision, reasons, versions and a `request_hash`. Amounts, customer ids, account numbers and payee names are also kept out of the stdout logs. Reason texts only quote policy thresholds, never the payment's amount.
- `assess` stays pure and the audited path is a separate function so evaluation and tests never write audit records; the API and CLI only use the audited path.
- When the audit cannot be written, REJECT results also become HOLD (`AUDIT_UNAVAILABLE`), as the brief says HOLD for any audit failure; the API returns 200 for that HOLD, not 422.
- A damaged last audit line stops all appends (so all decisions HOLD) instead of silently continuing the chain: integrity over availability.
- `/health` is 200 even when degraded so orchestration does not restart a service that is still deciding safely; the body says `degraded` and why.
- Policy and reference data are loaded once at API startup; if they cannot be loaded the engine reloads per request and fails safe (HOLD), so the service recovers when the files are fixed. The model is loaded once per process.
- Compose binds `127.0.0.1:8000` (no authentication), one uvicorn worker, audit on a named volume.
- Test isolation: CLI tests detach the API's stdout log handler, which is installed process-wide when `scamcheck.api` is imported. Starlette's test client prints a deprecation warning suggesting `httpx2`; I did not add a dependency for it.
