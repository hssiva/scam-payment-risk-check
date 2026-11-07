# Intent

## Problem
In an authorised push payment (APP) scam, the customer makes the payment themselves, because a
scammer has manipulated them. Typical tactics are impersonating a bank, police or a government
agency; fake investments; romance; invoice redirection; and remote-access "tech support" scams.
Authentication checks pass because the genuine customer is paying. The point of payment is
often the last chance to intervene.

## What this slice does
Given one payment request, `scamcheck` returns an explained decision:

| Decision | Meaning |
|---|---|
| `ALLOW` | Proceed |
| `WARN` | Show a targeted scam warning; customer must confirm |
| `HOLD` | Pause for analyst review |
| `REJECT` | Invalid request, not assessed |

Every request, including rejected ones, produces a tamper-evident audit record.

## Intended users
- **Payment systems** that call the service before releasing a payment (API).
- **Fraud analysts and engineers** who run, test and investigate decisions (web UI, CLI, audit log).
- **Model-risk and audit reviewers** who need to see why a decision was made (reason codes,
  versions and the audit chain).

## Assumptions
- Session signals (active phone call, remote-access tool detected, new device) are supplied by
  upstream systems, as they are in banks today.
- Customer history and payee details come from reference data. Here they're synthetic JSON files.
- Domestic AUD payments only.

## Constraints
- Runs locally from a clean checkout. No credentials, paid services or network.
- Synthetic data only.
- Deterministic and explainable: the same input gives the same decision, with reasons.
- Fail safe: when the service can't decide reliably, it holds the payment rather than allowing it.

## Out of scope
A rich UI (a thin demo UI is included), streaming ingestion, database, authentication, real data,
LLM features, case-management
integration, cloud deployment. The path to production is described in `design.md`.

## Success criteria
1. 100% of "must-hold" scam scenarios are held.
2. At least 90% of scam scenarios result in WARN or HOLD.
3. At most 10% of genuine scenarios are held (customer friction budget).
4. Every decision carries at least one reason code, model and policy versions, and the mode.
5. Invalid input is rejected with clear error codes. Missing data leads to HOLD (abstain). A bad
   model artifact switches the service to rules-only mode (degrade). All three are tested.
6. The audit chain verifies, and detects tampering.
7. `make verify` runs all checks with one command, locally and in CI.
