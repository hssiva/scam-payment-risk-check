# Decisions

Architecture decision records. Status of all: accepted, in force in this repository.

## ADR-1: No LLM in the core decision path

- **Context.** The service must run locally with no network, give the same decision for the same input, and explain every decision (`intent.md`). LLM features are listed as out of scope.
- **Decision.** Decisions come from seven transparent rules (R01 to R07) and a small logistic regression on seven features, trained in plain Python. Reasons are rule codes (`R*`) and the model's top two positive contributions (`M_*`). Rule, abstain, score, name-match and evaluation thresholds live in `config/policy.toml`.
- **Consequences.** Decisions are deterministic and testable (a test runs every scenario twice and compares). No keys, services or data leave the machine. The cost is recall: the system only sees what the signals expose, and the six known-limitation cases show it (low-signal marketplace scams, romance scams to a known payee, payments structured under the abstain amount, plus genuine payments that look risky). Closing those needs new information (payee history, confirmation of payee, call context), not another threshold.

## ADR-2: Model artifact is JSON with a SHA-256 sidecar, never pickle

- **Context.** CLAUDE.md forbids `pickle` and `eval`; loading a pickle can run arbitrary code. The model must also be checked before use.
- **Decision.** `models/risk_model_v1.json` holds coefficients, intercept, the exact feature list, `young_account_days` (the value used in training), the training-data hash and held-out metrics. `models/risk_model_v1.sha256` holds the file's SHA-256. At load the checksum and the feature list (order included) are verified.
- **Consequences.** The artifact is human-readable and safe to load, and training is reproducible (same data, same coefficients). Any failure degrades the service instead of crashing it (ADR-3). Limits: a checksum stored beside the artifact does not stop someone who can rewrite both (production would use signed artifacts in a registry), and the format only suits linear models.

## ADR-3: Fail safe: HOLD, never ALLOW, when the service cannot decide reliably

- **Context.** An unsafe default (releasing a payment on error) is the worst failure for an intervention control. `intent.md` requires invalid input (REJECT), missing data (abstain) and a bad model artifact (degrade) to be handled and tested; the audit fail-closed rule was added in the build.
- **Decision.** Missing customer or payee data at or above `abstain_amount` gives HOLD. If the model is unusable the mode is `DEGRADED_RULES_ONLY` and any risk signal at or above `abstain_amount` is held. Policy or reference data that cannot be loaded, and any unexpected exception, give HOLD. If the audit record cannot be written, the answer is HOLD (`AUDIT_UNAVAILABLE`), including for requests that would have been REJECT. Invalid input is REJECT (HTTP 422).
- **Consequences.** Safe but sometimes costly: degraded mode holds every new-payee payment of 1,000 AUD or more, and a damaged audit file blocks all decisions until repaired (integrity over availability). `/health` still returns 200 when degraded. Per CLAUDE.md the audit record has no amounts (the brief had listed one) and no payee names, and the account is masked to its last three digits. Failure table: `operate.md`.

## ADR-4: Reference data is validated JSON files, labelled SYNTHETIC

- **Context.** No real customer data, no network, and no database to run (`intent.md` constraints).
- **Decision.** Customers, payees and mule accounts are JSON files in `sample-data/reference/`, produced by a committed seeded script and loaded with strict validation (`_note` must say SYNTHETIC, BSBs only in `000xxx`, unknown fields rejected). Unknown customers and payees are explicit: the amount ratio is `None`, the payee counts as new, and `data_complete` is false, which drives abstain.
- **Consequences.** Simple, inspectable, reproducible (a test regenerates the files byte for byte). Not scalable, loaded at startup, and not shared across hosts. In production this becomes a managed store behind the same loader interface.

## ADR-5: What we did not build, and how the evaluation stays honest

- **Not built.** Authentication and authorisation; a database; streaming ingestion; real data or real confirmation of payee; case-management integration; cloud deployment and a delivery pipeline beyond `make verify` in GitHub Actions (shadow mode, champion/challenger, canary and model-risk sign-off are described in `design.md` as a proposal); off-box audit anchoring or WORM storage; multi-currency; multi-worker support for the demo switch.
- **Evaluation discipline.** Scenario labels were written before the first run and were not changed to make a gate pass; the gate limits (90% scams caught, 10% genuine held) are not tuned. Cases the system gets wrong live in a separate non-gating file and are reported on every run. One rule (R07, a young payee account with a high-value amount gives HOLD) was added test-first (scenario S19 failed before it and passes after) and its cost is accepted and visible: genuine high-value payments to accounts under 30 days old are held (case X06).
- **Consequences.** Anyone reading the repo can see what is demonstrated and what is not. Treat the metrics as evidence about this synthetic setup only.
