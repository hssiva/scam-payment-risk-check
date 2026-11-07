# scamcheck: instructions for AI coding agents

This file sets intent and constraints for agents working in this repository. A human engineer
reviews and approves every change. Read `evidence/intent.md` before starting any task.

## What we are building
A local, explainable payment scam risk check. Input: a payment request (JSON). Output: one of
`ALLOW`, `WARN`, `HOLD` (or `REJECT` for invalid input) with reason codes, plus an append-only
audit record. Synthetic data only.

## Hard constraints
- Python 3.12. Runtime dependencies: `fastapi`, `uvicorn`, `pydantic` (v2) only. Dev: `pytest`,
  `httpx`, `ruff`. **Ask before adding any other dependency.** Pin exact versions.
- No network calls at runtime. No API keys, secrets or credentials anywhere.
- No real customer data and no real bank names or branding. Label all data files as SYNTHETIC.
- Do not use `pickle` or `eval`. Model artifacts are JSON.
- Never log account numbers, payee names or amounts. Mask account numbers in the audit log
  (last 3 digits only).
- Fail safe: if the service cannot decide reliably, it must return `HOLD`, never `ALLOW`.

## Engineering rules
- Layout: `src/scamcheck/` (package), `tests/`, `sample-data/`, `config/`, `models/`,
  `scripts/`, `evidence/`.
- Every module gets unit tests in the same change. Test behaviour, including failure paths.
- **Never weaken, skip or delete a test to make it pass.** If a test looks wrong, stop and
  explain why.
- Keep thresholds and rules in `config/policy.toml`, not hard-coded.
- Type hints everywhere. Keep functions small. Prefer the standard library.
- `make verify` must pass before every commit. It runs: `ruff check`, `ruff format --check`,
  `pytest`, and the scenario evaluation gate (once it exists).

## Workflow for each task
1. Restate the task and list the files you will create or change.
2. Implement, then run `make verify` and show the result.
3. Summarise: what changed, test results, any assumption you made, anything you are unsure of.
4. **Wait for the human's approval before committing.** Use Conventional Commits
   (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`). One logical change per commit, then
   `git push`.
5. If you made a design decision, add a short entry to `evidence/decisions.md`.
6. Documentation as you go: after each task, add 1–3 factual lines about what you just built to
   the relevant evidence file (`design.md` for components, `verify.md` for tests and results,
   `operate.md` for config, logs and failure modes). Only real facts; no claims about results
   you have not run.
