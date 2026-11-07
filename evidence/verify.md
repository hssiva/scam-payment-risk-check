# Verification

## What `make verify` runs

`ruff check` and `ruff format --check`, then `pytest`, then `make eval` (the evaluation gate; exit
code 1 if any gate fails). `make verify` must pass before every commit (CLAUDE.md).

## Actual results (latest run)

| Check | Result |
|---|---|
| `ruff check`, `ruff format --check` | clean |
| `pytest` | **534 passed**, 1 warning (Starlette's test client suggests an `httpx2` package; not adopted, no new dependencies) |
| Evaluation gates (39 gated scenarios) | **6 of 6 pass** (below) |
| Known-limitation scenarios (6, non-gating) | **0 of 6** match the correct answer |

Evaluation gates (`evidence/eval-report.md` has the per-scenario table):

| Gate | Result |
|---|---|
| 1. Every `must_hold` scenario is HOLD | 14/14 |
| 2. Scams warned or held (need at least 90%) | 19/19 |
| 3. Genuine payments held (allow at most 10%) | 1/12 (8.3%): G04, a genuine car purchase from a new payee, scored 0.7284 against the 0.70 hold line |
| 4. Every non-REJECT decision has a reason | 34/34 |
| 5. Two runs give identical decisions | 39/39 |
| 6. Tampered model copy: must-hold still HOLD | tamper detected; 14/14 held in `DEGRADED_RULES_ONLY` |

Risk model `risk_model_v1` on its held-out split (1000 payments, 150 scams, SYNTHETIC): PR-AUC (average precision) 0.9127; at 0.50 precision 0.8626 / recall 0.7533; at `score_warn` 0.35 precision 0.7987 / recall 0.7933; at `score_hold` 0.70 precision 0.9794 / recall 0.6333. Retraining twice gave identical coefficients.

## Test inventory (534)

| Area | Tests | What they cover |
|---|---|---|
| Schemas, reference data, signals | 50 + 19 + 42 | strict validation and error codes, malformed files, name matching (same words, initials, reordered words, typos), unknown customer or payee |
| Policy, rules, engine | 21 + 39 + 44 | thresholds from policy, each rule at its boundary, severity, abstain, fail-safe HOLD |
| Model, engine with model, training | 48 + 51 + 16 | tampered, missing, mismatched or malformed artifact degrades; degraded mode never ALLOWs a risky high-value payment; seeded and reproducible generators |
| Evaluation | 38 | scenario validation, each gate at its boundary and in failure, exit codes 0, 1, 2 |
| Audit, engine audit | 53 + 17 | chain, edit, removal, insertion and reorder detected, masking, no amounts, 200 threaded and 4 multi-process appends, write failure gives HOLD |
| API, CLI, UI | 35 + 16 + 35 | happy, 422 and degraded paths, no unmasked data, demo endpoint 403, CSP and no `innerHTML`, external-resource checks |
| Deployment files, data generators, version | 6 + 3 + 1 | Dockerfile, compose, CI workflow; generators reproduce committed files |

## Local, pull request and pipeline

- **Local:** `make verify` (above). Not part of it, but done by hand: the API driven with curl (scam, genuine, audit verify, live tamper of the audit file); `docker compose up --build` (image builds, container healthy and non-root, same results, audit chain survives a restart, UI served with its headers); the web UI driven in headless Chrome by a scratch script (25 of 25 checks, including HTML injection attempts rendering as text and no CSP violations); a clean-clone check of the README (see the end of this file).
- **Pull request / push:** GitHub Actions (`.github/workflows/ci.yml`) runs `make setup` and `make verify` on Python 3.12. The three runs so far (the commits that added CI and later ones) all succeeded in about 20 seconds.
- **Pipeline (not built):** image build and scan, staging deployment, browser checks, shadow mode, canary. See `design.md`.

## Known gaps

- All data, labels and scenarios are synthetic and were written by the same author as the generators, so results are optimistic. The gated set has no scam that looks completely normal.
- Six hard cases are wrong by design of the signals: three missed scams (marketplace scam with no strong signal, romance scam to a known payee, payment just under the abstain amount) and three genuine payments held (call used to verify details, trading-name mismatch, a new high-value payment to a young account, the accepted cost of R07). The friction gate has little headroom.
- Only the direct dependencies are pinned exactly (`requirements*.txt`); transitive packages (starlette, anyio and others pip pulled in during the clean-clone Docker build) are not locked, so two builds can differ.
- No measurement of test coverage, no load or latency testing beyond the per-request `latency_ms`, no dependency vulnerability scan.
- Browser behaviour is checked by a scratch script, not a committed test. CI runs `make verify` only: it does not build the Docker image or start the service.
- Audit chain limits: removal of the newest records, or a whole-file rewrite with a recomputed chain, is not detected; multi-host and network filesystems are untested.
- No authentication to test. `make verify` leaves `evidence/eval-report.md` rewritten; commit it with the change that caused it.

## Clean-clone check of the README (2026-11-07, macOS)

A fresh `git clone` of this repository at `695be74` (so no `.venv`, no `audit/`, no build cache for the
Python route) plus the then-uncommitted README and evidence notes, followed in README order:

| README step | Result |
|---|---|
| Prerequisites | Docker 29.8.2 with Compose v5.5.0, Python 3.12.16, GNU Make 3.81 present |
| `docker compose up --build` | cold rebuild with `--no-cache` took about 11 s; container healthy, runs as `app`; `/`, `/docs`, `/health` and `/static/app.js` all HTTP 200 |
| Demo steps 1 to 5 (UI, demo mode off) | 8 of 8 checks: S01 red HOLD (0.9626), G01 green ALLOW, V01 grey REJECT with error codes, Verify chain `OK ... (3 records)`, evaluation six PASS gates and 39 rows, toggle not rendered, no console or CSP errors |
| Demo step 6 (uncomment the compose line, `docker compose up --build`) | 11 of 11 checks: toggle rendered, amber DEGRADED banner, S01 still HELD with no score in `DEGRADED_RULES_ONLY`, back to NORMAL |
| `make setup` | exit 0, about 20 s |
| `make verify` | first attempt failed one test (below); after reverting the compose edit: exit 0, 516 passed (before the name-matching change below), six of six gates pass, `eval-report.md` byte-identical to the committed one |
| CLI `assess`, `verify-audit`, `health`, `eval` | all work; the example output in the README matches the real output apart from `decision_id` and `latency_ms` |
| `SCAMCHECK_DEMO_MODE=1 make run-api`, `curl` example, UI demo steps 1 to 6 | API example returns HOLD 0.9626; 11 of 11 UI checks; `verify-audit` OK afterwards |
| README links and `make` targets | 12 relative links resolve; every named `make` target and CLI subcommand exists |

Findings: (1) `make verify` fails `test_compose_builds_and_publishes_port_8000_with_demo_mode_off` if README demo step 6 has been done and not reverted, because that test guards the committed default; the README now says to revert. (2) Transitive dependencies are not pinned (see known gaps). (3) Cosmetic: `verify-audit` prints "1 records" for a single record.

Differences from following the README literally: `docker compose up --build -d` (detached) so the shell was not blocked; the example request was saved in a scratch folder instead of `/tmp/request.json`; the UI steps were clicked by a scripted headless Chrome, not by hand; the clone came from the local repository (the README was not yet pushed). Not covered: Docker on Linux, Windows (not supported), cloning from GitHub. The Python route runs on Linux in GitHub Actions (`ubuntu-latest`).

## Name matching and threshold change (after review)

My own review found two of eight name pairs differing from what I expect: initials gave MATCH and a surname-first name gave MISMATCH. Changed on my instruction: initials and reordered words ("Smith, John", "Smith John Paul" for "John Paul Smith") are now CLOSE; MATCH needs the same words; typos are still CLOSE by similarity. The 0.80 similarity threshold moved from a default in `signals.py` into `config/policy.toml` as `name_close_threshold` (validated, required, passed to the signals by the engine); no copy of the value remains in code.

- Before and after, 18 name pairs: 9 changed, all to CLOSE (initials only 4, reordered words only 4, both 1); the rest (exact, typo, `K Smith`, `Jane Doe`, `Smith Holdings`, `Pat O'Brien`) are unchanged.
- Tests: 516 to 534. The old expectations for initials (MATCH) and `Smith John` (MISMATCH) were changed because the requirement changed, not to make them pass; new cases cover surname-first, three-word names, initials with reordering, the threshold being used, the policy key being validated, and the engine (surname-first and initials no longer raise R04; a stricter policy turns a typo into a mismatch).
- `make verify`: clean, 534 passed, six of six gates pass. `evidence/eval-report.md` is byte-identical to before, so no scenario result changed. The evaluation set has no surname-first scenario; the engine tests cover that case.
- `policy_version` was bumped from `2026.11.1` to `2026.11.2` in the commit after this change, because decisions for some names changed and the policy file gained a key. (R07 was added under `2026.11.1` without a bump.)
