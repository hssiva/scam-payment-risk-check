# Verification

## What `make verify` runs

`ruff check` and `ruff format --check`, then `pytest`, then `make eval` (the evaluation gate; exit
code 1 if any gate fails), then `make evidence-check` (the evidence gate, below). `make verify` must
pass before every commit (CLAUDE.md).

## Actual results (latest run)

| Check | Result |
|---|---|
| `ruff check`, `ruff format --check` | clean |
| `pytest` | **610 passed**, 1 warning (Starlette's test client suggests an `httpx2` package; not adopted, no new dependencies) |
| Evaluation gates (39 gated scenarios) | **6 of 6 pass** (below) |
| Known-limitation scenarios (6, non-gating) | **0 of 6** match the correct answer |
| Evidence gate (`scripts/check_evidence.py`) | **4 of 4 pass** (evidence files, decision records, Conventional Commits, evaluation evidence current) |

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

## Test inventory (610)

| Area | Tests | What they cover |
|---|---|---|
| Schemas, reference data, signals | 50 + 19 + 42 | strict validation and error codes, malformed files, name matching (same words, initials, reordered words, typos), unknown customer or payee |
| Policy, rules, engine | 21 + 39 + 44 | thresholds from policy, each rule at its boundary, severity, abstain, fail-safe HOLD |
| Model, engine with model, training | 48 + 51 + 16 | tampered, missing, mismatched or malformed artifact degrades; degraded mode never ALLOWs a risky high-value payment; seeded and reproducible generators |
| Evaluation | 38 | scenario validation, each gate at its boundary and in failure, exit codes 0, 1, 2 |
| Audit, engine audit | 53 + 17 | chain, edit, removal, insertion and reorder detected, masking, no amounts, 200 threaded and 4 multi-process appends, write failure gives HOLD |
| API, CLI, UI | 35 + 16 + 35 | happy, 422 and degraded paths, no unmasked data, demo endpoint 403, CSP and no `innerHTML`, external-resource checks |
| Deployment files, data generators, version | 6 + 3 + 1 | Dockerfile, compose, CI workflow; generators reproduce committed files |
| Evidence gate | 76 | each of the four checks in a temporary git repo (passing and failing cases, boundaries, merge commits, shallow clones, uncommitted changes), the command line, standard library only and no shell, `make verify` and CI wiring |

## Local, pull request and pipeline

- **Local:** `make verify` (above). Not part of it, but done by hand: the API driven with curl (scam, genuine, audit verify, live tamper of the audit file); `docker compose up --build` (image builds, container healthy and non-root, same results, audit chain survives a restart, UI served with its headers); the web UI driven in headless Chrome by a scratch script (25 of 25 checks, including HTML injection attempts rendering as text and no CSP violations); a clean-clone check of the README (see the end of this file).
- **Pull request / push:** GitHub Actions (`.github/workflows/ci.yml`) runs `make setup` and `make verify` on Python 3.12, with `fetch-depth: 0` so the evidence gate can read the commit history. The three runs so far (the commits that added CI and later ones) all succeeded in about 20 seconds.
- **Pipeline (not built):** image build and scan, staging deployment, browser checks, shadow mode, canary. See `design.md`.

## Known gaps

- All data, labels and scenarios are synthetic and were written by the same author as the generators, so results are optimistic. The gated set has no scam that looks completely normal.
- Six hard cases are wrong by design of the signals: three missed scams (marketplace scam with no strong signal, romance scam to a known payee, payment just under the abstain amount) and three genuine payments held (call used to verify details, trading-name mismatch, a new high-value payment to a young account, the accepted cost of R07). The friction gate has little headroom.
- Only the direct dependencies are pinned exactly (`requirements*.txt`); transitive packages (starlette, anyio and others pip pulled in during the clean-clone Docker build) are not locked, so two builds can differ.
- The evidence gate checks form, not quality: line counts, heading counts, commit-subject format and commit order. Its check 4 only watches `src/`, `config/`, `models/` and `sample-data/scenarios.jsonl`; the reference data and `scenarios_hard.jsonl` also feed the evaluation report but are not watched.
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

## Evidence gate

`make evidence-check` runs `scripts/check_evidence.py` (standard library; `git` is called with fixed argument lists, never through a shell) and prints one PASS or FAIL line per check:

1. `evidence/intent.md`, `design.md`, `agentic-workflow.md`, `verify.md`, `operate.md` and `decisions.md` exist, each with at least 5 non-empty lines that are not headings.
2. `evidence/decisions.md` has at least 3 level-2 headings (decision records).
3. Every commit subject reachable from HEAD is `feat|fix|test|docs|chore|ci|refactor`, an optional scope, then `: description`. Merge commits are skipped.
4. The last commit touching `evidence/eval-report.md` is not older than the last commit touching `src/`, `config/`, `models/` or `sample-data/scenarios.jsonl` ("older" means the source commit is not an ancestor of the report commit, so commits in the same second are handled correctly).

Latest run on this repository (inside `make verify`):

```
PASS  1. Evidence files: all 6 files exist with at least 5 content lines
PASS  2. Decision records: 5 level-2 headings (need 3)
PASS  3. Conventional Commits: 14 commit subjects match (0 merges skipped)
PASS  4. Evaluation evidence current: evidence/eval-report.md has uncommitted changes (commit it with the code)
```

Two things behave differently from a plain reading of the checks, on purpose:
- **Uncommitted changes.** So that `make verify` can pass before a commit (CLAUDE.md), check 4 also looks at the working tree: if source files have uncommitted changes the report must have uncommitted changes too; if the report has uncommitted changes it passes. With a clean tree (as in CI) only commits are compared.
- **Shallow clones fail checks 3 and 4** with a clear message, instead of silently checking a truncated history. CI uses `fetch-depth: 0`.

Finding: on a clean clone of the commit before the policy bump, check 4 **failed**, because `evidence/eval-report.md` was last committed in `864d6a9` and `src/` changed afterwards in `533e3af`, although the report's content had not changed (the evaluation results were identical). The bump to `policy_version` 2026.11.2 changes the report ("Policy version"), so committing the bump with the regenerated report makes check 4 pass (simulated in a throwaway clone). Consequence of the check as specified: any source commit that leaves the evaluation results unchanged also fails check 4, until `evidence/eval-report.md` is touched. A report fingerprint of the inputs (a hash of `src/`, `config/`, `models/` and the scenarios, printed in the report) would make regenerating it necessary and sufficient; that is not built.
