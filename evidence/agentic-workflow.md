# Agentic workflow

Draft. Everything marked `[YOU: ...]` is for the author to fill in or delete before committing.
My own terminal log (the commands I ran and their output) is in `evidence/build-log.md`.

## Tools and models
- Claude Code (CLI) 2.1.319, model `claude-sonnet-5-5` for the whole build. Subagents: none.
- 211 tool calls: Bash 157, Write 37, Read 13, Edit 4. 2 tool errors.

## Transparency
- Architecture, intent, CLAUDE.md and prompts were planned before the timebox (about [YOU: N] hours). Intent and CLAUDE.md were the first commit.
- Environment setup (installing Python, GitHub CLI, downloading libraries) was outside the timebox. [YOU: confirm]
- Build time: 15:35 to 17:39 on 7 Nov 2026 = 2 h 4 min, from the first commit (intent and CLAUDE.md) to the web UI commit. [YOU: update the end time after the evidence commit.] The session report shows 136 min from first to last event, which includes my review time.

## How I set intent and constraints
- `evidence/intent.md`: problem, users, success criteria.
- `CLAUDE.md`: hard constraints (no network, no secrets, no pickle or eval, never log amounts, fail-safe HOLD, never weaken tests) and the workflow: implement, `make verify`, summarise, wait for my approval, commit.
- CLAUDE.md makes the agent wait for my approval before committing, and I approved every commit myself (9 approvals).

## How I broke down the work
Minutes = start of the step's prompt to its commit, so they include my review time. Follow-ups = my messages to the agent other than the step prompt and the approval.

| Step | Goal | Mins | My follow-ups | Out tokens | Tests | Commit |
|---|---|---|---|---|---|---|
| P1 | Scaffold | 2 | 0 | 3.7k | 1 | f207acb |
| P2 | Schema and validation | 7 | 0 | 11.6k | 50 | 25f96ee |
| P3 | Reference data and signals | 12 | 1 (generator must be in the repo) | 25.1k | 102 | c05ffab |
| P4 | Rules and engine | 16 | 3 (hard-coded values; fix them; my missing-file check on `load_policy`) | 43.4k | 180 | ec49fbe |
| P5 | Risk model and degrade mode | 17 | 1 (my model-tamper check) | 64.8k | 304 | 8099626 |
| P6 | Evaluation gate | 25 | 5 (audit of changes; 5 hard cases; non-gating file and R07; S13 label; revert) | 86.0k | 354 | 864d6a9 |
| P7 | API, CLI, audit log, Docker, CI | 19 (+3 for the concurrency note) | 2 (no amounts in the audit; concurrency note) | 89.7k | 481 | 63ee56a, 03157ce, 2f71e49 |
| P7b | Web UI | 15 | 1 (port 8000 already in use) | 51.9k | 516 | 695be74 |
| P8 | Evidence pack | in progress | 5 so far (overclaim grep; write this file; my build log; my review checklists; fix name matching) | [YOU: recompute at the end] | 534 | [YOU: after commit] |

## Representative prompts
- P1: "Read CLAUDE.md and evidence/intent.md first. Scaffold the project: ... Run `make setup` then `make verify` and show me the output. Do not commit yet."
- P3 follow-up: "The data generator isn't in the repo: scripts/ only has README.md. Add it as scripts/generate_reference_data.py, with a fixed seed, so it recreates exactly the current files in sample-data/reference/."
- End of P6: "Show me the report. Do not change thresholds or labels to make gates pass: if a gate fails, show me which scenarios fail and why, and wait."
- After the hard cases: "Move them to a separate non-gating file and Improve a rule with a fraud reason ... Don't adjust gate thresholds without a genuine reason, we don't want to adjust only to get green to pass"

## Where I intervened, and why
1. **Generator in the repo (P3).** `ls scripts/` showed only a README: the agent had made the reference data with a scratch script. I required it in `scripts/` with a fixed seed. Now a test regenerates the files byte for byte.
2. **Hard-coded values (P4).** I grepped `rules.py` and `engine.py` for numeric literals (found `_MAX_ID_LENGTH = 64`) and the tests for threshold literals (4999, 5000, 1000 and others). I changed `high_value_amount` from 5000 to 3000 ("impersonation amount usually is less than 5k", my comment in `policy.toml`). I asked "why are there hard coded values in engine.py?". Result: thresholds only in `policy.toml`, tests derive amounts from the policy, duplicate max-amount and id-length constants removed.
3. **Name matching (P3 code, checked by me).** I tried 8 name pairs. Two differed from what I expect: `J Smith` vs `John Smith` gave MATCH (I expected CLOSE) and `Smith, John` vs `John Smith` gave MISMATCH (I expected CLOSE). A MISMATCH raises R04 and the model's name-mismatch feature, so a genuine payee typed surname-first could be warned or held. **Fixed after my review, on my instruction:** initials and reordered words are now CLOSE, and the 0.80 threshold moved into `policy.toml`. The tests that encoded the old behaviour were changed because I changed the requirement. [YOU: one line on why you expect CLOSE.]
4. **Gate discipline (P6).** I reviewed the scenarios with my own script (it printed 37 of 38 and crashed on V05, whose request is a plain string; only G04 differed from its expected decision). I asked for a list of every label, threshold or rule change after the first evaluation run (none), then asked for 5 cases the system gets wrong. They went to a non-gating file, and R07 (young payee account plus high value gives HOLD) was added test-first. I tried to change the S13 label, then reverted it.
5. **No amounts in the audit log (P7).** When I called `/v1/audit` the records had an `amount` field. CLAUDE.md says never log amounts, so I told the agent to follow CLAUDE.md and the field was removed.
6. **A bug found through my check (P4).** I called `load_policy('config/does-not-exist.toml')` to test the missing-file path. My command imported it from the wrong module (`ImportError`). When the agent re-ran it correctly, a string path crashed with `AttributeError`, because the function only accepted a `Path`. Fixed, with a test.

## How I verified AI output
- `make verify`: lint, format check, tests and the scenario evaluation gate, run locally and in GitHub Actions (all runs passed when I last checked, 3 runs; I watched the first run with `gh run watch`).
- Review of the data and model with my own scripts: the reference data (10 customers with tenure, typical amount and known payees; every BSB is `000xxx`; every file labelled SYNTHETIC), the model's coefficients and held-out metrics, the model's SHA-256 against its `.sha256` file, and `sigmoid` at extreme inputs (1.0, 0.0, 0.5). The scenarios, expected against actual with reasons (37 of 38 printed; one mismatch, G04).
- Checks I ran myself, by step:

| Step | What I ran | What I saw |
|---|---|---|
| P2 | validation snippets | no timezone gives `NAIVE_TIMESTAMP`; 3 decimals gives `AMOUNT_TOO_PRECISE` |
| P3 | 8 name pairs | 2 differed from my expectation (item 3 above) |
| P4 | `pytest` while the agent was mid-change | 58 failed, then 179 passed once the tests were updated |
| P5 | my degrade script, then `echo " " >> models/risk_model_v1.json` | `MODEL_INTEGRITY_FAILED`, `DEGRADED_RULES_ONLY`, score `None`, the payment still HOLD |
| P7 | `curl` a scam and an invalid request | scam HOLD (0.9626); invalid REJECT 422 `INVALID_BSB` |
| P7 | searched the API log for the account number, amount and payee name | no matches |
| P7 | edited a copy of the audit file, then `scamcheck verify-audit` | `record edited`, first bad line 1 |
| P7 | `chmod 444` on the audit file, then `scamcheck assess` | HOLD with `AUDIT_UNAVAILABLE`, even for a genuine payment that scored 0.0137 |
| P7 | demo endpoint with demo mode off | 403 |
| P7 | `docker compose up --build`, `exec id`, health checks | runs as uid 10001 (`app`), healthy; `gh run watch`: CI success |
| P7b | the UI in the browser, with demo mode on | the server log shows the page and files loading, a scam assessed, the evaluation run, and the degrade toggle switched on and off (all HTTP 200); favicon 204 |
| P8 | `make verify`; grep for counts and percentages in the README and notes; grep for overclaiming words; extracted the README code blocks to check the commands | 516 passed, six gates pass; one match, "append-only guarantees" in `operate.md`, left as is |

- Checks the agent ran, which I reviewed: HTML injected through an unknown field name and `customer_id` shown as text in headless Chrome; amounts, account numbers and names searched for across the audit file, API output and logs for all 39 scenarios (none found); the README followed in a clean clone.

## What the agent got wrong (AI error or spec gap)
| Issue | Found by | AI error or spec gap |
|---|---|---|
| Data generator left out of the repo | my review (`ls scripts/`) | Spec gap: the prompt did not say generators must be committed |
| Name matching: initials gave MATCH and surname-first gave MISMATCH, against my expectation (CLOSE) | my own check | Spec gap: the prompt said "initials" but not the verdict. Fixed after my review. |
| Name-match "close" threshold (0.80) left as a hard-coded default with a TODO | my grep | AI error: CLAUDE.md says thresholds live in `policy.toml`. Fixed after my review. |
| Duplicated constants and test literals tied to the live policy (5000) | my grep and my threshold change | AI error: CLAUDE.md says thresholds live in `policy.toml` |
| `load_policy` crashed on a string path | my missing-file check, re-run by the agent | AI error |
| Audit record had `amount`, against CLAUDE.md | my API check | Spec gap: the prompt and CLAUDE.md conflicted. The agent flagged it but followed the prompt. |
| Training had not converged at the first learning rate (rare feature) | agent's own convergence check | AI error, caught before commit |
| `scamcheck eval --report` was rejected by the CLI | tests | AI error |
| `.dockerignore` missed nested `egg-info`; `/favicon.ico` 404 | image inspection; browser run | AI error |
| UI needed `demo_mode` in `/health`, which P7 did not include | building the UI | Spec gap |
| Notes said CI "has not been run" after it had | agent check with `gh` | AI error, fixed in the evidence pack |

## Tokens and time
Session report TOTAL (generated 17:54, before the evidence commit): 136.4 min, 199 turns, input 464, cache write 561,326, cache read 66,009,916, output 437,097 (thinking 168,502), subagent output 0, tool calls 211, tool errors 2.

Almost all tokens were cache reads (66.0M, the context re-read each turn); new output was about 0.44M tokens over the session, with no subagents. [YOU: re-run `session_report.py` just before you submit and replace this row.] The per-step output tokens above come from the transcript, split at my prompt times, because the report put everything in one segment: it skips pasted prompts, so the `[P1]` tags were not picked up.

## What I'd change next time
- In CLAUDE.md: any generated data must come from a committed seeded script, plus a test that regenerates it.
- In CLAUDE.md: a threshold lives only in `policy.toml`, and tests derive their amounts from it.
- State the name-matching verdicts (initials, word-order swaps, typos) in the prompt, as a table of examples, so the agent does not choose them.
- Say which wins when a prompt conflicts with CLAUDE.md. (CLAUDE.md wins.)
- Write labelled hard cases in the P6 prompt from the start, and say labels are fixed before the first run.
- Give the P7 prompt the full `/health` fields the UI needs.
- Type the `[P#]` tag outside the pasted block so `session_report.py` can split steps (two were also missing the opening bracket, "P3]" and "P8]").
- [YOU: your own reflections, e.g. what you would build next.]
