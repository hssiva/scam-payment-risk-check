#!/usr/bin/env python3
"""Evidence gate: the repository checks its own engineering evidence. Standard library only.

Checks (each printed as PASS or FAIL with a one-line reason; exit 1 if any fails):
  1. evidence/intent.md, design.md, agentic-workflow.md, verify.md, operate.md and decisions.md
     exist and each has at least 5 non-empty lines that are not headings.
  2. evidence/decisions.md has at least 3 decision records (level-2 headings).
  3. Every commit subject reachable from HEAD is a Conventional Commit
     (feat|fix|test|docs|chore|ci|refactor, optional scope, optional "!", then ": description").
     Merge commits are allowed.
  4. The last commit touching evidence/eval-report.md is not older than the last commit touching
     src/, config/, models/ or sample-data/scenarios.jsonl (the evaluation evidence is current).

Git is run through ``subprocess`` with fixed argument lists (never through a shell). Checks 3 and
4 need the full history: a shallow clone fails them (in GitHub Actions use ``fetch-depth: 0``).

Check 4 also looks at uncommitted changes, so that it can run before a commit: if source files have
uncommitted changes the report must have uncommitted changes too (to be committed together with
them). With a clean working tree it compares commits only.

Usage: python scripts/check_evidence.py [--repo PATH]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REQUIRED_FILES = (
    "intent.md",
    "design.md",
    "agentic-workflow.md",
    "verify.md",
    "operate.md",
    "decisions.md",
)
MIN_CONTENT_LINES = 5
MIN_DECISIONS = 3
SUBJECT_RE = re.compile(r"^(feat|fix|test|docs|chore|ci|refactor)(\([^()\s][^()]*\))?!?: \S")
EVAL_REPORT = "evidence/eval-report.md"
SOURCE_PATHS = ("src", "config", "models", "sample-data/scenarios.jsonl")
_HEADING_RE = re.compile(r"^#{1,6}(\s|$)")
_LEVEL2_RE = re.compile(r"^## +\S")
_MAX_LISTED = 3


@dataclass(frozen=True)
class Result:
    number: int
    name: str
    ok: bool
    reason: str

    def line(self) -> str:
        return f"{'PASS' if self.ok else 'FAIL'}  {self.number}. {self.name}: {self.reason}"


class GitError(Exception):
    """Git is unavailable or the history cannot be used."""


# --- markdown helpers ----------------------------------------------------------------------------


def _outside_fences(text: str) -> list[str]:
    """Lines that are not inside a fenced code block (the fence lines themselves are kept)."""
    kept: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            kept.append(line)
        elif not in_fence:
            kept.append(line)
    return kept


def count_content_lines(text: str) -> int:
    """Non-empty lines that are not headings (a '#' line inside a code block is content)."""
    in_fence = False
    count = 0
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            count += 1
        elif line.strip() and (in_fence or not _HEADING_RE.match(line)):
            count += 1
    return count


def count_level2_headings(text: str) -> int:
    return sum(1 for line in _outside_fences(text) if _LEVEL2_RE.match(line))


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# --- checks 1 and 2 (files) ----------------------------------------------------------------------


def check_files(repo: Path) -> Result:
    problems: list[str] = []
    for name in REQUIRED_FILES:
        path = repo / "evidence" / name
        if not path.is_file():
            problems.append(f"{name} is missing")
            continue
        text = _read(path)
        if text is None:
            problems.append(f"{name} cannot be read")
            continue
        found = count_content_lines(text)
        if found < MIN_CONTENT_LINES:
            problems.append(f"{name} has {found} content lines (need {MIN_CONTENT_LINES})")
    reason = (
        f"all {len(REQUIRED_FILES)} files exist with at least {MIN_CONTENT_LINES} content lines"
        if not problems
        else "; ".join(problems)
    )
    return Result(1, "Evidence files", not problems, reason)


def check_decisions(repo: Path) -> Result:
    text = _read(repo / "evidence" / "decisions.md")
    if text is None:
        return Result(
            2, "Decision records", False, "evidence/decisions.md is missing or unreadable"
        )
    found = count_level2_headings(text)
    ok = found >= MIN_DECISIONS
    return Result(2, "Decision records", ok, f"{found} level-2 headings (need {MIN_DECISIONS})")


# --- git helpers ---------------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # fixed argument list, no shell
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc


def _git_out(repo: Path, *args: str) -> str:
    done = _git(repo, *args)
    if done.returncode != 0:
        first = (done.stderr.strip().splitlines() or ["git failed"])[0]
        raise GitError(first)
    return done.stdout.strip()


def _require_history(repo: Path) -> None:
    if _git(repo, "rev-parse", "--git-dir").returncode != 0:
        raise GitError(f"{repo} is not a git repository")
    if _git(repo, "rev-parse", "--verify", "--quiet", "HEAD").returncode != 0:
        raise GitError("the repository has no commits yet")
    if _git_out(repo, "rev-parse", "--is-shallow-repository") == "true":
        raise GitError("shallow clone: fetch the full history (GitHub Actions: fetch-depth: 0)")


# --- check 3 (commit subjects) --------------------------------------------------------------------


def check_commit_subjects(repo: Path) -> Result:
    name = "Conventional Commits"
    _require_history(repo)
    log = _git_out(repo, "log", "--format=%H%x1f%P%x1f%s", "HEAD")
    checked, merges = 0, 0
    bad: list[str] = []
    for line in log.splitlines():
        sha, parents, subject = line.split("\x1f", 2)
        if len(parents.split()) > 1:
            merges += 1
            continue
        checked += 1
        if not SUBJECT_RE.match(subject):
            bad.append(f"{sha[:7]} {subject[:50]!r}")
    if not bad:
        return Result(3, name, True, f"{checked} commit subjects match ({merges} merges skipped)")
    shown = "; ".join(bad[:_MAX_LISTED]) + (" ..." if len(bad) > _MAX_LISTED else "")
    return Result(3, name, False, f"{len(bad)} of {checked} subjects do not match: {shown}")


# --- check 4 (evaluation evidence is current) -----------------------------------------------------


def _pending(repo: Path, paths: tuple[str, ...]) -> bool:
    return bool(_git_out(repo, "status", "--porcelain", "--", *paths))


def _last_commit(repo: Path, paths: tuple[str, ...]) -> str | None:
    return _git_out(repo, "log", "-1", "--format=%H", "--", *paths) or None


def _is_ancestor(repo: Path, older: str, newer: str) -> bool:
    code = _git(repo, "merge-base", "--is-ancestor", older, newer).returncode
    if code not in (0, 1):
        raise GitError("cannot compare commits")
    return code == 0


def check_eval_current(repo: Path) -> Result:
    name = "Evaluation evidence current"
    _require_history(repo)
    report = (EVAL_REPORT,)
    report_pending = _pending(repo, report)
    source_pending = _pending(repo, SOURCE_PATHS)
    report_commit = _last_commit(repo, report)
    source_commit = _last_commit(repo, SOURCE_PATHS)

    if report_commit is None and not report_pending:
        return Result(4, name, False, f"{EVAL_REPORT} has never been committed")
    if source_pending and not report_pending:
        return Result(
            4,
            name,
            False,
            f"uncommitted changes in {', '.join(SOURCE_PATHS)} but {EVAL_REPORT} is unchanged: "
            "run make eval and commit the report with the change",
        )
    if report_pending:
        return Result(
            4, name, True, f"{EVAL_REPORT} has uncommitted changes (commit it with the code)"
        )
    if source_commit is None:
        return Result(4, name, True, "no source commits to compare with")
    if report_commit is None:  # only reachable if the report is pending, handled above
        return Result(4, name, False, f"{EVAL_REPORT} has never been committed")
    if _is_ancestor(repo, source_commit, report_commit):
        return Result(
            4,
            name,
            True,
            f"report last changed in {report_commit[:7]}, source in {source_commit[:7]} "
            "(not newer)",
        )
    subject = _git_out(repo, "log", "-1", "--format=%s", source_commit)
    return Result(
        4,
        name,
        False,
        f"source changed in {source_commit[:7]} ({subject[:40]!r}) after the report's last change "
        f"in {report_commit[:7]}: run make eval and commit {EVAL_REPORT}",
    )


# --- runner --------------------------------------------------------------------------------------

CHECKS: tuple[tuple[int, str, Callable[[Path], Result]], ...] = (
    (1, "Evidence files", check_files),
    (2, "Decision records", check_decisions),
    (3, "Conventional Commits", check_commit_subjects),
    (4, "Evaluation evidence current", check_eval_current),
)


def run_checks(repo: Path) -> list[Result]:
    results: list[Result] = []
    for number, name, check in CHECKS:
        try:
            results.append(check(repo))
        except GitError as exc:
            results.append(Result(number, name, False, str(exc)))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the repository's engineering evidence.")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    results = run_checks(args.repo)
    for result in results:
        print(result.line())
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
