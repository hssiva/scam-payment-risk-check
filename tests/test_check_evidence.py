import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_evidence.py"
FILES = ("intent.md", "design.md", "agentic-workflow.md", "verify.md", "operate.md", "decisions.md")
GOOD = "# Title\n\nline one\nline two\nline three\nline four\nline five\n"
GOOD_DECISIONS = "# Decisions\n\n## A\nwhy\nso\n\n## B\nwhy\nso\n\n## C\nwhy\nso\n"


@pytest.fixture(scope="module")
def ce() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_evidence", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_evidence"] = module  # dataclasses with postponed annotations need this
    spec.loader.exec_module(module)
    return module


# --- helpers to build a throwaway git repository -----------------------------------------------


GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args],
        capture_output=True,
        text=True,
        check=True,
        env=GIT_ENV,
    )
    return done.stdout.strip()


def new_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    return repo


def write(repo: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def commit(repo: Path, subject: str, files: dict[str, str] | None = None) -> None:
    write(repo, files or {})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", subject)


def decisions_text(count: int) -> str:
    return "# D\n" + "".join(f"## R{i}\ntext\n" for i in range(count))


def evidence_files(**overrides: str) -> dict[str, str]:
    files = {f"evidence/{n}": (GOOD_DECISIONS if n == "decisions.md" else GOOD) for n in FILES}
    files.update({f"evidence/{k}": v for k, v in overrides.items()})
    return files


# --- check 1: evidence files -------------------------------------------------------------------


def test_files_pass_when_all_exist_with_enough_content(ce: ModuleType, tmp_path: Path) -> None:
    write(tmp_path, evidence_files())
    result = ce.check_files(tmp_path)
    assert result.ok
    assert "all 6 files" in result.reason


@pytest.mark.parametrize("name", FILES)
def test_files_fail_when_one_is_missing(ce: ModuleType, tmp_path: Path, name: str) -> None:
    write(tmp_path, evidence_files())
    (tmp_path / "evidence" / name).unlink()
    result = ce.check_files(tmp_path)
    assert not result.ok
    assert f"{name} is missing" in result.reason


def test_files_fail_when_a_file_is_only_headings(ce: ModuleType, tmp_path: Path) -> None:
    write(tmp_path, evidence_files(**{"agentic-workflow.md": "# Agentic workflow\n\n## Tools\n"}))
    result = ce.check_files(tmp_path)
    assert not result.ok
    assert "agentic-workflow.md has 0 content lines" in result.reason


def test_files_boundary_is_five_content_lines(ce: ModuleType, tmp_path: Path) -> None:
    four = "# T\n" + "x\n" * 4
    five = "# T\n" + "x\n" * 5
    write(tmp_path, evidence_files(**{"verify.md": four}))
    assert not ce.check_files(tmp_path).ok
    write(tmp_path, evidence_files(**{"verify.md": five}))
    assert ce.check_files(tmp_path).ok


def test_blank_lines_and_headings_do_not_count(ce: ModuleType) -> None:
    text = "# H1\n\n## H2\n\n   \n### H3\ncontent\n\n#### H4\n"
    assert ce.count_content_lines(text) == 1


def test_table_rows_lists_and_hash_lines_inside_code_blocks_count(ce: ModuleType) -> None:
    text = "# T\n| a | b |\n|---|---|\n- item\n```\n# a comment inside code\n```\n"
    assert ce.count_content_lines(text) == 6


def test_files_report_every_problem_in_one_line(ce: ModuleType, tmp_path: Path) -> None:
    write(tmp_path, evidence_files(**{"design.md": "# D\n"}))
    (tmp_path / "evidence" / "operate.md").unlink()
    result = ce.check_files(tmp_path)
    assert not result.ok
    assert "design.md has 0 content lines" in result.reason
    assert "operate.md is missing" in result.reason
    assert "\n" not in result.reason


def test_files_fail_for_an_unreadable_file(ce: ModuleType, tmp_path: Path) -> None:
    write(tmp_path, evidence_files())
    (tmp_path / "evidence" / "intent.md").write_bytes(b"\xff\xfe\x00bad")
    result = ce.check_files(tmp_path)
    assert not result.ok
    assert "intent.md cannot be read" in result.reason


def test_files_fail_in_an_empty_folder(ce: ModuleType, tmp_path: Path) -> None:
    assert not ce.check_files(tmp_path).ok


# --- check 2: decision records -----------------------------------------------------------------


@pytest.mark.parametrize("count", [3, 4, 5])
def test_decisions_pass_with_three_or_more_records(
    ce: ModuleType, tmp_path: Path, count: int
) -> None:
    write(
        tmp_path,
        {"evidence/decisions.md": "# D\n" + "".join(f"## R{i}\ntext\n" for i in range(count))},
    )
    assert ce.check_decisions(tmp_path).ok


@pytest.mark.parametrize("count", [0, 1, 2])
def test_decisions_fail_with_fewer_than_three(ce: ModuleType, tmp_path: Path, count: int) -> None:
    write(
        tmp_path,
        {"evidence/decisions.md": "# D\n" + "".join(f"## R{i}\ntext\n" for i in range(count))},
    )
    result = ce.check_decisions(tmp_path)
    assert not result.ok
    assert f"{count} level-2 headings" in result.reason


def test_only_level_two_headings_count_as_records(ce: ModuleType, tmp_path: Path) -> None:
    text = "# D\n## A\n### sub\n### sub\n#### deeper\n# another top\n## B\n"
    write(tmp_path, {"evidence/decisions.md": text})
    result = ce.check_decisions(tmp_path)
    assert not result.ok
    assert "2 level-2 headings" in result.reason


def test_headings_inside_code_blocks_are_not_records(ce: ModuleType, tmp_path: Path) -> None:
    text = "# D\n## A\n## B\n```\n## not a record\n```\n"
    write(tmp_path, {"evidence/decisions.md": text})
    assert not ce.check_decisions(tmp_path).ok


def test_decisions_fail_when_the_file_is_missing(ce: ModuleType, tmp_path: Path) -> None:
    assert not ce.check_decisions(tmp_path).ok


# --- check 3: Conventional Commits -------------------------------------------------------------


@pytest.mark.parametrize(
    "subject",
    [
        "feat: add a thing",
        "fix: repair it",
        "test: cover it",
        "docs: explain it",
        "chore: tidy",
        "ci: run it",
        "refactor: reshape it",
        "feat(api): scoped change",
        "fix(audit-log)!: breaking change",
        "docs: a description: with a colon",
    ],
)
def test_valid_commit_subjects_pass(ce: ModuleType, tmp_path: Path, subject: str) -> None:
    repo = new_repo(tmp_path)
    commit(repo, subject)
    assert ce.check_commit_subjects(repo).ok


@pytest.mark.parametrize(
    "subject",
    [
        "Update readme",
        "feat:no space after the colon",
        "feature: wrong type",
        "Feat: capital type",
        "feat:",
        "feat(): empty scope",
        "fix : space before colon",
        "WIP",
        "perf: not an allowed type",
    ],
)
def test_invalid_commit_subjects_fail(ce: ModuleType, tmp_path: Path, subject: str) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: a good one")
    commit(repo, subject)
    result = ce.check_commit_subjects(repo)
    assert not result.ok
    assert "1 of 2 subjects do not match" in result.reason


def test_every_commit_is_checked_not_only_the_latest(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "bad first commit")
    commit(repo, "feat: good")
    commit(repo, "fix: good")
    result = ce.check_commit_subjects(repo)
    assert not result.ok
    assert "bad first commit" in result.reason


def test_offenders_are_listed_but_capped(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    for i in range(6):
        commit(repo, f"oops {i}")
    result = ce.check_commit_subjects(repo)
    assert "6 of 6 subjects do not match" in result.reason
    assert result.reason.endswith("...")
    assert "\n" not in result.reason


def test_merge_commits_are_allowed(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: base")
    default = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    git(repo, "checkout", "-q", "-b", "topic")
    commit(repo, "fix: on topic", {"a.txt": "a"})
    git(repo, "checkout", "-q", default)
    commit(repo, "docs: on main", {"b.txt": "b"})
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge branch 'topic'", "topic")
    result = ce.check_commit_subjects(repo)
    assert result.ok
    assert "1 merges skipped" in result.reason


def test_a_bad_commit_still_fails_when_merges_exist(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: base")
    default = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    git(repo, "checkout", "-q", "-b", "topic")
    commit(repo, "sloppy message", {"a.txt": "a"})
    git(repo, "checkout", "-q", default)
    commit(repo, "docs: on main", {"b.txt": "b"})
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge branch 'topic'", "topic")
    assert not ce.check_commit_subjects(repo).ok


def test_commit_subjects_fail_in_a_shallow_clone(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: one")
    commit(repo, "feat: two")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
        check=True,
        capture_output=True,
    )
    result = ce.run_checks(shallow)[2]
    assert not result.ok
    assert "shallow" in result.reason
    assert "fetch-depth: 0" in result.reason


def test_commit_subjects_fail_outside_a_repository_or_without_commits(
    ce: ModuleType, tmp_path: Path
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "not a git repository" in ce.run_checks(plain)[2].reason
    empty = new_repo(tmp_path, "empty")
    assert "no commits" in ce.run_checks(empty)[2].reason


# --- check 4: evaluation evidence is current ---------------------------------------------------

REPORT = {"evidence/eval-report.md": "report v1\n"}
SOURCES = ["src/app.py", "config/policy.toml", "models/model.json", "sample-data/scenarios.jsonl"]


def test_eval_passes_when_the_report_is_committed_after_the_source(
    ce: ModuleType, tmp_path: Path
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    assert ce.check_eval_current(repo).ok


def test_eval_passes_when_both_change_in_the_same_commit(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code and report", {"src/app.py": "v1", **REPORT})
    assert ce.check_eval_current(repo).ok


@pytest.mark.parametrize("path", SOURCES)
def test_eval_fails_when_the_source_changes_after_the_report(
    ce: ModuleType, tmp_path: Path, path: str
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "docs: report", REPORT)
    commit(repo, "feat: change source", {path: "changed"})
    result = ce.check_eval_current(repo)
    assert not result.ok
    assert "make eval" in result.reason
    assert "change source" in result.reason


def test_eval_passes_again_once_the_report_is_recommitted(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "docs: report", REPORT)
    commit(repo, "feat: change source", {"src/app.py": "changed"})
    assert not ce.check_eval_current(repo).ok
    commit(repo, "docs: regenerate report", {"evidence/eval-report.md": "report v2\n"})
    assert ce.check_eval_current(repo).ok


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_x.py",
        "scripts/tool.py",
        "README.md",
        "evidence/design.md",
        "sample-data/reference/customers.json",
        "sample-data/scenarios_hard.jsonl",
        "sample-data/training/data.csv",
    ],
)
def test_other_files_do_not_make_the_report_stale(
    ce: ModuleType, tmp_path: Path, path: str
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    commit(repo, "chore: unrelated change", {path: "x"})
    assert ce.check_eval_current(repo).ok


def test_eval_fails_when_the_report_was_never_committed(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    result = ce.check_eval_current(repo)
    assert not result.ok
    assert "never been committed" in result.reason


def test_eval_passes_when_there_are_no_source_commits(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "docs: report", REPORT)
    result = ce.check_eval_current(repo)
    assert result.ok
    assert "no source commits" in result.reason


def test_uncommitted_source_changes_need_an_uncommitted_report_change(
    ce: ModuleType, tmp_path: Path
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    assert ce.check_eval_current(repo).ok
    write(repo, {"src/app.py": "v2 edited, not committed"})
    result = ce.check_eval_current(repo)
    assert not result.ok
    assert "uncommitted changes" in result.reason


def test_a_new_untracked_source_file_counts_as_an_uncommitted_change(
    ce: ModuleType, tmp_path: Path
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "docs: report", REPORT)
    write(repo, {"src/new_module.py": "x"})
    assert not ce.check_eval_current(repo).ok


def test_uncommitted_source_and_report_changes_pass_together(
    ce: ModuleType, tmp_path: Path
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    write(repo, {"src/app.py": "v2", "evidence/eval-report.md": "report v2\n"})
    result = ce.check_eval_current(repo)
    assert result.ok
    assert "uncommitted" in result.reason


def test_an_uncommitted_report_change_alone_passes(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    commit(repo, "feat: more code", {"src/app.py": "v2"})
    assert not ce.check_eval_current(repo).ok
    write(repo, {"evidence/eval-report.md": "report v2\n"})
    assert ce.check_eval_current(repo).ok


def test_a_report_on_a_side_branch_that_lacks_the_source_change_is_not_current(
    ce: ModuleType, tmp_path: Path
) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: base", {"src/app.py": "v1"})
    default = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    git(repo, "checkout", "-q", "-b", "report-branch")
    commit(repo, "docs: report", REPORT)
    git(repo, "checkout", "-q", default)
    commit(repo, "feat: source change on main", {"src/app.py": "v2"})
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge branch 'report-branch'", "report-branch")
    assert not ce.check_eval_current(repo).ok  # the report was not made from the newer source


def test_eval_fails_in_a_shallow_clone(ce: ModuleType, tmp_path: Path) -> None:
    repo = new_repo(tmp_path)
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
        check=True,
        capture_output=True,
    )
    result = ce.run_checks(shallow)[3]
    assert not result.ok
    assert "shallow" in result.reason


# --- the command line --------------------------------------------------------------------------


def healthy_repo(tmp_path: Path) -> Path:
    repo = new_repo(tmp_path)
    commit(repo, "docs: evidence", evidence_files())
    commit(repo, "feat: code", {"src/app.py": "v1"})
    commit(repo, "docs: report", REPORT)
    return repo


def test_main_prints_four_pass_lines_and_exits_zero(
    ce: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert ce.main(["--repo", str(healthy_repo(tmp_path))]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 4
    assert [line.split()[0] for line in lines] == ["PASS"] * 4
    assert [line.split()[1] for line in lines] == ["1.", "2.", "3.", "4."]


def test_main_exits_non_zero_and_names_the_failing_checks(
    ce: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = healthy_repo(tmp_path)
    commit(repo, "sloppy subject", {"src/app.py": "v2"})
    assert ce.main(["--repo", str(repo)]) == 1
    lines = capsys.readouterr().out.splitlines()
    statuses = [line.split()[0] for line in lines]
    assert statuses == ["PASS", "PASS", "FAIL", "FAIL"]  # bad subject, and report now stale


def test_main_does_not_crash_on_a_path_that_is_not_a_repository(
    ce: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert ce.main(["--repo", str(tmp_path / "nothing-here")]) == 1
    assert capsys.readouterr().out.count("FAIL") == 4


# --- the script itself and its wiring ----------------------------------------------------------


def test_script_uses_only_the_standard_library_and_never_a_shell() -> None:
    tree = ast.parse(SCRIPT.read_text())
    modules = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert modules <= set(sys.stdlib_module_names) | {"__future__"}, modules
    text = SCRIPT.read_text()
    assert "shell=True" not in text
    assert "os.system" not in text


def test_make_verify_runs_the_evidence_check_last() -> None:
    makefile = (ROOT / "Makefile").read_text()
    assert "evidence-check:\n\t$(BIN)/python scripts/check_evidence.py" in makefile
    verify = makefile.split("verify:")[1].split("\n\n")[0]
    assert "evidence-check" in verify
    assert verify.index("eval") < verify.index("evidence-check")


def test_ci_checkout_fetches_the_full_history() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    checkout = workflow.split("actions/checkout@v4")[1].split("- uses:")[0]
    assert "fetch-depth: 0" in checkout
