"""Command line: ``scamcheck assess|eval|verify-audit|health``.

Exit codes: 0 success; 1 the request was rejected / the audit chain is broken / the service is
degraded / an evaluation gate failed; 2 usage or input problems (file missing, cannot run).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scamcheck import evaluate
from scamcheck.audit import AuditLog
from scamcheck.engine import assess_and_record
from scamcheck.health import check_health
from scamcheck.model import ModelRuntime
from scamcheck.policy import PolicyError, load_policy
from scamcheck.reference import ReferenceDataError, load_reference
from scamcheck.schemas import Decision


def _print(value: object) -> None:
    print(json.dumps(value, indent=2))


def cmd_assess(args: argparse.Namespace) -> int:
    try:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")
    except OSError:
        print(f"scamcheck: cannot read {args.file}", file=sys.stderr)
        return 2
    try:
        raw: object = json.loads(text)
    except ValueError:
        raw = None  # reported (and audited) as a REJECT, like the API does
    response = assess_and_record(raw, AuditLog())  # type: ignore[arg-type]
    _print(response.model_dump(mode="json"))
    return 1 if response.decision is Decision.REJECT else 0


def cmd_eval(args: argparse.Namespace) -> int:
    return evaluate.main(args.passthrough)


def cmd_verify_audit(args: argparse.Namespace) -> int:
    result = AuditLog().verify()
    _print(
        {
            "ok": result.ok,
            "records": result.records,
            "message": result.message,
            "first_bad_line": result.first_bad_line,
        }
    )
    return 0 if result.ok else 1


def cmd_health(args: argparse.Namespace) -> int:
    try:
        policy = load_policy()
    except PolicyError:
        policy = None
    try:
        reference = load_reference()
    except ReferenceDataError:
        reference = None
    health = check_health(policy, reference, ModelRuntime.from_path(), AuditLog())
    _print(health.as_dict())
    return 0 if health.status == "ok" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scamcheck", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("assess", help="assess one payment request (JSON file, or - for stdin)")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_assess)

    p = commands.add_parser(
        "eval", help="run the evaluation gate (--scenarios, --hard and --report are passed on)"
    )
    p.set_defaults(func=cmd_eval)

    p = commands.add_parser("verify-audit", help="verify the audit hash chain")
    p.set_defaults(func=cmd_verify_audit)

    p = commands.add_parser("health", help="show service health")
    p.set_defaults(func=cmd_health)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if args.command == "eval":
        args.passthrough = extra  # options for the evaluator, which validates them itself
    elif extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
