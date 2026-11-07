"""Append-only, hash-chained audit trail (JSON Lines).

Each record carries ``prev_hash`` (the previous record's ``record_hash``) and
``record_hash = sha256(prev_hash + canonical_json(record without record_hash))``. ``verify()``
recomputes the chain, so editing, inserting, removing or reordering records is detected.

What it cannot detect: removing records from the END of the file, or rewriting the whole file
with a recomputed chain. Keep copies of the latest ``record_hash`` elsewhere if that matters.

Privacy (CLAUDE.md): records never hold amounts, payee names or full account numbers; only the
last three digits of a valid account number are kept. ``customer_id`` is recorded.
``request_hash`` is a SHA-256 of the request (it covers the amount but cannot reveal it).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # POSIX file locking so several processes can share one chain
    import fcntl
except ImportError:  # pragma: no cover - not available on Windows
    fcntl = None  # type: ignore[assignment]

from scamcheck.schemas import ID_MAX_LENGTH, DecisionResponse

AUDIT_PATH_ENV = "SCAMCHECK_AUDIT_PATH"
DEFAULT_AUDIT_PATH = Path("audit/decisions.jsonl")
GENESIS_HASH = "0" * 64
MAX_READ_LIMIT = 100
_ACCOUNT = re.compile(r"^[0-9]{6,9}$")
_LAST_LINE_BLOCK = 4096

RECORD_FIELDS = (
    "decision_id",
    "ts",
    "request_hash",
    "customer_id",
    "payee_account_masked",
    "decision",
    "reasons",
    "risk_score",
    "mode",
    "model_version",
    "policy_version",
    "latency_ms",
    "prev_hash",
    "record_hash",
)


class AuditError(Exception):
    """The audit trail cannot be written or read reliably."""


def default_audit_path() -> Path:
    override = os.environ.get(AUDIT_PATH_ENV)
    return Path(override) if override else DEFAULT_AUDIT_PATH


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def mask_account(value: object) -> str | None:
    """Keep only the last three digits of a well-formed account number; else nothing."""
    if isinstance(value, str) and _ACCOUNT.match(value):
        return "*" * (len(value) - 3) + value[-3:]
    return None


def _clean_id(value: object) -> str | None:
    if isinstance(value, str) and 1 <= len(value) <= ID_MAX_LENGTH:
        return value
    return None


def build_entry(raw: object, response: DecisionResponse) -> dict[str, Any]:
    """The audit fields for one decision (no chain fields yet). Never includes the amount,
    payee names or full account numbers."""
    body = raw if isinstance(raw, dict) else {}
    payee = body.get("payee")
    account = payee.get("account_number") if isinstance(payee, dict) else None
    return {
        "decision_id": response.decision_id,
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "request_hash": sha256_text(canonical_json(raw)),
        "customer_id": _clean_id(body.get("customer_id")),
        "payee_account_masked": mask_account(account),
        "decision": response.decision.value,
        "reasons": [r.model_dump() for r in response.reasons],
        "risk_score": response.risk_score,
        "mode": response.mode.value,
        "model_version": response.model_version,
        "policy_version": response.policy_version,
        "latency_ms": response.latency_ms,
    }


def compute_record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return sha256_text(str(record.get("prev_hash", "")) + canonical_json(body))


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    message: str
    first_bad_line: int | None = None
    last_hash: str | None = None


class AuditLog:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_audit_path()
        self._lock = threading.Lock()

    # --- writing ------------------------------------------------------------------------

    def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Chain and append one record; returns it. Raises ``AuditError`` on any failure."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        except OSError as exc:
            raise AuditError("audit log cannot be opened for writing") from exc
        with self._lock, os.fdopen(fd, "r+b") as handle:
            try:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                record = {**entry, "prev_hash": self._last_hash(handle)}
                record["record_hash"] = compute_record_hash(record)
                handle.write((canonical_json(record) + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                raise AuditError("audit record could not be written") from exc
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return record

    @staticmethod
    def _last_hash(handle: Any) -> str:
        """record_hash of the last line, GENESIS if the file is empty. Refuses a damaged tail."""
        size = handle.seek(0, os.SEEK_END)
        if size == 0:
            return GENESIS_HASH
        data = b""
        position = size
        while position > 0 and data.count(b"\n") < 2:
            step = min(_LAST_LINE_BLOCK, position)
            position -= step
            handle.seek(position)
            data = handle.read(step) + data
        if not data.endswith(b"\n"):
            raise AuditError("audit log ends with an incomplete record; refusing to append")
        last = data.rstrip(b"\n").split(b"\n")[-1]
        try:
            value = json.loads(last)
            digest = value["record_hash"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError("last audit record is unreadable; refusing to append") from exc
        if not isinstance(digest, str):
            raise AuditError("last audit record is unreadable; refusing to append")
        return digest

    def writable(self) -> bool:
        """Cheap check that an append could succeed (creates nothing)."""
        if self.path.exists():
            return os.access(self.path, os.W_OK)
        ancestor = self.path.parent
        while not ancestor.exists() and ancestor != ancestor.parent:
            ancestor = ancestor.parent
        return ancestor.is_dir() and os.access(ancestor, os.W_OK | os.X_OK)

    # --- reading ------------------------------------------------------------------------

    def read_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """The most recent ``limit`` records (1..100), newest first."""
        limit = max(1, min(limit, MAX_READ_LIMIT))
        if not self.path.exists():
            return []
        try:
            with self.path.open(encoding="utf-8") as handle:
                lines = list(deque((ln for ln in handle if ln.strip()), maxlen=limit))
            return [json.loads(line) for line in reversed(lines)]
        except (OSError, ValueError) as exc:
            raise AuditError("audit log cannot be read") from exc

    def verify(self) -> VerifyResult:
        """Recompute the whole chain. Never raises."""
        if not self.path.exists():
            return VerifyResult(True, 0, "audit log is empty (no file yet)", None, GENESIS_HASH)
        try:
            return self._verify_file()
        except OSError:
            return VerifyResult(False, 0, "audit log cannot be read")

    def _verify_file(self) -> VerifyResult:
        previous = GENESIS_HASH
        count = 0
        with self.path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                problem = self._check_line(line, previous)
                if problem:
                    return VerifyResult(False, count, problem, number, previous)
                previous = json.loads(line)["record_hash"]
                count += 1
        return VerifyResult(True, count, f"chain intact ({count} records)", None, previous)

    @staticmethod
    def _check_line(line: str, previous: str) -> str | None:
        try:
            record = json.loads(line)
        except ValueError:
            return "record is not valid JSON"
        if not isinstance(record, dict) or set(record) != set(RECORD_FIELDS):
            return "record has missing or unexpected fields"
        if record["prev_hash"] != previous:
            return (
                "prev_hash does not match the previous record (record removed, inserted or moved)"
            )
        if record["record_hash"] != compute_record_hash(record):
            return "record_hash does not match the record contents (record edited)"
        return None
