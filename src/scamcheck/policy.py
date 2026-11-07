"""Load and validate config/policy.toml."""

from __future__ import annotations

import os
import tomllib
from decimal import Decimal
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

POLICY_PATH_ENV = "SCAMCHECK_POLICY_PATH"


class PolicyError(Exception):
    """The policy file is missing, unreadable or invalid."""

    def __init__(self, path: Path, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


class EvaluationGates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    min_scam_warn_or_hold_rate: Annotated[float, Field(gt=0, le=1)]
    max_genuine_hold_rate: Annotated[float, Field(ge=0, lt=1)]


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: Annotated[str, Field(min_length=1, max_length=32)]
    high_value_amount: Annotated[Decimal, Field(gt=0)]
    abstain_amount: Annotated[Decimal, Field(gt=0)]
    unusual_ratio: Annotated[Decimal, Field(gt=0)]
    young_account_days: Annotated[int, Field(ge=0, strict=True)]
    score_warn: Annotated[float, Field(gt=0, le=1)]
    score_hold: Annotated[float, Field(gt=0, le=1)]
    name_close_threshold: Annotated[float, Field(gt=0, le=1)]
    max_amount: Annotated[Decimal, Field(gt=0)]
    evaluation: EvaluationGates

    @model_validator(mode="after")
    def _warn_below_hold(self) -> Policy:
        if self.score_warn >= self.score_hold:
            raise ValueError("score_warn must be lower than score_hold")
        return self


def default_policy_path() -> Path:
    override = os.environ.get(POLICY_PATH_ENV)
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "config" / "policy.toml"


def load_policy(path: Path | str | None = None) -> Policy:
    """Load the policy. Raises ``PolicyError`` on any problem (messages never include values)."""
    path = Path(path) if path else default_policy_path()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(path, "file is missing or cannot be read") from exc
    try:
        raw = tomllib.loads(text, parse_float=Decimal)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise PolicyError(path, "file is not valid TOML") from exc
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        problems = sorted({".".join(str(p) for p in e["loc"]) or "policy" for e in exc.errors()})
        raise PolicyError(path, "invalid policy at: " + "; ".join(problems)) from exc
