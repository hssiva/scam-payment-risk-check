"""Risk model: a logistic regression stored as a JSON artifact (no pickle, no eval).

The artifact is verified before use: its SHA-256 must match the sidecar ``.sha256`` file and its
feature list must equal ``FEATURES`` exactly. Any problem puts the service in degraded mode
(``ModelRuntime.health()`` explains why) instead of raising at request time.

The checksum detects accidental damage and edits to the artifact alone; someone who can rewrite
both files can still swap the model, so protect the ``models/`` directory like code.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from scamcheck.schemas import Reason
from scamcheck.signals import NameMatch, Signals

logger = logging.getLogger(__name__)

MODEL_PATH_ENV = "SCAMCHECK_MODEL_PATH"
DEFAULT_MODEL_FILENAME = "risk_model_v1.json"
CHECKSUM_SUFFIX = ".sha256"
TOP_REASONS = 2
_MIN_RATIO = 1e-4  # numerical guard so log() is defined (ratios are quantised to 4 places)

FEATURES: tuple[str, ...] = (
    "new_payee",
    "log_amount_ratio",
    "young_account",
    "name_mismatch",
    "on_active_call",
    "remote_access_detected",
    "new_device",
)

# feature -> (reason code, detail). Details are fixed text with no values.
FEATURE_REASONS: dict[str, tuple[str, str]] = {
    "new_payee": ("M_NEW_PAYEE", "Payment to a payee the customer has not paid before."),
    "log_amount_ratio": (
        "M_AMOUNT_ABOVE_TYPICAL",
        "Amount is high compared with typical payments.",
    ),
    "young_account": ("M_YOUNG_PAYEE_ACCOUNT", "Payee account was opened recently."),
    "name_mismatch": ("M_NAME_MISMATCH", "Payee name does not match the name on the account."),
    "on_active_call": ("M_ON_ACTIVE_CALL", "Customer is on an active phone call."),
    "remote_access_detected": ("M_REMOTE_ACCESS", "A remote-access tool was detected."),
    "new_device": ("M_NEW_DEVICE", "Payment is being made from a new device."),
}

ModelErrorCode = Literal[
    "MODEL_FILE_MISSING",
    "MODEL_INTEGRITY_FAILED",
    "MODEL_MALFORMED",
    "MODEL_FEATURES_MISMATCH",
    "MODEL_LOAD_ERROR",
]


class ModelError(Exception):
    """The model artifact cannot be used. ``code`` says why."""

    def __init__(self, path: Path, code: ModelErrorCode, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.code: ModelErrorCode = code
        self.message = message


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_features(signals: Signals, young_account_days: int) -> list[float]:
    """Model inputs, in ``FEATURES`` order. Shared by training and scoring."""
    ratio = float(signals.amount_ratio) if signals.amount_ratio is not None else 1.0
    age = signals.payee_account_age_days
    values: dict[str, bool | float] = {
        "new_payee": signals.new_payee,
        "log_amount_ratio": math.log(max(ratio, _MIN_RATIO)),
        "young_account": age is not None and age < young_account_days,
        "name_mismatch": signals.payee_name_match is NameMatch.MISMATCH,
        "on_active_call": signals.on_active_call,
        "remote_access_detected": signals.remote_access_detected,
        "new_device": signals.new_device,
    }
    return [float(values[name]) for name in FEATURES]


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass(frozen=True)
class ModelScore:
    probability: float
    reasons: list[Reason]  # top contributions that raise risk, most important first


@dataclass(frozen=True)
class RiskModel:
    version: str
    coefficients: tuple[float, ...]
    intercept: float
    young_account_days: int

    def score(self, signals: Signals) -> ModelScore:
        x = extract_features(signals, self.young_account_days)
        contributions = [c * v for c, v in zip(self.coefficients, x, strict=True)]
        probability = sigmoid(self.intercept + sum(contributions))
        ranked = sorted(
            (i for i, c in enumerate(contributions) if c > 0),
            key=lambda i: (-contributions[i], i),
        )
        reasons = [
            Reason(code=FEATURE_REASONS[FEATURES[i]][0], detail=FEATURE_REASONS[FEATURES[i]][1])
            for i in ranked[:TOP_REASONS]
        ]
        return ModelScore(probability=probability, reasons=reasons)


class _Artifact(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model_version: Annotated[str, Field(min_length=1, strict=True)]
    coefficients: list[Annotated[float, Field(strict=True, allow_inf_nan=False)]]
    intercept: Annotated[float, Field(strict=True, allow_inf_nan=False)]
    young_account_days: Annotated[int, Field(ge=0, strict=True)]


def default_model_path() -> Path:
    override = os.environ.get(MODEL_PATH_ENV)
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "models" / DEFAULT_MODEL_FILENAME


def _read_bytes(path: Path, what: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ModelError(path, "MODEL_FILE_MISSING", f"{what} is missing or unreadable") from exc


def _verify_checksum(path: Path, data: bytes) -> None:
    sidecar = path.with_name(path.stem + CHECKSUM_SUFFIX)
    text = _read_bytes(sidecar, "checksum file").decode("utf-8", errors="replace").split()
    expected = text[0].lower() if text else ""
    if not hmac.compare_digest(expected, sha256_hex(data)):
        raise ModelError(path, "MODEL_INTEGRITY_FAILED", "checksum does not match the artifact")


def _parse(path: Path, data: bytes) -> dict[str, object]:
    try:
        parsed = json.loads(data)
    except ValueError as exc:  # includes JSONDecodeError and UnicodeDecodeError
        raise ModelError(path, "MODEL_MALFORMED", "artifact is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ModelError(path, "MODEL_MALFORMED", "artifact is not a JSON object")
    return parsed


def load_model(path: Path | str | None = None) -> RiskModel:
    """Load and verify the artifact. Raises ``ModelError`` on any problem."""
    path = Path(path) if path else default_model_path()
    data = _read_bytes(path, "model file")
    _verify_checksum(path, data)
    parsed = _parse(path, data)
    if parsed.get("features") != list(FEATURES):
        raise ModelError(path, "MODEL_FEATURES_MISMATCH", "feature list does not match the code")
    try:
        artifact = _Artifact.model_validate(parsed)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        raise ModelError(path, "MODEL_MALFORMED", "invalid fields: " + ", ".join(fields)) from exc
    if len(artifact.coefficients) != len(FEATURES):
        raise ModelError(path, "MODEL_MALFORMED", "coefficient count does not match features")
    return RiskModel(
        version=artifact.model_version,
        coefficients=tuple(artifact.coefficients),
        intercept=artifact.intercept,
        young_account_days=artifact.young_account_days,
    )


@dataclass(frozen=True)
class ModelHealth:
    status: Literal["ok", "degraded"]
    reason: str | None  # error code when degraded


@dataclass(frozen=True)
class ModelRuntime:
    """A loaded model, or the reason there isn't one."""

    model: RiskModel | None
    reason: str | None = None

    def health(self) -> ModelHealth:
        if self.model is not None:
            return ModelHealth("ok", None)
        return ModelHealth("degraded", self.reason or "MODEL_LOAD_ERROR")

    @classmethod
    def from_path(cls, path: Path | str | None = None) -> ModelRuntime:
        """Load the model; on any failure return a degraded runtime and log it once."""
        try:
            return cls(model=load_model(path))
        except ModelError as exc:
            code: str = exc.code
            detail = exc.message
        except Exception:  # never let a model problem stop the service from deciding
            code, detail = "MODEL_LOAD_ERROR", "unexpected error while loading the model"
        logger.warning(
            "Risk model unavailable (%s: %s); running in DEGRADED_RULES_ONLY mode", code, detail
        )
        return cls(model=None, reason=code)


@cache
def default_runtime() -> ModelRuntime:
    """The process-wide runtime, loaded once (so a degrade is logged once)."""
    return ModelRuntime.from_path()
