"""Load and look up SYNTHETIC reference data (customers, payees, mule accounts).

Files are validated strictly. Any problem raises a typed ``ReferenceDataError`` whose message
names the file and the offending field path, never the data values.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

REFERENCE_DIR_ENV = "SCAMCHECK_REFERENCE_DIR"
_BSB = r"^000[0-9]{3}$"  # only the 000xxx range is allowed in synthetic data
_ACCOUNT = r"^[0-9]{6,9}$"
_PAYEE_KEY = r"^000[0-9]{3}-[0-9]{6,9}$"


class ReferenceDataError(Exception):
    """Base error for reference data problems."""

    def __init__(self, path: Path, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


class ReferenceFileMissingError(ReferenceDataError):
    """A reference file does not exist or cannot be read."""


class ReferenceFileMalformedError(ReferenceDataError):
    """A reference file is not valid JSON or does not match the expected structure."""


def payee_key(bsb: str, account_number: str) -> str:
    return f"{bsb}-{account_number}"


@dataclass(frozen=True)
class Customer:
    customer_id: str
    tenure_days: int
    typical_payment_amount: Decimal
    known_payees: frozenset[str]


@dataclass(frozen=True)
class PayeeRecord:
    account_age_days: int
    name_on_account: str


@dataclass(frozen=True)
class ReferenceData:
    customers: dict[str, Customer]
    payees: dict[str, PayeeRecord]
    mule_accounts: frozenset[str]

    def customer(self, customer_id: str) -> Customer | None:
        return self.customers.get(customer_id)

    def payee(self, bsb: str, account_number: str) -> PayeeRecord | None:
        return self.payees.get(payee_key(bsb, account_number))

    def is_mule(self, bsb: str, account_number: str) -> bool:
        return payee_key(bsb, account_number) in self.mule_accounts


@dataclass(frozen=True)
class ReferencePaths:
    customers: Path
    payees: Path
    mule_accounts: Path

    @classmethod
    def in_directory(cls, directory: Path) -> ReferencePaths:
        return cls(
            customers=directory / "customers.json",
            payees=directory / "payees.json",
            mule_accounts=directory / "mule_accounts.json",
        )


def default_reference_dir() -> Path:
    override = os.environ.get(REFERENCE_DIR_ENV)
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "sample-data" / "reference"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=False)


class _File(_Model):
    note: str = Field(alias="_note")

    @field_validator("note")
    @classmethod
    def _must_be_labelled_synthetic(cls, value: str) -> str:
        if "SYNTHETIC" not in value:
            raise ValueError("data file must be labelled SYNTHETIC")
        return value


class _Account(_Model):
    bsb: Annotated[str, Field(pattern=_BSB, strict=True)]
    account_number: Annotated[str, Field(pattern=_ACCOUNT, strict=True)]


class _CustomerRow(_Model):
    customer_id: Annotated[str, Field(min_length=1, max_length=64, strict=True)]
    tenure_days: Annotated[int, Field(ge=0, strict=True)]
    typical_payment_amount: Annotated[Decimal, Field(gt=0, decimal_places=2)]
    known_payees: list[_Account]


class _CustomersFile(_File):
    customers: list[_CustomerRow]


class _PayeeRow(_Model):
    account_age_days: Annotated[int, Field(ge=0, strict=True)]
    name_on_account: Annotated[str, Field(min_length=1, max_length=140, strict=True)]


class _PayeesFile(_File):
    payees: dict[Annotated[str, Field(pattern=_PAYEE_KEY)], _PayeeRow]


class _MulesFile(_File):
    accounts: list[_Account]


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReferenceFileMissingError(path, "file is missing or cannot be read") from exc
    try:
        return json.loads(text, parse_float=Decimal)
    except ValueError as exc:  # includes JSONDecodeError and UnicodeDecodeError
        raise ReferenceFileMalformedError(path, "file is not valid JSON") from exc


def _parse[M: _Model](path: Path, model: type[M]) -> M:
    raw = _read_json(path)
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        problems = sorted(
            {".".join(str(p) for p in e["loc"]) + f" ({e['type']})" for e in exc.errors()}
        )
        raise ReferenceFileMalformedError(
            path, "invalid structure at: " + "; ".join(problems)
        ) from exc


def _load_customers(path: Path) -> dict[str, Customer]:
    customers: dict[str, Customer] = {}
    for row in _parse(path, _CustomersFile).customers:
        if row.customer_id in customers:
            raise ReferenceFileMalformedError(path, "duplicate customer_id")
        customers[row.customer_id] = Customer(
            customer_id=row.customer_id,
            tenure_days=row.tenure_days,
            typical_payment_amount=row.typical_payment_amount,
            known_payees=frozenset(payee_key(a.bsb, a.account_number) for a in row.known_payees),
        )
    return customers


def _load_payees(path: Path) -> dict[str, PayeeRecord]:
    return {
        key: PayeeRecord(row.account_age_days, row.name_on_account)
        for key, row in _parse(path, _PayeesFile).payees.items()
    }


def _load_mules(path: Path) -> frozenset[str]:
    return frozenset(payee_key(a.bsb, a.account_number) for a in _parse(path, _MulesFile).accounts)


def load_reference(paths: ReferencePaths | None = None) -> ReferenceData:
    """Load all reference files. Raises ``ReferenceDataError`` on any problem."""
    paths = paths or ReferencePaths.in_directory(default_reference_dir())
    return ReferenceData(
        customers=_load_customers(paths.customers),
        payees=_load_payees(paths.payees),
        mule_accounts=_load_mules(paths.mule_accounts),
    )
