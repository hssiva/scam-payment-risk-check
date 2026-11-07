import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from scamcheck.reference import (
    REFERENCE_DIR_ENV,
    ReferenceDataError,
    ReferenceFileMalformedError,
    ReferenceFileMissingError,
    ReferencePaths,
    default_reference_dir,
    load_reference,
    payee_key,
)

NOTE = "SYNTHETIC - not real customers"


def write_set(directory: Path, **overrides: Any) -> ReferencePaths:
    files: dict[str, Any] = {
        "customers.json": {
            "_note": NOTE,
            "customers": [
                {
                    "customer_id": "c1",
                    "tenure_days": 10,
                    "typical_payment_amount": 100.5,
                    "known_payees": [{"bsb": "000111", "account_number": "12345678"}],
                }
            ],
        },
        "payees.json": {
            "_note": NOTE,
            "payees": {"000111-12345678": {"account_age_days": 5, "name_on_account": "A B"}},
        },
        "mule_accounts.json": {
            "_note": NOTE,
            "accounts": [{"bsb": "000222", "account_number": "87654321"}],
        },
    }
    files.update(overrides)
    for name, body in files.items():
        text = body if isinstance(body, str) else json.dumps(body)
        (directory / name).write_text(text)
    return ReferencePaths.in_directory(directory)


def test_sample_data_loads_and_has_expected_shape() -> None:
    ref = load_reference()
    assert len(ref.customers) == 10
    assert 25 <= len(ref.payees) <= 35
    assert len(ref.mule_accounts) == 3
    assert all(k.startswith("000") for k in ref.payees)
    assert all(k.startswith("000") for k in ref.mule_accounts)


def test_sample_files_are_labelled_synthetic() -> None:
    for name in ("customers", "payees", "mule_accounts"):
        data = json.loads((default_reference_dir() / f"{name}.json").read_text())
        assert "SYNTHETIC" in data["_note"]


def test_every_known_payee_and_mule_in_sample_data_is_consistent() -> None:
    ref = load_reference()
    for customer in ref.customers.values():
        assert customer.known_payees <= ref.payees.keys()


def test_lookups(tmp_path: Path) -> None:
    ref = load_reference(write_set(tmp_path))
    customer = ref.customer("c1")
    assert customer is not None
    assert customer.typical_payment_amount == Decimal("100.5")
    assert customer.known_payees == {"000111-12345678"}
    assert ref.customer("nobody") is None
    payee = ref.payee("000111", "12345678")
    assert payee is not None
    assert payee.account_age_days == 5
    assert ref.payee("000111", "00000000") is None
    assert ref.is_mule("000222", "87654321")
    assert not ref.is_mule("000111", "12345678")


def test_payee_key_format() -> None:
    assert payee_key("000111", "12345678") == "000111-12345678"


def test_missing_file_raises_typed_error(tmp_path: Path) -> None:
    paths = write_set(tmp_path)
    paths.payees.unlink()
    with pytest.raises(ReferenceFileMissingError) as info:
        load_reference(paths)
    assert info.value.path == paths.payees
    assert isinstance(info.value, ReferenceDataError)


def test_directory_instead_of_file_is_a_missing_error(tmp_path: Path) -> None:
    paths = write_set(tmp_path)
    paths.mule_accounts.unlink()
    paths.mule_accounts.mkdir()
    with pytest.raises(ReferenceFileMissingError):
        load_reference(paths)


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("customers.json", "{not json"),
        ("payees.json", "[]"),
        ("mule_accounts.json", {"_note": NOTE}),
        ("mule_accounts.json", {"_note": NOTE, "accounts": [], "extra": 1}),
        ("customers.json", {"customers": []}),
        ("customers.json", {"_note": "real data", "customers": []}),
        (
            "mule_accounts.json",
            {"_note": NOTE, "accounts": [{"bsb": "062000", "account_number": "12345678"}]},
        ),
        (
            "payees.json",
            {"_note": NOTE, "payees": {"bad-key": {"account_age_days": 1, "name_on_account": "x"}}},
        ),
        (
            "payees.json",
            {
                "_note": NOTE,
                "payees": {"000111-12345678": {"account_age_days": -1, "name_on_account": "x"}},
            },
        ),
    ],
)
def test_malformed_files_raise_typed_error(tmp_path: Path, name: str, body: Any) -> None:
    paths = write_set(tmp_path, **{name: body})
    with pytest.raises(ReferenceFileMalformedError) as info:
        load_reference(paths)
    assert name in str(info.value)


def test_duplicate_customer_ids_are_malformed(tmp_path: Path) -> None:
    row = {
        "customer_id": "c1",
        "tenure_days": 1,
        "typical_payment_amount": 10,
        "known_payees": [],
    }
    paths = write_set(tmp_path, **{"customers.json": {"_note": NOTE, "customers": [row, row]}})
    with pytest.raises(ReferenceFileMalformedError):
        load_reference(paths)


def test_error_messages_do_not_contain_data_values(tmp_path: Path) -> None:
    bad = {"_note": NOTE, "accounts": [{"bsb": "062000", "account_number": "13572468"}]}
    paths = write_set(tmp_path, **{"mule_accounts.json": bad})
    with pytest.raises(ReferenceFileMalformedError) as info:
        load_reference(paths)
    assert "13572468" not in str(info.value)
    assert "062000" not in str(info.value)


def test_default_dir_can_be_overridden_by_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(REFERENCE_DIR_ENV, str(tmp_path))
    assert default_reference_dir() == tmp_path
    with pytest.raises(ReferenceFileMissingError):
        load_reference()
