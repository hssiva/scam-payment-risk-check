from decimal import Decimal
from typing import Any

import pytest

from scamcheck.reference import Customer, PayeeRecord, ReferenceData
from scamcheck.schemas import PaymentRequest, validate_request
from scamcheck.signals import NameMatch, build_signals, name_match, normalise_name

# Unit-test value. The engine passes policy.name_close_threshold instead.
NAME_CLOSE = 0.80

KNOWN = "000111-11111111"
OTHER = "000111-22222222"
MULE_ONLY = "000199-99999999"


def reference() -> ReferenceData:
    return ReferenceData(
        customers={
            "c1": Customer("c1", 500, Decimal("150.00"), frozenset({KNOWN})),
            "c2": Customer("c2", 10, Decimal("40.00"), frozenset()),
        },
        payees={
            KNOWN: PayeeRecord(1000, "John Smith"),
            OTHER: PayeeRecord(7, "Example Plumbing Pty Ltd"),
        },
        mule_accounts=frozenset({OTHER, MULE_ONLY}),
    )


def request(
    *,
    customer_id: str = "c1",
    payee: str = KNOWN,
    amount: str = "150.00",
    name: str = "John Smith",
    **session: bool,
) -> PaymentRequest:
    bsb, account = payee.split("-")
    raw: dict[str, Any] = {
        "request_id": "r1",
        "timestamp": "2026-03-01T10:00:00+11:00",
        "customer_id": customer_id,
        "amount": amount,
        "currency": "AUD",
        "payee": {"name": name, "bsb": bsb, "account_number": account},
        "channel": "web",
        "session": {
            "on_active_call": False,
            "remote_access_detected": False,
            "new_device": False,
        }
        | session,
    }
    result = validate_request(raw, Decimal("1000000"))
    assert isinstance(result, PaymentRequest)
    return result


def test_known_payee_is_not_new() -> None:
    assert build_signals(request(), reference(), NAME_CLOSE).new_payee is False


def test_unseen_payee_is_new() -> None:
    assert build_signals(request(payee=OTHER, name="x"), reference(), NAME_CLOSE).new_payee is True


def test_amount_ratio_is_decimal_and_quantised() -> None:
    signals = build_signals(request(amount="450.00"), reference(), NAME_CLOSE)
    assert signals.amount_ratio == Decimal("3.0000")
    assert isinstance(signals.amount_ratio, Decimal)
    third = build_signals(request(amount="100.00"), reference(), NAME_CLOSE).amount_ratio
    assert third == Decimal("0.6667")


def test_payee_account_age_is_passed_through() -> None:
    assert build_signals(request(), reference(), NAME_CLOSE).payee_account_age_days == 1000
    assert build_signals(request(payee=OTHER), reference(), NAME_CLOSE).payee_account_age_days == 7


def test_name_match_uses_account_name() -> None:
    assert build_signals(request(), reference(), NAME_CLOSE).payee_name_match is NameMatch.MATCH
    mismatch = build_signals(request(name="Someone Else"), reference(), NAME_CLOSE)
    assert mismatch.payee_name_match is NameMatch.MISMATCH
    close = build_signals(request(name="Jon Smith"), reference(), NAME_CLOSE)
    assert close.payee_name_match is NameMatch.CLOSE


def test_mule_flag() -> None:
    assert build_signals(request(), reference(), NAME_CLOSE).payee_on_mule_list is False
    assert build_signals(request(payee=OTHER), reference(), NAME_CLOSE).payee_on_mule_list is True


def test_session_flags_are_copied() -> None:
    signals = build_signals(
        request(on_active_call=True, remote_access_detected=True, new_device=True),
        reference(),
        NAME_CLOSE,
    )
    assert (signals.on_active_call, signals.remote_access_detected, signals.new_device) == (
        True,
        True,
        True,
    )
    quiet = build_signals(request(), reference(), NAME_CLOSE)
    assert (quiet.on_active_call, quiet.remote_access_detected, quiet.new_device) == (
        False,
        False,
        False,
    )


def test_complete_data() -> None:
    assert build_signals(request(), reference(), NAME_CLOSE).data_complete is True


def test_unknown_customer_is_incomplete_and_treated_as_new_payee() -> None:
    signals = build_signals(request(customer_id="ghost"), reference(), NAME_CLOSE)
    assert signals.data_complete is False
    assert signals.amount_ratio is None
    assert signals.new_payee is True
    assert signals.payee_account_age_days == 1000  # payee data is still looked up


def test_unknown_payee_is_incomplete_and_name_unavailable() -> None:
    signals = build_signals(request(payee="000111-33333333"), reference(), NAME_CLOSE)
    assert signals.data_complete is False
    assert signals.payee_name_match is NameMatch.UNAVAILABLE
    assert signals.payee_account_age_days is None
    assert signals.new_payee is True
    assert signals.amount_ratio == Decimal("1.0000")


def test_mule_list_applies_even_if_payee_is_not_in_reference() -> None:
    signals = build_signals(request(payee=MULE_ONLY), reference(), NAME_CLOSE)
    assert signals.payee_on_mule_list is True
    assert signals.data_complete is False


def test_unknown_customer_and_payee() -> None:
    signals = build_signals(
        request(customer_id="ghost", payee="000111-33333333"), reference(), NAME_CLOSE
    )
    assert signals.data_complete is False
    assert signals.payee_name_match is NameMatch.UNAVAILABLE
    assert signals.amount_ratio is None


@pytest.mark.parametrize(
    ("entered", "on_account", "expected"),
    [
        ("John Smith", "John Smith", NameMatch.MATCH),
        ("  JOHN   smith ", "John Smith", NameMatch.MATCH),
        ("John, Smith.", "John Smith", NameMatch.MATCH),
        ("J Smith", "J Smith", NameMatch.MATCH),
        ("Pat O'Brien", "Pat OBrien", NameMatch.MATCH),
        # initials instead of full words are CLOSE, never a full match
        ("J Smith", "John Smith", NameMatch.CLOSE),
        ("J. Smith", "John Smith", NameMatch.CLOSE),
        ("John Smith", "J Smith", NameMatch.CLOSE),
        ("J S", "John Smith", NameMatch.CLOSE),
        # the same words in another order are CLOSE, not a mismatch
        ("Smith, John", "John Smith", NameMatch.CLOSE),
        ("Smith John", "John Smith", NameMatch.CLOSE),
        ("Smith, J", "John Smith", NameMatch.CLOSE),
        ("Smith, John Paul", "John Paul Smith", NameMatch.CLOSE),
        ("John Paul Smith", "Smith John Paul", NameMatch.CLOSE),
        ("Paul John Smith", "John Paul Smith", NameMatch.CLOSE),
        ("Smith Jones", "Jones Smith", NameMatch.CLOSE),
        ("Jon Smith", "John Smith", NameMatch.CLOSE),
        ("John Smyth", "John Smith", NameMatch.CLOSE),
        ("K Smith", "John Smith", NameMatch.MISMATCH),
        ("Smith K", "John Smith", NameMatch.MISMATCH),
        ("Smith, Kevin", "John Smith", NameMatch.MISMATCH),
        ("Jane Doe", "John Smith", NameMatch.MISMATCH),
        ("Example Plumbing", "Example Plumbing Pty Ltd", NameMatch.CLOSE),
        ("...", "John Smith", NameMatch.MISMATCH),
        ("John Smith", "", NameMatch.MISMATCH),
    ],
)
def test_name_match_rules(entered: str, on_account: str, expected: NameMatch) -> None:
    assert name_match(entered, on_account, NAME_CLOSE) is expected


def test_close_threshold_is_adjustable() -> None:
    assert name_match("Jon Smith", "John Smith", close_threshold=0.99) is NameMatch.MISMATCH
    assert name_match("Jon Smith", "John Smith", close_threshold=0.5) is NameMatch.CLOSE


def test_normalise_name() -> None:
    assert normalise_name("  O'Brien-Smith, J. ") == ["obrien", "smith", "j"]


def test_initials_and_reordered_words_are_close_whatever_the_threshold() -> None:
    assert name_match("J Smith", "John Smith", close_threshold=1.0) is NameMatch.CLOSE
    assert name_match("Smith, John", "John Smith", close_threshold=1.0) is NameMatch.CLOSE
    assert name_match("Jon Smith", "John Smith", close_threshold=1.0) is NameMatch.MISMATCH  # typo


def test_the_close_threshold_passed_to_build_signals_is_used() -> None:
    lenient = build_signals(request(name="Jon Smith"), reference(), 0.5)
    strict = build_signals(request(name="Jon Smith"), reference(), 0.99)
    assert lenient.payee_name_match is NameMatch.CLOSE
    assert strict.payee_name_match is NameMatch.MISMATCH


def test_surname_first_and_initials_are_close_in_the_signals() -> None:
    for typed in ("Smith, John", "J Smith", "Smith John"):
        signals = build_signals(request(name=typed), reference(), NAME_CLOSE)
        assert signals.payee_name_match is NameMatch.CLOSE, typed
