"""Turn a validated payment request plus reference data into explainable signals."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from scamcheck.reference import ReferenceData, payee_key
from scamcheck.schemas import PaymentRequest

_RATIO_PLACES = Decimal("0.0001")


class NameMatch(StrEnum):
    MATCH = "MATCH"
    CLOSE = "CLOSE"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class Signals:
    new_payee: bool
    amount_ratio: Decimal | None
    payee_account_age_days: int | None
    payee_name_match: NameMatch
    payee_on_mule_list: bool
    on_active_call: bool
    remote_access_detected: bool
    new_device: bool
    data_complete: bool


def normalise_name(name: str) -> list[str]:
    """Lower-case, drop apostrophes, turn other punctuation into spaces, split into tokens."""
    cleaned = "".join(
        ch if ch.isalnum() else ("" if ch in "'’`" else " ") for ch in name.casefold()
    )
    return cleaned.split()


def _same_or_initial(a: str, b: str) -> bool:
    """The same word, or one side is only the first letter of the other ("j" and "john")."""
    return a == b or (min(len(a), len(b)) == 1 and a[0] == b[0])


def _aligned(a: list[str], b: list[str]) -> bool:
    return len(a) == len(b) and all(_same_or_initial(x, y) for x, y in zip(a, b, strict=True))


def _reorderings(tokens: list[str]) -> list[list[str]]:
    """The words as given, rotated and reversed: "Smith John Paul" is "John Paul Smith" rotated."""
    reverse = tokens[::-1]
    return [t[i:] + t[:i] for t in (tokens, reverse) for i in range(len(t))]


def name_match(entered: str, on_account: str, close_threshold: float) -> NameMatch:
    """Compare the name the customer typed with the name on the account.

    MATCH: the same words after normalising case, punctuation and spacing.
    CLOSE: the same words in a different order ("Smith, John"), initials instead of full words
    ("J Smith"), or similar enough to be a typo (similarity at or above ``close_threshold``).
    MISMATCH: anything else, including an empty name.
    """
    a, b = normalise_name(entered), normalise_name(on_account)
    if not a or not b:
        return NameMatch.MISMATCH
    if a == b:
        return NameMatch.MATCH
    if sorted(a) == sorted(b) or any(_aligned(a, order) for order in _reorderings(b)):
        return NameMatch.CLOSE
    ratio = difflib.SequenceMatcher(None, " ".join(a), " ".join(b)).ratio()
    return NameMatch.CLOSE if ratio >= close_threshold else NameMatch.MISMATCH


def build_signals(
    request: PaymentRequest,
    reference: ReferenceData,
    close_threshold: float,
) -> Signals:
    bsb, account = request.payee.bsb, request.payee.account_number
    customer = reference.customer(request.customer_id)
    payee = reference.payee(bsb, account)

    new_payee = customer is None or payee_key(bsb, account) not in customer.known_payees
    amount_ratio = (
        (request.amount / customer.typical_payment_amount).quantize(_RATIO_PLACES)
        if customer is not None
        else None
    )
    match = (
        name_match(request.payee.name, payee.name_on_account, close_threshold)
        if payee is not None
        else NameMatch.UNAVAILABLE
    )
    return Signals(
        new_payee=new_payee,
        amount_ratio=amount_ratio,
        payee_account_age_days=payee.account_age_days if payee is not None else None,
        payee_name_match=match,
        payee_on_mule_list=reference.is_mule(bsb, account),
        on_active_call=request.session.on_active_call,
        remote_access_detected=request.session.remote_access_detected,
        new_device=request.session.new_device,
        data_complete=customer is not None and payee is not None,
    )
