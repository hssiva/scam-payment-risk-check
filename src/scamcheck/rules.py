"""Policy rules. Each rule returns ``None`` or a ``RuleHit(floor, reason)``.

Reason text never includes amounts, names or account numbers.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import NamedTuple

from scamcheck.policy import Policy
from scamcheck.schemas import Decision, Reason
from scamcheck.signals import NameMatch, Signals

SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.HOLD: 2,
}


class RuleHit(NamedTuple):
    floor: Decision
    reason: Reason


Rule = Callable[[Signals, Decimal, Policy], RuleHit | None]


def most_severe(decisions: list[Decision]) -> Decision:
    """The most severe decision (ALLOW < WARN < HOLD); ALLOW if the list is empty."""
    return max(decisions, key=SEVERITY.__getitem__, default=Decision.ALLOW)


def r01_mule_payee(signals: Signals, amount: Decimal, policy: Policy) -> RuleHit | None:
    if signals.payee_on_mule_list:
        return RuleHit(
            Decision.HOLD,
            Reason(code="R01_MULE_PAYEE", detail="Payee account is on the mule account list."),
        )
    return None


def r02_remote_access_new_payee(
    signals: Signals, amount: Decimal, policy: Policy
) -> RuleHit | None:
    if signals.remote_access_detected and signals.new_payee:
        return RuleHit(
            Decision.HOLD,
            Reason(
                code="R02_REMOTE_ACCESS_NEW_PAYEE",
                detail="Remote-access tool detected while paying a new payee.",
            ),
        )
    return None


def r03_on_call_new_payee_high_value(
    signals: Signals, amount: Decimal, policy: Policy
) -> RuleHit | None:
    if signals.on_active_call and signals.new_payee and amount >= policy.high_value_amount:
        return RuleHit(
            Decision.HOLD,
            Reason(
                code="R03_ON_CALL_NEW_PAYEE_HIGH_VALUE",
                detail=(
                    "High-value payment to a new payee during an active call "
                    f"(high value is {policy.high_value_amount} AUD or more)."
                ),
            ),
        )
    return None


def r04_payee_name_mismatch(signals: Signals, amount: Decimal, policy: Policy) -> RuleHit | None:
    if signals.payee_name_match is not NameMatch.MISMATCH:
        return None
    high_value = amount >= policy.high_value_amount
    return RuleHit(
        Decision.HOLD if high_value else Decision.WARN,
        Reason(
            code="R04_PAYEE_NAME_MISMATCH",
            detail=(
                "Payee name does not match the name on the account"
                + (" (high-value payment)." if high_value else ".")
            ),
        ),
    )


def r05_unusual_amount(signals: Signals, amount: Decimal, policy: Policy) -> RuleHit | None:
    if signals.amount_ratio is not None and signals.amount_ratio >= policy.unusual_ratio:
        return RuleHit(
            Decision.WARN,
            Reason(
                code="R05_UNUSUAL_AMOUNT",
                detail=(
                    f"Amount is at least {policy.unusual_ratio} times the customer's "
                    "typical payment."
                ),
            ),
        )
    return None


def r06_young_payee_account(signals: Signals, amount: Decimal, policy: Policy) -> RuleHit | None:
    age = signals.payee_account_age_days
    if signals.new_payee and age is not None and age < policy.young_account_days:
        return RuleHit(
            Decision.WARN,
            Reason(
                code="R06_YOUNG_PAYEE_ACCOUNT",
                detail=(f"New payee whose account is under {policy.young_account_days} days old."),
            ),
        )
    return None


RULES: tuple[Rule, ...] = (
    r01_mule_payee,
    r02_remote_access_new_payee,
    r03_on_call_new_payee_high_value,
    r04_payee_name_mismatch,
    r05_unusual_amount,
    r06_young_payee_account,
)


def any_risk_signal(signals: Signals, policy: Policy) -> bool:
    """True if any signal the risk model would weigh is present (used in degraded mode)."""
    age = signals.payee_account_age_days
    ratio = signals.amount_ratio
    return (
        signals.payee_on_mule_list
        or signals.new_payee
        or signals.new_device
        or signals.on_active_call
        or signals.remote_access_detected
        or signals.payee_name_match is NameMatch.MISMATCH
        or (age is not None and age < policy.young_account_days)
        or (ratio is not None and ratio >= policy.unusual_ratio)
    )


def evaluate_rules(signals: Signals, amount: Decimal, policy: Policy) -> list[RuleHit]:
    """Run every rule in a fixed order and return the hits."""
    hits = (rule(signals, amount, policy) for rule in RULES)
    return [hit for hit in hits if hit is not None]
