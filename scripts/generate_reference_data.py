"""Regenerate the SYNTHETIC reference data in sample-data/reference/.

Fully deterministic: the data comes from the tables below and simple arithmetic, with no
random numbers, so every run produces identical files. All BSBs are in the 000xxx range.

Usage:
    python scripts/generate_reference_data.py [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

NOTE = "SYNTHETIC - not real customers"
DEFAULT_OUT_DIR = Path(__file__).resolve().parents[1] / "sample-data" / "reference"

# (name_on_account, account_age_days). Entries 28 and 29 (1-based) are mule accounts.
PAYEE_DEFS: list[tuple[str, int]] = [
    ("Jordan Examplesmith", 1500),
    ("Casey Samplewood", 900),
    ("Example Plumbing Pty Ltd", 2400),
    ("Taylor Testfield", 700),
    ("Sample Electrical Services", 3100),
    ("Morgan Placeholder", 400),
    ("Riley Mockton", 1200),
    ("Example Property Management", 2000),
    ("Avery Fictional", 365),
    ("Sample Council Rates", 5000),
    ("Quinn Demoson", 800),
    ("Example Energy Retail", 4000),
    ("Skyler Synthetic", 600),
    ("Example Landscaping Pty Ltd", 1800),
    ("Jamie Notreal", 950),
    ("Drew Fakeman", 1100),
    ("Example Tutoring Services", 1300),
    ("Sample Motors Pty Ltd", 2700),
    ("Peyton Dummyfield", 500),
    ("Example Travel Pty Ltd", 2200),
    ("Rowan Testcase", 3000),
    ("Example Accounting Pty Ltd", 3500),
    ("Sam Mockwell", 250),
    ("Example Pet Care", 1000),
    ("Blake Samplestone", 450),
    ("Invest Example Markets", 5),
    ("Example Crypto Exchange", 12),
    ("Robin Newaccount", 3),  # mule
    ("Lee Quickopen", 9),  # mule
    ("Example Trading Co", 30),
]

MULE_PAYEE_INDEXES = (28, 29)  # 1-based, into PAYEE_DEFS
MULE_ONLY_ACCOUNT = {"bsb": "000199", "account_number": "99887766"}  # not in payees.json

# (customer_id, tenure_days, typical_payment_amount, known payee indexes, 1-based)
CUSTOMER_DEFS: list[tuple[str, int, float, list[int]]] = [
    ("cust-001", 1800, 150.00, [1, 3, 8, 12]),
    ("cust-002", 3200, 420.00, [2, 5, 10, 12, 22]),
    ("cust-003", 20, 60.00, []),
    ("cust-004", 900, 85.50, [4, 7]),
    ("cust-005", 2600, 1200.00, [3, 8, 18, 22]),
    ("cust-006", 400, 250.00, [6, 9]),
    ("cust-007", 5100, 95.00, [10, 12, 24]),
    ("cust-008", 150, 500.00, [11]),
    ("cust-009", 1200, 2000.00, [13, 14, 20]),
    ("cust-010", 700, 300.00, [15, 16, 17, 19]),
]


def account_for(index: int) -> dict[str, str]:
    """Synthetic BSB/account for the 1-based payee index (BSB always 000xxx)."""
    return {
        "bsb": f"{100 + index // 10:06d}",
        "account_number": f"{70_000_000 + index * 1117:08d}",
    }


def build_files() -> dict[str, dict[str, Any]]:
    payees = {
        f"{acct['bsb']}-{acct['account_number']}": {
            "account_age_days": age,
            "name_on_account": name,
        }
        for i, (name, age) in enumerate(PAYEE_DEFS, start=1)
        for acct in [account_for(i)]
    }
    customers = [
        {
            "customer_id": customer_id,
            "tenure_days": tenure,
            "typical_payment_amount": typical,
            "known_payees": [account_for(i) for i in known],
        }
        for customer_id, tenure, typical, known in CUSTOMER_DEFS
    ]
    mules = [account_for(i) for i in MULE_PAYEE_INDEXES] + [MULE_ONLY_ACCOUNT]
    return {
        "customers.json": {"customers": customers},
        "payees.json": {"payees": payees},
        "mule_accounts.json": {"accounts": mules},
    }


def render(body: dict[str, Any]) -> str:
    return json.dumps({"_note": NOTE, **body}, indent=2) + "\n"


def generate(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, body in build_files().items():
        path = out_dir / name
        path.write_text(render(body), encoding="utf-8")
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    for path in generate(args.out_dir):
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
