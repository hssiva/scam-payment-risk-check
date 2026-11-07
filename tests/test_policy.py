from decimal import Decimal
from pathlib import Path

import pytest

from scamcheck.policy import POLICY_PATH_ENV, PolicyError, default_policy_path, load_policy

VALID = """
policy_version = "t1"
high_value_amount = 5000
abstain_amount = 1000
unusual_ratio = 5
young_account_days = 30
score_warn = 0.35
score_hold = 0.70
name_close_threshold = 0.8
max_amount = 1000000

[evaluation]
min_scam_warn_or_hold_rate = 0.9
max_genuine_hold_rate = 0.1
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(text)
    return path


def test_real_policy_values() -> None:
    policy = load_policy()
    assert policy.policy_version == "2026.11.1"
    assert policy.high_value_amount == Decimal("3000")
    assert policy.abstain_amount == Decimal("1000")
    assert policy.unusual_ratio == Decimal("5")
    assert policy.young_account_days == 30
    assert policy.score_warn == 0.35
    assert policy.score_hold == 0.70
    assert policy.name_close_threshold == 0.80
    assert policy.max_amount == Decimal("1000000")
    assert policy.evaluation.min_scam_warn_or_hold_rate == 0.90
    assert policy.evaluation.max_genuine_hold_rate == 0.10


def test_valid_custom_policy(tmp_path: Path) -> None:
    assert load_policy(write(tmp_path, VALID)).policy_version == "t1"


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as info:
        load_policy(tmp_path / "nope.toml")
    assert "missing" in info.value.message


def test_path_may_be_given_as_a_string(tmp_path: Path) -> None:
    good = write(tmp_path, VALID)
    assert load_policy(str(good)).policy_version == "t1"
    with pytest.raises(PolicyError):
        load_policy(str(tmp_path / "does-not-exist.toml"))


def test_invalid_toml(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as info:
        load_policy(write(tmp_path, "this is = = not toml"))
    assert "TOML" in info.value.message


@pytest.mark.parametrize(
    "text",
    [
        VALID.replace('policy_version = "t1"\n', ""),  # missing key
        VALID + "surprise = 1\n",  # unknown key
        VALID.replace("high_value_amount = 5000", "high_value_amount = 0"),
        VALID.replace("unusual_ratio = 5", "unusual_ratio = -1"),
        VALID.replace("young_account_days = 30", "young_account_days = 30.5"),
        VALID.replace("score_warn = 0.35", "score_warn = 0.8"),  # warn >= hold
        VALID.replace("score_hold = 0.70", "score_hold = 1.5"),
        VALID.replace("name_close_threshold = 0.8", "name_close_threshold = 0"),
        VALID.replace("name_close_threshold = 0.8", "name_close_threshold = 1.5"),
        VALID.replace("name_close_threshold = 0.8\n", ""),  # missing key
        VALID.replace("max_amount = 1000000", 'max_amount = "lots"'),
        VALID.replace("min_scam_warn_or_hold_rate = 0.9", "min_scam_warn_or_hold_rate = 0"),
        VALID.replace("max_genuine_hold_rate = 0.1", "max_genuine_hold_rate = 1.5"),
        VALID.replace("[evaluation]\n", "[evaluation]\nextra_gate = 1\n"),
        VALID.replace(
            "\n[evaluation]\nmin_scam_warn_or_hold_rate = 0.9\nmax_genuine_hold_rate = 0.1\n", ""
        ),
    ],
)
def test_invalid_policy_values(tmp_path: Path, text: str) -> None:
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, text))


def test_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = write(tmp_path, VALID)
    monkeypatch.setenv(POLICY_PATH_ENV, str(path))
    assert default_policy_path() == path
    assert load_policy().policy_version == "t1"
