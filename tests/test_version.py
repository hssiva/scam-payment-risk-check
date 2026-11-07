import scamcheck


def test_version_is_semver_like() -> None:
    parts = scamcheck.__version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
