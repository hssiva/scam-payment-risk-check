import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_reference_data.py"
COMMITTED = ROOT / "sample-data" / "reference"
FILES = ("customers.json", "payees.json", "mule_accounts.json")


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_reference_data", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_reproduces_committed_files_exactly(
    generator: ModuleType, tmp_path: Path
) -> None:
    written = generator.generate(tmp_path)
    assert sorted(p.name for p in written) == sorted(FILES)
    for name in FILES:
        assert (tmp_path / name).read_bytes() == (COMMITTED / name).read_bytes(), name


def test_generator_is_deterministic(generator: ModuleType, tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    generator.generate(first)
    generator.generate(second)
    for name in FILES:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_generated_bsbs_stay_in_synthetic_range(generator: ModuleType) -> None:
    text = "".join(generator.render(body) for body in generator.build_files().values())
    assert '"bsb": "' in text
    for line in text.splitlines():
        if '"bsb"' in line:
            assert line.split('"')[3].startswith("000")
