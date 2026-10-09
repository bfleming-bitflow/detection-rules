from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
YARA_DIR = ROOT / "rules" / "yara"
SIGMA_DIR = ROOT / "rules" / "sigma"
YARA_FIXTURES = ROOT / "tests" / "fixtures" / "yara"
SIGMA_FIXTURES = ROOT / "tests" / "fixtures" / "sigma"


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT
