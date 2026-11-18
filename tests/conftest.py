import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))  # make tests/helpers.py importable


@pytest.fixture
def quarantine(tmp_path: Path) -> Path:
    q = tmp_path / "quarantine"
    q.mkdir()
    return q
