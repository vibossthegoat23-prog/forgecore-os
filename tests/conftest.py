from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # allow running tests without installing
    sys.path.insert(0, str(REPO_ROOT))

from forgecore.config import Home  # noqa: E402


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Home:
    """An isolated ForgeCore home directory for one test."""
    root = tmp_path / "forgecore-home"
    monkeypatch.setenv("FORGECORE_HOME", str(root))
    monkeypatch.delenv("FORGECORE_VAULT_PASSWORD", raising=False)
    return Home(root=root)

# The background scheduler is exercised explicitly by its own tests; keep every
# other test free of a live thread.
import os as _os

_os.environ.setdefault("FORGECORE_SCHEDULER", "0")
