"""Filesystem layout for a ForgeCore home directory.

Everything the program writes lives under a single root so the state is easy to
inspect, back up or delete. The root defaults to ``~/.forgecore`` and can be
overridden with the ``FORGECORE_HOME`` environment variable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENV_HOME = "FORGECORE_HOME"
ENV_VAULT_PASSWORD = "FORGECORE_VAULT_PASSWORD"

DEFAULT_DIR_MODE = 0o700


@dataclass(frozen=True)
class Home:
    """Resolved on-disk layout for one ForgeCore installation."""

    root: Path

    @property
    def vault_dir(self) -> Path:
        return self.root / "vault"

    @property
    def uploads_dir(self) -> Path:
        return self.root / "uploads"

    @property
    def agents_file(self) -> Path:
        return self.root / "agents.json"

    def ensure(self) -> "Home":
        """Create the home directories with owner-only permissions."""
        for directory in (self.root, self.vault_dir, self.uploads_dir):
            directory.mkdir(parents=True, exist_ok=True, mode=DEFAULT_DIR_MODE)
            try:
                directory.chmod(DEFAULT_DIR_MODE)
            except OSError:  # pragma: no cover - exotic filesystems
                pass
        return self


def default_home() -> Home:
    """Return the home directory selected by ``FORGECORE_HOME`` or the default."""
    raw = os.environ.get(ENV_HOME)
    root = Path(raw).expanduser() if raw else Path.home() / ".forgecore"
    return Home(root=root)
