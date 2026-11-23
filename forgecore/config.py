"""Filesystem layout for a ForgeCore home directory.

Everything the program writes lives under a single root so the state is easy to
inspect, back up or delete. The root defaults to ``~/.forgecore`` and can be
overridden with the ``FORGECORE_HOME`` environment variable.

The home directory holds three kinds of file:

``master.key``
    The vault master key wrapped (encrypted) with the password-derived key.
``recovery.key``
    The same master key wrapped with a one-time recovery code, so a forgotten
    password no longer destroys the data.
``vault.id``
    A random identifier bound into every entry's associated data, so entries
    copied from a different vault cannot be transplanted into this one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENV_HOME = "FORGECORE_HOME"
ENV_VAULT_PASSWORD = "FORGECORE_VAULT_PASSWORD"
ENV_CONSOLE_PASSWORD = "FORGECORE_CONSOLE_PASSWORD"
ENV_RECOVERY_CODE = "FORGECORE_RECOVERY_CODE"
ENV_KDF_ITERATIONS = "FORGECORE_KDF_ITERATIONS"
ENV_SESSION_SECRET = "FORGECORE_SESSION_SECRET"

DEFAULT_DIR_MODE = 0o700
DEFAULT_FILE_MODE = 0o600


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

    @property
    def master_key_file(self) -> Path:
        return self.root / "master.key"

    @property
    def recovery_key_file(self) -> Path:
        return self.root / "recovery.key"

    @property
    def vault_id_file(self) -> Path:
        return self.root / "vault.id"

    @property
    def audit_log_file(self) -> Path:
        return self.root / "audit.log"

    @property
    def session_secret_file(self) -> Path:
        return self.root / "session.secret"

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


def kdf_iterations(default: int) -> int:
    """Return the KDF cost from ``FORGECORE_KDF_ITERATIONS`` or ``default``.

    The value is clamped by the vault itself; a malformed value is ignored
    rather than silently weakening or stalling the KDF.
    """
    raw = os.environ.get(ENV_KDF_ITERATIONS)
    if not raw:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default
