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
import shutil
from dataclasses import dataclass
from pathlib import Path

ENV_HOME = "FORGECORE_HOME"
ENV_VAULT_PASSWORD = "FORGECORE_VAULT_PASSWORD"
ENV_CONSOLE_PASSWORD = "FORGECORE_CONSOLE_PASSWORD"
ENV_RECOVERY_CODE = "FORGECORE_RECOVERY_CODE"
ENV_KDF_ITERATIONS = "FORGECORE_KDF_ITERATIONS"
ENV_SESSION_SECRET = "FORGECORE_SESSION_SECRET"
ENV_PERSISTENT = "FORGECORE_PERSISTENT_STORAGE"
ENV_UPLOAD_QUOTA = "FORGECORE_UPLOAD_QUOTA_BYTES"

DEFAULT_DIR_MODE = 0o700
DEFAULT_FILE_MODE = 0o600
DEFAULT_UPLOAD_QUOTA_BYTES = 2 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 64 * 1024 * 1024


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
        return self.vault_dir / "master.key"

    @property
    def recovery_key_file(self) -> Path:
        return self.vault_dir / "recovery.key"

    @property
    def vault_id_file(self) -> Path:
        return self.vault_dir / "vault.id"

    @property
    def audit_log_file(self) -> Path:
        return self.root / "audit.log"

    @property
    def session_secret_file(self) -> Path:
        return self.root / "session.secret"

    @property
    def console_hash_file(self) -> Path:
        """Salted hash of the first-run console password (never the password)."""
        return self.root / "console.json"

    @property
    def backups_dir(self) -> Path:
        return self.root / "backups"

    def storage_is_persistent(self) -> bool:
        """True when the operator declared the home directory as persistent.

        AppJet's Free plan has no persistent disk, so the container layer is
        wiped on redeploy. The console warns about that unless the operator
        states the data really survives a restart.
        """
        return os.environ.get(ENV_PERSISTENT, "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def free_bytes(self) -> int:
        """Free space on the filesystem holding the home directory."""
        try:
            return shutil.disk_usage(self.root).free
        except OSError:  # pragma: no cover - exotic filesystems
            return 0

    def check_writable(self) -> None:
        """Prove the state directory is writable, or fail with a clear reason.

        Called at startup so a read-only or full volume is reported immediately
        instead of surfacing later as a half-written vault entry.
        """
        self.ensure()
        probe = self.root / f".write-probe-{os.getpid()}"
        try:
            fd = os.open(
                probe,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                DEFAULT_FILE_MODE,
            )
            try:
                os.write(fd, b"probe")
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise RuntimeError(
                f"cannot write to {self.root} ({exc.strerror or exc}); mount a "
                f"writable volume and point {ENV_HOME} at it"
            ) from None
        finally:
            probe.unlink(missing_ok=True)

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


def upload_quota(default: int = DEFAULT_UPLOAD_QUOTA_BYTES) -> int:
    """Return the total uploads quota from ``FORGECORE_UPLOAD_QUOTA_BYTES``."""
    raw = os.environ.get(ENV_UPLOAD_QUOTA)
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


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
