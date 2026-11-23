"""Encrypted off-host replication of the whole installation state.

A host without a persistent disk wipes its container layer whenever the app is
redeployed or recreated, taking the vault, the uploads, the agent registry and
the console password hash with it. A manual backup only helps if somebody
downloads it before the wipe, which is not something to rely on.

This module keeps an encrypted copy of the same archive produced by
:mod:`forgecore.backup` on a destination the operator controls, and restores it
automatically when a fresh container starts with no local state:

``FORGECORE_REPLICA_URL``
    HTTPS endpoint that accepts ``PUT`` of the sealed archive and returns the
    latest copy on ``GET``. Any object store or small receiver that accepts a
    bearer token works.
``FORGECORE_REPLICA_TOKEN``
    Bearer token sent with every request.
``FORGECORE_REPLICA_KEY``
    Passphrase used to encrypt the archive before it leaves the host.
``FORGECORE_REPLICA_AUTORESTORE``
    Set to ``0``/``false`` to keep automatic restore off.

The archive is sealed with AES-256-GCM under a PBKDF2-HMAC-SHA256 key, so the
destination only ever holds ciphertext. Sealing is mandatory: uploads are
stored unencrypted inside the archive, so a plaintext remote copy would expose
them.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forgecore import __version__
from forgecore.backup import MAX_ARCHIVE_BYTES, create_backup, restore_backup
from forgecore.config import (
    ENV_REPLICA_AUTORESTORE,
    ENV_REPLICA_KEY,
    ENV_REPLICA_TOKEN,
    ENV_REPLICA_URL,
    Home,
)
from forgecore.security import utcnow_iso

MAGIC = b"FCREPLICA1\n"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
PBKDF2_ITERATIONS = 200_000
HTTP_TIMEOUT_SECONDS = 20
MAX_REMOTE_BYTES = MAX_ARCHIVE_BYTES + 64 * 1024

# Local snapshots are a convenience for a restart inside the same container;
# they do not survive a redeploy, which is what the replica is for.
SNAPSHOT_KEEP = 3

_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


class ReplicaError(Exception):
    """Raised when a replica operation cannot be completed."""


@dataclass(frozen=True)
class ReplicaConfig:
    """Where and how the encrypted replica is stored."""

    url: str
    token: str
    key: str
    autorestore: bool = True

    @property
    def host(self) -> str:
        """Host name of the endpoint, safe to show in the console."""
        try:
            return urllib.parse.urlsplit(self.url).hostname or ""
        except ValueError:  # pragma: no cover - defensive
            return ""

    @classmethod
    def from_env(cls) -> "ReplicaConfig | None":
        """Return the configured replica, or ``None`` when it is not set up."""
        url = os.environ.get(ENV_REPLICA_URL, "").strip()
        if not url:
            return None
        flag = os.environ.get(ENV_REPLICA_AUTORESTORE, "1").strip().lower()
        return cls(
            url=url,
            token=os.environ.get(ENV_REPLICA_TOKEN, "").strip(),
            key=os.environ.get(ENV_REPLICA_KEY, "").strip(),
            autorestore=flag not in {"0", "false", "no", "off"},
        )


def _cryptography():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        raise ReplicaError(
            "the 'cryptography' package is not installed; replication is disabled"
        ) from None
    return AESGCM


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, KEY_BYTES
    )


def seal(archive: bytes, passphrase: str) -> bytes:
    """Encrypt a backup archive for storage off-host."""
    if not passphrase:
        raise ReplicaError(
            f"{ENV_REPLICA_KEY} is required: uploads are unencrypted inside the "
            "archive, so the remote copy must be encrypted"
        )
    AESGCM = _cryptography()
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, archive, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def unseal(blob: bytes, passphrase: str) -> bytes:
    """Decrypt a sealed replica, rejecting anything tampered with."""
    if not passphrase:
        raise ReplicaError(f"{ENV_REPLICA_KEY} is required to read the replica")
    header = len(MAGIC) + SALT_BYTES + NONCE_BYTES
    if len(blob) <= header or not blob.startswith(MAGIC):
        raise ReplicaError("the remote copy is not a ForgeCore replica")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_BYTES]
    nonce = blob[len(MAGIC) + SALT_BYTES : header]
    AESGCM = _cryptography()
    try:
        return AESGCM(_derive_key(passphrase, salt)).decrypt(
            nonce, blob[header:], MAGIC
        )
    except Exception:
        # Wrong key or a modified ciphertext: both are authentication failures.
        raise ReplicaError(
            "the remote copy could not be decrypted; check "
            f"{ENV_REPLICA_KEY} matches the key it was written with"
        ) from None


def _checked_url(url: str) -> str:
    """Reject endpoints that would send the token over cleartext."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ReplicaError(f"{ENV_REPLICA_URL} must be an http(s) URL")
    if parts.scheme == "http" and (parts.hostname or "") not in _LOOPBACK:
        raise ReplicaError(
            "refusing to send the replica token over plain HTTP; use an https "
            "endpoint"
        )
    return url


def _request(config: ReplicaConfig, method: str, body: bytes | None = None) -> bytes:
    url = _checked_url(config.url)
    headers = {
        "User-Agent": f"ForgeCore/{__version__}",
        "Accept": "application/octet-stream",
    }
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise ReplicaError(f"replica endpoint returned HTTP {status}")
            payload = response.read(MAX_REMOTE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ReplicaNotFound("no replica exists at the configured endpoint") from None
        raise ReplicaError(f"replica endpoint returned HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise ReplicaError(f"cannot reach the replica endpoint ({exc.reason})") from None
    except TimeoutError:
        raise ReplicaError("the replica endpoint did not answer in time") from None
    if len(payload) > MAX_REMOTE_BYTES:
        raise ReplicaError("the remote copy is larger than the supported size")
    return payload


class ReplicaNotFound(ReplicaError):
    """Raised when the endpoint is reachable but holds no replica yet."""


def write_local_snapshot(home: Home) -> Path:
    """Write the current state to ``backups/`` and keep the newest few."""
    data, filename = create_backup(home)
    directory = home.backups_dir
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / filename
    staging = directory / f".{filename}.tmp"
    fd = os.open(
        staging,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(staging, target)
    snapshots = sorted(
        (item for item in directory.glob("forgecore-backup-*.tar.gz") if item.is_file()),
        key=lambda item: item.name,
    )
    for stale in snapshots[:-SNAPSHOT_KEEP]:
        stale.unlink(missing_ok=True)
    return target


def push(home: Home, config: ReplicaConfig) -> dict[str, Any]:
    """Seal the current state and store it at the replica endpoint."""
    data, filename = create_backup(home)
    blob = seal(data, config.key)
    _request(config, "PUT", blob)
    return {
        "at": utcnow_iso(),
        "bytes": len(blob),
        "archive_bytes": len(data),
        "name": filename,
        "endpoint": config.host,
    }


def pull(home: Home, config: ReplicaConfig) -> dict[str, Any]:
    """Fetch the replica and replace the local state with it."""
    blob = _request(config, "GET")
    archive = unseal(blob, config.key)
    return restore_backup(home, archive)


class ReplicaSyncer:
    """Push state to the replica shortly after every change.

    Writes are debounced: a burst of changes results in one upload instead of
    one per request, and the upload happens on a background thread so a slow
    endpoint never delays a response.
    """

    def __init__(
        self,
        home: Home,
        config: ReplicaConfig | None = None,
        *,
        debounce: float = 1.0,
    ) -> None:
        self.home = home
        self.config = config if config is not None else ReplicaConfig.from_env()
        self.debounce = debounce
        self._wake = threading.Event()
        self._push_lock = threading.Lock()
        self._thread_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._last: dict[str, Any] = {
            "at": None,
            "ok": None,
            "error": None,
            "bytes": 0,
        }

    @property
    def configured(self) -> bool:
        return self.config is not None

    def status(self) -> dict[str, Any]:
        with self._thread_lock:
            last = dict(self._last)
        return {
            "configured": self.configured,
            "endpoint": self.config.host if self.config else None,
            "key_configured": bool(self.config and self.config.key),
            "autorestore": bool(self.config and self.config.autorestore),
            "last_at": last["at"],
            "last_ok": last["ok"],
            "last_error": last["error"],
            "last_bytes": last["bytes"],
            "pending": self._wake.is_set(),
        }

    def _record(self, *, ok: bool, error: str | None, size: int) -> None:
        with self._thread_lock:
            self._last = {
                "at": utcnow_iso(),
                "ok": ok,
                "error": error,
                "bytes": size,
            }

    def push_once(self) -> dict[str, Any]:
        """Snapshot locally, then upload. Raises :class:`ReplicaError`."""
        if self.config is None:
            raise ReplicaError("no replica endpoint is configured")
        with self._push_lock:
            try:
                write_local_snapshot(self.home)
            except Exception:
                # A snapshot is best effort; the remote copy is what matters.
                pass
            try:
                result = push(self.home, self.config)
            except ReplicaError as exc:
                self._record(ok=False, error=str(exc), size=0)
                raise
            self._record(ok=True, error=None, size=result["bytes"])
            return result

    def mark_dirty(self) -> bool:
        """Queue a push. Returns ``True`` when replication is enabled."""
        if self.config is None:
            return False
        self._wake.set()
        with self._thread_lock:
            if self._thread is None or not self._thread.is_alive():
                thread = threading.Thread(
                    target=self._loop, name="forgecore-replica", daemon=True
                )
                self._thread = thread
                thread.start()
        return True

    def _loop(self) -> None:
        while True:
            if not self._wake.wait(timeout=0.25):
                return  # idle: let the thread exit
            self._wake.clear()
            if self.debounce:
                time.sleep(self.debounce)
            try:
                self.push_once()
            except ReplicaError:
                pass  # recorded in status() and the audit log by the caller

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait for any queued or running push. Used by tests and shutdown."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self._wake.is_set() and self._push_lock.acquire(
                timeout=0.05
            ):
                self._push_lock.release()
                return True
            time.sleep(0.02)
        return False
