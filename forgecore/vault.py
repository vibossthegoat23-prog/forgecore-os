"""Encrypted Vault: AES-256-GCM with a PBKDF2-HMAC-SHA256 derived key.

On-disk format of every vault entry (all integers big-endian)::

    magic       8 bytes   b"FGCVAULT1"
    iterations  4 bytes   PBKDF2 iteration count used for this entry
    salt       16 bytes   random per entry
    nonce      12 bytes   random per write, never reused
    ciphertext  n bytes   AES-256-GCM(payload, aad=magic+entry name) + 16-byte tag

The entry name is used as associated data, so a ciphertext cannot be renamed or
copied to a different entry name without failing authentication. Entries are
written atomically (temp file + ``os.replace``) with mode ``0600``.

If the ``cryptography`` package is unavailable the vault reports itself as
unavailable and every operation raises :class:`VaultUnavailable`. It never falls
back to storing plaintext or a home-made cipher.
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path

try:  # pragma: no cover - exercised only when the dependency is missing
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    AVAILABLE = True
except ImportError:  # pragma: no cover
    AVAILABLE = False

MAGIC = b"FGCVAULT1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 100_000
ALGORITHM = "AES-256-GCM / PBKDF2-SHA256"

_ITERATIONS = struct.Struct(">I")
_HEADER_SIZE = len(MAGIC) + _ITERATIONS.size + SALT_SIZE + NONCE_SIZE
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENTRY_MODE = 0o600


class VaultError(Exception):
    """Base class for vault failures."""


class VaultUnavailable(VaultError):
    """Raised when the cryptography backend is not installed."""


class InvalidEntryName(VaultError):
    """Raised for entry names that could escape the vault directory."""


def validate_name(name: str) -> str:
    """Validate an entry name and return it unchanged."""
    if not isinstance(name, str):
        raise InvalidEntryName("vault entry name must be a string")
    candidate = name.strip()
    if not _NAME_RE.match(candidate):
        raise InvalidEntryName(
            f"invalid vault entry name {name!r}: use 1-128 characters from "
            "A-Z, a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
        )
    return candidate


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(password, str) or not password:
        raise VaultError("vault password must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


class Vault:
    """A directory of individually encrypted entries."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _require_available() -> None:
        if not AVAILABLE:
            raise VaultUnavailable(
                "the 'cryptography' package is not installed; run "
                "'pip install cryptography' to enable the vault"
            )

    def _path(self, name: str) -> Path:
        return self.root / validate_name(name)

    def _write_atomic(self, path: Path, blob: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_name(f".{path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _ENTRY_MODE)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        try:
            path.chmod(_ENTRY_MODE)
        except OSError:  # pragma: no cover - exotic filesystems
            pass

    # -- public API ------------------------------------------------------
    def put(
        self,
        name: str,
        data: bytes,
        password: str,
        *,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> Path:
        """Encrypt ``data`` into the entry ``name`` and return its path."""
        self._require_available()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise VaultError("vault payload must be bytes")
        entry_name = validate_name(name)
        path = self.root / entry_name
        rounds = max(int(iterations), MIN_ITERATIONS)

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = _derive_key(password, salt, rounds)
        ciphertext = AESGCM(key).encrypt(
            nonce, bytes(data), MAGIC + entry_name.encode("utf-8")
        )
        blob = MAGIC + _ITERATIONS.pack(rounds) + salt + nonce + ciphertext
        self._write_atomic(path, blob)
        return path

    def get(self, name: str, password: str) -> bytes:
        """Decrypt and return the payload of ``name``."""
        self._require_available()
        entry_name = validate_name(name)
        path = self.root / entry_name
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            raise VaultError(f"no such vault entry: {entry_name}") from None

        if len(blob) < _HEADER_SIZE + TAG_SIZE or not blob.startswith(MAGIC):
            raise VaultError(f"vault entry {entry_name} is not a valid ForgeCore entry")

        offset = len(MAGIC)
        (iterations,) = _ITERATIONS.unpack_from(blob, offset)
        offset += _ITERATIONS.size
        if iterations < MIN_ITERATIONS:
            raise VaultError(f"vault entry {entry_name} declares an unsafe KDF cost")
        salt = blob[offset : offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = blob[offset:]

        key = _derive_key(password, salt, iterations)
        try:
            return AESGCM(key).decrypt(
                nonce, ciphertext, MAGIC + entry_name.encode("utf-8")
            )
        except InvalidTag:
            # Deliberately identical for a bad password and a tampered file.
            raise VaultError(
                f"cannot decrypt {entry_name}: wrong password or corrupted entry"
            ) from None

    def delete(self, name: str) -> bool:
        """Remove an entry. Returns ``True`` when something was deleted."""
        entry_name = validate_name(name)
        path = self.root / entry_name
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True

    def list(self) -> list[str]:
        """Return the sorted entry names currently stored in the vault."""
        if not self.root.is_dir():
            return []
        names = [
            item.name
            for item in self.root.iterdir()
            if item.is_file() and _NAME_RE.match(item.name) and not item.name.startswith(".")
        ]
        return sorted(names)

    def exists(self, name: str) -> bool:
        return self._path(name).is_file()
