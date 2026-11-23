"""Encrypted Vault: AES-256-GCM with envelope key wrapping and recovery.

Design
------
A random 32-byte *master key* encrypts every entry. The master key itself is
never stored in the clear; it is wrapped (encrypted) twice:

``master.key``
    wrapped with a key derived from the user's password (PBKDF2-HMAC-SHA256),
``recovery.key``
    wrapped with a key derived from a 160-bit one-time recovery code.

That gives three properties a password-only design cannot offer:

* **recovery** - a forgotten password can be replaced with the recovery code,
  without the data becoming unrecoverable;
* **cheap password changes** - rotating the password re-wraps 32 bytes instead
  of re-encrypting every entry;
* **one KDF per session** - unlocking costs one PBKDF2 run, not one per entry.

On-disk formats (all integers big-endian)::

    entry    b"FGCVAULT2" | nonce(12) | AES-GCM ciphertext + tag(16)
             aad = magic | vault id (32 ascii bytes) | 0x00 | entry name

    key wrap b"FGCWRAP2" | iterations(4) | salt(16) | nonce(12) | wrapped key(48)
             aad = b"FGCWRAP2" | purpose (b"password" or b"recovery")

Binding the entry name *and* a random per-vault id into the associated data
means a ciphertext cannot be renamed, copied onto another entry name, or
transplanted from a different vault without failing authentication.

Legacy ``b"FGCVAULT1"`` entries (password-derived key per entry) are still
readable, so vaults written by the previous version keep working.

Hardening rules enforced here:

* the KDF cost stored in a file is bounded on both sides, so a crafted file
  cannot make decryption spin for hours (a denial-of-service bug in the
  previous version, which only checked the lower bound);
* temp files come from :func:`tempfile.mkstemp` with ``O_EXCL`` instead of a
  predictable ``.<name>.tmp`` path that could be pre-created as a symlink;
* entries are opened with ``O_NOFOLLOW`` and rejected if they are symlinks or
  not regular files;
* entry payloads and entry files are size-capped before reading;
* internal file names are reserved and cannot be used as entry names, which
  previously allowed ``put("master.key", ...)`` to overwrite key material;
* no plaintext or home-made cipher fallback exists if ``cryptography`` is
  missing - the vault reports itself unavailable instead.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import stat
import struct
import tempfile
from pathlib import Path

try:  # pragma: no cover - exercised only when the dependency is missing
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    AVAILABLE = True
except ImportError:  # pragma: no cover
    AVAILABLE = False

MAGIC = b"FGCVAULT2"
LEGACY_MAGIC = b"FGCVAULT1"
WRAP_MAGIC = b"FGCWRAP2"

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
VAULT_ID_SIZE = 32

DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 2_000_000

MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_KEYFILE_BYTES = 4096

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_BYTES = 1024
RECOVERY_CODE_LENGTH = 32
RECOVERY_GROUP = 4

ALGORITHM = "AES-256-GCM / PBKDF2-SHA256"

MASTER_KEY_FILE = "master.key"
RECOVERY_KEY_FILE = "recovery.key"
VAULT_ID_FILE = "vault.id"
RESERVED_NAMES = frozenset({MASTER_KEY_FILE, RECOVERY_KEY_FILE, VAULT_ID_FILE})

_PURPOSE_PASSWORD = b"password"
_PURPOSE_RECOVERY = b"recovery"

_ITERATIONS = struct.Struct(">I")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VAULT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_RECOVERY_RE = re.compile(r"^[A-Z2-7]{32}$")
_ENTRY_MODE = 0o600
_DIR_MODE = 0o700

# Rejected outright: a short password here protects a long-lived secret.
_WEAK_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password12",
        "password123",
        "passw0rd",
        "1234567890",
        "12345678901",
        "qwertyuiop",
        "letmein123",
        "changeme123",
        "forgecore",
        "forgecore1",
    }
)


class VaultError(Exception):
    """Base class for vault failures."""


class VaultUnavailable(VaultError):
    """Raised when the cryptography backend is not installed."""


class InvalidEntryName(VaultError):
    """Raised for entry names that could escape or shadow the vault."""


class VaultLocked(VaultError):
    """Raised when an operation needs the master key but the vault is locked."""


# -- validation ----------------------------------------------------------
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
    if candidate.lower() in RESERVED_NAMES:
        raise InvalidEntryName(f"{candidate!r} is reserved for vault key material")
    return candidate


def validate_password(password: str) -> str:
    """Enforce the password policy used for vault creation and rotation."""
    if not isinstance(password, str) or not password:
        raise VaultError("vault password must not be empty")
    if len(password) > MAX_PASSWORD_BYTES:
        raise VaultError(
            f"vault password must be at most {MAX_PASSWORD_BYTES} bytes"
        )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise VaultError(
            f"vault password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if password.strip().lower() in _WEAK_PASSWORDS:
        raise VaultError("vault password is too common; choose another one")
    if len(set(password)) < 4:
        raise VaultError("vault password is too repetitive; choose another one")
    return password


def clamp_iterations(iterations: int) -> int:
    """Clamp a KDF cost into the supported range."""
    try:
        value = int(iterations)
    except (TypeError, ValueError):
        value = DEFAULT_ITERATIONS
    return max(MIN_ITERATIONS, min(value, MAX_ITERATIONS))


def normalize_recovery_code(code: str) -> str:
    """Normalise a user-supplied recovery code (dashes and spaces ignored)."""
    if not isinstance(code, str):
        raise VaultError("recovery code must be a string")
    raw = re.sub(r"[\s-]", "", code).upper()
    if not _RECOVERY_RE.match(raw):
        raise VaultError(
            "recovery code must be 32 characters from A-Z and 2-7"
        )
    return raw


def format_recovery_code(code: str) -> str:
    """Group a normalised recovery code for human transcription."""
    return "-".join(
        code[index : index + RECOVERY_GROUP]
        for index in range(0, len(code), RECOVERY_GROUP)
    )


# -- key derivation ------------------------------------------------------
def _derive_key(secret: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise VaultError("vault password must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(secret.encode("utf-8"))


def _wrap_blob(master: bytes, secret: str, iterations: int, purpose: bytes) -> bytes:
    """Wrap ``master`` with a key derived from ``secret``."""
    rounds = clamp_iterations(iterations)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(secret, salt, rounds)
    wrapped = AESGCM(key).encrypt(nonce, master, WRAP_MAGIC + purpose)
    return WRAP_MAGIC + _ITERATIONS.pack(rounds) + salt + nonce + wrapped


def _blob_iterations(blob: bytes) -> int:
    """Read and validate the KDF cost declared by a wrap blob."""
    if len(blob) < len(WRAP_MAGIC) + _ITERATIONS.size:
        raise VaultError("key file is truncated")
    (iterations,) = _ITERATIONS.unpack_from(blob, len(WRAP_MAGIC))
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise VaultError("key file declares an unsafe KDF cost")
    return iterations


def _unwrap_blob(blob: bytes, secret: str, purpose: bytes) -> bytes:
    """Unwrap a master key, raising the generic failure message on mismatch."""
    header = len(WRAP_MAGIC) + _ITERATIONS.size + SALT_SIZE + NONCE_SIZE
    if len(blob) != header + KEY_SIZE + TAG_SIZE or not blob.startswith(WRAP_MAGIC):
        raise VaultError("key file is not a valid ForgeCore key wrap")
    iterations = _blob_iterations(blob)

    offset = len(WRAP_MAGIC) + _ITERATIONS.size
    salt = blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    wrapped = blob[offset:]

    key = _derive_key(secret, salt, iterations)
    try:
        master = AESGCM(key).decrypt(nonce, wrapped, WRAP_MAGIC + purpose)
    except InvalidTag:
        raise VaultError("wrong password or corrupted entry") from None
    if len(master) != KEY_SIZE:
        raise VaultError("key wrap contains an invalid key length")
    return master


class Vault:
    """A directory of individually encrypted entries."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._master: bytes | None = None

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _require_available() -> None:
        if not AVAILABLE:
            raise VaultUnavailable(
                "the 'cryptography' package is not installed; run "
                "'pip install cryptography' to enable the vault"
            )

    @property
    def master_key_path(self) -> Path:
        return self.root / MASTER_KEY_FILE

    @property
    def recovery_key_path(self) -> Path:
        return self.root / RECOVERY_KEY_FILE

    @property
    def vault_id_path(self) -> Path:
        return self.root / VAULT_ID_FILE

    @property
    def unlocked(self) -> bool:
        return self._master is not None

    def is_initialized(self) -> bool:
        """True when key material exists for this vault."""
        return self.master_key_path.is_file()

    def has_recovery(self) -> bool:
        """True when a recovery code has been generated for this vault."""
        return self.recovery_key_path.is_file()

    def lock(self) -> None:
        """Forget the master key held in memory."""
        self._master = None

    def _path(self, name: str) -> Path:
        return self.root / validate_name(name)

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        try:
            self.root.chmod(_DIR_MODE)
        except OSError:  # pragma: no cover - exotic filesystems
            pass

    def _fsync_dir(self) -> None:
        try:
            fd = os.open(self.root, os.O_RDONLY)
        except OSError:  # pragma: no cover - exotic filesystems
            return
        try:
            os.fsync(fd)
        except OSError:  # pragma: no cover
            pass
        finally:
            os.close(fd)

    def _write_atomic(self, path: Path, blob: bytes) -> None:
        """Write ``blob`` to ``path`` via an unpredictable temp file."""
        self._ensure_root()
        fd, tmp_name = tempfile.mkstemp(
            dir=self.root, prefix=".tmp-", suffix=".part"
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, _ENTRY_MODE)
            os.replace(tmp_name, path)
            self._fsync_dir()
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:  # pragma: no cover
                pass
            raise
        try:
            path.chmod(_ENTRY_MODE)
        except OSError:  # pragma: no cover - exotic filesystems
            pass

    def _read_file(self, path: Path, limit: int) -> bytes:
        """Read a file without following symlinks, refusing oversized content."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            if os.path.islink(path):
                raise VaultError(f"refusing to read symbolic link {path.name}") from None
            raise VaultError(f"cannot open {path.name}: {exc.strerror or exc}") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise VaultError(f"{path.name} is not a regular file")
            if info.st_size > limit:
                raise VaultError(
                    f"{path.name} is {info.st_size} bytes, the limit is {limit} bytes"
                )
            with os.fdopen(fd, "rb", closefd=False) as handle:
                return handle.read(limit + 1)
        finally:
            os.close(fd)

    def _vault_id(self, *, create: bool) -> bytes:
        """Return the per-vault identifier bound into every entry's AAD."""
        try:
            raw = self._read_file(self.vault_id_path, 128).decode("ascii").strip()
        except FileNotFoundError:
            if not create:
                raise VaultError(
                    "vault id is missing; this vault cannot be opened safely"
                ) from None
            raw = secrets.token_hex(VAULT_ID_SIZE // 2)
            self._write_atomic(self.vault_id_path, (raw + "\n").encode("ascii"))
        if not _VAULT_ID_RE.match(raw):
            raise VaultError("vault id file is corrupt")
        return raw.encode("ascii")

    def _aad(self, vault_id: bytes, entry_name: str) -> bytes:
        return MAGIC + vault_id + b"\x00" + entry_name.encode("utf-8")

    # -- key management --------------------------------------------------
    def init_vault(
        self, password: str, *, iterations: int = DEFAULT_ITERATIONS
    ) -> None:
        """Create the master key wrapped by ``password``.

        The caller is responsible for offering the user a recovery code via
        :meth:`create_recovery` right afterwards.
        """
        self._require_available()
        validate_password(password)
        if self.is_initialized():
            raise VaultError("vault is already initialized")
        self._ensure_root()
        master = os.urandom(KEY_SIZE)
        self._write_atomic(
            self.master_key_path,
            _wrap_blob(master, password, iterations, _PURPOSE_PASSWORD),
        )
        self._vault_id(create=True)
        self._master = master

    def unlock(self, password: str) -> "Vault":
        """Unwrap the master key with ``password`` and keep it in memory."""
        self._require_available()
        if not self.is_initialized():
            raise VaultError("vault is not initialized")
        try:
            blob = self._read_file(self.master_key_path, MAX_KEYFILE_BYTES)
        except FileNotFoundError:
            raise VaultError("vault is not initialized") from None
        self._master = _unwrap_blob(blob, password, _PURPOSE_PASSWORD)
        return self

    def create_recovery(self, *, iterations: int = DEFAULT_ITERATIONS) -> str:
        """Wrap the master key with a fresh recovery code and return it.

        The code is shown once; it is never written anywhere in plaintext.
        """
        self._require_available()
        if self._master is None:
            raise VaultLocked("unlock the vault before creating a recovery code")
        code = base64.b32encode(os.urandom(20)).decode("ascii")
        if not _RECOVERY_RE.match(code):  # pragma: no cover - defensive
            raise VaultError("failed to generate a recovery code")
        self._write_atomic(
            self.recovery_key_path,
            _wrap_blob(self._master, code, iterations, _PURPOSE_RECOVERY),
        )
        return format_recovery_code(code)

    def recover(self, recovery_code: str, new_password: str) -> str:
        """Re-wrap the master key under a new password using the recovery code.

        Returns a fresh recovery code: the previous one stops working, so a
        leaked code cannot be replayed after a recovery.
        """
        self._require_available()
        validate_password(new_password)
        if not self.has_recovery():
            raise VaultError("this vault has no recovery code configured")
        code = normalize_recovery_code(recovery_code)
        try:
            blob = self._read_file(self.recovery_key_path, MAX_KEYFILE_BYTES)
        except FileNotFoundError:
            raise VaultError("this vault has no recovery code configured") from None
        iterations = _blob_iterations(blob)
        try:
            master = _unwrap_blob(blob, code, _PURPOSE_RECOVERY)
        except VaultError:
            raise VaultError(
                "recovery code is not valid for this vault"
            ) from None
        self._write_atomic(
            self.master_key_path,
            _wrap_blob(master, new_password, iterations, _PURPOSE_PASSWORD),
        )
        self._vault_id(create=True)
        self._master = master
        try:
            self.recovery_key_path.unlink()
        except FileNotFoundError:  # pragma: no cover
            pass
        return self.create_recovery(iterations=iterations)

    def change_password(self, old_password: str, new_password: str) -> None:
        """Re-wrap the master key under ``new_password``; entries are untouched."""
        self._require_available()
        validate_password(new_password)
        if not self.is_initialized():
            raise VaultError("vault is not initialized")
        try:
            blob = self._read_file(self.master_key_path, MAX_KEYFILE_BYTES)
        except FileNotFoundError:
            raise VaultError("vault is not initialized") from None
        iterations = _blob_iterations(blob)
        master = _unwrap_blob(blob, old_password, _PURPOSE_PASSWORD)
        self._write_atomic(
            self.master_key_path,
            _wrap_blob(master, new_password, iterations, _PURPOSE_PASSWORD),
        )
        self._master = master

    # -- entry operations ------------------------------------------------
    def put(
        self,
        name: str,
        data: bytes,
        password: str | None = None,
        *,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> Path:
        """Encrypt ``data`` into the entry ``name`` and return its path."""
        self._require_available()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise VaultError("vault payload must be bytes")
        payload = bytes(data)
        if len(payload) > MAX_ENTRY_BYTES:
            raise VaultError(
                f"payload is {len(payload)} bytes, the entry limit is "
                f"{MAX_ENTRY_BYTES} bytes"
            )
        entry_name = validate_name(name)

        if self._master is None:
            if not self.is_initialized():
                if password is None:
                    raise VaultError("vault password required to initialize the vault")
                self.init_vault(password, iterations=iterations)
            else:
                if password is None:
                    raise VaultLocked(
                        "vault is locked: provide the password or call unlock()"
                    )
                self.unlock(password)

        vault_id = self._vault_id(create=True)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(self._master).encrypt(
            nonce, payload, self._aad(vault_id, entry_name)
        )
        path = self.root / entry_name
        self._write_atomic(path, MAGIC + nonce + ciphertext)
        return path

    def get(self, name: str, password: str | None = None) -> bytes:
        """Decrypt and return the payload of ``name``."""
        self._require_available()
        entry_name = validate_name(name)
        path = self.root / entry_name
        try:
            blob = self._read_file(path, MAX_ENTRY_BYTES + 1024)
        except FileNotFoundError:
            raise VaultError(f"no such vault entry: {entry_name}") from None

        if blob.startswith(MAGIC):
            return self._get_wrapped(blob, entry_name, password)
        if blob.startswith(LEGACY_MAGIC):
            return self._get_legacy(blob, entry_name, password)
        raise VaultError(f"vault entry {entry_name} is not a valid ForgeCore entry")

    def _get_wrapped(
        self, blob: bytes, entry_name: str, password: str | None
    ) -> bytes:
        if len(blob) < len(MAGIC) + NONCE_SIZE + TAG_SIZE:
            raise VaultError(f"vault entry {entry_name} is truncated")
        if self._master is None:
            if password is None:
                raise VaultLocked(
                    "vault is locked: provide the password or call unlock()"
                )
            self.unlock(password)
        nonce = blob[len(MAGIC) : len(MAGIC) + NONCE_SIZE]
        ciphertext = blob[len(MAGIC) + NONCE_SIZE :]
        try:
            return AESGCM(self._master).decrypt(
                nonce, ciphertext, self._aad(self._vault_id(create=False), entry_name)
            )
        except InvalidTag:
            # Deliberately identical for a bad password and a tampered file.
            raise VaultError(
                f"cannot decrypt {entry_name}: wrong password or corrupted entry"
            ) from None

    def _get_legacy(
        self, blob: bytes, entry_name: str, password: str | None
    ) -> bytes:
        """Read an entry written by the previous password-derived format."""
        if password is None:
            raise VaultLocked(
                "this entry uses the legacy format and needs the vault password"
            )
        header = len(LEGACY_MAGIC) + _ITERATIONS.size + SALT_SIZE + NONCE_SIZE
        if len(blob) < header + TAG_SIZE:
            raise VaultError(f"vault entry {entry_name} is truncated")
        (iterations,) = _ITERATIONS.unpack_from(blob, len(LEGACY_MAGIC))
        if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
            raise VaultError(
                f"vault entry {entry_name} declares an unsafe KDF cost"
            )
        offset = len(LEGACY_MAGIC) + _ITERATIONS.size
        salt = blob[offset : offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce = blob[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = blob[offset:]
        key = _derive_key(password, salt, iterations)
        try:
            return AESGCM(key).decrypt(
                nonce, ciphertext, LEGACY_MAGIC + entry_name.encode("utf-8")
            )
        except InvalidTag:
            raise VaultError(
                f"cannot decrypt {entry_name}: wrong password or corrupted entry"
            ) from None

    def delete(self, name: str) -> bool:
        """Remove an entry. Returns ``True`` when something was deleted."""
        entry_name = validate_name(name)
        path = self.root / entry_name
        if path.is_symlink():
            path.unlink()
            return True
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        except IsADirectoryError:
            raise VaultError(f"vault entry {entry_name} is not a regular file") from None
        self._fsync_dir()
        return True

    def list(self) -> list[str]:
        """Return the sorted entry names currently stored in the vault."""
        if not self.root.is_dir():
            return []
        names: list[str] = []
        for item in self.root.iterdir():
            name = item.name
            if name.startswith(".") or name in RESERVED_NAMES:
                continue
            if item.is_symlink() or not item.is_file():
                continue
            if _NAME_RE.match(name):
                names.append(name)
        return sorted(names)

    def exists(self, name: str) -> bool:
        try:
            path = self._path(name)
        except InvalidEntryName:
            return False
        return path.is_file() and not path.is_symlink()
