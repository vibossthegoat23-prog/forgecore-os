"""Backup and restore of a ForgeCore home directory.

A backup is a gzip-compressed tar archive containing the whole on-disk state:

* ``master.key`` / ``recovery.key`` / ``vault.id`` - wrapped key material,
* ``vault/`` - individually encrypted entries (ciphertext only),
* ``uploads/`` - stored files,
* ``agents.json`` and ``audit.log``.

The archive carries a JSON manifest with the SHA-256 and size of every member,
so a truncated or tampered archive is rejected instead of half-restored.

Safety rules enforced on restore:

* every member must be a regular file with a name this program would itself
  write - no absolute paths, no ``..``, no symlinks, hardlinks or devices;
* the member count and the total uncompressed size are capped, so a crafted
  archive cannot exhaust the disk (a zip/tar bomb);
* every member is checked against the manifest checksum before anything is
  touched;
* the new state is staged next to the live one and swapped in with
  ``os.replace``; if the swap fails the previous state is put back, so a failed
  restore never leaves an empty installation.

Uploads are stored unencrypted, exactly as they are on disk, so a backup
archive must be handled as sensitive material.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import tarfile
import time
from pathlib import Path
from typing import Any

from forgecore import __version__
from forgecore.config import Home
from forgecore.security import utcnow_iso
from forgecore.uploads import UploadError, sanitize_name
from forgecore.vault import InvalidEntryName, validate_name

MANIFEST_NAME = "forgecore-manifest.json"
BACKUP_FORMAT = 1

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 5000

# The vault keeps its key material *inside* the vault directory
# (vault/master.key, vault/recovery.key, vault/vault.id); everything else sits
# in the home root. These paths are declared explicitly because inferring them
# once produced a backup that silently carried no key material at all.
VAULT_KEY_FILES = ("master.key", "recovery.key", "vault.id")
STATE_FILES = ("agents.json", "audit.log", "audit.log.1", "session.secret")
STATE_DIRS = ("vault", "uploads")
# Every top-level name restore_backup() has to swap in one transaction.
TOP_LEVEL = (*STATE_DIRS, *STATE_FILES)

_FILE_MODE = 0o600
_DIR_MODE = 0o700


class BackupError(Exception):
    """Raised when an archive cannot be created or safely restored."""


def _validated_member(name: str) -> str:
    """Validate one archive member name and return it unchanged."""
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise BackupError(f"backup contains an unsafe path: {name!r}")
    parts = name.split("/")
    if len(parts) == 1:
        if name not in STATE_FILES:
            raise BackupError(f"backup contains an unexpected file: {name!r}")
        return name
    if len(parts) != 2:
        raise BackupError(f"backup contains an unsafe path: {name!r}")
    directory, leaf = parts
    if directory == "vault":
        # Key material is a fixed, known set of names, not a user entry.
        if leaf in VAULT_KEY_FILES:
            return name
        try:
            validate_name(leaf)
        except InvalidEntryName as exc:
            raise BackupError(
                f"backup contains an invalid file name: {name!r}"
            ) from exc
        return name
    if directory == "uploads":
        try:
            sanitize_name(leaf)
        except UploadError as exc:
            raise BackupError(
                f"backup contains an invalid file name: {name!r}"
            ) from exc
        return name
    raise BackupError(f"backup contains an unexpected directory: {directory!r}")


def _members(home: Home) -> list[tuple[str, Path]]:
    """Return ``(archive name, path)`` pairs for the current state."""
    items: list[tuple[str, Path]] = []
    for name in STATE_FILES:
        path = home.root / name
        if path.is_file() and not path.is_symlink():
            items.append((name, path))
    # Key material first: without it a restored vault cannot be opened.
    key_members: set[str] = set()
    for key_name in VAULT_KEY_FILES:
        path = home.vault_dir / key_name
        if path.is_file() and not path.is_symlink():
            archive_name = f"vault/{key_name}"
            items.append((archive_name, path))
            key_members.add(archive_name)
    for directory_name in STATE_DIRS:
        directory = home.root / directory_name
        if not directory.is_dir():
            continue
        for item in sorted(directory.iterdir()):
            if item.is_symlink() or not item.is_file() or item.name.startswith("."):
                continue
            archive_name = f"{directory_name}/{item.name}"
            if archive_name in key_members:
                continue
            try:
                _validated_member(archive_name)
            except BackupError:
                continue
            items.append((archive_name, item))
    return items


def create_backup(home: Home) -> tuple[bytes, str]:
    """Return ``(archive bytes, suggested file name)`` for ``home``."""
    entries = _members(home)
    manifest: dict[str, Any] = {
        "format": BACKUP_FORMAT,
        "app_version": __version__,
        "created_at": utcnow_iso(),
        "members": [],
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for archive_name, path in entries:
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise BackupError(
                    f"cannot read {archive_name}: {exc.strerror or exc}"
                ) from None
            manifest["members"].append(
                {
                    "name": archive_name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            info = tarfile.TarInfo(archive_name)
            info.size = len(data)
            info.mode = _FILE_MODE
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))

        payload = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(payload)
        info.mode = _FILE_MODE
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(payload))

    data = buffer.getvalue()
    if len(data) > MAX_ARCHIVE_BYTES:
        raise BackupError(
            f"backup would be {len(data)} bytes, the limit is {MAX_ARCHIVE_BYTES}"
        )
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return data, f"forgecore-backup-{stamp}.tar.gz"


def inspect_backup(data: bytes) -> dict[str, Any]:
    """Parse and validate an archive without touching the live state."""
    if not data:
        raise BackupError("the uploaded backup is empty")
    if len(data) > MAX_ARCHIVE_BYTES:
        raise BackupError(
            f"backup is {len(data)} bytes, the limit is {MAX_ARCHIVE_BYTES}"
        )
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError(f"not a valid ForgeCore backup archive ({exc})") from None

    with archive:
        members = archive.getmembers()
        if not members:
            raise BackupError("the backup archive is empty")
        if len(members) > MAX_MEMBERS:
            raise BackupError(
                f"backup has {len(members)} members, the limit is {MAX_MEMBERS}"
            )
        declared_total = sum(member.size for member in members)
        if declared_total > MAX_ARCHIVE_BYTES:
            raise BackupError("backup expands beyond the supported size limit")

        blobs: dict[str, bytes] = {}
        manifest_raw: bytes | None = None
        for member in members:
            if not member.isfile():
                raise BackupError(
                    f"backup contains a non-regular file: {member.name!r}"
                )
            if member.name == MANIFEST_NAME:
                handle = archive.extractfile(member)
                if handle is None:  # pragma: no cover - defensive
                    raise BackupError("backup manifest cannot be read")
                manifest_raw = handle.read(1024 * 1024)
                continue
            _validated_member(member.name)
            handle = archive.extractfile(member)
            if handle is None:  # pragma: no cover - defensive
                raise BackupError(f"cannot read {member.name!r} from the backup")
            blobs[member.name] = handle.read(MAX_ARCHIVE_BYTES + 1)

    if manifest_raw is None:
        raise BackupError("backup is missing its manifest and cannot be trusted")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BackupError("backup manifest is not valid JSON") from None
    if not isinstance(manifest, dict) or manifest.get("format") != BACKUP_FORMAT:
        raise BackupError("backup manifest declares an unsupported format")

    declared = manifest.get("members")
    if not isinstance(declared, list):
        raise BackupError("backup manifest is missing its file list")
    expected: dict[str, dict] = {}
    for item in declared:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise BackupError("backup manifest has a malformed entry")
        _validated_member(item["name"])
        expected[item["name"]] = item

    if set(expected) != set(blobs):
        raise BackupError("backup contents do not match its manifest")

    for name, blob in blobs.items():
        item = expected[name]
        if item.get("size") != len(blob):
            raise BackupError(f"backup member {name!r} has the wrong size")
        digest = hashlib.sha256(blob).hexdigest()
        if item.get("sha256") != digest:
            raise BackupError(f"backup member {name!r} failed its checksum")

    return {
        "manifest": manifest,
        "blobs": blobs,
        "created_at": manifest.get("created_at"),
        "app_version": manifest.get("app_version"),
    }


def restore_backup(home: Home, data: bytes) -> dict[str, Any]:
    """Replace the state in ``home`` with the contents of ``data``."""
    parsed = inspect_backup(data)
    blobs: dict[str, bytes] = parsed["blobs"]

    home.root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    staging = home.root / f".restore-{secrets.token_hex(8)}"
    staging.mkdir(mode=_DIR_MODE)
    try:
        for directory_name in STATE_DIRS:
            (staging / directory_name).mkdir(mode=_DIR_MODE, exist_ok=True)
        for name, blob in blobs.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                _FILE_MODE,
            )
            try:
                os.write(fd, blob)
                os.fsync(fd)
            finally:
                os.close(fd)

        replaced = home.root / f".replaced-{secrets.token_hex(8)}"
        replaced.mkdir(mode=_DIR_MODE)
        moved: list[str] = []
        try:
            for name in TOP_LEVEL:
                current = home.root / name
                if current.exists() or current.is_symlink():
                    os.replace(current, replaced / name)
                    moved.append(name)
                staged = staging / name
                if staged.exists():
                    os.replace(staged, current)
        except BaseException:
            # Put the previous state back: a failed restore must not destroy it.
            for name in reversed(moved):
                current = home.root / name
                try:
                    if current.is_dir():
                        shutil.rmtree(current, ignore_errors=True)
                    elif current.exists() or current.is_symlink():
                        current.unlink()
                    os.replace(replaced / name, current)
                except OSError:  # pragma: no cover - best effort rollback
                    pass
            raise
        shutil.rmtree(replaced, ignore_errors=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    vault_entries = sum(1 for name in blobs if name.startswith("vault/"))
    uploads = sum(1 for name in blobs if name.startswith("uploads/"))
    return {
        "files": len(blobs),
        "vault_entries": vault_entries,
        "uploads": uploads,
        "created_at": parsed["created_at"],
        "app_version": parsed["app_version"],
    }
