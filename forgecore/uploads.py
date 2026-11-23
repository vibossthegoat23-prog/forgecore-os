"""Upload panel: safe intake of files into the ForgeCore uploads directory.

Guarantees enforced here:

* the destination name is sanitised, so ``../../etc/passwd`` cannot escape;
* the source must be a regular file, not a symlink or a directory;
* the size limit is enforced while copying, not only from the stat size;
* the copy is created with mode ``0600`` and is removed again on failure.
"""

from __future__ import annotations

import os
from pathlib import Path

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
_MAX_NAME_LENGTH = 200
_FILE_MODE = 0o600


class UploadError(Exception):
    """Raised when a file cannot be accepted by the upload panel."""


def sanitize_name(raw: str) -> str:
    """Reduce ``raw`` to a single safe file name or raise :class:`UploadError`."""
    if not isinstance(raw, str) or not raw.strip():
        raise UploadError("upload name must not be empty")
    name = Path(raw).name.strip()
    if name in {"", ".", ".."}:
        raise UploadError(f"invalid upload name: {raw!r}")
    if len(name) > _MAX_NAME_LENGTH:
        raise UploadError(
            f"upload name is {len(name)} characters, limit is {_MAX_NAME_LENGTH}"
        )
    if any(character in name for character in ("/", "\\", "\x00")):
        raise UploadError(f"invalid upload name: {raw!r}")
    if name.startswith("."):
        raise UploadError("upload name must not start with a dot")
    return name


def intake(
    source: Path | str,
    dest_dir: Path | str,
    *,
    name: str | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> Path:
    """Copy ``source`` into ``dest_dir`` and return the stored path."""
    src = Path(source)
    if src.is_symlink():
        raise UploadError(f"refusing to upload a symbolic link: {src}")
    if not src.exists():
        raise UploadError(f"no such file: {src}")
    if not src.is_file():
        raise UploadError(f"not a regular file: {src}")

    size = src.stat().st_size
    if size > max_bytes:
        raise UploadError(
            f"file is {size} bytes, the upload limit is {max_bytes} bytes"
        )

    target_name = sanitize_name(name or src.name)
    directory = Path(dest_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / target_name

    if target.resolve().parent != directory.resolve():  # pragma: no cover - defence in depth
        raise UploadError(f"refusing to write outside the upload directory: {target_name}")
    if target.exists():
        raise UploadError(f"an upload named {target_name!r} already exists")

    written = 0
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
            while True:
                chunk = inp.read(CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise UploadError(
                        f"file exceeds the upload limit of {max_bytes} bytes"
                    )
                out.write(chunk)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target


def list_uploads(dest_dir: Path | str) -> list[str]:
    """Return the sorted names of files currently in the uploads directory."""
    directory = Path(dest_dir)
    if not directory.is_dir():
        return []
    return sorted(
        item.name
        for item in directory.iterdir()
        if item.is_file() and not item.is_symlink() and not item.name.startswith(".")
    )


def stats(dest_dir: Path | str) -> tuple[int, int]:
    """Return ``(file_count, total_bytes)`` for the uploads directory."""
    directory = Path(dest_dir)
    if not directory.is_dir():
        return (0, 0)
    count = 0
    total = 0
    for item in directory.iterdir():
        if item.is_file() and not item.is_symlink():
            count += 1
            total += item.stat().st_size
    return (count, total)
