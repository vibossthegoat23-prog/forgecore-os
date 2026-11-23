"""Upload panel: safe intake of files into the ForgeCore uploads directory.

Guarantees enforced here:

* the destination name is sanitised, so ``../../etc/passwd`` cannot escape and
  dotfiles cannot shadow internal state;
* the source is opened with ``O_NOFOLLOW`` and re-checked with ``fstat`` after
  the open, which closes the time-of-check/time-of-use race where a path was
  swapped for a symlink between the check and the read;
* the destination is created with ``O_CREAT|O_EXCL|O_NOFOLLOW`` and mode
  ``0600``, so an existing file is never truncated and a planted symlink is
  never followed;
* the size limit is enforced while streaming, not only from the stat size;
* a partially written file is removed again on failure.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
DEFAULT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 64 * 1024 * 1024
ENV_UPLOAD_QUOTA = "FORGECORE_UPLOAD_QUOTA_BYTES"
_MAX_NAME_LENGTH = 200
_FILE_MODE = 0o600
_DIR_MODE = 0o700

# Conservative allow-list: no shell metacharacters, no leading dot, no path
# separators, no control characters, no unicode look-alikes.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


class UploadError(Exception):
    """Raised when a file cannot be accepted by the upload panel."""


def sanitize_name(raw: str) -> str:
    """Reduce ``raw`` to a single safe file name or raise :class:`UploadError`."""
    if not isinstance(raw, str) or not raw.strip():
        raise UploadError("upload name must not be empty")
    # A backslash is never a legitimate part of an uploaded file name; treat
    # it as an attack attempt instead of silently translating it.
    if "\\" in raw:
        raise UploadError(f"invalid upload name {raw!r}: backslash is not allowed")
    # Strip any directory component first, then validate what is left.
    name = raw.rsplit("/", 1)[-1].strip()
    if name in {"", ".", ".."}:
        raise UploadError(f"invalid upload name: {raw!r}")
    if len(name) > _MAX_NAME_LENGTH:
        raise UploadError(
            f"upload name is {len(name)} characters, limit is {_MAX_NAME_LENGTH}"
        )
    if "\x00" in name or name.startswith("."):
        raise UploadError(f"invalid upload name: {raw!r}")
    if not _SAFE_NAME_RE.match(name):
        raise UploadError(
            f"invalid upload name {raw!r}: use letters, digits, '.', '_' or '-'"
        )
    return name


def upload_quota() -> int:
    """Total bytes all stored uploads may occupy."""
    raw = os.environ.get(ENV_UPLOAD_QUOTA)
    if not raw:
        return DEFAULT_TOTAL_BYTES
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TOTAL_BYTES
    return value if value > 0 else DEFAULT_TOTAL_BYTES


def free_bytes(dest_dir: Path | str) -> int:
    """Free space on the filesystem holding ``dest_dir``."""
    directory = Path(dest_dir)
    probe = directory if directory.exists() else directory.parent
    try:
        return shutil.disk_usage(probe).free
    except OSError:  # pragma: no cover - exotic filesystems
        return 0


def ensure_capacity(dest_dir: Path | str, incoming_bytes: int = 0) -> None:
    """Refuse an upload that would exceed the quota or fill the disk.

    Without this a collection run keeps accepting files until the volume is
    full, at which point every write - including vault writes and the audit
    log - starts failing. Failing the upload early keeps the rest working.
    """
    incoming = max(0, int(incoming_bytes))
    _, total = stats(dest_dir)
    quota = upload_quota()
    if total + incoming > quota:
        raise UploadError(
            f"upload would use {(total + incoming) / (1024 * 1024):.1f} MiB of the "
            f"{quota / (1024 * 1024):.0f} MiB quota; delete files or raise "
            f"{ENV_UPLOAD_QUOTA}"
        )
    free = free_bytes(dest_dir)
    if free and free - incoming < MIN_FREE_BYTES:
        raise UploadError(
            f"not enough free disk space: {free / (1024 * 1024):.1f} MiB left, "
            f"at least {MIN_FREE_BYTES / (1024 * 1024):.0f} MiB must stay free"
        )


def _open_source(src: Path) -> int:
    """Open ``src`` read-only without following symlinks; return the fd."""
    if src.is_symlink():
        raise UploadError(f"refusing to upload a symbolic link: {src}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(src, flags)
    except FileNotFoundError:
        raise UploadError(f"no such file: {src}") from None
    except OSError as exc:
        raise UploadError(f"cannot open {src}: {exc.strerror or exc}") from None
    info = os.fstat(fd)
    # Re-check after opening: the path could have been replaced in between.
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise UploadError(f"not a regular file: {src}")
    return fd


def intake(
    source: Path | str,
    dest_dir: Path | str,
    *,
    name: str | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> Path:
    """Copy ``source`` into ``dest_dir`` and return the stored path."""
    if max_bytes <= 0:
        raise UploadError("upload limit must be positive")
    src = Path(source)
    target_name = sanitize_name(name or src.name)

    directory = Path(dest_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    try:
        directory.chmod(_DIR_MODE)
    except OSError:  # pragma: no cover - exotic filesystems
        pass
    target = directory / target_name

    src_fd = _open_source(src)
    out_fd = None
    try:
        size = os.fstat(src_fd).st_size
        if size > max_bytes:
            raise UploadError(
                f"file is {size} bytes, the upload limit is {max_bytes} bytes"
            )
        ensure_capacity(directory, size)
        out_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            out_fd = os.open(target, out_flags, _FILE_MODE)
        except FileExistsError:
            raise UploadError(
                f"an upload named {target_name!r} already exists"
            ) from None
        except OSError as exc:
            raise UploadError(
                f"cannot create {target_name}: {exc.strerror or exc}"
            ) from None

        written = 0
        while True:
            chunk = os.read(src_fd, CHUNK_SIZE)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                raise UploadError(
                    f"file exceeds the upload limit of {max_bytes} bytes"
                )
            view = memoryview(chunk)
            while view:
                view = view[os.write(out_fd, view) :]
        os.fsync(out_fd)
        os.chmod(target, _FILE_MODE)
    except BaseException:
        if out_fd is not None:
            os.close(out_fd)
            out_fd = None
        target.unlink(missing_ok=True)
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        os.close(src_fd)
    return target


def open_upload(dest_dir: Path | str, name: str, *, max_bytes: int = MAX_UPLOAD_BYTES) -> bytes:
    """Read a stored upload by name, refusing traversal and symlinks."""
    safe = sanitize_name(name)
    path = Path(dest_dir) / safe
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise UploadError(f"no such upload: {safe}") from None
    except OSError as exc:
        raise UploadError(f"cannot open {safe}: {exc.strerror or exc}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UploadError(f"{safe} is not a regular file")
        if info.st_size > max_bytes:
            raise UploadError(f"{safe} exceeds the {max_bytes} byte limit")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read(max_bytes + 1)
    finally:
        os.close(fd)


def delete_upload(dest_dir: Path | str, name: str) -> bool:
    """Delete a stored upload by name. Returns ``True`` if it existed."""
    safe = sanitize_name(name)
    path = Path(dest_dir) / safe
    if path.is_symlink():
        path.unlink()
        return True
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except IsADirectoryError:
        raise UploadError(f"{safe} is not a regular file") from None
    return True


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
        if item.is_symlink() or not item.is_file():
            continue
        count += 1
        total += item.stat().st_size
    return (count, total)
