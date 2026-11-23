"""Upload panel tests: size limits, traversal safety, atomic intake."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from forgecore.uploads import (
    UploadError,
    intake,
    list_uploads,
    sanitize_name,
    stats,
)


def test_intake_copies_file_with_owner_only_mode(tmp_path: Path) -> None:
    source = tmp_path / "report.txt"
    source.write_text("hello")
    stored = intake(source, tmp_path / "uploads")
    assert stored == tmp_path / "uploads" / "report.txt"
    assert stored.read_text() == "hello"
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600


def test_sanitize_strips_directories() -> None:
    assert sanitize_name("../../etc/passwd") == "passwd"
    assert sanitize_name("/absolute/path/file.bin") == "file.bin"


@pytest.mark.parametrize(
    "name",
    ["", "   ", ".", "..", ".hidden", "x" * 201, "back\\slash", "nul\x00byte"],
)
def test_sanitize_rejects_unsafe_names(name: str) -> None:
    with pytest.raises(UploadError):
        sanitize_name(name)


def test_intake_with_traversal_name_stays_inside_destination(tmp_path: Path) -> None:
    source = tmp_path / "evil.txt"
    source.write_text("x")
    destination = tmp_path / "uploads"
    stored = intake(source, destination, name="../../evil.txt")
    assert stored == destination / "evil.txt"
    assert not (tmp_path.parent / "evil.txt").exists()


def test_symlink_source_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_text("data")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(UploadError, match="symbolic link"):
        intake(link, tmp_path / "uploads")


def test_directory_source_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "folder"
    directory.mkdir()
    with pytest.raises(UploadError, match="not a regular file"):
        intake(directory, tmp_path / "uploads")


def test_missing_source_is_refused(tmp_path: Path) -> None:
    with pytest.raises(UploadError, match="no such file"):
        intake(tmp_path / "absent.bin", tmp_path / "uploads")


def test_size_limit_is_enforced(tmp_path: Path) -> None:
    source = tmp_path / "big.bin"
    source.write_bytes(b"x" * 11)
    with pytest.raises(UploadError, match="upload limit"):
        intake(source, tmp_path / "uploads", max_bytes=10)
    assert list_uploads(tmp_path / "uploads") == []


def test_duplicate_upload_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "report.txt"
    source.write_text("one")
    destination = tmp_path / "uploads"
    intake(source, destination)
    with pytest.raises(UploadError, match="already exists"):
        intake(source, destination)


def test_list_and_stats(tmp_path: Path) -> None:
    destination = tmp_path / "uploads"
    assert list_uploads(destination) == []
    assert stats(destination) == (0, 0)

    (tmp_path / "a.txt").write_text("12345")
    (tmp_path / "b.txt").write_text("123")
    intake(tmp_path / "a.txt", destination)
    intake(tmp_path / "b.txt", destination)

    assert list_uploads(destination) == ["a.txt", "b.txt"]
    assert stats(destination) == (2, 8)
