"""Backup/restore and storage guardrails.

The user's requirement is blunt: once this collects data it must not break or
lose that data. These tests pin the two halves of that promise - an archive
that is verified before use, and a hard refusal instead of a half-written
state when the disk or quota runs out.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from forgecore.backup import (
    MANIFEST_NAME,
    BackupError,
    create_backup,
    inspect_backup,
    restore_backup,
)
from forgecore.config import Home
from forgecore.uploads import (
    UploadError,
    ensure_capacity,
    intake,
    stats,
)
from forgecore.vault import Vault

PASSWORD = "vault-password-1234"
SECRET = b"code-1234"
PAYLOAD = b"payload-bytes"


def _seed(home: Home) -> None:
    """Create one vault entry and one upload, the state a backup must carry."""
    home.ensure()
    vault = Vault(home.vault_dir)
    vault.init_vault(PASSWORD)
    vault.put("launch-code", SECRET)
    source = home.root / "note.txt"
    source.write_bytes(PAYLOAD)
    intake(source, home.uploads_dir)


def _tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, blob in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
    return buffer.getvalue()


def test_backup_roundtrip_restores_entries_and_uploads(home: Home) -> None:
    _seed(home)
    data, filename = create_backup(home)
    assert filename.startswith("forgecore-backup-")
    assert filename.endswith(".tar.gz")
    assert data[:2] == b"\x1f\x8b"  # real gzip stream

    # A different, empty installation, as if the container had been recreated.
    fresh = Home(home.root.parent / "restored")
    summary = restore_backup(fresh, data)
    assert summary["vault_entries"] == 1
    assert summary["uploads"] == 1

    # The restored vault opens with the original password: the wrapped key
    # material survived, not just the ciphertext.
    assert Vault(fresh.vault_dir).get("launch-code", PASSWORD) == SECRET
    assert (fresh.uploads_dir / "note.txt").read_bytes() == PAYLOAD


def test_backup_is_verified_before_it_is_trusted(home: Home) -> None:
    _seed(home)
    data, _ = create_backup(home)
    parsed = inspect_backup(data)
    assert parsed["manifest"]["format"] == 1
    assert set(parsed["blobs"]) == {"vault/launch-code", "uploads/note.txt"}


def test_archive_without_manifest_is_rejected(home: Home) -> None:
    home.ensure()
    with pytest.raises(BackupError, match="manifest"):
        restore_backup(home, _tar({"vault/entry": b"x"}))


def test_archive_with_traversal_member_is_rejected(home: Home) -> None:
    home.ensure()
    manifest = b'{"format": 1, "members": []}'
    archive = _tar({"vault/../../etc/passwd": b"root", MANIFEST_NAME: manifest})
    with pytest.raises(BackupError, match="unsafe path"):
        restore_backup(home, archive)


def test_archive_with_bad_checksum_is_rejected(home: Home) -> None:
    home.ensure()
    body = b"tampered"
    manifest = (
        b'{"format": 1, "members": [{"name": "vault/entry", "size": 8, '
        b'"sha256": "' + b"0" * 64 + b'"}]}'
    )
    archive = _tar({"vault/entry": body, MANIFEST_NAME: manifest})
    with pytest.raises(BackupError, match="checksum"):
        restore_backup(home, archive)


def test_failed_restore_keeps_the_existing_state(home: Home) -> None:
    _seed(home)
    before = Vault(home.vault_dir).get("launch-code", PASSWORD)
    with pytest.raises(BackupError):
        restore_backup(home, b"not an archive at all")
    # Nothing was touched: the original entry is still readable.
    assert Vault(home.vault_dir).get("launch-code", PASSWORD) == before
    assert (home.uploads_dir / "note.txt").read_bytes() == PAYLOAD


def test_upload_quota_refuses_rather_than_filling_the_disk(
    home: Home, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORGECORE_UPLOAD_QUOTA_BYTES", "1024")
    home.ensure()
    with pytest.raises(UploadError, match="quota"):
        ensure_capacity(home.uploads_dir, 4096)


def test_intake_stops_at_the_quota(
    home: Home, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORGECORE_UPLOAD_QUOTA_BYTES", "2048")
    home.ensure()
    source = home.root / "big.bin"
    source.write_bytes(b"x" * 4096)
    with pytest.raises(UploadError):
        intake(source, home.uploads_dir)
    assert stats(home.uploads_dir) == (0, 0)


def test_stats_reports_what_is_really_on_disk(home: Home) -> None:
    _seed(home)
    count, total = stats(home.uploads_dir)
    assert count == 1
    assert total == len(PAYLOAD)
