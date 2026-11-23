"""Vault tests: real encryption, tamper detection, name safety."""

from __future__ import annotations

import stat
import struct
from pathlib import Path

import pytest

from forgecore.vault import (
    AVAILABLE,
    MAGIC,
    MAX_ITERATIONS,
    MIN_ITERATIONS,
    InvalidEntryName,
    Vault,
    VaultError,
)

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="cryptography is not installed")

FAST = {"iterations": MIN_ITERATIONS}
PASSWORD = "correct horse battery staple"
PLAINTEXT = b"unmistakable-plaintext-marker"


@pytest.fixture()
def vault(tmp_path: Path) -> Vault:
    return Vault(tmp_path / "vault")


def test_roundtrip(vault: Vault) -> None:
    vault.put("note", b"top secret", PASSWORD, **FAST)
    assert vault.get("note", PASSWORD) == b"top secret"


def test_empty_payload_roundtrip(vault: Vault) -> None:
    vault.put("empty", b"", PASSWORD, **FAST)
    assert vault.get("empty", PASSWORD) == b""


def test_ciphertext_does_not_contain_plaintext(vault: Vault) -> None:
    path = vault.put("note", PLAINTEXT, PASSWORD, **FAST)
    assert PLAINTEXT not in path.read_bytes()


def test_entry_file_is_owner_only(vault: Vault) -> None:
    path = vault.put("note", b"x", PASSWORD, **FAST)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_wrong_password_is_rejected(vault: Vault) -> None:
    vault.put("note", b"x", PASSWORD, **FAST)
    with pytest.raises(VaultError, match="wrong password or corrupted entry"):
        vault.get("note", "not-the-password")


def test_empty_password_is_rejected(vault: Vault) -> None:
    with pytest.raises(VaultError, match="must not be empty"):
        vault.put("note", b"x", "", **FAST)


def test_tampered_ciphertext_is_detected(vault: Vault) -> None:
    path = vault.put("note", b"payload", PASSWORD, **FAST)
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    with pytest.raises(VaultError, match="wrong password or corrupted entry"):
        vault.get("note", PASSWORD)


def test_entry_cannot_be_copied_to_another_name(vault: Vault) -> None:
    """The entry name is authenticated as associated data."""
    alpha = vault.put("alpha", b"payload", PASSWORD, **FAST)
    (alpha.parent / "beta").write_bytes(alpha.read_bytes())
    with pytest.raises(VaultError, match="wrong password or corrupted entry"):
        vault.get("beta", PASSWORD)


def test_nonce_and_salt_are_unique_per_write(vault: Vault) -> None:
    first = vault.put("note", b"same", PASSWORD, **FAST).read_bytes()
    second = vault.put("note", b"same", PASSWORD, **FAST).read_bytes()
    assert first != second
    # Header layout: magic | iterations | salt | nonce
    assert first[len(MAGIC) + 4 : len(MAGIC) + 20] != second[len(MAGIC) + 4 : len(MAGIC) + 20]


def test_kdf_cost_is_never_stored_below_the_minimum(vault: Vault) -> None:
    path = vault.put("note", b"x", PASSWORD, iterations=1)
    (iterations,) = struct.unpack_from(">I", path.read_bytes(), len(MAGIC))
    assert iterations == MIN_ITERATIONS


def test_kdf_cost_is_never_stored_above_the_maximum(vault: Vault) -> None:
    """A huge requested cost is clamped instead of stalling the process."""
    path = vault.put("note", b"x", PASSWORD, iterations=10**9)
    (iterations,) = struct.unpack_from(">I", path.read_bytes(), len(MAGIC))
    assert iterations == MAX_ITERATIONS


def test_entry_with_unsafe_kdf_cost_is_refused(vault: Vault) -> None:
    path = vault.put("note", b"x", PASSWORD, **FAST)
    blob = bytearray(path.read_bytes())
    struct.pack_into(">I", blob, len(MAGIC), 1000)
    path.write_bytes(bytes(blob))
    with pytest.raises(VaultError, match="unsafe KDF cost"):
        vault.get("note", PASSWORD)


def test_entry_with_absurd_kdf_cost_is_refused(vault: Vault) -> None:
    """A crafted header cannot force a multi-hour key derivation."""
    path = vault.put("note", b"x", PASSWORD, **FAST)
    blob = bytearray(path.read_bytes())
    struct.pack_into(">I", blob, len(MAGIC), 0xFFFFFFFF)
    path.write_bytes(bytes(blob))
    with pytest.raises(VaultError, match="unsafe KDF cost"):
        vault.get("note", PASSWORD)


def test_non_vault_file_is_rejected(vault: Vault) -> None:
    vault.root.mkdir(parents=True, exist_ok=True)
    (vault.root / "junk").write_bytes(b"just some bytes")
    with pytest.raises(VaultError, match="not a valid ForgeCore entry"):
        vault.get("junk", PASSWORD)


def test_missing_entry_reports_cleanly(vault: Vault) -> None:
    with pytest.raises(VaultError, match="no such vault entry"):
        vault.get("absent", PASSWORD)


@pytest.mark.parametrize(
    "name",
    ["", "   ", ".", "..", "../escape", ".hidden", "a" * 129, "with space", "nul\x00byte"],
)
def test_invalid_entry_names_are_rejected(vault: Vault, name: str) -> None:
    with pytest.raises(InvalidEntryName):
        vault.put(name, b"x", PASSWORD, **FAST)


def test_internal_state_names_are_reserved(vault: Vault) -> None:
    """An entry may not shadow the wrapped master key or vault id."""
    for reserved in ("master.key", "recovery.key", "vault.id"):
        with pytest.raises(InvalidEntryName):
            vault.put(reserved, b"x", PASSWORD, **FAST)


def test_traversal_name_cannot_escape_the_vault(vault: Vault) -> None:
    with pytest.raises(InvalidEntryName):
        vault.put("../../etc/passwd", b"x", PASSWORD, **FAST)
    assert not (vault.root.parent / "passwd").exists()


def test_list_delete_and_exists(vault: Vault) -> None:
    vault.put("zeta", b"1", PASSWORD, **FAST)
    vault.put("alpha", b"2", PASSWORD, **FAST)
    assert vault.list() == ["alpha", "zeta"]
    assert vault.exists("alpha") is True
    assert vault.delete("alpha") is True
    assert vault.delete("alpha") is False
    assert vault.list() == ["zeta"]
    assert vault.exists("alpha") is False


def test_list_ignores_internal_state_files(vault: Vault) -> None:
    vault.put("note", b"1", PASSWORD, **FAST)
    vault.init_vault(PASSWORD, **FAST)
    assert vault.list() == ["note"]


def test_list_on_missing_directory_is_empty(tmp_path: Path) -> None:
    assert Vault(tmp_path / "absent").list() == []
