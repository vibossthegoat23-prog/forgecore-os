"""Password recovery: the limitation "lost password loses the data" is closed.

The master key is wrapped twice, once under the password-derived key and once
under a one-time recovery code. Recovering re-wraps the master key under a new
password, so existing entries stay readable.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from forgecore.vault import (
    AVAILABLE,
    MIN_ITERATIONS,
    Vault,
    VaultError,
    format_recovery_code,
    normalize_recovery_code,
)

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="cryptography is not installed")

FAST = {"iterations": MIN_ITERATIONS}
PASSWORD = "original-password-123"
NEW_PASSWORD = "replacement-password-456"
SECRET = b"the launch codes"


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    return tmp_path / "vault"


@pytest.fixture()
def vault(root: Path) -> Vault:
    instance = Vault(root)
    instance.init_vault(PASSWORD, **FAST)
    return instance


def test_init_creates_master_key_and_vault_id(vault: Vault, root: Path) -> None:
    assert (root / "master.key").is_file()
    assert (root / "vault.id").is_file()
    assert vault.is_initialized() is True


def test_master_key_is_never_stored_in_the_clear(vault: Vault, root: Path) -> None:
    blob = (root / "master.key").read_bytes()
    assert len(blob) > 32
    assert PASSWORD.encode() not in blob


def test_unlock_then_put_then_read(vault: Vault, root: Path) -> None:
    vault.put("secret", SECRET, PASSWORD, **FAST)
    assert vault.get("secret") == SECRET
    assert Vault(root).unlock(PASSWORD).get("secret") == SECRET


def test_entry_written_under_master_key_is_not_plaintext(vault: Vault) -> None:
    path = vault.put("secret", SECRET, PASSWORD, **FAST)
    assert SECRET not in path.read_bytes()


def test_recovery_code_round_trip_format() -> None:
    code = normalize_recovery_code("a" * 32)
    formatted = format_recovery_code(code)
    assert formatted.count("-") == 7
    assert normalize_recovery_code(formatted) == code
    assert normalize_recovery_code(formatted.lower()) == code


def test_recovery_restores_access_after_password_is_lost(vault: Vault, root: Path) -> None:
    vault.put("secret", SECRET, PASSWORD, **FAST)
    code = vault.create_recovery(**FAST)

    with pytest.raises(VaultError, match="wrong password"):
        Vault(root).get("secret", "forgotten-password")

    fresh = vault.recover(code, NEW_PASSWORD)
    assert fresh != code
    assert Vault(root).get("secret", NEW_PASSWORD) == SECRET
    with pytest.raises(VaultError, match="wrong password"):
        Vault(root).get("secret", PASSWORD)


def test_recovery_code_is_single_use(vault: Vault, root: Path) -> None:
    code = vault.create_recovery(**FAST)
    vault.recover(code, NEW_PASSWORD)
    with pytest.raises(VaultError):
        Vault(root).recover(code, "another-password-789")


def test_wrong_recovery_code_is_rejected(vault: Vault) -> None:
    vault.create_recovery(**FAST)
    with pytest.raises(VaultError, match="not valid"):
        vault.recover(normalize_recovery_code("b" * 32), NEW_PASSWORD)


def test_recovery_without_a_configured_code_fails(vault: Vault) -> None:
    assert vault.has_recovery() is False
    with pytest.raises(VaultError, match="no recovery code"):
        vault.recover(normalize_recovery_code("c" * 32), NEW_PASSWORD)


def test_rotating_the_recovery_code_invalidates_the_previous_one(vault: Vault) -> None:
    first = vault.create_recovery(**FAST)
    second = vault.create_recovery(**FAST)
    assert first != second
    with pytest.raises(VaultError):
        vault.recover(first, NEW_PASSWORD)
    vault.recover(second, NEW_PASSWORD)


def test_change_password_keeps_entries_readable(vault: Vault, root: Path) -> None:
    vault.put("secret", SECRET, PASSWORD, **FAST)
    vault.change_password(PASSWORD, NEW_PASSWORD)
    assert Vault(root).get("secret", NEW_PASSWORD) == SECRET
    with pytest.raises(VaultError, match="wrong password"):
        Vault(root).get("secret", PASSWORD)


def test_change_password_rejects_a_short_new_password(vault: Vault) -> None:
    with pytest.raises(VaultError, match="at least"):
        vault.change_password(PASSWORD, "short")


def test_recovery_requires_an_unlocked_vault(root: Path) -> None:
    """A recovery code can only be created by someone holding the password."""
    Vault(root).init_vault(PASSWORD, **FAST)
    with pytest.raises(VaultError, match="unlock the vault"):
        Vault(root).create_recovery(**FAST)


def test_recovery_blob_is_owner_only(vault: Vault, root: Path) -> None:
    vault.create_recovery(**FAST)
    assert stat.S_IMODE((root / "recovery.key").stat().st_mode) == 0o600


def test_recovery_code_has_no_low_entropy_prefix(vault: Vault) -> None:
    """Codes must be unpredictable, so two codes never share a prefix."""
    codes = {vault.create_recovery(**FAST) for _ in range(3)}
    assert len(codes) == 3
    assert all(len(normalize_recovery_code(code)) == 32 for code in codes)
