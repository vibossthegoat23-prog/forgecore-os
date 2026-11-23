"""Production-readiness tests: backup/restore, health, failure paths, paging.

These cover the user's actual worry - "once it starts collecting data, it must
keep working" - at the HTTP surface, where a broken page or a half-restore
would be visible.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from forgecore.config import Home  # noqa: E402
from forgecore.vault import Vault  # noqa: E402
from forgecore.web import create_app  # noqa: E402

CONSOLE_PASSWORD = "console-password-123"
VAULT_PASSWORD = "vault-password-1234"

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture()
def console(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", CONSOLE_PASSWORD)
    home = Home(tmp_path / "home").ensure()
    app = create_app(home)
    with TestClient(app, follow_redirects=False) as client:
        yield client, home


def _csrf(client: TestClient, path: str = "/") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def _login(client: TestClient) -> None:
    assert client.post("/login", data={"password": CONSOLE_PASSWORD}).status_code == 303


def _unlock_and_store(client: TestClient, name: str = "secret", value: str = "v") -> None:
    _login(client)
    token = _csrf(client, "/vault")
    client.post("/vault/unlock", data={"csrf_token": token, "password": VAULT_PASSWORD})
    token = _csrf(client, "/vault")
    client.post(
        "/vault/entries", data={"csrf_token": token, "name": name, "content": value}
    )


def test_health_reports_storage_state(console) -> None:
    client, _home = console
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["storage"]["writable"] is True
    assert body["storage"]["persistent"] is False
    assert isinstance(body["storage"]["free_bytes"], int)
    assert body["uploads"]["count"] == 0
    assert body["vault_locked"] is True


def test_health_marks_persistent_storage(console, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _home = console
    monkeypatch.setenv("FORGECORE_PERSISTENT_STORAGE", "1")
    assert client.get("/healthz").json()["storage"]["persistent"] is True


def test_backup_export_downloads_a_gzip_archive(console) -> None:
    client, _home = console
    _unlock_and_store(client)
    token = _csrf(client, "/backup")
    response = client.post("/backup/export", data={"csrf_token": token})
    assert response.status_code == 200
    assert response.content[:2] == b"\x1f\x8b"
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition and ".tar.gz" in disposition


def test_restore_replaces_state_and_locks_the_vault(console) -> None:
    client, _home = console
    _unlock_and_store(client, name="launch", value="code-1234")
    token = _csrf(client, "/backup")
    archive = client.post("/backup/export", data={"csrf_token": token}).content

    # Data collected *after* the backup must be gone once it is restored.
    token = _csrf(client, "/uploads")
    client.post(
        "/uploads",
        data={"csrf_token": token},
        files={"file": ("later.txt", b"post-backup", "text/plain")},
    )
    assert "later.txt" in client.get("/uploads").text

    token = _csrf(client, "/backup")
    restored = client.post(
        "/backup/restore",
        data={"csrf_token": token},
        files={"file": ("backup.tar.gz", archive, "application/gzip")},
    )
    assert restored.status_code == 200
    assert "Restored" in restored.text
    assert "later.txt" not in client.get("/uploads").text

    # The vault material came from the archive, so it is locked again and the
    # original password still opens it.
    assert client.get("/health").json()["vault_locked"] is True
    token = _csrf(client, "/vault")
    unlock = client.post(
        "/vault/unlock", data={"csrf_token": token, "password": VAULT_PASSWORD}
    )
    assert unlock.status_code == 303
    assert "code-1234" in client.get("/vault/entries/launch").text


def test_restore_rejects_a_bad_archive_without_changing_anything(console) -> None:
    client, _home = console
    _unlock_and_store(client, name="keep", value="intact")
    token = _csrf(client, "/backup")
    response = client.post(
        "/backup/restore",
        data={"csrf_token": token},
        files={"file": ("broken.tar.gz", b"definitely-not-a-tar", "application/gzip")},
    )
    assert response.status_code == 400
    assert "Nothing was changed" in response.text
    assert "intact" in client.get("/vault/entries/keep").text


def test_restore_requires_csrf(console) -> None:
    client, _home = console
    _login(client)
    response = client.post(
        "/backup/restore",
        data={"csrf_token": "forged"},
        files={"file": ("x.tar.gz", b"\x1f\x8b", "application/gzip")},
    )
    assert response.status_code == 400


def test_unknown_page_renders_the_friendly_error_page(console) -> None:
    client, _home = console
    response = client.get("/no-such-page")
    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]
    assert "does not exist" in response.text


def test_corrupt_key_material_degrades_instead_of_crashing(console) -> None:
    """A damaged key file must show a locked vault, never a 500 traceback."""
    client, home = console
    _unlock_and_store(client, name="entry", value="value")
    token = _csrf(client, "/")
    client.post("/logout", data={"csrf_token": token})

    home.master_key_file.write_bytes(b"corrupted-key-material")
    _login(client)
    assert client.get("/vault").status_code == 200
    token = _csrf(client, "/vault")
    unlock = client.post(
        "/vault/unlock", data={"csrf_token": token, "password": VAULT_PASSWORD}
    )
    assert unlock.status_code == 401


def test_upload_quota_is_enforced_over_http(console, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _home = console
    monkeypatch.setenv("FORGECORE_UPLOAD_QUOTA_BYTES", "1024")
    _login(client)
    token = _csrf(client, "/uploads")
    response = client.post(
        "/uploads",
        data={"csrf_token": token},
        files={"file": ("huge.bin", b"x" * 8192, "application/octet-stream")},
    )
    assert response.status_code in (400, 413)
    assert "huge.bin" not in client.get("/uploads").text


def test_uploads_are_paginated_without_losing_rows(console) -> None:
    client, _home = console
    _login(client)
    names = {f"probe-{index:02d}.txt" for index in range(30)}
    for name in sorted(names):
        token = _csrf(client, "/uploads")
        client.post(
            "/uploads",
            data={"csrf_token": token},
            files={"file": (name, b"body", "text/plain")},
        )

    first = client.get("/uploads").text
    second = client.get("/uploads?page=2").text
    in_first = {name for name in names if name in first}
    in_second = {name for name in names if name in second}

    assert 0 < len(in_first) < len(names)  # bounded page, not everything
    assert not (in_first & in_second)  # no duplicates between pages
    assert in_first | in_second == names  # nothing lost


def test_pager_survives_a_nonsense_page_number(console) -> None:
    client, _home = console
    _login(client)
    assert client.get("/uploads?page=0").status_code == 200
    assert client.get("/uploads?page=abc").status_code == 200
    assert client.get("/uploads?page=9999").status_code == 200


def test_audit_log_paging_is_bounded(console) -> None:
    client, _home = console
    _login(client)
    body = client.get("/audit?page=1").text
    assert "audit" in body.lower()


def test_vault_still_opens_after_restore_of_its_own_export(console) -> None:
    """Sanity: export/restore of an untouched home keeps the wrapped key valid."""
    client, home = console
    _unlock_and_store(client, name="k", value="v")
    token = _csrf(client, "/backup")
    archive = client.post("/backup/export", data={"csrf_token": token}).content
    token = _csrf(client, "/backup")
    assert client.post(
        "/backup/restore",
        data={"csrf_token": token},
        files={"file": ("b.tar.gz", archive, "application/gzip")},
    ).status_code == 200
    assert Vault(home.vault_dir).get("k", VAULT_PASSWORD) == b"v"
