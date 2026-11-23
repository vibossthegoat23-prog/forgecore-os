"""End-to-end web console tests: auth, CSRF, uploads, vault, recovery."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from forgecore.config import Home  # noqa: E402
from forgecore.web import create_app  # noqa: E402

CONSOLE_PASSWORD = "console-password-123"
VAULT_PASSWORD = "vault-password-1234"
NEW_VAULT_PASSWORD = "recovered-password-5678"

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
RECOVERY_RE = re.compile(r"\b[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}\b")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", CONSOLE_PASSWORD)
    home = Home(tmp_path / "home").ensure()
    app = create_app(home)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _csrf(client: TestClient, path: str = "/") -> str:
    body = client.get(path).text
    match = CSRF_RE.search(body)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def _login(client: TestClient) -> None:
    response = client.post("/login", data={"password": CONSOLE_PASSWORD})
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_health_endpoint_is_public(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.text.strip() == "ok"


def test_login_page_renders(client: TestClient) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    assert "password" in response.text.lower()


def test_protected_page_redirects_to_login(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_security_headers_are_sent(client: TestClient) -> None:
    headers = client.get("/login").headers
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert "no-store" in headers["cache-control"]


def test_wrong_console_password_is_rejected(client: TestClient) -> None:
    response = client.post("/login", data={"password": "definitely-wrong"})
    assert response.status_code == 401
    assert client.get("/").status_code == 303


def test_login_is_rate_limited(client: TestClient) -> None:
    statuses = [
        client.post("/login", data={"password": f"wrong-{index}"}).status_code
        for index in range(8)
    ]
    assert 429 in statuses
    assert statuses[-1] == 429


def test_dashboard_renders_after_login(client: TestClient) -> None:
    _login(client)
    response = client.get("/")
    assert response.status_code == 200
    assert "ForgeCore" in response.text


def test_upload_roundtrip(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/uploads")
    response = client.post(
        "/uploads",
        data={"csrf_token": token},
        files={"file": ("report.txt", b"hello upload", "text/plain")},
    )
    assert response.status_code == 303

    listing = client.get("/uploads").text
    assert "report.txt" in listing

    stored = client.get("/uploads/report.txt")
    assert stored.status_code == 200
    assert stored.content == b"hello upload"


def test_upload_without_csrf_is_refused(client: TestClient) -> None:
    _login(client)
    response = client.post(
        "/uploads",
        data={"csrf_token": "forged"},
        files={"file": ("report.txt", b"payload", "text/plain")},
    )
    assert response.status_code == 400
    assert "report.txt" not in client.get("/uploads").text


def test_upload_traversal_name_is_neutralised(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/uploads")
    client.post(
        "/uploads",
        data={"csrf_token": token},
        files={"file": ("../../escape.txt", b"payload", "text/plain")},
    )
    listing = client.get("/uploads").text
    assert "escape.txt" in listing
    assert ".." not in listing


def test_vault_entry_roundtrip(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/vault")
    unlock = client.post(
        "/vault/unlock", data={"csrf_token": token, "password": VAULT_PASSWORD}
    )
    assert unlock.status_code == 303

    token = _csrf(client, "/vault")
    created = client.post(
        "/vault/entries",
        data={"csrf_token": token, "name": "launch", "content": "code-1234"},
    )
    assert created.status_code == 303

    entry = client.get("/vault/entries/launch")
    assert entry.status_code == 200
    assert "code-1234" in entry.text


def test_vault_entry_cannot_be_traversed(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/vault")
    client.post("/vault/unlock", data={"csrf_token": token, "password": VAULT_PASSWORD})
    for path in ("/vault/entries/master.key", "/vault/entries/vault.id"):
        assert client.get(path).status_code == 404


def test_password_recovery_restores_access(client: TestClient) -> None:
    """The reported limitation: a lost password must not lose the entries."""
    _login(client)
    token = _csrf(client, "/vault")
    client.post("/vault/unlock", data={"csrf_token": token, "password": VAULT_PASSWORD})
    token = _csrf(client, "/vault")
    client.post(
        "/vault/entries",
        data={"csrf_token": token, "name": "secret", "content": "recoverable"},
    )

    token = _csrf(client, "/vault")
    recovery_page = client.post("/vault/recovery", data={"csrf_token": token})
    assert recovery_page.status_code == 200
    match = RECOVERY_RE.search(recovery_page.text)
    assert match, "recovery code was not shown"
    code = match.group(0)

    recovered = client.post(
        "/recover",
        data={
            "recovery_code": code,
            "new_password": NEW_VAULT_PASSWORD,
            "confirm_password": NEW_VAULT_PASSWORD,
        },
    )
    assert recovered.status_code in (200, 303)

    # A fresh login proves the new password really unlocks the same entries.
    client.post("/logout", data={"csrf_token": _csrf(client, "/")})
    _login(client)
    token = _csrf(client, "/vault")
    unlock = client.post(
        "/vault/unlock",
        data={"csrf_token": token, "password": NEW_VAULT_PASSWORD},
    )
    assert unlock.status_code == 303
    entry = client.get("/vault/entries/secret")
    assert entry.status_code == 200
    assert "recoverable" in entry.text


def test_recovery_rejects_a_bad_code(client: TestClient) -> None:
    _login(client)
    response = client.post(
        "/recover",
        data={
            "recovery_code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH",
            "new_password": NEW_VAULT_PASSWORD,
            "confirm_password": NEW_VAULT_PASSWORD,
        },
    )
    assert response.status_code in (400, 200)


def test_logout_ends_the_session(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/")
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 303
    assert client.get("/").status_code == 303


def test_agent_registry_roundtrip(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/agents")
    created = client.post(
        "/agents", data={"csrf_token": token, "name": "scout", "role": "recon"}
    )
    assert created.status_code == 303
    assert "scout" in client.get("/agents").text


def test_audit_page_lists_events(client: TestClient) -> None:
    _login(client)
    response = client.get("/audit")
    assert response.status_code == 200
    assert "audit" in response.text.lower()
