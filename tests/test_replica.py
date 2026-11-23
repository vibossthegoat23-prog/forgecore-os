"""Tests for off-host replication and the inline vault unlock flow.

The two problems these cover:

* a host without a persistent disk loses everything on redeploy, so the state
  must be recoverable from somewhere other than the container layer;
* a locked vault used to be a dead end, so unlocking has to be possible from the
  page that says it is locked.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from forgecore import web as web_module
from forgecore.config import Home
from forgecore.replica import (
    MAGIC,
    ReplicaConfig,
    ReplicaError,
    ReplicaNotFound,
    ReplicaSyncer,
    pull,
    push,
    seal,
    unseal,
)
from forgecore.web import create_app

CONSOLE_PASSWORD = "replica-console-password-1"
VAULT_PASSWORD = "replica-vault-password-1"
REPLICA_TOKEN = "test-replica-token"
REPLICA_KEY = "test-replica-key-0123456789abcdef"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class _Store:
    """A stand-in for a remote object store."""

    def __init__(self) -> None:
        self.blob: bytes | None = None
        self.puts = 0
        self.authorization: str | None = None


@pytest.fixture()
def replica_server():
    """Serve a single mutable blob, like an S3 key or a small upload endpoint."""
    store = _Store()

    class Handler(BaseHTTPRequestHandler):
        def do_PUT(self) -> None:  # noqa: N802 - http.server naming
            length = int(self.headers.get("Content-Length") or 0)
            store.blob = self.rfile.read(length)
            store.puts += 1
            store.authorization = self.headers.get("Authorization")
            self.send_response(204)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            if store.blob is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(store.blob)))
            self.end_headers()
            self.wfile.write(store.blob)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield store, f"http://127.0.0.1:{server.server_port}/state"
    finally:
        server.shutdown()
        server.server_close()


def _use_replica(
    monkeypatch: pytest.MonkeyPatch, url: str, *, autorestore: bool = True
) -> None:
    monkeypatch.setenv("FORGECORE_REPLICA_URL", url)
    monkeypatch.setenv("FORGECORE_REPLICA_TOKEN", REPLICA_TOKEN)
    monkeypatch.setenv("FORGECORE_REPLICA_KEY", REPLICA_KEY)
    monkeypatch.setenv("FORGECORE_REPLICA_AUTORESTORE", "1" if autorestore else "0")


@pytest.fixture()
def client(home: Home, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", CONSOLE_PASSWORD)
    app = create_app(home)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture()
def replica_client(home: Home, monkeypatch: pytest.MonkeyPatch, replica_server):
    store, url = replica_server
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", CONSOLE_PASSWORD)
    _use_replica(monkeypatch, url)
    app = create_app(home)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client, store


def _csrf(client: TestClient, path: str = "/") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match is not None, f"no csrf token on {path}"
    return match.group(1)


def _login(client: TestClient, password: str = CONSOLE_PASSWORD) -> None:
    data: dict[str, str] = {"password": password}
    match = CSRF_RE.search(client.get("/login").text)
    if match is not None:
        data["csrf_token"] = match.group(1)
    response = client.post("/login", data=data)
    assert response.status_code == 303, response.text


# -- encryption ---------------------------------------------------------------


def test_seal_roundtrip_and_tamper_detection() -> None:
    blob = seal(b"archive-bytes", REPLICA_KEY)
    assert blob.startswith(MAGIC)
    assert b"archive-bytes" not in blob
    assert unseal(blob, REPLICA_KEY) == b"archive-bytes"

    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(ReplicaError):
        unseal(bytes(tampered), REPLICA_KEY)
    with pytest.raises(ReplicaError):
        unseal(blob, "a-different-key-entirely")


def test_seal_refuses_an_empty_passphrase() -> None:
    with pytest.raises(ReplicaError):
        seal(b"archive-bytes", "")


def test_plain_http_endpoint_is_refused(home: Home, monkeypatch: pytest.MonkeyPatch) -> None:
    """The remote copy holds unencrypted uploads, so it must not travel in clear."""
    _use_replica(monkeypatch, "http://example.com/state")
    config = ReplicaConfig.from_env()
    assert config is not None
    with pytest.raises(ReplicaError) as excinfo:
        push(home, config)
    assert "https" in str(excinfo.value).lower()


# -- remote copy --------------------------------------------------------------


def test_push_stores_only_ciphertext(
    home: Home, monkeypatch: pytest.MonkeyPatch, replica_server
) -> None:
    store, url = replica_server
    _use_replica(monkeypatch, url)
    config = ReplicaConfig.from_env()
    assert config is not None

    push(home, config)
    assert store.blob is not None
    assert store.blob.startswith(MAGIC)
    assert store.authorization == f"Bearer {REPLICA_TOKEN}"
    assert b"master.key" not in store.blob

    push(home, config)
    assert store.puts == 2


def test_pull_reports_a_missing_remote(
    home: Home, monkeypatch: pytest.MonkeyPatch, replica_server
) -> None:
    store, url = replica_server
    _use_replica(monkeypatch, url)
    config = ReplicaConfig.from_env()
    assert config is not None
    with pytest.raises(ReplicaNotFound):
        pull(home, config)


def test_syncer_pushes_after_a_change(
    home: Home, monkeypatch: pytest.MonkeyPatch, replica_server
) -> None:
    store, url = replica_server
    _use_replica(monkeypatch, url)
    config = ReplicaConfig.from_env()

    syncer = ReplicaSyncer(home, config, debounce=0.01)
    assert syncer.configured is True
    syncer.mark_dirty()
    assert syncer.flush(timeout=10.0) is True
    assert store.puts >= 1
    assert syncer.status()["last_ok"] is True


# -- surviving a redeploy -----------------------------------------------------


def test_state_survives_a_redeploy(
    home: Home, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replica_server
) -> None:
    store, url = replica_server
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", CONSOLE_PASSWORD)
    _use_replica(monkeypatch, url)

    app = create_app(home)
    with TestClient(app, follow_redirects=False) as client:
        _login(client)
        token = _csrf(client, "/vault")
        assert (
            client.post(
                "/vault/unlock",
                data={"csrf_token": token, "password": VAULT_PASSWORD},
            ).status_code
            == 303
        )
        token = _csrf(client, "/vault")
        assert (
            client.post(
                "/vault/entries",
                data={"csrf_token": token, "name": "launch", "content": "code-1234"},
            ).status_code
            == 303
        )
        token = _csrf(client, "/uploads")
        assert (
            client.post(
                "/uploads",
                data={"csrf_token": token},
                files={"file": ("report.txt", b"payload-bytes", "text/plain")},
            ).status_code
            == 303
        )
        web_module.console.replica.push_once()

    assert store.blob is not None

    # A redeploy: a brand new, empty volume and the same replica endpoint.
    second = Home(tmp_path / "second").ensure()
    restored_app = create_app(second)
    console = web_module.console
    assert console.replica_restore_note is not None
    assert console.replica_restore_note["ok"] is True
    assert console.vault.is_initialized() is True

    with TestClient(restored_app, follow_redirects=False) as client:
        _login(client)
        token = _csrf(client, "/vault")
        assert (
            client.post(
                "/vault/unlock",
                data={"csrf_token": token, "password": VAULT_PASSWORD},
            ).status_code
            == 303
        )
        entry = client.get("/vault/entries/launch")
        assert entry.status_code == 200
        assert b"code-1234" in entry.content

        upload = client.get("/uploads/report.txt")
        assert upload.status_code == 200
        assert b"payload-bytes" in upload.content


def test_claimed_console_password_survives_a_redeploy(
    home: Home, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replica_server
) -> None:
    """Without this the restored copy would demand setup, and anyone could claim it."""
    store, url = replica_server
    _use_replica(monkeypatch, url)

    app = create_app(home)
    with TestClient(app, follow_redirects=False) as client:
        token = _csrf(client, "/setup")
        assert (
            client.post(
                "/setup",
                data={"csrf_token": token, "password": CONSOLE_PASSWORD, "confirm": CONSOLE_PASSWORD},
            ).status_code
            == 303
        )
        assert web_module.console.needs_setup is False
        web_module.console.replica.push_once()

    assert store.blob is not None

    second = Home(tmp_path / "second").ensure()
    restored_app = create_app(second)
    console = web_module.console
    assert console.needs_setup is False

    with TestClient(restored_app, follow_redirects=False) as client:
        _login(client)
        # Setup stays closed for a later visitor.
        assert client.get("/setup").status_code == 303


# -- the web surface ----------------------------------------------------------


def test_backup_page_pushes_and_restores(replica_client) -> None:
    client, store = replica_client
    _login(client)

    body = client.get("/backup").text
    assert "Off-host replication" in body

    token = _csrf(client, "/backup")
    response = client.post("/backup/replica/push", data={"csrf_token": token})
    assert response.status_code == 303
    assert response.headers["location"] == "/backup"
    assert store.blob is not None and store.blob.startswith(MAGIC)

    token = _csrf(client, "/backup")
    response = client.post("/backup/replica/restore", data={"csrf_token": token})
    assert response.status_code == 303
    assert web_module.console.replica_restore_note["ok"] is True


def test_replica_push_requires_a_csrf_token(replica_client) -> None:
    client, store = replica_client
    _login(client)
    response = client.post("/backup/replica/push", data={"csrf_token": "wrong"})
    assert response.status_code == 303
    assert store.puts == 0


def test_locked_vault_offers_an_inline_unlock(client) -> None:
    _login(client)
    body = client.get("/").text
    assert 'action="/vault/unlock"' in body
    assert 'name="next"' in body
    assert "/recover" in body

    # The vault page already has its own form, so the card must not duplicate it.
    assert 'name="next"' not in client.get("/vault").text


def test_unlock_returns_to_the_page_you_came_from(client) -> None:
    _login(client)
    token = _csrf(client, "/vault")
    response = client.post(
        "/vault/unlock",
        data={"csrf_token": token, "password": VAULT_PASSWORD, "next": "/uploads"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/uploads"

    token = _csrf(client, "/vault")
    assert client.post("/vault/lock", data={"csrf_token": token}).status_code == 303
    token = _csrf(client, "/vault")
    response = client.post(
        "/vault/unlock",
        data={
            "csrf_token": token,
            "password": VAULT_PASSWORD,
            "next": "//evil.example/steal",
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/vault"
