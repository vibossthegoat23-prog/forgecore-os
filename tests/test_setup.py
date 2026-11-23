"""First-run console setup: claiming a console with no password configured."""

from __future__ import annotations

import json
import stat

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from forgecore.config import Home  # noqa: E402
from forgecore.security import (  # noqa: E402
    PASSWORD_MIN_LENGTH,
    hash_password,
    load_console_hash,
    verify_password,
)
from forgecore.web import create_app  # noqa: E402

NEW_PASSWORD = "first-run-password-1"


def _client(home: Home) -> TestClient:
    return TestClient(create_app(home), follow_redirects=False)


@pytest.fixture()
def unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGECORE_CONSOLE_PASSWORD", raising=False)
    home = Home(tmp_path / "home").ensure()
    with _client(home) as client:
        yield client, home


def test_login_redirects_to_setup_when_no_password_exists(unconfigured):
    client, _ = unconfigured
    response = client.get("/login")
    assert response.status_code == 303
    assert response.headers["location"] == "/setup"


def test_protected_page_still_requires_a_session(unconfigured):
    client, _ = unconfigured
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_setup_page_renders_the_form(unconfigured):
    client, _ = unconfigured
    response = client.get("/setup")
    assert response.status_code == 200
    assert "Set up this console" in response.text
    assert f'minlength="{PASSWORD_MIN_LENGTH}"' in response.text


def test_short_password_is_rejected_without_writing_a_hash(unconfigured):
    client, home = unconfigured
    response = client.post("/setup", data={"password": "short", "confirm": "short"})
    assert response.status_code == 400
    assert "at least" in response.text
    assert not home.console_hash_file.exists()


def test_mismatched_confirmation_is_rejected(unconfigured):
    client, home = unconfigured
    response = client.post(
        "/setup", data={"password": NEW_PASSWORD, "confirm": NEW_PASSWORD + "x"}
    )
    assert response.status_code == 400
    assert "do not match" in response.text
    assert not home.console_hash_file.exists()


def test_setup_stores_only_a_hash_and_signs_the_operator_in(unconfigured):
    client, home = unconfigured
    response = client.post(
        "/setup", data={"password": NEW_PASSWORD, "confirm": NEW_PASSWORD}
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.get("/").status_code == 200

    raw = home.console_hash_file.read_text("utf-8")
    assert NEW_PASSWORD not in raw
    stored = json.loads(raw)["password_hash"]
    assert stored.startswith("pbkdf2_sha256$")
    assert load_console_hash(home.console_hash_file) == stored
    assert verify_password(stored, NEW_PASSWORD)
    assert not verify_password(stored, NEW_PASSWORD + "x")
    assert stat.S_IMODE(home.console_hash_file.stat().st_mode) == 0o600


def test_setup_closes_permanently_once_a_password_exists(unconfigured):
    client, home = unconfigured
    client.post("/setup", data={"password": NEW_PASSWORD, "confirm": NEW_PASSWORD})

    page = client.get("/setup")
    assert page.status_code == 303
    assert page.headers["location"] == "/login"

    again = client.post(
        "/setup", data={"password": "attacker-password-9", "confirm": "attacker-password-9"}
    )
    assert again.status_code == 303
    stored = json.loads(home.console_hash_file.read_text("utf-8"))["password_hash"]
    assert verify_password(stored, NEW_PASSWORD)
    assert not verify_password(stored, "attacker-password-9")


def test_chosen_password_survives_a_restart(unconfigured):
    client, home = unconfigured
    client.post("/setup", data={"password": NEW_PASSWORD, "confirm": NEW_PASSWORD})

    with _client(home) as restarted:
        assert restarted.get("/login").status_code == 200
        wrong = restarted.post("/login", data={"password": "not-the-password"})
        assert wrong.status_code == 401
        good = restarted.post("/login", data={"password": NEW_PASSWORD})
        assert good.status_code == 303
        assert good.headers["location"] == "/"


def test_env_password_disables_the_setup_page(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", "env-console-password-1")
    home = Home(tmp_path / "home").ensure()
    with _client(home) as client:
        response = client.get("/setup")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert client.get("/login").status_code == 200
        login = client.post("/login", data={"password": "env-console-password-1"})
        assert login.status_code == 303
        assert not home.console_hash_file.exists()


def test_short_env_password_still_fails_fast(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", "short")
    home = Home(tmp_path / "home").ensure()
    with pytest.raises(RuntimeError):
        create_app(home)


def test_password_hash_helpers_reject_malformed_records():
    assert not verify_password("", NEW_PASSWORD)
    assert not verify_password("md5$1$aa$bb", NEW_PASSWORD)
    assert not verify_password("pbkdf2_sha256$600000$not-base64$also-bad", NEW_PASSWORD)
    stored = hash_password(NEW_PASSWORD)
    assert verify_password(stored, NEW_PASSWORD)
    assert not verify_password(stored, NEW_PASSWORD + " ")
