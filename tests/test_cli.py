"""CLI tests: end-to-end commands, honest status, no import side effects."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from forgecore.cli import main
from forgecore.config import Home

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_status_reports_real_state(home: Home, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "ForgeCore OS" in out
    assert "Encrypted Vault" in out
    assert "0 vault entries" in out


def test_no_arguments_shows_status(home: Home, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "ForgeCore OS" in capsys.readouterr().out


def test_dashboard_shows_metrics(home: Home, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["dashboard"]) == 0
    out = capsys.readouterr().out
    assert "disk free" in out
    assert "uploads" in out


def test_upload_then_list(home: Home, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "report.txt"
    source.write_text("hello")
    assert main(["upload", str(source)]) == 0
    assert (home.uploads_dir / "report.txt").read_text() == "hello"

    capsys.readouterr()
    assert main(["uploads"]) == 0
    assert "report.txt" in capsys.readouterr().out


def test_vault_roundtrip_through_cli(
    home: Home, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORGECORE_VAULT_PASSWORD", "cli-password-1")
    source = tmp_path / "secret.txt"
    source.write_text("classified")

    assert main(["vault", "put", "secret", "--file", str(source)]) == 0
    out_file = tmp_path / "out.txt"
    assert main(["vault", "get", "secret", "--out", str(out_file)]) == 0
    assert out_file.read_text() == "classified"


def test_vault_list_and_rm(home: Home, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGECORE_VAULT_PASSWORD", "cli-password-1")
    source = tmp_path / "s.txt"
    source.write_text("x")
    main(["vault", "put", "entry", "--file", str(source)])
    assert main(["vault", "list"]) == 0
    assert main(["vault", "rm", "entry"]) == 0
    assert main(["vault", "rm", "entry"]) == 1


def test_vault_wrong_password_fails(
    home: Home,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("FORGECORE_VAULT_PASSWORD", "right-password-1")
    source = tmp_path / "s.txt"
    source.write_text("x")
    assert main(["vault", "put", "s", "--file", str(source)]) == 0

    monkeypatch.setenv("FORGECORE_VAULT_PASSWORD", "wrong-password-1")
    capsys.readouterr()
    assert main(["vault", "get", "s"]) == 1
    assert "error:" in capsys.readouterr().err


def test_vault_without_password_is_a_clean_error(
    home: Home, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No password and no TTY must fail with guidance, not a traceback."""
    source = tmp_path / "s.txt"
    source.write_text("x")
    assert main(["vault", "put", "s", "--file", str(source)]) == 1
    assert "FORGECORE_VAULT_PASSWORD" in capsys.readouterr().err


def test_agents_cli(home: Home, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["agents", "add", "scout", "--role", "recon"]) == 0
    assert "offline" in capsys.readouterr().out

    assert main(["agents", "heartbeat", "scout"]) == 0
    assert "online" in capsys.readouterr().out

    assert main(["agents", "list"]) == 0
    out = capsys.readouterr().out
    assert "scout" in out and "online" in out

    assert main(["agents", "rm", "scout"]) == 0
    assert main(["agents", "rm", "scout"]) == 1


def test_unknown_command_is_a_usage_error(home: Home) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["nope"])
    assert excinfo.value.code == 2


def test_import_has_no_side_effects(tmp_path: Path) -> None:
    """Importing the package must not print or create anything."""
    env = {
        **os.environ,
        "FORGECORE_HOME": str(tmp_path / "home"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    proc = subprocess.run(
        [sys.executable, "-c", "import forgecore, forgecore.cli, forgecore.vault"],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert not (tmp_path / "home").exists()


def test_ascii_stdout_does_not_crash(tmp_path: Path) -> None:
    """The original UnicodeEncodeError bug must not come back."""
    env = {
        **os.environ,
        "FORGECORE_HOME": str(tmp_path / "home"),
        "PYTHONIOENCODING": "ascii",
    }
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "main.py")],
        capture_output=True,
        env=env,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert "ForgeCore OS" in proc.stdout.decode("ascii")
    assert "UnicodeEncodeError" not in proc.stderr.decode("utf-8", "replace")


def test_utf8_stdout_still_uses_the_banner_symbols(tmp_path: Path) -> None:
    env = {
        **os.environ,
        "FORGECORE_HOME": str(tmp_path / "home"),
        "PYTHONIOENCODING": "utf-8",
    }
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "main.py")],
        capture_output=True,
        env=env,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert "\U0001f680".encode("utf-8") in proc.stdout
