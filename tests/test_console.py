"""Console tests: honest rendering and non-UTF-8 safety."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from forgecore.config import Home
from forgecore.console import (
    human_bytes,
    human_duration,
    render_dashboard,
    render_status,
    supports_unicode,
)
from forgecore.dashboard import snapshot
from forgecore.vault import AVAILABLE, MIN_ITERATIONS, Vault


class _FakeStream:
    def __init__(self, encoding: str, reconfigurable: bool = False) -> None:
        self.encoding = encoding
        self._reconfigurable = reconfigurable

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        pass

    def reconfigure(self, **kwargs: object) -> None:
        if not self._reconfigurable:
            raise ValueError("stream cannot be reconfigured")


@pytest.mark.parametrize(
    ("size", "expected"),
    [(0, "0 B"), (512, "512 B"), (1536, "1.5 KiB"), (1024 * 1024, "1.0 MiB")],
)
def test_human_bytes(size: int, expected: str) -> None:
    assert human_bytes(size) == expected


@pytest.mark.parametrize(
    ("seconds", "expected"), [(0, "0s"), (59, "59s"), (65, "1m 5s"), (3700, "1h 1m")]
)
def test_human_duration(seconds: int, expected: str) -> None:
    assert human_duration(seconds) == expected


def test_ascii_stream_falls_back_to_ascii_symbols(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream("ascii"))
    assert supports_unicode() is False
    lines = render_status(snapshot(Home(tmp_path / "home")))
    assert all(line.isascii() for line in lines), lines
    assert "ForgeCore OS" in lines[0]


def test_utf8_stream_uses_unicode_symbols(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream("utf-8"))
    assert supports_unicode() is True
    lines = render_status(snapshot(Home(tmp_path / "home")))
    assert "\U0001f680" in lines[0]


def test_status_reports_measured_vault_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The banner must report real counts, not a hard-coded claim."""
    monkeypatch.setattr(sys, "stdout", _FakeStream("utf-8"))
    home = Home(tmp_path / "home")
    vault = Vault(home.vault_dir)
    if AVAILABLE:
        vault.put("one", b"a", "console-password-1", iterations=MIN_ITERATIONS)
        vault.put("two", b"b", "console-password-1", iterations=MIN_ITERATIONS)

    lines = render_status(snapshot(home))
    vault_line = next(line for line in lines if "Encrypted Vault" in line)
    expected = "2 entries" if AVAILABLE else "unavailable"
    assert expected in vault_line


def test_dashboard_renders_agent_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from forgecore.agents import AgentRegistry

    monkeypatch.setattr(sys, "stdout", _FakeStream("utf-8"))
    home = Home(tmp_path / "home")
    registry = AgentRegistry(home.agents_file)
    registry.add("scout", "recon")
    registry.heartbeat("scout")

    lines = render_dashboard(snapshot(home))
    text = "\n".join(lines)
    assert "scout (recon)" in text
    assert "online" in text
    assert "disk free" in text
