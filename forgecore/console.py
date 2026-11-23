"""Founder Console output: terminal-safe rendering of real subsystem state.

Two behaviours matter here:

* output never crashes on a non-UTF-8 stream - ``errors="replace"`` is applied
  where the stream allows it, and the emoji symbol set degrades to ASCII
  markers when the encoding cannot represent it;
* every rendered line reports measured state, not a hard-coded claim.
"""

from __future__ import annotations

import sys
from typing import Any, Sequence

UNICODE_SYMBOLS = {
    "title": "\U0001f680",      # rocket
    "console": "\U0001f53a",    # up-pointing red triangle
    "dashboard": "\U0001f4ca",  # bar chart
    "agents": "\U0001f916",     # robot
    "uploads": "\U0001f4c1",    # folder
    "vault": "\U0001f510",      # locked with key
}

ASCII_SYMBOLS = {
    "title": ">>",
    "console": "//",
    "dashboard": "[]",
    "agents": "<>",
    "uploads": "::",
    "vault": "**",
}


def configure_output() -> None:
    """Make stdout/stderr resilient to characters the encoding cannot represent."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def supports_unicode() -> bool:
    """True when the current stdout encoding can represent the emoji banner."""
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        UNICODE_SYMBOLS["title"].encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def human_bytes(size: int) -> str:
    """Format a byte count with binary units."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"  # pragma: no cover - unreachable


def human_duration(seconds: float) -> str:
    """Format an elapsed time as a short human-readable string."""
    total = max(int(seconds), 0)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _layout() -> tuple[dict[str, str], str, str]:
    if supports_unicode():
        return UNICODE_SYMBOLS, " \u00b7 ", "\u2014"
    return ASCII_SYMBOLS, " | ", "-"


def render_status(status: dict[str, Any]) -> list[str]:
    """Render the startup banner with live state for each subsystem."""
    symbols, sep, dash = _layout()
    entries = status["vault_entries"]
    uploads_count = status["uploads_count"]

    lines = [
        f"{symbols['title']} {status['app']} {status['version']} {dash} local operator console",
        f"{symbols['console']} Founder Console: ready{sep}Python {status['python']}{sep}{status['platform']}",
        f"{symbols['dashboard']} Daily Dashboard: uptime {human_duration(status['uptime_seconds'])}"
        f"{sep}{entries} vault entries{sep}{uploads_count} uploads"
        f" ({human_bytes(status['uploads_bytes'])})",
        f"{symbols['agents']} Agent Nexus Hub: {status['agents_total']} registered{sep}"
        f"{status['agents_online']} online",
        f"{symbols['uploads']} Upload Panel: {status['uploads_dir']}{sep}"
        f"limit {human_bytes(status['upload_limit'])}",
    ]

    if status["vault_available"]:
        lines.append(
            f"{symbols['vault']} Encrypted Vault: {status['vault_algorithm']}"
            f"{sep}{entries} entries{sep}password required"
        )
    else:
        lines.append(
            f"{symbols['vault']} Encrypted Vault: unavailable{sep}"
            "install 'cryptography' to enable"
        )
    return lines


def render_dashboard(status: dict[str, Any]) -> list[str]:
    """Render detailed metrics for the Daily Dashboard command."""
    symbols, sep, dash = _layout()
    lines = [
        f"{symbols['dashboard']} {status['app']} dashboard {dash} uptime "
        f"{human_duration(status['uptime_seconds'])}",
        f"  home            {status['home']}",
        f"  vault           "
        + (
            f"{status['vault_entries']} entries ({status['vault_algorithm']})"
            if status["vault_available"]
            else "unavailable (install 'cryptography')"
        ),
        f"  uploads         {status['uploads_count']} files, "
        f"{human_bytes(status['uploads_bytes'])} of {human_bytes(status['upload_limit'])}",
        f"  uploads dir     {status['uploads_dir']}",
        f"  agents          {status['agents_total']} registered, {status['agents_online']} online",
        f"  disk free       {human_bytes(status['disk_free_bytes'])}",
    ]
    if status["agents"]:
        lines.append("  agent detail:")
        for agent in status["agents"]:
            last_seen = agent.get("last_seen") or "never"
            lines.append(
                f"    - {agent['name']} ({agent['role']}) {sep.strip()} "
                f"{agent['status']}{sep}last seen {last_seen}"
            )
    return lines


def print_lines(lines: Sequence[str]) -> None:
    """Print pre-rendered lines to stdout."""
    for line in lines:
        print(line)
