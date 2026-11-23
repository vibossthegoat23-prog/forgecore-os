"""Daily Dashboard: metrics computed from real on-disk state."""

from __future__ import annotations

import platform
import shutil
import time
from typing import Any

from forgecore import APP_NAME, __version__
from forgecore import uploads as uploads_module
from forgecore.agents import AgentError, AgentRegistry
from forgecore.config import Home
from forgecore.vault import ALGORITHM, AVAILABLE as VAULT_AVAILABLE, Vault

STARTED_AT = time.monotonic()


def uptime_seconds() -> int:
    """Seconds since this process started."""
    return int(time.monotonic() - STARTED_AT)


def snapshot(home: Home) -> dict[str, Any]:
    """Collect a status snapshot. Read-only: creates no files or directories."""
    vault_entries = 0
    if VAULT_AVAILABLE:
        try:
            vault_entries = len(Vault(home.vault_dir).list())
        except OSError:
            vault_entries = 0

    try:
        agents = AgentRegistry(home.agents_file).list()
    except (AgentError, OSError):
        agents = []

    upload_count, upload_bytes = uploads_module.stats(home.uploads_dir)

    try:
        disk_free = shutil.disk_usage(home.root).free
    except OSError:
        disk_free = 0

    return {
        "app": APP_NAME,
        "version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}".strip(),
        "uptime_seconds": uptime_seconds(),
        "home": str(home.root),
        "vault_available": VAULT_AVAILABLE,
        "vault_algorithm": ALGORITHM,
        "vault_entries": vault_entries,
        "uploads_dir": str(home.uploads_dir),
        "uploads_count": upload_count,
        "uploads_bytes": upload_bytes,
        "upload_limit": uploads_module.MAX_UPLOAD_BYTES,
        "agents_total": len(agents),
        "agents_online": sum(1 for agent in agents if agent["status"] == "online"),
        "agents": agents,
        "disk_free_bytes": disk_free,
    }
