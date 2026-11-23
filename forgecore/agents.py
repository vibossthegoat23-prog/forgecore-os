"""Agent Nexus hub: a small local registry of registered agents.

Agent status is *derived*, never stored as a claim: an agent is ``online`` only
when its last heartbeat is recent. A newly registered agent is therefore
``offline`` until it actually checks in.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ONLINE_WINDOW_SECONDS = 300
MAX_REGISTRY_BYTES = 4 * 1024 * 1024
_FILE_MODE = 0o600
_DIR_MODE = 0o700
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,47}$")


class AgentError(Exception):
    """Raised for invalid agent operations."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _validate_name(name: str) -> str:
    candidate = name.strip() if isinstance(name, str) else ""
    if not _NAME_RE.match(candidate):
        raise AgentError(
            f"invalid agent name {name!r}: use 1-32 characters from A-Z, a-z, "
            "0-9, '.', '_' or '-', starting with a letter or digit"
        )
    return candidate


def _validate_role(role: str) -> str:
    candidate = role.strip() if isinstance(role, str) else ""
    if not _ROLE_RE.match(candidate):
        raise AgentError(f"invalid agent role {role!r}")
    return candidate


class AgentRegistry:
    """JSON-backed registry stored at ``path``."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # -- storage ---------------------------------------------------------
    def _load(self) -> dict[str, dict]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise AgentError(
                f"cannot open agent registry {self.path}: {exc.strerror or exc}"
            ) from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise AgentError(f"agent registry is not a regular file: {self.path}")
            if info.st_size > MAX_REGISTRY_BYTES:
                raise AgentError(
                    f"agent registry is larger than {MAX_REGISTRY_BYTES} bytes: {self.path}"
                )
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
                raw = handle.read(MAX_REGISTRY_BYTES + 1)
        finally:
            os.close(fd)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AgentError(f"agent registry is corrupt: {self.path} ({exc})") from None
        agents = data.get("agents") if isinstance(data, dict) else None
        if not isinstance(agents, dict):
            raise AgentError(f"agent registry has an unexpected shape: {self.path}")
        return agents

    def _save(self, agents: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        payload = json.dumps({"version": 1, "agents": agents}, indent=2, sort_keys=True)
        # mkstemp gives an unpredictable, exclusively created name; the old
        # fixed '.<name>.tmp' path could be pre-planted as a symlink.
        fd, tmp_name = tempfile.mkstemp(
            dir=self.path.parent, prefix=".tmp-", suffix=".part"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, _FILE_MODE)
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        try:
            self.path.chmod(_FILE_MODE)
        except OSError:  # pragma: no cover - exotic filesystems
            pass

    # -- operations ------------------------------------------------------
    def add(self, name: str, role: str = "general") -> dict:
        agent_name = _validate_name(name)
        agent_role = _validate_role(role)
        agents = self._load()
        key = agent_name.lower()
        if key in agents:
            raise AgentError(f"agent {agent_name!r} is already registered")
        record = {
            "name": agent_name,
            "role": agent_role,
            "created_at": _utcnow().isoformat(),
            "last_seen": None,
        }
        agents[key] = record
        self._save(agents)
        return dict(record, status="offline")

    def remove(self, name: str) -> bool:
        key = _validate_name(name).lower()
        agents = self._load()
        if key not in agents:
            return False
        del agents[key]
        self._save(agents)
        return True

    def heartbeat(self, name: str) -> dict:
        agent_name = _validate_name(name)
        key = agent_name.lower()
        agents = self._load()
        if key not in agents:
            raise AgentError(f"unknown agent {agent_name!r}")
        agents[key]["last_seen"] = _utcnow().isoformat()
        self._save(agents)
        return self._decorate(agents[key])

    def list(self) -> list[dict]:
        agents = self._load()
        return [self._decorate(record) for _, record in sorted(agents.items())]

    def get(self, name: str) -> dict:
        key = _validate_name(name).lower()
        agents = self._load()
        if key not in agents:
            raise AgentError(f"unknown agent {name!r}")
        return self._decorate(agents[key])

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _decorate(record: dict) -> dict:
        last_seen = record.get("last_seen")
        online = False
        if last_seen:
            try:
                seen_at = datetime.fromisoformat(last_seen)
            except ValueError:
                seen_at = None
            if seen_at is not None:
                if seen_at.tzinfo is None:
                    seen_at = seen_at.replace(tzinfo=timezone.utc)
                age = (_utcnow() - seen_at).total_seconds()
                online = 0 <= age <= ONLINE_WINDOW_SECONDS
        return dict(record, status="online" if online else "offline")
