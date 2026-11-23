"""Agent Nexus registry tests: honest online/offline derivation."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from forgecore.agents import AgentError, AgentRegistry


@pytest.fixture()
def registry(tmp_path: Path) -> AgentRegistry:
    return AgentRegistry(tmp_path / "agents.json")


def test_new_agent_is_offline(registry: AgentRegistry) -> None:
    record = registry.add("scout")
    assert record["name"] == "scout"
    assert record["role"] == "general"
    assert record["status"] == "offline"
    assert record["last_seen"] is None


def test_heartbeat_makes_agent_online(registry: AgentRegistry) -> None:
    registry.add("scout", "recon")
    assert registry.heartbeat("scout")["status"] == "online"
    listed = registry.list()
    assert listed[0]["status"] == "online"
    assert listed[0]["role"] == "recon"


def test_duplicate_registration_is_refused(registry: AgentRegistry) -> None:
    registry.add("scout")
    with pytest.raises(AgentError, match="already registered"):
        registry.add("scout")


def test_registration_is_case_insensitive(registry: AgentRegistry) -> None:
    registry.add("Scout")
    with pytest.raises(AgentError, match="already registered"):
        registry.add("scout")
    assert len(registry.list()) == 1


@pytest.mark.parametrize("name", ["", " ", "bad name", "x" * 33, "-leading", "sla/sh"])
def test_invalid_names_are_rejected(registry: AgentRegistry, name: str) -> None:
    with pytest.raises(AgentError):
        registry.add(name)


def test_unknown_agent_operations(registry: AgentRegistry) -> None:
    with pytest.raises(AgentError, match="unknown agent"):
        registry.heartbeat("ghost")
    with pytest.raises(AgentError, match="unknown agent"):
        registry.get("ghost")
    assert registry.remove("ghost") is False


def test_remove_agent(registry: AgentRegistry) -> None:
    registry.add("scout")
    assert registry.remove("scout") is True
    assert registry.list() == []
    assert registry.remove("scout") is False


def test_registry_file_is_owner_only_and_valid_json(registry: AgentRegistry) -> None:
    registry.add("scout")
    path = registry.path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    payload = json.loads(path.read_text())
    assert payload["version"] == 1
    assert "scout" in payload["agents"]


def test_corrupt_registry_is_reported(registry: AgentRegistry) -> None:
    registry.path.write_text("{not json")
    with pytest.raises(AgentError, match="corrupt"):
        registry.list()


def test_unexpected_shape_is_reported(registry: AgentRegistry) -> None:
    registry.path.write_text(json.dumps({"version": 1, "agents": []}))
    with pytest.raises(AgentError, match="unexpected shape"):
        registry.list()
