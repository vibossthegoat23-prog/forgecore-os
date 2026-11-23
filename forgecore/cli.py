"""Command line interface for ForgeCore OS.

The vault password is read from ``FORGECORE_VAULT_PASSWORD`` or an interactive
prompt. It is never accepted as a command line argument, because arguments are
visible to other users through the process table.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Sequence

from forgecore import APP_NAME, __version__
from forgecore.agents import AgentError, AgentRegistry
from forgecore.config import ENV_VAULT_PASSWORD, Home, default_home
from forgecore.console import (
    configure_output,
    human_bytes,
    print_lines,
    render_dashboard,
    render_status,
)
from forgecore.dashboard import snapshot
from forgecore.uploads import UploadError, intake, list_uploads
from forgecore.vault import Vault, VaultError

EXIT_OK = 0
EXIT_ERROR = 1


# -- helpers -------------------------------------------------------------
def _password(*, confirm: bool = False) -> str:
    from_env = os.environ.get(ENV_VAULT_PASSWORD)
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        raise VaultError(
            "no vault password available: set "
            f"{ENV_VAULT_PASSWORD} for non-interactive use"
        )
    password = getpass.getpass("Vault password: ")
    if confirm and getpass.getpass("Repeat password: ") != password:
        raise VaultError("passwords did not match")
    return password


def _write_private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


# -- command handlers ----------------------------------------------------
def _cmd_status(args: argparse.Namespace, home: Home) -> int:
    print_lines(render_status(snapshot(home)))
    return EXIT_OK


def _cmd_dashboard(args: argparse.Namespace, home: Home) -> int:
    print_lines(render_dashboard(snapshot(home)))
    return EXIT_OK


def _cmd_upload(args: argparse.Namespace, home: Home) -> int:
    stored = intake(args.file, home.uploads_dir, name=args.name)
    print(f"stored {stored.name} ({human_bytes(stored.stat().st_size)}) in {home.uploads_dir}")
    return EXIT_OK


def _cmd_uploads(args: argparse.Namespace, home: Home) -> int:
    names = list_uploads(home.uploads_dir)
    if not names:
        print("no uploads yet")
        return EXIT_OK
    for name in names:
        print(name)
    return EXIT_OK


def _cmd_vault_list(args: argparse.Namespace, home: Home) -> int:
    entries = Vault(home.vault_dir).list()
    if not entries:
        print("vault is empty")
        return EXIT_OK
    for entry in entries:
        print(entry)
    return EXIT_OK


def _cmd_vault_put(args: argparse.Namespace, home: Home) -> int:
    if args.stdin:
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.file).read_bytes()
    password = _password(confirm=True)
    path = Vault(home.vault_dir).put(args.name, data, password)
    print(f"encrypted {len(data)} bytes into vault entry {path.name}")
    return EXIT_OK


def _cmd_vault_get(args: argparse.Namespace, home: Home) -> int:
    data = Vault(home.vault_dir).get(args.name, _password())
    if args.out:
        _write_private_file(Path(args.out), data)
        print(f"wrote {len(data)} bytes to {args.out}", file=sys.stderr)
    else:
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    return EXIT_OK


def _cmd_vault_rm(args: argparse.Namespace, home: Home) -> int:
    if Vault(home.vault_dir).delete(args.name):
        print(f"removed vault entry {args.name}")
        return EXIT_OK
    print(f"no such vault entry: {args.name}", file=sys.stderr)
    return EXIT_ERROR


def _cmd_agents_add(args: argparse.Namespace, home: Home) -> int:
    record = AgentRegistry(home.agents_file).add(args.name, args.role)
    print(f"registered agent {record['name']} ({record['role']}) - status {record['status']}")
    return EXIT_OK


def _cmd_agents_list(args: argparse.Namespace, home: Home) -> int:
    agents = AgentRegistry(home.agents_file).list()
    if not agents:
        print("no agents registered")
        return EXIT_OK
    for agent in agents:
        last_seen = agent.get("last_seen") or "never"
        print(f"{agent['name']}\t{agent['role']}\t{agent['status']}\tlast seen {last_seen}")
    return EXIT_OK


def _cmd_agents_rm(args: argparse.Namespace, home: Home) -> int:
    if AgentRegistry(home.agents_file).remove(args.name):
        print(f"removed agent {args.name}")
        return EXIT_OK
    print(f"unknown agent: {args.name}", file=sys.stderr)
    return EXIT_ERROR


def _cmd_agents_heartbeat(args: argparse.Namespace, home: Home) -> int:
    record = AgentRegistry(home.agents_file).heartbeat(args.name)
    print(f"agent {record['name']} is now {record['status']}")
    return EXIT_OK


# -- parser --------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forgecore",
        description=f"{APP_NAME} - a local operator console with an encrypted vault.",
    )
    parser.add_argument(
        "--version", action="version", version=f"{APP_NAME} {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command")

    status = subparsers.add_parser("status", help="show subsystem status")
    status.set_defaults(handler=_cmd_status)

    dashboard = subparsers.add_parser("dashboard", help="show detailed metrics")
    dashboard.set_defaults(handler=_cmd_dashboard)

    upload = subparsers.add_parser("upload", help="copy a file into the upload panel")
    upload.add_argument("file", help="path of the file to upload")
    upload.add_argument("--name", default=None, help="store under a different name")
    upload.set_defaults(handler=_cmd_upload)

    uploads = subparsers.add_parser("uploads", help="list uploaded files")
    uploads.set_defaults(handler=_cmd_uploads)

    vault = subparsers.add_parser("vault", help="manage the encrypted vault")
    vault_sub = vault.add_subparsers(dest="vault_command", required=True)

    vault_list = vault_sub.add_parser("list", help="list vault entries")
    vault_list.set_defaults(handler=_cmd_vault_list)

    vault_put = vault_sub.add_parser("put", help="encrypt a file or stdin into the vault")
    vault_put.add_argument("name", help="vault entry name")
    source = vault_put.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="file to encrypt")
    source.add_argument("--stdin", action="store_true", help="read the payload from stdin")
    vault_put.set_defaults(handler=_cmd_vault_put)

    vault_get = vault_sub.add_parser("get", help="decrypt an entry to stdout or a file")
    vault_get.add_argument("name", help="vault entry name")
    vault_get.add_argument("--out", default=None, help="write plaintext to this file")
    vault_get.set_defaults(handler=_cmd_vault_get)

    vault_rm = vault_sub.add_parser("rm", help="delete a vault entry")
    vault_rm.add_argument("name", help="vault entry name")
    vault_rm.set_defaults(handler=_cmd_vault_rm)

    agents = subparsers.add_parser("agents", help="manage the Agent Nexus registry")
    agents_sub = agents.add_subparsers(dest="agents_command", required=True)

    agents_add = agents_sub.add_parser("add", help="register an agent")
    agents_add.add_argument("name", help="agent name")
    agents_add.add_argument("--role", default="general", help="agent role")
    agents_add.set_defaults(handler=_cmd_agents_add)

    agents_list = agents_sub.add_parser("list", help="list registered agents")
    agents_list.set_defaults(handler=_cmd_agents_list)

    agents_rm = agents_sub.add_parser("rm", help="remove an agent")
    agents_rm.add_argument("name", help="agent name")
    agents_rm.set_defaults(handler=_cmd_agents_rm)

    agents_beat = agents_sub.add_parser("heartbeat", help="record an agent heartbeat")
    agents_beat.add_argument("name", help="agent name")
    agents_beat.set_defaults(handler=_cmd_agents_heartbeat)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    configure_output()
    args = build_parser().parse_args(argv)
    home = default_home()
    handler = getattr(args, "handler", None)
    try:
        if handler is None:
            return _cmd_status(args, home)
        return handler(args, home)
    except (VaultError, UploadError, AgentError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
