"""Command line interface for ForgeCore OS.

The vault password is read from ``FORGECORE_VAULT_PASSWORD`` or an interactive
prompt. It is never accepted as a command line argument, because arguments are
visible to other users through the process table. The same rule applies to the
recovery code (``FORGECORE_RECOVERY_CODE`` or a prompt).
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
from forgecore.config import (
    ENV_RECOVERY_CODE,
    ENV_VAULT_PASSWORD,
    Home,
    default_home,
)
from forgecore.console import (
    configure_output,
    human_bytes,
    print_lines,
    render_dashboard,
    render_status,
)
from forgecore.dashboard import snapshot
from forgecore.security import AuditLog
from forgecore.uploads import UploadError, intake, list_uploads
from forgecore.vault import (
    Vault,
    VaultError,
    format_recovery_code,
    normalize_recovery_code,
)

EXIT_OK = 0
EXIT_ERROR = 1


# -- helpers -------------------------------------------------------------
def _prompt_secret(label: str, *, confirm: bool = False) -> str:
    """Prompt on the terminal. Never reads from a non-interactive stdin."""
    if not sys.stdin.isatty():
        raise VaultError(
            f"no {label.strip().rstrip(':').lower()} available: "
            "run this command on an interactive terminal"
        )
    secret = getpass.getpass(label)
    if confirm and getpass.getpass("Repeat secret: ") != secret:
        raise VaultError("values did not match")
    return secret


def _password(*, confirm: bool = False) -> str:
    from_env = os.environ.get(ENV_VAULT_PASSWORD)
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        raise VaultError(
            "no vault password available: set "
            f"{ENV_VAULT_PASSWORD} for non-interactive use"
        )
    return _prompt_secret("Vault password: ", confirm=confirm)


def _recovery_code() -> str:
    from_env = os.environ.get(ENV_RECOVERY_CODE)
    if from_env:
        return normalize_recovery_code(from_env)
    return normalize_recovery_code(_prompt_secret("Recovery code: "))


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
    vault = Vault(home.vault_dir)
    entries = vault.list()
    if not entries:
        print("vault is empty")
    else:
        for entry in entries:
            print(entry)
    print(
        "recovery code: " + ("configured" if vault.has_recovery() else "not configured"),
        file=sys.stderr,
    )
    return EXIT_OK


def _cmd_vault_put(args: argparse.Namespace, home: Home) -> int:
    if args.stdin:
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.file).read_bytes()
    password = _password(confirm=True)
    vault = Vault(home.vault_dir)
    path = vault.put(args.name, data, password)
    AuditLog(home.audit_log_file).record("vault.put", actor="cli", name=args.name)
    print(f"encrypted {len(data)} bytes into vault entry {path.name}")
    return EXIT_OK


def _cmd_vault_get(args: argparse.Namespace, home: Home) -> int:
    data = Vault(home.vault_dir).get(args.name, _password())
    AuditLog(home.audit_log_file).record("vault.get", actor="cli", name=args.name)
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
        AuditLog(home.audit_log_file).record("vault.delete", actor="cli", name=args.name)
        print(f"removed vault entry {args.name}")
        return EXIT_OK
    print(f"no such vault entry: {args.name}", file=sys.stderr)
    return EXIT_ERROR


def _cmd_vault_init(args: argparse.Namespace, home: Home) -> int:
    vault = Vault(home.vault_dir)
    if vault.is_initialized():
        print("vault already initialised; use 'vault passwd' to change the password",
              file=sys.stderr)
        return EXIT_ERROR
    vault.init_vault(_password(confirm=True))
    code = vault.create_recovery()
    AuditLog(home.audit_log_file).record("vault.init", actor="cli")
    print("vault initialised")
    print("recovery code (shown once, store it offline):")
    print(format_recovery_code(code))
    return EXIT_OK


def _cmd_vault_recovery(args: argparse.Namespace, home: Home) -> int:
    vault = Vault(home.vault_dir)
    if not vault.is_initialized():
        print("no vault to attach a recovery code to", file=sys.stderr)
        return EXIT_ERROR
    if not vault.unlocked:
        vault.unlock(_password())
    code = vault.create_recovery()
    AuditLog(home.audit_log_file).record("vault.recovery_created", actor="cli")
    print("recovery code (shown once, replaces any previous code):")
    print(format_recovery_code(code))
    return EXIT_OK


def _cmd_vault_recover(args: argparse.Namespace, home: Home) -> int:
    vault = Vault(home.vault_dir)
    if not vault.is_initialized():
        print("no vault to recover on this host", file=sys.stderr)
        return EXIT_ERROR
    if not vault.has_recovery():
        print("this vault has no recovery code configured", file=sys.stderr)
        return EXIT_ERROR
    code = _recovery_code()
    new_password = _prompt_secret("New vault password: ", confirm=True)
    fresh = vault.recover(code, new_password)
    AuditLog(home.audit_log_file).record("vault.recovered", actor="cli")
    print("vault recovered; the new password is active")
    print("new recovery code (shown once):")
    print(format_recovery_code(fresh))
    return EXIT_OK


def _cmd_vault_passwd(args: argparse.Namespace, home: Home) -> int:
    vault = Vault(home.vault_dir)
    old_password = _password()
    new_password = _prompt_secret("New vault password: ", confirm=True)
    vault.change_password(old_password, new_password)
    AuditLog(home.audit_log_file).record("vault.password_changed", actor="cli")
    print("vault password changed")
    return EXIT_OK


def _cmd_audit(args: argparse.Namespace, home: Home) -> int:
    entries = AuditLog(home.audit_log_file).tail(args.limit)
    if not entries:
        print("no audit events recorded")
        return EXIT_OK
    for entry in entries:
        print(
            "{ts}\t{event}\t{actor}\t{detail}".format(
                ts=entry.get("ts", ""),
                event=entry.get("event", ""),
                actor=entry.get("actor", ""),
                detail=entry.get("detail", ""),
            )
        )
    return EXIT_OK


def _cmd_serve(args: argparse.Namespace, home: Home) -> int:
    import uvicorn

    from forgecore.web import create_app

    port = int(os.environ.get("PORT", args.port))
    home.ensure()
    uvicorn.run(
        create_app(home),
        host=args.host,
        port=port,
        log_level=args.log_level,
        proxy_headers=False,
    )
    return EXIT_OK


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
        description=f"{APP_NAME} - an operator console with an encrypted vault.",
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

    vault_init = vault_sub.add_parser("init", help="create the vault and a recovery code")
    vault_init.set_defaults(handler=_cmd_vault_init)

    vault_recovery = vault_sub.add_parser(
        "recovery", help="create or rotate the one-time recovery code"
    )
    vault_recovery.set_defaults(handler=_cmd_vault_recovery)

    vault_recover = vault_sub.add_parser(
        "recover", help="set a new password using the recovery code"
    )
    vault_recover.set_defaults(handler=_cmd_vault_recover)

    vault_passwd = vault_sub.add_parser("passwd", help="change the vault password")
    vault_passwd.set_defaults(handler=_cmd_vault_passwd)

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

    audit = subparsers.add_parser("audit", help="show recent security events")
    audit.add_argument("--limit", type=int, default=20, help="number of events")
    audit.set_defaults(handler=_cmd_audit)

    serve = subparsers.add_parser("serve", help="run the web console")
    serve.add_argument("--host", default="0.0.0.0", help="bind address")
    serve.add_argument("--port", type=int, default=8000, help="bind port (PORT overrides)")
    serve.add_argument("--log-level", default="info", help="uvicorn log level")
    serve.set_defaults(handler=_cmd_serve)

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
