# ForgeCore OS

A local operator console: a single command-line tool that keeps an encrypted vault,
an upload panel, an agent registry and a live dashboard under one home directory.

This repository used to contain a six-line `main.py` that printed a startup banner
claiming a dashboard, an agent hub, an upload panel and a "secured encrypted vault"
while none of those existed. The banner is now backed by real code, and every line
it prints reports measured state instead of a hard-coded claim.

## What it does

| Subsystem | Reality |
| --- | --- |
| Founder Console | The CLI itself (`forgecore status`, `dashboard`, `upload`, `vault`, `agents`) |
| Daily Dashboard | Metrics read from disk: vault entries, uploads and bytes, agents online, disk free, uptime |
| Agent Nexus Hub | A JSON registry of agents; `online` is derived from a heartbeat within 300 s, never asserted |
| Upload Panel | Copies files into the uploads directory with a 25 MiB limit, sanitised names and mode `0600` |
| Encrypted Vault | AES-256-GCM with a PBKDF2-HMAC-SHA256 key (600 000 iterations, 16-byte salt, 12-byte nonce per write) |

State lives in `~/.forgecore` by default:

```
~/.forgecore/
├── vault/        encrypted entries, mode 0600
├── uploads/      uploaded files, mode 0600
└── agents.json   agent registry, mode 0600
```

## Install

```bash
python3 -m pip install -e .          # provides the `forgecore` command
# or just run it from the repository without installing:
python3 main.py
```

Requires Python 3.10+ and [`cryptography`](https://cryptography.io) (`pip install cryptography`).
Without it the vault reports itself as unavailable and refuses to run; it never
falls back to plaintext or a home-made cipher.

## Usage

```bash
forgecore                                   # banner with live status
forgecore status                            # same as above
forgecore dashboard                         # detailed metrics and agent detail

forgecore upload ./report.pdf               # copy into the upload panel
forgecore uploads                           # list uploaded files

export FORGECORE_VAULT_PASSWORD='…'         # or get an interactive prompt
forgecore vault put notes --file ./notes.txt
forgecore vault put notes --stdin < ./notes.txt
forgecore vault list
forgecore vault get notes                   # plaintext to stdout
forgecore vault get notes --out ./notes.txt # plaintext to a 0600 file
forgecore vault rm notes

forgecore agents add scout --role recon
forgecore agents heartbeat scout
forgecore agents list
forgecore agents rm scout
```

Exit codes: `0` success, `1` runtime error (wrong password, missing entry, refused
upload, unknown agent), `2` usage error.

## Security notes

* The vault password is read from `FORGECORE_VAULT_PASSWORD` or an interactive
  prompt — never from a command-line argument, which other users can read from the
  process table.
* The entry name is authenticated as associated data, so an encrypted entry cannot
  be renamed or copied to a different name without decryption failing.
* A wrong password and a tampered file produce the same error, so the vault does not
  reveal which one occurred.
* Upload names are reduced to a single path component; `../../etc/passwd` is stored
  as `passwd` inside the uploads directory, and symlink sources are refused.
* Nothing is written outside the ForgeCore home directory.

There is no password recovery: losing the vault password means losing the entries.

## Tests

```bash
python3 -m pytest
```

The suite covers encryption round-trips, wrong-password and tamper detection,
name-binding, traversal and symlink refusal, upload size limits, honest
online/offline agent status, ASCII terminal fallback (the original
`UnicodeEncodeError` crash), and that importing the package has no side effects.
