"""Collection engine: fetch a source, extract records, store them, search them.

This is the part of ForgeCore that does actual work. A *job* names a source
(an HTTP(S) URL) and how to turn the response into records:

``links``
    Every anchor on the page, optionally filtered by a regular expression.
``text``
    The page title, meta description and paragraph text as one record.
``json``
    A list inside a JSON document (dotted path), one record per element.
``import``
    Records imported from an uploaded file; never fetched.

Records are de-duplicated by a SHA-256 fingerprint of ``job|url|title|body``,
so re-running a job only appends what is genuinely new. Everything lives in a
single SQLite database under the home directory, which keeps the dataset inside
the existing backup and off-host replica story.

Network safety
--------------
A hosted console must not become a proxy for reaching the host's own network.
Every URL - including each redirect hop - is checked against the resolved
addresses, and loopback, private, link-local, reserved, multicast and
unspecified ranges are refused. ``FORGECORE_ALLOW_PRIVATE_FETCH=1`` relaxes this
for tests only.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import threading
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urljoin, urlsplit

ENV_ALLOW_PRIVATE = "FORGECORE_ALLOW_PRIVATE_FETCH"
ENV_SCHEDULER = "FORGECORE_SCHEDULER"

KINDS = ("links", "text", "json", "import")
MAX_FETCH_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
FETCH_TIMEOUT = 15.0
MAX_BODY_CHARS = 20_000
MAX_EXPORT_ROWS = 50_000
USER_AGENT = "ForgeCore-Collector/1.0 (local operator console)"

_DB_DIR_MODE = 0o700
_DB_FILE_MODE = 0o600
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class CollectError(Exception):
    """Raised for an invalid job, an unsafe URL or a failed collection."""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def allow_private_fetch() -> bool:
    return os.environ.get(ENV_ALLOW_PRIVATE, "").strip().lower() in {"1", "true", "yes", "on"}


# -- URL safety ---------------------------------------------------------
def _is_public_address(raw: str) -> bool:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def check_url(url: str) -> str:
    """Validate ``url`` and return it unchanged, or raise :class:`CollectError`."""
    if not isinstance(url, str) or not url.strip():
        raise CollectError("a source URL is required")
    candidate = url.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise CollectError(f"unsupported scheme in {candidate!r}: use http or https")
    if parsed.username or parsed.password:
        raise CollectError("URLs with embedded credentials are not allowed")
    host = parsed.hostname
    if not host:
        raise CollectError(f"invalid URL {candidate!r}: no host")
    if len(candidate) > 2048:
        raise CollectError("URL is longer than 2048 characters")
    if allow_private_fetch():
        return candidate
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise CollectError(f"cannot resolve host {host!r}") from None
    for info in infos:
        address = str(info[4][0])
        if not _is_public_address(address):
            raise CollectError(
                f"refusing to fetch {host!r}: it resolves to the non-public "
                f"address {address}"
            )
    return candidate


def fetch(
    url: str,
    *,
    max_bytes: int = MAX_FETCH_BYTES,
    timeout: float = FETCH_TIMEOUT,
) -> tuple[bytes, str, str]:
    """Fetch ``url`` and return ``(body, final_url, content_type)``.

    Redirects are followed manually so each hop is re-validated; a redirect to
    a private address is rejected exactly like a direct request would be.
    """
    import httpx  # imported lazily so the module stays importable without it

    current = check_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        with httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        ) as client:
            with client.stream("GET", current) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise CollectError(
                            f"{current} returned {response.status_code} without a Location"
                        )
                    current = check_url(urljoin(current, location))
                    continue
                if response.status_code >= 400:
                    raise CollectError(
                        f"{current} returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes(64 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise CollectError(
                            f"response is larger than the {max_bytes // 1024} KiB limit"
                        )
                    chunks.append(chunk)
                return (
                    b"".join(chunks),
                    str(response.url),
                    response.headers.get("content-type", ""),
                )
    raise CollectError(f"{url} redirected more than {MAX_REDIRECTS} times")


# -- extraction ---------------------------------------------------------
class _AnchorParser(HTMLParser):
    """Collect ``(href, text)`` pairs and the document title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.title = ""
        self.paragraphs: list[str] = []
        self.description = ""
        self._in_anchor = False
        self._href = ""
        self._text: list[str] = []
        self._in_title = False
        self._title_parts: list[str] = []
        self._in_paragraph = False
        self._paragraph_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): (value or "") for key, value in attrs}
        if tag == "a":
            self._in_anchor = True
            self._href = attributes.get("href", "")
            self._text = []
        elif tag == "title":
            self._in_title = True
            self._title_parts = []
        elif tag == "p":
            self._in_paragraph = True
            self._paragraph_parts = []
        elif tag == "meta" and attributes.get("name", "").lower() == "description":
            self.description = attributes.get("content", "").strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_anchor:
            self._in_anchor = False
            text = " ".join("".join(self._text).split())
            if self._href:
                self.anchors.append((self._href.strip(), text))
            self._href = ""
            self._text = []
        elif tag == "title" and self._in_title:
            self._in_title = False
            self.title = " ".join("".join(self._title_parts).split())
        elif tag == "p" and self._in_paragraph:
            self._in_paragraph = False
            text = " ".join("".join(self._paragraph_parts).split())
            if text:
                self.paragraphs.append(text)

    def handle_data(self, data: str) -> None:
        if self._in_anchor:
            self._text.append(data)
        if self._in_title:
            self._title_parts.append(data)
        if self._in_paragraph:
            self._paragraph_parts.append(data)


def _decode(body: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", errors="replace")


def _dotted(document: Any, path: str) -> Any:
    """Walk ``path`` (``a.b.0.c``) into ``document``; ``""`` returns it whole."""
    current = document
    for part in [piece for piece in (path or "").split(".") if piece]:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if current is None:
            return None
    return current


def extract(
    job: dict[str, Any],
    body: bytes,
    final_url: str,
    content_type: str = "",
) -> list[dict[str, str]]:
    """Turn a fetched document into records for ``job``."""
    kind = job.get("kind", "text")
    text = _decode(body)

    if kind == "links":
        parser = _AnchorParser()
        try:
            parser.feed(text)
        except Exception as exc:  # pragma: no cover - html.parser is lenient
            raise CollectError(f"cannot parse HTML: {exc}") from None
        pattern = job.get("pattern") or ""
        try:
            matcher = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error as exc:
            raise CollectError(f"invalid pattern {pattern!r}: {exc}") from None
        records: list[dict[str, str]] = []
        for href, label in parser.anchors:
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(final_url, href)
            if not absolute.startswith(("http://", "https://")):
                continue
            if matcher and not (matcher.search(absolute) or matcher.search(label)):
                continue
            records.append(
                {
                    "url": absolute,
                    "title": label or absolute,
                    "body": f"{label}\n{absolute}".strip(),
                }
            )
        return records

    if kind == "json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CollectError(f"response is not valid JSON: {exc}") from None
        rows = _dotted(document, job.get("path") or "")
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise CollectError(
                f"path {job.get('path') or '(root)'!r} did not resolve to a list"
            )
        title_field = job.get("title_field") or "title"
        records = []
        for row in rows:
            if isinstance(row, dict):
                title = row.get(title_field)
                if title is None:
                    title = next((str(v) for v in row.values() if v), "")
                body_text = json.dumps(row, ensure_ascii=False, sort_keys=True)
                url = row.get("url") or row.get("link") or final_url
            else:
                title = str(row)
                body_text = str(row)
                url = final_url
            records.append(
                {
                    "url": str(url)[:2048],
                    "title": str(title)[:500],
                    "body": body_text[:MAX_BODY_CHARS],
                }
            )
        return records

    # kind == "text"
    parser = _AnchorParser()
    try:
        parser.feed(text)
    except Exception:  # pragma: no cover
        pass
    paragraphs = parser.paragraphs
    if not paragraphs:
        stripped = re.sub(r"<[^>]+>", " ", text)
        paragraphs = [" ".join(stripped.split())[:MAX_BODY_CHARS]]
    body_text = "\n\n".join(paragraphs)[:MAX_BODY_CHARS]
    title = parser.title or final_url
    if parser.description:
        body_text = f"{parser.description}\n\n{body_text}"[:MAX_BODY_CHARS]
    return [{"url": final_url[:2048], "title": title[:500], "body": body_text}]


# -- storage ------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    url TEXT NOT NULL,
    pattern TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    title_field TEXT NOT NULL DEFAULT 'title',
    schedule_minutes INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_run_at TEXT,
    last_status TEXT NOT NULL DEFAULT 'never',
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    url TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL UNIQUE,
    collected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_job ON items(job_id, id DESC);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    found INTEGER NOT NULL DEFAULT 0,
    added INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_job ON runs(job_id, id DESC);
"""


def validate_job_name(name: str) -> str:
    candidate = name.strip() if isinstance(name, str) else ""
    if not candidate:
        raise CollectError("a job name is required")
    if len(candidate) > 64:
        raise CollectError("job names are limited to 64 characters")
    if _CONTROL_RE.search(candidate):
        raise CollectError("job names cannot contain control characters")
    return candidate


class Store:
    """SQLite-backed jobs, records and run history."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=_DB_DIR_MODE)
        try:
            self.path.parent.chmod(_DB_DIR_MODE)
        except OSError:  # pragma: no cover - exotic filesystems
            pass
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(_SCHEMA)
        try:
            self.path.chmod(_DB_FILE_MODE)
        except OSError:  # pragma: no cover
            pass

    # -- jobs ------------------------------------------------------------
    def add_job(
        self,
        name: str,
        kind: str,
        url: str,
        *,
        pattern: str = "",
        path: str = "",
        title_field: str = "title",
        schedule_minutes: int = 0,
    ) -> dict[str, Any]:
        job_name = validate_job_name(name)
        if kind not in KINDS:
            raise CollectError(f"unknown job kind {kind!r}")
        if kind != "import":
            url = check_url(url)
        if len(pattern) > 200:
            raise CollectError("the filter pattern is limited to 200 characters")
        if schedule_minutes < 0 or schedule_minutes > 10080:
            raise CollectError("schedule must be between 0 and 10080 minutes")
        with self._lock, self._connect() as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO jobs (name, kind, url, pattern, path, title_field,"
                    " schedule_minutes, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        job_name,
                        kind,
                        url,
                        pattern,
                        path,
                        title_field,
                        int(schedule_minutes),
                        1 if schedule_minutes else 0,
                        utcnow_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise CollectError(f"a job named {job_name!r} already exists") from None
            return self._job_row(connection, cursor.lastrowid)

    def get_job(self, job_id: int) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            return self._job_row(connection, job_id)

    def _job_row(self, connection: sqlite3.Connection, job_id: int) -> dict[str, Any]:
        row = connection.execute(
            "SELECT j.*, (SELECT COUNT(*) FROM items i WHERE i.job_id = j.id)"
            " AS item_count FROM jobs j WHERE j.id = ?",
            (int(job_id),),
        ).fetchone()
        if row is None:
            raise CollectError(f"no job with id {job_id}")
        return dict(row)

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT j.*, (SELECT COUNT(*) FROM items i WHERE i.job_id = j.id)"
                " AS item_count FROM jobs j ORDER BY j.name COLLATE NOCASE"
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_job(self, job_id: int) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM jobs WHERE id = ?", (int(job_id),))
            connection.execute("DELETE FROM runs WHERE job_id = ?", (int(job_id),))
            return cursor.rowcount > 0

    def set_enabled(self, job_id: int, enabled: bool) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE jobs SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, int(job_id)),
            )

    def update_job_run(self, job_id: int, status: str, error: str = "") -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE jobs SET last_run_at = ?, last_status = ?, last_error = ?"
                " WHERE id = ?",
                (utcnow_iso(), status, error[:500], int(job_id)),
            )

    # -- records ---------------------------------------------------------
    def insert_items(self, job_id: int, records: Iterable[dict[str, str]]) -> int:
        added = 0
        stamp = utcnow_iso()
        with self._lock, self._connect() as connection:
            for record in records:
                title = (record.get("title") or "").strip()[:500]
                body = (record.get("body") or "").strip()[:MAX_BODY_CHARS]
                url = (record.get("url") or "").strip()[:2048]
                if not (title or body):
                    continue
                digest = hashlib.sha256(
                    f"{job_id}|{url}|{title}|{body}".encode("utf-8", "replace")
                ).hexdigest()
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO items"
                    " (job_id, url, title, body, fingerprint, collected_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (int(job_id), url, title, body, digest, stamp),
                )
                added += cursor.rowcount
        return added

    def search(
        self,
        *,
        job_id: int | None = None,
        query: str = "",
        page: int = 1,
        size: int = 20,
    ) -> dict[str, Any]:
        where, params = self._filters(job_id, query)
        page = max(1, int(page))
        size = max(1, min(int(size), 100))
        with self._lock, self._connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM items i {where}", params
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT i.id, i.job_id, i.url, i.title, i.collected_at, j.name AS job_name"
                f" FROM items i JOIN jobs j ON j.id = i.job_id {where}"
                " ORDER BY i.id DESC LIMIT ? OFFSET ?",
                (*params, size, (page - 1) * size),
            ).fetchall()
        pages = max(1, (total + size - 1) // size)
        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "page": min(page, pages),
            "pages": pages,
            "size": size,
        }

    def _filters(self, job_id: int | None, query: str) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if job_id:
            clauses.append("i.job_id = ?")
            params.append(int(job_id))
        if query:
            needle = query.strip()[:200]
            escaped = (
                needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            clauses.append(
                "(i.title LIKE ? ESCAPE '\\' OR i.body LIKE ? ESCAPE '\\'"
                " OR i.url LIKE ? ESCAPE '\\')"
            )
            params.extend([f"%{escaped}%"] * 3)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def get_item(self, item_id: int) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT i.*, j.name AS job_name FROM items i JOIN jobs j ON j.id = i.job_id"
                " WHERE i.id = ?",
                (int(item_id),),
            ).fetchone()
        if row is None:
            raise CollectError(f"no record with id {item_id}")
        return dict(row)

    def iter_records(
        self,
        *,
        job_id: int | None = None,
        query: str = "",
        limit: int = MAX_EXPORT_ROWS,
    ) -> Iterator[dict[str, Any]]:
        where, params = self._filters(job_id, query)
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "SELECT i.id, i.url, i.title, i.body, i.collected_at, j.name AS job_name"
                f" FROM items i JOIN jobs j ON j.id = i.job_id {where}"
                " ORDER BY i.id DESC LIMIT ?",
                (*params, int(limit)),
            )
            for row in cursor:
                yield dict(row)

    # -- runs ------------------------------------------------------------
    def start_run(self, job_id: int) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO runs (job_id, started_at, status) VALUES (?,?,?)",
                (int(job_id), utcnow_iso(), "running"),
            )
            return int(cursor.lastrowid)

    def finish_run(
        self, run_id: int, status: str, found: int = 0, added: int = 0, error: str = ""
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE runs SET finished_at = ?, status = ?, found = ?, added = ?,"
                " error = ? WHERE id = ?",
                (utcnow_iso(), status, int(found), int(added), error[:500], int(run_id)),
            )

    def recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT r.*, j.name AS job_name FROM runs r"
                " LEFT JOIN jobs j ON j.id = r.job_id"
                " ORDER BY r.id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def due_jobs(self) -> list[dict[str, Any]]:
        """Enabled jobs whose schedule interval has elapsed."""
        now = datetime.now(timezone.utc)
        due: list[dict[str, Any]] = []
        for job in self.list_jobs():
            if not job["enabled"] or not job["schedule_minutes"]:
                continue
            last = job.get("last_run_at")
            if not last:
                due.append(job)
                continue
            try:
                last_at = datetime.fromisoformat(last)
            except ValueError:
                due.append(job)
                continue
            if last_at.tzinfo is None:
                last_at = last_at.replace(tzinfo=timezone.utc)
            if (now - last_at).total_seconds() >= job["schedule_minutes"] * 60:
                due.append(job)
        return due

    def stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            jobs = connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            enabled = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE enabled = 1"
            ).fetchone()[0]
            items = connection.execute("SELECT COUNT(*) FROM items").fetchone()[0]
            runs = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            last = connection.execute(
                "SELECT MAX(last_run_at) FROM jobs"
            ).fetchone()[0]
        return {
            "jobs": jobs,
            "enabled_jobs": enabled,
            "items": items,
            "runs": runs,
            "last_run_at": last,
        }


# -- running ------------------------------------------------------------
def run_job(
    store: Store,
    job_id: int,
    *,
    fetch_fn: Callable[..., tuple[bytes, str, str]] | None = None,
) -> dict[str, Any]:
    """Run one job now and record the outcome. Never raises for fetch errors."""
    job = store.get_job(job_id)
    if job["kind"] == "import":
        raise CollectError("import jobs are filled by uploading a file, not by fetching")
    run_id = store.start_run(job_id)
    started = time.monotonic()
    try:
        body, final_url, content_type = (fetch_fn or fetch)(job["url"])
        records = extract(job, body, final_url, content_type)
        added = store.insert_items(job_id, records)
    except CollectError as exc:
        store.finish_run(run_id, "error", 0, 0, str(exc))
        store.update_job_run(job_id, "error", str(exc))
        return {
            "status": "error",
            "found": 0,
            "added": 0,
            "error": str(exc),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except Exception as exc:  # network stack and parsing surprises
        message = f"{type(exc).__name__}: {exc}"
        store.finish_run(run_id, "error", 0, 0, message)
        store.update_job_run(job_id, "error", message)
        return {
            "status": "error",
            "found": 0,
            "added": 0,
            "error": message,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    store.finish_run(run_id, "ok", len(records), added)
    store.update_job_run(job_id, "ok", "")
    return {
        "status": "ok",
        "found": len(records),
        "added": added,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def ingest_upload(store: Store, upload_name: str, payload: bytes) -> dict[str, Any]:
    """Import an uploaded CSV, JSON or text file as a dataset job."""
    job_name = f"import {upload_name}"[:64]
    existing = {job["name"]: job for job in store.list_jobs()}
    job = existing.get(job_name)
    if job is None:
        job = store.add_job(job_name, "import", f"upload:{upload_name}")
    job_id = int(job["id"])
    run_id = store.start_run(job_id)

    text = payload.decode("utf-8-sig", errors="replace")
    lowered = upload_name.lower()
    records: list[dict[str, str]] = []
    try:
        if lowered.endswith(".json"):
            document = json.loads(text)
            rows = document if isinstance(document, list) else [document]
            for row in rows:
                if isinstance(row, dict):
                    title = row.get("title") or next(
                        (str(v) for v in row.values() if v), ""
                    )
                    records.append(
                        {
                            "url": str(row.get("url", "")),
                            "title": str(title),
                            "body": json.dumps(row, ensure_ascii=False, sort_keys=True),
                        }
                    )
                else:
                    records.append({"url": "", "title": str(row), "body": str(row)})
        elif lowered.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                values = [value for value in row.values() if value]
                title = (row.get("title") or (values[0] if values else "")) or ""
                records.append(
                    {
                        "url": (row.get("url") or "")[:2048],
                        "title": str(title),
                        "body": json.dumps(row, ensure_ascii=False, sort_keys=True),
                    }
                )
        else:
            for line in text.splitlines():
                stripped = line.strip()
                if stripped:
                    records.append({"url": "", "title": stripped[:500], "body": stripped})
    except (json.JSONDecodeError, csv.Error, UnicodeError) as exc:
        message = f"cannot read {upload_name}: {exc}"
        store.finish_run(run_id, "error", 0, 0, message)
        store.update_job_run(job_id, "error", message)
        raise CollectError(message) from None

    added = store.insert_items(job_id, records)
    store.finish_run(run_id, "ok", len(records), added)
    store.update_job_run(job_id, "ok", "")
    return {"job_id": job_id, "job_name": job_name, "found": len(records), "added": added}


# -- scheduling ---------------------------------------------------------
class Scheduler:
    """Background loop that runs enabled jobs when their interval elapses."""

    def __init__(self, store: Store, interval: float = 30.0) -> None:
        self.store = store
        self.interval = max(1.0, float(interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_tick: str | None = None

    def tick(self) -> list[dict[str, Any]]:
        results = []
        for job in self.store.due_jobs():
            try:
                outcome = run_job(self.store, int(job["id"]))
            except CollectError as exc:  # pragma: no cover - import jobs are disabled
                outcome = {"status": "error", "error": str(exc), "job": job["name"]}
            results.append({"job": job["name"], **outcome})
        self.last_tick = utcnow_iso()
        return results

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="forgecore-scheduler", daemon=True
        )
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:  # pragma: no cover - never kill the loop
                continue

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def scheduler_enabled() -> bool:
    return os.environ.get(ENV_SCHEDULER, "").strip().lower() not in {
        "0",
        "off",
        "false",
        "no",
    }
