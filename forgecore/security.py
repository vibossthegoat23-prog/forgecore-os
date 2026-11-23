"""Security primitives shared by the CLI and the web console.

Nothing in here stores a password or a plaintext secret on disk.

* :class:`SessionStore` keeps sessions in process memory only, so a stolen
  cookie database cannot exist and logout is immediate. The cookie carries a
  random identifier, never user data.
* :class:`RateLimiter` throttles authentication attempts per client and
  globally, so a single IP cannot brute force the console and a botnet cannot
  spread guesses.
* :class:`AuditLog` appends JSON lines for security-relevant events and never
  records passwords, plaintext payloads or key material.
* :func:`security_headers` returns a strict, JS-free content security policy.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SESSION_COOKIE = "forgecore_sid"
CSRF_FIELD = "csrf_token"

SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 5 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
LOGIN_GLOBAL_MAX_ATTEMPTS = 50
LOGIN_GLOBAL_WINDOW_SECONDS = 5 * 60

AUDIT_MAX_BYTES = 1024 * 1024
_FILE_MODE = 0o600


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings without leaking length or content via timing."""
    return hmac.compare_digest(
        hashlib.sha256(left.encode("utf-8")).digest(),
        hashlib.sha256(right.encode("utf-8")).digest(),
    )


class RateLimitExceeded(Exception):
    """Raised when a caller has exhausted its attempt budget."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"too many attempts, retry in {retry_after} seconds")
        self.retry_after = max(1, int(retry_after))


@dataclass
class _Bucket:
    hits: list[float] = field(default_factory=list)
    blocked_until: float = 0.0


class RateLimiter:
    """Sliding-window limiter with a lockout once the budget is spent.

    ``limit`` attempts are allowed inside ``window`` seconds; exceeding it
    blocks the key for ``lockout`` seconds. The number of tracked keys is
    bounded so an attacker cannot grow memory without limit.
    """

    def __init__(
        self,
        limit: int,
        window: float,
        *,
        lockout: float = 0.0,
        max_keys: int = 4096,
        clock=time.monotonic,
    ) -> None:
        self.limit = max(1, int(limit))
        self.window = float(window)
        self.lockout = float(lockout)
        self.max_keys = max(16, int(max_keys))
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        stale = [
            key
            for key, bucket in self._buckets.items()
            if bucket.blocked_until <= now
            and (not bucket.hits or now - bucket.hits[-1] > self.window)
        ]
        for key in stale:
            del self._buckets[key]

    def check(self, key: str) -> None:
        """Raise :class:`RateLimitExceeded` when ``key`` must be refused."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None and bucket.blocked_until > now:
                raise RateLimitExceeded(bucket.blocked_until - now)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._prune(now)
                    if len(self._buckets) >= self.max_keys:
                        # Fail closed for new keys rather than growing forever.
                        raise RateLimitExceeded(self.window)
                bucket = _Bucket()
                self._buckets[key] = bucket
            bucket.hits = [hit for hit in bucket.hits if now - hit <= self.window]
            if len(bucket.hits) >= self.limit:
                bucket.blocked_until = now + max(self.lockout, self.window)
                raise RateLimitExceeded(bucket.blocked_until - now)

    def register_failure(self, key: str) -> None:
        """Record one failed attempt for ``key``."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.setdefault(key, _Bucket())
            bucket.hits = [hit for hit in bucket.hits if now - hit <= self.window]
            bucket.hits.append(now)
            if len(bucket.hits) >= self.limit and self.lockout:
                bucket.blocked_until = now + self.lockout

    def reset(self, key: str) -> None:
        """Clear the budget for ``key`` after a successful authentication."""
        with self._lock:
            self._buckets.pop(key, None)

    def retry_after(self, key: str) -> int:
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return 0
            return max(0, int(bucket.blocked_until - now))


@dataclass
class Session:
    """A server-side console session. The master key stays in memory only."""

    sid: str
    csrf: str
    created: float
    last_seen: float
    master_key: bytes | None = None

    def expired(self, now: float) -> bool:
        if now - self.created > SESSION_ABSOLUTE_SECONDS:
            return True
        return now - self.last_seen > SESSION_IDLE_SECONDS


class SessionStore:
    """In-memory session table with idle and absolute expiry."""

    def __init__(self, *, clock=time.monotonic, max_sessions: int = 512) -> None:
        self._clock = clock
        self.max_sessions = max_sessions
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def _sweep(self, now: float) -> None:
        for sid in [sid for sid, s in self._sessions.items() if s.expired(now)]:
            self._sessions.pop(sid, None)

    def create(self) -> Session:
        now = self._clock()
        with self._lock:
            self._sweep(now)
            if len(self._sessions) >= self.max_sessions:
                oldest = min(self._sessions.values(), key=lambda s: s.last_seen)
                self._sessions.pop(oldest.sid, None)
            sid = secrets.token_urlsafe(32)
            session = Session(
                sid=sid,
                csrf=secrets.token_urlsafe(32),
                created=now,
                last_seen=now,
            )
            self._sessions[sid] = session
            return session

    def get(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        now = self._clock()
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            if session.expired(now):
                self._sessions.pop(sid, None)
                return None
            session.last_seen = now
            return session

    def destroy(self, sid: str | None) -> None:
        if not sid:
            return
        with self._lock:
            self._sessions.pop(sid, None)

    def __len__(self) -> int:  # pragma: no cover - diagnostics
        with self._lock:
            return len(self._sessions)


class AuditLog:
    """Append-only JSON-lines audit trail, owner-readable only."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.stat().st_size < AUDIT_MAX_BYTES:
                return
        except FileNotFoundError:
            return
        except OSError:  # pragma: no cover
            return
        backup = self.path.with_suffix(self.path.suffix + ".1")
        try:
            os.replace(self.path, backup)
        except OSError:  # pragma: no cover
            pass

    def record(self, event: str, *, actor: str = "system", **detail) -> None:
        """Append one event. Callers must not pass secrets in ``detail``."""
        entry = {"ts": utcnow_iso(), "event": event, "actor": actor, "detail": detail}
        line = json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n"
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                self._rotate_if_needed()
                fd = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                    _FILE_MODE,
                )
                try:
                    os.write(fd, line.encode("utf-8"))
                finally:
                    os.close(fd)
                try:
                    self.path.chmod(_FILE_MODE)
                except OSError:  # pragma: no cover
                    pass
            except OSError:
                # Auditing must never crash a request; the caller keeps working.
                pass

    def tail(self, limit: int = 20) -> list[dict]:
        """Return up to ``limit`` most recent entries, newest last."""
        try:
            raw = self.path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, OSError):
            return []
        entries: list[dict] = []
        for line in raw.splitlines()[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries


def security_headers(*, allow_forms: bool = True) -> dict[str, str]:
    """Strict headers for a server-rendered, JavaScript-free UI."""
    csp = (
        "default-src 'none'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    headers = {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Cache-Control": "no-store",
    }
    if not allow_forms:  # pragma: no cover - reserved for future use
        headers["Content-Security-Policy"] = csp.replace(
            "form-action 'self'; ", ""
        )
    return headers


def client_key(forwarded_for: str | None, peer: str | None) -> str:
    """Derive a rate-limit key from the proxy's view of the client.

    The hosting proxy appends the real client address to ``X-Forwarded-For``,
    so the last entry is the value our own proxy observed. Anything a client
    prepends is ignored, which prevents trivial key spoofing.
    """
    if forwarded_for:
        parts = [part.strip() for part in forwarded_for.split(",") if part.strip()]
        if parts:
            return parts[-1][:64]
    return (peer or "unknown")[:64]
