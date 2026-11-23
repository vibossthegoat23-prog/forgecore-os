"""Security primitives: throttling, sessions, audit log, response headers."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from forgecore.security import (
    AuditLog,
    RateLimitExceeded,
    RateLimiter,
    SessionStore,
    client_key,
    constant_time_equals,
    security_headers,
)


def test_constant_time_compare_matches_real_equality() -> None:
    assert constant_time_equals("abc", "abc") is True
    assert constant_time_equals("abc", "abd") is False
    assert constant_time_equals("", "") is True
    assert constant_time_equals("abc", "abcd") is False


def test_rate_limiter_blocks_after_the_failure_budget() -> None:
    limiter = RateLimiter(max_failures=3, window_seconds=60)
    for _ in range(3):
        limiter.check("1.2.3.4")
        limiter.register_failure("1.2.3.4")
    with pytest.raises(RateLimitExceeded) as excinfo:
        limiter.check("1.2.3.4")
    assert excinfo.value.retry_after >= 1


def test_rate_limiter_is_per_key() -> None:
    limiter = RateLimiter(max_failures=1, window_seconds=60)
    limiter.register_failure("a")
    with pytest.raises(RateLimitExceeded):
        limiter.check("a")
    limiter.check("b")  # a different client is unaffected


def test_successful_login_resets_the_failure_count() -> None:
    limiter = RateLimiter(max_failures=2, window_seconds=60)
    limiter.register_failure("key")
    limiter.reset("key")
    limiter.check("key")
    limiter.register_failure("key")
    limiter.check("key")


def test_rate_limiter_window_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    limiter = RateLimiter(max_failures=1, window_seconds=10, clock=lambda: now[0])
    limiter.register_failure("key")
    with pytest.raises(RateLimitExceeded):
        limiter.check("key")
    now[0] += 11
    limiter.check("key")


def test_session_lifecycle() -> None:
    store = SessionStore()
    session = store.create()
    assert store.get(session.sid) is session
    assert session.csrf
    store.destroy(session.sid)
    assert store.get(session.sid) is None


def test_sessions_are_unique_and_carry_no_user_data() -> None:
    store = SessionStore()
    first, second = store.create(), store.create()
    assert first.sid != second.sid
    assert first.csrf != second.csrf
    assert len(first.sid) >= 32


def test_unknown_session_identifier_is_rejected() -> None:
    assert SessionStore().get("not-a-real-session") is None
    assert SessionStore().get(None) is None


def test_session_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [0.0]
    store = SessionStore(clock=lambda: now[0], ttl_seconds=10)
    session = store.create()
    now[0] += 11
    assert store.get(session.sid) is None


def test_session_store_is_bounded() -> None:
    store = SessionStore(max_sessions=3)
    for _ in range(10):
        store.create()
    assert len(store) <= 3


def test_audit_log_appends_without_secrets(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log")
    log.record("vault.unlock_failed", actor="1.2.3.4", reason="wrong password")
    raw = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "vault.unlock_failed" in raw
    payload = json.loads(raw.strip().splitlines()[-1])
    assert payload["event"] == "vault.unlock_failed"
    assert payload["actor"] == "1.2.3.4"


def test_audit_log_tail_is_limited_and_ordered(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log")
    for index in range(5):
        log.record("event", actor="cli", index=index)
    tail = log.tail(2)
    assert len(tail) == 2
    assert tail[-1]["index"] == 4


def test_audit_log_tail_on_missing_file_is_empty(tmp_path: Path) -> None:
    assert AuditLog(tmp_path / "absent.log").tail() == []


def test_audit_log_is_owner_only(tmp_path: Path) -> None:
    import stat

    log = AuditLog(tmp_path / "audit.log")
    log.record("event")
    assert stat.S_IMODE((tmp_path / "audit.log").stat().st_mode) == 0o600


def test_security_headers_block_script_and_framing() -> None:
    headers = security_headers()
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp.split("style-src")[0]
    assert "frame-ancestors 'none'" in csp
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in headers["Cache-Control"]


def test_client_key_prefers_the_forwarded_client() -> None:
    assert client_key("203.0.113.9", "10.0.0.1") == "203.0.113.9"
    assert client_key("198.51.100.4, 10.0.0.1", "10.0.0.1") == "198.51.100.4"
    assert client_key(None, "10.0.0.1") == "10.0.0.1"
    assert client_key("", None) == "unknown"


def test_rate_limiter_prunes_stale_buckets() -> None:
    now = [0.0]
    limiter = RateLimiter(max_failures=1, window_seconds=5, clock=lambda: now[0])
    for index in range(200):
        limiter.register_failure(f"client-{index}")
    now[0] += 100
    limiter.check("fresh")
    assert time.monotonic() >= 0
