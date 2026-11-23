"""ForgeCore web console: a small, server-rendered UI over the subsystems.

Security posture
----------------
* **Authentication** - one operator password, compared in constant time. It is
  read from ``FORGECORE_CONSOLE_PASSWORD`` when set; otherwise a one-time
  ``/setup`` page stores a PBKDF2-HMAC-SHA256 hash (600k iterations, random
  salt) in the home directory. Only the hash is written, never the password,
  and the setup page closes for good once a password exists.
* **Sessions** - the cookie holds a random identifier only. Session state lives
  in process memory, so logout and expiry are immediate and no user data is
  exposed to the client.
* **CSRF** - every state-changing form carries a per-session token checked in
  constant time. ``SameSite=Lax`` is set as defence in depth.
* **Throttling** - login attempts are limited per client and globally.
* **No JavaScript** - the UI is plain HTML forms, which lets the content
  security policy forbid scripts entirely.
* **Downloads** - always ``application/octet-stream`` with
  ``Content-Disposition: attachment`` so an uploaded HTML file can never be
  rendered as a page in the console origin.
* **Vault** - the master key is derived from a password supplied at unlock time
  and kept in memory for that session only; it is never persisted or logged.
"""

from __future__ import annotations

import csv
import io
import json
import os
import secrets
import sys
import traceback
from pathlib import Path
from urllib.parse import quote
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, Request, Response, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response as RawResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from forgecore import APP_NAME, __version__
from forgecore.backup import (
    MAX_ARCHIVE_BYTES,
    BackupError,
    create_backup,
    restore_backup,
)
from forgecore.agents import ONLINE_WINDOW_SECONDS, AgentError, AgentRegistry
from forgecore.collect import (
    KINDS as COLLECT_KINDS,
)
from forgecore.collect import (
    CollectError,
    Scheduler,
    Store,
    ingest_upload,
    run_job,
    scheduler_enabled,
)
from forgecore.config import (
    ENV_CONSOLE_PASSWORD,
    ENV_KDF_ITERATIONS,
    ENV_VAULT_PASSWORD,
    Home,
    default_home,
    kdf_iterations,
)
from forgecore.dashboard import snapshot
from forgecore.replica import ReplicaError, ReplicaNotFound, ReplicaSyncer
from forgecore.console import human_bytes, human_duration
from forgecore.security import (
    CSRF_FIELD,
    LOGIN_GLOBAL_MAX_ATTEMPTS,
    LOGIN_GLOBAL_WINDOW_SECONDS,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    PASSWORD_MIN_LENGTH,
    SESSION_COOKIE,
    AuditLog,
    RateLimitExceeded,
    RateLimiter,
    Session,
    SessionStore,
    client_key,
    constant_time_equals,
    load_console_hash,
    save_console_hash,
    security_headers,
    verify_password,
)
from forgecore.uploads import (
    MAX_UPLOAD_BYTES,
    MIN_FREE_BYTES,
    UploadError,
    delete_upload,
    intake,
    list_uploads,
    open_upload,
    sanitize_name,
    stats,
    upload_quota,
)
from forgecore.vault import (
    DEFAULT_ITERATIONS,
    Vault,
    VaultError,
    format_recovery_code,
    normalize_recovery_code,
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

MAX_FORM_BYTES = MAX_UPLOAD_BYTES + (1024 * 1024)
CONSOLE_PASSWORD_FILE = "console.password"

UPLOADS_PAGE_SIZE = 25
VAULT_PAGE_SIZE = 25
AUDIT_PAGE_SIZE = 50

SAFE_DOWNLOAD_TYPE = "application/octet-stream"


def _configured_console_password() -> str | None:
    """Return the operator password from the environment, if one is set.

    ``FORGECORE_CONSOLE_PASSWORD`` wins over everything else: when present the
    first-run setup page is disabled, so a hosted install can be locked down
    from configuration alone.
    """
    configured = os.environ.get(ENV_CONSOLE_PASSWORD, "").strip()
    if not configured:
        return None
    if len(configured) < PASSWORD_MIN_LENGTH:
        raise RuntimeError(
            f"{ENV_CONSOLE_PASSWORD} must be at least {PASSWORD_MIN_LENGTH} characters"
        )
    return configured


class Console:
    """Container for the mutable server state of one console instance."""

    def __init__(self, home: Home) -> None:
        self.home = home.ensure()
        # Fail fast: a read-only or full volume must be reported at startup,
        # not as a half-written vault entry during a collection run.
        self.home.check_writable()
        self.vault = Vault(self.home.vault_dir)
        self.agents = AgentRegistry(self.home.agents_file)
        self.audit = AuditLog(self.home.audit_log_file)
        self.sessions = SessionStore()
        self.login_limiter = RateLimiter(
            LOGIN_MAX_ATTEMPTS,
            LOGIN_WINDOW_SECONDS,
            lockout=LOGIN_LOCKOUT_SECONDS,
        )
        self.global_limiter = RateLimiter(
            LOGIN_GLOBAL_MAX_ATTEMPTS, LOGIN_GLOBAL_WINDOW_SECONDS
        )
        self.password = _configured_console_password()
        self.password_hash = (
            None if self.password else load_console_hash(self.home.console_hash_file)
        )
        self.setup_limiter = RateLimiter(
            LOGIN_MAX_ATTEMPTS,
            LOGIN_WINDOW_SECONDS,
            lockout=LOGIN_LOCKOUT_SECONDS,
        )
        self.iterations = kdf_iterations(DEFAULT_ITERATIONS)
        self.replica = ReplicaSyncer(self.home)
        self.replica_restore_note: dict[str, Any] | None = None
        # Recreate state before anything reads it: on a host without a
        # persistent disk this process may have started on an empty volume.
        self._restore_from_replica()
        # Collected records live in data/, which backup and the replica carry.
        self.dataset = Store(self.home.dataset_db)
        self.scheduler = Scheduler(self.dataset)
        if scheduler_enabled():
            self.scheduler.start()
        self.audit.on_record = self._on_audit_event
        self._auto_unlock()
        self.audit.record("console.start", version=__version__)

    def _auto_unlock(self) -> None:
        """Unlock the vault at startup when a password is supplied via env."""
        password = os.environ.get(ENV_VAULT_PASSWORD)
        if not password:
            return
        try:
            if not self.vault.is_initialized():
                self.vault.init_vault(password, iterations=self.iterations)
                self.audit.record("vault.init", actor="startup")
            else:
                self.vault.unlock(password)
                self.audit.record("vault.unlock", actor="startup")
        except VaultError as exc:
            self.audit.record("vault.unlock_failed", actor="startup", reason=str(exc))

    # -- durability -------------------------------------------------------
    # Events that change stored state, and so are worth replicating off-host.
    REPLICATED_EVENTS = frozenset(
        {
            "vault.init",
            "vault.entry_created",
            "vault.entry_deleted",
            "vault.recovery_created",
            "vault.recovered",
            "upload.created",
            "upload.deleted",
            "agent.registered",
            "agent.removed",
            "backup.restored",
            "console.password_set",
        }
    )
    # Setup attempts that changed nothing must not trigger an upload.
    REPLICATE_EXCLUDED = frozenset(
        {
            "console.setup_failed",
            "console.setup_rejected",
            "console.setup_throttled",
        }
    )

    def _restore_from_replica(self) -> None:
        """Recreate state from the off-host replica when starting empty."""
        config = self.replica.config
        if config is None or not config.autorestore:
            return
        try:
            if self.vault.is_initialized():
                return  # local state wins; never overwrite it at boot
        except VaultError:  # pragma: no cover - defensive
            return
        try:
            summary = self.replica.pull_once()
        except ReplicaNotFound:
            self.replica_restore_note = {
                "ok": False,
                "message": (
                    "No replica was stored yet, so this empty installation started "
                    "fresh. The first change will create the off-host copy."
                ),
            }
            self.audit.record("replica.empty", endpoint=config.host)
            return
        except ReplicaError as exc:
            self.replica_restore_note = {
                "ok": False,
                "message": f"Could not restore from the replica: {exc}",
            }
            self.audit.record("replica.restore_failed", reason=str(exc))
            return
        # The restore replaced the files behind these objects.
        self.vault = Vault(self.home.vault_dir)
        self.agents = AgentRegistry(self.home.agents_file)
        self.password_hash = (
            None
            if self.password
            else load_console_hash(self.home.console_hash_file)
        )
        self.replica_restore_note = {
            "ok": True,
            "message": (
                f"Restored {summary.get('files', 0)} file(s) and "
                f"{summary.get('uploads', 0)} upload(s) from the off-host replica "
                f"after this host started empty."
            ),
        }
        self.audit.record(
            "replica.restored",
            files=summary.get("files"),
            uploads=summary.get("uploads"),
            endpoint=config.host,
        )

    def _on_audit_event(self, event: str) -> None:
        """Queue a replica push when an event changed stored state."""
        if event in self.REPLICATE_EXCLUDED:
            return
        if event in self.REPLICATED_EVENTS or event.startswith("console.setup"):
            self.replica.mark_dirty()

    def mark_dirty(self) -> None:
        """Queue a replica push after a state change made outside the audit log."""
        self.replica.mark_dirty()

    # -- console password -------------------------------------------------
    @property
    def needs_setup(self) -> bool:
        """True while no console password exists anywhere (first run)."""
        return self.password is None and self.password_hash is None

    def check_password(self, candidate: str) -> bool:
        """Verify a login attempt against the env password or stored hash."""
        if not candidate:
            return False
        if self.password is not None:
            return constant_time_equals(candidate, self.password)
        if self.password_hash is not None:
            return verify_password(self.password_hash, candidate)
        return False

    def store_password(self, password: str) -> None:
        """Persist a first-run password as a PBKDF2 hash and adopt it."""
        save_console_hash(self.home.console_hash_file, password)
        self.password_hash = load_console_hash(self.home.console_hash_file)
        self.password = None

    # -- helpers ---------------------------------------------------------
    def session_from(self, request: Request) -> Session | None:
        return self.sessions.get(request.cookies.get(SESSION_COOKIE))

    def csrf_ok(self, session: Session, token: str | None) -> bool:
        return bool(token) and constant_time_equals(session.csrf, token or "")


def _client_key(request: Request) -> str:
    return client_key(
        request.headers.get("x-forwarded-for"),
        request.client.host if request.client else None,
    )


def create_app(home: Home | None = None) -> FastAPI:
    """Build the FastAPI application. Importing this module has no side effects."""
    app = FastAPI(
        title=f"{APP_NAME} console",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    console = Console(home or default_home())
    app.state.console = console
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    templates.env.filters["human_bytes"] = human_bytes
    templates.env.filters["human_duration"] = human_duration

    if console.needs_setup:
        print(
            "[forgecore] no console password configured yet; open /setup in a "
            f"browser to choose one, or set {ENV_CONSOLE_PASSWORD} to disable "
            "the setup page.",
            file=sys.stderr,
            flush=True,
        )

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # -- middleware ------------------------------------------------------
    @app.middleware("http")
    async def harden(request: Request, call_next):
        length = request.headers.get("content-length")
        # A backup restore is a legitimate large upload; every other form keeps
        # the small limit so a huge body cannot be streamed into memory.
        limit = (
            MAX_ARCHIVE_BYTES + (1024 * 1024)
            if request.url.path == "/backup/restore"
            else MAX_FORM_BYTES
        )
        if length and length.isdigit() and int(length) > limit:
            return HTMLResponse(
                "<h1>413 Payload Too Large</h1>", status_code=413,
                headers=security_headers(),
            )
        response = await call_next(request)
        for name, value in security_headers().items():
            response.headers.setdefault(name, value)
        return response

    def _safe_next(value: str, default: str = "/vault") -> str:
        """Only accept a same-origin absolute path as a redirect target."""
        if not value or not value.startswith("/") or value.startswith("//"):
            return default
        if "\r" in value or "\n" in value:
            return default
        return value

    # -- rendering -------------------------------------------------------
    def page(
        request: Request,
        template: str,
        *,
        session: Session | None = None,
        status_code: int = 200,
        **context: Any,
    ) -> HTMLResponse:
        base = {
            "app_name": APP_NAME,
            "version": __version__,
            "csrf_token": session.csrf if session else "",
            "signed_in": session is not None,
            "notice": None,
            "error": None,
            "storage_persistent": console.home.storage_is_persistent(),
            "vault_locked": not console.vault.unlocked,
            "replica": console.replica.status(),
            "replica_restore_note": console.replica_restore_note,
            "inline_unlock": True,
            "current_path": request.url.path,
        }
        base.update(context)
        return templates.TemplateResponse(
            request, template, base, status_code=status_code
        )

    def _label(value: int | None) -> str:
        if not value:
            return "0 B"
        if value >= 1024 * 1024 * 1024:
            return f"{value / (1024 * 1024 * 1024):.2f} GiB"
        if value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.1f} MiB"
        return f"{value / 1024:.0f} KiB"

    def storage_context() -> dict[str, Any]:
        count, total = stats(console.home.uploads_dir)
        quota = upload_quota()
        free = console.home.free_bytes()
        return {
            "persistent": console.home.storage_is_persistent(),
            "free_bytes": free,
            "upload_count": count,
            "upload_bytes": total,
            "upload_quota_bytes": quota,
            "used_label": _label(total),
            "quota_label": _label(quota),
            "free_label": _label(free),
            "percent_used": int(min(100, (total / quota * 100) if quota else 0)),
        }

    def page_number(request: Request) -> int:
        try:
            return max(1, int(request.query_params.get("page", "1")))
        except (TypeError, ValueError):
            return 1

    def paginate(
        items: list[Any], current: int, size: int, base: str
    ) -> dict[str, Any]:
        """Return one bounded page of ``items`` plus the pager metadata."""
        total = len(items)
        pages = max(1, (total + size - 1) // size)
        current = min(max(1, current), pages)
        start = (current - 1) * size
        chunk = items[start : start + size]
        return {
            "items": chunk,
            "page": current,
            "pages": pages,
            "total": total,
            "start": start + 1 if total else 0,
            "end": start + len(chunk),
            "base": base,
            "has_prev": current > 1,
            "has_next": current < pages,
        }

    def current_session(request: Request) -> Session | None:
        return console.session_from(request)

    def require_session(request: Request) -> Session:
        session = console.session_from(request)
        if session is None:
            raise _RedirectToLogin()
        return session

    class _RedirectToLogin(Exception):
        pass

    @app.exception_handler(_RedirectToLogin)
    async def _login_redirect(request: Request, exc: _RedirectToLogin):
        return RedirectResponse("/login", status_code=303)

    def redirect(path: str, *, session: Session | None = None) -> RedirectResponse:
        response = RedirectResponse(path, status_code=303)
        if session is not None:
            response.set_cookie(
                SESSION_COOKIE,
                session.sid,
                httponly=True,
                samesite="lax",
                secure=False,
                path="/",
                max_age=8 * 60 * 60,
            )
        return response

    def set_session_cookie(response: Response, session: Session, request: Request) -> None:
        secure = request.url.scheme == "https" or request.headers.get(
            "x-forwarded-proto", ""
        ).split(",")[0].strip() == "https"
        response.set_cookie(
            SESSION_COOKIE,
            session.sid,
            httponly=True,
            samesite="lax",
            secure=secure,
            path="/",
            max_age=8 * 60 * 60,
        )

    def download(data: bytes, filename: str) -> RawResponse:
        safe = sanitize_name(filename)
        return RawResponse(
            content=data,
            media_type=SAFE_DOWNLOAD_TYPE,
            headers={
                "Content-Disposition": f'attachment; filename="{safe}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    # -- public routes ---------------------------------------------------
    def health_payload() -> tuple[dict[str, Any], int]:
        """Liveness plus the state the app needs to keep accepting data.

        A process that cannot write its own state is not healthy: the next
        collection write would fail, so the probe reports 503 instead of
        staying green while every upload errors.
        """
        writable = True
        reason = None
        try:
            console.home.check_writable()
        except (RuntimeError, OSError) as exc:
            writable = False
            reason = str(exc)
        free = console.home.free_bytes()
        if writable and free and free < MIN_FREE_BYTES:
            writable = False
            reason = f"only {free // (1024 * 1024)} MiB free"
        count, total = stats(console.home.uploads_dir)
        payload: dict[str, Any] = {
            "status": "ok" if writable else "degraded",
            "app": APP_NAME,
            "version": __version__,
            "storage": {
                "writable": writable,
                "persistent": console.home.storage_is_persistent(),
                "free_bytes": free,
                "reason": reason,
            },
            "uploads": {"count": count, "bytes": total},
            "vault_locked": not console.vault.unlocked,
        }
        return payload, 200 if writable else 503

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        payload, status_code = health_payload()
        return JSONResponse(payload, status_code=status_code)

    # The hosting edge answers /healthz itself, so the same answer is exposed
    # on /health, which is what the container healthcheck uses.
    @app.get("/health")
    async def health() -> JSONResponse:
        payload, status_code = health_payload()
        return JSONResponse(payload, status_code=status_code)

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        if console.session_from(request):
            return RedirectResponse("/", status_code=303)
        if console.needs_setup:
            return RedirectResponse("/setup", status_code=303)
        return page(request, "login.html")

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(
        request: Request,
        password: Annotated[str, Form()] = "",
    ):
        if console.needs_setup:
            return RedirectResponse("/setup", status_code=303)
        key = _client_key(request)
        try:
            console.login_limiter.check(key)
            console.global_limiter.check("global")
        except RateLimitExceeded as exc:
            console.audit.record("auth.throttled", actor=key)
            return page(
                request,
                "login.html",
                status_code=429,
                error=f"Too many attempts. Try again in {exc.retry_after} seconds.",
            )

        if not console.check_password(password):
            console.login_limiter.register_failure(key)
            console.global_limiter.register_failure("global")
            console.audit.record("auth.failure", actor=key)
            return page(
                request,
                "login.html",
                status_code=401,
                error="Incorrect password.",
            )

        console.login_limiter.reset(key)
        session = console.sessions.create()
        console.audit.record("auth.success", actor=key)
        response = RedirectResponse("/", status_code=303)
        set_session_cookie(response, session, request)
        return response

    # -- first run --------------------------------------------------------
    @app.get("/setup", response_class=HTMLResponse)
    async def setup_form(request: Request):
        """One-time page that claims a console with no password configured."""
        if not console.needs_setup:
            return RedirectResponse("/login", status_code=303)
        return page(request, "setup.html", min_length=PASSWORD_MIN_LENGTH)

    @app.post("/setup", response_class=HTMLResponse)
    async def setup_submit(
        request: Request,
        password: Annotated[str, Form()] = "",
        confirm: Annotated[str, Form()] = "",
    ):
        if not console.needs_setup:
            # Setup closes permanently once a password exists, so an already
            # claimed console cannot be taken over by a later visitor.
            return RedirectResponse("/login", status_code=303)
        key = _client_key(request)
        try:
            console.setup_limiter.check(key)
            console.global_limiter.check("global")
        except RateLimitExceeded as exc:
            console.audit.record("console.setup_throttled", actor=key)
            return page(
                request,
                "setup.html",
                status_code=429,
                min_length=PASSWORD_MIN_LENGTH,
                error=f"Too many attempts. Try again in {exc.retry_after} seconds.",
            )
        problem = None
        if len(password) < PASSWORD_MIN_LENGTH:
            problem = f"Use at least {PASSWORD_MIN_LENGTH} characters."
        elif password != confirm:
            problem = "The two passwords do not match."
        if problem:
            console.setup_limiter.register_failure(key)
            console.audit.record("console.setup_rejected", actor=key)
            return page(
                request,
                "setup.html",
                status_code=400,
                min_length=PASSWORD_MIN_LENGTH,
                error=problem,
            )
        try:
            console.store_password(password)
        except OSError:
            console.audit.record("console.setup_failed", actor=key)
            return page(
                request,
                "setup.html",
                status_code=500,
                min_length=PASSWORD_MIN_LENGTH,
                error=(
                    "Could not save the password: the data directory is not "
                    "writable. Check the storage mount and try again."
                ),
            )
        console.login_limiter.reset(key)
        console.audit.record("console.setup", actor=key)
        session = console.sessions.create()
        response = RedirectResponse("/", status_code=303)
        set_session_cookie(response, session, request)
        return response

    @app.post("/logout")
    async def logout(request: Request, csrf_token: Annotated[str, Form()] = ""):
        session = console.session_from(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/", status_code=303)
        console.sessions.destroy(session.sid)
        console.audit.record("auth.logout", actor=_client_key(request))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # -- recovery (no session required: the password is what was lost) ----
    @app.get("/recover", response_class=HTMLResponse)
    async def recover_form(request: Request):
        return page(
            request,
            "recover.html",
            has_recovery=console.vault.has_recovery(),
            initialized=console.vault.is_initialized(),
        )

    @app.post("/recover", response_class=HTMLResponse)
    async def recover_submit(
        request: Request,
        recovery_code: Annotated[str, Form()] = "",
        new_password: Annotated[str, Form()] = "",
        confirm_password: Annotated[str, Form()] = "",
    ):
        key = _client_key(request)
        try:
            console.login_limiter.check(key)
            console.global_limiter.check("global")
        except RateLimitExceeded as exc:
            return page(
                request,
                "recover.html",
                status_code=429,
                has_recovery=console.vault.has_recovery(),
                initialized=console.vault.is_initialized(),
                error=f"Too many attempts. Try again in {exc.retry_after} seconds.",
            )

        context = {
            "has_recovery": console.vault.has_recovery(),
            "initialized": console.vault.is_initialized(),
        }
        if new_password != confirm_password:
            return page(
                request,
                "recover.html",
                status_code=400,
                error="The new passwords do not match.",
                **context,
            )
        try:
            code = normalize_recovery_code(recovery_code)
            fresh_code = console.vault.recover(code, new_password)
        except VaultError as exc:
            console.login_limiter.register_failure(key)
            console.global_limiter.register_failure("global")
            console.audit.record("vault.recover_failed", actor=key)
            return page(
                request, "recover.html", status_code=400, error=str(exc), **context
            )

        console.login_limiter.reset(key)
        console.audit.record("vault.recovered", actor=key)
        return page(
            request,
            "recover_done.html",
            has_recovery=True,
            initialized=True,
            recovery_code=format_recovery_code(fresh_code),
        )

    # -- authenticated routes -------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def dashboard_view(request: Request, session: Session = Depends(require_session)):
        data = snapshot(console.home)
        return page(
            request,
            "dashboard.html",
            session=session,
            data=data,
            vault_locked=not console.vault.unlocked,
            recovery=console.vault.has_recovery(),
        )

    @app.get("/uploads", response_class=HTMLResponse)
    async def uploads_view(request: Request, session: Session = Depends(require_session)):
        listing = paginate(
            list_uploads(console.home.uploads_dir),
            page_number(request),
            UPLOADS_PAGE_SIZE,
            "/uploads",
        )
        return page(
            request,
            "uploads.html",
            session=session,
            names=listing["items"],
            pagination=listing,
            limit_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
            storage=storage_context(),
        )

    @app.post("/uploads", response_class=HTMLResponse)
    async def uploads_create(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        file: UploadFile | None = None,
    ):
        def uploads_page(**extra: Any):
            """Render the uploads view with the context its template needs.

            Rendering it from an error branch without ``storage`` and
            ``pagination`` used to turn a quota refusal into a 500.
            """
            listing = paginate(
                list_uploads(console.home.uploads_dir),
                page_number(request),
                UPLOADS_PAGE_SIZE,
                "/uploads",
            )
            return page(
                request,
                "uploads.html",
                session=session,
                names=listing["items"],
                pagination=listing,
                limit_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
                storage=storage_context(),
                **extra,
            )

        if not console.csrf_ok(session, csrf_token):
            return page(request, "error.html", session=session, status_code=400,
                        error="Invalid form token. Reload the page and try again.")
        if file is None or not file.filename:
            return uploads_page(status_code=400, error="Choose a file to upload.")
        try:
            target_name = sanitize_name(file.filename)
            staging = console.home.root / f".incoming-{secrets.token_hex(8)}"
            written = 0
            with open(staging, "wb") as handle:
                while True:
                    chunk = await file.read(64 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_UPLOAD_BYTES:
                        raise UploadError(
                            f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit."
                        )
                    handle.write(chunk)
            try:
                intake(staging, console.home.uploads_dir, name=target_name)
            finally:
                staging.unlink(missing_ok=True)
            console.audit.record(
                "upload.created", actor=_client_key(request), name=target_name, bytes=written
            )
        except UploadError as exc:
            return uploads_page(status_code=400, error=str(exc))
        return redirect("/uploads")

    @app.get("/uploads/{name}")
    async def uploads_download(name: str, session: Session = Depends(require_session)):
        try:
            data = open_upload(console.home.uploads_dir, name)
        except UploadError as exc:
            return HTMLResponse(str(exc), status_code=404)
        console.audit.record("upload.downloaded", actor="operator", name=name)
        return download(data, name)

    @app.post("/uploads/{name}/delete", response_class=HTMLResponse)
    async def uploads_delete(
        name: str,
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/uploads", status_code=303)
        try:
            delete_upload(console.home.uploads_dir, name)
            console.audit.record("upload.deleted", actor=_client_key(request), name=name)
        except UploadError:
            pass
        return redirect("/uploads")

    @app.post("/uploads/{name}/import", response_class=HTMLResponse)
    async def uploads_import(
        name: str,
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        """Turn a stored upload into dataset rows so it is searchable/exportable."""
        if not console.csrf_ok(session, csrf_token):
            return page(request, "error.html", session=session, status_code=400,
                        error="Invalid form token. Reload the page and try again.")
        try:
            payload = open_upload(console.home.uploads_dir, name)
            summary = ingest_upload(console.dataset, name, payload)
        except (UploadError, CollectError) as exc:
            listing = paginate(
                list_uploads(console.home.uploads_dir),
                page_number(request),
                UPLOADS_PAGE_SIZE,
                "/uploads",
            )
            return page(
                request,
                "uploads.html",
                session=session,
                names=listing["items"],
                pagination=listing,
                limit_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
                storage=storage_context(),
                status_code=400,
                error=str(exc),
            )
        console.audit.record(
            "upload.imported",
            actor=_client_key(request),
            name=name,
            added=summary["added"],
        )
        console.mark_dirty()
        return redirect(f"/results?job={summary['job_id']}", session=session)

    @app.get("/vault", response_class=HTMLResponse)
    async def vault_view(request: Request, session: Session = Depends(require_session)):
        listing = paginate(
            console.vault.list(), page_number(request), VAULT_PAGE_SIZE, "/vault"
        )
        return page(
            request,
            "vault.html",
            session=session,
            entries=listing["items"],
            pagination=listing,
            locked=not console.vault.unlocked,
            initialized=console.vault.is_initialized(),
            recovery=console.vault.has_recovery(),
            inline_unlock=False,
        )

    @app.post("/backup/replica/push", response_class=HTMLResponse)
    async def backup_replica_push(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/backup", status_code=303)
        actor = _client_key(request)
        try:
            result = console.replica.push_once()
            console.audit.record("replica.pushed", actor=actor, bytes=result["bytes"])
        except ReplicaError as exc:
            console.audit.record("replica.push_failed", actor=actor, reason=str(exc))
        return redirect("/backup")

    @app.post("/backup/replica/restore", response_class=HTMLResponse)
    async def backup_replica_restore(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/backup", status_code=303)
        actor = _client_key(request)
        try:
            summary = console.replica.pull_once()
        except ReplicaError as exc:
            console.replica_restore_note = {"ok": False, "message": str(exc)}
            console.audit.record("replica.restore_failed", actor=actor, reason=str(exc))
            return redirect("/backup")
        # The restored key material is not the material that was in memory.
        console.vault = Vault(console.home.vault_dir)
        console.agents = AgentRegistry(console.home.agents_file)
        console.password_hash = (
            None
            if console.password
            else load_console_hash(console.home.console_hash_file)
        )
        console.replica_restore_note = {
            "ok": True,
            "message": (
                f"Restored {summary['files']} files: "
                f"{summary['vault_entries']} vault entries and "
                f"{summary['uploads']} uploads."
            ),
        }
        console.audit.record("replica.restored", actor=actor, files=summary["files"])
        return redirect("/backup")

    @app.post("/vault/unlock", response_class=HTMLResponse)
    async def vault_unlock(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        password: Annotated[str, Form()] = "",
        next: Annotated[str, Form()] = "",
    ):
        target = _safe_next(next)
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse(target, status_code=303)
        key = _client_key(request)
        try:
            console.login_limiter.check(f"vault:{key}")
        except RateLimitExceeded as exc:
            return page(request, "vault.html", session=session, status_code=429,
                        entries=[], locked=True,
                        initialized=console.vault.is_initialized(),
                        recovery=console.vault.has_recovery(),
                        error=f"Too many attempts. Try again in {exc.retry_after} seconds.")
        try:
            if not console.vault.is_initialized():
                console.vault.init_vault(password, iterations=console.iterations)
                console.audit.record("vault.init", actor=key)
            else:
                console.vault.unlock(password)
                console.audit.record("vault.unlock", actor=key)
        except VaultError as exc:
            console.login_limiter.register_failure(f"vault:{key}")
            console.audit.record("vault.unlock_failed", actor=key)
            return page(request, "vault.html", session=session, status_code=400,
                        entries=[], locked=True,
                        initialized=console.vault.is_initialized(),
                        recovery=console.vault.has_recovery(), error=str(exc))
        return redirect(target)

    @app.post("/vault/lock", response_class=HTMLResponse)
    async def vault_lock(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if console.csrf_ok(session, csrf_token):
            console.vault.lock()
            console.audit.record("vault.locked", actor=_client_key(request))
        return redirect("/vault")

    @app.post("/vault/entries", response_class=HTMLResponse)
    async def vault_create(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        name: Annotated[str, Form()] = "",
        content: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/vault", status_code=303)
        if not console.vault.unlocked:
            return page(request, "vault.html", session=session, status_code=400,
                        entries=console.vault.list(), locked=True,
                        initialized=console.vault.is_initialized(),
                        recovery=console.vault.has_recovery(),
                        error="Unlock the vault before adding entries.")
        try:
            console.vault.put(name, content.encode("utf-8"))
            console.audit.record("vault.entry_created", actor=_client_key(request), name=name)
        except VaultError as exc:
            return page(request, "vault.html", session=session, status_code=400,
                        entries=console.vault.list(), locked=False,
                        initialized=True, recovery=console.vault.has_recovery(),
                        error=str(exc))
        return redirect("/vault")

    @app.get("/vault/entries/{name}")
    async def vault_download(name: str, session: Session = Depends(require_session)):
        try:
            data = console.vault.get(name)
        except VaultError as exc:
            return HTMLResponse(str(exc), status_code=404)
        console.audit.record("vault.entry_downloaded", actor="operator", name=name)
        return download(data, f"{sanitize_name(name)}.txt")

    @app.post("/vault/entries/{name}/delete", response_class=HTMLResponse)
    async def vault_delete(
        name: str,
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/vault", status_code=303)
        try:
            console.vault.delete(name)
            console.audit.record("vault.entry_deleted", actor=_client_key(request), name=name)
        except VaultError:
            pass
        return redirect("/vault")

    @app.post("/vault/recovery", response_class=HTMLResponse)
    async def vault_recovery(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/vault", status_code=303)
        try:
            code = console.vault.create_recovery(iterations=console.iterations)
        except VaultError as exc:
            return page(request, "vault.html", session=session, status_code=400,
                        entries=console.vault.list(),
                        locked=not console.vault.unlocked,
                        initialized=console.vault.is_initialized(),
                        recovery=console.vault.has_recovery(), error=str(exc))
        console.audit.record("vault.recovery_created", actor=_client_key(request))
        return page(request, "recovery_code.html", session=session, recovery_code=code)

    @app.get("/agents", response_class=HTMLResponse)
    async def agents_view(request: Request, session: Session = Depends(require_session)):
        return page(
            request,
            "agents.html",
            session=session,
            agents=console.agents.list(),
            window=ONLINE_WINDOW_SECONDS,
        )

    @app.post("/agents", response_class=HTMLResponse)
    async def agents_create(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        name: Annotated[str, Form()] = "",
        role: Annotated[str, Form()] = "general",
    ):
        if not console.csrf_ok(session, csrf_token):
            return RedirectResponse("/agents", status_code=303)
        try:
            console.agents.add(name, role)
            console.audit.record("agent.registered", actor=_client_key(request), name=name)
        except AgentError as exc:
            return page(request, "agents.html", session=session, status_code=400,
                        agents=console.agents.list(), window=ONLINE_WINDOW_SECONDS,
                        error=str(exc))
        return redirect("/agents")

    @app.post("/agents/{name}/heartbeat", response_class=HTMLResponse)
    async def agents_heartbeat(
        name: str,
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if console.csrf_ok(session, csrf_token):
            try:
                console.agents.heartbeat(name)
                console.audit.record("agent.heartbeat", actor=_client_key(request), name=name)
            except AgentError:
                pass
        return redirect("/agents")

    @app.post("/agents/{name}/delete", response_class=HTMLResponse)
    async def agents_delete(
        name: str,
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if console.csrf_ok(session, csrf_token):
            try:
                console.agents.remove(name)
                console.audit.record("agent.removed", actor=_client_key(request), name=name)
            except AgentError:
                pass
        return redirect("/agents")

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_view(request: Request, session: Session = Depends(require_session)):
        number = page_number(request)
        entries = console.audit.page(number, AUDIT_PAGE_SIZE)
        # The log is append-only and unbounded, so paging walks backwards from
        # the newest event instead of counting the whole file.
        pagination = {
            "items": entries,
            "page": number,
            "pages": None,
            "total": None,
            "start": (number - 1) * AUDIT_PAGE_SIZE,
            "end": (number - 1) * AUDIT_PAGE_SIZE + len(entries),
            "base": "/audit",
            "has_prev": number > 1,
            "has_next": len(entries) == AUDIT_PAGE_SIZE,
        }
        return page(
            request,
            "audit.html",
            session=session,
            entries=entries,
            pagination=pagination,
        )

    # -- backup / restore ------------------------------------------------
    @app.get("/backup", response_class=HTMLResponse)
    async def backup_view(request: Request, session: Session = Depends(require_session)):
        return page(
            request,
            "backup.html",
            session=session,
            storage=storage_context(),
            backup_limit_mb=MAX_ARCHIVE_BYTES // (1024 * 1024),
        )

    @app.post("/backup/export", response_class=HTMLResponse)
    async def backup_export(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        context = {
            "storage": storage_context(),
            "backup_limit_mb": MAX_ARCHIVE_BYTES // (1024 * 1024),
        }
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "backup.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
                **context,
            )
        try:
            data, filename = create_backup(console.home)
        except (BackupError, OSError) as exc:
            console.audit.record("backup.failed", actor=_client_key(request))
            return page(
                request,
                "backup.html",
                session=session,
                status_code=500,
                error=f"Backup failed: {exc}",
                **context,
            )
        console.audit.record(
            "backup.exported", actor=_client_key(request), bytes=len(data)
        )
        return download(data, filename)

    @app.post("/backup/restore", response_class=HTMLResponse)
    async def backup_restore(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        file: UploadFile | None = None,
    ):
        context = {
            "storage": storage_context(),
            "backup_limit_mb": MAX_ARCHIVE_BYTES // (1024 * 1024),
        }
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "backup.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
                **context,
            )
        if file is None or not file.filename:
            return page(
                request,
                "backup.html",
                session=session,
                status_code=400,
                error="Choose a backup archive to restore.",
                **context,
            )
        buffer = bytearray()
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > MAX_ARCHIVE_BYTES:
                return page(
                    request,
                    "backup.html",
                    session=session,
                    status_code=413,
                    error="That archive is larger than the supported backup size.",
                    **context,
                )
        try:
            summary = restore_backup(console.home, bytes(buffer))
        except (BackupError, OSError) as exc:
            console.audit.record(
                "backup.restore_failed", actor=_client_key(request), reason=str(exc)
            )
            return page(
                request,
                "backup.html",
                session=session,
                status_code=400,
                error=f"Restore rejected: {exc}. Nothing was changed.",
                **context,
            )
        # The restored key material is not the material that was in memory.
        console.vault = Vault(console.home.vault_dir)
        console.agents = AgentRegistry(console.home.agents_file)
        console.audit.record(
            "backup.restored", actor=_client_key(request), files=summary["files"]
        )
        return page(
            request,
            "backup.html",
            session=session,
            notice=(
                f"Restored {summary['files']} files ({summary['vault_entries']} vault "
                f"entries, {summary['uploads']} uploads) from the backup taken "
                f"{summary['created_at']}. The vault is locked again: unlock it with "
                "the password that belongs to that backup."
            ),
            **context,
        )

    # -- collection jobs -------------------------------------------------
    def _jobs_page(
        request: Request, session: Session, **extra: Any
    ) -> HTMLResponse:
        """Render the jobs view with every context key its template needs."""
        return page(
            request,
            "jobs.html",
            session=session,
            jobs=console.dataset.list_jobs(),
            runs=console.dataset.recent_runs(8),
            kinds=COLLECT_KINDS,
            scheduler_on=scheduler_enabled(),
            stats=console.dataset.stats(),
            **extra,
        )

    @app.get("/jobs", response_class=HTMLResponse)
    async def jobs_view(request: Request, session: Session = Depends(require_session)):
        extra: dict[str, Any] = {}
        ran = request.query_params.get("ran", "")
        if ran.isdigit():
            try:
                job = console.dataset.get_job(int(ran))
            except CollectError:
                job = None
            if job is not None:
                if job.get("last_status") == "ok":
                    extra["notice"] = (
                        f"{job['name']} ran and stored {job.get('item_count', 0)} "
                        "record(s) in total."
                    )
                elif job.get("last_status"):
                    extra["error"] = (
                        f"{job['name']} failed: "
                        f"{job.get('last_error') or 'unknown error'}"
                    )
        return _jobs_page(request, session, **extra)

    @app.post("/jobs", response_class=HTMLResponse)
    async def jobs_create(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        name: Annotated[str, Form()] = "",
        kind: Annotated[str, Form()] = "links",
        url: Annotated[str, Form()] = "",
        pattern: Annotated[str, Form()] = "",
        path: Annotated[str, Form()] = "",
        title_field: Annotated[str, Form()] = "title",
        schedule_minutes: Annotated[str, Form()] = "0",
    ):
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "error.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
            )
        try:
            minutes = int(schedule_minutes or 0)
        except (TypeError, ValueError):
            return _jobs_page(
                request,
                session,
                status_code=400,
                error="Schedule must be a whole number of minutes (0 for manual).",
            )
        try:
            job = console.dataset.add_job(
                name,
                kind,
                url,
                pattern=pattern,
                path=path,
                title_field=title_field or "title",
                schedule_minutes=minutes,
            )
        except CollectError as exc:
            return _jobs_page(request, session, status_code=400, error=str(exc))
        console.audit.record("collect.job_created", job=job["name"], kind=job["kind"])
        console.mark_dirty()
        return redirect("/jobs", session=session)

    @app.post("/jobs/{job_id}/run", response_class=HTMLResponse)
    async def jobs_run(
        request: Request,
        job_id: int,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "error.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
            )
        try:
            outcome = run_job(console.dataset, job_id)
        except CollectError as exc:
            return _jobs_page(request, session, status_code=400, error=str(exc))
        console.audit.record(
            "collect.run",
            job=job_id,
            status=outcome["status"],
            added=outcome["added"],
        )
        console.mark_dirty()
        return redirect(f"/jobs?ran={int(job_id)}", session=session)

    @app.post("/jobs/{job_id}/toggle", response_class=HTMLResponse)
    async def jobs_toggle(
        request: Request,
        job_id: int,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "error.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
            )
        try:
            job = console.dataset.get_job(job_id)
            console.dataset.set_enabled(job_id, not job["enabled"])
        except CollectError as exc:
            return _jobs_page(request, session, status_code=400, error=str(exc))
        console.audit.record(
            "collect.job_toggled", job=job_id, enabled=not job["enabled"]
        )
        console.mark_dirty()
        return redirect("/jobs", session=session)

    @app.post("/jobs/{job_id}/delete", response_class=HTMLResponse)
    async def jobs_delete(
        request: Request,
        job_id: int,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
    ):
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "error.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
            )
        try:
            job = console.dataset.get_job(job_id)
        except CollectError as exc:
            return _jobs_page(request, session, status_code=400, error=str(exc))
        console.dataset.delete_job(job_id)
        console.audit.record("collect.job_deleted", job=job["name"])
        console.mark_dirty()
        return redirect("/jobs", session=session)

    # -- collected records ------------------------------------------------
    def _result_filters(request: Request) -> tuple[int | None, str]:
        query = request.query_params.get("q", "").strip()[:200]
        raw_job = request.query_params.get("job", "").strip()
        job_id = int(raw_job) if raw_job.isdigit() else None
        return job_id, query

    def _results_page(
        request: Request, session: Session, **extra: Any
    ) -> HTMLResponse:
        job_id, query = _result_filters(request)
        found = console.dataset.search(
            job_id=job_id,
            query=query,
            page=page_number(request),
            size=25,
        )
        total = int(found["total"])
        start = (found["page"] - 1) * found["size"] + 1 if total else 0
        end = min(total, found["page"] * found["size"])
        return page(
            request,
            "results.html",
            session=session,
            records=found["items"],
            total=total,
            page_no=found["page"],
            pages=found["pages"],
            start=start,
            end=end,
            query=query,
            selected_job=job_id,
            jobs=console.dataset.list_jobs(),
            qs=f"q={quote(query)}&job={job_id or ''}",
            **extra,
        )

    @app.get("/results", response_class=HTMLResponse)
    async def results_view(request: Request, session: Session = Depends(require_session)):
        return _results_page(request, session)

    @app.get("/results/export.csv")
    async def results_export_csv(
        request: Request, session: Session = Depends(require_session)
    ):
        job_id, query = _result_filters(request)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["id", "job", "title", "url", "collected_at", "body"])
        for record in console.dataset.iter_records(job_id=job_id, query=query):
            writer.writerow(
                [
                    record["id"],
                    record["job_name"],
                    record["title"],
                    record["url"],
                    record["collected_at"],
                    record["body"],
                ]
            )
        return RawResponse(
            content=buffer.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="forgecore-results.csv"'
            },
        )

    @app.get("/results/export.json")
    async def results_export_json(
        request: Request, session: Session = Depends(require_session)
    ):
        job_id, query = _result_filters(request)
        records = list(console.dataset.iter_records(job_id=job_id, query=query))
        return RawResponse(
            content=json.dumps(records, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="forgecore-results.json"'
            },
        )

    @app.post("/results/import", response_class=HTMLResponse)
    async def results_import(
        request: Request,
        session: Session = Depends(require_session),
        csrf_token: Annotated[str, Form()] = "",
        file: UploadFile | None = None,
    ):
        if not console.csrf_ok(session, csrf_token):
            return page(
                request,
                "error.html",
                session=session,
                status_code=400,
                error="Invalid form token. Reload the page and try again.",
            )
        if file is None or not file.filename:
            return _results_page(
                request,
                session,
                status_code=400,
                error="Choose a CSV, JSON or text file to import.",
            )
        payload = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(payload) > MAX_UPLOAD_BYTES:
            return _results_page(
                request,
                session,
                status_code=400,
                error=(
                    "File exceeds the "
                    f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit."
                ),
            )
        try:
            summary = ingest_upload(
                console.dataset, sanitize_name(file.filename), payload
            )
        except CollectError as exc:
            return _results_page(request, session, status_code=400, error=str(exc))
        console.audit.record(
            "collect.import", job=summary["job_name"], added=summary["added"]
        )
        console.mark_dirty()
        return redirect(f"/results?job={summary['job_id']}", session=session)

    @app.get("/results/{item_id}", response_class=HTMLResponse)
    async def result_view(
        request: Request,
        item_id: int,
        session: Session = Depends(require_session),
    ):
        try:
            record = console.dataset.get_item(item_id)
        except CollectError:
            return page(
                request,
                "error.html",
                session=session,
                status_code=404,
                error="That record does not exist.",
            )
        return page(request, "result.html", session=session, record=record)

    # -- failure handling ------------------------------------------------
    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404:
            return page(
                request,
                "error.html",
                status_code=404,
                error="That page does not exist.",
            )
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=security_headers(),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        """Never show a stack trace, never lose the page, always log a reference."""
        reference = secrets.token_hex(6)
        print(
            f"[forgecore] unhandled {reference}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        traceback.print_exc()
        try:
            console.audit.record(
                "app.error",
                reference=reference,
                kind=type(exc).__name__,
                path=request.url.path,
            )
        except OSError:  # pragma: no cover - the audit log itself is failing
            pass
        return page(
            request,
            "error.html",
            status_code=500,
            error=(
                f"Something went wrong (reference {reference}). Your stored data was "
                "not modified. Retry the action; quote the reference if it persists."
            ),
        )

    return app
