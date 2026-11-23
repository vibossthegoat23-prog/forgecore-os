"""Collection engine tests: real HTTP fetch, storage, search, export, schedule.

The fetch tests run against a throwaway HTTP server on the loopback interface, so
the whole path (validate URL, stream body, extract, store, dedupe) is exercised
for real instead of being mocked.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from forgecore import collect  # noqa: E402
from forgecore.collect import (  # noqa: E402
    CollectError,
    Scheduler,
    Store,
    check_url,
    ingest_upload,
    run_job,
)
from forgecore.config import Home  # noqa: E402
from forgecore.web import create_app  # noqa: E402

CONSOLE_PASSWORD = "console-password-123"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')

LINKS_PAGE = b"""<html><head><title>News</title></head><body>
<h1>News</h1>
<a href="/news/one">First story</a>
<a href="/news/two">Second story</a>
<a href="/about">About us</a>
</body></html>"""

JSON_PAGE = json.dumps(
    {
        "data": {
            "items": [
                {"title": "Alpha", "url": "https://e.com/a"},
                {"title": "Beta", "url": "https://e.com/b"},
            ]
        }
    }
).encode()

TEXT_PAGE = b"""<html><head><title>Status</title>
<meta name="description" content="All systems operational"></head>
<body><p>First paragraph.</p><p>Second paragraph.</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        paths = {"/links": LINKS_PAGE, "/json": JSON_PAGE, "/text": TEXT_PAGE}
        body = paths.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(collect.ENV_ALLOW_PRIVATE, "1")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "dataset.db")


# -- URL guard ---------------------------------------------------------
def test_private_address_is_refused_without_opt_in(monkeypatch) -> None:
    monkeypatch.delenv(collect.ENV_ALLOW_PRIVATE, raising=False)
    with pytest.raises(CollectError):
        check_url("http://127.0.0.1:8000/x")


def test_private_address_allowed_with_opt_in(monkeypatch) -> None:
    monkeypatch.setenv(collect.ENV_ALLOW_PRIVATE, "1")
    assert check_url("http://127.0.0.1:8000/x")


def test_bad_scheme_is_refused() -> None:
    with pytest.raises(CollectError):
        check_url("file:///etc/passwd")


def test_embedded_credentials_are_refused() -> None:
    with pytest.raises(CollectError):
        check_url("http://user:pass@example.com/")


# -- jobs --------------------------------------------------------------
def test_links_job_stores_records(store: Store, server: str) -> None:
    job = store.add_job("news", "links", f"{server}/links")
    outcome = run_job(store, job["id"])
    assert outcome["status"] == "ok"
    assert outcome["added"] == 3
    titles = {row["title"] for row in store.search()["items"]}
    assert "First story" in titles


def test_links_pattern_filters(store: Store, server: str) -> None:
    job = store.add_job("filtered", "links", f"{server}/links", pattern="/news/")
    assert run_job(store, job["id"])["added"] == 2


def test_second_run_deduplicates(store: Store, server: str) -> None:
    job = store.add_job("dedupe", "links", f"{server}/links")
    assert run_job(store, job["id"])["added"] == 3
    again = run_job(store, job["id"])
    assert again["status"] == "ok"
    assert again["added"] == 0
    assert store.search()["total"] == 3


def test_json_job_follows_path(store: Store, server: str) -> None:
    job = store.add_job("api", "json", f"{server}/json", path="data.items")
    assert run_job(store, job["id"])["added"] == 2
    assert {row["title"] for row in store.search()["items"]} == {"Alpha", "Beta"}


def test_text_job_captures_title_and_body(store: Store, server: str) -> None:
    job = store.add_job("status", "text", f"{server}/text")
    run_job(store, job["id"])
    record = store.search()["items"][0]
    detail = store.get_item(record["id"])
    assert detail["title"] == "Status"
    assert "First paragraph" in detail["body"]


def test_failed_fetch_is_recorded_not_raised(store: Store, server: str) -> None:
    job = store.add_job("missing", "links", f"{server}/nowhere")
    outcome = run_job(store, job["id"])
    assert outcome["status"] == "error"
    stored = store.get_job(job["id"])
    assert stored["last_status"] == "error"
    assert store.recent_runs(5)[0]["status"] == "error"


def test_job_names_are_validated(store: Store, monkeypatch) -> None:
    # Keep URL validation offline: this test is about the name rules.
    monkeypatch.setenv(collect.ENV_ALLOW_PRIVATE, "1")
    with pytest.raises(CollectError):
        store.add_job("  ", "links", "https://e.com/")
    with pytest.raises(CollectError):
        store.add_job("x" * 80, "links", "https://e.com/")
    store.add_job("dup", "links", "https://e.com/")
    with pytest.raises(CollectError):
        store.add_job("dup", "links", "https://e.com/")


def test_unknown_kind_is_refused(store: Store, monkeypatch) -> None:
    monkeypatch.setenv(collect.ENV_ALLOW_PRIVATE, "1")
    with pytest.raises(CollectError):
        store.add_job("weird", "telepathy", "https://e.com/")


def test_delete_job_removes_its_records(store: Store, server: str) -> None:
    job = store.add_job("temp", "links", f"{server}/links")
    run_job(store, job["id"])
    assert store.search()["total"] == 3
    store.delete_job(job["id"])
    assert store.search()["total"] == 0


# -- search ------------------------------------------------------------
def test_search_filters_by_text_and_job(store: Store, server: str) -> None:
    a = store.add_job("one", "links", f"{server}/links")
    b = store.add_job("two", "json", f"{server}/json", path="data.items")
    run_job(store, a["id"])
    run_job(store, b["id"])

    assert store.search(query="Alpha")["total"] == 1
    assert store.search(job_id=a["id"])["total"] == 3
    assert store.search(job_id=b["id"])["total"] == 2


def test_search_paginates(store: Store, server: str) -> None:
    job = store.add_job("many", "links", f"{server}/links")
    run_job(store, job["id"])
    first = store.search(page=1, size=2)
    assert len(first["items"]) == 2
    assert first["pages"] == 2
    assert first["total"] == 3


# -- imports -----------------------------------------------------------
def test_import_csv(store: Store) -> None:
    payload = b"title,url\nalfa,https://e.com/a\nbeta,https://e.com/b\n"
    summary = ingest_upload(store, "rows.csv", payload)
    assert summary["added"] == 2
    assert store.search(query="alfa")["total"] == 1


def test_import_json(store: Store) -> None:
    payload = json.dumps([{"title": "One"}, {"title": "Two"}]).encode()
    assert ingest_upload(store, "rows.json", payload)["added"] == 2


def test_import_text_lines(store: Store) -> None:
    summary = ingest_upload(store, "notes.txt", b"first line\n\nsecond line\n")
    assert summary["added"] == 2


def test_import_bad_json_reports_error(store: Store) -> None:
    with pytest.raises(CollectError):
        ingest_upload(store, "broken.json", b"{not json")


# -- scheduler ---------------------------------------------------------
def test_scheduler_runs_due_job(store: Store, server: str) -> None:
    job = store.add_job("scheduled", "links", f"{server}/links", schedule_minutes=1)
    assert [row["id"] for row in store.due_jobs()] == [job["id"]]
    scheduler = Scheduler(store, interval=1)
    outcomes = scheduler.tick()
    assert outcomes and outcomes[0]["status"] == "ok"
    assert store.search()["total"] == 3
    assert store.due_jobs() == []


def test_disabled_job_is_not_due(store: Store, server: str) -> None:
    job = store.add_job("paused", "links", f"{server}/links", schedule_minutes=1)
    store.set_enabled(job["id"], False)
    assert store.due_jobs() == []


# -- web console -------------------------------------------------------
@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FORGECORE_CONSOLE_PASSWORD", CONSOLE_PASSWORD)
    monkeypatch.setenv(collect.ENV_ALLOW_PRIVATE, "1")
    home = Home(tmp_path / "home").ensure()
    app = create_app(home)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _csrf(client: TestClient, path: str = "/jobs") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def _login(client: TestClient) -> None:
    response = client.post("/login", data={"password": CONSOLE_PASSWORD})
    assert response.status_code == 303


def _create_job(client: TestClient, token: str, url: str, name: str = "web-news") -> int:
    created = client.post(
        "/jobs",
        data={
            "csrf_token": token,
            "name": name,
            "kind": "links",
            "url": url,
            "schedule_minutes": "0",
        },
    )
    assert created.status_code == 303
    assert created.headers["location"] == "/jobs"
    match = re.search(r'action="/jobs/(\d+)/run"', client.get("/jobs").text)
    assert match, "created job has no run form"
    return int(match.group(1))


def test_jobs_page_needs_login(client: TestClient) -> None:
    response = client.get("/jobs")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_results_page_needs_login(client: TestClient) -> None:
    assert client.get("/results").status_code == 303
    assert client.get("/results/export.csv").status_code == 303


def test_create_and_run_job_via_web(client: TestClient, server: str) -> None:
    _login(client)
    token = _csrf(client)
    job_id = _create_job(client, token, f"{server}/links")
    assert "web-news" in client.get("/jobs").text

    ran = client.post(f"/jobs/{job_id}/run", data={"csrf_token": token})
    assert ran.status_code == 303
    assert "ran and stored" in client.get(ran.headers["location"]).text


def test_job_create_without_csrf_is_refused(client: TestClient, server: str) -> None:
    _login(client)
    response = client.post(
        "/jobs", data={"name": "nocsrf", "kind": "links", "url": f"{server}/links"}
    )
    assert response.status_code == 400
    assert "Invalid form token" in response.text


def test_results_and_exports_via_web(client: TestClient, server: str) -> None:
    _login(client)
    token = _csrf(client)
    job_id = _create_job(client, token, f"{server}/links", name="exportable")
    client.post(f"/jobs/{job_id}/run", data={"csrf_token": token})

    listing = client.get("/results")
    assert "First story" in listing.text

    csv_body = client.get("/results/export.csv")
    assert csv_body.status_code == 200
    assert "text/csv" in csv_body.headers["content-type"]
    assert "First story" in csv_body.text

    json_body = client.get("/results/export.json")
    assert json_body.status_code == 200
    assert len(json_body.json()) == 3


def test_import_via_web(client: TestClient) -> None:
    _login(client)
    token = _csrf(client)
    response = client.post(
        "/results/import",
        data={"csrf_token": token},
        files={"file": ("rows.csv", b"title\nimported\n", "text/csv")},
    )
    assert response.status_code == 303
    assert "imported" in client.get("/results").text


def test_record_detail_and_missing_record(client: TestClient) -> None:
    _login(client)
    token = _csrf(client)
    client.post(
        "/results/import",
        data={"csrf_token": token},
        files={"file": ("rows.json", b'[{"title": "Detail me"}]', "application/json")},
    )
    listing = client.get("/results")
    item_id = re.search(r'href="/results/(\d+)"', listing.text).group(1)
    detail = client.get(f"/results/{item_id}")
    assert detail.status_code == 200
    assert "Detail me" in detail.text
    assert client.get("/results/999999").status_code == 404


def test_delete_job_via_web(client: TestClient, server: str) -> None:
    _login(client)
    token = _csrf(client)
    job_id = _create_job(client, token, f"{server}/links", name="throwaway")
    deleted = client.post(f"/jobs/{job_id}/delete", data={"csrf_token": token})
    assert deleted.status_code == 303
    assert "throwaway" not in client.get("/jobs").text
