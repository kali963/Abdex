"""Operations for the production server: security journal archive (SEC-LOG-04), admin network allowlist
(SEC-AZ-06), secrets from files (GOV-R-07), shared metrics and operations gauges (NFR-OBS-01), request tracing,
integration quotas (GOV-R-05), automatic re-check of deferred registry checks (GOV-R-08)."""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import func, select

from app.config import settings
from app.db import SessionLocal


def _set(monkeypatch, name, value):
    """settings is a frozen dataclass: patch a field for one test, restored afterwards."""
    old = getattr(settings, name)
    object.__setattr__(settings, name, value)
    monkeypatch.undo_stack = getattr(monkeypatch, "undo_stack", [])
    monkeypatch.undo_stack.append((name, old))


@pytest.fixture(autouse=True)
def _restore_settings(monkeypatch):
    yield
    for name, old in reversed(getattr(monkeypatch, "undo_stack", [])):
        object.__setattr__(settings, name, old)


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def archive(tmp_path, monkeypatch, db):
    """An empty archive directory and a reset cursor: the whole journal is exported from the start."""
    from app.core import audit_archive
    from app.modules.platform.service import set_setting

    monkeypatch.setenv("AUDIT_ARCHIVE_DIR", str(tmp_path / "archive"))
    set_setting(db, audit_archive.CURSOR, {})
    db.commit()
    yield tmp_path / "archive"
    set_setting(db, audit_archive.CURSOR, {})
    db.commit()


def _export_all(db) -> int:
    from app.core.audit_archive import export

    total = 0
    while True:
        n = export(db)
        db.commit()
        total += n
        if not n:
            return total


def test_audit_archive_export_verify_and_tamper(db, archive):
    from app.core.audit import audit
    from app.core.audit_archive import verify
    from app.modules.accounts.models import AuditLog

    exported = _export_all(db)
    assert exported == db.execute(select(func.count(AuditLog.id))).scalar_one() > 0
    res = verify(db)
    assert res["ok"], res["problems"]
    assert res["records"] == exported

    audit(db, "test.archive_event", object_type="platform", object_id="archive")
    db.commit()
    assert _export_all(db) == 1
    assert verify(db)["ok"]
    files = sorted(archive.rglob("audit-*.jsonl"))
    assert files and all(oct(f.stat().st_mode)[-3:] == "640" for f in files)

    # changing one record anywhere breaks the chain
    last = files[-1]
    original = last.read_text(encoding="utf-8")
    lines = original.splitlines()
    item = json.loads(lines[-1])
    item["rec"]["action"] = "test.forged"
    lines[-1] = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    last.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = verify(db)
    assert not res["ok"] and "chain broken" in res["problems"][0]
    last.write_text(original, encoding="utf-8")
    assert verify(db)["ok"]

    # lines beyond the committed cursor (a run that crashed before its commit) are set aside, never deleted
    with open(last, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"rec": {"id": "x"}, "mac": "0" * 64}) + "\n")
    audit(db, "test.archive_event2", object_type="platform", object_id="archive")
    db.commit()
    assert _export_all(db) == 1
    assert verify(db)["ok"]
    assert list((archive / "orphaned").glob("orphan-*"))

    # a removed file: the archive no longer ends at the cursor — export stops, verification reports it
    for f in sorted(archive.rglob("audit-*.jsonl")):
        f.unlink()
    audit(db, "test.archive_event3", object_type="platform", object_id="archive")
    db.commit()
    from app.core.audit_archive import export

    assert export(db) == 0
    res = verify(db)
    assert not res["ok"]


def test_audit_verify_cli(db, archive, capsys):
    from app import cli

    assert cli.main(["audit-verify"]) == 0
    assert "archive intact" in capsys.readouterr().out


def test_admin_network_allowlist(login, monkeypatch):
    from app.web.routes_admin import admin_network_allowed

    _set(monkeypatch, "admin_networks", "10.0.0.0/8, 192.168.1.0/24, bad-entry")
    assert admin_network_allowed("10.1.2.3")
    assert admin_network_allowed("192.168.1.77")
    assert not admin_network_allowed("192.168.2.1")
    assert not admin_network_allowed("not-an-ip")
    admin = login("admin@abdex.kz")
    assert admin.c.get("/admin", follow_redirects=False).status_code == 404  # the test client is not in the list
    _set(monkeypatch, "admin_networks", "")
    assert admin_network_allowed("203.0.113.5")
    assert admin.c.get("/admin", follow_redirects=False).status_code == 200


def test_secrets_from_files(tmp_path, monkeypatch):
    from app.core import secrets as sec

    monkeypatch.setattr(sec, "SECRETS_DIR", tmp_path)
    monkeypatch.setenv("ABDEX_T_TOKEN", "from-env")
    assert sec.secret("ABDEX_T_TOKEN") == "from-env"
    (tmp_path / "abdex_t_token").write_text("", encoding="utf-8")
    assert sec.secret("ABDEX_T_TOKEN") == "from-env"  # an empty placeholder file falls through
    (tmp_path / "abdex_t_token").write_text("from-docker-secret\n", encoding="utf-8")
    assert sec.secret("ABDEX_T_TOKEN") == "from-docker-secret"
    explicit = tmp_path / "vault.txt"
    explicit.write_text("from-file-var", encoding="utf-8")
    monkeypatch.setenv("ABDEX_T_TOKEN_FILE", str(explicit))
    assert sec.secret("ABDEX_T_TOKEN") == "from-file-var"
    assert sec.has("ABDEX_T_TOKEN") and not sec.has("ABDEX_T_MISSING")


def test_metrics_with_operations_gauges(client_app, db, tmp_path, monkeypatch):
    from app.modules.platform.service import set_setting

    _set(monkeypatch, "metrics_token", "test-metrics-token")
    status = tmp_path / "last_success"
    status.write_text("1700000000\n", encoding="utf-8")
    monkeypatch.setenv("BACKUP_STATUS_FILE", str(status))
    set_setting(db, "worker.heartbeat", 1700000123.5)
    db.commit()
    assert client_app.get("/metrics").status_code == 404
    client_app.get("/")
    r = client_app.get("/metrics", headers={"Authorization": "Bearer test-metrics-token"})
    assert r.status_code == 200
    body = r.text
    assert 'abdex_http_requests_total{method="GET",status="2xx"}' in body
    assert "abdex_backup_last_success_timestamp 1700000000.0" in body
    assert "abdex_worker_last_tick_timestamp 1700000123.5" in body
    assert 'abdex_orders{status="' in body  # every company's orders, past row-level security
    if db.get_bind().dialect.name == "postgresql":
        assert "abdex_clock_skew_seconds" in body


def test_worker_writes_heartbeat(client_app, db):
    from app.modules.platform.service import get_setting
    from app.worker import _heartbeat

    before = time.time()
    _heartbeat(db)
    db.commit()
    assert float(get_setting(db, "worker.heartbeat")) >= before


def test_trace_context(client_app):
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    r = client_app.get("/", headers={"traceparent": f"00-{trace}-00f067aa0ba902b7-01"})
    assert r.headers["traceresponse"].startswith(f"00-{trace}-")
    r = client_app.get("/", headers={"traceparent": "00-" + "0" * 32 + "-00f067aa0ba902b7-01"})  # invalid id
    assert trace not in r.headers["traceresponse"] and len(r.headers["traceresponse"]) == 55


def test_outgoing_calls_carry_the_trace(client_app):
    from app.core import tracing
    from app.core.context import RequestContext, reset_ctx, set_ctx

    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.update({k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    tracing.install()
    tok = set_ctx(RequestContext(request_id="req-1", trace_id="ab" * 16))
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_port}/", timeout=5) as resp:  # noqa: S310 — local test server
            assert resp.read() == b"ok"
    finally:
        reset_ctx(tok)
        srv.server_close()
    assert seen["traceparent"].startswith("00-" + "ab" * 16 + "-")
    assert seen["x-request-id"] == "req-1"


def test_integration_daily_quota(client_app, monkeypatch):
    from app.modules.integrations import base

    class QuotaAdapter(base.Adapter):
        name = "quota-test"
        retries = 0

    monkeypatch.setattr(base, "_quota_cache", (time.monotonic(), {"quota-test": 2}))
    monkeypatch.setattr(base, "_quota_local", {})
    a = QuotaAdapter()
    assert a.call("op", lambda: 1) == 1
    assert a.call("op", lambda: 2) == 2
    with pytest.raises(base.IntegrationUnavailable):
        a.call("op", lambda: 3)
    base.flush_journal()


def test_deferred_registry_check_is_repeated(client_app, db, monkeypatch):
    from app.modules.accounts.models import Company
    from app.modules.fleet import service
    from app.modules.fleet.models import RegistryCheck

    monkeypatch.setattr(service, "RECHECK_AFTER", timedelta(0))

    company = db.execute(select(Company).where(Company.kind == "carrier", Company.is_blocked.is_(False))
                         .order_by(Company.created_at)).scalars().first()
    db.add(RegistryCheck(subject_type="company", subject_key=company.bin_iin, company_id=company.id,
                         source="test", basis="user_action", status="unavailable", result="{}"))
    db.commit()
    assert service.recheck_deferred(db, limit=1000) >= 1
    db.commit()
    from app.modules.integrations.base import flush_journal

    flush_journal()
    latest = db.execute(select(RegistryCheck).where(RegistryCheck.company_id == company.id)
                        .order_by(RegistryCheck.created_at.desc())).scalars().first()
    assert latest.status != "unavailable" and latest.basis == "scheduled"


def test_preflight_checks_the_clock(client_app, db):
    from app.core.preflight import OK, _check_clock

    items = _check_clock(db)
    if db.get_bind().dialect.name == "postgresql":
        assert items and items[0].level == OK
    else:
        assert items == []


def test_sms_outage_is_not_an_internal_error(client_app, monkeypatch):
    """GOV-R-08 / INT-GEN-03: an external service that is down gives "try again later", the form is kept."""
    from app.modules.accounts import service as accounts
    from app.modules.integrations.base import IntegrationUnavailable
    from tests.demo_data import make_bin
    from tests.conftest import csrf_from

    def down(*a, **k):
        raise IntegrationUnavailable("sms")

    monkeypatch.setattr(accounts, "send_otp", down)
    page = client_app.get("/register?type=client").text
    r = client_app.post("/register", data={
        "csrf_token": csrf_from(page), "account_type": "client", "full_name": "Тест Отказов", "phone": "+77029990011",
        "email": "outage@example.kz", "password": "Outage-Test-2026!x", "company_name": "ТОО Отказ",
        "bin_iin": make_bin("99031045671"), "consent_registration": "on"})
    assert r.status_code == 503, r.text[-500:]
    assert "Тест Отказов" in r.text and "временно недоступен" in r.text  # the form is kept, with the reason


def test_log_lines_carry_request_and_trace_ids(client_app):
    import logging

    from app.core.logsetup import JsonFormatter

    lines = []

    class Grab(logging.Handler):
        def emit(self, record):
            lines.append(json.loads(JsonFormatter().format(record)))

    h = Grab()
    logging.getLogger("abdex.http").addHandler(h)
    try:
        trace = "5bf92f3577b34da6a3ce929d0e0e4736"
        client_app.get("/", headers={"traceparent": f"00-{trace}-00f067aa0ba902b7-01", "X-Request-ID": "req-log-1"})
    finally:
        logging.getLogger("abdex.http").removeHandler(h)
    assert any(x["trace_id"] == trace and x["request_id"] == "req-log-1" for x in lines), lines


def test_caches_reload_right_after_boot(client_app, monkeypatch):
    """time.monotonic() starts near zero at boot: an invalidated cache must still be reloaded then (a reset to
    0.0 counted as "fresh" during the first minute — CI runners showed it as a flaky test)."""
    import time as _time

    from app.modules.accounts import permissions
    from app.modules.platform import processing

    monkeypatch.setattr(_time, "monotonic", lambda: 5.0)  # five seconds after boot
    monkeypatch.setitem(processing._cache, "adapters", {"stale-adapter"})
    monkeypatch.setitem(processing._cache, "at", 4.0)
    processing.invalidate()
    assert "stale-adapter" not in processing.registered_adapters()
    monkeypatch.setitem(permissions._cache, "perms", {"stale": set()})
    monkeypatch.setitem(permissions._cache, "at", 4.0)
    permissions.invalidate()
    assert "stale" not in permissions._load()["perms"]
    processing.invalidate()
    permissions.invalidate()
