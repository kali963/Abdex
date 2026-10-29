"""Test setup: isolated SQLite DB + storage, demo data as fixtures, no background worker.
Tests never call real external systems (INT-GEN-07): all adapters are simulators."""
from __future__ import annotations

import os
import re
import shutil
import tempfile

_tmp = tempfile.mkdtemp(prefix="abdex-test-")
os.environ["APP_ENV"] = "test"
# TEST_DATABASE_URL=postgresql+psycopg://... runs the suite on PostgreSQL through Alembic migrations.
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{_tmp}/test.db"
os.environ["STORAGE_DIR"] = f"{_tmp}/storage"
os.environ["RUN_BACKGROUND_WORKER"] = "false"
os.environ["REQUIRE_2FA_PRIVILEGED"] = "false"

if os.environ["DATABASE_URL"].startswith("postgresql"):
    # Migrations run as the owner in a separate process; the application under test then connects as a
    # plain role, as in production, so append-only triggers and row-level security policies are in force.
    import subprocess
    import sys

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _owner_url = os.environ["DATABASE_URL"]
    for _step in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run([sys.executable, "-m", "alembic", *_step], cwd=_root, check=True,  # noqa: S603
                       env={**os.environ, "DATABASE_URL": _owner_url})
    _app_role, _app_pw = "abdex_app_test", "abdex-app-test-pw"  # noqa: S105 — throwaway role of the test database
    _eng = create_engine(_owner_url)
    with _eng.begin() as _c:
        _c.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_app_role}') THEN "  # noqa: S608 — fixed test role name
                        f"CREATE ROLE {_app_role} LOGIN PASSWORD '{_app_pw}' NOSUPERUSER NOBYPASSRLS; END IF; END $$"))
        _c.execute(text(f"GRANT USAGE ON SCHEMA public TO {_app_role}"))
        _c.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {_app_role}"))
        _c.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {_app_role}"))
    _eng.dispose()
    os.environ["DATABASE_URL"] = make_url(_owner_url).set(username=_app_role, password=_app_pw).render_as_string(
        hide_password=False)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core import ratelimit  # noqa: E402
from app.main import app  # noqa: E402

def seed_test_data() -> None:
    """Test companies, users and deals (tests/demo_data.py) — only in the test database."""
    from app.db import SessionLocal
    from tests.demo_data import seed_demo

    db = SessionLocal()
    try:
        seed_demo(db)
    finally:
        db.close()
    from app.modules.integrations.base import flush_journal

    flush_journal()


PASSWORD = "AbdexDemo2026!"  # noqa: S105 — public demo password, dev only


@pytest.fixture(scope="session")
def client_app():
    with TestClient(app) as c:
        seed_test_data()
        yield c
    shutil.rmtree(_tmp, ignore_errors=True)


@pytest.fixture(autouse=True)
def _reset_limits():
    ratelimit.reset_all()
    yield


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf-token" content="([^"]+)"', html) or re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf token not found"
    return m.group(1)


class Session:
    def __init__(self, login: str):
        self.c = TestClient(app)
        self.c.__enter__()
        page = self.c.get("/login").text
        r = self.c.post("/login", data={"login": login, "password": PASSWORD, "csrf_token": csrf_from(page)},
                        follow_redirects=False)
        assert r.status_code == 303, r.text
        self.csrf = csrf_from(self.c.get("/account").text)

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, data=None, **kw):
        data = dict(data or {})
        data.setdefault("csrf_token", self.csrf)
        kw.setdefault("follow_redirects", False)
        return self.c.post(url, data=data, **kw)


@pytest.fixture
def login(client_app):
    sessions = []

    def _login(who: str) -> Session:
        s = Session(who)
        sessions.append(s)
        return s

    yield _login
    for s in sessions:
        s.c.__exit__(None, None, None)
