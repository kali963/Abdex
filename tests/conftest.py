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
os.environ["SEED_DEMO_DATA"] = "true"
os.environ["REQUIRE_2FA_PRIVILEGED"] = "false"

if os.environ["DATABASE_URL"].startswith("postgresql"):
    from alembic import command
    from alembic.config import Config

    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _cfg = Config(os.path.join(_root, "alembic.ini"))
    _cfg.set_main_option("script_location", os.path.join(_root, "alembic"))
    command.downgrade(_cfg, "base")
    command.upgrade(_cfg, "head")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core import ratelimit  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "AbdexDemo2026!"  # noqa: S105 — public demo password, dev only


@pytest.fixture(scope="session")
def client_app():
    with TestClient(app) as c:
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
