"""The first accounts of a new installation come from the server settings; there are no demo accounts."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db import SessionLocal


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _env(monkeypatch, **values):
    for k, v in values.items():
        monkeypatch.setenv(k, v)


def test_admin_and_user_created_once(db, monkeypatch):
    from app.core.security import verify_password
    from app.modules.accounts.initial import ensure_initial_accounts
    from app.modules.accounts.models import Company, Membership, User
    from app.modules.accounts.service import make_bin

    _env(monkeypatch, INITIAL_ADMIN_PHONE="+7 705 111 22 33", INITIAL_ADMIN_NAME="Главный Администратор",
         INITIAL_ADMIN_EMAIL="Chief@abdex.kz", INITIAL_ADMIN_PASSWORD="Real-Admin-Pass-2026!",  # noqa: S106 — test values
         INITIAL_USER_PHONE="+77051112244", INITIAL_USER_NAME="Первый Клиент", INITIAL_USER_PASSWORD="First-User-Pass-2026!",  # noqa: S106
         INITIAL_USER_COMPANY="ТОО Первый Клиент", INITIAL_USER_BIN=make_bin("20051112244"), INITIAL_USER_TYPE="client")
    assert ensure_initial_accounts(db) == 2
    admin = db.execute(select(User).where(User.phone == "+77051112233")).scalar_one()
    assert admin.staff_role == "admin" and admin.email == "chief@abdex.kz" and admin.phone_verified
    assert verify_password(admin.password_hash, "Real-Admin-Pass-2026!")
    user = db.execute(select(User).where(User.phone == "+77051112244")).scalar_one()
    assert user.staff_role is None
    m = db.execute(select(Membership).where(Membership.user_id == user.id)).scalar_one()
    company = db.get(Company, m.company_id)
    assert m.role == "owner" and company.kind == "client" and company.name == "ТОО Первый Клиент"

    # later starts never touch the accounts again (a changed password stays changed)
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "Another-Pass-2026-xyz!")
    assert ensure_initial_accounts(db) == 0
    db.refresh(admin)
    assert verify_password(admin.password_hash, "Real-Admin-Pass-2026!")


def test_nothing_without_settings_and_weak_passwords_refused(db, monkeypatch):
    from app.modules.accounts.initial import ensure_initial_accounts
    from app.modules.accounts.models import User

    for k in ("INITIAL_ADMIN_PHONE", "INITIAL_USER_PHONE"):
        monkeypatch.delenv(k, raising=False)
    assert ensure_initial_accounts(db) == 0
    _env(monkeypatch, INITIAL_ADMIN_PHONE="+77051113355", INITIAL_ADMIN_NAME="Админ", INITIAL_ADMIN_PASSWORD="short")  # noqa: S106
    assert ensure_initial_accounts(db) == 0
    assert db.execute(select(User.id).where(User.phone == "+77051113355")).first() is None


def test_existing_user_is_not_promoted(db, monkeypatch):
    from app.modules.accounts.initial import ensure_initial_accounts
    from app.modules.accounts.models import User

    existing = db.execute(select(User).where(User.staff_role.is_(None))).scalars().first()
    _env(monkeypatch, INITIAL_ADMIN_PHONE=existing.phone, INITIAL_ADMIN_NAME="Чужой",
         INITIAL_ADMIN_PASSWORD="Takeover-Attempt-2026!")  # noqa: S106
    monkeypatch.delenv("INITIAL_USER_PHONE", raising=False)
    assert ensure_initial_accounts(db) == 0
    db.refresh(existing)
    assert existing.staff_role is None


def test_login_page_has_no_demo_accounts(client_app):
    page = client_app.get("/login").text
    assert "AbdexDemo2026" not in page and "admin@abdex.kz" not in page
    assert "Vercel" not in client_app.get("/").text


def test_dev_secret_key_is_shared_between_processes(tmp_path):
    """Without SECRET_KEY every process of a development install uses the same key (no random logouts)."""
    from app.config import _dev_secret_key

    first = _dev_secret_key(tmp_path / "storage")
    assert len(first) > 40
    assert _dev_secret_key(tmp_path / "storage") == first  # a second process reads the same key
    assert oct((tmp_path / "storage" / ".dev-secret-key").stat().st_mode)[-3:] == "600"
