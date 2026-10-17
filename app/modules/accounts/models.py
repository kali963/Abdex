"""Users, companies, memberships, sessions, consents (M1, section 5)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db import AppendOnly, AwareDateTime, Encrypted, Model

# Account type (what kind of market participant) ------------------------------------------
COMPANY_CLIENT = "client"
COMPANY_CARRIER = "carrier"

# Roles inside a company (FR-AUTH-02, section 5) ------------------------------------------
ROLE_OWNER = "owner"            # client company owner
ROLE_LOGIST = "logist"
ROLE_ACCOUNTANT = "accountant"
ROLE_FLEET_OWNER = "fleet_owner"
ROLE_DISPATCHER = "dispatcher"
ROLE_DRIVER = "driver"

CLIENT_ROLES = (ROLE_OWNER, ROLE_LOGIST, ROLE_ACCOUNTANT)
CARRIER_ROLES = (ROLE_FLEET_OWNER, ROLE_DISPATCHER, ROLE_DRIVER)
OWNER_ROLES = (ROLE_OWNER, ROLE_FLEET_OWNER)

# Platform staff roles ----------------------------------------------------------------------
STAFF_MANAGER = "manager"
STAFF_MODERATOR = "moderator"
STAFF_FINANCE = "finance"
STAFF_ADMIN = "admin"
STAFF_AUDITOR = "auditor"
STAFF_ROLES = (STAFF_MANAGER, STAFF_MODERATOR, STAFF_FINANCE, STAFF_ADMIN, STAFF_AUDITOR)


class User(Model):
    __tablename__ = "users"

    phone: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    phone_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    locale: Mapped[str] = mapped_column(String(5), default="ru")
    timezone: Mapped[str] = mapped_column(String(40), default="Asia/Almaty")
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)  # blocks TOTP code replay
    sms_2fa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    staff_role: Mapped[str | None] = mapped_column(String(20))
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(AwareDateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    anonymized_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    # FR-AUTH-09: IIN taken from a verified qualified certificate when the user binds the EDS login
    iin: Mapped[str] = mapped_column(Encrypted("users.iin"), default="")  # NFR-DB-08
    iin_index: Mapped[str] = mapped_column(String(40), default="", index=True)
    eds_linked_at: Mapped[datetime | None] = mapped_column(AwareDateTime)

    @validates("iin")
    def _index_iin(self, key, value):
        from app.core.crypto import blind_index

        self.iin_index = blind_index(value, "iin") if value else ""
        return value

    @property
    def is_staff(self) -> bool:
        return bool(self.staff_role)

    @property
    def has_2fa(self) -> bool:
        return bool(self.totp_enabled or self.sms_2fa_enabled)


class Company(Model):
    __tablename__ = "companies"

    kind: Mapped[str] = mapped_column(String(10), index=True)  # client / carrier
    name: Mapped[str] = mapped_column(String(300))
    bin_iin: Mapped[str] = mapped_column(String(12), index=True)
    legal_form: Mapped[str] = mapped_column(String(30), default="ТОО")
    legal_address: Mapped[str] = mapped_column(String(500), default="")
    actual_address: Mapped[str] = mapped_column(String(500), default="")
    vat_payer: Mapped[bool] = mapped_column(Boolean, default=False)
    contact_phone: Mapped[str] = mapped_column(String(20), default="")
    contact_email: Mapped[str] = mapped_column(String(255), default="")
    timezone: Mapped[str] = mapped_column(String(40), default="Asia/Almaty")
    locale: Mapped[str] = mapped_column(String(5), default="ru")
    verification_level: Mapped[int] = mapped_column(Integer, default=0)
    deal_limit_minor: Mapped[int | None] = mapped_column(BigInteger)  # L1 limit (section 8)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    show_finance_to_drivers: Mapped[bool] = mapped_column(Boolean, default=False)  # FR-ACL-03
    is_self_employed_driver: Mapped[bool] = mapped_column(Boolean, default=False)  # FR-AUTH-05
    # L3 (section 8): the company confirmed itself with a qualified certificate issued to its BIN
    eds_confirmed_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    eds_cert_serial: Mapped[str] = mapped_column(String(80), default="")


class Membership(Model):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "company_id", name="uq_membership"),)

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Invitation(Model):
    __tablename__ = "invitations"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    note: Mapped[str] = mapped_column(String(200), default="")
    expires_at: Mapped[datetime] = mapped_column(AwareDateTime)
    used_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    used_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    revoked_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class UserSession(Model):
    """Server-side session; the app process itself stays stateless (NFR-ARC-04)."""

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    active_company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"))
    mfa_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime] = mapped_column(AwareDateTime)
    expires_at: Mapped[datetime] = mapped_column(AwareDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")
    device_id: Mapped[str] = mapped_column(String(64), default="")
    # FR-ADM-05: support works "as the user" only in a separate short session that names the staff member.
    impersonator_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    impersonation_reason: Mapped[str] = mapped_column(String(300), default="")


class OtpCode(Model):
    """One-time codes (SEC-AUT-04). Only a hash is stored."""

    __tablename__ = "otp_codes"

    target: Mapped[str] = mapped_column(String(255), index=True)
    purpose: Mapped[str] = mapped_column(String(40))
    code_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(AwareDateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    context: Mapped[str] = mapped_column(String(100), default="")


class Consent(Model):
    """Separate consents per purpose with text version (SEC-DAT-04)."""

    __tablename__ = "consents"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(30))  # registration, verification, biometrics, geolocation, marketing
    text_version: Mapped[str] = mapped_column(String(20))
    method: Mapped[str] = mapped_column(String(30), default="web_checkbox")
    ip: Mapped[str] = mapped_column(String(64), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class BankAccount(Model):
    """Bank details with two-channel confirmation and cooling-off (FR-AUTH-08, SEC-AUT-10)."""

    __tablename__ = "bank_accounts"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    iban: Mapped[str] = mapped_column(Encrypted("bank_accounts.iban"))  # NFR-DB-08
    iban_index: Mapped[str] = mapped_column(String(40), default="", index=True)
    bank_name: Mapped[str] = mapped_column(String(200), default="")
    bik: Mapped[str] = mapped_column(String(11), default="")
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending / active / superseded
    confirmed_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    effective_at: Mapped[datetime | None] = mapped_column(AwareDateTime)

    @validates("iban")
    def _index_iban(self, key, value):
        from app.core.crypto import blind_index

        self.iban_index = blind_index(value, "iban")
        return value


class AuditLog(AppendOnly, Model):
    """Security & business audit trail (SEC-LOG-01..03). Append-only for every role."""

    __tablename__ = "audit_log"

    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    role: Mapped[str] = mapped_column(String(20), default="")
    action: Mapped[str] = mapped_column(String(60), index=True)
    object_type: Mapped[str] = mapped_column(String(40), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    result: Mapped[str] = mapped_column(String(20), default="ok")
    ip: Mapped[str] = mapped_column(String(64), default="")
    device: Mapped[str] = mapped_column(String(64), default="")
    request_id: Mapped[str] = mapped_column(String(40), default="")
    reason: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[str] = mapped_column(Text, default="{}")


class SupportAccessGrant(Model):
    """FR-ADM-05: the user's consent for support to work in their account for a limited time."""

    __tablename__ = "support_access_grants"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    valid_until: Mapped[datetime] = mapped_column(AwareDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    ticket_number: Mapped[str] = mapped_column(String(30), default="")


class RoleDefinition(Model):
    """FR-ACL-06: roles are data. Built-in roles are seeded; an administrator can add more without a release."""

    __tablename__ = "role_definitions"

    code: Mapped[str] = mapped_column(String(20), unique=True)
    scope: Mapped[str] = mapped_column(String(10))  # client / carrier / staff
    name_ru: Mapped[str] = mapped_column(String(100))
    name_kk: Mapped[str] = mapped_column(String(100), default="")
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)


class RolePermission(Model):
    """FR-ACL-06: the permission matrix stored in the database and edited by an administrator."""

    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role", "permission", name="uq_role_permission"),)

    role: Mapped[str] = mapped_column(String(20), index=True)
    permission: Mapped[str] = mapped_column(String(40))


class EgovSignSession(Model):
    """FR-AUTH-09: one login attempt through eGov mobile (QR + signing in the app, mgovSign protocol).
    Only hashes of the three secrets are stored: the QR token, the app's bearer token and the browser's cookie."""

    __tablename__ = "egov_sign_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    auth_token_hash: Mapped[str] = mapped_column(String(64))
    browser_hash: Mapped[str] = mapped_column(String(64))
    challenge: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(10), default="pending")  # pending / signed / failed / used
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    error: Mapped[str] = mapped_column(String(100), default="")
    expires_at: Mapped[datetime] = mapped_column(AwareDateTime)
