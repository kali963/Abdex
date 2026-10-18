"""Login and document signing through eGov mobile / eGov Business (FR-AUTH-09, FR-DOC-07).

mgovSign protocol of eGov mobile:
1. the browser asks for a login attempt and shows a QR code ``mobileSign:<base>/egov/mgov/<token>``;
2. the eGov mobile app opens that URL and gets a description plus the document URL and a bearer token;
3. it fetches the document (our one-time challenge), the user signs it in the app with the key kept there;
4. it sends the signed CMS back with PUT; the platform verifies it (NCANode in production) and binds the IIN
   from the certificate to the attempt;
5. the browser, which polls with its own cookie secret, gets signed in — the usual second factor still applies.

The IIN must already be bound to an account (security settings → EDS login): eGov mobile is another way to
present the same qualified certificate. Attempts live 5 minutes and succeed once; only hashes of the secrets are
kept (the app's bearer token is derived from the QR token with the server key).
In development a "test phone" in the browser plays the app with the browser's test key.

Document signing (purpose "document") uses the same steps: the app downloads the deal document itself (PDF),
signs it with the user's key (eGov Business: the company key), and the detached CMS is verified exactly like an
NCALayer signature (``documents.sign_qualified``: integrity, chain, validity, OCSP, owner BIN). The attempt is
bound to the user and company that started it, and only their browser learns the result.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, NotFound
from app.db import utcnow
from app.modules.accounts.models import EgovSignSession, User

TTL = timedelta(minutes=5)


def _h(value: str) -> str:
    return hashlib.sha256((value or "").encode()).hexdigest()


def enabled(db: Session) -> bool:
    from app.modules.platform.service import flag_enabled

    return flag_enabled(db, "auth.egov_mobile")


def signing_enabled(db: Session) -> bool:
    from app.modules.platform.service import flag_enabled

    return flag_enabled(db, "eds.egov_mobile")


def start(db: Session, *, document=None, user_id=None, company_id=None) -> tuple[str, str]:
    """Returns (token for the QR link, browser secret for the cookie). With ``document`` the attempt signs that
    deal document on behalf of ``user_id`` / ``company_id`` (checked by the caller)."""
    ratelimit.hit("eds_challenge", get_ctx().ip or "local")
    token, browser = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    purpose = "document" if document is not None else "login"
    challenge = f"AbdEX {purpose} via eGov mobile {utcnow():%Y-%m-%dT%H:%M:%SZ} {secrets.token_hex(16)}"
    db.add(EgovSignSession(token_hash=_h(token), auth_token_hash=_h(_auth_token(token)), browser_hash=_h(browser),
                           challenge=challenge, expires_at=utcnow() + TTL, purpose=purpose,
                           document_id=document.id if document is not None else None,
                           user_id=user_id if document is not None else None, company_id=company_id))
    db.flush()
    return token, browser


def _active(db: Session, s: EgovSignSession) -> bool:
    return signing_enabled(db) if s.purpose == "document" else enabled(db)


def _doc_title(db: Session, s: EgovSignSession) -> tuple[str, str, str]:
    from app.core.i18n import translate
    from app.modules.deals.models import Deal
    from app.modules.documents.models import Document

    doc = db.get(Document, s.document_id)
    deal = db.get(Deal, doc.deal_id) if doc and doc.deal_id else None
    number = deal.number if deal else ""
    out = []
    for loc in ("ru", "kk", "en"):
        kind = translate(f"doc.{doc.doc_type}", locale=loc) if doc else ""
        out.append(f"{kind} · {number}".strip(" ·"))
    return out[0], out[1], out[2]


def _get(db: Session, token: str, *, lock: bool = False) -> EgovSignSession:
    q = select(EgovSignSession).where(EgovSignSession.token_hash == _h(token))
    if lock:
        q = q.with_for_update()
    s = db.execute(q).scalar_one_or_none()
    if s is None or s.expires_at < utcnow():
        raise NotFound()
    return s


def _auth_token(token: str) -> str:
    """The app's bearer token is derived from the QR token with the server key: nothing to store in clear."""
    import hmac

    from app.config import settings

    return hmac.new(settings.secret_key.encode(), f"egov-mgov:{token}".encode(), hashlib.sha256).hexdigest()


def describe(db: Session, token: str, base: str) -> dict:
    """Step 2: what the app shows, where the document is and the bearer token to fetch it."""
    s = _get(db, token)
    if s.status != "pending" or not _active(db, s):
        raise NotFound()
    auth = _auth_token(token)
    if s.purpose == "document":
        ru, kk, en = _doc_title(db, s)
        description = f"Подписание: {ru} / Қол қою: {kk} / Signing: {en}"
    else:
        description = "Вход в AbdEX / AbdEX-ке кіру / Sign in to AbdEX"
    return {"description": description,
            "expiry_date": s.expires_at.isoformat(),
            "organisation": {"nameRu": "AbdEX", "nameKz": "AbdEX", "nameEn": "AbdEX", "bin": ""},
            "document": {"uri": f"{base}/egov/mgov/{token}/document", "auth_type": "Token", "auth_token": auth}}


def _authorize(s: EgovSignSession, authorization: str) -> None:
    raw = (authorization or "").removeprefix("Bearer ").strip()
    if not raw or not secrets.compare_digest(_h(raw), s.auth_token_hash):
        raise NotFound()


def document(db: Session, token: str, authorization: str) -> dict:
    """Step 3: the document to sign — the one-time challenge."""
    s = _get(db, token)
    _authorize(s, authorization)
    if s.status != "pending" or not _active(db, s):
        raise NotFound()
    if s.purpose == "document":
        ru, kk, en = _doc_title(db, s)
        data = base64.b64encode(_document_bytes(db, s)).decode()
        return {"signMethod": "CMS_SIGN_ONLY", "documentsToSign": [{
            "id": 1, "nameRu": ru, "nameKz": kk, "nameEn": en, "meta": [],
            "document": {"file": {"mime": "@file/pdf", "data": data}}}]}
    data = base64.b64encode(s.challenge.encode()).decode()
    return {"signMethod": "CMS_SIGN_ONLY", "documentsToSign": [{
        "id": 1, "nameRu": "Вход в AbdEX", "nameKz": "AbdEX-ке кіру", "nameEn": "Sign in to AbdEX", "meta": [],
        "document": {"file": {"mime": "", "data": data}}}]}


def _document_bytes(db: Session, s: EgovSignSession) -> bytes:
    from app.core.storage import storage
    from app.modules.documents.models import Document, StoredFile

    with _as_initiator(db, s):
        doc = db.get(Document, s.document_id)
        f = db.get(StoredFile, doc.file_id) if doc else None
        if f is None:
            raise NotFound()
        return storage.get(f.storage_key)


class _as_initiator:
    """The app's calls carry no session: the document steps run in the context of the user and company that
    started the attempt, so row-level security and the audit trail see them, not a system bypass."""

    def __init__(self, db: Session, s: EgovSignSession):
        self.db, self.s = db, s

    def __enter__(self):
        from app.core import rls
        from app.modules.accounts.models import Membership

        ctx = get_ctx()
        self.saved = (ctx.user_id, ctx.company_id, ctx.role)
        role = self.db.execute(select(Membership.role).where(Membership.user_id == self.s.user_id,
                                                             Membership.company_id == self.s.company_id,
                                                             Membership.is_active.is_(True))).scalar()
        ctx.user_id, ctx.company_id, ctx.role = self.s.user_id, self.s.company_id, role or ""
        rls.apply(self.db)
        return self

    def __exit__(self, exc_type, *exc):
        from app.core import rls

        if exc_type is None:
            self.db.flush()  # the writes go out while the initiator's company is the RLS context
        ctx = get_ctx()
        ctx.user_id, ctx.company_id, ctx.role = self.saved
        rls.apply(self.db)
        return False


def _package(data_b64: str) -> str:
    """eGov mobile returns a CMS (base64). The development test phone sends the browser test package, which is
    JSON, base64-encoded the same way."""
    try:
        raw = base64.b64decode(data_b64, validate=True)
        text = raw.decode()
        if text.lstrip().startswith("{"):
            json.loads(text)
            return text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return data_b64


def signed(db: Session, token: str, authorization: str, body: dict) -> None:
    """Step 4: the signed document comes back; the signature is verified and the IIN found."""
    from app.core.crypto import blind_index
    from app.modules.documents import eds
    from app.modules.platform.service import get_setting

    s = _get(db, token, lock=True)
    _authorize(s, authorization)
    if s.status != "pending" or not _active(db, s):
        raise NotFound()
    try:
        data_b64 = str(body["documentsToSign"][0]["document"]["file"]["data"])
        if not data_b64 or len(data_b64) > 200_000:
            raise ValueError
    except (KeyError, IndexError, TypeError, ValueError):
        s.status, s.error = "failed", "malformed"
        return
    if s.purpose == "document":
        _sign_document(db, s, _package(data_b64))
        return
    revoked = set(get_setting(db, "eds.revoked_serials", []) or [])
    res = eds.verifier().verify(_package(data_b64), s.challenge.encode(), signed_at=utcnow(), expected_bin="",
                                revoked=revoked)
    checks = {k: v for k, v in res.checks.items() if k != "owner"}
    iin = str(res.signer.get("iin", ""))
    if not checks or not all(checks.values()) or len(iin) != 12:
        s.status, s.error = "failed", ",".join(k for k, v in checks.items() if not v)[:100] or "invalid"
        audit(db, "auth.egov_rejected", object_type="user", object_id="", result="denied", details={"checks": checks})
        return
    user = db.execute(select(User).where(User.iin_index == blind_index(iin, "iin"), User.is_deleted.is_(False))
                      ).scalar_one_or_none()
    if user is None or not user.eds_linked_at or user.is_blocked:
        s.status, s.error = "failed", "not_linked"
        audit(db, "auth.login_failed", object_type="user", object_id="", result="denied", details={"method": "egov"})
        return
    s.status, s.user_id = "signed", user.id


def poll(db: Session, token: str, browser_secret: str) -> tuple[str, User | None]:
    """Step 5: the browser that started the attempt (and only it) learns the result; a success is used once."""
    s = _get(db, token, lock=True)
    if s.purpose != "login" or not browser_secret or not secrets.compare_digest(_h(browser_secret), s.browser_hash):
        raise NotFound()
    if s.status == "signed":
        s.status = "used"
        user = db.get(User, s.user_id)
        audit(db, "auth.login_egov", object_type="user", object_id=user.id, user_id=user.id)
        return "signed", user
    if s.status == "failed":
        raise AppError("eds_not_linked" if s.error == "not_linked" else "eds_invalid", status_code=422,
                       checks=s.error)
    return s.status, None


def _sign_document(db: Session, s: EgovSignSession, package: str) -> None:
    """The same server-side verification as an NCALayer signature; a failure is reported to the browser."""
    from app.modules.accounts.models import Company
    from app.modules.deals import service as deals
    from app.modules.deals.models import Deal
    from app.modules.documents import service as documents
    from app.modules.documents.models import Document

    with _as_initiator(db, s):
        doc = db.get(Document, s.document_id)
        user, company = db.get(User, s.user_id), db.get(Company, s.company_id)
        from app.modules.accounts.permissions import company_can

        # rights are re-checked at signing time: a membership removed after the QR was shown does not sign
        if (doc is None or user is None or company is None or user.is_blocked or company.is_blocked
                or not company_can(get_ctx().role, "deal.sign")):
            s.status, s.error = "failed", "invalid"
            return
        try:
            # a refused signature writes nothing but its audit entry (raised before the signature is stored)
            documents.sign_qualified(db, doc, user=user, company=company, package=package)
            deals.on_document_signed(db, db.get(Deal, doc.deal_id))
        except AppError as exc:
            s.status, s.error = "failed", f"{exc.code}:{exc.params.get('checks', '')}"[:100]
            return
    s.status = "signed"


def poll_document(db: Session, token: str, browser_secret: str, *, user_id, document_id) -> str:
    """The browser and user that started a document attempt learn its result (once)."""
    s = _get(db, token, lock=True)
    if (s.purpose != "document" or s.user_id != user_id or s.document_id != document_id or not browser_secret
            or not secrets.compare_digest(_h(browser_secret), s.browser_hash)):
        raise NotFound()
    if s.status == "signed":
        s.status = "used"
        return "signed"
    if s.status == "failed":
        code, sep, checks = s.error.partition(":")
        if not sep:  # malformed answer from the app, rights lost
            code, checks = "eds_invalid", s.error
        raise AppError(code, status_code=422, checks=checks)
    return s.status
