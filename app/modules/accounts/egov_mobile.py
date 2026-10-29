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
from app.modules.integrations.base import Adapter, IntegrationUnavailable

TTL = timedelta(minutes=5)


def _h(value: str) -> str:
    return hashlib.sha256((value or "").encode()).hexdigest()


def enabled(db: Session) -> bool:
    from app.modules.platform.service import flag_enabled

    return flag_enabled(db, "auth.egov_mobile")


def signing_enabled(db: Session) -> bool:
    from app.modules.platform.service import flag_enabled

    return flag_enabled(db, "eds.egov_mobile")


def provider() -> str:
    """``EGOV_PROVIDER``: "direct" — the platform's own mgovSign endpoints (needs the Smart Bridge registration
    of the QR-signing service); "sigex" — through the SIGEX QR-signing API (no Smart Bridge registration; the
    signature still comes back to us and is verified by NCANode like any other)."""
    import os

    name = os.getenv("EGOV_PROVIDER", "direct").strip().lower()
    return name if name in ("direct", "sigex") else "direct"


def start(db: Session, *, document=None, user_id=None, company_id=None, base: str = "",
          link_user_id=None) -> tuple[str, str, dict]:
    """Returns (token, browser secret for the cookie, what the browser shows: QR image, QR text, deep links).
    With ``document`` the attempt signs that deal document on behalf of ``user_id`` / ``company_id`` (checked by
    the caller). With ``link_user_id`` the signed certificate is bound to that (signed-in) user for EDS login.
    For SIGEX the returned ``launch`` callable must be called after the commit."""
    ratelimit.hit("eds_challenge", get_ctx().ip or "local")
    token, browser = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    purpose = "document" if document is not None else ("link" if link_user_id is not None else "login")
    challenge = f"AbdEX {purpose} via eGov mobile {utcnow():%Y-%m-%dT%H:%M:%SZ} {secrets.token_hex(16)}"
    s = EgovSignSession(token_hash=_h(token), auth_token_hash=_h(_auth_token(token)), browser_hash=_h(browser),
                        challenge=challenge, expires_at=utcnow() + TTL, purpose=purpose,
                        document_id=document.id if document is not None else None,
                        user_id=user_id if document is not None else link_user_id, company_id=company_id)
    db.add(s)
    db.flush()
    if provider() == "sigex":
        return token, browser, _sigex_start(db, s)
    lk = links(base, token)
    return token, browser, {"qr_text": lk["qr"], "deeplinks": lk["deeplinks"]}


def for_browser(token: str, show: dict, status_url: str, *, scale: int = 4) -> dict:
    """What the page needs: the QR image, the deep links and where to poll."""
    import segno

    if show.get("qr_png"):
        qr = "data:image/png;base64," + show["qr_png"]
    else:
        qr = segno.make(show["qr_text"], error="m").svg_data_uri(scale=scale, border=2)
    return {"token": token, "link": show.get("qr_text", ""), "qr": qr, "deeplinks": show.get("deeplinks", {}),
            "status": status_url}


def start_safely(db: Session, **kwargs) -> tuple[str, str, dict]:
    """``start`` with an outage of the signing operator turned into a clear message."""
    try:
        return start(db, **kwargs)
    except IntegrationUnavailable as exc:
        db.rollback()
        raise AppError("egov_unavailable", status_code=503) from exc


# ------------------------------------------------------------------ SIGEX QR-signing API


def _sigex_base() -> str:
    import os

    return os.getenv("SIGEX_URL", "https://sigex.kz").rstrip("/")


class SigexAdapter(Adapter):
    """SIGEX QR signing (https://sigex.kz, reference client sigex-qr-signing-client): register the procedure,
    hand the data over (the call returns once eGov mobile has fetched it), wait for the signatures."""

    name = "sigex"
    personal_data = True  # the signed document goes to the operator: processing register record "egov_sign"
    timeout = 30.0
    retries = 1

    def _http(self, method: str, url: str, body: dict | None, timeout: float) -> dict:
        import urllib.request

        if not url.startswith(_sigex_base() + "/"):
            raise RuntimeError("unexpected SIGEX url")  # only addresses of the configured service are called
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,  # noqa: S310 — checked above
                                     headers={"Content-Type": "application/json"}, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — configured https service
            return json.loads(resp.read(2_000_000) or b"{}")

    def register(self, description: str) -> dict:
        out = self.call("register", lambda: self._http("POST", f"{_sigex_base()}/api/egovQr",
                                                       {"description": description[:500]}, self.timeout),
                        summary="egovQr")
        if out.get("message") or not out.get("dataURL") or not out.get("signURL"):
            raise IntegrationUnavailable(f"sigex: {str(out.get('message', 'no urls'))[:100]}")
        return out

    def exchange(self, reg: dict, documents: list, wait: float) -> dict:
        """Blocking: send the data (returns when the app took it), then wait for the signatures."""
        sent = self._http("POST", reg["dataURL"], {"signMethod": "CMS_SIGN_ONLY", "version": 1,
                                                   "documentsToSign": documents}, wait)
        if sent.get("message"):
            return {"error": str(sent["message"])[:100]}
        return self._http("GET", reg["signURL"], None, wait)


sigex = None


def _sigex():
    global sigex
    if sigex is None:
        sigex = SigexAdapter()
    return sigex


def _to_sign(db: Session, s: EgovSignSession) -> list:
    """The documents for the app, in the mgovSign format (the same for SIGEX and our own API №2)."""
    if s.purpose == "document":
        ru, kk, en = _doc_title(db, s)
        data, mime = base64.b64encode(_document_bytes(db, s)).decode(), "@file/pdf"
    else:
        ru, kk, en = "Вход в AbdEX", "AbdEX-ке кіру", "Sign in to AbdEX"
        data, mime = base64.b64encode(s.challenge.encode()).decode(), ""
    return [{"id": 1, "nameRu": ru, "nameKz": kk, "nameEn": en, "meta": [], "document": {"file": {"mime": mime,
                                                                                              "data": data}}}]


def _description(db: Session, s: EgovSignSession) -> str:
    if s.purpose == "document":
        ru, kk, en = _doc_title(db, s)
        return f"Подписание: {ru} / Қол қою: {kk} / Signing: {en}"
    return "Вход в AbdEX / AbdEX-ке кіру / Sign in to AbdEX"


def _sigex_start(db: Session, s: EgovSignSession) -> dict:
    import threading

    import re

    reg = _sigex().register(_description(db, s))
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", str(reg.get("qrCode", ""))):  # a PNG in base64, nothing else
        raise IntegrationUnavailable("sigex: no QR image")
    for key in ("eGovMobileLaunchLink", "eGovBusinessLaunchLink"):  # only the eGov launcher, never another site
        if reg.get(key) and not str(reg[key]).startswith("https://m.egov.kz/"):
            reg[key] = None
    documents = _to_sign(db, s)
    session_id, wait = s.id, TTL.total_seconds() + 15

    def launch():
        threading.Thread(target=_sigex_wait, args=(session_id, reg, documents, wait), daemon=True,
                         name=f"sigex-{session_id}").start()

    return {"qr_png": reg.get("qrCode", ""), "deeplinks": {k: v for k, v in (
        ("mgov", reg.get("eGovMobileLaunchLink")), ("business", reg.get("eGovBusinessLaunchLink"))) if v},
        "launch": launch}


def _sigex_wait(session_id, reg: dict, documents: list, wait: float) -> None:
    """Background: wait for the user to sign in the app, then verify exactly as with our own endpoints."""
    import logging

    from app.core.context import RequestContext, reset_ctx, set_ctx
    from app.db import SessionLocal

    try:
        out = _sigex().exchange(reg, documents, wait)
    except Exception as exc:  # noqa: BLE001 — timeouts, network: the attempt simply fails
        logging.getLogger("abdex.integrations").warning("sigex exchange failed: %s", type(exc).__name__)
        out = {"error": "unavailable"}
    tok = set_ctx(RequestContext(request_id=f"sigex-{session_id.hex}"))
    db = SessionLocal()
    try:
        s = db.execute(select(EgovSignSession).where(EgovSignSession.id == session_id).with_for_update()
                       ).scalar_one_or_none()
        if s is None or s.status != "pending" or s.expires_at < utcnow():
            return
        if out.get("status") == "CANCELED":
            s.status, s.error = "failed", "cancelled"
        elif out.get("error") or out.get("message"):
            s.status, s.error = "failed", "egov_unavailable"
        else:
            try:
                data_b64 = str(out["documentsToSign"][0]["document"]["file"]["data"])
            except (KeyError, IndexError, TypeError):
                s.status, s.error = "failed", "malformed"
            else:
                _complete(db, s, data_b64)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logging.getLogger("abdex.integrations").exception("sigex result not processed")
    finally:
        db.close()
        reset_ctx(tok)


# Cross-signing on the same phone: the "API №1" address handed to the eGov launcher. The format is the one the
# apps accept today (as issued by SIGEX for eGov mobile / eGov Business: the old *.page.link dynamic links of
# the Smart Bridge documentation stopped working with Firebase Dynamic Links in 2025). Configurable in case it
# changes again; {link} is the API №1 address with the "?mgovSign" marker.
DEEPLINKS = {
    "mgov": ("EGOV_DEEPLINK_MGOV", "https://m.egov.kz/mobileSign/?link={link}"),
    "business": ("EGOV_DEEPLINK_BUSINESS", "https://m.egov.kz/businessSign/?link={link}"),
}


def links(base: str, token: str) -> dict:
    """QR content (``mobileSign:`` + API №1) and the deep links for signing on the same phone."""
    import os

    api1 = f"{base}/egov/mgov/{token}"
    out = {"api": api1, "qr": f"mobileSign:{api1}", "deeplinks": {}}
    for name, (env, default) in DEEPLINKS.items():
        template = os.getenv(env, default)
        if template and "{link}" in template:
            out["deeplinks"][name] = template.replace("{link}", f"{api1}?mgovSign")
    return out


def _organisation() -> dict:
    import os

    name = os.getenv("EGOV_ORG_NAME", "AbdEX")
    return {"nameRu": name, "nameKz": name, "nameEn": name, "bin": os.getenv("EGOV_ORG_BIN", "")}


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
    return {"description": _description(db, s),
            "expiry_date": s.expires_at.isoformat(),
            "organisation": _organisation(),
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
    return {"signMethod": "CMS_SIGN_ONLY", "documentsToSign": _to_sign(db, s)}


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
    _complete(db, s, data_b64)


def _complete(db: Session, s: EgovSignSession, data_b64: str) -> None:
    """The signature is back (from the app or from SIGEX): verify it and record the outcome on the attempt."""
    from app.core.crypto import blind_index
    from app.modules.documents import eds
    from app.modules.platform.service import get_setting

    if not data_b64 or len(data_b64) > 200_000:
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
        audit(db, "auth.egov_rejected", object_type="user", object_id="", result="denied",
              details={"checks": checks, "error": res.error})
        return
    if s.purpose == "link":
        _link(db, s, iin, res.signer)
        return
    user = db.execute(select(User).where(User.iin_index == blind_index(iin, "iin"), User.is_deleted.is_(False))
                      ).scalar_one_or_none()
    if user is None or not user.eds_linked_at or user.is_blocked:
        s.status, s.error = "failed", "not_linked"
        audit(db, "auth.login_failed", object_type="user", object_id="", result="denied", details={"method": "egov"})
        return
    s.status, s.user_id = "signed", user.id


def _link(db: Session, s: EgovSignSession, iin: str, signer: dict) -> None:
    """Binding the certificate's IIN to the user who started the attempt (security settings)."""
    from app.core.crypto import blind_index

    user = db.get(User, s.user_id)
    if user is None or user.is_deleted or user.is_blocked:
        s.status, s.error = "failed", "invalid"
        return
    other = db.execute(select(User.id).where(User.iin_index == blind_index(iin, "iin"), User.id != user.id)).first()
    if other:
        audit(db, "auth.eds_link_conflict", object_type="user", object_id=user.id, result="denied")
        s.status, s.error = "failed", "iin_taken"
        return
    user.iin, user.eds_linked_at = iin, utcnow()
    audit(db, "auth.eds_linked", object_type="user", object_id=user.id,
          details={"serial": signer.get("serial", ""), "via": "egov"})
    s.status = "signed"


def poll_link(db: Session, token: str, browser_secret: str, *, user_id) -> str:
    """The signed-in browser that started a binding learns its result."""
    s = _get(db, token, lock=True)
    if (s.purpose != "link" or s.user_id != user_id or not browser_secret
            or not secrets.compare_digest(_h(browser_secret), s.browser_hash)):
        raise NotFound()
    if s.status == "signed":
        s.status = "used"
        return "signed"
    if s.status == "failed":
        raise _failure(s.error)
    return s.status


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
        raise _failure(s.error)
    return s.status, None


def _failure(error: str) -> AppError:
    if error == "not_linked":
        return AppError("eds_not_linked", status_code=422)
    if error == "iin_taken":
        return AppError("eds_iin_taken", status_code=409)
    if error in ("cancelled", "egov_unavailable"):
        return AppError("egov_cancelled" if error == "cancelled" else "egov_unavailable", status_code=422)
    code, sep, checks = error.partition(":")
    if not sep:  # malformed answer from the app, rights lost, failed checks of a login
        code, checks = "eds_invalid", error
    return AppError(code, status_code=422, checks=checks)


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
        raise _failure(s.error)
    return s.status
