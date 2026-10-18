"""Deal card — the single entry point (FR-DEAL-04): terms, participants, documents, chat,
statuses, tracking, finance, change history. Also the driver's trip screens (M18)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, WebSocket
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.storage import IMAGE_TYPES, save_upload
from app.db import get_db
from app.modules.accounts import service as accounts
from app.modules.accounts.models import Company, User
from app.modules.billing.models import Invoice
from app.modules.chat import service as chat
from app.modules.deals import service as deals
from app.modules.deals import telematics
from app.modules.deals.tracking import trip_map
from app.modules.documents import customs, transport
from app.modules.documents.eds import is_dev_signer
from app.modules.platform.service import flag_enabled
from app.modules.deals.models import Dispute, ExecutorChange, Incident, Rating, Supplement
from app.modules.documents import service as documents
from app.modules.documents.models import Document
from app.modules.fleet.models import Driver, Vehicle
from app.modules.fleet.service import company_drivers, company_vehicles
from app.modules.orders import flow
from app.modules.orders.models import Order
from app.modules.platform.fx import deal_kzt
from app.modules.platform.service import dictionary, dictionary_map
from app.web.access import deal_access
from app.web.deps import Principal, _sysmsg as sysmsg, csrf_protect, file_url, get_principal, parse_uuid, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


@router.get("/deals")
def deals_list(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("deal.view"))):
    if me.role == "driver":
        return redirect("/trips")
    rows = deals.deals_for_company(db, me.company.id)
    names = {c.id: c.name for c in db.execute(select(Company)).scalars()} if rows else {}
    return render(request, "deals/list.html", {"rows": rows, "names": names})


@router.get("/trips")
def trips(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("trip.execute"))):
    return render(request, "deals/trips.html", {"rows": deals.deals_for_driver(db, me.user.id)})


@router.get("/deals/{did}")
def deal_card(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    acc = deal_access(db, me, parse_uuid(did), staff=request.url.path.startswith("/admin/"))
    d, o = acc.deal, acc.order
    client = db.get(Company, d.client_company_id)
    carrier = db.get(Company, d.carrier_company_id)
    docs = documents.deal_documents(db, d.id)
    if acc.side != "client" or (acc.side == "client" and not me.can("finance.view")):
        # platform-fee documents: the payer's finance roles only (a logist has no access to finance)
        docs = [x for x in docs if x.doc_type not in documents.FINANCIAL_DOC_TYPES]
    if acc.side == "driver":
        docs = [x for x in docs if x.doc_type not in ("contract_order",) or carrier.show_finance_to_drivers]
    sigs = {doc.id: documents.signatures(db, doc.id) for doc in docs}
    msgs = chat.thread_messages(db, deal_id=d.id)
    chat.mark_read(db, msgs, me.user.id)
    db.commit()
    show_finance = acc.side in ("client", "carrier") or (acc.side == "driver" and carrier.show_finance_to_drivers)
    ctx = {
        "acc": acc, "deal": d, "order": o, "client": client, "carrier": carrier,
        "vehicle": db.get(Vehicle, d.vehicle_id) if d.vehicle_id else None,
        "driver": db.get(Driver, d.driver_id) if d.driver_id else None,
        "docs": docs, "sigs": sigs, "messages": msgs, "history": deals.history(db, o.id),
        "checkpoints": deals.checkpoints(db, d.id), "snapshot": deals.latest_snapshot(db, d.id),
        "supplements": list(db.execute(select(Supplement).where(Supplement.deal_id == d.id)
                                       .order_by(Supplement.created_at.desc())).scalars()),
        "exchanges": list(db.execute(select(ExecutorChange).where(ExecutorChange.deal_id == d.id)
                                     .order_by(ExecutorChange.created_at.desc())).scalars()),
        "incidents": list(db.execute(select(Incident).where(Incident.deal_id == d.id)).scalars()),
        "dispute": deals.open_dispute_for(db, d.id),
        "my_rating": db.execute(select(Rating).where(Rating.deal_id == d.id,
                                                     Rating.from_company_id == (me.company.id if me.company else None))
                                ).scalar_one_or_none(),
        "invoice": db.execute(select(Invoice).where(Invoice.deal_id == d.id)).scalars().first()
        if acc.side == "client" and me.can("finance.view") else None,
        "show_finance": show_finance,
        "next_checkpoints": _next_checkpoints(o.status, deals.checkpoints(db, d.id)),
        "trip_map": trip_map(d, o, deals.checkpoints(db, d.id), telematics.points_for(db, d.id)),
        "transport_regs": transport.registrations(db, d.id),
        "transport_types": transport.required_types(db, o),
        "fx_kzt": deal_kzt(d),
        "customs": customs.checklist(db, d, o, customs.get(db, d)) if o.is_international else None,
        "customs_dossier": customs.get(db, d) if o.is_international else None,
        "countries": dictionary(db, "countries"), "crossings": dictionary(db, "border_crossings"),
        "eds_enabled": bool(me.company) and flag_enabled(db, "qualified_signature", me.company.id),
        "eds_mode": "dev" if is_dev_signer() else "ncalayer",
        "egov_sign": bool(me.company) and flag_enabled(db, "qualified_signature", me.company.id)
        and flag_enabled(db, "eds.egov_mobile"),
        "can_dispute": acc.side in ("client", "carrier") and o.status in (flow.ASSIGNED, flow.IN_TRANSIT, flow.UNLOADED),
        "my_vehicles": company_vehicles(db, carrier.id) if acc.side == "carrier" else [],
        "my_drivers": company_drivers(db, carrier.id) if acc.side == "carrier" else [],
        "dispute_subjects": dictionary(db, "dispute_subjects"), "incident_kinds": dictionary(db, "incident_kinds"),
        "subject_map": dictionary_map(db, "dispute_subjects"), "body_map": dictionary_map(db, "body_types"), "upload_types": documents.UPLOAD_DOC_TYPES,
        "sign_doc": request.query_params.get("sign"),
        "read_ids": chat.read_by_others(db, [m.id for m in msgs if m.author_user_id == me.user.id], me.user.id),
    }
    return render(request, "deals/card.html", ctx)


def _next_checkpoints(status: str, done) -> list[str]:
    done_kinds = {c.kind for c in done}
    order = {"arrived_load": (flow.DOCS_SIGNED,), "loaded": (flow.LOADING,), "departed": (flow.IN_TRANSIT,),
             "arrived_unload": (flow.IN_TRANSIT,), "unloaded": (flow.IN_TRANSIT,)}
    return [k for k in deals.CHECKPOINTS if status in order[k] and k not in done_kinds]


def _ctx_side(acc, *sides):
    if acc.side not in sides:
        raise Forbidden()


# ------------------------------------------------------------------ documents & signature


@router.post("/deals/{did}/docs/{doc_id}/sign-code")
def sign_code(did: str, doc_id: str, db: Session = Depends(get_db), me: Principal = Depends(require("deal.sign"))):
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None or doc.deal_id != acc.deal.id:
        raise NotFound()
    accounts.send_otp(db, me.user.phone, "sign", context=str(doc.id))
    db.commit()
    return redirect(f"/deals/{did}?sign={doc.id}#docs", flash=("info", "msg.code_sent"))


@router.post("/deals/{did}/docs/{doc_id}/sign")
async def sign(did: str, doc_id: str, request: Request, db: Session = Depends(get_db),
               me: Principal = Depends(require("deal.sign"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None or doc.deal_id != acc.deal.id:
        raise NotFound()
    documents.sign_simple(db, doc, user=db.get(User, me.user.id), company_id=me.company.id,
                          code=str(form.get("code", "")))
    deals.on_document_signed(db, acc.deal)
    db.commit()
    return redirect(f"/deals/{did}#docs", flash=("success", "msg.signed"))


@router.post("/deals/{did}/docs/{doc_id}/sign-eds")
async def sign_eds(did: str, doc_id: str, request: Request, db: Session = Depends(get_db),
                   me: Principal = Depends(require("deal.sign"))):
    """FR-DOC-07: the browser sends the signature only; verification and the signed status happen here."""
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None or doc.deal_id != acc.deal.id:
        raise NotFound()
    documents.sign_qualified(db, doc, user=db.get(User, me.user.id), company=me.company,
                             package=str(form.get("package", "")))
    deals.on_document_signed(db, acc.deal)
    db.commit()
    return redirect(f"/deals/{did}/docs/{doc.id}/signatures", flash=("success", "msg.signed_eds"))


# ------------------------------------------------------------------ FR-DOC-07: signing in eGov mobile / eGov Business

EGOV_DOC_COOKIE = "abdex_egov_doc"


def _signable_doc(db: Session, me: Principal, did: str, doc_id: str) -> tuple:
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None or doc.deal_id != acc.deal.id:
        raise NotFound()
    return acc, doc


@router.post("/deals/{did}/docs/{doc_id}/egov/start")
def egov_sign_start(did: str, doc_id: str, request: Request, db: Session = Depends(get_db),
                    me: Principal = Depends(require("deal.sign"))):
    """A QR code for eGov mobile / eGov Business: the app downloads this document and signs it with the user's
    (or the company's) key; the server verifies the signature exactly as for NCALayer."""

    from app.core.errors import AppError, Conflict
    from app.modules.accounts import egov_mobile
    from app.web.routes_public import _public_base

    acc, doc = _signable_doc(db, me, did, doc_id)
    if not egov_mobile.signing_enabled(db) or not flag_enabled(db, "qualified_signature", me.company.id):
        raise AppError("qualified_signature_off", status_code=403)
    if not doc.requires_signatures:
        raise Conflict("not_signable")
    if any(s.company_id == me.company.id for s in documents.signatures(db, doc.id)):
        raise Conflict("already_signed")
    token, browser, show = egov_mobile.start_safely(db, document=doc, user_id=me.user.id, company_id=me.company.id,
                                                    base=_public_base(request))
    db.commit()
    if "launch" in show:
        show.pop("launch")()  # SIGEX: wait for the signature in the background
    data = egov_mobile.for_browser(token, show, f"/deals/{acc.deal.id}/docs/{doc.id}/egov/{token}/status", scale=3)
    if is_dev_signer() and egov_mobile.provider() == "direct":
        data["dev_api"] = f"/egov/mgov/{token}"  # the in-browser test phone plays the app in development
    resp = JSONResponse(data, headers={"Cache-Control": "no-store"})
    from app.config import settings

    resp.set_cookie(EGOV_DOC_COOKIE, browser, max_age=300, httponly=True, secure=settings.secure_cookies,
                    samesite="strict", path=f"/deals/{acc.deal.id}/docs/{doc.id}/egov")
    return resp


@router.get("/deals/{did}/docs/{doc_id}/egov/{token}/status")
def egov_sign_status(did: str, doc_id: str, token: str, request: Request, db: Session = Depends(get_db),
                     me: Principal = Depends(require("deal.sign"))):
    from app.core.errors import AppError
    from app.core.i18n import translate
    from app.modules.accounts import egov_mobile

    acc, doc = _signable_doc(db, me, did, doc_id)
    try:
        state = egov_mobile.poll_document(db, token, request.cookies.get(EGOV_DOC_COOKIE, ""),
                                          user_id=me.user.id, document_id=doc.id)
    except NotFound:
        raise
    except AppError as exc:
        db.commit()
        return JSONResponse({"status": "failed", "message": translate(exc.message_key, **exc.params)})
    db.commit()
    if state != "signed":
        return JSONResponse({"status": state})
    from app.web.deps import set_flash

    resp = JSONResponse({"status": "signed", "redirect": f"/deals/{acc.deal.id}/docs/{doc.id}/signatures"})
    set_flash(resp, "success", "msg.signed_eds")
    resp.delete_cookie(EGOV_DOC_COOKIE, path=f"/deals/{acc.deal.id}/docs/{doc.id}/egov")
    return resp


@router.api_route("/deals/{did}/docs/{doc_id}/signatures", methods=["GET", "POST"])
async def doc_signatures(did: str, doc_id: str, request: Request, db: Session = Depends(get_db),
                         me: Principal = Depends(get_principal)):
    """GOV-DS-04/05: the signature set and a fresh server-side re-check at any time (POST)."""
    acc = deal_access(db, me, parse_uuid(did), staff=request.url.path.startswith("/admin/"))
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None or doc.deal_id != acc.deal.id:
        raise NotFound()
    recheck = documents.reverify_qualified(db, doc) if request.method == "POST" else None
    db.commit()
    import json as _json

    return render(request, "deals/signatures.html", {
        "deal": acc.deal, "doc": doc, "sigs": documents.signatures(db, doc.id),
        "qsigs": documents.qualified_signatures(db, doc.id), "recheck": recheck, "json_loads": _json.loads})


@router.post("/deals/{did}/transport-docs")
async def transport_docs(did: str, request: Request, db: Session = Depends(get_db),
                         me: Principal = Depends(require("deal.manage"))):
    """GOV-TR-02/04/05: form the consignment note (and CMR abroad) from the deal data."""
    from app.modules.documents import transport

    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    transport.form_documents(db, acc.deal, mode=str(form.get("mode", "electronic")),
                             paper_number=str(form.get("paper_number", "")))
    db.commit()
    return redirect(f"/deals/{did}#transport", flash=("success", "etd.formed"))


# ------------------------------------------------------------------ GOV-TR-06 customs data


@router.post("/deals/{did}/customs")
async def customs_save(did: str, request: Request, db: Session = Depends(get_db),
                       me: Principal = Depends(require("deal.manage"))):
    """Each side fills its own part: the shipper the goods and invoice, the carrier the transit data."""
    form = dict((await request.form()).items())
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    customs.save(db, acc.deal, acc.side, form)
    db.commit()
    return redirect(f"/deals/{did}#customs", flash=("success", "msg.saved"))


@router.post("/deals/{did}/customs/ready")
def customs_ready(did: str, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    customs.mark_ready(db, acc.deal)
    customs.pdf_summary(db, acc.deal)
    db.commit()
    return redirect(f"/deals/{did}#customs", flash=("success", "customs.ready_done"))


@router.get("/deals/{did}/customs.xml")
def customs_xml(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    from fastapi.responses import Response

    acc = deal_access(db, me, parse_uuid(did), staff=request.url.path.startswith("/admin/"))
    if acc.side not in ("client", "carrier", "staff") or not db.get(Order, acc.deal.order_id).is_international:
        raise NotFound()  # invoice values and the consignee are not for the driver
    audit(db, "customs.exported", object_type="deal", object_id=acc.deal.id)
    db.commit()
    return Response(customs.xml_export(db, acc.deal), media_type="application/xml",
                    headers={"Content-Disposition": 'attachment; filename="customs-preliminary-information.xml"'})


@router.post("/deals/{did}/transport-docs/{rid}/submit")
def transport_submit(did: str, rid: str, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    from app.modules.documents import transport

    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    _, reg = transport.get_registration(db, acc.deal.id, parse_uuid(rid))
    transport.submit_paper(db, reg)
    db.commit()
    return redirect(f"/deals/{did}#transport", flash=("success", "etd.submitted"))


@router.get("/deals/{did}/transport-docs/{rid}.xml")
def transport_xml(did: str, rid: str, request: Request, db: Session = Depends(get_db),
                  me: Principal = Depends(get_principal)):
    from urllib.parse import quote

    from fastapi.responses import Response

    from app.modules.documents import transport

    acc = deal_access(db, me, parse_uuid(did), staff=request.url.path.startswith("/admin/"))
    doc, reg = transport.get_registration(db, acc.deal.id, parse_uuid(rid))
    return Response(transport.xml_export(reg, doc), media_type="application/xml",
                    headers={"Content-Disposition": "attachment; filename=\"transport-document.xml\"; "
                             f"filename*=UTF-8''{quote(doc.doc_type + '-' + doc.number + '.xml')}"})


@router.post("/deals/{did}/docs/upload")
async def upload_doc(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise ValidationFailed({"file": "error.required"})
    f = save_upload(db, data=await upload.read(), original_name=upload.filename or "doc",
                    company_id=me.company.id if me.company else None, user_id=me.user.id)
    documents.register_upload(db, deal_id=acc.deal.id, company_id=me.company.id if me.company else None,
                              doc_type=str(form.get("doc_type", "other")), file=f)
    from app.modules.notifications.service import notify_event

    notify_event(db, "document.uploaded", params={"number": acc.deal.number}, link=f"/deals/{acc.deal.id}",
                 client_company_id=acc.deal.client_company_id, carrier_company_id=acc.deal.carrier_company_id)
    deals.try_close_by_documents(db, acc)
    db.commit()
    return redirect(f"/deals/{did}#docs", flash=("success", "msg.uploaded"))


@router.post("/deals/{did}/docs/{doc_id}/review")
async def review_doc(did: str, doc_id: str, request: Request, db: Session = Depends(get_db),
                     me: Principal = Depends(require("deal.manage"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None or doc.deal_id != acc.deal.id or doc.is_generated or doc.company_id == me.company.id:
        raise NotFound()  # the other side reviews a document
    documents.mark_status(db, doc, str(form.get("status", "")), str(form.get("reason", "")))
    db.commit()
    return redirect(f"/deals/{did}#docs")


# ------------------------------------------------------------------ trip


@router.post("/deals/{did}/checkpoint")
async def checkpoint(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    photo_id = None
    upload = form.get("photo")
    if upload is not None and hasattr(upload, "read") and getattr(upload, "filename", ""):
        data = await upload.read()
        if data:
            f = save_upload(db, data=data, original_name=upload.filename, company_id=acc.deal.carrier_company_id,
                            user_id=me.user.id, allowed=IMAGE_TYPES,
                            extra_meta={"lat": form.get("lat"), "lng": form.get("lng")})
            photo_id = f.id

    def _f(key):
        try:
            return float(form.get(key)) if form.get(key) else None
        except ValueError:
            return None

    deals.add_checkpoint(db, acc, str(form.get("kind", "")), lat=_f("lat"), lng=_f("lng"), photo_file_id=photo_id,
                         note=str(form.get("note", "")), offline_id=str(form.get("offline_id", "")))
    db.commit()
    if request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({"ok": True})
    return redirect(f"/deals/{did}#trip", flash=("success", "msg.checkpoint_saved"))


@router.post("/deals/{did}/geo-consent")
async def geo_consent(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-TRK-03: geo only with explicit consent and only for the duration of the trip."""
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "driver", "carrier")
    on = form.get("on") == "1"
    acc.deal.geo_consent = on and acc.order.status in (flow.DOCS_SIGNED, flow.LOADING, flow.IN_TRANSIT)
    if on:
        accounts.record_consent(db, me.user.id, "geolocation")
    db.commit()
    return redirect(f"/deals/{did}#trip")


@router.post("/deals/{did}/unloaded")
def confirm_unloaded(did: str, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client")
    order = flow.lock_order(db, acc.order.id)
    flow.transition(db, order, flow.UNLOADED, actor=flow.CLIENT, reason="client confirmed unloading")
    deals.try_close_by_documents(db, acc)
    db.commit()
    return redirect(f"/deals/{did}", flash=("success", "msg.saved"))


@router.post("/deals/{did}/incident")
async def incident(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    deals.report_incident(db, acc, str(form.get("kind", "delay")), str(form.get("description", "")))
    db.commit()
    return redirect(f"/deals/{did}#trip", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ terms


@router.post("/deals/{did}/supplement")
async def supplement(did: str, request: Request, db: Session = Depends(get_db),
                     me: Principal = Depends(require("deal.manage"))):
    form = dict((await request.form()).items())
    acc = deal_access(db, me, parse_uuid(did))
    _ctx_side(acc, "client", "carrier")
    deals.propose_supplement(db, acc, form)
    db.commit()
    return redirect(f"/deals/{did}#terms", flash=("success", "msg.supplement_sent"))


@router.post("/deals/{did}/supplement/{sid}")
async def supplement_decide(did: str, sid: str, request: Request, db: Session = Depends(get_db),
                            me: Principal = Depends(require("deal.manage"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    sup = db.get(Supplement, parse_uuid(sid))
    if sup is None:
        raise NotFound()
    deals.decide_supplement(db, acc, sup, accept=form.get("accept") == "1")
    db.commit()
    return redirect(f"/deals/{did}#terms", flash=("success", "msg.saved"))


@router.post("/deals/{did}/executor")
async def executor(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    vid = parse_uuid(form["vehicle_id"]) if form.get("vehicle_id") else None
    drv = parse_uuid(form["driver_id"]) if form.get("driver_id") else None
    deals.propose_executor_change(db, acc, vid, drv, str(form.get("reason", "")))
    db.commit()
    return redirect(f"/deals/{did}#terms", flash=("success", "msg.saved"))


@router.post("/deals/{did}/executor/{cid}")
async def executor_decide(did: str, cid: str, request: Request, db: Session = Depends(get_db),
                          me: Principal = Depends(require("deal.manage"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    ch = db.get(ExecutorChange, parse_uuid(cid))
    if ch is None:
        raise NotFound()
    deals.decide_executor_change(db, acc, ch, accept=form.get("accept") == "1")
    db.commit()
    return redirect(f"/deals/{did}#terms", flash=("success", "msg.saved"))


# ------------------------------------------------------------------ dispute & rating


@router.post("/deals/{did}/dispute")
async def dispute(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    deals.open_dispute(db, acc, str(form.get("subject", "other")), str(form.get("description", "")))
    db.commit()
    return redirect(f"/deals/{did}", flash=("success", "msg.dispute_opened"))


@router.post("/deals/{did}/dispute/{dsid}/position")
async def dispute_position(did: str, dsid: str, request: Request, db: Session = Depends(get_db),
                           me: Principal = Depends(require("deal.manage"))):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    d = db.get(Dispute, parse_uuid(dsid))
    if d is None or d.deal_id != acc.deal.id:
        raise NotFound()
    deals.add_dispute_position(db, acc, d, str(form.get("text", "")))
    db.commit()
    return redirect(f"/deals/{did}", flash=("success", "msg.saved"))


@router.post("/deals/{did}/rate")
async def rate(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    form = dict((await request.form()).items())
    acc = deal_access(db, me, parse_uuid(did))
    deals.rate(db, acc, form)
    db.commit()
    return redirect(f"/deals/{did}", flash=("success", "msg.thanks_rating"))


# ------------------------------------------------------------------ chat


@router.post("/deals/{did}/chat")
async def chat_post(did: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    form = await request.form()
    acc = deal_access(db, me, parse_uuid(did))
    file_id = None
    upload = form.get("file")
    if upload is not None and hasattr(upload, "read") and getattr(upload, "filename", ""):
        data = await upload.read()
        if data:
            file_id = save_upload(db, data=data, original_name=upload.filename,
                                  company_id=me.company.id if me.company else None, user_id=me.user.id).id
    msg = chat.post(db, deal_id=acc.deal.id, body=str(form.get("body", "")), attachment_file_id=file_id)
    db.commit()
    if request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({"ok": True, "id": str(msg.id)})
    return redirect(f"/deals/{did}#chat")


def chat_payload(db: Session, me: Principal, deal_id, after: str = "") -> dict:
    """FR-CHAT-06: the same payload for polling and for the WebSocket: new messages (read on delivery) and
    which of my messages the other side has read (the read indicator)."""
    acc = deal_access(db, me, deal_id)
    after_id = parse_uuid(after) if after else None
    msgs = chat.thread_messages(db, deal_id=acc.deal.id, after=after_id)
    chat.mark_read(db, msgs, me.user.id)
    users = {u.id: u.full_name for u in db.execute(select(User).where(
        User.id.in_([m.author_user_id for m in msgs if m.author_user_id] or [None]))).scalars()}
    out = []
    for m in msgs:
        text = sysmsg(m.body) if m.kind == "system" else m.body
        out.append({"id": str(m.id), "kind": m.kind, "text": text, "author": users.get(m.author_user_id, ""),
                    "mine": m.author_user_id == me.user.id, "at": m.created_at.isoformat(),
                    "file": file_url(m.attachment_file_id) if m.attachment_file_id else ""})
    mine = [m.id for m in chat.thread_messages(db, deal_id=acc.deal.id) if m.author_user_id == me.user.id][-200:]
    read = [str(i) for i in chat.read_by_others(db, mine, me.user.id)]
    return {"messages": out, "read": read}


ws_router = APIRouter()  # WebSockets carry no CSRF form token: the Origin check below protects them


def _ws_principal(db: Session, raw_session: str | None) -> Principal | None:
    from app.modules.accounts.models import Company
    from app.modules.accounts.service import role_in
    from app.web.deps import load_session

    sess = load_session(db, raw_session)
    if sess is None or not sess.mfa_passed or sess.impersonator_id:
        return None
    user = db.get(User, sess.user_id)
    if user is None or user.is_blocked or user.is_deleted:
        return None
    company = db.get(Company, sess.active_company_id) if sess.active_company_id else None
    role = role_in(db, user.id, company.id) if company else None
    if company is not None and role is None:
        return None
    return Principal(user=user, session=sess, company=company, role=role)


def _ws_tick(raw_session: str | None, deal_id, after: str) -> dict | None:
    """One poll of the database for the socket; None ends the connection (session gone, access lost)."""
    import uuid as _uuid

    from app.core import rls
    from app.core.context import RequestContext, reset_ctx, set_ctx
    from app.core.errors import AppError
    from app.db import SessionLocal

    db = SessionLocal()
    tok = set_ctx(RequestContext(request_id=_uuid.uuid4().hex))
    try:
        me = _ws_principal(db, raw_session)
        if me is None:
            return None
        from app.core.context import get_ctx

        ctx = get_ctx()
        ctx.user_id, ctx.company_id, ctx.role = me.user.id, me.company.id if me.company else None, me.role or ""
        rls.apply(db)
        try:
            data = chat_payload(db, me, deal_id, after)
        except AppError:
            return None
        db.commit()
        return data
    finally:
        reset_ctx(tok)
        db.close()


@ws_router.websocket("/deals/{did}/chat/ws")
async def chat_ws(websocket: WebSocket, did: str):
    """FR-CHAT-06: real-time delivery. The server pushes new messages and read receipts; the database is the
    bus, so it works with several application processes. Same-origin only (no cross-site WebSocket hijacking)."""
    import asyncio
    from urllib.parse import urlparse

    from starlette.concurrency import run_in_threadpool
    from starlette.websockets import WebSocketDisconnect

    from app.web.deps import SESSION_COOKIE

    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not origin or urlparse(origin).netloc != host:
        await websocket.close(code=4403)
        return
    try:
        deal_id = parse_uuid(did)
    except Exception:  # noqa: BLE001
        await websocket.close(code=4404)
        return
    raw = websocket.cookies.get(SESSION_COOKIE)
    after = websocket.query_params.get("after", "")
    first = await run_in_threadpool(_ws_tick, raw, deal_id, after)
    if first is None:
        await websocket.close(code=4403)
        return
    await websocket.accept()
    read_seen: set = set()
    data = first
    try:
        while True:
            fresh = [r for r in data["read"] if r not in read_seen]
            if data["messages"] or fresh:
                read_seen.update(fresh)
                await websocket.send_json({"messages": data["messages"], "read": fresh})
                if data["messages"]:
                    after = data["messages"][-1]["id"]
            await asyncio.sleep(2)
            data = await run_in_threadpool(_ws_tick, raw, deal_id, after)
            if data is None:
                await websocket.close(code=4401)
                return
    except (WebSocketDisconnect, RuntimeError):
        return


@router.get("/deals/{did}/chat.json")
def chat_poll(did: str, after: str = "", db: Session = Depends(get_db), me: Principal = Depends(get_principal)):
    """FR-CHAT-06: periodic polling — the fallback when the WebSocket is not available."""
    data = chat_payload(db, me, parse_uuid(did), after)
    db.commit()
    return JSONResponse(data)


@router.get("/deals/{did}/dossier.zip")
def dossier(did: str, db: Session = Depends(get_db), me: Principal = Depends(require("deal.manage"))):
    acc = deal_access(db, me, parse_uuid(did))
    data = deals.dossier_zip(db, acc)
    db.commit()
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="dossier-{acc.deal.number}.zip"'})
