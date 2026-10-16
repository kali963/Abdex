"""Finance, analytics, calculator, support."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.db import get_db, utcnow
from app.modules.analytics import service as analytics
from app.modules.billing import service as billing
from app.modules.calc import service as calc
from app.modules.chat import service as chat
from app.modules.platform.models import CalcResult, Ticket
from app.modules.platform.service import dictionary, dictionary_map
from app.modules.support import service as support
from app.web.deps import Principal, csrf_protect, parse_uuid, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


@router.get("/finance")
def finance(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("finance.view"))):
    ctx = {"ledger": billing.ledger(db, me.company.id)} if me.company.kind == "client" else {}
    if me.company.kind == "carrier":
        ctx["carrier"] = analytics.carrier_analytics(db, me.company.id)
    else:
        ctx["promos"] = billing.company_promos(db, me.company.id)
    today = utcnow().date()
    from app.modules.platform.service import flag_enabled

    ctx.update(today=today, month_start=today.replace(day=1),
               online_payments=flag_enabled(db, "online_payments", me.company.id))
    return render(request, "finance/finance.html", ctx)


@router.get("/analytics")
def analytics_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("analytics.view"))):
    if me.company.kind == "client":
        data = analytics.client_analytics(db, me.company.id)
    else:
        data = analytics.carrier_analytics(db, me.company.id)
    return render(request, "finance/analytics.html", {"data": data})


@router.get("/analytics/export.{fmt}")
def analytics_export(fmt: str, db: Session = Depends(get_db), me: Principal = Depends(require("analytics.view"))):
    """FR-BI-05: XLSX and CSV export of any report."""
    ratelimit.hit("export", str(me.user.id))
    from app.modules.deals.service import deals_for_company

    rows = [["Сделка", "Заявка", "Статус", "Маршрут", "Сумма", "Валюта", "Дата"]]
    for d, o in deals_for_company(db, me.company.id):
        route = f"{o.origin.city if o.origin else ''} → {o.destination.city if o.destination else ''}"
        rows.append([d.number, o.number, o.status, route, d.price_minor / 100, d.currency,
                     d.created_at.strftime("%d.%m.%Y")])
    # FR-ACL-07: exports over 100 records only for roles allowed bulk export; logged separately
    if len(rows) - 1 > 100 and not me.can("export.bulk"):
        raise Forbidden("bulk_export_restricted")
    audit(db, "export.bulk" if len(rows) - 1 > 100 else "export.deals", object_type="company",
          object_id=me.company.id, details={"rows": len(rows) - 1})
    db.commit()
    if fmt == "csv":
        return Response(analytics.to_csv(rows), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="deals.csv"'})
    if fmt == "xlsx":
        return Response(analytics.to_xlsx(rows, "Сделки"),
                        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": 'attachment; filename="deals.xlsx"'})
    raise NotFound()


@router.get("/calc")
def calc_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("calc.use"))):
    recent = list(db.execute(select(CalcResult).where(CalcResult.user_id == me.user.id)
                             .order_by(CalcResult.created_at.desc()).limit(5)).scalars())
    return render(request, "finance/calc.html", {"body_types": dictionary(db, "body_types"), "recent": recent})


@router.post("/calc")
async def calc_run(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("calc.use"))):
    form = dict((await request.form()).items())
    kind = form.get("kind", "trip_cost")
    ctx = {"body_types": dictionary(db, "body_types"), "form": form, "kind": kind, "recent": []}
    try:
        ctx["result"] = calc.client_price(db, form) if kind == "client_price" else calc.trip_cost(db, form)
    except ValidationFailed as exc:
        ctx["errors"] = exc.fields
        return render(request, "finance/calc.html", ctx, status_code=422)
    db.commit()
    return render(request, "finance/calc.html", ctx)


@router.get("/support")
def support_list(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("support.use"))):
    return render(request, "support/list.html", {"items": support.my_tickets(db, me.user.id),
                                                 "categories": dictionary(db, "support_categories"),
                                                 "cat_map": dictionary_map(db, "support_categories")})


@router.post("/support")
async def support_create(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("support.use"))):
    form = await request.form()
    deal_id = None
    if form.get("deal_id"):
        from app.web.access import deal_access

        import uuid as _uuid

        try:
            deal_id = deal_access(db, me, _uuid.UUID(str(form.get("deal_id")).strip())).deal.id
        except (ValueError, NotFound):
            raise ValidationFailed({"deal_id": "error.deal_not_found"})
    t = support.create_ticket(db, category=str(form.get("category", "")), subject=str(form.get("subject", "")),
                              body=str(form.get("body", "")), deal_id=deal_id)
    db.commit()
    return redirect(f"/support/{t.id}", flash=("success", "msg.ticket_created"))


@router.get("/support/{tid}")
def support_view(tid: str, request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("support.use"))):
    t = db.get(Ticket, parse_uuid(tid))
    if t is None or t.user_id != me.user.id:
        raise NotFound()
    return render(request, "support/view.html", {"t": t, "messages": chat.thread_messages(db, ticket_id=t.id),
                                                 "cat_map": dictionary_map(db, "support_categories")})


@router.post("/support/{tid}")
async def support_reply(tid: str, request: Request, db: Session = Depends(get_db),
                        me: Principal = Depends(require("support.use"))):
    form = await request.form()
    t = db.get(Ticket, parse_uuid(tid))
    if t is None or t.user_id != me.user.id:
        raise NotFound()
    chat.post(db, ticket_id=t.id, body=str(form.get("body", "")))
    if t.status == "resolved":
        t.status = "open"
    db.commit()
    return redirect(f"/support/{t.id}")
