"""Demo data for development and acceptance demos (SEED_DEMO_DATA=true).

Builds a realistic set of participants and deals through the real services, so the demo
also exercises the status machine, documents and billing end-to-end.
Password for every demo account: AbdexDemo2026!
"""
from __future__ import annotations

import logging
from datetime import date, timedelta

from sqlalchemy import select

from app.core.context import RequestContext, reset_ctx, set_ctx
from app.core.i18n import to_local_input
from app.core.security import hash_password
from app.db import utcnow
from app.modules.accounts.models import BankAccount, Company, Membership, User
from app.modules.accounts.service import bin_control_digit
from app.modules.fleet.models import Driver, Vehicle

log = logging.getLogger("abdex.demo")
PASSWORD = "AbdexDemo2026!"  # noqa: S105 — public demo password, dev only


def make_bin(prefix11: str) -> str:
    for i in range(10):
        candidate = prefix11[:10] + str(i)
        cd = bin_control_digit(candidate)
        if cd is not None:
            return candidate + str(cd)
    raise ValueError("cannot build BIN")


def _user(db, phone, name, email=None, staff=None) -> User:
    u = User(phone=phone, email=email, full_name=name, password_hash=hash_password(PASSWORD), phone_verified=True,
             email_verified=bool(email), staff_role=staff)
    db.add(u)
    db.flush()
    return u


def _company(db, kind, name, bin_prefix, level, **kw) -> Company:
    c = Company(kind=kind, name=name, bin_iin=make_bin(bin_prefix), verification_level=level,
                legal_address=kw.get("address", "г. Алматы"), contact_phone=kw.get("phone", ""),
                contact_email=kw.get("email", ""), legal_form=kw.get("form", "ТОО"))
    db.add(c)
    db.flush()
    return c


def _make_l3(db, company, vehicles, drivers) -> None:
    """Demo: the main carrier has everything L3 needs — company EDS, vehicle passports, driver biometrics."""
    from app.core.storage import save_generated
    from app.modules.fleet.models import BiometricCheck, VerificationDocument

    for v in vehicles:
        f = save_generated(db, data=b"%PDF-1.4\n% demo technical passport\n", name=f"tech-passport-{v.plate}.pdf",
                           content_type="application/pdf", company_id=company.id)
        db.add(VerificationDocument(company_id=company.id, subject_type="vehicle", subject_id=v.id,
                                    doc_type="tech_passport", file_id=f.id, status="approved"))
    for d in drivers:
        db.add(BiometricCheck(driver_id=d.id, company_id=company.id, provider="demo", match=True, liveness=True,
                              score=96, status="passed", valid_until=date.today() + timedelta(days=365)))
    company.eds_confirmed_at, company.eds_cert_serial = utcnow(), "demo"
    company.verification_level = 3


def seed_demo(db) -> None:
    if db.execute(select(User.id).where(User.email == "admin@abdex.kz")).first():
        return
    log.info("seeding demo data")
    from app.modules.platform.models import FeatureFlag

    for key in ("qualified_signature", "online_payments", "auth.eds_login", "auth.egov_mobile", "eds.egov_mobile",
                "digital_modules", "subscriptions"):  # demo: show the integrations with their simulators
        flag = db.execute(select(FeatureFlag).where(FeatureFlag.key == key)).scalar_one_or_none()
        if flag is not None:
            flag.enabled = True
    staff = {}
    for role, email, name in (("admin", "admin@abdex.kz", "Администратор платформы"),
                              ("manager", "manager@abdex.kz", "Айгерим Менеджер"),
                              ("moderator", "moderator@abdex.kz", "Данияр Модератор"),
                              ("finance", "finance@abdex.kz", "Сауле Финансист"),
                              ("auditor", "auditor@abdex.kz", "Ерлан Аудитор ИБ")):
        staff[role] = _user(db, f"+7700000000{len(staff) + 1}", name, email, role)

    client = _company(db, "client", "ТОО «Казахстан Агро Трейд»", "16054000123", 2, address="г. Алматы, пр. Абая, 10",
                      phone="+77010000001", email="logistics@agrotrade.kz")
    owner = _user(db, "+77010000001", "Асель Нурланова", "owner@agrotrade.kz")
    logist = _user(db, "+77010000002", "Тимур Логистов")
    accountant = _user(db, "+77010000003", "Гульнара Бухгалтер")
    for u, r in ((owner, "owner"), (logist, "logist"), (accountant, "accountant")):
        db.add(Membership(user_id=u.id, company_id=client.id, role=r))
    db.add(BankAccount(company_id=client.id, iban="KZ86125KZT5004100100", bank_name="Halyk Bank", bik="HSBKKZKX",
                       status="active", confirmed_at=utcnow(), effective_at=utcnow()))

    carrier = _company(db, "carrier", "ТОО «Жол Транс Логистик»", "19034000456", 2,
                       address="г. Астана, ул. Кенесары, 40", phone="+77020000001")
    fleet_owner = _user(db, "+77020000001", "Бауыржан Жолтранс")
    dispatcher = _user(db, "+77020000002", "Марат Диспетчер")
    driver_user = _user(db, "+77020000003", "Серик Водитель")
    for u, r in ((fleet_owner, "fleet_owner"), (dispatcher, "dispatcher"), (driver_user, "driver")):
        db.add(Membership(user_id=u.id, company_id=carrier.id, role=r))
    v1 = Vehicle(company_id=carrier.id, plate="777ABC01", vin="XLRTE47MS0E123456", body_type="tent", capacity_kg=20000,
                 volume_m3=86, status="approved", insurance_until=date.today() + timedelta(days=200),
                 international_permit=True)
    v2 = Vehicle(company_id=carrier.id, plate="555REF02", vin="WMA06XZZ1KM765432", body_type="refrigerator",
                 capacity_kg=18000, volume_m3=76, status="approved", adr_allowed=True,
                 insurance_until=date.today() + timedelta(days=25))
    d1 = Driver(company_id=carrier.id, user_id=driver_user.id, full_name="Серик Водитель", iin=make_bin("85040130012"),
                phone="+77020000003", license_number="KZ 123456", license_categories="C,CE",
                license_until=date.today() + timedelta(days=900), status="approved", adr_permit=True)
    d2 = Driver(company_id=carrier.id, full_name="Нурлан Ахметов", iin=make_bin("79120230045"), phone="+77020000004",
                license_categories="C,CE", status="approved")
    v4 = Vehicle(company_id=carrier.id, plate="888TNT03", vin="YS2R4X20005123456", body_type="tent", capacity_kg=20000,
                 volume_m3=82, status="approved", insurance_until=date.today() + timedelta(days=300))
    db.add_all([v1, v2, v4, d1, d2])
    db.flush()
    _make_l3(db, carrier, (v1, v2, v4), (d1, d2))

    carrier2 = _company(db, "carrier", "ИП Сапаров А.К.", "88062030078", 1, form="ИП", phone="+77030000001")
    owner2 = _user(db, "+77030000001", "Айдар Сапаров")
    db.add(Membership(user_id=owner2.id, company_id=carrier2.id, role="fleet_owner"))
    carrier2.deal_limit_minor = 300_000_000
    v3 = Vehicle(company_id=carrier2.id, plate="123KZ05", body_type="tent", capacity_kg=10000, volume_m3=45,
                 status="approved")
    d3 = Driver(company_id=carrier2.id, full_name="Айдар Сапаров", iin=make_bin("88062030078"), phone="+77030000001",
                status="approved")
    db.add_all([v3, d3])
    # SEC-FRD-04 demo: an unverified company with the same phone and truck as the sole trader — seen in the link graph
    shell = _company(db, "carrier", "ТОО «Транзит Сервис»", make_bin("19114000789"), 0, phone="+77030000001")
    db.add(Vehicle(company_id=shell.id, plate="123KZ05", body_type="tent", capacity_kg=10000, volume_m3=45))
    db.commit()

    from app.modules.billing.models import Tariff

    db.add(Tariff(name="Переменный: 3 %, минимум 15 000 ₸", company_id=client.id, model="percent", percent_bp=300,
                  min_minor=1_500_000, max_minor=0, valid_from=date(2026, 1, 1), deal_type="international"))
    db.commit()

    _build_orders(db, client, carrier, carrier2, owner, logist, fleet_owner, owner2, staff, v1, v2, v3, d1, d2, d3, v4)


def _as(user, company, role):
    return set_ctx(RequestContext(request_id="demo-seed", extra={"rls_bypass": True}, ip="127.0.0.1", user_agent="seed", user_id=user.id,
                                  company_id=company.id if company else None, role=role))


def _form(cities, cargo, weight, rate, load_in_days, body="tent", **extra):
    load = utcnow() + timedelta(days=load_in_days)
    form = {"cargo_name": cargo, "cargo_type": extra.get("cargo_type", "general"), "weight_kg": str(weight),
            "volume_m3": str(extra.get("volume", 60)), "places": str(extra.get("places", 20)), "body_type": body,
            "desired_rate": str(rate), "currency": "KZT", "payment_terms": extra.get("terms", "on_unload"),
            "vat_included": "on", "load_from": to_local_input(load), "load_to": to_local_input(load + timedelta(hours=6)),
            "unload_to": to_local_input(load + timedelta(days=extra.get("days", 3))),
            "point_kind": ["load"] + ["stop"] * (len(cities) - 2) + ["unload"], "point_city": [c for c, _ in cities],
            "point_address": [a for _, a in cities], "point_contact_name": ["Склад"] * len(cities),
            "point_contact_phone": ["+77011112233"] * len(cities)}
    for k in ("is_international", "countries", "border_crossing", "needs_cmr", "temperature_mode"):
        if k in extra:
            form[k] = extra[k]
    return form


def _build_orders(db, client, carrier, carrier2, owner, logist, fleet_owner, owner2, staff, v1, v2, v3, d1, d2, d3, v4):
    from app.modules.bids.service import accept, counter_offer, place_bid
    from app.modules.billing.models import Invoice
    from app.modules.billing.service import register_payment
    from app.modules.deals import service as deals
    from app.modules.documents.models import Document, Signature
    from app.modules.documents.service import register_upload, render_pdf
    from app.modules.orders.service import create_order, submit
    from app.core.storage import save_generated

    tok = _as(logist, client, "logist")
    try:
        o1 = create_order(db, client, _form([("Алматы", "ул. Складская, 5"), ("Астана", "пр. Туран, 20")],
                                            "Мука пшеничная в мешках", 20000, 650000, 2))
        submit(db, o1)
        o2 = create_order(db, client, _form([("Алматы", "Промзона, 12"), ("Шымкент", "ул. Байтурсынова, 3")],
                                            "Подсолнечное масло", 18000, 420000, 3))
        submit(db, o2)
        o3 = create_order(db, client, _form([("Алматы", "Терминал Восток"), ("Караганда", "ул. Ленина, 1")],
                                            "Оборудование для элеватора", 15000, 380000, 1, places=8))
        submit(db, o3)
        o4 = create_order(db, client, _form([("Хоргос", "СЭЗ Хоргос"), ("Алматы", "ул. Рыскулова, 70")],
                                            "Комплектующие (импорт КНР)", 19000, 300000, 1,
                                            is_international="on", countries="CN, KZ", border_crossing="khorgos",
                                            needs_cmr="on"))
        submit(db, o4)
        o5 = create_order(db, client, _form([("Алматы", ""), ("Усть-Каменогорск", "")],
                                            "Стройматериалы", 12000, 0, 10), preliminary=True)
        db.commit()
    finally:
        reset_ctx(tok)

    def bid(order, company, user, price, vehicle, driver):
        t = _as(user, company, "fleet_owner")
        try:
            b = place_bid(db, order.id, company, {"price": str(price), "vehicle_id": str(vehicle.id),
                                                  "driver_id": str(driver.id), "comment": "Готовы подать вовремя"})
            db.commit()
            return b
        finally:
            reset_ctx(t)

    bid(o2, carrier, fleet_owner, 410000, v1, d1)
    b22 = bid(o2, carrier2, owner2, 395000, v3, d3)
    tok = _as(logist, client, "logist")
    counter_offer(db, b22, "380000", "Можем сразу согласовать на 380 000")
    db.commit()
    reset_ctx(tok)
    b3 = bid(o3, carrier, fleet_owner, 375000, v4, d2)  # v1/d1 are busy on o4 the same days (FR-PLAN-04)
    b4 = bid(o4, carrier, fleet_owner, 300000, v1, d1)

    def sign_both(deal):
        contract = db.execute(select(Document).where(Document.deal_id == deal.id,
                                                     Document.doc_type == "contract_order")).scalars().first()
        for company, user in ((client, owner), (carrier, fleet_owner)):
            db.add(Signature(document_id=contract.id, user_id=user.id, company_id=company.id, kind="simple",
                             signed_at=utcnow(), ip="127.0.0.1", document_hash=contract.sha256))
        db.flush()
        deals.on_document_signed(db, deal)

    tok = _as(owner, client, "owner")
    deal3 = accept(db, b3.id, client)
    deal4 = accept(db, b4.id, client)
    sign_both(deal3)
    sign_both(deal4)
    db.commit()
    reset_ctx(tok)

    tok = _as(fleet_owner, carrier, "fleet_owner")
    for deal, kinds in ((deal3, ("arrived_load", "loaded", "departed")),
                        (deal4, ("arrived_load", "loaded", "departed", "arrived_unload", "unloaded"))):
        acc = deals.get_access(db, deal.id, user=fleet_owner, company_id=carrier.id, role="fleet_owner")
        acc.deal.geo_consent = True
        from app.modules.integrations.adapters import CITY_COORDS

        order = acc.order
        a = CITY_COORDS.get(order.origin.city.lower(), (43.24, 76.89))
        b = CITY_COORDS.get(order.destination.city.lower(), (51.17, 71.45))
        for i, k in enumerate(kinds):
            f = {"arrived_load": 0.0, "loaded": 0.0, "departed": 0.35, "arrived_unload": 1.0, "unloaded": 1.0}[k]
            deals.add_checkpoint(db, acc, k, lat=round(a[0] + (b[0] - a[0]) * f + 0.01 * i, 4),
                                 lng=round(a[1] + (b[1] - a[1]) * f, 4), offline_id=f"demo-{deal.id}-{k}")
        db.commit()
    acc4 = deals.get_access(db, deal4.id, user=fleet_owner, company_id=carrier.id, role="fleet_owner")
    pdf = render_pdf("CMR / ТТН", "Груз принят без замечаний. Пломба № 445566.")
    f = save_generated(db, data=pdf, name="cmr-scan.pdf", content_type="application/pdf", company_id=carrier.id)
    register_upload(db, deal_id=deal4.id, company_id=carrier.id, doc_type="cmr", file=f)
    deals.try_close_by_documents(db, acc4)  # -> closed_docs -> fee accrued -> fee_invoiced
    from app.modules.chat.service import post

    acc3 = deals.get_access(db, deal3.id, user=fleet_owner, company_id=carrier.id, role="fleet_owner")
    post(db, deal_id=acc3.deal.id, body="Машина загружена, выезжаем. Ориентировочно будем завтра к 18:00.")
    db.commit()
    reset_ctx(tok)

    tok = _as(staff["finance"], None, "finance")
    inv = db.execute(select(Invoice).where(Invoice.deal_id == deal4.id)).scalars().first()
    if inv:
        register_payment(db, inv, inv.amount_minor, source="bank_statement", reference="п/п 1024")
    db.commit()
    reset_ctx(tok)

    tok = _as(owner, client, "owner")
    acc_c = deals.get_access(db, deal4.id, user=owner, company_id=client.id, role="owner")
    deals.rate(db, acc_c, {"score": "5", "punctuality": "5", "vehicle_condition": "4", "documents_quality": "5",
                           "communication": "5", "payment_discipline": "5", "comment": "Отличная работа"})
    db.commit()
    reset_ctx(tok)
    log.info("demo data ready: orders %s %s %s %s %s", o1.number, o2.number, o3.number, o4.number, o5.number)
