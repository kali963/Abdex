"""Register of personal data processing, recipients and cross-border transfers (SEC-DAT-10/11).

The register is not just a document: an integration adapter that sends personal data out of the platform
works only while an active record names it (``Adapter.personal_data``). Switching a record off stops the
transfer at once; every change is audited. The public part is shown on the privacy page.
"""
from __future__ import annotations

import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.platform.models import ProcessingRecord

# code: (purpose, data categories, legal basis, recipient, cross_border, countries, safeguards, retention, adapter)
DEFAULT_RECORDS = {
    "accounts": ("Регистрация и вход, работа аккаунта", "ФИО, телефон, e-mail", "Согласие на регистрацию; договор",
                 "", False, "", "Хранение в РК, шифрование каналов", "Срок жизни аккаунта", ""),
    "verification": ("Верификация участников и водителей", "ИИН, документы, данные ВУ", "Согласие на верификацию",
                     "", False, "", "Шифрование полей ИИН и ВУ, доступ модераторов по роли", "Срок действия документов + 3 года", ""),
    "registry_checks": ("Проверка по реестрам", "БИН/ИИН", "Согласие на верификацию; запрос пользователя",
                        "Коммерческий источник реестровых данных (РК)", False, "", "Минимум данных в запросе, журнал вызовов",
                        "90 дней (результат)", "registry"),
    "sms": ("Коды подтверждения и уведомления", "Номер телефона", "Договор; безопасность аккаунта",
            "SMS-провайдер (РК)", False, "", "Текст без ПДн, только событие и ссылка", "Журнал 90 дней", "sms"),
    "email": ("Уведомления по e-mail", "E-mail", "Договор", "Почтовый провайдер (РК)", False, "",
              "Текст без ПДн", "Журнал 90 дней", "email"),
    "push": ("Push-уведомления", "Идентификатор устройства", "Согласие в браузере", "Сервис push браузера",
             True, "US, EU", "Только событие и ссылка, без ПДн", "Журнал 90 дней", "push"),
    "telegram": ("Уведомления в Telegram", "Идентификатор чата", "Согласие пользователя (привязка бота)",
                 "Telegram Messenger Inc.", True, "AE, NL, SG", "Только событие и ссылка, без ПДн; отключается в профиле",
                 "Журнал 90 дней", "telegram"),
    "biometrics": ("Биометрическая проверка водителя", "Селфи, фото документа, результат сверки",
                   "Отдельное согласие на биометрию", "Провайдер биометрической сверки (РК)", False, "",
                   "Хранится только результат; изображения удаляются через 24 ч", "Результат — 1 год", "biometrics"),
    "geolocation": ("Трекинг рейса", "Геопозиция водителя", "Отдельное согласие на время рейса", "", False, "",
                    "Только во время рейса, отключается после выгрузки", "Срок хранения сделки", ""),
}

_cache: dict = {"at": 0.0, "adapters": None}


def seed(db: Session) -> None:
    have = set(db.execute(select(ProcessingRecord.code)).scalars())
    for code, (purpose, cats, basis, recipient, xb, countries, safeguards, retention, adapter) in DEFAULT_RECORDS.items():
        if code not in have:
            db.add(ProcessingRecord(code=code, purpose=purpose, data_categories=cats, legal_basis=basis,
                                    recipient=recipient, cross_border=xb, countries=countries, safeguards=safeguards,
                                    retention=retention, adapter=adapter))
    db.flush()
    invalidate()


def invalidate() -> None:
    _cache["at"] = 0.0


def registered_adapters() -> set[str]:
    """Adapters allowed to send personal data out (cached for a minute in each process)."""
    if _cache["adapters"] is not None and time.monotonic() - _cache["at"] < 60:
        return _cache["adapters"]
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        names = set(db.execute(select(ProcessingRecord.adapter).where(ProcessingRecord.active.is_(True),
                                                                      ProcessingRecord.adapter != "")).scalars())
    except Exception:  # noqa: BLE001 — table not migrated yet: nothing is registered
        names = set()
    finally:
        db.close()
    _cache.update(at=time.monotonic(), adapters=names)
    return names


def records(db: Session, *, active_only: bool = False) -> list[ProcessingRecord]:
    q = select(ProcessingRecord).order_by(ProcessingRecord.code)
    if active_only:
        q = q.where(ProcessingRecord.active.is_(True))
    return list(db.execute(q).scalars())
