"""Database initialisation and reference data (appendix 57.1)."""
from __future__ import annotations

import json
import logging
import threading
from datetime import date

from sqlalchemy import select

import app.models  # noqa: F401 — registers all tables
from app.config import settings
from app.db import Base, SessionLocal, engine
from app.modules.billing.models import Tariff
from app.modules.documents.models import DocumentTemplate
from app.modules.platform.models import DictionaryItem, FeatureFlag, PlatformSetting

log = logging.getLogger("abdex.bootstrap")

DICTIONARIES: dict[str, list[tuple]] = {
    # code, name_ru, name_kk, extra
    "body_types": [
        ("tent", "Тент", "Тент"), ("refrigerator", "Рефрижератор", "Рефрижератор"),
        ("isotherm", "Изотерм", "Изотерм"), ("board", "Борт", "Борт"), ("dump", "Самосвал", "Өзітүсіргіш"),
        ("container", "Контейнеровоз", "Контейнер тасығыш"), ("car_carrier", "Автовоз", "Автовоз"),
        ("tank", "Цистерна", "Цистерна"), ("platform", "Площадка", "Алаң"), ("trawl", "Трал", "Трал"),
    ],
    "cargo_types": [
        ("general", "Генеральный", "Жалпы"), ("liquid", "Наливной", "Құйылатын"), ("bulk", "Насыпной", "Үйілмелі"),
        ("oversize", "Негабаритный", "Габаритсіз"), ("dangerous", "Опасный", "Қауіпті"),
        ("perishable", "Скоропортящийся", "Тез бұзылатын"), ("valuable", "Ценный", "Құнды"),
    ],
    "adr_classes": [
        ("1", "1 — Взрывчатые вещества", "1 — Жарылғыш заттар"), ("2", "2 — Газы", "2 — Газдар"),
        ("3", "3 — Легковоспламеняющиеся жидкости", "3 — Тез тұтанатын сұйықтар"),
        ("4", "4 — Легковоспламеняющиеся твердые вещества", "4 — Тез тұтанатын қатты заттар"),
        ("5", "5 — Окисляющие вещества", "5 — Тотықтырғыш заттар"), ("6", "6 — Токсичные вещества", "6 — Улы заттар"),
        ("7", "7 — Радиоактивные материалы", "7 — Радиоактивті материалдар"),
        ("8", "8 — Коррозионные вещества", "8 — Коррозиялық заттар"), ("9", "9 — Прочие", "9 — Басқалары"),
    ],
    "currencies": [("KZT", "Тенге", "Теңге"), ("USD", "Доллар США", "АҚШ доллары"), ("EUR", "Евро", "Еуро"),
                   ("RUB", "Российский рубль", "Ресей рублі"), ("CNY", "Юань", "Юань")],
    "countries": [("KZ", "Казахстан", "Қазақстан"), ("CN", "Китай", "Қытай"), ("RU", "Россия", "Ресей"),
                  ("UZ", "Узбекистан", "Өзбекстан"), ("KG", "Кыргызстан", "Қырғызстан"),
                  ("BY", "Беларусь", "Беларусь"), ("TM", "Туркменистан", "Түрікменстан")],
    "border_crossings": [("khorgos", "Хоргос (КЗ—КНР)", "Қорғас (ҚЗ—ҚХР)"),
                         ("dostyk", "Достык — Алашанькоу", "Достық — Алашаңкоу"),
                         ("bakhty", "Бахты — Чугучак", "Бақты — Шәуешек"),
                         ("zhibek_zholy", "Жибек жолы (КЗ—УЗ)", "Жібек жолы (ҚЗ—ӨЗ)"),
                         ("kordai", "Кордай (КЗ—КГ)", "Қордай (ҚЗ—ҚР)"),
                         ("syrym", "Сырым (КЗ—РФ)", "Сырым (ҚЗ—РФ)")],
    "verification_reject_reasons": [
        ("unreadable", "Документ нечитаемый", "Құжат оқылмайды"),
        ("expired", "Срок действия документа истек", "Құжаттың мерзімі өткен"),
        ("mismatch", "Данные не совпадают с реестром", "Деректер тізіліммен сәйкес емес"),
        ("incomplete", "Неполный комплект документов", "Құжаттар толық емес"),
        ("ok", "Проверка пройдена", "Тексеруден өтті"),
    ],
    "cancel_reasons": [("plans_changed", "Изменились планы", "Жоспар өзгерді"),
                       ("no_bids", "Нет подходящих предложений", "Қолайлы ұсыныс жоқ"),
                       ("found_elsewhere", "Перевозка найдена вне площадки", "Тасымал басқа жерден табылды"),
                       ("error", "Ошибка в заявке", "Өтінімдегі қате")],
    "failure_reasons": [("vehicle_breakdown", "Поломка ТС", "КҚ бұзылуы"), ("driver_absent", "Нет водителя", "Жүргізуші жоқ"),
                        ("better_offer", "Взят другой заказ", "Басқа тапсырыс алынды")],
    "dispute_subjects": [("payment", "Оплата", "Төлем"), ("damage", "Повреждение груза", "Жүктің бүлінуі"),
                         ("delay", "Срыв сроков", "Мерзімнің бұзылуы"), ("downtime", "Простой", "Тұрып қалу"),
                         ("documents", "Документы", "Құжаттар"),
                         ("carrier_refusal", "Отказ перевозчика от рейса", "Тасымалдаушының рейстен бас тартуы"),
                         ("other", "Другое", "Басқа")],
    "incident_kinds": [("delay", "Задержка", "Кешігу"), ("breakdown", "Поломка", "Бұзылу"), ("accident", "ДТП", "ЖКО"),
                       ("refused", "Отказ в приемке", "Қабылдаудан бас тарту"), ("downtime", "Простой", "Тұрып қалу")],
    "support_categories": [
        ("account", "Доступ и аккаунт", "Қолжетімділік және аккаунт", {"sla_hours": 8, "priority": "high"}),
        ("order", "Заявки и предложения", "Өтінімдер мен ұсыныстар", {"sla_hours": 12, "priority": "normal"}),
        ("deal", "Исполнение сделки", "Мәмілені орындау", {"sla_hours": 4, "priority": "high"}),
        ("payment", "Оплата и документы", "Төлем және құжаттар", {"sla_hours": 24, "priority": "normal"}),
        ("driver", "Вопрос водителя", "Жүргізуші сұрағы", {"sla_hours": 4, "priority": "high"}),
        ("idea", "Предложение по сервису", "Сервис бойынша ұсыныс", {"sla_hours": 72, "priority": "low"}),
    ],
    "expense_items": [("fuel", "Топливо", "Жанармай"), ("per_diem", "Суточные", "Тәуліктік"),
                      ("tolls", "Платные дороги", "Ақылы жолдар"), ("loading", "ПРР", "Тиеу-түсіру"),
                      ("parking", "Стоянки", "Тұрақтар"), ("amortization", "Амортизация", "Амортизация"),
                      ("other", "Прочее", "Басқа")],
    "calc_coefficients": [
        ("fuel_per_100_km", "Расход топлива, л/100 км", "Жанармай шығыны", {"value": 32}),
        ("diesel_price_kzt", "Цена ДТ, ₸/л", "ДО бағасы", {"value": 310}),
        ("driver_per_diem_kzt", "Суточные водителя, ₸/сут", "Жүргізуші тәуліктігі", {"value": 15000}),
        ("amortization_per_km_kzt", "Амортизация, ₸/км", "Амортизация", {"value": 60}),
        ("tax_rate", "Налоговая нагрузка (доля)", "Салық жүктемесі", {"value": 0.03}),
        ("base_rate_tent", "Базовая ставка тент, ₸/км", "Тент базалық мөлшерлемесі", {"value": 450}),
        ("base_rate_refrigerator", "Базовая ставка реф, ₸/км", "Реф базалық мөлшерлемесі", {"value": 600}),
        ("base_rate_isotherm", "Базовая ставка изотерм, ₸/км", "Изотерм мөлшерлемесі", {"value": 520}),
        ("base_rate_tank", "Базовая ставка цистерна, ₸/км", "Цистерна мөлшерлемесі", {"value": 650}),
        ("base_rate_container", "Базовая ставка контейнер, ₸/км", "Контейнер мөлшерлемесі", {"value": 500}),
        ("surcharge_urgent", "Надбавка за срочность", "Шұғылдық үстемесі", {"value": 0.2}),
        ("surcharge_temperature", "Надбавка за температурный режим", "Температура үстемесі", {"value": 0.15}),
        ("surcharge_adr", "Надбавка ADR", "ADR үстемесі", {"value": 0.3}),
        ("surcharge_oversize", "Надбавка за негабарит", "Габаритсіз үстемесі", {"value": 0.4}),
        ("surcharge_season", "Сезонная надбавка", "Маусымдық үстеме", {"value": 0.1}),
    ],
    "income_types": [
        ("platform_fee_fixed", "Платформенное вознаграждение фиксированное", "Тіркелген платформалық сыйақы"),
        ("platform_fee_variable", "Платформенное вознаграждение переменное", "Ауыспалы платформалық сыйақы"),
        ("digital_modules", "Платные цифровые модули", "Ақылы цифрлық модульдер"),
        ("subscription", "Абонентская плата", "Абоненттік төлем"),
        ("other_non_priority", "Прочее (неприоритетное)", "Басқа (басым емес)"),
    ],
}

SETTINGS = {
    "platform.role_explanation": (
        {"ru": "AbdEX — оператор онлайн-площадки, а не перевозчик и не экспедитор. Договор перевозки заключается "
               "напрямую между клиентом и перевозчиком. Вознаграждение платформы взимается за предоставление "
               "программно-технических возможностей для оформления сделки: верификацию участников, фиксацию "
               "условий, документы и цифровую историю.",
         "kk": "AbdEX — тасымалдаушы немесе экспедитор емес, онлайн-алаң операторы. Тасымалдау шарты клиент пен "
               "тасымалдаушы арасында тікелей жасалады. Платформа сыйақысы мәмілені ресімдеуге арналған "
               "бағдарламалық-техникалық мүмкіндіктер үшін алынады."},
        "FR-PVD-05: пояснение о роли платформы"),
    "antifraud.risk_threshold": (50, "Порог риска для ручной проверки сделки"),
    "sla.moderation_hours": (24, "SLA модерации верификации, ч"),
    "orders.default_bidding_hours": (24, "Срок сбора предложений по умолчанию, ч"),
    "moderation.min_rate_per_km_minor": (15000, "Минимальная ставка за км (тиын) для автопроверки"),
    "moderation.manual_on_warning": (True, "Оставлять заявку на ручной модерации при предупреждениях"),
    "kyc.l1_deal_limit_minor": (300_000_000, "Лимит суммы сделки для уровня L1 (тиын)"),
    "billing.payment_days": (5, "Срок оплаты счета на вознаграждение, дней"),
    "billing.debt_threshold_minor": (10_000_000, "Порог задолженности для ограничения (тиын)"),
    "billing.grace_days": (10, "Льготный период по просрочке, дней"),
    "billing.reference_fixed_fee_minor": (3_500_000, "Ориентир фиксированного вознаграждения (тиын)"),
    "billing.vat_note": ("Без НДС", "Отметка об НДС в счетах"),
    "chat.leak_mode": ("flag", "Реакция на контакты в чате: flag / mask"),
    "rating.formula": ({"w_reviews": 0.6, "w_reliability": 0.4, "neutral_review": 4.0, "window_days": 365,
                        "penalty": {"breakdown": 3.0, "late_delivery": 1.0, "doc_rejected": 0.5, "dispute_lost": 2.0}},
                       "FR-RAT-01: формула рейтинга (веса и штрафы)"),
    "rating.breakdown_limit": ({"count": 3, "days": 90, "restrict_days": 30},
                               "FR-BID-08: порог срывов и срок ограничения подачи предложений"),
    "matching.weights": ({"body": 25, "geo": 20, "history": 15, "rating": 20, "level": 10, "load": 10},
                         "FR-BID-04: веса скоринга автоподбора перевозчиков"),
    "platform.requisites": ({"name": "ТОО «AbdEX»", "bin": "000000000000", "address": "г. Алматы",
                             "iik": "KZ000000000000000000", "bank": "", "bik": "", "vat_payer": False},
                            "FR-BIL-07: реквизиты оператора площадки для счетов, актов и ЭСФ"),
    "transport_docs.rules": ({"domestic": ["e_waybill"], "international": ["cmr_form", "e_waybill"]},
                             "GOV-TR-04: какие транспортные документы формируются по направлению перевозки"),
    "biometrics.image_ttl_hours": (24, "SEC-DAT-10: срок хранения исходных изображений биометрии, ч"),
    "impersonation.minutes": (30, "FR-ADM-05: длительность сеанса работы от имени пользователя, мин"),
    "ratelimit.limits": ({"bid": [60, 3600], "order_create": [100, 3600], "export": [20, 3600], "login": [10, 300]},
                         "SEC-APP-07: лимиты действий {корзина: [число, окно в секундах]}"),
    "retention.policies": ({"otp_codes": 7, "sessions": 180, "notifications": 365, "outbox": 90, "device_events": 180,
                            "product_events": 400, "idempotency_keys": 30, "webhook_deliveries": 90,
                            "invitations": 90, "support_grants": 365, "track_points": 90},
                           "SEC-DAT-06: сроки хранения по категориям, дней (0 — не удалять)"),
    "security.thresholds": ({"failed_logins": 5, "bulk_exports_per_hour": 5, "access_denied_per_hour": 20,
                             "work_from": 8, "work_to": 20, "timezone": "Asia/Almaty"},
                            "SEC-LOG-06: пороги корреляции событий безопасности"),
    "calc.forecast_window_days": (365, "FR-CALC-06: за сколько дней брать сделки для прогноза"),
    "calc.forecast_min_deals": (3, "FR-CALC-06: минимум сделок по направлению для показа прогноза"),
    "calc.forecast_min_companies": (2, "FR-CALC-06: минимум разных заказчиков в выборке (цена одной компании не раскрывается)"),
    "kyc.l3_required_for": (["international", "valuable"],
                            "Раздел 8: какие грузы доступны только перевозчикам уровня L3 (international, valuable)"),
    "kyc.reverify": ({"new_device": True, "geo_km": 300, "break_days": 90, "block_trips": True},
                     "FR-KYC-09: признаки повторной проверки водителя — новое устройство, удаление от маршрута (км), "
                     "перерыв в рейсах (дней); блокировать ли рейсы до проверки"),
    "customs.rules": ({"groups": {"eaeu": ["RU", "BY", "KG", "AM"], "china": ["CN"],
                                  "cis": ["UZ", "TJ", "TM", "AZ", "GE", "MD"]},
                       "eaeu": {"customs": False,
                                "fields": ["goods_description", "gross_kg", "places", "invoice_number", "invoice_value",
                                           "invoice_currency", "consignee_name", "consignee_country"],
                                "documents": ["cmr", "commercial_invoice"]},
                       "china": {"customs": True,
                                 "fields": ["hs_code", "goods_description", "gross_kg", "net_kg", "places",
                                            "invoice_number", "invoice_date", "invoice_value", "invoice_currency",
                                            "origin_country", "consignee_name", "consignee_address", "consignee_country",
                                            "transit_mode", "border_crossing"],
                                 "documents": ["cmr", "commercial_invoice", "packing_list", "origin_certificate"]},
                       "cis": {"customs": True,
                               "fields": ["hs_code", "goods_description", "gross_kg", "net_kg", "places",
                                          "invoice_number", "invoice_date", "invoice_value", "invoice_currency",
                                          "origin_country", "consignee_name", "consignee_address", "consignee_country",
                                          "transit_mode", "border_crossing"],
                               "documents": ["cmr", "commercial_invoice", "packing_list", "origin_certificate"]}},
                      "GOV-TR-06: состав таможенных сведений и документов по группам стран назначения"),
    "security.vuln_status": ("CI: pip-audit, bandit, gitleaks — без замечаний высокого уровня",
                             "SEC-LOG-08: статус уязвимостей для ежемесячного отчета"),
}

FLAGS = [
    ("digital_modules", "Платные цифровые модули (пилот не ранее 17-го месяца)", False),
    ("subscriptions", "Абонентская плата", False),
    ("integration.routing", "Картографический сервис", True),
    ("integration.registry", "Проверка по реестрам (коммерческий источник)", True),
    ("integration.telegram", "Telegram-бот", True),
    ("gov.services", "Государственные сервисы через ШЭП/Smart Bridge", False),
    ("qualified_signature", "Подписание ЭЦП НУЦ РК", False),
    ("online_payments", "Онлайн-оплата счетов через платежного провайдера", False),
    ("gov.etd", "Регистрация электронных транспортных документов в госсистеме", False),
    ("auth.eds_login", "Вход через ЭЦП НУЦ РК (FR-AUTH-09)", False),
    ("auth.egov_mobile", "Вход через eGov mobile — QR и подпись в приложении (FR-AUTH-09)", False),
    ("eds.egov_mobile", "Подписание документов сделки в eGov mobile / eGov Business по QR (FR-DOC-07)", False),
    ("gov.esf", "Отправка ЭСФ и АВР в ИС ЭСФ (FR-BIL-07)", False),
    ("matching.ai", "ИИ-подбор: веса подбора обучаются на истории выбора заказчиков (FR-BID-09)", False),
    ("calc.forecast", "Прогноз стоимости по направлению — включается подпиской на модуль (FR-CALC-06)", False),
]

# FR-BIL-08: modules on sale; prices and terms are edited in /admin/modules. Sales are opened by the
# "digital_modules" / "subscriptions" flags (pilot not before month 17, FR-PVD-07).
MODULES = [
    {"code": "forecast", "name": "Прогноз стоимости по направлениям", "flag_key": "calc.forecast",
     "description": "Медиана и диапазон цен по накопленным сделкам площадки, ставка за км, тренд за 90 дней.",
     "price_minor": 500_000, "period_days": 30, "income_type": "digital_modules", "audience": "any"},
]

TEMPLATES = {
    ("contract_order", "ru"): (
        "Договор-заявка № ${number} на перевозку груза",
        """Дата: ${date}
Сделка: ${deal_number} (заявка ${order_number})

## Стороны
Заказчик (грузоотправитель): ${client_name}, БИН ${client_bin}, ${client_address}
Перевозчик: ${carrier_name}, БИН/ИИН ${carrier_bin}, ${carrier_address}
Оператор онлайн-площадки: AbdEX. Оператор площадки не является стороной договора перевозки, не является перевозчиком и экспедитором и предоставляет сторонам программно-технические возможности для оформления сделки.

## Предмет
Перевозчик обязуется доставить вверенный ему груз по маршруту: ${route}.
Груз: ${cargo}; вес ${weight} кг; объем ${volume} м³; мест ${places}.
Дата погрузки: ${load_date}. Срок выгрузки: ${unload_date}.
Транспортное средство: ${vehicle}. Водитель: ${driver}.

## Стоимость и оплата
Стоимость перевозки: ${price}. Условия оплаты: ${payment_terms}.
Оплата производится Заказчиком непосредственно Перевозчику.

## Фиксация условий
Условия зафиксированы на площадке AbdEX в неизменяемом снапшоте; хеш условий: ${snapshot_hash}.
Изменение условий возможно только дополнительным соглашением с акцептом второй стороны на площадке.

## Подписи
Документ подписывается сторонами простой электронной подписью на площадке AbdEX с фиксацией времени, пользователя, IP-адреса и хеша документа."""),
    ("contract_order", "kk"): (
        "Жүкті тасымалдауға арналған № ${number} шарт-өтінім",
        """Күні: ${date}
Мәміле: ${deal_number} (өтінім ${order_number})

## Тараптар
Тапсырыс беруші: ${client_name}, БСН ${client_bin}
Тасымалдаушы: ${carrier_name}, БСН/ЖСН ${carrier_bin}
Онлайн-алаң операторы: AbdEX. Алаң операторы тасымалдау шартының тарапы болып табылмайды және тараптарға мәмілені ресімдеуге бағдарламалық-техникалық мүмкіндіктер ұсынады.

## Мәні
Бағыт: ${route}. Жүк: ${cargo}; салмағы ${weight} кг.
Тиеу күні: ${load_date}. Түсіру мерзімі: ${unload_date}.
Көлік құралы: ${vehicle}. Жүргізуші: ${driver}.

## Құны
Тасымалдау құны: ${price}. Төлем шарттары: ${payment_terms}.
Шарттар хеші: ${snapshot_hash}."""),
    ("e_waybill", "ru"): (
        "Товарно-транспортная накладная № ${number}",
        """Дата составления: ${date}. Сделка ${deal_number} (заявка ${order_number}).

## Грузоотправитель
${shipper_name}, БИН ${shipper_bin}, ${shipper_address}

## Грузополучатель
${consignee}

## Перевозчик
${carrier_name}, БИН/ИИН ${carrier_bin}
Транспортное средство: ${vehicle}${trailer}. Водитель: ${driver}, ВУ ${driver_license}

## Маршрут
Пункт погрузки: ${load_point}, дата ${load_date}
Пункт разгрузки: ${unload_point}, срок ${unload_date}

## Груз
Наименование: ${cargo}. Упаковка: ${packaging}. Мест: ${places}. Вес брутто: ${weight} кг. Объем: ${volume} м³.
Опасный груз: ${adr}

## Отметки
Груз сдал: ____________   Груз принял к перевозке: ____________   Груз получил: ____________
Электронная регистрация: ${registration}"""),
    ("cmr_form", "ru"): (
        "Международная товарно-транспортная накладная CMR № ${number}",
        """Дата: ${date}. Сделка ${deal_number}. Перевозка по Конвенции КДПГ (CMR).

## 1. Отправитель
${shipper_name}, ${shipper_address}, ${shipper_country}

## 2. Получатель
${consignee}

## 3–4. Место разгрузки / место и дата погрузки
${unload_point} / ${load_point}, ${load_date}

## 6–12. Груз
${cargo}; упаковка ${packaging}; мест ${places}; вес брутто ${weight} кг; объем ${volume} м³; ADR: ${adr}

## 16. Перевозчик
${carrier_name}, БИН/ИИН ${carrier_bin}; ТС ${vehicle}${trailer}; водитель ${driver}

## 18. Пункт пропуска
${border}

Подписи и печати: отправитель ________  перевозчик ________  получатель ________"""),
    ("fee_invoice", "ru"): (
        "Счет на оплату № ${number} от ${date}",
        """Поставщик: AbdEX — оператор онлайн-площадки
Покупатель: ${client_name}, БИН ${client_bin}

## Предмет
${subject}

Сумма к оплате: ${amount}
${vat_note}
Срок оплаты: до ${due_date}

Основание: оформленная на площадке сделка № ${deal_number}."""),
    ("customs_info", "ru"): (
        "Сведения для таможенного оформления № ${number} от ${date}",
        """Сделка ${deal_number} (заявка ${order_number}); маршрут: ${route}

## Отправитель
${shipper_name}, БИН ${shipper_bin}

## Получатель
${consignee_name}; ${consignee_address}; страна ${consignee_country}; налоговый номер ${consignee_tax_id}

## Товар
Код ТН ВЭД ЕАЭС: ${hs_code}
Наименование: ${goods_description}
Вес брутто ${gross_kg} кг, нетто ${net_kg} кг; мест ${places}; упаковка ${packaging}
Страна происхождения: ${origin_country}

## Инвойс
№ ${invoice_number} от ${invoice_date}; стоимость ${invoice_value} ${invoice_currency}

## Транспорт
Перевозчик ${carrier_name}, БИН ${carrier_bin}; прицеп ${trailer_plate}
Транзит: ${transit_mode}; книжка МДП ${tir_carnet}; транзитная декларация ${transit_declaration}
Пункт пропуска: ${border_crossing}"""),
    ("module_invoice", "ru"): (
        "Счет на оплату № ${number} от ${date}",
        """Поставщик: AbdEX — оператор онлайн-площадки
Покупатель: ${client_name}, БИН ${client_bin}

## Предмет
${subject}

Сумма к оплате: ${amount}
${vat_note}
Срок оплаты: до ${due_date}

Основание: подключение цифрового модуля «${module}» на период ${period}."""),
    # FR-LOC-05: the language of a financial document follows the recipient company's setting
    ("fee_invoice", "kk"): (
        "Төлем шоты № ${number}, ${date}",
        """Жеткізуші: AbdEX — онлайн-алаң операторы
Сатып алушы: ${client_name}, БСН ${client_bin}

## Мәні
${subject}

Төленетін сома: ${amount}
${vat_note}
Төлеу мерзімі: ${due_date} дейін

Негіздеме: алаңда рәсімделген № ${deal_number} мәміле."""),
    ("fee_act", "kk"): (
        "Көрсетілген қызметтер актісі № ${number}, ${date}",
        """Орындаушы: AbdEX — онлайн-алаң операторы
Тапсырыс беруші: ${client_name}, БСН ${client_bin}

## Атауы
${subject}

Құны: ${amount}. ${vat_note}
Қызметтер толық көлемде көрсетілді, тараптардың бір-біріне наразылығы жоқ."""),
    ("module_invoice", "kk"): (
        "Төлем шоты № ${number}, ${date}",
        """Жеткізуші: AbdEX — онлайн-алаң операторы
Сатып алушы: ${client_name}, БСН ${client_bin}

## Мәні
${subject}

Төленетін сома: ${amount}
${vat_note}
Төлеу мерзімі: ${due_date} дейін

Негіздеме: «${module}» цифрлық модулін ${period} кезеңге қосу."""),
    ("fee_act", "ru"): (
        "Акт оказанных услуг № ${number} от ${date}",
        """Исполнитель: AbdEX — оператор онлайн-площадки
Заказчик: ${client_name}, БИН ${client_bin}

## Наименование
${subject}

Стоимость: ${amount}. ${vat_note}
Услуги оказаны в полном объеме, стороны претензий не имеют."""),
}


_init_lock = threading.Lock()
_initialized = False


def ensure_initialized() -> None:
    """Idempotent, safe to call on every request (serverless runtimes may skip lifespan)."""
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if not _initialized:
            init_db()
            _initialized = True


def _migrate() -> None:
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(cfg, "head")


def _ratelimit_loader() -> dict:
    db = SessionLocal()
    try:
        from app.modules.platform.service import get_setting

        return get_setting(db, "ratelimit.limits", {}) or {}
    finally:
        db.close()


def init_db() -> None:
    from app.core import ratelimit

    ratelimit.loader = _ratelimit_loader
    if settings.database_url.startswith("sqlite"):
        Base.metadata.create_all(engine)
        _init_data()
        return
    # PostgreSQL: several instances may start at once (serverless cold starts, rolling deploys); one at a time
    # migrates and seeds, the others wait and then find everything in place.
    from sqlalchemy import text

    # A transaction-level lock: also correct behind a transaction-mode pooler (Neon, PgBouncer); it is released
    # when this transaction ends, whatever happens below.
    with engine.connect() as lock_conn, lock_conn.begin():
        lock_conn.execute(text("SELECT pg_advisory_xact_lock(7302915)"))
        if settings.auto_migrate:
            _migrate()  # otherwise PostgreSQL is migrated by `alembic upgrade head` at deploy
        _init_data()


def _init_data() -> None:
    db = SessionLocal()
    try:
        seed_reference(db)
        from app.cli import check_data_origin

        check_data_origin(db)  # SEC-DAT-09
        db.commit()
        if settings.seed_demo_data:
            from app.demo import seed_demo

            seed_demo(db)
    finally:
        db.close()
        from app.modules.integrations.base import flush_journal

        flush_journal()


def seed_reference(db) -> None:
    for dictionary, items in DICTIONARIES.items():
        existing = set(db.execute(select(DictionaryItem.code).where(DictionaryItem.dictionary == dictionary)).scalars())
        for i, item in enumerate(items):
            code, ru, kk = item[:3]
            extra = item[3] if len(item) > 3 else {}
            if code not in existing:
                db.add(DictionaryItem(dictionary=dictionary, code=code, name_ru=ru, name_kk=kk,
                                      extra=json.dumps(extra, ensure_ascii=False), sort=i * 10))
    existing = set(db.execute(select(PlatformSetting.key)).scalars())
    for key, (value, desc) in SETTINGS.items():
        if key not in existing:
            db.add(PlatformSetting(key=key, value=json.dumps(value, ensure_ascii=False), description=desc))
    existing = set(db.execute(select(FeatureFlag.key)).scalars())
    for key, desc, enabled in FLAGS:
        if key not in existing:
            db.add(FeatureFlag(key=key, description=desc, enabled=enabled))
    for (doc_type, locale), (title, body) in TEMPLATES.items():
        found = db.execute(select(DocumentTemplate.id).where(DocumentTemplate.doc_type == doc_type,
                                                            DocumentTemplate.locale == locale)).first()
        if not found:
            db.add(DocumentTemplate(doc_type=doc_type, locale=locale, version=1, title=title, body=body,
                                    valid_from=date(2026, 1, 1)))
    from app.modules.billing.models import DigitalModule

    have = set(db.execute(select(DigitalModule.code)).scalars())
    for m in MODULES:
        if m["code"] not in have:
            db.add(DigitalModule(**m))
    from app.modules.accounts.acl import seed as seed_acl

    seed_acl(db)
    from app.modules.platform.antifraud import seed as seed_antifraud

    seed_antifraud(db)
    from app.modules.platform.processing import seed as seed_processing

    seed_processing(db)
    if not db.execute(select(Tariff.id).where(Tariff.company_id.is_(None))).first():
        db.add(Tariff(name="Базовый: фиксированное вознаграждение", model="fixed", fixed_minor=3_500_000,
                      valid_from=date(2026, 1, 1)))
