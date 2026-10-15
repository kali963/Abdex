"""Unit tests of business rules — run without the HTTP layer (NFR-ARC-02, OPS-20)."""
from __future__ import annotations

from datetime import date

import pytest

from app.core.money import format_money, percent_of, round_minor, to_minor
from app.core.security import hash_password, password_problems, sign_payload, verify_password, verify_signed_payload
from app.modules.accounts.service import validate_bin
from app.modules.billing.models import Tariff
from app.modules.billing.service import FEE_SUBJECT, compute_fee
from app.modules.chat.leaks import mask_contacts
from app.modules.documents.service import validate_template_body
from app.core.errors import ValidationFailed
from app.modules.orders import flow
from app.demo import make_bin


# ------------------------------------------------------------------ status machine (FR-FLOW-01)

def test_transition_table_matches_spec():
    expected = {
        ("draft", "moderation"), ("moderation", "published"), ("moderation", "draft"), ("published", "bidding"),
        ("bidding", "assigned"), ("bidding", "cancelled"), ("assigned", "docs_signed"), ("docs_signed", "loading"),
        ("loading", "in_transit"), ("in_transit", "unloaded"), ("unloaded", "closed_docs"),
        ("closed_docs", "fee_invoiced"), ("fee_invoiced", "completed"), ("assigned", "dispute"),
        ("in_transit", "dispute"), ("unloaded", "dispute"), ("dispute", "closed_docs"), ("dispute", "cancelled"),
        ("draft", "cancelled"), ("published", "cancelled"),
    }
    assert set(flow.TRANSITIONS) == expected


def test_every_status_reachable_and_final_states_closed():
    targets = {to for _, to in flow.TRANSITIONS}
    assert set(flow.ALL_STATUSES) - {"draft"} <= targets
    for final in flow.FINAL:
        assert not [k for k in flow.TRANSITIONS if k[0] == final]


def test_role_restrictions():
    assert flow.can("dispute", "closed_docs", flow.MANAGER)
    assert not flow.can("dispute", "closed_docs", flow.CLIENT)
    assert not flow.can("bidding", "assigned", flow.CLIENT)  # only through the acceptance service
    assert flow.TRANSITIONS[("moderation", "draft")].reason_required


# ------------------------------------------------------------------ money (FR-CALC-04)

def test_money_minor_units_and_rounding():
    assert to_minor("35 000") == 3_500_000
    assert to_minor("1234,567") == 123457  # ROUND_HALF_UP in one place
    assert round_minor(2.5) == 3
    assert percent_of(10_000_000, 300) == 300_000
    assert format_money(3_500_000).replace(" ", " ") == "35 000 ₸"
    with pytest.raises(ValueError):
        to_minor("-5")


# ------------------------------------------------------------------ billing (FR-BIL-01, FR-PVD-03)

def _tariff(**kw):
    base = dict(name="t", model="fixed", fixed_minor=3_500_000, percent_bp=0, min_minor=0, max_minor=0,
                currency="KZT", valid_from=date(2026, 1, 1))
    base.update(kw)
    return Tariff(**base)


def test_fee_models():
    assert compute_fee(_tariff(), 50_000_000)[:2] == (3_500_000, "platform_fee_fixed")
    amount, income, _ = compute_fee(_tariff(model="percent", percent_bp=300, min_minor=1_500_000), 30_000_000)
    assert (amount, income) == (1_500_000, "platform_fee_variable")  # 3% = 9 000 ₸ < min 15 000 ₸
    amount, _, _ = compute_fee(_tariff(model="combined", fixed_minor=1_000_000, percent_bp=100, max_minor=1_200_000),
                               50_000_000)
    assert amount == 1_200_000


def test_financial_wording_enforced():
    validate_template_body("fee_invoice", FEE_SUBJECT.format(deal="SD-1"))
    for bad in ("Услуги перевозки груза", "экспедирование", "Доставка груза по маршруту"):
        with pytest.raises(ValidationFailed):
            validate_template_body("fee_act", bad)
    with pytest.raises(ValidationFailed):
        validate_template_body("contract_order", "AbdEX выступает перевозчиком по настоящему договору.")


# ------------------------------------------------------------------ security primitives

def test_password_policy_and_hashing():
    assert "password.too_short" in password_problems("short")
    assert "password.too_common" in password_problems("qwerty123456")
    assert password_problems("Correct-Horse-Battery-9") == []
    h = hash_password("Correct-Horse-Battery-9")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "Correct-Horse-Battery-9") and not verify_password(h, "wrong")


def test_bin_checksum():
    good = make_bin("16054000123")
    assert validate_bin(good)
    assert not validate_bin(good[:-1] + str((int(good[-1]) + 1) % 10))
    assert not validate_bin("12345")


def test_signed_links_expire_and_bind_payload():
    sig = sign_payload("file-1", ttl_seconds=60)
    assert verify_signed_payload("file-1", sig)
    assert not verify_signed_payload("file-2", sig)
    assert not verify_signed_payload("file-1", sign_payload("file-1", ttl_seconds=-1))


def test_contact_leak_masking():
    text, leaked = mask_contacts("звоните +7 701 123 45 67 или пишите в телеграм @truck_kz")
    assert leaked and "701" not in text and "@truck_kz" not in text
    assert mask_contacts("Подадим машину к 9 утра")[1] is False
