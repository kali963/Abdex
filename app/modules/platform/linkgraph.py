"""Link graph between companies (SEC-FRD-04).

Two companies are linked when they share a phone, an IBAN, an IIN/BIN, an address, a device, a vehicle or a
member. The graph is built on demand around one company (breadth-first, limited depth and size) and shown to
the moderator as an SVG drawn on the server — values themselves are never shown: an IBAN or IIN is compared
through its blind index, a phone is masked, so the graph reveals the link, not the personal data.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.accounts.models import BankAccount, Company, Membership, User
from app.modules.fleet.models import Driver, Vehicle
from app.modules.platform.models import DeviceEvent

KINDS = ("member", "phone", "iban", "iin", "address", "device", "vehicle")
MAX_NODES = 40


@dataclass
class Graph:
    center: object
    nodes: dict = field(default_factory=dict)  # company id -> Company
    edges: dict = field(default_factory=dict)  # (a, b) sorted -> {kind: count}
    depth_of: dict = field(default_factory=dict)
    truncated: bool = False


def _addr(text: str) -> str:
    return " ".join((text or "").replace(",", " ").replace(".", " ").split()).casefold()


def _members(db: Session, company_ids) -> dict:
    out = defaultdict(set)
    for uid, cid in db.execute(select(Membership.user_id, Membership.company_id)
                               .where(Membership.company_id.in_(company_ids))).all():
        out[cid].add(uid)
    return out


def _neighbours(db: Session, company: Company) -> dict:
    """{other company id: {kind: count}} for one company."""
    found: dict = defaultdict(lambda: defaultdict(int))
    cid = company.id

    def mark(other, kind):
        if other and other != cid:
            found[other][kind] += 1

    users = set(db.execute(select(Membership.user_id).where(Membership.company_id == cid)).scalars())
    # member: the same person in several companies
    if users:
        for other in db.execute(select(Membership.company_id).where(Membership.user_id.in_(users))).scalars():
            mark(other, "member")
    # phone: company contact phone and members' phones against other companies' contact / members' phones
    phones = {p for p in db.execute(select(User.phone).where(User.id.in_(users))).scalars() if p} if users else set()
    if company.contact_phone:
        phones.add(company.contact_phone)
    if phones:
        for other in db.execute(select(Company.id).where(Company.contact_phone.in_(phones))).scalars():
            mark(other, "phone")
        phone_users = set(db.execute(select(User.id).where(User.phone.in_(phones))).scalars()) - users
        if phone_users:
            for other in db.execute(select(Membership.company_id).where(Membership.user_id.in_(phone_users))).scalars():
                mark(other, "phone")
    # iban (blind index)
    ibans = {i for i in db.execute(select(BankAccount.iban_index).where(BankAccount.company_id == cid)).scalars() if i}
    if ibans:
        for other in db.execute(select(BankAccount.company_id).where(BankAccount.iban_index.in_(ibans))).scalars():
            mark(other, "iban")
    # iin: drivers' IIN (blind index) and the company BIN/IIN itself
    iins = {i for i in db.execute(select(Driver.iin_index).where(Driver.company_id == cid)).scalars() if i}
    if iins:
        for other in db.execute(select(Driver.company_id).where(Driver.iin_index.in_(iins))).scalars():
            mark(other, "iin")
    if company.bin_iin:
        for other in db.execute(select(Company.id).where(Company.bin_iin == company.bin_iin)).scalars():
            mark(other, "iin")
    # address (normalised; short placeholders ignored)
    mine = {a for a in (_addr(company.legal_address), _addr(company.actual_address)) if len(a) >= 10}
    if mine:
        for other, legal, actual in db.execute(select(Company.id, Company.legal_address, Company.actual_address)
                                               .where(Company.id != cid)).all():
            if mine & {_addr(legal), _addr(actual)}:
                mark(other, "address")
    # device: the same browser/device used by accounts of different companies
    q = select(DeviceEvent.device_id).where(DeviceEvent.device_id != "")
    q = q.where((DeviceEvent.company_id == cid) | (DeviceEvent.user_id.in_(users))) if users else q.where(DeviceEvent.company_id == cid)
    devices = set(db.execute(q).scalars())
    if devices:
        dev_users, dev_companies = set(), set()
        for uid, dcid in db.execute(select(DeviceEvent.user_id, DeviceEvent.company_id)
                                    .where(DeviceEvent.device_id.in_(devices))).all():
            if dcid:
                dev_companies.add(dcid)
            if uid and uid not in users:
                dev_users.add(uid)
        if dev_users:
            dev_companies |= set(db.execute(select(Membership.company_id).where(Membership.user_id.in_(dev_users))).scalars())
        for other in dev_companies:
            mark(other, "device")
    # vehicle plate registered by several companies
    plates = {p for p in db.execute(select(Vehicle.plate).where(Vehicle.company_id == cid)).scalars() if p}
    if plates:
        for other in db.execute(select(Vehicle.company_id).where(Vehicle.plate.in_(plates))).scalars():
            mark(other, "vehicle")
    return found


def build(db: Session, company_id, *, depth: int = 2, max_nodes: int = MAX_NODES) -> Graph:
    from app.core import rls

    depth = max(1, min(depth, 3))
    with rls.system(db):
        center = db.get(Company, company_id)
        if center is None:
            from app.core.errors import NotFound

            raise NotFound()
        g = Graph(center=center)
        g.nodes[center.id], g.depth_of[center.id] = center, 0
        frontier = [center]
        for level in range(1, depth + 1):
            nxt = []
            for c in frontier:
                for other, kinds in _neighbours(db, c).items():
                    key = tuple(sorted((c.id, other), key=str))
                    if other not in g.nodes:
                        if len(g.nodes) >= max_nodes:
                            g.truncated = True
                            continue
                        oc = db.get(Company, other)
                        if oc is None:
                            continue
                        g.nodes[other], g.depth_of[other] = oc, level
                        nxt.append(oc)
                    merged = g.edges.setdefault(key, {})
                    for k, n in kinds.items():
                        merged[k] = max(merged.get(k, 0), n)
            frontier = nxt
    return g


def layout(g: Graph, size: int | None = None) -> dict:
    """Concentric layout: the company in the middle, each depth on its own ring."""
    n = len(g.nodes)
    size = size or (400 if n <= 3 else 520 if n <= 12 else 640)
    cx = cy = size / 2
    rings = defaultdict(list)
    for nid, d in g.depth_of.items():
        rings[d].append(nid)
    pos = {g.center.id: (cx, cy)}
    max_depth = max(rings) if rings else 0
    for d in range(1, max_depth + 1):
        ids = sorted(rings[d], key=lambda i: g.nodes[i].name)
        radius = (size / 2 - 60) * d / max_depth
        for i, nid in enumerate(ids):
            a = 2 * math.pi * i / max(len(ids), 1) - math.pi / 2 + (d - 1) * 0.35
            pos[nid] = (round(cx + radius * math.cos(a), 1), round(cy + radius * math.sin(a), 1))
    edges = []
    for (a, b), kinds in g.edges.items():
        if a in pos and b in pos:
            (x1, y1), (x2, y2) = pos[a], pos[b]
            strong = bool({"iban", "iin", "device", "vehicle"} & set(kinds))
            edges.append({"x1": x1, "y1": y1, "x2": x2, "y2": y2, "kinds": sorted(kinds), "strong": strong,
                          "mx": round((x1 + x2) / 2, 1), "my": round((y1 + y2) / 2, 1), "a": a, "b": b})
    nodes = [{"id": nid, "x": pos[nid][0], "y": pos[nid][1], "name": g.nodes[nid].name,
              "kind": g.nodes[nid].kind, "blocked": g.nodes[nid].is_blocked, "depth": g.depth_of[nid],
              "center": nid == g.center.id} for nid in pos]
    return {"size": size, "nodes": nodes, "edges": edges}
