"""One-page command centre: the CEO, CIO and CISO boards (ServiceNow ITOM / ITSM style).

Everything a board shows is computed here in one pass over the user's scope, so the page renders on a single
screen without extra queries per widget.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.config import settings
from itam.enums import (
    INSTALLED_STATUSES,
    OUTAGE_CATEGORIES,
    RESPONSE_MINUTES,
    SECURITY_CATEGORIES,
    AlertCategory,
    AlertStatus,
    AssetStatus,
    ChangeStatus,
    ChangeType,
    ExceptionStatus,
    ExceptionType,
    OperState,
    ReadPointKind,
    Severity,
    ShipmentStatus,
)
from itam.geo_cameroon import CENTROIDS, HEIGHT, PATHS, WIDTH, project
from itam.models import (
    Alert,
    Asset,
    Branch,
    ChangeRequest,
    Collector,
    ControlException,
    ReadPoint,
    Shipment,
    User,
    VideoClip,
    utcnow,
)
from itam.rbac import Role, scope_branches
from itam.services.dashboard import branch_states, rfid_kpis

BOARDS = {"ceo": "CEO", "cio": "CIO", "ciso": "CISO"}
INSTALLED = [s.value for s in INSTALLED_STATUSES]
SECURITY = [c.value for c in SECURITY_CATEGORIES] + [AlertCategory.UNAPPROVED_DEVICE.value, AlertCategory.ROGUE_DEVICE.value,
                                                     AlertCategory.DEVICE_SWAPPED.value]
CATEGORY_LABELS = {
    "BRANCH_OFFLINE": "Branch offline", "DEVICE_DOWN": "Device down", "REDUNDANCY_LOST": "Redundancy lost",
    "DEGRADED": "Degraded", "ENVIRONMENT": "Environment", "CONFIG_CHANGE": "Config change",
    "DEVICE_NOT_DISCOVERED": "Not discovered", "DEVICE_SWAPPED": "Device swapped", "ROGUE_DEVICE": "Rogue device",
    "WARRANTY_EXPIRY": "Warranty", "END_OF_LIFE": "End of life", "COLLECTOR_OFFLINE": "Collector offline",
    "UNAPPROVED_DEVICE": "Unapproved device", "SUSPECTED_REMOVAL": "Suspected removal",
    "CABINET_TAG_MISSING": "Cabinet tag missing", "CABINET_DOOR": "Cabinet door", "INTRUSION": "Intrusion",
    "SECURITY_DEVICE_TAMPER": "Reader / camera tamper", "SHIPMENT_VARIANCE": "Delivery variance",
    "SHIPMENT_OVERDUE": "Delivery overdue", "UNEXPLAINED_EXIT": "Unexplained exit",
}


def default_board(user: User) -> str:
    if user.has_role(Role.CISO, Role.INTERNAL_AUDIT):
        return "ciso"
    if user.has_role(Role.CIO, Role.HEAD_INFRA, Role.NOC, Role.IT_ASSET_MANAGER, Role.REGIONAL_LEAD, Role.REGIONAL_IT):
        return "cio"
    return "ceo"


def _pct(n: float, d: float) -> float | None:
    return round(100.0 * n / d, 1) if d else None


def _weeks(now, n: int = 8) -> list[tuple]:
    return [(now - timedelta(days=7 * (w + 1)), now - timedelta(days=7 * w)) for w in range(n - 1, -1, -1)]


def build(db: Session, user: User, board: str) -> dict:
    now = utcnow()
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    ids = [b.id for b in branches] or [-1]
    states = branch_states(db, branches)

    assets = db.execute(select(Asset).where(Asset.branch_id.in_(ids), Asset.status != AssetStatus.DISPOSED.value)).scalars().all()
    alerts_open = db.execute(select(Alert).where(Alert.status != AlertStatus.RESOLVED.value,
                                                 Alert.branch_id.in_(ids) | Alert.branch_id.is_(None))).scalars().all()
    since = now - timedelta(days=56)
    alerts_recent = db.execute(select(Alert).where(Alert.detected_at >= since,
                                                   Alert.branch_id.in_(ids) | Alert.branch_id.is_(None))).scalars().all()
    exc_open = db.execute(select(ControlException).where(
        ControlException.status == ExceptionStatus.OPEN.value,
        ControlException.branch_id.in_(ids) | ControlException.branch_id.is_(None))).scalars().all()

    # --- Regions & branch dots for the map ---------------------------------------------------------------
    regions: dict[str, dict] = {}
    for b in branches:
        r = regions.setdefault(b.region.code, {"code": b.region.code, "name": b.region.name, "branches": 0, "online": 0,
                                               "degraded": 0, "offline": 0, "not_monitored": 0, "alerts": 0, "p1": 0,
                                               "security": 0, "assets": 0, "exceptions": 0})
        r["branches"] += 1
        r[states.get(b.id, "not_monitored")] += 1
    region_of = {b.id: b.region.code for b in branches}
    for a in assets:
        if a.branch_id in region_of:
            regions[region_of[a.branch_id]]["assets"] += 1
    for a in alerts_open:
        code = region_of.get(a.branch_id)
        if code:
            regions[code]["alerts"] += 1
            regions[code]["p1"] += a.severity == Severity.P1.value
            regions[code]["security"] += a.category in SECURITY
    for e in exc_open:
        code = region_of.get(e.branch_id)
        if code:
            regions[code]["exceptions"] += 1
    for r in regions.values():
        monitored = r["online"] + r["degraded"] + r["offline"]
        r["monitored"] = monitored
        r["availability"] = _pct(r["online"] + r["degraded"], monitored)
        r["risk"] = r["security"] * 3 + r["exceptions"]
        cx, cy = CENTROIDS.get(r["code"], (0, 0))
        r["cx"], r["cy"] = cx, cy

    def fill_level(r: dict) -> int:
        """0 = no data, 1 = good … 4 = bad, per the board's map metric."""
        if board == "ciso":
            risk = r["risk"]
            return 1 if risk == 0 else 2 if risk <= 3 else 3 if risk <= 8 else 4
        if r["availability"] is None:
            return 0
        a = r["availability"]
        return 1 if a >= 99.5 else 2 if a >= 97 else 3 if a >= 90 else 4

    shapes = []
    for code, d in PATHS.items():
        r = regions.get(code)
        shapes.append({"code": code, "d": d, "region": r, "level": fill_level(r) if r else 0,
                       "cx": CENTROIDS[code][0], "cy": CENTROIDS[code][1]})
    dots = []
    for b in branches:
        if b.latitude is None or b.longitude is None:
            continue
        x, y = project(b.longitude, b.latitude)
        dots.append({"x": x, "y": y, "state": states.get(b.id, "not_monitored"), "branch": b})
    dots.sort(key=lambda d: ["not_monitored", "online", "degraded", "offline"].index(d["state"]))
    counts_state = Counter(states.values())

    # --- Service health -----------------------------------------------------------------------------------
    monitored = sum(1 for s in states.values() if s != "not_monitored")
    up = sum(1 for s in states.values() if s in ("online", "degraded"))
    installed = [a for a in assets if a.status in INSTALLED and a.monitored]
    healthy = [a for a in installed if a.oper_state == OperState.UP.value and a.status == AssetStatus.ACTIVE.value]
    by_priority = Counter(a.severity for a in alerts_open)
    month_ago = now - timedelta(days=30)
    last30 = [a for a in alerts_recent if a.detected_at >= month_ago]
    acked = [a for a in last30 if a.acknowledged_at]
    sla_met = [a for a in acked if (a.acknowledged_at - a.detected_at).total_seconds() / 60
               <= RESPONSE_MINUTES[Severity(a.severity)]]
    outages = [a for a in last30 if a.category in {c.value for c in OUTAGE_CATEGORIES}]
    mttd = [(a.detected_at - a.occurred_at).total_seconds() / 60 for a in outages]
    mttr = [(a.resolved_at - a.occurred_at).total_seconds() / 3600 for a in outages if a.resolved_at]

    trend = []
    for start, end in _weeks(now):
        opened = [a for a in alerts_recent if start <= a.detected_at < end]
        resolved = [a for a in alerts_recent if a.resolved_at and start <= a.resolved_at < end]
        out = [a for a in opened if a.category in {c.value for c in OUTAGE_CATEGORIES}]
        r_hours = [(a.resolved_at - a.occurred_at).total_seconds() / 3600 for a in out if a.resolved_at]
        sec = [a for a in opened if a.category in SECURITY]
        trend.append({"label": end.strftime("%d %b"), "opened": len(opened), "resolved": len(resolved),
                      "mttr": round(sum(r_hours) / len(r_hours), 1) if r_hours else None, "security": len(sec),
                      "outages": len(out)})

    cat_counts = Counter(a.category for a in alerts_recent if a.detected_at >= month_ago)
    top_categories = [{"label": CATEGORY_LABELS.get(k, k.title()), "n": n} for k, n in cat_counts.most_common(6)]

    # --- Assets lifecycle, changes, rollout ------------------------------------------------------------------
    life = Counter(a.status for a in assets)
    changes = db.execute(select(ChangeRequest.status, func.count(ChangeRequest.id)).where(
        ChangeRequest.from_branch_id.in_(ids)).group_by(ChangeRequest.status)).all()
    change_counts = dict(changes)
    shipments = dict(db.execute(select(Shipment.status, func.count(Shipment.id)).where(
        Shipment.to_branch_id.in_(ids)).group_by(Shipment.status)).all())
    waves = Counter((b.wave or "—", b.rollout_stage == "LIVE") for b in branches if not b.is_head_office)
    wave_rows = []
    for key, label in (("PILOT", "Pilot"), ("WAVE1", "Wave 1"), ("WAVE2", "Wave 2"), ("WAVE3", "Wave 3")):
        live, total = waves[(key, True)], waves[(key, True)] + waves[(key, False)]
        if total:
            wave_rows.append({"label": label, "live": live, "total": total, "pct": _pct(live, total) or 0})

    stale = now - timedelta(minutes=settings.collector_stale_minutes)
    collectors = db.execute(select(Collector).where(Collector.is_active.is_(True))).scalars().all()
    collectors_ok = sum(1 for c in collectors if c.last_heartbeat_at and c.last_heartbeat_at >= stale)

    today = now.date()
    horizon = today + timedelta(days=settings.warranty_warning_days)
    due = sum(1 for a in assets if a.status != AssetStatus.RETIRED.value and (
        (a.effective_warranty_end and today <= a.effective_warranty_end <= horizon) or (a.eos_date and a.eos_date <= horizon)))

    # --- Security --------------------------------------------------------------------------------------------
    sec_open = [a for a in alerts_open if a.category in SECURITY]
    sec_open.sort(key=lambda a: (a.severity, -a.detected_at.timestamp()))
    exc_types = Counter(e.exception_type for e in exc_open)
    ageing = {"0–7 d": 0, "8–30 d": 0, "> 30 d": 0}
    for e in exc_open:
        days = (now - e.created_at).days
        ageing["0–7 d" if days <= 7 else "8–30 d" if days <= 30 else "> 30 d"] += 1
    fixed = [ReadPointKind.DOCK_IN.value, ReadPointKind.CAGE.value, ReadPointKind.DISPATCH.value,
             ReadPointKind.CABINET.value, ReadPointKind.EXIT_PORTAL.value]
    readers = db.execute(select(ReadPoint).where(ReadPoint.is_active.is_(True), ReadPoint.kind.in_(fixed),
                                                 ReadPoint.branch_id.in_(ids))).scalars().all()
    reader_stale = now - timedelta(minutes=settings.reader_stale_minutes)
    readers_ok = sum(1 for r in readers if r.last_heartbeat_at and r.last_heartbeat_at >= reader_stale)
    clips = db.execute(select(VideoClip.status, func.count(VideoClip.id)).group_by(VideoClip.status)).all()
    pci = [a for a in assets if a.pci_scope and a.status in INSTALLED]
    pci_unmonitored = sum(1 for a in pci if not a.monitored)
    disposals = db.execute(select(ChangeRequest).where(
        ChangeRequest.change_type == ChangeType.DISPOSE.value, ChangeRequest.status == ChangeStatus.COMPLETED.value,
        ChangeRequest.from_branch_id.in_(ids))).scalars().all()
    wiped = sum(1 for c in disposals if c.wipe_certificate_ref or c.asset.asset_type not in ("SRV", "STO", "EUD", "ATM"))
    chain = None
    if board == "ciso":
        ok, checked, bad = auditlog.verify_chain(db)
        chain = {"ok": ok, "checked": checked, "bad": bad}
    rfid = rfid_kpis(db, assets) if board in ("cio", "ciso") else {}

    return {
        "board": board, "boards": BOARDS, "now": now, "scope": len(branches),
        "map": {"w": WIDTH, "h": HEIGHT, "shapes": shapes, "dots": dots, "metric": "risk" if board == "ciso" else "availability"},
        "regions": sorted(regions.values(), key=lambda r: r["code"]),
        "states": {k: counts_state.get(k, 0) for k in ("online", "degraded", "offline", "not_monitored")},
        "branches": len(branches), "monitored": monitored, "up": up,
        "branch_availability": _pct(up, monitored),
        "asset_health": _pct(len(healthy), len(installed)),
        "assets": len(assets), "live": sum(1 for a in assets if a.status == AssetStatus.ACTIVE.value),
        "priority": {p: by_priority.get(p, 0) for p in ("P1", "P2", "P3", "P4")},
        "open_alerts": len(alerts_open),
        "sla": _pct(len(sla_met), len(acked)), "sla_n": len(acked),
        "mttd": round(sum(mttd) / len(mttd), 1) if mttd else None,
        "mttr_h": round(sum(mttr) / len(mttr), 1) if mttr else None,
        "trend": trend, "top_categories": top_categories,
        "life": {k: life.get(k, 0) for k in ("ACTIVE", "FAULTY", "IN_STOCK", "IN_TRANSIT", "UNDER_REPAIR", "MISSING", "RETIRED")},
        "changes": {"pending": change_counts.get(ChangeStatus.PENDING_APPROVAL.value, 0),
                    "approved": change_counts.get(ChangeStatus.APPROVED.value, 0),
                    "in_progress": change_counts.get(ChangeStatus.IN_PROGRESS.value, 0),
                    "completed": change_counts.get(ChangeStatus.COMPLETED.value, 0)},
        "shipments": {k: shipments.get(v.value, 0) for k, v in (("packed", ShipmentStatus.PACKED),
                                                                 ("transit", ShipmentStatus.IN_TRANSIT),
                                                                 ("variance", ShipmentStatus.VARIANCE))},
        "waves": wave_rows,
        "collectors": len(collectors), "collectors_ok": collectors_ok, "due": due,
        "worst": sorted([r for r in regions.values() if r["monitored"]], key=lambda r: (r["availability"] or 0))[:5],
        "incidents": sorted([a for a in alerts_open if a.category not in SECURITY], key=lambda a: (a.severity, a.detected_at))[:6],
        "security_open": sec_open[:7], "security_count": len(sec_open),
        "security_p1": sum(1 for a in sec_open if a.severity == Severity.P1.value),
        "suspected": sum(1 for a in assets if a.suspected_removal_at),
        "unapproved": exc_types.get(ExceptionType.UNAPPROVED_DEVICE.value, 0) + exc_types.get(ExceptionType.ROGUE_DEVICE.value, 0),
        "missing": life.get(AssetStatus.MISSING.value, 0),
        "exceptions": len(exc_open), "exc_types": exc_types.most_common(6), "ageing": ageing,
        "readers": len(readers), "readers_ok": readers_ok, "clips": dict(clips),
        "pci": len(pci), "pci_unmonitored": pci_unmonitored,
        "disposals": len(disposals), "wiped": wiped, "chain": chain, "rfid": rfid,
    }
