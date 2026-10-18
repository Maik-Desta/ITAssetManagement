"""Executive dashboard (slide 23) and programme KPIs (slide 33)."""

from __future__ import annotations

from datetime import date, timedelta
from statistics import mean

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam.config import settings
from itam.enums import (
    INSTALLED_STATUSES,
    NETWORK_TYPES,
    OUTAGE_CATEGORIES,
    AlertCategory,
    AlertSource,
    AlertStatus,
    AssetStatus,
    AssetType,
    AuditStatus,
    Criticality,
    ExceptionStatus,
    ExceptionType,
    OperState,
    Severity,
)
from itam.models import (
    Alert,
    Asset,
    Branch,
    Collector,
    ControlException,
    Milestone,
    PhysicalAudit,
    User,
    utcnow,
)
from itam.rbac import scope_branches
from itam.services.audits import league_table

INSTALLED = [s.value for s in INSTALLED_STATUSES]


def _pct(num: float, den: float) -> float | None:
    return round(100.0 * num / den, 1) if den else None


def branch_states(db: Session, branches: list[Branch]) -> dict[int, str]:
    """online / offline / degraded / not_monitored per branch."""
    ids = [b.id for b in branches]
    if not ids:
        return {}
    routers = db.execute(select(Asset.branch_id, Asset.oper_state).where(
        Asset.branch_id.in_(ids), Asset.asset_type == AssetType.RTR.value, Asset.monitored.is_(True),
        Asset.status.in_(INSTALLED))).all()
    by_branch: dict[int, list[str]] = {}
    for bid, state in routers:
        by_branch.setdefault(bid, []).append(state)
    open_alerts = db.execute(select(Alert.branch_id, Alert.category, Alert.severity).where(
        Alert.branch_id.in_(ids), Alert.status != AlertStatus.RESOLVED.value)).all()
    offline = {bid for bid, cat, _ in open_alerts if cat == AlertCategory.BRANCH_OFFLINE.value}
    degraded = {bid for bid, cat, sev in open_alerts
                if sev in (Severity.P1.value, Severity.P2.value) and cat != AlertCategory.BRANCH_OFFLINE.value}
    states: dict[int, str] = {}
    for b in branches:
        rs = by_branch.get(b.id)
        if not rs:
            states[b.id] = "not_monitored"
        elif b.id in offline or all(s == OperState.DOWN.value for s in rs):
            states[b.id] = "offline"
        elif b.id in degraded or any(s in (OperState.DOWN.value, OperState.DEGRADED.value) for s in rs):
            states[b.id] = "degraded"
        else:
            states[b.id] = "online"
    return states


def _weekly_trend(alerts: list[Alert], weeks: int = 8) -> list[dict]:
    today = utcnow()
    rows = []
    for w in range(weeks - 1, -1, -1):
        start = today - timedelta(days=7 * (w + 1))
        end = today - timedelta(days=7 * w)
        bucket = [a for a in alerts if start <= a.detected_at < end]
        mttd = [(a.detected_at - a.occurred_at).total_seconds() / 60 for a in bucket]
        mttr = [(a.resolved_at - a.occurred_at).total_seconds() / 60 for a in bucket if a.resolved_at]
        rows.append({"week": end.strftime("%d %b"), "count": len(bucket),
                     "mttd": round(mean(mttd), 1) if mttd else None, "mttr": round(mean(mttr), 1) if mttr else None})
    return rows


def age_profile(assets: list[Asset]) -> list[dict]:
    buckets = [("< 1 yr", 0, 1), ("1–3 yrs", 1, 3), ("3–5 yrs", 3, 5), ("5–7 yrs", 5, 7), ("> 7 yrs", 7, 200)]
    today = date.today()
    counts = {label: 0 for label, *_ in buckets}
    unknown = 0
    for a in assets:
        start = a.install_date or a.received_date
        if not start:
            unknown += 1
            continue
        years = (today - start).days / 365.25
        for label, lo, hi in buckets:
            if lo <= years < hi:
                counts[label] += 1
                break
    rows = [{"label": label, "count": counts[label]} for label, *_ in buckets]
    if unknown:
        rows.append({"label": "Unknown", "count": unknown})
    return rows


def executive_summary(db: Session, user: User) -> dict:
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    ids = [b.id for b in branches] or [-1]
    states = branch_states(db, branches)
    monitored = [bid for bid, s in states.items() if s != "not_monitored"]
    online = [bid for bid, s in states.items() if s in ("online", "degraded")]

    assets = db.execute(select(Asset).where(Asset.branch_id.in_(ids),
                                            Asset.status != AssetStatus.DISPOSED.value)).scalars().all()
    installed = [a for a in assets if a.status in INSTALLED and a.monitored]
    healthy = [a for a in installed if a.oper_state == OperState.UP.value and a.status == AssetStatus.ACTIVE.value]
    missing = [a for a in assets if a.status == AssetStatus.MISSING.value]
    rogue = db.execute(select(func.count(ControlException.id)).where(
        ControlException.branch_id.in_(ids), ControlException.status == ExceptionStatus.OPEN.value,
        ControlException.exception_type == ExceptionType.ROGUE_DEVICE.value)).scalar_one()
    open_alerts = db.execute(select(Alert).where(Alert.branch_id.in_(ids),
                                                 Alert.status != AlertStatus.RESOLVED.value)).scalars().all()
    p1 = sum(1 for a in open_alerts if a.severity == Severity.P1.value)
    p2 = sum(1 for a in open_alerts if a.severity == Severity.P2.value)

    today = date.today()
    horizon = today + timedelta(days=settings.warranty_warning_days)
    due = []
    for a in assets:
        if a.status == AssetStatus.RETIRED.value:
            continue
        w = a.effective_warranty_end
        if w and today <= w <= horizon:
            due.append({"asset": a, "what": "Warranty", "date": w})
        if a.eos_date and a.eos_date <= horizon:
            due.append({"asset": a, "what": "End of support", "date": a.eos_date})
    due.sort(key=lambda d: d["date"])

    since = utcnow() - timedelta(days=56)
    outage_alerts = db.execute(select(Alert).where(
        Alert.branch_id.in_(ids), Alert.category.in_([c.value for c in OUTAGE_CATEGORIES]),
        Alert.source == AlertSource.MONITORING.value, Alert.detected_at >= since)).scalars().all()

    month_ago = utcnow() - timedelta(days=30)
    unapproved = db.execute(select(func.count(Alert.id)).where(
        Alert.branch_id.in_(ids), Alert.detected_at >= month_ago,
        Alert.category.in_([AlertCategory.CONFIG_CHANGE.value, AlertCategory.DEVICE_NOT_DISCOVERED.value,
                            AlertCategory.DEVICE_SWAPPED.value]))).scalar_one()
    unapproved += db.execute(select(func.count(ControlException.id)).where(
        ControlException.branch_id.in_(ids), ControlException.created_at >= month_ago,
        ControlException.exception_type == ExceptionType.LOCATION_MISMATCH.value)).scalar_one()

    stale = utcnow() - timedelta(minutes=settings.collector_stale_minutes)
    collectors = db.execute(select(Collector).where(Collector.is_active.is_(True)).order_by(Collector.name)).scalars().all()

    league = league_table(db, branches)
    breakdown = asset_breakdown(db, branches)
    return {
        "generated_at": utcnow(),
        "breakdown": breakdown,
        "branches": branches,
        "branch_states": states,
        "branches_total": len(branches),
        "branches_monitored": len(monitored),
        "branches_online": len(online),
        "assets_registered": len(assets),
        "healthy_pct": _pct(len(healthy), len(installed)),
        "installed_monitored": len(installed),
        "missing": len(missing),
        "rogue": rogue,
        "open_p1": p1,
        "open_p2": p2,
        "open_alerts": sorted(open_alerts, key=lambda a: (a.severity, a.detected_at))[:8],
        "due": due[:12],
        "due_count": len(due),
        "league_top": [r for r in league if r["score"] is not None][:5],
        "league_bottom": [r for r in league if r["score"] is not None][-5:][::-1],
        "trend": _weekly_trend(outage_alerts),
        "age_profile": age_profile(assets),
        "unapproved_changes": unapproved,
        "collectors": [{"c": c, "healthy": bool(c.last_heartbeat_at and c.last_heartbeat_at >= stale)} for c in collectors],
    }


# ---------------------------------------------------------------------------
# KPIs (slide 33)
# ---------------------------------------------------------------------------


def kpis(db: Session) -> list[dict]:
    now = utcnow()
    year_ago = now - timedelta(days=365)
    month_ago = now - timedelta(days=30)
    live_assets = db.execute(select(Asset).where(Asset.status != AssetStatus.DISPOSED.value)).scalars().all()

    audits = db.execute(select(PhysicalAudit).where(PhysicalAudit.status == AuditStatus.COMPLETED.value,
                                                    PhysicalAudit.completed_at >= year_ago)).scalars().all()
    found = sum(a.found_count for a in audits)
    checked = sum(a.expected_count + a.unexpected_count for a in audits)
    accuracy = _pct(found, checked)

    in_scope = [a for a in live_assets if a.status in INSTALLED and a.asset_type in NETWORK_TYPES]
    critical = [a for a in in_scope if a.criticality == Criticality.CRITICAL.value]
    cov_all = _pct(sum(1 for a in in_scope if a.monitored), len(in_scope))
    cov_crit = _pct(sum(1 for a in critical if a.monitored), len(critical))

    # A valid tag is an RFID + QR label applied and verified by a read.
    tagged = _pct(sum(1 for a in live_assets if a.tag_applied_at and a.rfid_verified_at), len(live_assets))

    outages = db.execute(select(Alert).where(Alert.category.in_([c.value for c in OUTAGE_CATEGORIES]),
                                             Alert.detected_at >= month_ago)).scalars().all()
    monitored_outages = [a for a in outages if a.source == AlertSource.MONITORING.value]
    mttd_vals = [(a.detected_at - a.occurred_at).total_seconds() / 60 for a in monitored_outages]
    mttd = round(mean(mttd_vals), 1) if mttd_vals else None
    proactive = _pct(len(monitored_outages), len(outages))

    missing = sum(1 for a in live_assets if a.status == AssetStatus.MISSING.value or a.suspected_removal_at)
    rfid = rfid_kpis(db, live_assets)

    excs = db.execute(select(ControlException).where(ControlException.created_at >= year_ago)).scalars().all()
    due_excs = [e for e in excs if e.status == ExceptionStatus.RESOLVED.value or now - e.created_at > timedelta(days=30)]
    closed_in_time = [e for e in due_excs if e.resolved_at and e.resolved_at - e.created_at <= timedelta(days=30)]
    closure = _pct(len(closed_in_time), len(due_excs))

    warranty_vis = _pct(sum(1 for a in live_assets if a.effective_warranty_end and a.eol_date), len(live_assets))

    milestones = db.execute(select(Milestone).order_by(Milestone.planned_date)).scalars().all()
    due_ms = [m for m in milestones if m.actual_date or m.planned_date <= date.today()]
    on_time = [m for m in due_ms if m.actual_date and m.actual_date <= m.planned_date]
    on_time_pct = _pct(len(on_time), len(due_ms))
    spent = [m for m in milestones if m.budget_actual is not None and m.budget_planned]
    planned_total = sum(float(m.budget_planned) for m in spent)
    variance = round(100.0 * (sum(float(m.budget_actual) for m in spent) - planned_total) / planned_total, 1) if planned_total else None

    def row(name, definition, value, display, target, met, reported_to):
        return {"name": name, "definition": definition, "value": value, "display": display, "target": target,
                "met": met, "reported_to": reported_to}

    def ge(v, t):
        return None if v is None else v >= t

    fmt = lambda v, suffix="%": "—" if v is None else f"{v}{suffix}"  # noqa: E731
    return [
        row("Asset register accuracy", "Physical audit matches system record (last 12 months)", accuracy, fmt(accuracy),
            "≥ 98%", ge(accuracy, 98), "Steering Committee"),
        row("Monitoring coverage", "In-scope devices actively monitored", cov_all,
            f"{fmt(cov_crit)} critical / {fmt(cov_all)} all", "100% critical, ≥ 95% all",
            None if cov_all is None else (cov_crit in (None, 100.0) and cov_all >= 95), "Programme Board"),
        row("Assets tagged", "Assets with valid tag and number", tagged, fmt(tagged), "100%", ge(tagged, 100),
            "Programme Board"),
        row("Mean time to detect (MTTD)", "Failure to alert for outages (30 days)", mttd, fmt(mttd, " min"),
            "< 5 minutes", None if mttd is None else mttd < 5, "CIO / NOC"),
        row("Proactive detection rate", "Outages found by monitoring before user reports (30 days)", proactive,
            fmt(proactive), "≥ 90%", ge(proactive, 90), "CIO / NOC"),
        row("Unexplained removals", "Missing or suspected-removal assets without approved change", missing,
            str(missing), "0", missing == 0, "CISO, Internal Audit"),
        row("Audit exception closure", "Exceptions closed within 30 days", closure, fmt(closure), "≥ 95%",
            ge(closure, 95), "Internal Audit"),
        row("Warranty / EOL visibility", "Assets with warranty and EOL dates recorded", warranty_vis,
            fmt(warranty_vis), "100%", ge(warranty_vis, 100), "CIO, CFO"),
        row("Programme delivery", "Milestones on time; budget variance", on_time_pct,
            f"{fmt(on_time_pct)} on time; {fmt(variance)} budget", "≥ 90%; < 10%",
            None if on_time_pct is None else (on_time_pct >= 90 and (variance is None or variance < 10)),
            "Steering Committee"),
        # RFID implementation targets (slide 54) and the standard branch blueprint (slides 9, 26).
        row("New assets RFID-tagged at staging", "Shipped items with a verified RFID tag before leaving staging",
            rfid["tagged_at_staging"], fmt(rfid["tagged_at_staging"]), "100%", ge(rfid["tagged_at_staging"], 100),
            "Programme Board"),
        row("Portal read rate", "Shipped items read by the dispatch exit portal", rfid["portal_read_rate"],
            fmt(rfid["portal_read_rate"]), "≥ 99%", ge(rfid["portal_read_rate"], 99), "Programme Board"),
        row("Installed without manifest match", "Shipped assets installed without a matched branch receipt",
            rfid["unmatched_installs"], str(rfid["unmatched_installs"]), "0", rfid["unmatched_installs"] == 0,
            "CISO, Internal Audit"),
        row("Existing assets retrofitted", "Assets in service with a verified RFID + QR label", rfid["retrofitted"],
            fmt(rfid["retrofitted"]), "100% by end of Wave 3", ge(rfid["retrofitted"], 100), "Programme Board"),
        row("Blueprint compliance", "Rolled-out branches with only standard, approved kit and no unapproved devices",
            rfid["blueprint"], fmt(rfid["blueprint"]), "100%", ge(rfid["blueprint"], 100), "CIO, CISO"),
    ]


def rfid_kpis(db: Session, live_assets: list[Asset] | None = None) -> dict:
    from itam.enums import ShipmentItemResult
    from itam.models import Branch, Shipment, ShipmentItem
    from itam.services.catalogue import branch_compliance

    if live_assets is None:
        live_assets = db.execute(select(Asset).where(Asset.status != AssetStatus.DISPOSED.value)).scalars().all()
    shipped = db.execute(select(ShipmentItem).join(Shipment).where(Shipment.dispatched_at.is_not(None))).scalars().all()
    tagged_at_staging = _pct(sum(1 for i in shipped if i.asset.rfid_verified_at
                                 and i.asset.rfid_verified_at <= i.shipment.dispatched_at), len(shipped))
    portal = _pct(sum(1 for i in shipped if i.dispatch_read_at), len(shipped))
    last_item: dict[int, ShipmentItem] = {}
    for i in shipped:
        if i.asset_id not in last_item or i.id > last_item[i.asset_id].id:
            last_item[i.asset_id] = i
    unmatched = sum(1 for i in last_item.values()
                    if i.asset.install_date and i.result != ShipmentItemResult.MATCHED.value)
    in_service = [a for a in live_assets if a.status in INSTALLED]
    retrofitted = _pct(sum(1 for a in in_service if a.rfid_verified_at), len(in_service))
    rows = [r for r in branch_compliance(db, db.execute(select(Branch)).scalars().all()) if r["started"]]
    blueprint = _pct(sum(1 for r in rows if r["compliant"]), len(rows))
    return {"tagged_at_staging": tagged_at_staging, "portal_read_rate": portal, "unmatched_installs": unmatched,
            "retrofitted": retrofitted, "blueprint": blueprint}


# ---------------------------------------------------------------------------
# Asset status breakdown per region / per branch
# ---------------------------------------------------------------------------

BREAKDOWN_COLUMNS = [
    # key, label, asset-list flag (for click-through), help text
    ("total", "Total assets", "", "All registered assets, excluding disposed"),
    ("installed", "Installed", "installed", "In service at the branch (active or faulty)"),
    ("live", "Live", "live", "Installed, in service and with no fault or alarm"),
    ("issues", "Has issues", "issues", "Faulty, degraded, missing or under repair"),
    ("down", "Down", "down", "Monitored and currently not responding"),
    ("not_monitored", "Not monitored", "not_monitored", "Installed but not covered by monitoring"),
]


def classify_asset(status: str, oper_state: str, monitored: bool) -> set[str]:
    """Which breakdown buckets an asset falls into (an asset can be in several)."""
    if status == AssetStatus.DISPOSED.value:
        return set()
    buckets = {"total"}
    installed = status in INSTALLED
    if installed:
        buckets.add("installed")
        if not monitored:
            buckets.add("not_monitored")
    if monitored and installed and oper_state == OperState.DOWN.value:
        buckets.add("down")
    if (status in (AssetStatus.FAULTY.value, AssetStatus.MISSING.value, AssetStatus.UNDER_REPAIR.value)
            or (installed and monitored and oper_state in (OperState.DOWN.value, OperState.DEGRADED.value))):
        buckets.add("issues")
    elif status == AssetStatus.ACTIVE.value:
        buckets.add("live")
    return buckets


def asset_breakdown(db: Session, branches: list[Branch]) -> dict:
    """Counts per branch and per region for the dashboard table."""
    ids = [b.id for b in branches]
    keys = [c[0] for c in BREAKDOWN_COLUMNS]
    empty = lambda: dict.fromkeys(keys, 0)  # noqa: E731
    per_branch = {bid: empty() for bid in ids}
    if ids:
        rows = db.execute(select(Asset.branch_id, Asset.status, Asset.oper_state, Asset.monitored, func.count(Asset.id))
                          .where(Asset.branch_id.in_(ids))
                          .group_by(Asset.branch_id, Asset.status, Asset.oper_state, Asset.monitored)).all()
        for bid, status, oper, monitored, n in rows:
            for bucket in classify_asset(status, oper, bool(monitored)):
                per_branch[bid][bucket] += n
    states = branch_states(db, branches)
    regions: dict[int, dict] = {}
    for b in branches:
        r = regions.setdefault(b.region_id, {"region": b.region, "branches": 0, "monitored": 0, "online": 0,
                                             "counts": empty()})
        r["branches"] += 1
        if states.get(b.id) != "not_monitored":
            r["monitored"] += 1
        if states.get(b.id) in ("online", "degraded"):
            r["online"] += 1
        for k in keys:
            r["counts"][k] += per_branch[b.id][k]
    totals = {"branches": len(branches), "monitored": sum(r["monitored"] for r in regions.values()),
              "online": sum(r["online"] for r in regions.values()), "counts": empty()}
    for r in regions.values():
        for k in keys:
            totals["counts"][k] += r["counts"][k]
    branch_rows = [{"branch": b, "state": states.get(b.id), "counts": per_branch[b.id]} for b in branches]
    return {"columns": BREAKDOWN_COLUMNS, "regions": sorted(regions.values(), key=lambda r: r["region"].code),
            "branches": branch_rows, "totals": totals}


# ---------------------------------------------------------------------------
# Asset inventory: where every asset is in its deployment journey (board view)
# ---------------------------------------------------------------------------

# Deployment stages in chart stacking order; colour slots 1-5 follow this order (style.css .stage-*).
STAGES = [
    ("installed", "Installed", "In service at a branch (including faulty)"),
    ("not_installed", "At branch, not installed", "Delivered to the branch but not yet installed and live"),
    ("store", "Central store", "Purchased and received, not yet assigned to a branch"),
    ("transit", "In transit", "Dispatched to a branch, not yet signed for"),
    ("out", "Out of service", "Under repair, missing or retired awaiting disposal"),
]
STAGE_KEYS = [k for k, *_ in STAGES]


def deployment_stage(status: str, is_head_office: bool) -> str | None:
    if status == AssetStatus.DISPOSED.value:
        return None
    if status in INSTALLED:
        return "installed"
    if status == AssetStatus.IN_TRANSIT.value:
        return "transit"
    if status == AssetStatus.IN_STOCK.value:
        return "store" if is_head_office else "not_installed"
    return "out"


def _compact(value: float) -> str:
    for div, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(value) >= div:
            return f"{value / div:.1f}{suffix}"
    return f"{value:,.0f}"


def asset_inventory(db: Session, branches: list[Branch]) -> dict:
    from itam.enums import TYPE_LABELS, AssetType, RequestStatus
    from itam.models import AssetModel, EquipmentRequest

    ids = [b.id for b in branches] or [-1]
    by_branch = {b.id: b for b in branches}
    rows = db.execute(
        select(Asset.branch_id, Asset.asset_type, Asset.status, Asset.model_id, Asset.received_date,
               Asset.purchase_cost)
        .where(Asset.branch_id.in_(ids), Asset.status != AssetStatus.DISPOSED.value)
    ).all()

    empty_stages = lambda: dict.fromkeys(STAGE_KEYS, 0)  # noqa: E731
    types = {t.value: {"type": t.value, "label": TYPE_LABELS[t], "total": 0, "value": 0.0, "stages": empty_stages()}
             for t in AssetType}
    regions: dict[int, dict] = {}
    branch_stages: dict[int, dict] = {}
    matrix: dict[tuple[int, str], int] = {}
    stage_totals = empty_stages()
    stage_value = dict.fromkeys(STAGE_KEYS, 0.0)
    store_groups: dict[tuple[str, int | None], dict] = {}
    not_installed_branches: dict[int, dict] = {}
    today = date.today()
    total_value = 0.0

    for branch_id, atype, status, model_id, received, cost in rows:
        b = by_branch[branch_id]
        stage = deployment_stage(status, b.is_head_office)
        cost = float(cost or 0)
        total_value += cost
        stage_totals[stage] += 1
        stage_value[stage] += cost
        t = types[atype]
        t["total"] += 1
        t["value"] += cost
        t["stages"][stage] += 1
        r = regions.setdefault(b.region_id, {"region": b.region, "total": 0, "value": 0.0, "stages": empty_stages()})
        r["total"] += 1
        r["value"] += cost
        r["stages"][stage] += 1
        branch_stages.setdefault(branch_id, empty_stages())[stage] += 1
        matrix[(b.region_id, atype)] = matrix.get((b.region_id, atype), 0) + 1
        age = (today - received).days if received else None
        if stage == "store":
            g = store_groups.setdefault((atype, model_id), {"type": atype, "model_id": model_id, "count": 0,
                                                            "value": 0.0, "oldest_days": 0})
            g["count"] += 1
            g["value"] += cost
            g["oldest_days"] = max(g["oldest_days"], age or 0)
        elif stage == "not_installed":
            n = not_installed_branches.setdefault(branch_id, {"branch": b, "count": 0, "oldest_days": 0, "types": {}})
            n["count"] += 1
            n["oldest_days"] = max(n["oldest_days"], age or 0)
            n["types"][atype] = n["types"].get(atype, 0) + 1

    models = {m.id: m for m in db.execute(select(AssetModel)).scalars()}
    store = sorted(store_groups.values(), key=lambda g: (-g["count"], g["type"]))
    for g in store:
        g["model"] = models[g["model_id"]].display if g["model_id"] in models else "—"
        g["label"] = TYPE_LABELS[AssetType(g["type"])]

    on_order = db.execute(select(EquipmentRequest).where(
        EquipmentRequest.status.in_([RequestStatus.APPROVED.value, RequestStatus.ORDERED.value]),
        EquipmentRequest.branch_id.in_(ids))).scalars().all()
    on_order_qty = sum(r.quantity - r.received_quantity for r in on_order if r.status == RequestStatus.ORDERED.value)
    awaiting_po = sum(r.quantity for r in on_order if r.status == RequestStatus.APPROVED.value)

    type_rows = sorted((t for t in types.values() if t["total"]), key=lambda t: -t["total"])
    region_rows = sorted(regions.values(), key=lambda r: r["region"].code)
    present_types = [t["type"] for t in type_rows]
    matrix_rows = [{"region": r["region"], "cells": [matrix.get((r["region"].id, t), 0) for t in present_types],
                    "total": r["total"]} for r in region_rows]
    matrix_max = max([c for row in matrix_rows for c in row["cells"]] or [0])

    return {
        "stages": STAGES, "stage_totals": stage_totals, "stage_value": stage_value,
        "total": sum(stage_totals.values()), "total_value": total_value, "total_value_compact": _compact(total_value),
        "types": type_rows, "regions": region_rows, "branch_stages": branch_stages,
        "matrix_types": present_types, "matrix": matrix_rows, "matrix_max": matrix_max,
        "store": store, "store_value": stage_value["store"],
        "not_installed": sorted(not_installed_branches.values(), key=lambda n: (-n["count"], n["branch"].code)),
        "on_order_qty": on_order_qty, "awaiting_po": awaiting_po, "currency": settings.currency,
    }


def key_messages(summary: dict, inv: dict) -> list[dict]:
    """Plain-language headlines for the CEO, generated from live data."""
    bd = summary["breakdown"]
    tot = bd["totals"]
    c = tot["counts"]
    msgs = []
    pct = round(100 * tot["monitored"] / tot["branches"]) if tot["branches"] else 0
    msgs.append({"tone": "good" if pct >= 95 else "info",
                 "text": f"{tot['monitored']} of {tot['branches']} branches ({pct}%) are onboarded and monitored live; "
                         f"{tot['branches'] - tot['monitored']} are scheduled in the remaining rollout waves."})
    msgs.append({"tone": "info",
                 "text": f"The Bank holds {inv['total']:,} IT assets worth {inv['currency']} {inv['total_value_compact']} at cost; "
                         f"{c['installed']:,} are installed and {c['live']:,} are live with no issues."})
    if c["issues"] or summary["open_p1"]:
        msgs.append({"tone": "critical" if summary["open_p1"] else "warning",
                     "text": f"{c['issues']} assets need attention ({c['down']} down); {summary['open_p1']} critical (P1) "
                             f"and {summary['open_p2']} high (P2) alerts are open."})
    else:
        msgs.append({"tone": "good", "text": "No assets are currently down and no critical alerts are open."})
    idle = inv["stage_totals"]["store"] + inv["stage_totals"]["not_installed"]
    if idle:
        msgs.append({"tone": "warning",
                     "text": f"{idle} purchased assets are not yet in service: {inv['stage_totals']['store']} in the central "
                             f"store and {inv['stage_totals']['not_installed']} delivered to branches but not installed "
                             f"({inv['currency']} {_compact(inv['stage_value']['store'] + inv['stage_value']['not_installed'])})."})
    msgs.append({"tone": "critical" if summary["missing"] else "good",
                 "text": (f"{summary['missing']} assets are missing without an approved change and are under investigation."
                          if summary["missing"] else "No unexplained asset removals.")})
    if summary["due_count"]:
        msgs.append({"tone": "warning",
                     "text": f"{summary['due_count']} assets reach warranty expiry or end of vendor support within 90 days."})
    return msgs
