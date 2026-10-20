"""NOC console: grouped incidents, service impact, affected assets, escalation and response performance."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from itam.enums import (
    CHANNEL_LABELS,
    IMPACT_LABELS,
    INSTALLED_STATUSES,
    RESPONSE_MINUTES,
    AlertCategory,
    AlertStatus,
    NotificationChannel,
    NotificationStatus,
    OperState,
    Severity,
)
from itam.models import Alert, Asset, Branch, Notification, User, utcnow
from itam.rbac import scope_branches
from itam.services import announce
from itam.services.monitoring import ESCALATION_LEVELS, MAX_ESCALATION, ceo_informed, escalation_path

IMPACTS = [("P1", "Critical"), ("P2", "Major"), ("P3", "Medium"), ("P4", "Minor")]
CHANNEL_ORDER = [NotificationChannel.VOICE, NotificationChannel.SMS, NotificationChannel.EMAIL,
                 NotificationChannel.CHAT, NotificationChannel.SYSTEM]


def _minutes(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return max((b - a).total_seconds() / 60, 0)


def _avg(values: list[float]) -> float | None:
    return round(mean(values), 1) if values else None


def notification_summary(notifications: list[Notification]) -> list[dict]:
    """Per channel: how many messages, and whether they were delivered or are held in the outbox."""
    by_channel: dict[str, list[Notification]] = defaultdict(list)
    for n in notifications:
        by_channel[n.channel].append(n)
    out = []
    for ch in CHANNEL_ORDER:
        items = by_channel.get(ch.value, [])
        if not items:
            continue
        delivered = sum(1 for n in items if n.status in (NotificationStatus.SENT.value, NotificationStatus.UNREAD.value,
                                                           NotificationStatus.READ.value))
        failed = sum(1 for n in items if n.status == NotificationStatus.FAILED.value)
        out.append({"channel": ch.value, "label": CHANNEL_LABELS[ch], "count": len(items), "delivered": delivered,
                    "failed": failed, "state": "failed" if failed else ("sent" if delivered == len(items) else "logged")})
    return out


AT_RISK_SHARE = 0.75  # warn when 75% of the response target has elapsed without acknowledgement


def response_sla(a: Alert, now: datetime) -> dict:
    """Did / will this case meet its response target? state: met, breached, at_risk, on_track."""
    target = RESPONSE_MINUTES[Severity(a.severity)]
    if a.acknowledged_at:
        used = _minutes(a.detected_at, a.acknowledged_at)
        state = "met" if used <= target else "breached"
    else:
        used = _minutes(a.detected_at, now)
        state = "breached" if used > target else ("at_risk" if used >= target * AT_RISK_SHARE else "on_track")
    return {"state": state, "used_min": round(used, 1), "target_min": target,
            "pct": min(round(100 * used / target), 100) if target else 100,
            "remaining_min": max(target - used, 0) if not a.acknowledged_at else None}


def noc_overview(db: Session, user: User, now: datetime | None = None, window_days: int = 30) -> dict:
    now = now or utcnow()
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    branch_ids = [b.id for b in branches] or [-1]
    by_id = {b.id: b for b in branches}

    open_alerts = db.execute(
        select(Alert).options(selectinload(Alert.escalations))
        .where(Alert.status != AlertStatus.RESOLVED.value,
               (Alert.branch_id.in_(branch_ids)) | Alert.branch_id.is_(None))
        .order_by(Alert.severity, Alert.detected_at)
    ).scalars().all()
    notes: dict[int, list[Notification]] = defaultdict(list)
    if open_alerts:
        for n in db.execute(select(Notification).where(Notification.alert_id.in_([a.id for a in open_alerts]))).scalars():
            notes[n.alert_id].append(n)

    def enrich(a: Alert) -> dict:
        return {"alert": a, "impact": IMPACT_LABELS[Severity(a.severity)], "path": escalation_path(a, now),
                "channels": notification_summary(notes.get(a.id, [])), "ceo": ceo_informed(a),
                "age_min": _minutes(a.occurred_at, now), "sla": response_sla(a, now),
                "critical_unacked": a.severity == Severity.P1.value and a.status == AlertStatus.OPEN.value,
                "overdue": a.status == AlertStatus.OPEN.value and now > a.response_due_at}

    rows = [enrich(a) for a in open_alerts]
    for r in rows:
        r["level"] = max((st["level"] for st in r["path"] if st["state"] == "done"), default=0)

    # Where each open case currently sits on the escalation path (highest level notified).
    by_level = []
    for level, lvl in enumerate(ESCALATION_LEVELS):
        items = [r for r in rows if r["level"] == level]
        handled = [r for r in items if r["sla"]["state"] in ("met", "on_track", "at_risk")]
        by_level.append({
            "level": level, "code": lvl["code"], "name": lvl["name"], "count": len(items),
            "critical": sum(1 for r in items if r["alert"].severity == Severity.P1.value),
            "critical_unacked": sum(1 for r in items if r["critical_unacked"]),
            "unacked": sum(1 for r in items if r["alert"].status == AlertStatus.OPEN.value),
            "breached": sum(1 for r in items if r["sla"]["state"] == "breached"),
            "at_risk": sum(1 for r in items if r["sla"]["state"] == "at_risk"),
            "compliance": round(100 * len(handled) / len(items)) if items else None,
            "oldest_min": max((r["age_min"] for r in items), default=None),
        })
    sla_counts = {k: sum(1 for r in rows if r["sla"]["state"] == k) for k in ("met", "on_track", "at_risk", "breached")}

    # Group issues into incidents per branch (one incident per site, most severe first).
    groups: dict[int | None, dict] = {}
    for r in rows:
        a = r["alert"]
        g = groups.setdefault(a.branch_id, {"branch": by_id.get(a.branch_id) if a.branch_id else None, "alerts": [],
                                            "severity": a.severity, "started": a.occurred_at, "assets": set(),
                                            "offline": False, "ceo": False, "unacked": 0, "max_level": 0})
        g["alerts"].append(r)
        g["severity"] = min(g["severity"], a.severity)
        g["started"] = min(g["started"], a.occurred_at)
        if a.asset_id:
            g["assets"].add(a.asset_id)
        g["offline"] |= a.category == AlertCategory.BRANCH_OFFLINE.value
        g["ceo"] |= r["ceo"]
        g["unacked"] += a.status == AlertStatus.OPEN.value
        g["max_level"] = max(g["max_level"], r["level"])
        g["critical_unacked"] = g.get("critical_unacked", False) or r["critical_unacked"]
        g["breached"] = g.get("breached", 0) + (r["sla"]["state"] == "breached")
    incidents = sorted(groups.values(), key=lambda g: (g["severity"], not g["offline"], g["started"]))
    for g in incidents:
        g["impact"] = IMPACT_LABELS[Severity(g["severity"])]
        g["lead"] = g["alerts"][0]
        g["age_min"] = _minutes(g["started"], now)

    impact_counts = {code: 0 for code, _ in IMPACTS}
    for r in rows:
        impact_counts[r["alert"].severity] += 1

    # Affected assets per region / branch.
    assets = db.execute(select(Asset).where(
        Asset.branch_id.in_(branch_ids), Asset.monitored.is_(True),
        Asset.status.in_([s.value for s in INSTALLED_STATUSES]),
        Asset.oper_state.in_([OperState.DOWN.value, OperState.DEGRADED.value, OperState.UNKNOWN.value]),
    ).order_by(Asset.branch_id, Asset.asset_type)).scalars().all()
    offline_ids = {g["branch"].id for g in incidents if g["offline"] and g["branch"]}
    affected: dict[int, dict] = {}
    for a in assets:
        if a.oper_state == OperState.UNKNOWN.value and a.branch_id not in offline_ids:
            continue  # not yet polled, not an outage
        b = by_id[a.branch_id]
        reg = affected.setdefault(b.region_id, {"region": b.region, "branches": {}, "down": 0, "degraded": 0,
                                                "unreachable": 0})
        br = reg["branches"].setdefault(b.id, {"branch": b, "assets": [], "offline": b.id in offline_ids})
        state = "unreachable" if a.oper_state == OperState.UNKNOWN.value else a.oper_state.lower()
        br["assets"].append({"asset": a, "state": state, "since": a.oper_state_since})
        reg[state] += 1
    affected_regions = sorted(affected.values(), key=lambda r: r["region"].code)
    for g in incidents:
        if g["offline"] and g["branch"]:
            br = affected.get(g["branch"].region_id, {}).get("branches", {}).get(g["branch"].id)
            g["announce"] = announce.branch_offline(g, br["assets"] if br else [])
    for reg in affected_regions:
        reg["branch_list"] = sorted(reg["branches"].values(), key=lambda b: (not b["offline"], b["branch"].code))

    # Response performance over the window.
    since = now - timedelta(days=window_days)
    recent = db.execute(select(Alert).where(Alert.detected_at >= since, Alert.severity != Severity.P4.value,
                                            Alert.branch_id.in_(branch_ids))).scalars().all()

    def perf(items: list[Alert]) -> dict:
        acked = [a for a in items if a.acknowledged_at]
        resolved = [a for a in items if a.resolved_at]
        within = [a for a in acked if a.acknowledged_at - a.detected_at <= timedelta(
            minutes=RESPONSE_MINUTES[Severity(a.severity)])]
        return {"alerts": len(items),
                "mtta": _avg([_minutes(a.detected_at, a.acknowledged_at) for a in acked]),
                "mttr": _avg([_minutes(a.occurred_at, a.resolved_at) for a in resolved]),
                "sla": round(100 * len(within) / len(acked)) if acked else None,
                "open": sum(1 for a in items if a.status != AlertStatus.RESOLVED.value)}

    per_region: dict[int, list[Alert]] = defaultdict(list)
    per_sev: dict[str, list[Alert]] = defaultdict(list)
    for a in recent:
        b = by_id.get(a.branch_id)
        if b:
            per_region[b.region_id].append(a)
        per_sev[a.severity].append(a)
    regions = {b.region_id: b.region for b in branches}
    performance = [{"region": regions[rid], **perf(items)} for rid, items in sorted(
        per_region.items(), key=lambda kv: regions[kv[0]].code)]
    by_severity = [{"code": code, "impact": label, "target": RESPONSE_MINUTES[Severity(code)],
                    "max_level": ESCALATION_LEVELS[MAX_ESCALATION[Severity(code)]]["code"], **perf(per_sev.get(code, []))}
                   for code, label in IMPACTS]

    return {
        "now": now, "rows": rows, "incidents": incidents, "impact_counts": impact_counts,
        "offline": [g for g in incidents if g["offline"]],
        "affected": affected_regions,
        "asset_counts": {k: sum(r[k] for r in affected_regions) for k in ("down", "degraded", "unreachable")},
        "overall": perf(recent), "performance": performance, "by_severity": by_severity, "window_days": window_days,
        "levels": ESCALATION_LEVELS, "branches": branches,
        "unacked": sum(1 for r in rows if r["alert"].status == AlertStatus.OPEN.value),
        "by_level": by_level, "sla_counts": sla_counts,
        "sla_compliance": (round(100 * (len(rows) - sla_counts["breached"]) / len(rows)) if rows else None),
        "critical_unacked": sum(1 for r in rows if r["critical_unacked"]),
        "overdue": sum(1 for r in rows if r["overdue"]),
    }
