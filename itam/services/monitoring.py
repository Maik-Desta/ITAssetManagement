"""Monitoring & event management: state ingestion, alerting, severity and escalation (slide 21)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.config import settings
from itam.enums import (
    INSTALLED_STATUSES,
    AlertCategory,
    AlertSource,
    AlertStatus,
    AssetStatus,
    AssetType,
    Criticality,
    NotificationChannel,
    OperState,
    Severity,
)
from itam.models import Alert, AlertEscalation, Asset, Branch, Collector, MonitoringEvent, User, utcnow
from itam.notifications import notify
from itam.rbac import Role, can
from itam.services import PermissionDenied, ServiceError
from itam.services.assets import set_status

# Escalation path for unacknowledged alerts (slide 21, extended to the CEO for business-critical outages).
ESCALATION_LEVELS = [
    {"code": "L1", "name": "NOC & regional engineer", "roles": [Role.NOC, Role.REGIONAL_IT]},
    {"code": "L2", "name": "Regional IT lead", "roles": [Role.REGIONAL_LEAD]},
    {"code": "L3", "name": "Head of Infrastructure & CIO", "roles": [Role.HEAD_INFRA, Role.CIO]},
    {"code": "CEO", "name": "Chief Executive", "roles": [Role.EXECUTIVE]},
]
ESCALATION_CHAIN: list[list[Role]] = [lvl["roles"] for lvl in ESCALATION_LEVELS]
CEO_LEVEL = 3
# Highest level an unacknowledged alert can reach, by severity (keeps the CEO out of minor noise).
MAX_ESCALATION = {Severity.P1: 3, Severity.P2: 2, Severity.P3: 1, Severity.P4: 0}

C = NotificationChannel
SEVERITY_CHANNELS = {
    Severity.P1: [C.VOICE, C.SMS, C.EMAIL, C.CHAT, C.SYSTEM],  # immediate call + SMS
    Severity.P2: [C.SMS, C.EMAIL, C.CHAT, C.SYSTEM],
    Severity.P3: [C.EMAIL, C.SYSTEM],  # ticket
    Severity.P4: [],  # report, next business day
}
CEO_CHANNELS = [C.VOICE, C.SMS, C.EMAIL, C.SYSTEM]

# Extra audiences by category (slide 20: missing alert to NOC, Security and Branch Manager).
CATEGORY_AUDIENCE: dict[AlertCategory, list[Role]] = {
    AlertCategory.DEVICE_NOT_DISCOVERED: [Role.CISO, Role.BRANCH_MANAGER],
    AlertCategory.ROGUE_DEVICE: [Role.CISO],
    AlertCategory.DEVICE_SWAPPED: [Role.CISO, Role.BRANCH_MANAGER],
    AlertCategory.CONFIG_CHANGE: [Role.CISO],
    AlertCategory.UNAPPROVED_DEVICE: [Role.CISO, Role.BRANCH_MANAGER],
    # Physical security (slide 33: branch manager, security, SOC).
    AlertCategory.SUSPECTED_REMOVAL: [Role.CISO, Role.BRANCH_MANAGER, Role.IT_ASSET_MANAGER],
    AlertCategory.CABINET_TAG_MISSING: [Role.CISO],
    AlertCategory.CABINET_DOOR: [Role.CISO, Role.BRANCH_MANAGER],
    AlertCategory.INTRUSION: [Role.CISO, Role.BRANCH_MANAGER],
    AlertCategory.SECURITY_DEVICE_TAMPER: [Role.CISO],
    AlertCategory.UNEXPLAINED_EXIT: [Role.CISO, Role.IT_ASSET_MANAGER],
    # Logistics (slides 27-28).
    AlertCategory.SHIPMENT_VARIANCE: [Role.CISO, Role.IT_ASSET_MANAGER],
    AlertCategory.SHIPMENT_OVERDUE: [Role.CISO, Role.IT_ASSET_MANAGER],
}

TEMPERATURE_LIMIT_C = 35.0


def parse_ts(value: Any, default: datetime | None = None) -> datetime:
    """Parse an ISO-8601 timestamp to naive UTC. Timestamps in the future are clamped to now."""
    if isinstance(value, str) and value:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return min(value.replace(microsecond=0), utcnow())
    return default or utcnow()


def resolve_asset(db: Session, ref: dict[str, Any]) -> Asset | None:
    """Find a registered asset from an asset number, serial, MAC or IP reported by a collector."""
    if ref.get("asset_number"):
        found = db.execute(select(Asset).where(Asset.asset_number == ref["asset_number"])).scalar_one_or_none()
        if found:
            return found
    live = Asset.status != AssetStatus.DISPOSED.value
    for field, column in (("serial", Asset.serial_number), ("mac", Asset.mac_address), ("ip", Asset.ip_address)):
        value = ref.get(field)
        if value:
            value = value.lower() if field == "mac" else value
            found = db.execute(select(Asset).where(column == value, live).order_by(Asset.id.desc())).scalars().first()
            if found:
                return found
    return None


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def _ticket_ref(alert: Alert) -> str | None:
    return f"INC-{alert.id:06d}" if alert.severity in (Severity.P1.value, Severity.P2.value, Severity.P3.value) else None


def open_alert(db: Session, dedup_key: str) -> Alert | None:
    return db.execute(select(Alert).where(Alert.dedup_key == dedup_key,
                                          Alert.status != AlertStatus.RESOLVED.value)).scalars().first()


def raise_alert(db: Session, *, dedup_key: str, severity: Severity, category: AlertCategory, title: str,
                asset: Asset | None = None, branch: Branch | None = None, detail: str | None = None,
                occurred_at: datetime | None = None, source: AlertSource = AlertSource.MONITORING) -> Alert:
    existing = open_alert(db, dedup_key)
    if existing:
        if detail:
            existing.detail = detail
        # Escalate severity if the situation got worse (e.g. backup link also failed).
        if severity.value < existing.severity:
            existing.severity = severity.value
        return existing
    branch = branch or (asset.branch if asset else None)
    now = utcnow()
    alert = Alert(dedup_key=dedup_key, severity=severity.value, category=category.value, source=source.value,
                  title=title[:255], detail=detail, asset_id=asset.id if asset else None,
                  branch_id=branch.id if branch else None, status=AlertStatus.OPEN.value,
                  occurred_at=min(occurred_at or now, now), detected_at=now, escalation_level=0)
    db.add(alert)
    db.flush()
    alert.ticket_ref = _ticket_ref(alert)
    roles = list(ESCALATION_CHAIN[0]) + CATEGORY_AUDIENCE.get(category, [])
    channels = SEVERITY_CHANNELS[severity]
    if channels:
        where = f"{branch.code} {branch.name}" if branch else "estate"
        record_escalation(db, alert, 0, "Alert raised", roles, channels,
                          f"[{severity.value}] {title}", f"{where}\n{detail or ''}\nTicket: {alert.ticket_ref}")
    if category == AlertCategory.BRANCH_OFFLINE and branch is not None:
        # A branch completely offline is business-critical: the CEO is told immediately, not after escalation.
        record_escalation(db, alert, CEO_LEVEL, "Branch completely offline — immediate CEO alert", ESCALATION_CHAIN[CEO_LEVEL],
                          CEO_CHANNELS, f"CRITICAL: {branch.code} {branch.name} is completely offline",
                          f"All WAN links to {branch.name} are down. NOC is responding. Ticket {alert.ticket_ref}.")
    auditlog.record(db, None, "alert.raise", "alert", alert.id, severity=severity.value, category=category.value,
                    title=title, asset=asset.asset_number if asset else None, branch=branch.code if branch else None)
    if category in (AlertCategory.DEVICE_DOWN, AlertCategory.DEVICE_NOT_DISCOVERED, AlertCategory.DEVICE_SWAPPED):
        from itam.services.security import attach_comms_room_clip

        attach_comms_room_clip(db, alert)
    return alert


def alert_ever_raised(db: Session, dedup_key: str) -> bool:
    return db.execute(select(Alert.id).where(Alert.dedup_key == dedup_key)).first() is not None


def auto_resolve(db: Session, dedup_key: str, resolution: str, at: datetime | None = None) -> Alert | None:
    alert = open_alert(db, dedup_key)
    if alert:
        alert.status = AlertStatus.RESOLVED.value
        alert.resolved_at = at or utcnow()
        alert.resolution = resolution
        auditlog.record(db, None, "alert.auto_resolve", "alert", alert.id, resolution=resolution)
    return alert


def acknowledge(db: Session, actor: User, alert: Alert) -> Alert:
    if not can(actor, "alert.respond"):
        raise PermissionDenied("You may not respond to alerts")
    if alert.status != AlertStatus.OPEN.value:
        raise ServiceError("Alert is not open")
    alert.status = AlertStatus.ACKNOWLEDGED.value
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by_id = actor.id
    auditlog.record(db, actor, "alert.ack", "alert", alert.id)
    return alert


def resolve(db: Session, actor: User, alert: Alert, resolution: str) -> Alert:
    if not can(actor, "alert.respond"):
        raise PermissionDenied("You may not respond to alerts")
    if alert.status == AlertStatus.RESOLVED.value:
        raise ServiceError("Alert already resolved")
    if not resolution or not resolution.strip():
        raise ServiceError("Resolution notes are required")
    now = utcnow()
    if not alert.acknowledged_at:
        alert.acknowledged_at, alert.acknowledged_by_id = now, actor.id
    alert.status = AlertStatus.RESOLVED.value
    alert.resolved_at = now
    alert.resolved_by_id = actor.id
    alert.resolution = resolution.strip()
    auditlog.record(db, actor, "alert.resolve", "alert", alert.id, resolution=resolution)
    from itam.services.security import clear_suspected_removal

    clear_suspected_removal(db, alert)
    return alert


def report_user_incident(db: Session, actor: User, branch: Branch, description: str, asset: Asset | None = None,
                         severity: Severity = Severity.P2, occurred_at: datetime | None = None) -> Alert:
    """An outage reported by staff/customers rather than detected by monitoring (proactive-rate KPI)."""
    if not can(actor, "incident.report"):
        raise PermissionDenied("Only the NOC logs user-reported incidents")
    key_asset = f"DOWN:{asset.id}" if asset else None
    for key in filter(None, [key_asset, f"BRANCH_OFFLINE:{branch.id}"]):
        existing = open_alert(db, key)
        if existing:
            existing.detail = (existing.detail or "") + f"\nAlso reported by users: {description}"
            return existing  # already detected by monitoring
    category = AlertCategory.DEVICE_DOWN if asset else AlertCategory.BRANCH_OFFLINE
    alert = raise_alert(db, dedup_key=f"USER:{branch.id}:{utcnow().isoformat()}", severity=severity,
                        category=category, title=f"User-reported outage: {description[:120]}", asset=asset,
                        branch=branch, detail=description, occurred_at=occurred_at, source=AlertSource.USER_REPORT)
    auditlog.record(db, actor, "incident.user_report", "alert", alert.id, branch=branch.code)
    return alert


def record_escalation(db: Session, alert: Alert, level: int, reason: str, roles: list[Role],
                      channels: list[NotificationChannel], subject: str, body: str) -> AlertEscalation:
    from itam.notifications import users_with_role

    users: dict[int, User] = {}
    for role in roles:
        for u in users_with_role(db, role, alert.branch):
            users[u.id] = u
    sent = notify(db, users.values(), subject, body, channels, alert_id=alert.id)
    step = AlertEscalation(level=level, at=utcnow(), reason=reason[:160],
                           recipients=sorted(u.full_name for u in users.values()),
                           channels=[c.value for c in channels], notifications_sent=len(sent))
    alert.escalations.append(step)
    db.flush()
    return step


def ceo_informed(alert: Alert) -> bool:
    return any(e.level == CEO_LEVEL for e in alert.escalations)


def escalate_overdue(db: Session, now: datetime | None = None) -> int:
    """Escalate unacknowledged alerts one level per elapsed response target, up to the severity's ceiling."""
    now = now or utcnow()
    count = 0
    alerts = db.execute(select(Alert).where(Alert.status == AlertStatus.OPEN.value)).scalars().all()
    for alert in alerts:
        sev = Severity(alert.severity)
        target = alert.escalation_step
        due_level = min(int((now - alert.detected_at) / target), MAX_ESCALATION[sev])
        if due_level <= alert.escalation_level:
            continue
        for level in range(alert.escalation_level + 1, due_level + 1):
            if level == CEO_LEVEL and ceo_informed(alert):
                continue
            lvl = ESCALATION_LEVELS[level]
            minutes = int((now - alert.detected_at).total_seconds() // 60)
            record_escalation(db, alert, level, f"Not acknowledged within {minutes} min", lvl["roles"],
                              SEVERITY_CHANNELS[sev] or [C.EMAIL, C.SYSTEM],
                              f"ESCALATION {lvl['code']} [{alert.severity}] {alert.title}",
                              f"Unacknowledged for {minutes} min. Ticket {alert.ticket_ref}")
            auditlog.record(db, None, "alert.escalate", "alert", alert.id, level=lvl["code"],
                            roles=[r.value for r in lvl["roles"]])
        alert.escalation_level = due_level
        alert.last_escalated_at = now
        count += 1
    return count


def escalation_path(alert: Alert, now: datetime | None = None) -> list[dict]:
    """L1 → L2 → L3 → CEO with the state of each step: done, due (time), skipped or not applicable."""
    now = now or utcnow()
    sev = Severity(alert.severity)
    target = alert.escalation_step
    done = {}
    for e in alert.escalations:
        done.setdefault(e.level, e)
    steps = []
    for level, lvl in enumerate(ESCALATION_LEVELS):
        e = done.get(level)
        due_at = alert.detected_at + target * level
        if e:
            state = "done"
        elif level > MAX_ESCALATION[sev] or (level > 0 and not SEVERITY_CHANNELS[sev]):
            state = "na"
        elif alert.acknowledged_at or alert.status == AlertStatus.RESOLVED.value:
            state = "stopped"
        else:
            state = "due" if due_at > now else "overdue"
        steps.append({"level": level, "code": lvl["code"], "name": lvl["name"], "state": state, "escalation": e,
                      "due_at": due_at})
    return steps


# ---------------------------------------------------------------------------
# Collector ingestion
# ---------------------------------------------------------------------------


def heartbeat(db: Session, collector: Collector) -> None:
    collector.last_heartbeat_at = utcnow()
    auto_resolve(db, f"COLLECTOR:{collector.id}", "Collector reporting again")


def _branch_routers(db: Session, branch_id: int) -> list[Asset]:
    return db.execute(select(Asset).where(
        Asset.branch_id == branch_id, Asset.asset_type == AssetType.RTR.value, Asset.monitored.is_(True),
        Asset.status.in_([s.value for s in INSTALLED_STATUSES]),
    )).scalars().all()


def _classify_down(db: Session, asset: Asset) -> tuple[Severity, AlertCategory, str, str]:
    """Severity rules from slide 21. Returns (severity, category, dedup_key, title)."""
    branch = asset.branch
    if asset.asset_type == AssetType.RTR.value:
        routers = _branch_routers(db, branch.id)
        if all(r.oper_state == OperState.DOWN.value for r in routers):
            return (Severity.P1, AlertCategory.BRANCH_OFFLINE, f"BRANCH_OFFLINE:{branch.id}",
                    f"Branch offline: {branch.code} {branch.name}")
        return (Severity.P2, AlertCategory.REDUNDANCY_LOST, f"DOWN:{asset.id}",
                f"Redundancy lost: {asset.hostname or asset.asset_number} down at {branch.code}")
    if asset.asset_type == AssetType.FWL.value or asset.criticality == Criticality.CRITICAL.value:
        return (Severity.P1, AlertCategory.DEVICE_DOWN, f"DOWN:{asset.id}",
                f"Core device down: {asset.hostname or asset.asset_number} at {branch.code}")
    if asset.asset_type == AssetType.SRV.value or asset.criticality == Criticality.HIGH.value:
        return (Severity.P2, AlertCategory.DEVICE_DOWN, f"DOWN:{asset.id}",
                f"Device down: {asset.hostname or asset.asset_number} at {branch.code}")
    return (Severity.P3, AlertCategory.DEVICE_DOWN, f"DOWN:{asset.id}",
            f"Device down: {asset.hostname or asset.asset_number} at {branch.code}")


def _record_event(db: Session, asset: Asset | None, collector: Collector | None, occurred_at: datetime, kind: str,
                  metric: str | None = None, value: Any = None, message: str | None = None,
                  severity: str | None = None) -> MonitoringEvent:
    ev = MonitoringEvent(asset_id=asset.id if asset else None, branch_id=asset.branch_id if asset else None,
                         collector_id=collector.id if collector else None, occurred_at=occurred_at, kind=kind,
                         metric=metric, value=None if value is None else str(value)[:120], message=message,
                         severity=severity, received_at=utcnow())
    db.add(ev)
    return ev


def apply_state(db: Session, asset: Asset, state: OperState, occurred_at: datetime,
                collector: Collector | None = None, message: str | None = None) -> Alert | None:
    """Apply one polled up/down/degraded state to an asset."""
    if state in (OperState.UP, OperState.DEGRADED):
        asset.last_seen_at = max(asset.last_seen_at or occurred_at, occurred_at)
    if not asset.monitored or asset.status not in [s.value for s in INSTALLED_STATUSES]:
        return None
    previous = OperState(asset.oper_state)
    if previous == state:
        return None
    if asset.oper_state_since and occurred_at < asset.oper_state_since:
        return None  # stale buffered sample, a newer state is already known
    asset.oper_state = state.value
    asset.oper_state_since = occurred_at
    ev = _record_event(db, asset, collector, occurred_at, "STATE", "availability", state.value, message)
    alert: Alert | None = None

    if state == OperState.DOWN and asset.asset_type != AssetType.RTR.value \
            and open_alert(db, f"BRANCH_OFFLINE:{asset.branch_id}"):
        # Event correlation: the branch is unreachable, so this device's state is unknown, not "down".
        asset.oper_state = OperState.UNKNOWN.value
        ev.value = OperState.UNKNOWN.value
        ev.message = "Suppressed: branch offline"
        return None

    if state == OperState.DOWN:
        severity, category, key, title = _classify_down(db, asset)
        alert = raise_alert(db, dedup_key=key, severity=severity, category=category, title=title, asset=asset,
                            detail=message, occurred_at=occurred_at)
        if asset.asset_type == AssetType.RTR.value and category == AlertCategory.BRANCH_OFFLINE:
            # A redundancy alert may already exist for the first router; the branch alert supersedes it.
            for r in _branch_routers(db, asset.branch_id):
                auto_resolve(db, f"DOWN:{r.id}", "Superseded by branch-offline alert", occurred_at)
        if asset.status == AssetStatus.ACTIVE.value:
            set_status(db, asset, AssetStatus.FAULTY, None, "ALARM", f"Monitoring: {title}")
    elif state == OperState.DEGRADED:
        alert = raise_alert(db, dedup_key=f"DEGRADED:{asset.id}", severity=Severity.P3,
                            category=AlertCategory.DEGRADED,
                            title=f"Performance degraded: {asset.hostname or asset.asset_number} at {asset.branch.code}",
                            asset=asset, detail=message, occurred_at=occurred_at)
        if previous == OperState.DOWN:
            _recovered(db, asset, occurred_at)
    else:  # UP
        _recovered(db, asset, occurred_at)
        auto_resolve(db, f"DEGRADED:{asset.id}", "Performance back to normal", occurred_at)
    if alert:
        ev.ticket_ref = alert.ticket_ref
        ev.severity = alert.severity
    return alert


def _recovered(db: Session, asset: Asset, at: datetime) -> None:
    auto_resolve(db, f"DOWN:{asset.id}", "Device recovered (monitoring)", at)
    if asset.asset_type == AssetType.RTR.value:
        auto_resolve(db, f"BRANCH_OFFLINE:{asset.branch_id}", "Branch link restored", at)
    if asset.status == AssetStatus.FAULTY.value:
        set_status(db, asset, AssetStatus.ACTIVE, None, "RECOVERED", "Monitoring: device back up")


def _apply_metrics(db: Session, asset: Asset, metrics: dict[str, Any], occurred_at: datetime,
                   collector: Collector | None) -> None:
    asset.last_metrics = {**(asset.last_metrics or {}), **metrics, "_at": occurred_at.isoformat()}
    temp = metrics.get("temperature_c")
    on_battery = metrics.get("on_battery")
    key = f"ENV:{asset.id}"
    problems = []
    if temp is not None and float(temp) >= TEMPERATURE_LIMIT_C:
        problems.append(f"temperature {temp}°C")
    if on_battery in (True, "true", 1, "1"):
        problems.append("UPS on battery (mains power lost)")
    if problems:
        _record_event(db, asset, collector, occurred_at, "METRIC", "environment", ", ".join(problems))
        raise_alert(db, dedup_key=key, severity=Severity.P2, category=AlertCategory.ENVIRONMENT,
                    title=f"Environment alarm at {asset.branch.code}: {', '.join(problems)}", asset=asset,
                    occurred_at=occurred_at)
    elif temp is not None or on_battery is not None:
        auto_resolve(db, key, "Environment back to normal", occurred_at)


def ingest_poll_results(db: Session, collector: Collector | None, results: list[dict[str, Any]]) -> dict[str, int]:
    """Collector poll results: [{asset_number|serial|mac|ip, state, occurred_at, metrics, message}]."""
    applied = unknown = alerts = 0
    for item in sorted(results, key=lambda r: str(r.get("occurred_at") or "")):
        asset = resolve_asset(db, item)
        if asset is None:
            unknown += 1
            continue
        occurred_at = parse_ts(item.get("occurred_at"))
        state_raw = (item.get("state") or "").upper()
        if state_raw:
            if state_raw not in OperState._value2member_map_:
                raise ServiceError(f"Unknown state {state_raw}")
            if apply_state(db, asset, OperState(state_raw), occurred_at, collector, item.get("message")):
                alerts += 1
        if item.get("metrics"):
            _apply_metrics(db, asset, item["metrics"], occurred_at, collector)
        applied += 1
    if collector:
        heartbeat(db, collector)
    return {"applied": applied, "unknown": unknown, "alerts": alerts}


def ingest_events(db: Session, collector: Collector | None, events: list[dict[str, Any]]) -> dict[str, int]:
    """Syslog / SNMP traps / config-change notifications."""
    from itam.services.changes import authorised_change_for

    stored = flagged = 0
    for item in events:
        asset = resolve_asset(db, item)
        occurred_at = parse_ts(item.get("occurred_at"))
        kind = (item.get("kind") or "SYSLOG").upper()
        message = item.get("message")
        _record_event(db, asset, collector, occurred_at, kind, item.get("metric"), item.get("value"), message,
                      item.get("severity"))
        stored += 1
        if kind == "CONFIG_CHANGE" and asset is not None:
            change = authorised_change_for(db, asset)
            if change is None and not item.get("change_ref"):
                raise_alert(db, dedup_key=f"CONFIG:{asset.id}:{occurred_at.isoformat()}", severity=Severity.P3,
                            category=AlertCategory.CONFIG_CHANGE,
                            title=f"Unapproved configuration change on {asset.hostname or asset.asset_number}",
                            asset=asset, detail=message, occurred_at=occurred_at)
                flagged += 1
    if collector:
        heartbeat(db, collector)
    return {"stored": stored, "unapproved_config_changes": flagged}


def check_collectors(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    stale = timedelta(minutes=settings.collector_stale_minutes)
    raised = 0
    for c in db.execute(select(Collector).where(Collector.is_active.is_(True))).scalars():
        if c.last_heartbeat_at and now - c.last_heartbeat_at > stale:
            raise_alert(db, dedup_key=f"COLLECTOR:{c.id}", severity=Severity.P2,
                        category=AlertCategory.COLLECTOR_OFFLINE, title=f"Collector {c.name} not reporting",
                        detail=f"Last heartbeat {c.last_heartbeat_at:%Y-%m-%d %H:%M} UTC",
                        source=AlertSource.SCHEDULER)
            raised += 1
    return raised


def collector_healthy_for(db: Session, branch: Branch, now: datetime | None = None) -> bool:
    now = now or utcnow()
    stale = now - timedelta(minutes=settings.collector_stale_minutes)
    return db.execute(select(Collector.id).where(
        Collector.is_active.is_(True), Collector.last_heartbeat_at >= stale,
        or_(Collector.region_id == branch.region_id, Collector.region_id.is_(None)),
    )).first() is not None


def warranty_and_eol_alerts(db: Session, today=None) -> int:
    """P4 informational alerts for warranty expiry / end-of-support within the warning window."""
    today = today or date.today()
    horizon = today + timedelta(days=settings.warranty_warning_days)
    raised = 0
    assets = db.execute(select(Asset).where(Asset.status.notin_([AssetStatus.DISPOSED.value,
                                                                  AssetStatus.RETIRED.value]))).scalars()
    for asset in assets:
        wend = asset.effective_warranty_end
        if wend and today <= wend <= horizon and not alert_ever_raised(db, f"WARRANTY:{asset.id}:{wend}"):
            raise_alert(db, dedup_key=f"WARRANTY:{asset.id}:{wend}", severity=Severity.P4,
                        category=AlertCategory.WARRANTY_EXPIRY,
                        title=f"Warranty expires {wend:%Y-%m-%d}: {asset.asset_number}", asset=asset,
                        source=AlertSource.SCHEDULER)
            raised += 1
        eos = asset.eos_date
        if eos and eos <= horizon and not alert_ever_raised(db, f"EOS:{asset.id}:{eos}"):
            raise_alert(db, dedup_key=f"EOS:{asset.id}:{eos}", severity=Severity.P4, category=AlertCategory.END_OF_LIFE,
                        title=f"End of support {eos:%Y-%m-%d}: {asset.asset_number} ({asset.model.display})",
                        asset=asset, source=AlertSource.SCHEDULER)
            raised += 1
    return raised
