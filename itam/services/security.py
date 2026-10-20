"""Removal detection and physical security: RFID, cameras and alarms in one event engine (slides 31-33).

1. Detect  — exit-portal read, cabinet reader no longer sees a tag, door contact, motion, device health.
2. Correlate — is there an approved change / transfer / repair ticket or shipment for the asset? an authorised
   badge at this door just now? are we inside an approved change window?
3. Act — approved: log and keep the clip as evidence. Otherwise: P1 incident, camera bookmark + clip
   (30 s before / 60 s after), asset flagged 'suspected removal'.
4. Notify — SOC / NOC, branch manager, security; unacknowledged alarms escalate every 5 minutes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.config import settings
from itam.enums import (
    AlertCategory,
    AlertSource,
    AlertStatus,
    BranchTier,
    ChangeStatus,
    ClipStatus,
    ReadPointKind,
    SecurityEventKind,
    Severity,
    ShipmentStatus,
)
from itam.models import (
    Alert,
    Asset,
    Branch,
    ChangeRequest,
    Collector,
    ReadPoint,
    SecurityEvent,
    Shipment,
    ShipmentItem,
    VideoClip,
    utcnow,
)
from itam.services import NotFound, PermissionDenied, ServiceError
from itam.services.assets import add_history

log = logging.getLogger("itam.security")

CLIP_BEFORE = timedelta(seconds=30)
CLIP_AFTER = timedelta(seconds=60)


# ---------------------------------------------------------------------------
# Video management system (bookmark, clip, PTZ)
# ---------------------------------------------------------------------------


def request_clip(db: Session, alert: Alert, camera_ref: str | None, at: datetime, evidence_only: bool = False) -> VideoClip | None:
    """Bookmark the camera and ask the VMS for a clip around ``at``; PTZ to preset and snapshot for alarms."""
    if not camera_ref:
        return None
    clip = VideoClip(alert_id=alert.id, camera_ref=camera_ref, start_at=at - CLIP_BEFORE, end_at=at + CLIP_AFTER,
                     status=ClipStatus.REQUESTED.value if settings.vms_url else ClipStatus.NOT_CONFIGURED.value,
                     requested_at=utcnow())
    alert.clips.append(clip)
    db.flush()
    if settings.vms_url:
        payload = {"action": "bookmark_clip" if evidence_only else "bookmark_clip_ptz_snapshot", "camera": camera_ref,
                   "start": clip.start_at.isoformat() + "Z", "end": clip.end_at.isoformat() + "Z",
                   "alert": alert.ticket_ref or alert.id, "clip_id": clip.id}
        try:
            req = urllib.request.Request(settings.vms_url, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 - configured internal endpoint
                body = json.loads(resp.read() or b"{}")
                clip.vms_ref = str(body.get("ref") or body.get("bookmark") or "")[:120] or None
        except Exception as exc:  # noqa: BLE001 - the alarm must still be raised if the VMS is unreachable
            log.warning("VMS request failed for alert %s: %s", alert.id, exc)
    auditlog.record(db, None, "security.clip_request", "alert", alert.id, camera=camera_ref,
                    start=clip.start_at.isoformat(), end=clip.end_at.isoformat(), status=clip.status)
    return clip


def archive_clip(db: Session, clip_id: int, *, sha256: str, url: str | None = None, vms_ref: str | None = None) -> VideoClip:
    """VMS callback: the clip was exported; its hash is kept as evidence (slide 31: clip hashed and kept)."""
    clip = db.get(VideoClip, clip_id)
    if clip is None:
        raise NotFound("Clip not found")
    sha256 = (sha256 or "").strip().lower()
    if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
        raise ServiceError("sha256 must be 64 hexadecimal characters")
    if clip.sha256 and clip.sha256 != sha256:
        raise ServiceError("Clip already archived with a different hash", 409)
    clip.sha256, clip.url = sha256, url or clip.url
    clip.vms_ref = vms_ref or clip.vms_ref
    clip.status = ClipStatus.ARCHIVED.value
    clip.archived_at = utcnow()
    auditlog.record(db, None, "security.clip_archived", "alert", clip.alert_id, clip=clip.id, sha256=sha256)
    return clip


def clip_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def comms_room_camera(db: Session, branch: Branch) -> str | None:
    rp = db.execute(select(ReadPoint).where(ReadPoint.branch_id == branch.id, ReadPoint.camera_ref.is_not(None),
                                            ReadPoint.kind == ReadPointKind.CABINET.value)).scalars().first()
    return rp.camera_ref if rp else None


def attach_comms_room_clip(db: Session, alert: Alert) -> None:
    """Port down / device swapped at a Tier A branch: attach the comms-room clip around the event (slide 33)."""
    branch = alert.branch
    if branch is None or (branch.security_tier or BranchTier.B.value) != BranchTier.A.value:
        return
    request_clip(db, alert, comms_room_camera(db, branch), alert.occurred_at)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def authorised_badge(db: Session, branch: Branch, at: datetime, door: str | None = None) -> SecurityEvent | None:
    """An authorised badge at this site (and door, if known) within the badge window before ``at``."""
    q = select(SecurityEvent).where(
        SecurityEvent.branch_id == branch.id, SecurityEvent.kind == SecurityEventKind.BADGE.value,
        SecurityEvent.authorised.is_(True),
        SecurityEvent.occurred_at >= at - timedelta(seconds=settings.badge_window_seconds),
        SecurityEvent.occurred_at <= at + timedelta(seconds=10),
    )
    if door:
        q = q.where(SecurityEvent.door == door)
    return db.execute(q.order_by(SecurityEvent.occurred_at.desc())).scalars().first()


def change_window(db: Session, branch: Branch, at: datetime, asset: Asset | None = None) -> ChangeRequest | None:
    """An approved / in-progress change at the branch scheduled within the change window around ``at``."""
    window = timedelta(hours=settings.change_window_hours)
    q = select(ChangeRequest).where(
        ChangeRequest.from_branch_id == branch.id,
        ChangeRequest.status.in_([ChangeStatus.APPROVED.value, ChangeStatus.IN_PROGRESS.value]),
        ChangeRequest.scheduled_for.is_not(None),
        ChangeRequest.scheduled_for >= at - window, ChangeRequest.scheduled_for <= at + window,
    )
    if asset is not None:
        q = q.where(ChangeRequest.asset_id == asset.id)
    return db.execute(q).scalars().first()


def removal_ticket(db: Session, asset: Asset) -> str | None:
    """The ticket that explains an asset leaving its place: an approved change or an open shipment."""
    from itam.services.changes import authorised_change_for

    change = authorised_change_for(db, asset)
    if change is not None:
        return change.reference
    item = db.execute(select(ShipmentItem).join(Shipment).where(
        ShipmentItem.asset_id == asset.id,
        Shipment.status.in_([ShipmentStatus.PACKED.value, ShipmentStatus.IN_TRANSIT.value]),
    )).scalars().first()
    return item.shipment.reference if item else None


def _alarm(db: Session, *, key: str, category: AlertCategory, severity: Severity, title: str, detail: str,
           branch: Branch, asset: Asset | None, at: datetime, camera_ref: str | None) -> Alert:
    from itam.services.monitoring import open_alert, raise_alert

    is_new = open_alert(db, key) is None
    alert = raise_alert(db, dedup_key=key, severity=severity, category=category, title=title, asset=asset,
                        branch=branch, detail=detail, occurred_at=at, source=AlertSource.SECURITY)
    if is_new:
        request_clip(db, alert, camera_ref, at)
    return alert


def exit_read(db: Session, asset: Asset, rp: ReadPoint, at: datetime) -> tuple[bool, str]:
    """A tagged asset passed an exit portal. Returns (alarm_raised, detail)."""
    from itam.services.monitoring import raise_alert

    branch = rp.branch
    ticket = removal_ticket(db, asset)
    badge = authorised_badge(db, branch, at)
    window = change_window(db, branch, at, asset)
    context = (f"badge {badge.badge_id} authorised at {badge.door or 'door'}" if badge else "no authorised badge") + \
              (f"; inside change window {window.reference}" if window else "")
    if ticket:
        # Approved removal: log only, keep the exit clip as evidence (slide 33, last row).
        alert = raise_alert(db, dedup_key=f"EXIT_OK:{asset.id}:{at:%Y%m%d%H%M}", severity=Severity.P4,
                            category=AlertCategory.SUSPECTED_REMOVAL, asset=asset, branch=branch, occurred_at=at,
                            source=AlertSource.SECURITY,
                            title=f"Approved exit: {asset.asset_number} left {branch.code} under {ticket}",
                            detail=f"Exit portal {rp.code}; {context}. Clip archived as evidence.")
        alert.status, alert.resolved_at, alert.resolution = AlertStatus.RESOLVED.value, utcnow(), f"Authorised by {ticket}"
        request_clip(db, alert, rp.camera_ref, at, evidence_only=True)
        add_history(db, asset, None, "EXIT_AUTHORISED", f"Left through {rp.name} under {ticket}")
        return False, f"authorised by {ticket}; {context}"
    asset.suspected_removal_at = at
    add_history(db, asset, None, "SUSPECTED_REMOVAL", f"Read at exit portal {rp.name} with no approved ticket")
    _alarm(db, key=f"REMOVAL:{asset.id}", category=AlertCategory.SUSPECTED_REMOVAL, severity=Severity.P1,
           title=f"Suspected removal: {asset.asset_number} ({asset.hostname or asset.asset_type}) passed the exit at "
                 f"{branch.code} with no approved ticket",
           detail=f"Exit portal {rp.code} at {at:%H:%M:%S} UTC; {context}. Exit-camera clip and PTZ snapshot requested.",
           branch=branch, asset=asset, at=at, camera_ref=rp.camera_ref)
    return True, f"ALARM: no approved ticket; {context}"


def cabinet_not_seen(db: Session, asset: Asset, rp: ReadPoint, at: datetime, cycles: int) -> tuple[bool, str]:
    """The cabinet reader missed the tag for ``cycles`` read cycles (slide 33: 2 cycles, no change ticket)."""
    if cycles < settings.cabinet_missed_cycles:
        return False, f"missed {cycles} cycle(s); waiting for {settings.cabinet_missed_cycles}"
    ticket = removal_ticket(db, asset) or (w.reference if (w := change_window(db, rp.branch, at, asset)) else None)
    if ticket:
        return False, f"not seen in cabinet; authorised by {ticket}"
    seen = f"last seen by discovery {asset.last_seen_at:%Y-%m-%d %H:%M} UTC" if asset.last_seen_at else "never seen by discovery"
    _alarm(db, key=f"CABINET:{asset.id}", category=AlertCategory.CABINET_TAG_MISSING, severity=Severity.P1,
           title=f"Tag not seen in comms cabinet: {asset.asset_number} at {rp.branch.code}",
           detail=f"Cabinet reader {rp.code} missed {cycles} read cycles; no change ticket. Cross-check: {seen}, "
                  f"monitoring state {asset.oper_state}. Comms-room clip requested.",
           branch=rp.branch, asset=asset, at=at, camera_ref=rp.camera_ref)
    return True, f"ALARM: missed {cycles} cycles, no change ticket"


def reader_tamper(db: Session, rp: ReadPoint, at: datetime, message: str) -> Alert:
    return _alarm(db, key=f"TAMPER:RP:{rp.id}", category=AlertCategory.SECURITY_DEVICE_TAMPER, severity=Severity.P2,
                  title=f"RFID reader offline or tampered: {rp.name} at {rp.branch.code}",
                  detail=f"{message}. Engineer to be dispatched.", branch=rp.branch, asset=None, at=at,
                  camera_ref=rp.camera_ref)


def check_readers(db: Session, now: datetime | None = None) -> int:
    """Fixed readers that stopped reporting are treated as tampered / offline (scheduled job)."""
    from itam.services.monitoring import open_alert

    now = now or utcnow()
    cutoff = now - timedelta(minutes=settings.reader_stale_minutes)
    # A reader that went silent recently is the tamper signal; one silent for over a day is already known
    # (decommissioned, or never commissioned) and is shown on the health widgets instead of re-alarming.
    recent = now - timedelta(hours=24)
    fixed = [k.value for k in (ReadPointKind.DOCK_IN, ReadPointKind.CAGE, ReadPointKind.DISPATCH,
                               ReadPointKind.CABINET, ReadPointKind.EXIT_PORTAL)]
    raised = 0
    for rp in db.execute(select(ReadPoint).where(ReadPoint.is_active.is_(True), ReadPoint.kind.in_(fixed),
                                                 ReadPoint.last_heartbeat_at.is_not(None),
                                                 ReadPoint.last_heartbeat_at < cutoff,
                                                 ReadPoint.last_heartbeat_at >= recent)).scalars():
        if open_alert(db, f"TAMPER:RP:{rp.id}") is None:
            reader_tamper(db, rp, rp.last_heartbeat_at, f"No reads or heartbeat since {rp.last_heartbeat_at:%Y-%m-%d %H:%M} UTC")
            raised += 1
    return raised


def ingest_events(db: Session, collector: Collector | None, events: list[dict[str, Any]]) -> dict[str, int]:
    """Access-control badges, door contacts, motion sensors and camera / reader health from the security systems."""
    from itam.services.monitoring import parse_ts

    counts = {"received": 0, "alarms": 0, "logged": 0}
    for ev in events:
        branch = db.execute(select(Branch).where(Branch.code == ev.get("branch_code"))).scalar_one_or_none()
        if branch is None:
            raise NotFound(f"Unknown branch {ev.get('branch_code')}")
        if collector and collector.region_id and branch.region_id != collector.region_id:
            raise PermissionDenied("Branch is outside this collector's region")
        kind = (ev.get("kind") or "").upper()
        if kind not in SecurityEventKind._value2member_map_:
            raise ServiceError(f"Unknown security event kind {kind}")
        at = parse_ts(ev.get("occurred_at"))
        event = SecurityEvent(branch_id=branch.id, kind=kind, occurred_at=at, door=ev.get("door"),
                              badge_id=ev.get("badge_id"), authorised=ev.get("authorised"),
                              device_ref=ev.get("device_ref") or ev.get("camera_ref"), message=ev.get("message"))
        db.add(event)
        db.flush()
        counts["received"] += 1
        alert = _correlate(db, event, ev.get("camera_ref"))
        if alert is not None:
            event.alert_id = alert.id
            counts["alarms"] += 1
        else:
            counts["logged"] += 1
    if collector:
        collector.last_heartbeat_at = utcnow()
    return counts


def _correlate(db: Session, event: SecurityEvent, camera_ref: str | None) -> Alert | None:
    branch, at = event.branch, event.occurred_at
    camera_ref = camera_ref or comms_room_camera(db, branch)
    after_hours = settings.is_after_hours(at.hour)
    kind = SecurityEventKind(event.kind)
    if kind == SecurityEventKind.BADGE:
        return None
    if kind == SecurityEventKind.DOOR_OPEN:
        badge = authorised_badge(db, branch, at, event.door)
        window = change_window(db, branch, at)
        if badge and (not after_hours or window):
            return None
        why = "after hours" if badge else "no authorised badge"
        return _alarm(db, key=f"DOOR:{branch.id}:{event.door or 'cabinet'}", category=AlertCategory.CABINET_DOOR,
                      severity=Severity.P1, title=f"Cabinet door opened at {branch.code} ({why})",
                      detail=f"Door {event.door or 'comms cabinet'} at {at:%H:%M:%S} UTC; {why}"
                             f"{'' if not window else '; change ' + window.reference + ' scheduled'}. "
                             f"Live view pushed to the SOC wall; clip saved.",
                      branch=branch, asset=None, at=at, camera_ref=camera_ref)
    if kind == SecurityEventKind.MOTION:
        if not after_hours or change_window(db, branch, at):
            return None
        return _alarm(db, key=f"MOTION:{branch.id}", category=AlertCategory.INTRUSION, severity=Severity.P2,
                      title=f"Movement after hours at {branch.code} {branch.name}",
                      detail=f"Motion sensor {event.device_ref or ''} at {at:%H:%M:%S} UTC outside business hours "
                             f"and outside any approved change window.",
                      branch=branch, asset=None, at=at, camera_ref=camera_ref)
    if kind == SecurityEventKind.DEVICE_TAMPER:
        return _alarm(db, key=f"TAMPER:{branch.id}:{event.device_ref or 'device'}",
                      category=AlertCategory.SECURITY_DEVICE_TAMPER, severity=Severity.P2,
                      title=f"Camera or reader tampered at {branch.code}: {event.device_ref or 'device'}",
                      detail=f"{event.message or 'Offline, view blocked or moved'}. Engineer to be dispatched.",
                      branch=branch, asset=None, at=at, camera_ref=None)
    return None


def clear_suspected_removal(db: Session, alert: Alert) -> None:
    """Resolving a removal incident clears the asset's 'suspected removal' flag."""
    if alert.category == AlertCategory.SUSPECTED_REMOVAL.value and alert.asset is not None:
        alert.asset.suspected_removal_at = None

