"""RFID read points and automatic updates (slides 20, 29).

The RFID middleware filters and de-duplicates raw reads, maps EPC → asset and reports events
(ARRIVED, LEFT, SEEN, NOT_SEEN) per read point. Each event is handled by the read point's role in the flow.

Rule (slide 29): a read never overwrites a record silently. Every read is stored with its outcome, every
automatic update is written to the asset history and the audit log, and any mismatch with the expected
state becomes an exception ticket (and, where it is a security matter, an alarm).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import (
    AlertCategory,
    AlertSource,
    AuditStatus,
    ExceptionSource,
    ExceptionType,
    ReadEvent,
    ReadOutcome,
    ReadPointKind,
    Severity,
    ShipmentStatus,
)
from itam.models import (
    Asset,
    Branch,
    Collector,
    Location,
    PhysicalAudit,
    ReadPoint,
    RfidRead,
    Shipment,
    ShipmentItem,
    User,
    utcnow,
)
from itam.rbac import can
from itam.services import NotFound, PermissionDenied, ServiceError
from itam.services.assets import add_history, find_by_epc, verify_rfid

RP = ReadPointKind
HANDHELD_KINDS = {RP.BRANCH_RECEIPT, RP.INSTALL, RP.AUDIT_SWEEP}


def create_read_point(db: Session, actor: User, *, code: str, name: str, kind: str, branch: Branch,
                      location_id: int | None = None, camera_ref: str | None = None) -> ReadPoint:
    if not can(actor, "readpoints.manage"):
        raise PermissionDenied("Only administrators and the ITAM Office can register read points")
    if kind not in ReadPointKind._value2member_map_:
        raise ServiceError("Unknown read-point type")
    code = (code or "").strip().upper()
    if not code or not (name or "").strip():
        raise ServiceError("Code and name are required")
    if db.execute(select(ReadPoint).where(ReadPoint.code == code)).first():
        raise ServiceError(f"Read point {code} already exists", 409)
    if location_id:
        loc = db.get(Location, location_id)
        if loc is None or loc.branch_id != branch.id:
            raise ServiceError("Location does not belong to the branch")
    rp = ReadPoint(code=code, name=name.strip(), kind=kind, branch_id=branch.id, location_id=location_id,
                   camera_ref=(camera_ref or "").strip() or None, is_active=True)
    db.add(rp)
    db.flush()
    auditlog.record(db, actor, "readpoint.create", "read_point", code, kind=kind, branch=branch.code,
                    camera=rp.camera_ref)
    return rp


def _exception(db: Session, asset: Asset | None, rp: ReadPoint, branch: Branch, key: str, summary: str,
               observed: dict) -> str:
    from itam.services.discovery import raise_exception

    exc, _ = raise_exception(db, exception_type=ExceptionType.RFID_MISMATCH, source=ExceptionSource.RFID,
                             dedup_key=key, branch=branch, asset=asset, summary=summary,
                             observed={"read_point": rp.code, **observed})
    return exc.ticket_ref


def heartbeat(db: Session, collector: Collector, codes: list[str]) -> int:
    from itam.services.monitoring import auto_resolve

    n = 0
    for rp in db.execute(select(ReadPoint).where(ReadPoint.code.in_([c.upper() for c in codes]))).scalars():
        _check_region(collector, rp.branch)
        rp.last_heartbeat_at = utcnow()
        auto_resolve(db, f"TAMPER:RP:{rp.id}", "Reader reporting again")
        n += 1
    return n


def _check_region(collector: Collector | None, branch: Branch) -> None:
    if collector and collector.region_id and branch.region_id != collector.region_id:
        raise PermissionDenied(f"Branch {branch.code} is outside this middleware's region")


def ingest_reads(db: Session, collector: Collector | None, reads: list[dict[str, Any]]) -> dict[str, int]:
    """Process a batch of middleware events. Returns counts per outcome."""
    from itam.services.monitoring import auto_resolve, parse_ts

    counts = {o.value: 0 for o in ReadOutcome}
    points: dict[str, ReadPoint] = {}
    for r in reads:
        code = (r.get("read_point") or "").strip().upper()
        rp = points.get(code) or db.execute(select(ReadPoint).where(ReadPoint.code == code)).scalar_one_or_none()
        if rp is None or not rp.is_active:
            raise NotFound(f"Unknown or inactive read point {code}")
        points[code] = rp
        # Handhelds move between branches; they say where they are reading.
        branch = rp.branch
        if r.get("branch_code") and RP(rp.kind) in HANDHELD_KINDS:
            branch = db.execute(select(Branch).where(Branch.code == r["branch_code"])).scalar_one_or_none()
            if branch is None:
                raise NotFound(f"Unknown branch {r['branch_code']}")
        _check_region(collector, branch)
        event = (r.get("event") or ReadEvent.SEEN.value).upper()
        if event not in ReadEvent._value2member_map_:
            raise ServiceError(f"Unknown read event {event}")
        at = parse_ts(r.get("read_at"))
        epc = (r.get("epc") or "").strip().upper()
        asset = find_by_epc(db, epc) if epc else None
        if asset is None:
            outcome, detail = ReadOutcome.UNKNOWN_TAG, "Tag is not a registered asset"
        else:
            outcome, detail = _handle(db, rp, branch, asset, ReadEvent(event), at, r)
        db.add(RfidRead(read_point_id=rp.id, epc=epc or "-", asset_id=asset.id if asset else None, event=event,
                        read_at=at, outcome=outcome.value, detail=detail, operator=r.get("operator"),
                        received_at=utcnow()))
        rp.last_heartbeat_at = utcnow()
        auto_resolve(db, f"TAMPER:RP:{rp.id}", "Reader reporting again")
        counts[outcome.value] += 1
    db.flush()
    if collector:
        collector.last_heartbeat_at = utcnow()
    return counts


def _touch(asset: Asset, rp: ReadPoint, at: datetime) -> None:
    asset.last_rfid_read_at = max(asset.last_rfid_read_at or at, at)
    asset.last_read_point_id = rp.id


def _handle(db: Session, rp: ReadPoint, branch: Branch, asset: Asset, event: ReadEvent, at: datetime,
            raw: dict[str, Any]) -> tuple[ReadOutcome, str]:
    from itam.services import logistics, security

    kind = RP(rp.kind)
    if event == ReadEvent.NOT_SEEN:
        if kind != RP.CABINET:
            return ReadOutcome.CONFIRMED, "Not-seen events are only acted on for cabinet readers"
        alarm, detail = security.cabinet_not_seen(db, asset, rp, at, int(raw.get("cycles_missed") or 1))
        return (ReadOutcome.EXCEPTION if alarm else ReadOutcome.CONFIRMED), detail
    _touch(asset, rp, at)

    if kind == RP.REGISTRATION:
        if asset.rfid_verified_at:
            return ReadOutcome.CONFIRMED, "Tag already verified"
        verify_rfid(db, None, asset, asset.rfid_epc, where=rp.name)
        return ReadOutcome.UPDATED, "Tag encoded and verified; record ready"

    if kind in (RP.CAGE, RP.DOCK_IN):
        if asset.branch_id != branch.id:
            ref = _exception(db, asset, rp, branch, f"RFID:LOC:{asset.id}:{branch.id}",
                             f"{asset.asset_number} read at {rp.name} ({branch.code}) but registered at {asset.branch.code}",
                             {"status": asset.status})
            return ReadOutcome.EXCEPTION, f"Registered at {asset.branch.code}; exception {ref}"
        if kind == RP.CAGE and event == ReadEvent.LEFT:
            ticket = security.removal_ticket(db, asset)
            if ticket:
                return ReadOutcome.CONFIRMED, f"Left the cage under {ticket}"
            return _unexplained_exit(db, rp, branch, asset, at, "left the secure store")
        return ReadOutcome.CONFIRMED, f"Stock location confirmed at {rp.name}"

    if kind == RP.DISPATCH:
        shipment = logistics.open_shipment_for(db, asset)
        if shipment is None or shipment.status != ShipmentStatus.PACKED.value or shipment.from_branch_id != branch.id:
            return _unexplained_exit(db, rp, branch, asset, at, "passed the dispatch portal without a packed manifest")
        if logistics.record_dispatch_read(db, shipment, asset, at):
            logistics.dispatch(db, None, shipment, via=f"exit portal {rp.code}")
            return ReadOutcome.UPDATED, f"Last item of {shipment.reference} read: shipment dispatched, status In transit"
        return ReadOutcome.CONFIRMED, f"On manifest {shipment.reference}; waiting for the remaining cartons"

    if kind == RP.BRANCH_RECEIPT:
        shipment = logistics.open_shipment_for(db, asset)
        if shipment is not None and shipment.status == ShipmentStatus.IN_TRANSIT.value and shipment.to_branch_id == branch.id:
            logistics.record_receipt_read(db, shipment, asset, at)
            return ReadOutcome.CONFIRMED, f"Matched to manifest {shipment.reference}; awaiting seal check and sign-off"
        return _receipt_variance(db, rp, branch, asset, at)

    if kind == RP.INSTALL:
        if asset.branch_id != branch.id:
            ref = _exception(db, asset, rp, branch, f"RFID:LOC:{asset.id}:{branch.id}",
                             f"{asset.asset_number} read at a rack in {branch.code} but registered at {asset.branch.code}",
                             {"status": asset.status})
            return ReadOutcome.EXCEPTION, f"Not registered at this branch; exception {ref}"
        loc_id = raw.get("location_id") or rp.location_id
        rack_u = raw.get("rack_u")
        loc = db.get(Location, loc_id) if loc_id else None
        if loc is None or loc.branch_id != branch.id:
            return ReadOutcome.CONFIRMED, "Read at rack; no location given"
        changes = []
        if asset.location_id != loc.id:
            changes.append(f"location {asset.location.label if asset.location else '—'} → {loc.label}")
            asset.location_id = loc.id
        if rack_u and rack_u != asset.rack_u:
            changes.append(f"U-position {asset.rack_u or '—'} → {rack_u}")
            asset.rack_u = rack_u
        if not changes:
            return ReadOutcome.CONFIRMED, f"Rack position confirmed: {loc.label} {asset.rack_u or ''}".strip()
        add_history(db, asset, None, "RFID_LOCATION", f"Read at rack ({rp.name}): " + "; ".join(changes))
        auditlog.record(db, None, "rfid.location", "asset", asset.asset_number, read_point=rp.code, changes=changes)
        return ReadOutcome.UPDATED, "; ".join(changes)

    if kind == RP.CABINET:
        security_alert = f"CABINET:{asset.id}"
        from itam.services.monitoring import auto_resolve

        if auto_resolve(db, security_alert, f"Tag read again by {rp.code}", at):
            return ReadOutcome.UPDATED, "Tag seen again in the cabinet; alarm resolved"
        return ReadOutcome.CONFIRMED, "Present in cabinet"

    if kind == RP.EXIT_PORTAL:
        alarm, detail = security.exit_read(db, asset, rp, at)
        return (ReadOutcome.EXCEPTION if alarm else ReadOutcome.CONFIRMED), detail

    if kind == RP.AUDIT_SWEEP:
        return _audit_sweep(db, rp, branch, asset, raw)

    return ReadOutcome.CONFIRMED, "No action for this read point"


def _unexplained_exit(db: Session, rp: ReadPoint, branch: Branch, asset: Asset, at: datetime,
                      what: str) -> tuple[ReadOutcome, str]:
    from itam.services.security import _alarm

    ref = _exception(db, asset, rp, branch, f"RFID:EXIT:{asset.id}", f"Unexplained exit: {asset.asset_number} {what}",
                     {"status": asset.status, "at": at.isoformat()})
    _alarm(db, key=f"EXIT:{asset.id}", category=AlertCategory.UNEXPLAINED_EXIT, severity=Severity.P1,
           title=f"Unexplained exit at {branch.code}: {asset.asset_number} {what}",
           detail=f"{rp.name} at {at:%H:%M:%S} UTC; no packed manifest, transfer or repair ticket. Exception {ref}.",
           branch=branch, asset=asset, at=at, camera_ref=rp.camera_ref)
    asset.suspected_removal_at = at
    return ReadOutcome.EXCEPTION, f"Unexplained exit; exception {ref}"


def _receipt_variance(db: Session, rp: ReadPoint, branch: Branch, asset: Asset, at: datetime) -> tuple[ReadOutcome, str]:
    from itam.services.monitoring import raise_alert

    ref = _exception(db, asset, rp, branch, f"RFID:RECEIPT:{asset.id}:{branch.id}",
                     f"{asset.asset_number} delivered to {branch.code} but not on any manifest in transit there",
                     {"status": asset.status, "registered_branch": asset.branch.code})
    raise_alert(db, dedup_key=f"RECEIPT:{asset.id}:{branch.id}", severity=Severity.P2,
                category=AlertCategory.SHIPMENT_VARIANCE, asset=asset, branch=branch, source=AlertSource.RFID,
                occurred_at=at, title=f"Wrong item delivered at {branch.code}: {asset.asset_number} is not on a manifest",
                detail=f"Exception {ref}. Do not install; the ITAM Office will investigate.")
    return ReadOutcome.EXCEPTION, f"Not on a manifest to this branch; exception {ref}"


def _audit_sweep(db: Session, rp: ReadPoint, branch: Branch, asset: Asset, raw: dict) -> tuple[ReadOutcome, str]:
    from itam.services import audits as audit_svc

    audit = db.execute(select(PhysicalAudit).where(PhysicalAudit.branch_id == branch.id,
                                                   PhysicalAudit.status == AuditStatus.IN_PROGRESS.value)
                       .order_by(PhysicalAudit.id.desc())).scalars().first()
    if audit is None:
        return ReadOutcome.CONFIRMED, f"Sweep read at {branch.code}; no audit in progress"
    operator = db.execute(select(User).where(User.username == raw.get("operator"))).scalar_one_or_none() \
        if raw.get("operator") else None
    actor = operator or audit.auditor
    if actor is None:
        raise ServiceError("Audit sweep read needs the auditor (operator) to be identified")
    item = audit_svc.scan(db, actor, audit, asset.asset_number, location_id=raw.get("location_id"))
    return ReadOutcome.UPDATED, f"Audit {audit.id}: {item.result.lower().replace('_', ' ')}"


def recent_reads(db: Session, asset: Asset, limit: int = 20) -> list[RfidRead]:
    return list(db.execute(select(RfidRead).where(RfidRead.asset_id == asset.id)
                           .order_by(RfidRead.read_at.desc(), RfidRead.id.desc()).limit(limit)).scalars())


def shipment_for_item(db: Session, asset: Asset) -> ShipmentItem | None:
    return db.execute(select(ShipmentItem).join(Shipment).where(ShipmentItem.asset_id == asset.id)
                      .order_by(ShipmentItem.id.desc())).scalars().first()

