"""Central staging to branch: pick & pack, dispatch, delivery and branch receipt (slides 27-28, 48).

* A shipment carries a manifest (asset numbers + RFID EPCs) and a tamper-seal number.
* New equipment ordered for the branch, and transfers with an approved change, can be shipped.
  Every item must have a verified RFID tag; network kit must have passed configuration and burn-in.
* The exit-portal read (or the ITAM Office) dispatches it: status 'In transit', ETA to the branch.
* The branch reads the cartons with a handheld; anything that does not match the manifest, or a broken
  seal, stops the flow and opens an exception plus a Security alert. Nothing is installed without a matched record.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import (
    AlertCategory,
    AlertSource,
    AssetStatus,
    ChangeStatus,
    ChangeType,
    ExceptionSource,
    ExceptionType,
    NotificationChannel,
    Severity,
    ShipmentItemResult,
    ShipmentStatus,
)
from itam.models import Asset, Branch, ChangeRequest, EquipmentRequest, Shipment, ShipmentItem, User, utcnow
from itam.notifications import notify, notify_roles, users_with_role
from itam.rbac import Role, acts_for_branch, can
from itam.services import PermissionDenied, ServiceError
from itam.services.assets import add_history, find_by_number, is_staged_ready, set_status

S = AssetStatus
OPEN_SHIPMENT_STATUSES = (ShipmentStatus.PACKED.value, ShipmentStatus.IN_TRANSIT.value)


def _next_reference(db: Session) -> str:
    count = db.execute(select(func.count(Shipment.id))).scalar_one()
    return f"SHP-{count + 1:06d}"


def open_shipment_for(db: Session, asset: Asset) -> Shipment | None:
    item = db.execute(select(ShipmentItem).join(Shipment).where(
        ShipmentItem.asset_id == asset.id, Shipment.status.in_(OPEN_SHIPMENT_STATUSES))).scalars().first()
    return item.shipment if item else None


def _approved_transfer(db: Session, asset: Asset, to_branch: Branch) -> ChangeRequest | None:
    return db.execute(select(ChangeRequest).where(
        ChangeRequest.asset_id == asset.id, ChangeRequest.change_type == ChangeType.TRANSFER_BRANCH.value,
        ChangeRequest.status == ChangeStatus.APPROVED.value, ChangeRequest.to_branch_id == to_branch.id,
    )).scalars().first()


def shippable_reason(db: Session, asset: Asset, to_branch: Branch) -> tuple[ChangeRequest | None, str | None]:
    """(authorising transfer change or None, reason it cannot be shipped or None)."""
    if asset.status != S.IN_STOCK.value:
        return None, "not in stock"
    if open_shipment_for(db, asset):
        return None, "already on an open shipment"
    if not asset.rfid_verified_at:
        return None, "RFID tag not encoded and verified"
    change = _approved_transfer(db, asset, to_branch)
    if change is None:
        req = db.get(EquipmentRequest, asset.request_id) if asset.request_id else None
        if req is None or req.branch_id != to_branch.id or asset.install_date:
            return None, f"no approved transfer to {to_branch.code} and not new equipment ordered for it"
        if not is_staged_ready(asset):
            return None, "configuration and burn-in not recorded (staged – ready)"
    return change, None


def create_shipment(db: Session, actor: User, *, to_branch: Branch, assets: list[Asset], seal_number: str,
                    carrier: str | None = None, eta: datetime | None = None) -> Shipment:
    """Pick & pack against the branch install order; manifest with tag list and seal number (slide 27, step 5)."""
    if not can(actor, "shipment.manage"):
        raise PermissionDenied("Only the ITAM Office (staging) can pack shipments")
    if not assets:
        raise ServiceError("Choose at least one asset to ship")
    if not (seal_number or "").strip():
        raise ServiceError("Tamper-seal number is required")
    from_ids = {a.branch_id for a in assets}
    if len(from_ids) != 1:
        raise ServiceError("All items of a shipment must leave from the same site")
    from_branch = assets[0].branch
    if from_branch.id == to_branch.id:
        raise ServiceError("Destination must be a different branch")
    problems, changes = [], {}
    for a in assets:
        change, why = shippable_reason(db, a, to_branch)
        if why:
            problems.append(f"{a.asset_number}: {why}")
        changes[a.id] = change
    if problems:
        raise ServiceError("Cannot ship: " + "; ".join(problems))
    now = utcnow()
    shipment = Shipment(reference=_next_reference(db), from_branch_id=from_branch.id, to_branch_id=to_branch.id,
                        status=ShipmentStatus.PACKED.value, seal_number=seal_number.strip(), carrier=carrier or None,
                        eta=eta, created_by_id=actor.id, created_at=now)
    db.add(shipment)
    db.flush()
    for a in assets:
        db.add(ShipmentItem(shipment_id=shipment.id, asset_id=a.id, change_id=changes[a.id].id if changes[a.id] else None,
                            result=ShipmentItemResult.PENDING.value))
        add_history(db, a, actor, "PACKED", f"{shipment.reference}: packed for {to_branch.code}, seal {shipment.seal_number}")
    db.flush()
    db.refresh(shipment)
    auditlog.record(db, actor, "shipment.create", "shipment", shipment.reference, to=to_branch.code,
                    seal=shipment.seal_number, manifest=[{"asset": a.asset_number, "epc": a.rfid_epc} for a in assets])
    return shipment


def record_dispatch_read(db: Session, shipment: Shipment, asset: Asset, at: datetime) -> bool:
    """Exit-portal read of a manifest item. Returns True once every item has been read (the flow dispatches)."""
    for item in shipment.items:
        if item.asset_id == asset.id and item.dispatch_read_at is None:
            item.dispatch_read_at = at
    return all(i.dispatch_read_at for i in shipment.items)


def dispatch(db: Session, actor: User | None, shipment: Shipment, via: str = "ITAM Office") -> Shipment:
    """Cartons leave through the exit portal; handover to courier (slide 27, step 6). Status 'In transit'."""
    if actor is not None and not can(actor, "shipment.manage"):
        raise PermissionDenied("Only the ITAM Office can dispatch shipments")
    if shipment.status != ShipmentStatus.PACKED.value:
        raise ServiceError("Only packed shipments can be dispatched")
    now = utcnow()
    shipment.status = ShipmentStatus.IN_TRANSIT.value
    shipment.dispatched_at = now
    shipment.dispatched_by_id = actor.id if actor else None
    dest = shipment.to_branch
    for item in shipment.items:
        asset = item.asset
        set_status(db, asset, S.IN_TRANSIT, actor, "DISPATCHED",
                   f"{shipment.reference}: dispatched to {dest.code} {dest.name} ({via}); seal {shipment.seal_number}")
        asset.location_id = None
        if item.change is not None:
            change = item.change
            change.status = ChangeStatus.IN_PROGRESS.value
            change.executed_at = now
            change.executed_by_id = actor.id if actor else shipment.created_by_id
            change.evidence_ref = change.evidence_ref or f"Manifest {shipment.reference}"
    auditlog.record(db, actor, "shipment.dispatch", "shipment", shipment.reference, via=via,
                    items=[i.asset.asset_number for i in shipment.items])
    eta = f"ETA {shipment.eta:%Y-%m-%d %H:%M}" if shipment.eta else "ETA to be confirmed"
    manifest = "\n".join(f"{i.asset.asset_number} ({i.asset.asset_type})" for i in shipment.items)
    recipients = ([dest.manager] if dest.manager else []) + users_with_role(db, Role.REGIONAL_IT, dest)
    notify(db, recipients, f"{shipment.reference} on its way to {dest.code}: {len(shipment.items)} item(s), {eta}",
           f"Carrier: {shipment.carrier or '—'}. Seal {shipment.seal_number}. Read the cartons with the handheld on "
           f"delivery and check the seal.\n{manifest}", [NotificationChannel.EMAIL, NotificationChannel.SMS])
    return shipment


def record_receipt_read(db: Session, shipment: Shipment, asset: Asset, at: datetime) -> bool:
    """Handheld read at branch delivery. Returns False if the asset is not on this manifest."""
    for item in shipment.items:
        if item.asset_id == asset.id:
            item.received_read_at = item.received_read_at or at
            return True
    return False


def in_transit_to(db: Session, branch: Branch) -> list[Shipment]:
    return list(db.execute(select(Shipment).where(Shipment.to_branch_id == branch.id,
                                                  Shipment.status == ShipmentStatus.IN_TRANSIT.value)).scalars())


def can_receive(user: User, shipment: Shipment) -> bool:
    dest = shipment.to_branch
    return (acts_for_branch(user, Role.BRANCH_MANAGER, dest) or acts_for_branch(user, Role.REGIONAL_IT, dest)
            or acts_for_branch(user, Role.REGIONAL_LEAD, dest) or user.has_role(Role.IT_ASSET_MANAGER))


def receive_shipment(db: Session, actor: User, shipment: Shipment, *, scanned: list[str], seal_intact: bool,
                     seal_number: str | None = None, note: str | None = None) -> Shipment:
    """Branch receipt (slide 28, steps 8-9): seal checked, cartons read, matched to the manifest."""
    from itam.services.discovery import raise_exception
    from itam.services.monitoring import auto_resolve, raise_alert

    if shipment.status != ShipmentStatus.IN_TRANSIT.value:
        raise ServiceError("Only shipments in transit can be received")
    if not can_receive(actor, shipment):
        raise PermissionDenied("Only the destination branch can receive this shipment")
    dest, now = shipment.to_branch, utcnow()
    on_manifest = {i.asset_id: i for i in shipment.items}
    unexpected: list[str] = []
    for value in [v.strip() for v in scanned if v and v.strip()]:
        asset = find_by_number(db, value)
        if asset is not None and asset.id in on_manifest:
            on_manifest[asset.id].received_read_at = on_manifest[asset.id].received_read_at or now
        else:
            unexpected.append(asset.asset_number if asset else value)
    seal_ok = bool(seal_intact) and (not seal_number or seal_number.strip() == shipment.seal_number)
    shipment.seal_intact = seal_ok
    missing: list[str] = []
    for item in shipment.items:
        asset = item.asset
        if item.received_read_at is None:
            item.result = ShipmentItemResult.MISSING.value
            missing.append(asset.asset_number)
            continue
        item.result = ShipmentItemResult.MATCHED.value
        _land(db, actor, asset, dest, shipment)
        if item.change is not None:
            item.change.status = ChangeStatus.COMPLETED.value
            item.change.completed_by_id, item.change.completed_at = actor.id, now
    shipment.received_at, shipment.received_by_id = now, actor.id
    variance = bool(missing or unexpected or not seal_ok)
    shipment.status = ShipmentStatus.VARIANCE.value if variance else ShipmentStatus.DELIVERED.value
    parts = []
    if missing:
        parts.append(f"missing: {', '.join(missing)}")
    if unexpected:
        parts.append(f"not on manifest: {', '.join(unexpected)}")
    if not seal_ok:
        parts.append(f"seal {'broken' if not seal_intact else 'number ' + (seal_number or '') + ' differs'}"
                     f" (expected {shipment.seal_number})")
    shipment.variance_note = "; ".join(parts) + (f". {note}" if note else "") if variance else note
    auto_resolve(db, f"OVERDUE:{shipment.id}", f"Received at {dest.code}")
    if variance:
        exc, _ = raise_exception(
            db, exception_type=ExceptionType.SHIPMENT_VARIANCE, source=ExceptionSource.LOGISTICS,
            dedup_key=f"SHIPMENT:{shipment.id}", branch=dest,
            summary=f"{shipment.reference} received at {dest.code} with variance: {'; '.join(parts)}"[:255],
            observed={"shipment": shipment.reference, "missing": missing, "unexpected": unexpected,
                      "seal_intact": bool(seal_intact), "seal_number": seal_number, "expected_seal": shipment.seal_number},
        )
        raise_alert(db, dedup_key=f"SHIPVAR:{shipment.id}", severity=Severity.P2, category=AlertCategory.SHIPMENT_VARIANCE,
                    branch=dest, source=AlertSource.RFID,
                    title=f"Delivery variance: {shipment.reference} at {dest.code} ({'; '.join(parts)})"[:255],
                    detail=f"Exception {exc.ticket_ref}. Missing items stay 'In transit' until found; nothing is "
                           f"installed without a matched record.")
    auditlog.record(db, actor, "shipment.receive", "shipment", shipment.reference, status=shipment.status,
                    missing=missing, unexpected=unexpected, seal_intact=seal_ok)
    notify_roles(db, [Role.IT_ASSET_MANAGER], f"{shipment.reference} received at {dest.code}: {shipment.status.lower()}",
                 shipment.variance_note or "All items matched to the manifest; seal intact.", [NotificationChannel.EMAIL])
    return shipment


def _land(db: Session, actor: User, asset: Asset, dest: Branch, shipment: Shipment) -> None:
    asset.branch_id, asset.branch = dest.id, dest
    asset.location_id = None
    asset.install_date = None
    asset.go_live_verified_at = None
    asset.custodian_id = asset.custody_accepted_at = asset.custody_accepted_by_id = None
    set_status(db, asset, S.IN_STOCK, actor, "DELIVERED",
               f"{shipment.reference}: matched to manifest at {dest.code} by {actor.full_name}")


def accept_custody(db: Session, actor: User, shipment: Shipment) -> int:
    """Branch manager signs for the delivered items in one step (digital signature; slide 28, step 9)."""
    from itam.services.assets import accept_custody as accept_one

    if not acts_for_branch(actor, Role.BRANCH_MANAGER, shipment.to_branch):
        raise PermissionDenied("Only the receiving branch manager can accept custody")
    count = 0
    for item in shipment.items:
        if item.result == ShipmentItemResult.MATCHED.value and item.asset.custody_accepted_by_id != actor.id:
            accept_one(db, actor, item.asset)
            count += 1
    auditlog.record(db, actor, "shipment.custody", "shipment", shipment.reference, items=count)
    return count


def cancel(db: Session, actor: User, shipment: Shipment, reason: str) -> Shipment:
    if not can(actor, "shipment.manage"):
        raise PermissionDenied("Only the ITAM Office can cancel shipments")
    if shipment.status != ShipmentStatus.PACKED.value:
        raise ServiceError("Only shipments that have not left can be cancelled")
    shipment.status = ShipmentStatus.CANCELLED.value
    shipment.variance_note = reason
    auditlog.record(db, actor, "shipment.cancel", "shipment", shipment.reference, reason=reason)
    return shipment


def overdue_shipments(db: Session, now: datetime | None = None) -> int:
    """In transit past the ETA: alert the ITAM Office and Security (slide 27, step 7)."""
    from itam.services.monitoring import open_alert, raise_alert

    now = now or utcnow()
    raised = 0
    for s in db.execute(select(Shipment).where(Shipment.status == ShipmentStatus.IN_TRANSIT.value,
                                               Shipment.eta.is_not(None), Shipment.eta < now)).scalars():
        key = f"OVERDUE:{s.id}"
        if open_alert(db, key):
            continue
        hours = int((now - s.eta).total_seconds() // 3600)
        raise_alert(db, dedup_key=key, severity=Severity.P3, category=AlertCategory.SHIPMENT_OVERDUE, branch=s.to_branch,
                    source=AlertSource.SCHEDULER, occurred_at=s.eta,
                    title=f"Delivery overdue: {s.reference} to {s.to_branch.code} ({hours} h past ETA)",
                    detail=f"{len(s.items)} item(s), carrier {s.carrier or '—'}, seal {s.seal_number}.")
        raised += 1
    return raised
