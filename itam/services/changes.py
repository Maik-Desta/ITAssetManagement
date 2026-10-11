"""Moving, removing and disposing of equipment with maker-checker approval (slide 20)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import (
    AUTHORISED_CHANGE_STATUSES,
    CHANGE_LABELS,
    CRITICAL_RETIRE_TYPES,
    DATA_BEARING_TYPES,
    OPEN_CHANGE_STATUSES,
    AlertStatus,
    AssetStatus,
    ChangeStatus,
    ChangeType,
    Criticality,
    NotificationChannel,
)
from itam.models import Alert, Asset, Branch, ChangeApproval, ChangeRequest, Location, User, utcnow
from itam.notifications import notify, notify_roles, users_with_role
from itam.numbering import extract_asset_number
from itam.rbac import Role, acts_for_branch, can
from itam.services import PermissionDenied, ServiceError
from itam.services.assets import add_history, set_status

S = AssetStatus
CT = ChangeType

ALLOWED_FROM: dict[ChangeType, set[AssetStatus]] = {
    CT.MOVE_WITHIN_BRANCH: {S.IN_STOCK, S.ACTIVE, S.FAULTY},
    CT.TRANSFER_BRANCH: {S.IN_STOCK, S.ACTIVE, S.FAULTY},
    CT.SEND_REPAIR: {S.IN_STOCK, S.ACTIVE, S.FAULTY},
    CT.RETIRE: {S.IN_STOCK, S.ACTIVE, S.FAULTY, S.UNDER_REPAIR},
    CT.DISPOSE: {S.RETIRED, S.MISSING},
}


def is_critical_device(asset: Asset) -> bool:
    return asset.asset_type in CRITICAL_RETIRE_TYPES or asset.criticality == Criticality.CRITICAL.value


def approval_matrix(change_type: ChangeType, asset: Asset) -> list[Role]:
    """Approver 1 / Approver 2 per action (slide 20)."""
    if change_type == CT.MOVE_WITHIN_BRANCH:
        return [Role.REGIONAL_LEAD]
    if change_type == CT.TRANSFER_BRANCH:
        return [Role.BRANCH_MANAGER, Role.IT_ASSET_MANAGER]  # sending branch manager, then ITAM
    if change_type == CT.SEND_REPAIR:
        return [Role.REGIONAL_LEAD, Role.IT_ASSET_MANAGER]
    if change_type == CT.RETIRE:
        if is_critical_device(asset):
            return [Role.HEAD_INFRA, Role.CISO]
        return [Role.REGIONAL_LEAD, Role.IT_ASSET_MANAGER]
    if change_type == CT.DISPOSE:
        return [Role.CIO, Role.CFO]
    raise ServiceError("Unknown change type")


def evidence_required(change: ChangeRequest) -> list[str]:
    ct = ChangeType(change.change_type)
    if ct == CT.MOVE_WITHIN_BRANCH:
        return ["ticket_ref"]
    if ct == CT.TRANSFER_BRANCH:
        return ["evidence_ref"]  # transfer note
    if ct == CT.SEND_REPAIR:
        return ["evidence_ref"]  # vendor RMA / chain of custody
    if ct == CT.RETIRE:
        return ["ticket_ref", "evidence_ref"] if is_critical_device(change.asset) else ["ticket_ref"]
    if ct == CT.DISPOSE:
        needed = ["disposal_certificate_ref"]
        if change.asset.status != S.MISSING.value and (
            change.asset.asset_type in DATA_BEARING_TYPES or change.asset.holds_customer_data
        ):
            needed.append("wipe_certificate_ref")
        return needed
    return []


EVIDENCE_LABELS = {
    "ticket_ref": "Change ticket reference",
    "evidence_ref": "Evidence reference (transfer note / RMA / data-wipe plan)",
    "wipe_certificate_ref": "Certified data-wipe certificate",
    "disposal_certificate_ref": "Disposal / write-off certificate",
}


def open_change_for(db: Session, asset: Asset) -> ChangeRequest | None:
    return db.execute(select(ChangeRequest).where(
        ChangeRequest.asset_id == asset.id, ChangeRequest.status.in_([s.value for s in OPEN_CHANGE_STATUSES])
    )).scalars().first()


def authorised_change_for(db: Session, asset: Asset) -> ChangeRequest | None:
    """An approved / in-progress change that explains the asset leaving its place."""
    return db.execute(select(ChangeRequest).where(
        ChangeRequest.asset_id == asset.id,
        ChangeRequest.status.in_([s.value for s in AUTHORISED_CHANGE_STATUSES]),
    )).scalars().first()


def _next_reference(db: Session) -> str:
    count = db.execute(select(func.count(ChangeRequest.id))).scalar_one()
    return f"CHG-{count + 1:06d}"


def create_change(db: Session, actor: User, asset: Asset, change_type: ChangeType, reason: str, *,
                  to_branch: Branch | None = None, to_location: Location | None = None,
                  scheduled_for: datetime | None = None, ticket_ref: str | None = None) -> ChangeRequest:
    if not can(actor, "change.create"):
        raise PermissionDenied("You may not raise change requests")
    if not reason or not reason.strip():
        raise ServiceError("A reason is required")
    status = AssetStatus(asset.status)
    if status not in ALLOWED_FROM[change_type]:
        raise ServiceError(f"{CHANGE_LABELS[change_type]} is not possible while the asset is '{status.value}'")
    if open_change_for(db, asset):
        raise ServiceError("This asset already has an open change request", 409)
    if change_type == CT.MOVE_WITHIN_BRANCH:
        if to_location is None or to_location.branch_id != asset.branch_id:
            raise ServiceError("Choose a destination location within the same branch")
        if to_location.id == asset.location_id:
            raise ServiceError("Asset is already at that location")
    if change_type == CT.TRANSFER_BRANCH:
        if to_branch is None or to_branch.id == asset.branch_id:
            raise ServiceError("Choose a different destination branch")
        if to_location is not None and to_location.branch_id != to_branch.id:
            raise ServiceError("Destination location must belong to the destination branch")

    change = ChangeRequest(
        reference=_next_reference(db), change_type=change_type.value, asset_id=asset.id, requester_id=actor.id,
        reason=reason.strip(), status=ChangeStatus.PENDING_APPROVAL.value, from_branch_id=asset.branch_id,
        from_location_id=asset.location_id, to_branch_id=to_branch.id if to_branch else None,
        to_location_id=to_location.id if to_location else None, scheduled_for=scheduled_for,
        ticket_ref=ticket_ref or None, created_at=utcnow(),
    )
    db.add(change)
    db.flush()
    for step, role in enumerate(approval_matrix(change_type, asset), start=1):
        db.add(ChangeApproval(change_id=change.id, step=step, required_role=role.value))
    db.flush()
    db.refresh(change)
    add_history(db, asset, actor, "CHANGE_REQUESTED", f"{change.reference}: {CHANGE_LABELS[change_type]}")
    auditlog.record(db, actor, "change.create", "change", change.reference, asset=asset.asset_number,
                    type=change_type.value, reason=reason, approvers=[a.required_role for a in change.approvals])
    _notify_next_approver(db, change)
    return change


def pending_step(change: ChangeRequest) -> ChangeApproval | None:
    for approval in change.approvals:
        if approval.decision is None:
            return approval
    return None


def can_approve(user: User, change: ChangeRequest) -> tuple[bool, str]:
    if change.status != ChangeStatus.PENDING_APPROVAL.value:
        return False, "Change is not awaiting approval"
    step = pending_step(change)
    if step is None:
        return False, "No approval pending"
    if user.id == change.requester_id:
        return False, "Maker-checker: the requester cannot approve their own change"
    if any(a.approver_id == user.id for a in change.approvals if a.decision):
        return False, "Maker-checker: the same person cannot give both approvals"
    role = Role(step.required_role)
    if not acts_for_branch(user, role, change.from_branch):
        return False, f"Approval step {step.step} requires {role.value} for branch {change.from_branch.code}"
    return True, ""


def _notify_next_approver(db: Session, change: ChangeRequest) -> None:
    step = pending_step(change)
    if step is None:
        return
    recipients = [u for u in users_with_role(db, Role(step.required_role), change.from_branch)
                  if u.id != change.requester_id]
    notify(db, recipients, f"Approval needed: {change.reference} {CHANGE_LABELS[ChangeType(change.change_type)]}",
           f"{change.asset.asset_number} — {change.reason}\nRequested by {change.requester.full_name}.",
           [NotificationChannel.EMAIL])


def decide(db: Session, actor: User, change: ChangeRequest, approve: bool, comment: str | None = None) -> ChangeRequest:
    ok, why = can_approve(actor, change)
    if not ok:
        raise PermissionDenied(why)
    if not approve and not (comment and comment.strip()):
        raise ServiceError("A reason is required to reject")
    step = pending_step(change)
    step.approver_id = actor.id
    step.decision = "APPROVED" if approve else "REJECTED"
    step.comment = comment
    step.decided_at = utcnow()
    auditlog.record(db, actor, "change.approve" if approve else "change.reject", "change", change.reference,
                    step=step.step, role=step.required_role, comment=comment)
    if not approve:
        change.status = ChangeStatus.REJECTED.value
        add_history(db, change.asset, actor, "CHANGE_REJECTED", f"{change.reference} rejected: {comment}")
        notify(db, [change.requester], f"{change.reference} rejected", comment or "", [NotificationChannel.EMAIL])
        return change
    if pending_step(change) is None:
        change.status = ChangeStatus.APPROVED.value
        add_history(db, change.asset, actor, "CHANGE_APPROVED", f"{change.reference} fully approved")
        when = change.scheduled_for.strftime("%Y-%m-%d %H:%M") if change.scheduled_for else "unscheduled"
        # "Change ticket scheduled; NOC informed"
        notify_roles(db, [Role.NOC], f"Approved change {change.reference} ({when})",
                     f"{CHANGE_LABELS[ChangeType(change.change_type)]}: {change.asset.asset_number} at "
                     f"{change.from_branch.code}. Expect the device to leave discovery.",
                     [NotificationChannel.EMAIL, NotificationChannel.CHAT])
        notify(db, [change.requester], f"{change.reference} approved", "Your change may now be executed.",
               [NotificationChannel.EMAIL])
    else:
        _notify_next_approver(db, change)
    return change


def _require_evidence(change: ChangeRequest, evidence: dict[str, str | None]) -> None:
    for field in ("ticket_ref", "evidence_ref", "wipe_certificate_ref", "disposal_certificate_ref"):
        value = (evidence.get(field) or "").strip()
        if value:
            setattr(change, field, value)
    missing = [EVIDENCE_LABELS[f] for f in evidence_required(change) if not getattr(change, f)]
    if missing:
        raise ServiceError("Evidence required: " + "; ".join(missing))


def execute(db: Session, actor: User, change: ChangeRequest, scanned_tag: str, **evidence: str | None) -> ChangeRequest:
    """Engineer performs the change; the tag must be scanned to prove the right device was handled."""
    if not can(actor, "change.execute"):
        raise PermissionDenied("You may not execute changes")
    if change.status != ChangeStatus.APPROVED.value:
        raise ServiceError("Only fully approved changes can be executed")
    if actor.id == change.requester_id and ChangeType(change.change_type) == CT.DISPOSE:
        raise PermissionDenied("The requester cannot execute their own disposal")
    asset = change.asset
    if extract_asset_number(scanned_tag) != asset.asset_number:
        raise ServiceError("Scanned tag does not match the asset on this change")
    _require_evidence(change, evidence)
    ct = ChangeType(change.change_type)
    now = utcnow()
    change.executed_by_id = actor.id
    change.executed_at = now

    if ct == CT.MOVE_WITHIN_BRANCH:
        asset.location_id = change.to_location_id
        add_history(db, asset, actor, "MOVED", f"{change.reference}: moved to {change.to_location.label}")
        _complete(db, actor, change)
    elif ct == CT.TRANSFER_BRANCH:
        set_status(db, asset, S.IN_TRANSIT, actor, "DISPATCHED",
                   f"{change.reference}: in transit to {change.to_branch.code} {change.to_branch.name}")
        asset.location_id = None
        change.status = ChangeStatus.IN_PROGRESS.value
    elif ct == CT.SEND_REPAIR:
        set_status(db, asset, S.UNDER_REPAIR, actor, "SENT_FOR_REPAIR", f"{change.reference}: RMA {change.evidence_ref}")
        change.status = ChangeStatus.IN_PROGRESS.value
    elif ct == CT.RETIRE:
        set_status(db, asset, S.RETIRED, actor, "RETIRED", f"{change.reference}: removed from service")
        _complete(db, actor, change)
    elif ct == CT.DISPOSE:
        set_status(db, asset, S.DISPOSED, actor, "DISPOSED",
                   f"{change.reference}: wipe cert {change.wipe_certificate_ref or 'n/a'}, "
                   f"disposal cert {change.disposal_certificate_ref}")
        asset.custodian_id = None
        _complete(db, actor, change)
        notify_roles(db, [Role.FINANCE], f"Update fixed-asset register: {asset.asset_number} disposed",
                     f"{change.reference}: please write off finance ref {asset.finance_asset_ref or '(none)'}.",
                     [NotificationChannel.EMAIL])
    _close_open_alerts(db, asset, change)
    auditlog.record(db, actor, "change.execute", "change", change.reference, asset=asset.asset_number,
                    status=change.status, evidence={k: getattr(change, k) for k in EVIDENCE_LABELS})
    return change


def _complete(db: Session, actor: User, change: ChangeRequest) -> None:
    change.status = ChangeStatus.COMPLETED.value
    change.completed_by_id = actor.id
    change.completed_at = utcnow()


def _close_open_alerts(db: Session, asset: Asset, change: ChangeRequest) -> None:
    """Removal is authorised — close not-discovered / down alerts for the asset."""
    if asset.status not in (S.IN_TRANSIT.value, S.UNDER_REPAIR.value, S.RETIRED.value, S.DISPOSED.value):
        return
    for alert in db.execute(select(Alert).where(Alert.asset_id == asset.id,
                                                Alert.status != AlertStatus.RESOLVED.value)).scalars():
        alert.status = AlertStatus.RESOLVED.value
        alert.resolved_at = utcnow()
        alert.resolution = f"Authorised by {change.reference}"
        alert.change_id = change.id


def confirm_delivery(db: Session, actor: User, change: ChangeRequest, to_location: Location | None = None) -> ChangeRequest:
    """Destination branch signs for a transferred asset (slide 19 step 5 / slide 20 evidence)."""
    if change.change_type != CT.TRANSFER_BRANCH.value or change.status != ChangeStatus.IN_PROGRESS.value:
        raise ServiceError("Only in-transit transfers can be received")
    dest = change.to_branch
    if not (acts_for_branch(actor, Role.BRANCH_MANAGER, dest) or acts_for_branch(actor, Role.REGIONAL_IT, dest)
            or acts_for_branch(actor, Role.REGIONAL_LEAD, dest) or actor.has_role(Role.IT_ASSET_MANAGER)):
        raise PermissionDenied("Only the destination branch can sign for delivery")
    location = to_location or change.to_location
    if location is not None and location.branch_id != dest.id:
        raise ServiceError("Location must be at the destination branch")
    asset = change.asset
    asset.branch_id = dest.id
    asset.branch = dest
    asset.location_id = location.id if location else None
    asset.install_date = None
    asset.go_live_verified_at = None
    asset.custodian_id = None
    asset.custody_accepted_at = None
    asset.custody_accepted_by_id = None
    set_status(db, asset, S.IN_STOCK, actor, "DELIVERED", f"{change.reference}: delivery signed at {dest.code} by {actor.full_name}")
    _complete(db, actor, change)
    auditlog.record(db, actor, "change.deliver", "change", change.reference, asset=asset.asset_number, branch=dest.code)
    return change


def return_from_repair(db: Session, actor: User, change: ChangeRequest, note: str | None = None) -> ChangeRequest:
    if change.change_type != CT.SEND_REPAIR.value or change.status != ChangeStatus.IN_PROGRESS.value:
        raise ServiceError("Only assets out for repair can be returned")
    if not can(actor, "change.execute"):
        raise PermissionDenied("Not permitted")
    asset = change.asset
    asset.install_date = None
    asset.go_live_verified_at = None
    set_status(db, asset, S.IN_STOCK, actor, "RETURNED_FROM_REPAIR", note or f"{change.reference}: returned from repair")
    _complete(db, actor, change)
    auditlog.record(db, actor, "change.return_repair", "change", change.reference, asset=asset.asset_number, note=note)
    return change


def cancel(db: Session, actor: User, change: ChangeRequest, reason: str) -> ChangeRequest:
    if change.status not in (ChangeStatus.PENDING_APPROVAL.value, ChangeStatus.APPROVED.value):
        raise ServiceError("Only changes that have not started can be cancelled")
    if actor.id != change.requester_id and not can(actor, "change.close"):
        raise PermissionDenied("Only the requester or ITAM Office can cancel")
    change.status = ChangeStatus.CANCELLED.value
    auditlog.record(db, actor, "change.cancel", "change", change.reference, reason=reason)
    add_history(db, change.asset, actor, "CHANGE_CANCELLED", f"{change.reference}: {reason}")
    return change


def finance_confirm(db: Session, actor: User, change: ChangeRequest) -> ChangeRequest:
    """Finance updates the fixed-asset register after disposal."""
    if not can(actor, "change.finance_confirm"):
        raise PermissionDenied("Only Finance can confirm the fixed-asset register update")
    if change.change_type != CT.DISPOSE.value or change.status != ChangeStatus.COMPLETED.value:
        raise ServiceError("Only completed disposals need Finance confirmation")
    if change.finance_confirmed_at:
        raise ServiceError("Already confirmed")
    change.finance_confirmed_by_id = actor.id
    change.finance_confirmed_at = utcnow()
    auditlog.record(db, actor, "change.finance_confirm", "change", change.reference, asset=change.asset.asset_number)
    return change
