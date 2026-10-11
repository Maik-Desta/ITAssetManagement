"""New equipment: request & approve → procure → receive & tag → register (slide 19, steps 1-4)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import AssetType, NotificationChannel, RequestStatus
from itam.models import AssetModel, Branch, Contract, EquipmentRequest, User, utcnow
from itam.notifications import notify, notify_roles
from itam.rbac import Role, can
from itam.services import PermissionDenied, ServiceError
from itam.services.assets import register_asset


def _next_reference(db: Session) -> str:
    count = db.execute(select(func.count(EquipmentRequest.id))).scalar_one()
    return f"REQ-{count + 1:06d}"


def central_store(db: Session) -> Branch:
    store = db.execute(select(Branch).where(Branch.is_head_office.is_(True)).order_by(Branch.id)).scalars().first()
    if store is None:
        raise ServiceError("No head-office central store is configured")
    return store


def create_request(db: Session, actor: User, *, branch: Branch, asset_type: str, quantity: int,
                   justification: str, model_id: int | None = None,
                   estimated_cost: float | None = None) -> EquipmentRequest:
    if not can(actor, "request.create"):
        raise PermissionDenied("You may not raise equipment requests")
    if asset_type not in AssetType._value2member_map_:
        raise ServiceError("Unknown asset type")
    if quantity < 1 or quantity > 500:
        raise ServiceError("Quantity must be between 1 and 500")
    if not justification or not justification.strip():
        raise ServiceError("Justification is required")
    if model_id:
        model = db.get(AssetModel, model_id)
        if model is None or model.asset_type != asset_type:
            raise ServiceError("Model does not match the asset type")
        if not model.is_standard:
            raise ServiceError("Only approved standard models can be requested")
    req = EquipmentRequest(reference=_next_reference(db), requester_id=actor.id, branch_id=branch.id,
                           asset_type=asset_type, model_id=model_id, quantity=quantity,
                           justification=justification.strip(), estimated_cost=estimated_cost,
                           status=RequestStatus.PENDING_APPROVAL.value, created_at=utcnow())
    db.add(req)
    db.flush()
    auditlog.record(db, actor, "request.create", "request", req.reference, branch=branch.code,
                    type=asset_type, quantity=quantity)
    notify_roles(db, [Role.IT_ASSET_MANAGER, Role.FINANCE], f"Equipment request {req.reference} awaiting approval",
                 f"{quantity} × {asset_type} for {branch.code} {branch.name}: {justification}", [NotificationChannel.EMAIL])
    return req


def approve(db: Session, actor: User, req: EquipmentRequest, kind: str) -> EquipmentRequest:
    """kind = 'it' (IT Manager) or 'budget' (Finance / budget owner). Both are required."""
    if req.status != RequestStatus.PENDING_APPROVAL.value:
        raise ServiceError("Request is not awaiting approval")
    if actor.id == req.requester_id:
        raise PermissionDenied("Maker-checker: the requester cannot approve their own request")
    if kind == "it":
        if not can(actor, "request.approve_it"):
            raise PermissionDenied("IT approval requires the IT Manager role")
        if req.it_approved_at:
            raise ServiceError("IT approval already given")
        if req.budget_approver_id == actor.id:
            raise PermissionDenied("The same person cannot give both approvals")
        req.it_approver_id, req.it_approved_at = actor.id, utcnow()
    elif kind == "budget":
        if not can(actor, "request.approve_budget"):
            raise PermissionDenied("Budget approval requires Finance")
        if req.budget_approved_at:
            raise ServiceError("Budget approval already given")
        if req.it_approver_id == actor.id:
            raise PermissionDenied("The same person cannot give both approvals")
        req.budget_approver_id, req.budget_approved_at = actor.id, utcnow()
    else:
        raise ServiceError("Unknown approval type")
    auditlog.record(db, actor, f"request.approve_{kind}", "request", req.reference)
    if req.it_approved_at and req.budget_approved_at:
        req.status = RequestStatus.APPROVED.value
        notify_roles(db, [Role.PROCUREMENT], f"Raise PO for {req.reference}",
                     f"{req.quantity} × {req.asset_type} for {req.branch.code}", [NotificationChannel.EMAIL])
        notify(db, [req.requester], f"{req.reference} approved", "Procurement will raise the PO.", [NotificationChannel.EMAIL])
    return req


def reject(db: Session, actor: User, req: EquipmentRequest, reason: str) -> EquipmentRequest:
    if req.status != RequestStatus.PENDING_APPROVAL.value:
        raise ServiceError("Request is not awaiting approval")
    if not (can(actor, "request.approve_it") or can(actor, "request.approve_budget")):
        raise PermissionDenied("Not permitted")
    if not reason or not reason.strip():
        raise ServiceError("A reason is required")
    req.status = RequestStatus.REJECTED.value
    req.rejected_by_id = actor.id
    req.rejection_reason = reason.strip()
    auditlog.record(db, actor, "request.reject", "request", req.reference, reason=reason)
    notify(db, [req.requester], f"{req.reference} rejected", reason, [NotificationChannel.EMAIL])
    return req


def record_po(db: Session, actor: User, req: EquipmentRequest, po_number: str, supplier: str,
              contract_id: int | None = None) -> EquipmentRequest:
    if not can(actor, "request.procure"):
        raise PermissionDenied("Only Procurement can raise purchase orders")
    if req.status != RequestStatus.APPROVED.value:
        raise ServiceError("PO can only be raised for approved requests")
    if not po_number.strip() or not supplier.strip():
        raise ServiceError("PO number and supplier are required")
    if contract_id and db.get(Contract, contract_id) is None:
        raise ServiceError("Unknown contract")
    req.po_number, req.supplier, req.contract_id = po_number.strip(), supplier.strip(), contract_id
    req.status = RequestStatus.ORDERED.value
    auditlog.record(db, actor, "request.po", "request", req.reference, po=po_number, supplier=supplier)
    notify_roles(db, [Role.IT_ASSET_MANAGER], f"PO {po_number} raised for {req.reference}",
                 "Goods to be received and tagged at the central store.", [NotificationChannel.EMAIL])
    return req


def receive(db: Session, actor: User, req: EquipmentRequest, serials: list[str],
            unit_cost: float | None = None) -> list:
    """Goods checked against the PO, asset numbers issued, QR tags applied, records created 'In stock'."""
    if not can(actor, "request.receive"):
        raise PermissionDenied("Only the ITAM Office can receive equipment")
    if req.status != RequestStatus.ORDERED.value:
        raise ServiceError("Only ordered requests can be received")
    serials = [s.strip() for s in serials if s and s.strip()]
    if not serials:
        raise ServiceError("Enter at least one serial number")
    if len(set(serials)) != len(serials):
        raise ServiceError("Duplicate serial numbers in this delivery")
    remaining = req.quantity - req.received_quantity
    if len(serials) > remaining:
        raise ServiceError(f"Only {remaining} item(s) outstanding on this PO")
    store = central_store(db)
    created = []
    for serial in serials:
        created.append(register_asset(
            db, actor, branch=store, number_branch=req.branch, asset_type=req.asset_type, serial_number=serial,
            model_id=req.model_id, contract_id=req.contract_id, request_id=req.id,
            purchase_cost=unit_cost if unit_cost is not None else (
                float(req.estimated_cost) / req.quantity if req.estimated_cost else None),
        ))
    req.received_quantity += len(serials)
    if req.received_quantity >= req.quantity:
        req.status = RequestStatus.RECEIVED.value
    auditlog.record(db, actor, "request.receive", "request", req.reference,
                    assets=[a.asset_number for a in created])
    return created
