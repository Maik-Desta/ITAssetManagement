"""New equipment: request & approve → procure → receive & tag → register (slide 19, steps 1-4)."""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import AssetType, ExceptionSource, ExceptionType, NotificationChannel, RequestStatus
from itam.models import AssetModel, Branch, Contract, EquipmentRequest, ShippingNotice, User, utcnow
from itam.notifications import notify, notify_roles
from itam.rbac import Role, can
from itam.services import PermissionDenied, ServiceError
from itam.services.assets import register_asset
from itam.services.catalogue import exceeds_blueprint

# The Design Authority signs off anything outside the standard branch blueprint (slide 38).
DESIGN_AUTHORITY_ROLES = (Role.HEAD_INFRA, Role.CIO)


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
    # Requests are raised against the approved catalogue only (slide 48, step 1).
    if not model_id:
        raise ServiceError("Choose a model from the approved catalogue")
    model = db.get(AssetModel, model_id)
    if model is None or model.asset_type != asset_type:
        raise ServiceError("Model does not match the asset type")
    if not model.is_standard:
        raise ServiceError("Only models in the approved catalogue can be requested")
    outside = exceeds_blueprint(db, branch, asset_type, quantity)
    req = EquipmentRequest(reference=_next_reference(db), requester_id=actor.id, branch_id=branch.id,
                           asset_type=asset_type, model_id=model_id, quantity=quantity,
                           justification=justification.strip(), estimated_cost=estimated_cost,
                           status=RequestStatus.PENDING_APPROVAL.value, outside_blueprint=outside, created_at=utcnow())
    db.add(req)
    db.flush()
    auditlog.record(db, actor, "request.create", "request", req.reference, branch=branch.code,
                    type=asset_type, quantity=quantity, outside_blueprint=outside)
    it_roles = list(DESIGN_AUTHORITY_ROLES) if outside else [Role.IT_ASSET_MANAGER]
    note = "\nOutside the standard branch blueprint: IT approval by the Design Authority." if outside else ""
    notify_roles(db, it_roles + [Role.FINANCE], f"Equipment request {req.reference} awaiting approval",
                 f"{quantity} × {asset_type} for {branch.code} {branch.name}: {justification}{note}",
                 [NotificationChannel.EMAIL])
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
        if req.outside_blueprint and not actor.has_role(*DESIGN_AUTHORITY_ROLES):
            raise PermissionDenied("Outside the standard branch blueprint: IT approval must come from the "
                                   "Design Authority (Head of Infrastructure or CIO)")
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


def shipping_notice(db: Session, req: EquipmentRequest) -> ShippingNotice | None:
    return db.execute(select(ShippingNotice).where(ShippingNotice.request_id == req.id)
                      .order_by(ShippingNotice.id.desc())).scalars().first()


def record_shipping_notice(db: Session, actor: User, req: EquipmentRequest, asn_ref: str, serials: list[str],
                           eta: date | None = None) -> ShippingNotice:
    """Vendor confirms and sends the shipping notice with serials (slide 48, step 2).

    The serials become the expected records ('on order'); goods-in is matched against them.
    """
    if not (can(actor, "request.procure") or can(actor, "request.receive")):
        raise PermissionDenied("Only Procurement or the ITAM Office can record a shipping notice")
    if req.status != RequestStatus.ORDERED.value:
        raise ServiceError("A shipping notice can only be recorded for an ordered request")
    serials = [s.strip() for s in serials if s and s.strip()]
    if not (asn_ref or "").strip() or not serials:
        raise ServiceError("Shipping notice reference and serial numbers are required")
    if len({s.lower() for s in serials}) != len(serials):
        raise ServiceError("Duplicate serial numbers in the shipping notice")
    if len(serials) > req.quantity - req.received_quantity:
        raise ServiceError(f"The PO has only {req.quantity - req.received_quantity} item(s) outstanding")
    if db.execute(select(ShippingNotice).where(ShippingNotice.asn_ref == asn_ref.strip())).first():
        raise ServiceError("This shipping notice was already recorded", 409)
    asn = ShippingNotice(request_id=req.id, asn_ref=asn_ref.strip(), serials=serials, eta=eta, received_serials=[],
                         created_by_id=actor.id, created_at=utcnow())
    db.add(asn)
    db.flush()
    auditlog.record(db, actor, "request.asn", "request", req.reference, asn=asn.asn_ref, serials=serials,
                    eta=eta.isoformat() if eta else None)
    notify_roles(db, [Role.IT_ASSET_MANAGER, Role.FINANCE],
                 f"Shipping notice {asn.asn_ref} for {req.reference}",
                 f"{len(serials)} item(s) expected at the staging centre"
                 f"{' on ' + eta.isoformat() if eta else ''}. Destination: {req.branch.code} {req.branch.name}.",
                 [NotificationChannel.EMAIL])
    notify(db, [req.branch.manager] if req.branch.manager else [], f"Equipment on order for {req.branch.code}",
           f"{req.reference}: {len(serials)} × {req.asset_type} shipped by the vendor to central staging.",
           [NotificationChannel.EMAIL])
    return asn


def receive(db: Session, actor: User, req: EquipmentRequest, serials: list[str],
            unit_cost: float | None = None) -> list:
    """Goods-in (slide 27, steps 2-3): goods checked against the PO and shipping notice, asset numbers issued,
    RFID + QR labels encoded, records created 'In stock'. A short or wrong delivery opens an exception ticket;
    items not on the shipping notice are not registered."""
    from itam.services.discovery import raise_exception

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
    asn = shipping_notice(db, req)
    if asn is not None:
        expected = {s.lower() for s in asn.outstanding}
        wrong = [s for s in serials if s.lower() not in expected]
        serials = [s for s in serials if s.lower() in expected]
        short = [s for s in asn.outstanding if s.lower() not in {x.lower() for x in serials}]
        if wrong or short:
            raise_exception(
                db, exception_type=ExceptionType.GOODS_RECEIPT_VARIANCE, source=ExceptionSource.LOGISTICS,
                dedup_key=f"GRN:{asn.id}:{utcnow():%Y%m%d%H%M%S}", branch=central_store(db),
                summary=f"Goods-in variance on {req.reference} / {asn.asn_ref}: {len(wrong)} not on notice, "
                        f"{len(short)} short",
                observed={"request": req.reference, "asn": asn.asn_ref, "not_on_notice": wrong, "short": short,
                          "po": req.po_number},
            )
            notify_roles(db, [Role.PROCUREMENT, Role.IT_ASSET_MANAGER], f"Goods-in variance: {req.reference}",
                         f"Shipping notice {asn.asn_ref}. Not on notice (held, not registered): {', '.join(wrong) or '—'}. "
                         f"Short: {', '.join(short) or '—'}.", [NotificationChannel.EMAIL])
        if not serials:
            return []
        asn.received_serials = list(asn.received_serials or []) + serials
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
                    assets=[a.asset_number for a in created], asn=asn.asn_ref if asn else None)
    # Asset no. ↔ tag ↔ serial bound; Finance notified to capitalise (slide 27, step 3).
    notify_roles(db, [Role.FINANCE], f"Capitalise {len(created)} asset(s) from {req.reference}",
                 f"PO {req.po_number}: " + ", ".join(a.asset_number for a in created), [NotificationChannel.EMAIL])
    return created
