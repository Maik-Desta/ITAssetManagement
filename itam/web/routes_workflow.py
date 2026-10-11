"""Equipment requests (slide 19) and change requests with maker-checker approval (slide 20)."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select

from itam.enums import CHANGE_LABELS, OPEN_CHANGE_STATUSES, AssetType, ChangeStatus, ChangeType, RequestStatus
from itam.models import Asset, AssetModel, Branch, ChangeRequest, Contract, EquipmentRequest, Location
from itam.rbac import can, can_see_branch, scope_branches
from itam.services import NotFound, ServiceError
from itam.services import changes as change_svc
from itam.services import requests as req_svc
from itam.web.deps import DB, CurrentUser, csrf_protect, get_or_404, opt_float, opt_int, opt_str, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


# --- Equipment requests ----------------------------------------------------------


@router.get("/requests")
def request_list(request: Request, db: DB, user: CurrentUser, status: str = ""):
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(EquipmentRequest).where(EquipmentRequest.branch_id.in_(branch_ids))
    if status:
        q = q.where(EquipmentRequest.status == status)
    rows = db.execute(q.order_by(EquipmentRequest.id.desc()).limit(300)).scalars().all()
    return render(request, "requests.html", user, rows=rows, status=status, statuses=list(RequestStatus))


@router.get("/requests/new")
def request_new(request: Request, db: DB, user: CurrentUser):
    require(user, "request.create")
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    models = db.execute(select(AssetModel).where(AssetModel.is_standard.is_(True))
                        .order_by(AssetModel.asset_type)).scalars().all()
    return render(request, "request_form.html", user, branches=branches, models=models, types=list(AssetType))


@router.post("/requests/new")
def request_create(request: Request, db: DB, user: CurrentUser, branch_id: int = Form(...), asset_type: str = Form(...),
                   quantity: int = Form(1), justification: str = Form(...), model_id: str = Form(""),
                   estimated_cost: str = Form("")):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    if not can_see_branch(user, branch):
        raise NotFound("Branch not found")
    req = req_svc.create_request(db, user, branch=branch, asset_type=asset_type, quantity=quantity,
                                 justification=justification, model_id=opt_int(model_id),
                                 estimated_cost=opt_float(estimated_cost))
    return redirect(f"/requests/{req.id}", f"Request {req.reference} submitted for approval.", request)


@router.get("/requests/{rid}")
def request_detail(request: Request, db: DB, user: CurrentUser, rid: int):
    req = get_or_404(db, EquipmentRequest, rid, "Request")
    if not can_see_branch(user, req.branch):
        raise NotFound("Request not found")
    received = db.execute(select(Asset).where(Asset.request_id == req.id).order_by(Asset.id)).scalars().all()
    contracts = db.execute(select(Contract).order_by(Contract.reference)).scalars().all()
    return render(request, "request_detail.html", user, req=req, received=received, contracts=contracts)


@router.post("/requests/{rid}/approve")
def request_approve(request: Request, db: DB, user: CurrentUser, rid: int, kind: str = Form(...)):
    req = get_or_404(db, EquipmentRequest, rid, "Request")
    req_svc.approve(db, user, req, kind)
    return redirect(f"/requests/{req.id}", "Approval recorded.", request)


@router.post("/requests/{rid}/reject")
def request_reject(request: Request, db: DB, user: CurrentUser, rid: int, reason: str = Form(...)):
    req = get_or_404(db, EquipmentRequest, rid, "Request")
    req_svc.reject(db, user, req, reason)
    return redirect(f"/requests/{req.id}", "Request rejected.", request)


@router.post("/requests/{rid}/po")
def request_po(request: Request, db: DB, user: CurrentUser, rid: int, po_number: str = Form(...),
               supplier: str = Form(...), contract_id: str = Form("")):
    req = get_or_404(db, EquipmentRequest, rid, "Request")
    req_svc.record_po(db, user, req, po_number, supplier, opt_int(contract_id))
    return redirect(f"/requests/{req.id}", "Purchase order recorded.", request)


@router.post("/requests/{rid}/receive")
def request_receive(request: Request, db: DB, user: CurrentUser, rid: int, serials: str = Form(...),
                    unit_cost: str = Form("")):
    req = get_or_404(db, EquipmentRequest, rid, "Request")
    created = req_svc.receive(db, user, req, serials.replace(",", "\n").splitlines(), opt_float(unit_cost))
    ids = ",".join(str(a.id) for a in created)
    return redirect(f"/requests/{req.id}?labels={ids}",
                    f"Received {len(created)} item(s) into the central store. Print the QR tags.", request)


# --- Change requests --------------------------------------------------------------


@router.get("/changes")
def change_list(request: Request, db: DB, user: CurrentUser, view: str = "open"):
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(ChangeRequest)
    if view == "mine":
        q = q.where(ChangeRequest.status == ChangeStatus.PENDING_APPROVAL.value)
    else:
        q = q.where(ChangeRequest.from_branch_id.in_(branch_ids) | ChangeRequest.to_branch_id.in_(branch_ids))
        if view == "open":
            q = q.where(ChangeRequest.status.in_([s.value for s in OPEN_CHANGE_STATUSES]))
        elif view == "finance":
            q = q.where(ChangeRequest.change_type == ChangeType.DISPOSE.value,
                        ChangeRequest.status == ChangeStatus.COMPLETED.value,
                        ChangeRequest.finance_confirmed_at.is_(None))
    rows = db.execute(q.order_by(ChangeRequest.id.desc()).limit(300)).scalars().all()
    if view == "mine":
        rows = [c for c in rows if change_svc.can_approve(user, c)[0]]
    return render(request, "changes.html", user, rows=rows, view=view)


@router.get("/changes/new")
def change_new(request: Request, db: DB, user: CurrentUser, asset_id: int, type: str = ""):
    require(user, "change.create")
    asset = get_or_404(db, Asset, asset_id, "Asset")
    if not can_see_branch(user, asset.branch):
        raise NotFound("Asset not found")
    branches = db.execute(select(Branch).order_by(Branch.code)).scalars().all()
    locations = db.execute(select(Location).order_by(Location.branch_id, Location.id)).scalars().all()
    change_type = ChangeType(type) if type in ChangeType._value2member_map_ else None
    matrix = {ct.value: [r.value for r in change_svc.approval_matrix(ct, asset)] for ct in ChangeType}
    return render(request, "change_form.html", user, asset=asset, branches=branches, locations=locations,
                  change_type=change_type, matrix=matrix,
                  allowed=[ct for ct in ChangeType if asset.status in {s.value for s in change_svc.ALLOWED_FROM[ct]}])


@router.post("/changes/new")
def change_create(request: Request, db: DB, user: CurrentUser, asset_id: int = Form(...), change_type: str = Form(...),
                  reason: str = Form(...), to_branch_id: str = Form(""), to_location_id: str = Form(""),
                  scheduled_for: str = Form(""), ticket_ref: str = Form("")):
    asset = get_or_404(db, Asset, asset_id, "Asset")
    if not can_see_branch(user, asset.branch):
        raise NotFound("Asset not found")
    to_branch = db.get(Branch, opt_int(to_branch_id)) if opt_int(to_branch_id) else None
    to_location = db.get(Location, opt_int(to_location_id)) if opt_int(to_location_id) else None
    try:
        when = datetime.fromisoformat(scheduled_for) if scheduled_for else None
    except ValueError:
        raise ServiceError("Invalid scheduled date/time") from None
    change = change_svc.create_change(db, user, asset, ChangeType(change_type), reason, to_branch=to_branch,
                                      to_location=to_location, scheduled_for=when, ticket_ref=opt_str(ticket_ref))
    return redirect(f"/changes/{change.id}", f"{change.reference} submitted for approval.", request)


@router.get("/changes/{cid}")
def change_detail(request: Request, db: DB, user: CurrentUser, cid: int):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    if not (can_see_branch(user, change.from_branch) or (change.to_branch and can_see_branch(user, change.to_branch))
            or change_svc.can_approve(user, change)[0]):
        raise NotFound("Change not found")
    ok, why = change_svc.can_approve(user, change)
    dest_locations = []
    if change.to_branch_id:
        dest_locations = db.execute(select(Location).where(Location.branch_id == change.to_branch_id)).scalars().all()
    return render(request, "change_detail.html", user, change=change, can_approve=ok, approve_reason=why,
                  evidence=change_svc.evidence_required(change), evidence_labels=change_svc.EVIDENCE_LABELS,
                  dest_locations=dest_locations, label=CHANGE_LABELS[ChangeType(change.change_type)],
                  can_execute=can(user, "change.execute"))


@router.post("/changes/{cid}/decide")
def change_decide(request: Request, db: DB, user: CurrentUser, cid: int, decision: str = Form(...),
                  comment: str = Form("")):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    change_svc.decide(db, user, change, decision == "approve", opt_str(comment))
    return redirect(f"/changes/{change.id}", f"Decision recorded: {change.status.replace('_', ' ').lower()}.", request)


@router.post("/changes/{cid}/execute")
def change_execute(request: Request, db: DB, user: CurrentUser, cid: int, scanned_tag: str = Form(...),
                   ticket_ref: str = Form(""), evidence_ref: str = Form(""), wipe_certificate_ref: str = Form(""),
                   disposal_certificate_ref: str = Form("")):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    change_svc.execute(db, user, change, scanned_tag, ticket_ref=ticket_ref, evidence_ref=evidence_ref,
                       wipe_certificate_ref=wipe_certificate_ref, disposal_certificate_ref=disposal_certificate_ref)
    return redirect(f"/changes/{change.id}", "Change executed.", request)


@router.post("/changes/{cid}/deliver")
def change_deliver(request: Request, db: DB, user: CurrentUser, cid: int, to_location_id: str = Form("")):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    loc = db.get(Location, opt_int(to_location_id)) if opt_int(to_location_id) else None
    change_svc.confirm_delivery(db, user, change, loc)
    return redirect(f"/changes/{change.id}", "Delivery signed. Install the asset and accept custody.", request)


@router.post("/changes/{cid}/return")
def change_return(request: Request, db: DB, user: CurrentUser, cid: int, note: str = Form("")):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    change_svc.return_from_repair(db, user, change, opt_str(note))
    return redirect(f"/changes/{change.id}", "Asset returned from repair.", request)


@router.post("/changes/{cid}/cancel")
def change_cancel(request: Request, db: DB, user: CurrentUser, cid: int, reason: str = Form(...)):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    change_svc.cancel(db, user, change, reason)
    return redirect(f"/changes/{change.id}", "Change cancelled.", request)


@router.post("/changes/{cid}/finance")
def change_finance(request: Request, db: DB, user: CurrentUser, cid: int):
    change = get_or_404(db, ChangeRequest, cid, "Change")
    change_svc.finance_confirm(db, user, change)
    return redirect(f"/changes/{change.id}", "Fixed-asset register update confirmed.", request)
