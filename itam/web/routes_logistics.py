"""Staging & logistics (slides 27-28, 48) and the standard branch blueprint (slides 9, 26, 40)."""

from __future__ import annotations

from datetime import datetime, time

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import or_, select

from itam.enums import BRANCH_BLUEPRINT, AssetStatus, ShipmentStatus
from itam.models import Asset, Branch, Shipment, utcnow
from itam.rbac import can, can_see_branch, scope_branches
from itam.services import NotFound, ServiceError
from itam.services import catalogue as cat_svc
from itam.services import logistics as log_svc
from itam.services.requests import central_store
from itam.web.deps import DB, CurrentUser, csrf_protect, get_or_404, mix, opt_date, opt_str, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


def _visible_shipment(db, user, sid: int) -> Shipment:
    require(user, "shipment.view")
    s = get_or_404(db, Shipment, sid, "Shipment")
    if not (can_see_branch(user, s.to_branch) or can_see_branch(user, s.from_branch)):
        raise NotFound("Shipment not found")
    return s


@router.get("/shipments")
def shipment_list(request: Request, db: DB, user: CurrentUser, status: str = ""):
    require(user, "shipment.view")
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(Shipment).where(or_(Shipment.to_branch_id.in_(branch_ids), Shipment.from_branch_id.in_(branch_ids)))
    if status:
        q = q.where(Shipment.status == status)
    rows = db.execute(q.order_by(Shipment.id.desc()).limit(300)).scalars().all()
    from sqlalchemy import func

    from itam.web.mixes import SHIPMENT_STATUS

    counts = dict(db.execute(select(Shipment.status, func.count(Shipment.id)).where(
        or_(Shipment.to_branch_id.in_(branch_ids), Shipment.from_branch_id.in_(branch_ids)))
        .group_by(Shipment.status)).all())
    return render(request, "shipments.html", user, rows=rows, status=status, statuses=list(ShipmentStatus), now=utcnow(),
                  status_mix=mix(counts, SHIPMENT_STATUS, "/shipments?status={key}", status))


@router.get("/shipments/new")
def shipment_new(request: Request, db: DB, user: CurrentUser, to: int | None = None):
    require(user, "shipment.manage")
    store = central_store(db)
    branches = db.execute(select(Branch).where(Branch.id != store.id).order_by(Branch.code)).scalars().all()
    dest = db.get(Branch, to) if to else None
    candidates = []
    if dest is not None:
        stock = db.execute(select(Asset).where(Asset.branch_id == store.id, Asset.status == AssetStatus.IN_STOCK.value)
                           .order_by(Asset.asset_number)).scalars().all()
        for a in stock:
            _change, why = log_svc.shippable_reason(db, a, dest)
            if why is None or "not new equipment ordered" not in why:
                candidates.append((a, why))
    return render(request, "shipment_form.html", user, branches=branches, dest=dest, candidates=candidates, store=store)


@router.post("/shipments/new")
async def shipment_create(request: Request, db: DB, user: CurrentUser):
    f = await request.form()
    dest = db.get(Branch, int(f.get("to_branch_id") or 0))
    if dest is None:
        raise ServiceError("Choose a destination branch")
    ids = [int(v) for v in f.getlist("asset_id") if str(v).isdigit()]
    assets = [a for a in (db.get(Asset, i) for i in ids) if a is not None]
    eta_day = opt_date(f.get("eta"))
    s = log_svc.create_shipment(db, user, to_branch=dest, assets=assets, seal_number=f.get("seal_number") or "",
                                carrier=opt_str(f.get("carrier")),
                                eta=datetime.combine(eta_day, time(17, 0)) if eta_day else None)
    return redirect(f"/shipments/{s.id}", f"{s.reference} packed: {len(assets)} item(s), seal {s.seal_number}.", request)


@router.get("/shipments/{sid}")
def shipment_detail(request: Request, db: DB, user: CurrentUser, sid: int):
    s = _visible_shipment(db, user, sid)
    return render(request, "shipment_detail.html", user, s=s, can_receive=log_svc.can_receive(user, s),
                  is_manager=s.to_branch.manager_id == user.id)


@router.post("/shipments/{sid}/dispatch")
def shipment_dispatch(request: Request, db: DB, user: CurrentUser, sid: int):
    s = _visible_shipment(db, user, sid)
    log_svc.dispatch(db, user, s, via=f"ITAM Office ({user.username})")
    return redirect(f"/shipments/{s.id}", f"{s.reference} dispatched; the branch has been sent the ETA.", request)


@router.post("/shipments/{sid}/receive")
def shipment_receive(request: Request, db: DB, user: CurrentUser, sid: int, scanned: str = Form(""),
                     seal_intact: str = Form(""), seal_number: str = Form(""), note: str = Form("")):
    s = _visible_shipment(db, user, sid)
    log_svc.receive_shipment(db, user, s, scanned=scanned.replace(",", "\n").splitlines(), seal_intact=seal_intact == "1",
                             seal_number=opt_str(seal_number), note=opt_str(note))
    msg = "All items matched; delivery closed." if s.status == ShipmentStatus.DELIVERED.value else \
        f"Received with variance ({s.variance_note}). The ITAM Office and Security have been alerted."
    return redirect(f"/shipments/{s.id}", msg, request, "success" if s.status == ShipmentStatus.DELIVERED.value else "error")


@router.post("/shipments/{sid}/custody")
def shipment_custody(request: Request, db: DB, user: CurrentUser, sid: int):
    s = _visible_shipment(db, user, sid)
    n = log_svc.accept_custody(db, user, s)
    return redirect(f"/shipments/{s.id}", f"Custody accepted for {n} item(s).", request)


@router.post("/shipments/{sid}/cancel")
def shipment_cancel(request: Request, db: DB, user: CurrentUser, sid: int, reason: str = Form(...)):
    s = _visible_shipment(db, user, sid)
    log_svc.cancel(db, user, s, reason)
    return redirect(f"/shipments/{s.id}", "Shipment cancelled.", request)


@router.get("/blueprint")
def blueprint(request: Request, db: DB, user: CurrentUser, show: str = "issues"):
    require(user, "blueprint.view")
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    rows = cat_svc.branch_compliance(db, branches)
    started = [r for r in rows if r["started"]]
    summary = {"branches": len(started), "compliant": sum(1 for r in started if r["compliant"]),
               "non_catalogue": sum(r["non_catalogue"] for r in rows), "unapproved": sum(r["unapproved"] for r in rows),
               "excess": sum(r["excess"] for r in rows)}
    if show == "issues":
        rows = [r for r in rows if not r["compliant"]]
    return render(request, "blueprint.html", user, rows=rows[:400], summary=summary, show=show,
                  blueprint=BRANCH_BLUEPRINT, models=cat_svc.approved_models(db),
                  can_manage=can(user, "reference.manage"))
