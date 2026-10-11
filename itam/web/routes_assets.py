"""Asset register pages: list, export, register, detail, edit, lifecycle actions, QR labels."""

from __future__ import annotations

import csv
import io

import segno
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import or_, select

from itam.enums import AssetStatus, AssetType, ChangeType, Criticality
from itam.models import (
    Alert,
    Asset,
    AssetModel,
    Branch,
    ChangeRequest,
    Contract,
    ControlException,
    Location,
    MonitoringEvent,
    Region,
)
from itam.rbac import Role, acts_for_branch, can_see_branch, scope_assets, scope_branches
from itam.services import NotFound
from itam.services import assets as asset_svc
from itam.services import changes as change_svc
from itam.services.audits import asset_completeness
from itam.services.discovery import resolve_exception
from itam.web.deps import (
    DB,
    CurrentUser,
    csrf_protect,
    get_or_404,
    opt_date,
    opt_float,
    opt_int,
    opt_str,
    redirect,
    render,
    require,
)

router = APIRouter(dependencies=[Depends(csrf_protect)])
PAGE_SIZE = 50


def _visible_asset(db, user, asset_id: int) -> Asset:
    asset = get_or_404(db, Asset, asset_id, "Asset")
    if not can_see_branch(user, asset.branch):
        raise NotFound("Asset not found")
    return asset


def _filtered(db, user, params: dict):
    q = scope_assets(user, select(Asset))
    if params.get("q"):
        like = f"%{params['q'].strip()}%"
        q = q.where(or_(Asset.asset_number.ilike(like), Asset.serial_number.ilike(like), Asset.hostname.ilike(like),
                        Asset.ip_address.ilike(like), Asset.finance_asset_ref.ilike(like)))
    if params.get("status"):
        q = q.where(Asset.status == params["status"])
    else:
        q = q.where(Asset.status != AssetStatus.DISPOSED.value) if not params.get("include_disposed") else q
    if params.get("type"):
        q = q.where(Asset.asset_type == params["type"])
    if params.get("branch"):
        q = q.where(Asset.branch.has(Branch.code == params["branch"]))
    if params.get("region"):
        q = q.where(Asset.branch.has(Branch.region.has(Region.code == params["region"])))
    if params.get("criticality"):
        q = q.where(Asset.criticality == params["criticality"])
    if params.get("flag") == "untagged":
        q = q.where(Asset.tag_applied_at.is_(None))
    elif params.get("flag") == "no_custody":
        q = q.where(Asset.custody_accepted_at.is_(None), Asset.status.in_(["ACTIVE", "FAULTY"]))
    elif params.get("flag") == "pci":
        q = q.where(Asset.pci_scope.is_(True))
    elif params.get("flag") == "pending_golive":
        q = q.where(Asset.status == AssetStatus.IN_STOCK.value, Asset.install_date.is_not(None))
    return q.order_by(Asset.asset_number)


@router.get("/assets")
def asset_list(request: Request, db: DB, user: CurrentUser, page: int = 1):
    params = dict(request.query_params)
    q = _filtered(db, user, params)
    from sqlalchemy import func

    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    rows = db.execute(q.offset((max(page, 1) - 1) * PAGE_SIZE).limit(PAGE_SIZE)).scalars().all()
    regions = db.execute(select(Region).order_by(Region.code)).scalars().all()
    qs = "&".join(f"{k}={v}" for k, v in params.items() if k != "page" and v)
    return render(request, "assets.html", user, assets=rows, total=total, page=max(page, 1), page_size=PAGE_SIZE,
                  params=params, regions=regions, qs=qs)


@router.get("/assets/export.csv")
def asset_export(request: Request, db: DB, user: CurrentUser):
    require(user, "asset.export")
    rows = db.execute(_filtered(db, user, dict(request.query_params))).scalars().all()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["asset_number", "serial_number", "type", "vendor", "model", "status", "criticality", "region", "branch_code",
                "branch", "location", "rack_u", "hostname", "ip_address", "mac_address", "custodian", "custody_accepted_at",
                "install_date", "warranty_end", "eol_date", "eos_date", "purchase_cost", "finance_asset_ref", "pci_scope",
                "holds_customer_data", "monitored", "oper_state", "last_seen_at", "tag_applied_at"])
    for a in rows:
        w.writerow([a.asset_number, a.serial_number, a.asset_type, a.model.vendor.name if a.model else "",
                    a.model.name if a.model else "", a.status, a.criticality, a.branch.region.code, a.branch.code,
                    a.branch.name, a.location.label if a.location else "", a.rack_u or "", a.hostname or "",
                    a.ip_address or "", a.mac_address or "", a.custodian.full_name if a.custodian else "",
                    a.custody_accepted_at or "", a.install_date or "", a.effective_warranty_end or "", a.eol_date or "",
                    a.eos_date or "", a.purchase_cost or "", a.finance_asset_ref or "", a.pci_scope,
                    a.holds_customer_data, a.monitored, a.oper_state, a.last_seen_at or "", a.tag_applied_at or ""])
    from itam import auditlog

    auditlog.record(db, user, "asset.export", "asset", None, rows=len(rows), filters=dict(request.query_params))
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=asset_register.csv"})


def _form_context(db, user, **extra):
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    models = db.execute(select(AssetModel).order_by(AssetModel.asset_type, AssetModel.name)).scalars().all()
    contracts = db.execute(select(Contract).order_by(Contract.reference)).scalars().all()
    locations = db.execute(select(Location).order_by(Location.branch_id, Location.id)).scalars().all()
    return dict(branches=branches, models=models, contracts=contracts, locations=locations,
                types=list(AssetType), criticalities=list(Criticality), **extra)


@router.get("/assets/new")
def asset_new(request: Request, db: DB, user: CurrentUser):
    require(user, "asset.register")
    prefill = dict(request.query_params)
    return render(request, "asset_form.html", user, asset=None, prefill=prefill, **_form_context(db, user))


@router.post("/assets/new")
async def asset_create(request: Request, db: DB, user: CurrentUser):
    require(user, "asset.register")
    f = await request.form()
    branch = get_or_404(db, Branch, opt_int(f.get("branch_id")), "Branch")
    initial = AssetStatus(f.get("initial_status") or "IN_STOCK")
    asset = asset_svc.register_asset(
        db, user, branch=branch, asset_type=f.get("asset_type", ""), serial_number=f.get("serial_number", ""),
        model_id=opt_int(f.get("model_id")), initial_status=initial, tag_applied=f.get("tag_applied") == "1",
        criticality=opt_str(f.get("criticality")), hostname=opt_str(f.get("hostname")),
        ip_address=opt_str(f.get("ip_address")), mac_address=opt_str((f.get("mac_address") or "").lower()),
        location_id=opt_int(f.get("location_id")), rack_u=opt_str(f.get("rack_u")),
        contract_id=opt_int(f.get("contract_id")), purchase_cost=opt_float(f.get("purchase_cost")),
        warranty_end=opt_date(f.get("warranty_end")), finance_asset_ref=opt_str(f.get("finance_asset_ref")),
        pci_scope=f.get("pci_scope") == "1", holds_customer_data=f.get("holds_customer_data") == "1",
        notes=opt_str(f.get("notes")),
    )
    exc_id = opt_int(f.get("exception_id"))
    if exc_id:
        exc = db.get(ControlException, exc_id)
        if exc and exc.status == "OPEN":
            resolve_exception(db, user, exc, f"Registered as {asset.asset_number}", linked_asset=asset)
    return redirect(f"/assets/{asset.id}", f"Registered {asset.asset_number}. Print and apply the QR tag.", request)


@router.get("/assets/{asset_id}")
def asset_detail(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    changes = db.execute(select(ChangeRequest).where(ChangeRequest.asset_id == asset.id)
                         .order_by(ChangeRequest.id.desc())).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.asset_id == asset.id).order_by(Alert.detected_at.desc()).limit(20)).scalars().all()
    events = db.execute(select(MonitoringEvent).where(MonitoringEvent.asset_id == asset.id)
                        .order_by(MonitoringEvent.occurred_at.desc()).limit(20)).scalars().all()
    exceptions = db.execute(select(ControlException).where(ControlException.asset_id == asset.id)
                            .order_by(ControlException.id.desc())).scalars().all()
    locations = db.execute(select(Location).where(Location.branch_id == asset.branch_id)).scalars().all()
    filled, required, missing = asset_completeness(asset)
    open_change = change_svc.open_change_for(db, asset)
    allowed_changes = [ct for ct in ChangeType if AssetStatus(asset.status) in change_svc.ALLOWED_FROM[ct]]
    return render(request, "asset_detail.html", user, asset=asset, changes=changes, alerts=alerts, events=events,
                  exceptions=exceptions, locations=locations, completeness=(filled, required, missing),
                  open_change=open_change, allowed_changes=allowed_changes,
                  install_checklist=asset_svc.INSTALL_CHECKLIST,
                  is_manager=acts_for_branch(user, Role.BRANCH_MANAGER, asset.branch))


@router.get("/assets/{asset_id}/edit")
def asset_edit_form(request: Request, db: DB, user: CurrentUser, asset_id: int):
    require(user, "asset.edit")
    asset = _visible_asset(db, user, asset_id)
    return render(request, "asset_form.html", user, asset=asset, prefill={}, **_form_context(db, user))


@router.post("/assets/{asset_id}/edit")
async def asset_edit(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    f = await request.form()
    changes = {
        "serial_number": (f.get("serial_number") or "").strip() or asset.serial_number,
        "model_id": opt_int(f.get("model_id")), "criticality": f.get("criticality") or asset.criticality,
        "hostname": opt_str(f.get("hostname")), "ip_address": opt_str(f.get("ip_address")),
        "mac_address": opt_str((f.get("mac_address") or "").lower()), "location_id": opt_int(f.get("location_id")),
        "rack_u": opt_str(f.get("rack_u")), "contract_id": opt_int(f.get("contract_id")),
        "purchase_cost": opt_float(f.get("purchase_cost")), "warranty_end": opt_date(f.get("warranty_end")),
        "finance_asset_ref": opt_str(f.get("finance_asset_ref")), "pci_scope": f.get("pci_scope") == "1",
        "holds_customer_data": f.get("holds_customer_data") == "1", "notes": opt_str(f.get("notes")),
    }
    if changes["purchase_cost"] is not None and asset.purchase_cost is not None \
            and float(asset.purchase_cost) == changes["purchase_cost"]:
        changes["purchase_cost"] = asset.purchase_cost
    asset_svc.update_asset(db, user, asset, changes)
    return redirect(f"/assets/{asset.id}", "Asset updated.", request)


@router.post("/assets/{asset_id}/install")
async def asset_install(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    f = await request.form()
    asset_svc.install_asset(db, user, asset, location_id=opt_int(f.get("location_id")),
                            ip_address=opt_str(f.get("ip_address")), hostname=opt_str(f.get("hostname")),
                            mac_address=opt_str((f.get("mac_address") or "").lower()), rack_u=opt_str(f.get("rack_u")),
                            checklist={k: f.get(k) == "1" for k in asset_svc.INSTALL_CHECKLIST})
    msg = ("Installed. Status becomes 'Installed – active' once discovery confirms the device."
           if asset.status == AssetStatus.IN_STOCK.value else "Installed and live.")
    return redirect(f"/assets/{asset.id}", msg, request)


@router.post("/assets/{asset_id}/verify")
def asset_verify(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    asset_svc.verify_go_live(db, user, asset, method=f"manual by {user.username}")
    return redirect(f"/assets/{asset.id}", "Go-live verified.", request)


@router.post("/assets/{asset_id}/custody")
def asset_custody(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    asset_svc.accept_custody(db, user, asset)
    return redirect(f"/assets/{asset.id}", "Custody accepted.", request)


@router.post("/assets/{asset_id}/tag")
def asset_tag(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    asset_svc.mark_tag_applied(db, user, asset)
    return redirect(f"/assets/{asset.id}", "Tag recorded as applied.", request)


def _qr_payload(request: Request, asset: Asset) -> str:
    return f"{str(request.base_url).rstrip('/')}/scan/{asset.asset_number}"


@router.get("/assets/{asset_id}/qr.svg")
def asset_qr(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    buf = io.BytesIO()
    segno.make(_qr_payload(request, asset), error="m").save(buf, kind="svg", scale=4, border=2, dark="#000")
    return Response(buf.getvalue(), media_type="image/svg+xml")


@router.get("/assets/{asset_id}/label")
def asset_label(request: Request, db: DB, user: CurrentUser, asset_id: int):
    asset = _visible_asset(db, user, asset_id)
    return render(request, "label.html", user, assets=[asset])


@router.get("/labels")
def labels(request: Request, db: DB, user: CurrentUser, branch: str = "", ids: str = ""):
    """Batch label sheet for pre-printing QR tags (branch-day T-10)."""
    q = scope_assets(user, select(Asset).where(Asset.status != AssetStatus.DISPOSED.value))
    if ids:
        q = q.where(Asset.id.in_([int(i) for i in ids.split(",") if i.isdigit()]))
    elif branch:
        q = q.where(Asset.branch.has(Branch.code == branch))
    else:
        q = q.where(Asset.tag_applied_at.is_(None))
    rows = db.execute(q.order_by(Asset.asset_number).limit(200)).scalars().all()
    return render(request, "label.html", user, assets=rows)


@router.get("/scan/{asset_number}")
def scan_landing(request: Request, db: DB, user: CurrentUser, asset_number: str):
    """Target of the QR code: opens the asset record on a phone."""
    asset = asset_svc.find_by_number(db, asset_number)
    if asset is None or not can_see_branch(user, asset.branch):
        raise NotFound("Unknown tag")
    return redirect(f"/assets/{asset.id}")
