"""Assurance pages: exceptions, physical audits (mobile scan), Finance reconciliation, controls, audit log."""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from itam import auditlog
from itam.enums import AuditMethod, AuditStatus, ExceptionStatus, ExceptionType
from itam.models import (
    AuditLogEntry,
    Branch,
    ControlException,
    FinanceReconciliation,
    Location,
    PhysicalAudit,
    utcnow,
)
from itam.rbac import can_see_branch, scope_branches
from itam.services import NotFound, ServiceError
from itam.services import audits as audit_svc
from itam.services import integrations as int_svc
from itam.services.discovery import resolve_exception
from itam.web.deps import DB, CurrentUser, csrf_protect, get_or_404, opt_date, opt_int, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


# --- Exceptions ----------------------------------------------------------------------


@router.get("/exceptions")
def exception_list(request: Request, db: DB, user: CurrentUser, status: str = "OPEN", type: str = "",
                   source: str = ""):
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(ControlException).where((ControlException.branch_id.in_(branch_ids)) | ControlException.branch_id.is_(None))
    if status:
        q = q.where(ControlException.status == status)
    if type:
        q = q.where(ControlException.exception_type == type)
    if source:
        q = q.where(ControlException.source == source)
    rows = db.execute(q.order_by(ControlException.created_at).limit(500)).scalars().all()
    now = utcnow()
    ageing = {"0–7 d": 0, "8–30 d": 0, "> 30 d": 0}
    for e in rows:
        if e.status == ExceptionStatus.OPEN.value:
            days = (now - e.created_at).days
            ageing["0–7 d" if days <= 7 else "8–30 d" if days <= 30 else "> 30 d"] += 1
    return render(request, "exceptions.html", user, rows=rows, status=status, type=type, source=source,
                  types=list(ExceptionType), ageing=ageing, now=now)


@router.get("/exceptions/{eid}")
def exception_detail(request: Request, db: DB, user: CurrentUser, eid: int):
    exc = get_or_404(db, ControlException, eid, "Exception")
    if exc.branch and not can_see_branch(user, exc.branch):
        raise NotFound("Exception not found")
    return render(request, "exception_detail.html", user, exc=exc, now=utcnow())


@router.post("/exceptions/{eid}/resolve")
def exception_resolve(request: Request, db: DB, user: CurrentUser, eid: int, resolution: str = Form(...),
                      allowlist: str = Form("0")):
    exc = get_or_404(db, ControlException, eid, "Exception")
    resolve_exception(db, user, exc, resolution, allowlist=allowlist == "1")
    return redirect(f"/exceptions/{exc.id}", "Exception resolved.", request)


# --- Physical audits ------------------------------------------------------------------


@router.get("/audits")
def audit_list(request: Request, db: DB, user: CurrentUser, status: str = ""):
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(PhysicalAudit).where(PhysicalAudit.branch_id.in_(branch_ids))
    if status:
        q = q.where(PhysicalAudit.status == status)
    rows = db.execute(q.order_by(PhysicalAudit.scheduled_for.desc()).limit(300)).scalars().all()
    year_start = date(date.today().year, 1, 1)
    covered = db.execute(select(func.count(func.distinct(PhysicalAudit.branch_id))).where(
        PhysicalAudit.status == AuditStatus.COMPLETED.value, PhysicalAudit.completed_at >= year_start)).scalar_one()
    total = db.execute(select(func.count(Branch.id))).scalar_one()
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    return render(request, "audits.html", user, rows=rows, status=status, covered=covered, total=total,
                  branches=branches, today=date.today())


@router.post("/audits/schedule-quarter")
def audit_schedule_quarter(request: Request, db: DB, user: CurrentUser, start: str = Form("")):
    created = audit_svc.schedule_quarterly_cycle(db, user, opt_date(start) or date.today())
    return redirect("/audits?status=SCHEDULED", f"Scheduled {len(created)} cyclical audits (25% of branches).", request)


@router.post("/audits/schedule")
def audit_schedule(request: Request, db: DB, user: CurrentUser, branch_id: int = Form(...),
                   scheduled_for: str = Form(...), method: str = Form("MOBILE_SCAN")):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    when = opt_date(scheduled_for)
    if when is None:
        raise ServiceError("Choose a date")
    audit = audit_svc.schedule_audit(db, user, branch, when, AuditMethod(method))
    return redirect(f"/audits/{audit.id}", "Audit scheduled.", request)


def _visible_audit(db, user, audit_id: int) -> PhysicalAudit:
    audit = get_or_404(db, PhysicalAudit, audit_id, "Audit")
    if not can_see_branch(user, audit.branch):
        raise NotFound("Audit not found")
    return audit


@router.get("/audits/{aid}")
def audit_detail(request: Request, db: DB, user: CurrentUser, aid: int):
    audit = _visible_audit(db, user, aid)
    locations = db.execute(select(Location).where(Location.branch_id == audit.branch_id)).scalars().all()
    scanned = sum(1 for i in audit.items if i.result)
    order = {"MISSING": 0, "UNEXPECTED": 1, "WRONG_LOCATION": 2, None: 3, "FOUND": 4}
    items = sorted(audit.items, key=lambda i: (order.get(i.result, 3), i.asset.asset_number if i.asset else ""))
    return render(request, "audit_detail.html", user, audit=audit, locations=locations, scanned=scanned, items=items)


@router.post("/audits/{aid}/start")
def audit_start(request: Request, db: DB, user: CurrentUser, aid: int):
    audit = _visible_audit(db, user, aid)
    audit_svc.start_audit(db, user, audit)
    return redirect(f"/audits/{audit.id}", f"Audit started: {audit.expected_count} assets expected.", request)


@router.post("/audits/{aid}/scan")
def audit_scan(request: Request, db: DB, user: CurrentUser, aid: int, scanned: str = Form(...),
               location_id: str = Form(""), note: str = Form("")):
    audit = _visible_audit(db, user, aid)
    item = audit_svc.scan(db, user, audit, scanned, opt_int(location_id), note or None)
    label = item.asset.asset_number if item.asset else item.scanned_value
    category = "success" if item.result == "FOUND" else "warning"
    return redirect(f"/audits/{audit.id}#scan", f"{label}: {item.result.replace('_', ' ').lower()}", request, category)


@router.post("/audits/{aid}/complete")
def audit_complete(request: Request, db: DB, user: CurrentUser, aid: int, notes: str = Form("")):
    audit = _visible_audit(db, user, aid)
    audit_svc.complete_audit(db, user, audit, notes or None)
    return redirect(f"/audits/{audit.id}", f"Audit completed — accuracy {audit.accuracy}%.", request)


# --- Finance reconciliation -------------------------------------------------------------


@router.get("/reconciliation")
def reconciliation(request: Request, db: DB, user: CurrentUser):
    require(user, "finance.reconcile")
    runs = db.execute(select(FinanceReconciliation).order_by(FinanceReconciliation.id.desc()).limit(20)).scalars().all()
    return render(request, "reconciliation.html", user, runs=runs)


@router.post("/reconciliation")
async def reconciliation_run(request: Request, db: DB, user: CurrentUser, file: UploadFile = File(...)):
    require(user, "finance.reconcile")
    raw = await file.read()
    if len(raw) > 20 * 1024 * 1024:
        raise ServiceError("File too large (max 20 MB)")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    run = int_svc.reconcile_finance(db, user, text, file.filename or "upload.csv")
    return redirect("/reconciliation", f"Reconciliation #{run.id}: {run.matched} matched, {run.mismatched} mismatched, "
                    f"{run.finance_only} Finance-only, {run.it_only} IT-only.", request)


@router.get("/reconciliation/it-register.csv")
def reconciliation_export(request: Request, db: DB, user: CurrentUser):
    require(user, "finance.reconcile")
    auditlog.record(db, user, "finance.export", "reconciliation", None)
    return StreamingResponse(iter([int_svc.finance_register_csv(db)]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=it_register_for_finance.csv"})


# --- Internal Audit -----------------------------------------------------------------------


@router.get("/controls")
def controls(request: Request, db: DB, user: CurrentUser):
    require(user, "controls.view")
    return render(request, "controls.html", user, tests=audit_svc.control_tests(db))


@router.get("/audit-log")
def audit_log(request: Request, db: DB, user: CurrentUser, actor: str = "", action: str = "", entity: str = "",
              page: int = 1, verify: int = 0):
    require(user, "auditlog.view")
    q = select(AuditLogEntry)
    if actor:
        q = q.where(AuditLogEntry.actor == actor)
    if action:
        q = q.where(AuditLogEntry.action.like(f"{action}%"))
    if entity:
        q = q.where(AuditLogEntry.entity_id == entity)
    size = 100
    rows = db.execute(q.order_by(AuditLogEntry.id.desc()).offset((max(page, 1) - 1) * size).limit(size)).scalars().all()
    verification = auditlog.verify_chain(db) if verify else None
    return render(request, "audit_log.html", user, rows=rows, actor=actor, action=action, entity=entity,
                  page=max(page, 1), size=size, verification=verification)
