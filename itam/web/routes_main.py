"""Executive dashboard, NOC console, alerts, branches."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select

from itam.enums import (
    ROLLOUT_CHECKLIST,
    AlertSource,
    AlertStatus,
    AssetStatus,
    AuditMethod,
    AuditStatus,
    RolloutStage,
    Severity,
)
from itam.models import (
    Alert,
    Asset,
    Attestation,
    Branch,
    ControlException,
    MonitoringEvent,
    PhysicalAudit,
    Region,
    utcnow,
)
from itam.rbac import Role, acts_for_branch, can_see_branch, scope_branches
from itam.services import NotFound, PermissionDenied
from itam.services import audits as audit_svc
from itam.services import dashboard as dash_svc
from itam.services import monitoring as mon_svc
from itam.services import rollout as rollout_svc
from itam.web.deps import DB, CurrentUser, csrf_protect, get_or_404, opt_date, opt_float, opt_int, redirect, render, require

router = APIRouter(dependencies=[Depends(csrf_protect)])


@router.get("/")
def home():
    return redirect("/dashboard")


@router.get("/dashboard")
def dashboard(request: Request, db: DB, user: CurrentUser, board: str = ""):
    """One-page command centre: CEO, CIO or CISO board (defaults to the user's role)."""
    from itam.services import command as cmd_svc

    board = board if board in cmd_svc.BOARDS else cmd_svc.default_board(user)
    return render(request, "board.html", user, d=cmd_svc.build(db, user, board), refresh=120)


@router.get("/dashboard/details")
def dashboard_details(request: Request, db: DB, user: CurrentUser, region: str = ""):
    summary = dash_svc.executive_summary(db, user)
    inv = dash_svc.asset_inventory(db, summary["branches"])
    return render(request, "dashboard.html", user, s=summary, inv=inv, region=region,
                  messages_ceo=dash_svc.key_messages(summary, inv))


# --- NOC console ---------------------------------------------------------------


def _scoped_alerts(db, user, statuses, severities=None, branch_id=None):
    branches = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(Alert).where(Alert.status.in_(statuses))
    q = q.where((Alert.branch_id.in_(branches)) | (Alert.branch_id.is_(None)))
    if severities:
        q = q.where(Alert.severity.in_(severities))
    if branch_id:
        q = q.where(Alert.branch_id == branch_id)
    return db.execute(q.order_by(Alert.severity, Alert.detected_at.desc()).limit(500)).scalars().all()


@router.get("/noc")
def noc(request: Request, db: DB, user: CurrentUser, show: str = "live"):
    from itam.services.noc import noc_overview

    data = noc_overview(db, user)
    history = []
    if show == "history":
        history = _scoped_alerts(db, user, [AlertStatus.RESOLVED.value], None)[:200]
    return render(request, "noc.html", user, n=data, show=show, history=history, refresh=60 if show == "live" else 0)


@router.get("/notifications")
def my_notifications(request: Request, db: DB, user: CurrentUser):
    from itam.models import Notification

    rows = db.execute(select(Notification).where(Notification.recipient_user_id == user.id)
                      .order_by(Notification.id.desc()).limit(200)).scalars().all()
    unread = [n for n in rows if n.channel == "SYSTEM" and n.status == "UNREAD"]
    page = render(request, "my_notifications.html", user, rows=rows, unread_ids={n.id for n in unread})
    for n in unread:
        n.status = "READ"
    return page


@router.get("/alerts/{alert_id}")
def alert_detail(request: Request, db: DB, user: CurrentUser, alert_id: int):
    alert = db.get(Alert, alert_id)
    if alert is None or (alert.branch and not can_see_branch(user, alert.branch)):
        raise NotFound("Alert not found")
    from itam.models import Notification
    from itam.services.monitoring import escalation_path
    from itam.services.noc import notification_summary

    notifications = db.execute(select(Notification).where(Notification.alert_id == alert.id)
                               .order_by(Notification.id)).scalars().all()
    events = []
    if alert.asset_id:
        events = db.execute(select(MonitoringEvent).where(MonitoringEvent.asset_id == alert.asset_id)
                            .order_by(MonitoringEvent.occurred_at.desc()).limit(30)).scalars().all()
    return render(request, "alert_detail.html", user, alert=alert, events=events, now=utcnow(),
                  esc_path=escalation_path(alert), notifications=notifications,
                  channels=notification_summary(notifications))


@router.post("/alerts/{alert_id}/ack")
def alert_ack(request: Request, db: DB, user: CurrentUser, alert_id: int, next: str = Form("/noc")):
    alert = get_or_404(db, Alert, alert_id, "Alert")
    mon_svc.acknowledge(db, user, alert)
    return redirect(next if next.startswith("/") else "/noc", f"Alert {alert.ticket_ref or alert.id} acknowledged.", request)


@router.post("/alerts/{alert_id}/resolve")
def alert_resolve(request: Request, db: DB, user: CurrentUser, alert_id: int, resolution: str = Form(...)):
    alert = get_or_404(db, Alert, alert_id, "Alert")
    mon_svc.resolve(db, user, alert, resolution)
    return redirect(f"/alerts/{alert.id}", "Alert resolved.", request)


@router.post("/noc/incident")
def report_incident(request: Request, db: DB, user: CurrentUser, branch_id: int = Form(...),
                    description: str = Form(...), severity: str = Form("P2"), asset_number: str = Form("")):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    asset = None
    if asset_number.strip():
        asset = db.execute(select(Asset).where(Asset.asset_number == asset_number.strip().upper())).scalar_one_or_none()
        if asset is None:
            raise NotFound("Asset number not found")
    alert = mon_svc.report_user_incident(db, user, branch, description, asset, Severity(severity))
    msg = ("Already detected by monitoring — report attached to the existing alert."
           if alert.source == AlertSource.MONITORING.value else "User-reported incident logged.")
    return redirect(f"/alerts/{alert.id}", msg, request)


# --- Branches ------------------------------------------------------------------


@router.get("/branches")
def branches(request: Request, db: DB, user: CurrentUser, region: str = "", q: str = ""):
    query = scope_branches(user, select(Branch).order_by(Branch.code))
    if region:
        query = query.where(Branch.region.has(Region.code == region))
    if q:
        like = f"%{q.strip()}%"
        query = query.where(Branch.name.ilike(like) | Branch.code.ilike(like) | Branch.city.ilike(like))
    rows = db.execute(query).scalars().all()
    states = dash_svc.branch_states(db, rows)
    counts = dict(db.execute(select(Asset.branch_id, func.count(Asset.id)).where(
        Asset.status != AssetStatus.DISPOSED.value).group_by(Asset.branch_id)).all())
    regions = db.execute(select(Region).order_by(Region.code)).scalars().all()
    from collections import Counter

    from itam.web.deps import mix
    from itam.web.mixes import BRANCH_STATE

    return render(request, "branches.html", user, branches=rows, states=states, counts=counts, regions=regions,
                  region=region, q=q, state_mix=mix(Counter(states.get(b.id) for b in rows), BRANCH_STATE))


@router.get("/branches/{branch_id}")
def branch_detail(request: Request, db: DB, user: CurrentUser, branch_id: int):
    branch = db.get(Branch, branch_id)
    if branch is None or not can_see_branch(user, branch):
        raise NotFound("Branch not found")
    assets = db.execute(select(Asset).where(Asset.branch_id == branch.id).order_by(Asset.asset_type, Asset.asset_number)).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.branch_id == branch.id, Alert.status != AlertStatus.RESOLVED.value)
                        .order_by(Alert.severity)).scalars().all()
    audits = db.execute(select(PhysicalAudit).where(PhysicalAudit.branch_id == branch.id)
                        .order_by(PhysicalAudit.scheduled_for.desc())).scalars().all()
    attestations = db.execute(select(Attestation).where(Attestation.branch_id == branch.id)
                              .order_by(Attestation.attested_at.desc())).scalars().all()
    exceptions = db.execute(select(ControlException).where(ControlException.branch_id == branch.id,
                                                           ControlException.status == "OPEN")).scalars().all()
    dq = audit_svc.branch_data_quality(db, branch)
    state = dash_svc.branch_states(db, [branch]).get(branch.id)
    stage = RolloutStage(branch.rollout_stage)
    return render(request, "branch_detail.html", user, branch=branch, assets=assets, alerts=alerts, audits=audits,
                  attestations=attestations, exceptions=exceptions, dq=dq, state=state,
                  checklist=ROLLOUT_CHECKLIST.get(stage, []), stage=stage,
                  is_manager=acts_for_branch(user, Role.BRANCH_MANAGER, branch),
                  pending_custody=[a for a in assets if a.status in (AssetStatus.ACTIVE.value, AssetStatus.FAULTY.value,
                                                                     AssetStatus.IN_STOCK.value)
                                   and not a.custody_accepted_at])


@router.post("/branches/{branch_id}/attest")
def branch_attest(request: Request, db: DB, user: CurrentUser, branch_id: int, statement: str = Form(...),
                  audit_id: str = Form("")):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    audit = db.get(PhysicalAudit, opt_int(audit_id)) if opt_int(audit_id) else None
    audit_svc.attest(db, user, branch, statement, audit)
    return redirect(f"/branches/{branch.id}", "Custody attestation recorded.", request)


@router.post("/branches/{branch_id}/custody-all")
def branch_custody_all(request: Request, db: DB, user: CurrentUser, branch_id: int):
    from itam.services.assets import accept_custody

    branch = get_or_404(db, Branch, branch_id, "Branch")
    if not acts_for_branch(user, Role.BRANCH_MANAGER, branch):
        raise PermissionDenied("Only the branch manager can accept custody")
    count = 0
    for asset in db.execute(select(Asset).where(Asset.branch_id == branch.id, Asset.custody_accepted_at.is_(None),
                                                Asset.status.in_([AssetStatus.ACTIVE.value, AssetStatus.FAULTY.value,
                                                                  AssetStatus.IN_STOCK.value]))).scalars():
        accept_custody(db, user, asset)
        count += 1
    return redirect(f"/branches/{branch.id}", f"Custody accepted for {count} asset(s).", request)


@router.post("/branches/{branch_id}/rollout/check")
def rollout_check(request: Request, db: DB, user: CurrentUser, branch_id: int, item: str = Form(...),
                  done: str = Form("0")):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    rollout_svc.toggle_item(db, user, branch, item, done == "1")
    return redirect(f"/branches/{branch.id}#rollout")


@router.post("/branches/{branch_id}/rollout/advance")
def rollout_advance(request: Request, db: DB, user: CurrentUser, branch_id: int):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    rollout_svc.advance(db, user, branch)
    return redirect(f"/branches/{branch.id}#rollout", f"Branch moved to stage {branch.rollout_stage}.", request)


@router.post("/branches/{branch_id}/audits")
def branch_schedule_audit(request: Request, db: DB, user: CurrentUser, branch_id: int, scheduled_for: str = Form(...),
                          method: str = Form("MOBILE_SCAN")):
    branch = get_or_404(db, Branch, branch_id, "Branch")
    when = opt_date(scheduled_for)
    if when is None:
        return redirect(f"/branches/{branch.id}", "Choose a date.", request, "error")
    audit = audit_svc.schedule_audit(db, user, branch, when, AuditMethod(method))
    return redirect(f"/audits/{audit.id}", "Audit scheduled.", request)


# --- Rollout & KPIs --------------------------------------------------------------


@router.get("/rollout")
def rollout(request: Request, db: DB, user: CurrentUser):
    from itam.models import Milestone

    waves = rollout_svc.wave_summary(db)
    branches = db.execute(scope_branches(user, select(Branch).where(
        Branch.rollout_stage != RolloutStage.LIVE.value, Branch.rollout_stage != RolloutStage.NOT_STARTED.value)
        .order_by(Branch.planned_go_live))).scalars().all()
    milestones = db.execute(select(Milestone).order_by(Milestone.planned_date)).scalars().all()
    live_last_week = db.execute(select(func.count(Branch.id)).where(
        Branch.went_live_at >= utcnow() - timedelta(days=7)
    )).scalar_one()
    from itam.config import settings
    from itam.enums import OPERATING_MODEL_LABELS, ORDER_STAGES, STAGE_OPERATORS, OperatingModel

    model = OperatingModel(settings.operating_model) if settings.operating_model in OperatingModel._value2member_map_ \
        else OperatingModel.SISTER_COMPANY
    return render(request, "rollout.html", user, waves=waves, in_flight=branches, milestones=milestones,
                  live_last_week=live_last_week, operating_model=model, model_labels=OPERATING_MODEL_LABELS,
                  stages=list(zip(ORDER_STAGES, STAGE_OPERATORS[model])), all_operators=STAGE_OPERATORS,
                  operator_name=settings.operator_name)


@router.post("/rollout/milestones/{mid}")
def milestone_update(request: Request, db: DB, user: CurrentUser, mid: int, actual_date: str = Form(""),
                     budget_actual: str = Form("")):
    from itam import auditlog
    from itam.models import Milestone

    require(user, "programme.manage")
    m = get_or_404(db, Milestone, mid, "Milestone")
    m.actual_date = opt_date(actual_date)
    m.budget_actual = opt_float(budget_actual)
    auditlog.record(db, user, "programme.milestone", "milestone", m.code, actual=m.actual_date, budget=m.budget_actual)
    return redirect("/rollout", f"Milestone {m.code} updated.", request)


@router.get("/kpis")
def kpis(request: Request, db: DB, user: CurrentUser):
    return render(request, "kpis.html", user, kpis=dash_svc.kpis(db))


@router.get("/data-quality")
def data_quality(request: Request, db: DB, user: CurrentUser):
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    rows = [r for r in audit_svc.league_table(db, branches) if r["assets"]]
    return render(request, "data_quality.html", user, rows=rows,
                  audits_due=db.execute(select(func.count(PhysicalAudit.id)).where(
                      PhysicalAudit.status == AuditStatus.SCHEDULED.value)).scalar_one())
