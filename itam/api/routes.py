"""REST API (``/api/v1``).

* Collector endpoints authenticate with ``X-API-Key`` (regional collectors, slide 15).
* Everything else uses the signed-in session; state-changing calls need the ``X-CSRF-Token`` header.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Header, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from itam.models import Alert, Asset, Branch, Collector, ControlException, User
from itam.rbac import can_see_branch, scope_assets, scope_branches
from itam.security import hash_api_key
from itam.services import NotFound, PermissionDenied
from itam.services import dashboard as dash_svc
from itam.services import discovery as disc_svc
from itam.services import integrations as int_svc
from itam.services import monitoring as mon_svc
from itam.services.assets import register_asset
from itam.web.deps import DB, csrf_protect, current_user

router = APIRouter(prefix="/api/v1")


class ApiAuthError(Exception):
    pass


# --- auth ---------------------------------------------------------------------------------


def api_user(request: Request, db: DB) -> User:
    user = current_user(request, db)
    if user is None:
        raise ApiAuthError()
    return user


def collector_auth(db: DB, x_api_key: Annotated[str | None, Header()] = None) -> Collector:
    if not x_api_key:
        raise ApiAuthError()
    c = db.execute(select(Collector).where(Collector.api_key_hash == hash_api_key(x_api_key))).scalar_one_or_none()
    if c is None or not c.is_active:
        raise ApiAuthError()
    return c


ApiUser = Annotated[User, Depends(api_user)]
CollectorAuth = Annotated[Collector, Depends(collector_auth)]


# --- schemas ---------------------------------------------------------------------------------


class AssetRef(BaseModel):
    asset_number: str | None = None
    serial: str | None = None
    mac: str | None = None
    ip: str | None = None


class PollResult(AssetRef):
    state: str | None = Field(None, description="UP, DOWN, DEGRADED")
    occurred_at: datetime | None = None
    metrics: dict[str, Any] | None = None
    message: str | None = None


class EventIn(AssetRef):
    kind: str = Field("SYSLOG", description="SYSLOG, TRAP, CONFIG_CHANGE")
    occurred_at: datetime | None = None
    metric: str | None = None
    value: str | None = None
    severity: str | None = None
    message: str | None = None
    change_ref: str | None = None


class DiscoveredDevice(BaseModel):
    ip: str | None = None
    mac: str | None = None
    serial: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    type: str | None = None


class DiscoveryIn(BaseModel):
    branch_code: str
    run_at: datetime | None = None
    devices: list[DiscoveredDevice]


class AssetIn(BaseModel):
    branch_code: str
    asset_type: str
    serial_number: str
    model_id: int | None = None
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    criticality: str | None = None
    purchase_cost: float | None = None
    warranty_end: date | None = None
    finance_asset_ref: str | None = None
    initial_status: str = "IN_STOCK"


def asset_json(a: Asset) -> dict:
    return {
        "asset_number": a.asset_number, "serial_number": a.serial_number, "type": a.asset_type,
        "model": a.model.display if a.model else None, "status": a.status, "criticality": a.criticality,
        "branch_code": a.branch.code, "branch": a.branch.name, "region": a.branch.region.code,
        "location": a.location.label if a.location else None, "hostname": a.hostname, "ip_address": a.ip_address,
        "mac_address": a.mac_address, "oper_state": a.oper_state, "monitored": a.monitored,
        "last_seen_at": a.last_seen_at, "install_date": a.install_date, "warranty_end": a.effective_warranty_end,
        "eol_date": a.eol_date, "eos_date": a.eos_date, "custodian": a.custodian.full_name if a.custodian else None,
        "finance_asset_ref": a.finance_asset_ref, "pci_scope": a.pci_scope,
    }


def alert_json(a: Alert) -> dict:
    return {"id": a.id, "ticket_ref": a.ticket_ref, "severity": a.severity, "category": a.category, "source": a.source,
            "title": a.title, "status": a.status, "branch_code": a.branch.code if a.branch else None,
            "asset_number": a.asset.asset_number if a.asset else None, "occurred_at": a.occurred_at,
            "detected_at": a.detected_at, "acknowledged_at": a.acknowledged_at, "resolved_at": a.resolved_at,
            "escalation_level": a.escalation_level}


# --- collector endpoints -------------------------------------------------------------------------


@router.post("/collector/heartbeat", tags=["collector"])
def collector_heartbeat(db: DB, collector: CollectorAuth):
    mon_svc.heartbeat(db, collector)
    return {"ok": True, "collector": collector.name}


@router.post("/collector/poll", tags=["collector"])
def collector_poll(db: DB, collector: CollectorAuth, results: list[PollResult] = Body(...)):
    return mon_svc.ingest_poll_results(db, collector, [r.model_dump() for r in results])


@router.post("/collector/events", tags=["collector"])
def collector_events(db: DB, collector: CollectorAuth, events: list[EventIn] = Body(...)):
    return mon_svc.ingest_events(db, collector, [e.model_dump() for e in events])


@router.post("/collector/discovery", tags=["collector"])
def collector_discovery(db: DB, collector: CollectorAuth, payload: DiscoveryIn):
    branch = db.execute(select(Branch).where(Branch.code == payload.branch_code)).scalar_one_or_none()
    if branch is None:
        raise NotFound(f"Unknown branch {payload.branch_code}")
    if collector.region_id and branch.region_id != collector.region_id:
        raise PermissionDenied("Branch is outside this collector's region")
    run = disc_svc.ingest_discovery(db, collector, payload.branch_code,
                                    [d.model_dump() for d in payload.devices], payload.run_at)
    return {"branch": payload.branch_code, "seen": run.devices_seen, "matched": run.matched, "rogue": run.rogue,
            "not_seen": run.not_seen, "mismatched": run.mismatched}


# --- read / act API for signed-in users ------------------------------------------------------------


@router.get("/assets", tags=["assets"])
def list_assets(db: DB, user: ApiUser, branch: str | None = None, status: str | None = None,
                type: str | None = None, limit: int = Query(500, le=5000), offset: int = 0):
    q = scope_assets(user, select(Asset))
    if branch:
        q = q.where(Asset.branch.has(Branch.code == branch))
    if status:
        q = q.where(Asset.status == status)
    if type:
        q = q.where(Asset.asset_type == type)
    rows = db.execute(q.order_by(Asset.asset_number).offset(offset).limit(limit)).scalars().all()
    return [asset_json(a) for a in rows]


@router.get("/assets/{asset_number}", tags=["assets"])
def get_asset(db: DB, user: ApiUser, asset_number: str):
    a = db.execute(select(Asset).where(Asset.asset_number == asset_number.upper())).scalar_one_or_none()
    if a is None or not can_see_branch(user, a.branch):
        raise NotFound("Asset not found")
    data = asset_json(a)
    data["history"] = [{"at": h.at, "event": h.event, "from": h.from_status, "to": h.to_status, "detail": h.detail}
                       for h in a.history[:50]]
    return data


@router.post("/assets", tags=["assets"], dependencies=[Depends(csrf_protect)], status_code=201)
def create_asset(db: DB, user: ApiUser, payload: AssetIn):
    from itam.enums import AssetStatus

    branch = db.execute(select(Branch).where(Branch.code == payload.branch_code)).scalar_one_or_none()
    if branch is None:
        raise NotFound("Unknown branch")
    a = register_asset(db, user, branch=branch, asset_type=payload.asset_type, serial_number=payload.serial_number,
                       model_id=payload.model_id, initial_status=AssetStatus(payload.initial_status),
                       hostname=payload.hostname, ip_address=payload.ip_address,
                       mac_address=payload.mac_address.lower() if payload.mac_address else None,
                       criticality=payload.criticality, purchase_cost=payload.purchase_cost,
                       warranty_end=payload.warranty_end, finance_asset_ref=payload.finance_asset_ref)
    return asset_json(a)


@router.get("/branches", tags=["branches"])
def list_branches(db: DB, user: ApiUser):
    rows = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    states = dash_svc.branch_states(db, rows)
    return [{"code": b.code, "name": b.name, "region": b.region.code, "city": b.city, "latitude": b.latitude,
             "longitude": b.longitude, "state": states.get(b.id), "wave": b.wave, "rollout_stage": b.rollout_stage}
            for b in rows]


@router.get("/alerts", tags=["monitoring"])
def list_alerts(db: DB, user: ApiUser, status: str = "active", severity: str | None = None):
    statuses = ["OPEN", "ACKNOWLEDGED"] if status == "active" else [status.upper()]
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(Alert).where(Alert.status.in_(statuses),
                            (Alert.branch_id.in_(branch_ids)) | Alert.branch_id.is_(None))
    if severity:
        q = q.where(Alert.severity == severity)
    return [alert_json(a) for a in db.execute(q.order_by(Alert.severity, Alert.detected_at.desc()).limit(1000)).scalars()]


@router.post("/alerts/{alert_id}/ack", tags=["monitoring"], dependencies=[Depends(csrf_protect)])
def ack_alert(db: DB, user: ApiUser, alert_id: int):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise NotFound("Alert not found")
    return alert_json(mon_svc.acknowledge(db, user, alert))


@router.get("/exceptions", tags=["assurance"])
def list_exceptions(db: DB, user: ApiUser, status: str = "OPEN"):
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    rows = db.execute(select(ControlException).where(
        ControlException.status == status,
        (ControlException.branch_id.in_(branch_ids)) | ControlException.branch_id.is_(None),
    ).order_by(ControlException.created_at)).scalars().all()
    return [{"ref": e.ticket_ref, "type": e.exception_type, "source": e.source, "status": e.status,
             "summary": e.summary, "branch_code": e.branch.code if e.branch else None,
             "asset_number": e.asset.asset_number if e.asset else None, "created_at": e.created_at,
             "resolved_at": e.resolved_at} for e in rows]


@router.get("/dashboard", tags=["reporting"])
def dashboard(db: DB, user: ApiUser):
    s = dash_svc.executive_summary(db, user)
    return {k: s[k] for k in ("branches_total", "branches_monitored", "branches_online", "assets_registered",
                              "healthy_pct", "missing", "rogue", "open_p1", "open_p2", "due_count",
                              "unapproved_changes", "trend", "age_profile")}


@router.get("/kpis", tags=["reporting"])
def kpis(db: DB, user: ApiUser):
    return dash_svc.kpis(db)


@router.post("/integrations/hr/leavers", tags=["integrations"], dependencies=[Depends(csrf_protect)])
def hr_leavers(db: DB, user: ApiUser, identifiers: list[str] = Body(..., embed=True)):
    return int_svc.process_hr_leavers(db, user, identifiers)
