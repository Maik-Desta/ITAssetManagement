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

from itam.models import Alert, Asset, Branch, Collector, ControlException, EquipmentRequest, Shipment, User
from itam.rbac import can, can_see_branch, scope_assets, scope_branches
from itam.security import hash_api_key
from itam.services import NotFound, PermissionDenied
from itam.services import catalogue as cat_svc
from itam.services import dashboard as dash_svc
from itam.services import discovery as disc_svc
from itam.services import integrations as int_svc
from itam.services import monitoring as mon_svc
from itam.services import requests as req_svc
from itam.services import rfid as rfid_svc
from itam.services import security as sec_svc
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


class RfidReadIn(BaseModel):
    read_point: str = Field(..., description="Read-point code, e.g. HQ-DISPATCH")
    epc: str = Field(..., description="96-bit EPC as 24 hex characters")
    event: str = Field("SEEN", description="SEEN, ARRIVED, LEFT, NOT_SEEN")
    read_at: datetime | None = None
    cycles_missed: int | None = Field(None, description="Cabinet readers: consecutive read cycles without the tag")
    branch_code: str | None = Field(None, description="Handhelds: the branch where the read was taken")
    location_id: int | None = None
    rack_u: str | None = None
    operator: str | None = Field(None, description="Handheld user name")


class ReaderHeartbeatIn(BaseModel):
    read_points: list[str]


class SecurityEventIn(BaseModel):
    branch_code: str
    kind: str = Field(..., description="BADGE, DOOR_OPEN, MOTION, DEVICE_TAMPER")
    occurred_at: datetime | None = None
    door: str | None = None
    badge_id: str | None = None
    authorised: bool | None = Field(None, description="Access control: badge holder authorised for this door")
    device_ref: str | None = None
    camera_ref: str | None = None
    message: str | None = None


class ClipArchivedIn(BaseModel):
    sha256: str
    url: str | None = None
    vms_ref: str | None = None


class ShippingNoticeIn(BaseModel):
    asn_ref: str
    serials: list[str]
    eta: date | None = None


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
        "rfid_epc": a.rfid_epc, "rfid_verified_at": a.rfid_verified_at, "last_rfid_read_at": a.last_rfid_read_at,
        "staged_at": a.staged_at, "suspected_removal_at": a.suspected_removal_at,
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


# --- RFID middleware, security systems and VMS (slides 20, 29, 31-33) ------------------------------


@router.post("/rfid/reads", tags=["rfid"])
def rfid_reads(db: DB, collector: CollectorAuth, reads: list[RfidReadIn] = Body(...)):
    """Filtered, de-duplicated tag events from the RFID middleware. Every read is stored with its outcome."""
    return rfid_svc.ingest_reads(db, collector, [r.model_dump() for r in reads])


@router.post("/rfid/heartbeat", tags=["rfid"])
def rfid_heartbeat(db: DB, collector: CollectorAuth, payload: ReaderHeartbeatIn):
    return {"read_points": rfid_svc.heartbeat(db, collector, payload.read_points)}


@router.post("/security/events", tags=["security"])
def security_events(db: DB, collector: CollectorAuth, events: list[SecurityEventIn] = Body(...)):
    """Badge, door-contact, motion and device-health events; correlated with tickets, badges and change windows."""
    return sec_svc.ingest_events(db, collector, [e.model_dump() for e in events])


@router.post("/security/clips/{clip_id}", tags=["security"])
def security_clip_archived(db: DB, collector: CollectorAuth, clip_id: int, payload: ClipArchivedIn):
    """VMS callback once the clip is exported: the hash is kept as evidence."""
    clip = sec_svc.archive_clip(db, clip_id, sha256=payload.sha256, url=payload.url, vms_ref=payload.vms_ref)
    return {"clip": clip.id, "status": clip.status, "sha256": clip.sha256}


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


@router.post("/requests/{reference}/shipping-notice", tags=["logistics"], dependencies=[Depends(csrf_protect)],
             status_code=201)
def shipping_notice(db: DB, user: ApiUser, reference: str, payload: ShippingNoticeIn):
    """Vendor shipping notice (ASN) with serials, e.g. relayed from the vendor EDI / API by Procurement."""
    req = db.execute(select(EquipmentRequest).where(EquipmentRequest.reference == reference.upper())).scalar_one_or_none()
    if req is None:
        raise NotFound("Request not found")
    asn = req_svc.record_shipping_notice(db, user, req, payload.asn_ref, payload.serials, payload.eta)
    return {"asn_ref": asn.asn_ref, "request": req.reference, "expected": len(asn.serials)}


@router.get("/shipments", tags=["logistics"])
def list_shipments(db: DB, user: ApiUser, status: str | None = None):
    if not can(user, "shipment.view"):
        raise PermissionDenied("Not permitted")
    branch_ids = db.execute(scope_branches(user, select(Branch.id))).scalars().all()
    q = select(Shipment).where(Shipment.to_branch_id.in_(branch_ids) | Shipment.from_branch_id.in_(branch_ids))
    if status:
        q = q.where(Shipment.status == status.upper())
    return [{"reference": s.reference, "status": s.status, "from": s.from_branch.code, "to": s.to_branch.code,
             "seal_number": s.seal_number, "carrier": s.carrier, "eta": s.eta, "dispatched_at": s.dispatched_at,
             "received_at": s.received_at, "variance": s.variance_note,
             "manifest": [{"asset_number": i.asset.asset_number, "epc": i.asset.rfid_epc, "result": i.result}
                          for i in s.items]}
            for s in db.execute(q.order_by(Shipment.id.desc()).limit(500)).scalars()]


@router.get("/blueprint", tags=["reporting"])
def blueprint(db: DB, user: ApiUser):
    if not can(user, "blueprint.view"):
        raise PermissionDenied("Not permitted")
    branches = db.execute(scope_branches(user, select(Branch).order_by(Branch.code))).scalars().all()
    return [{"branch_code": r["branch"].code, "compliant": r["compliant"], "short": r["short"], "excess": r["excess"],
             "non_catalogue": r["non_catalogue"], "unapproved_devices": r["unapproved"], "lines": r["lines"]}
            for r in cat_svc.branch_compliance(db, branches)]
