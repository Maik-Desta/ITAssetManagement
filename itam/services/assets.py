"""Asset register and lifecycle (slides 16, 18, 19)."""

from __future__ import annotations

from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import (
    NETWORK_TYPES,
    STATUS_LABELS,
    AssetStatus,
    AssetType,
    Criticality,
    OperState,
)
from itam.models import Asset, AssetHistory, AssetModel, Branch, Contract, Location, User, utcnow
from itam.numbering import extract_asset_number, next_asset_number
from itam.rbac import Role, acts_for_branch, can
from itam.services import NotFound, PermissionDenied, ServiceError

S = AssetStatus

# Allowed lifecycle transitions. Anything else is rejected.
TRANSITIONS: dict[AssetStatus, set[AssetStatus]] = {
    S.IN_STOCK: {S.IN_TRANSIT, S.ACTIVE, S.UNDER_REPAIR, S.RETIRED, S.MISSING},
    S.IN_TRANSIT: {S.IN_STOCK, S.MISSING},
    S.ACTIVE: {S.FAULTY, S.IN_STOCK, S.IN_TRANSIT, S.UNDER_REPAIR, S.RETIRED, S.MISSING},
    S.FAULTY: {S.ACTIVE, S.IN_STOCK, S.IN_TRANSIT, S.UNDER_REPAIR, S.RETIRED, S.MISSING},
    S.UNDER_REPAIR: {S.IN_STOCK, S.RETIRED, S.MISSING},
    S.MISSING: {S.ACTIVE, S.FAULTY, S.IN_STOCK, S.DISPOSED},
    S.RETIRED: {S.DISPOSED},
    S.DISPOSED: set(),
}

INSTALL_CHECKLIST = {
    "hardened": "Hardened configuration applied",
    "snmpv3": "SNMPv3 enabled",
    "syslog": "Syslog to regional collector",
    "ntp": "NTP time sync",
}

EDITABLE_FIELDS = {
    "hostname", "ip_address", "mac_address", "criticality", "model_id", "contract_id", "purchase_cost",
    "warranty_end", "finance_asset_ref", "pci_scope", "holds_customer_data", "notes", "rack_u",
    "location_id", "serial_number",
}


def get_asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFound("Asset not found")
    return asset


def find_by_number(db: Session, value: str) -> Asset | None:
    number = extract_asset_number(value)
    return db.execute(select(Asset).where(Asset.asset_number == number)).scalar_one_or_none()


def add_history(db: Session, asset: Asset, actor: User | None, event: str, detail: str | None = None,
                from_status: str | None = None, to_status: str | None = None) -> None:
    db.add(AssetHistory(asset_id=asset.id, actor_id=actor.id if actor else None, event=event, detail=detail,
                        from_status=from_status, to_status=to_status, at=utcnow()))


def set_status(db: Session, asset: Asset, new_status: AssetStatus, actor: User | None, event: str,
               detail: str | None = None) -> None:
    current = AssetStatus(asset.status)
    if new_status == current:
        return
    if new_status not in TRANSITIONS[current]:
        raise ServiceError(f"Status change {STATUS_LABELS[current]} → {STATUS_LABELS[new_status]} is not allowed")
    asset.status = new_status.value
    if new_status in (S.IN_TRANSIT, S.UNDER_REPAIR, S.RETIRED, S.DISPOSED):
        asset.monitored = False
    add_history(db, asset, actor, event, detail, current.value, new_status.value)
    auditlog.record(db, actor, "asset.status", "asset", asset.asset_number,
                    from_status=current.value, to_status=new_status.value, event=event, detail=detail)


def _check_duplicate_serial(db: Session, serial: str, exclude_id: int | None = None) -> None:
    q = select(Asset).where(Asset.serial_number == serial, Asset.status != S.DISPOSED.value)
    if exclude_id:
        q = q.where(Asset.id != exclude_id)
    existing = db.execute(q).scalars().first()
    if existing:
        raise ServiceError(f"Serial {serial} is already registered as {existing.asset_number}", 409)


def register_asset(db: Session, actor: User, *, branch: Branch, asset_type: str, serial_number: str,
                   model_id: int | None = None, number_branch: Branch | None = None,
                   initial_status: AssetStatus = S.IN_STOCK, tag_applied: bool = True,
                   request_id: int | None = None, **fields: Any) -> Asset:
    """Create a record and issue its asset number (slide 19, steps 3-4).

    ``number_branch`` is the branch encoded in the number (the destination branch); it defaults to
    ``branch``. ``initial_status`` may be ACTIVE only for baseline onboarding of equipment already
    in service (branch-day physical count).
    """
    if not can(actor, "asset.register"):
        raise PermissionDenied("Only the ITAM Office can register assets")
    serial_number = (serial_number or "").strip()
    if not serial_number:
        raise ServiceError("Serial number is required")
    if asset_type not in AssetType._value2member_map_:
        raise ServiceError("Unknown asset type")
    if initial_status not in (S.IN_STOCK, S.ACTIVE):
        raise ServiceError("New assets start 'In stock' (or 'Installed – active' for baseline onboarding)")
    if model_id:
        model = db.get(AssetModel, model_id)
        if model is None or model.asset_type != asset_type:
            raise ServiceError("Model does not match the asset type")
    _check_duplicate_serial(db, serial_number)
    criticality = fields.pop("criticality", None) or default_criticality(asset_type)
    if criticality not in Criticality._value2member_map_:
        raise ServiceError("Unknown criticality")
    location_id = fields.get("location_id")
    if location_id:
        loc = db.get(Location, location_id)
        if loc is None or loc.branch_id != branch.id:
            raise ServiceError("Location does not belong to the branch")
    unknown = set(fields) - EDITABLE_FIELDS - {"install_date", "received_date", "custodian_id"}
    if unknown:
        raise ServiceError(f"Unknown fields: {', '.join(sorted(unknown))}")

    number = next_asset_number(db, number_branch or branch, asset_type)
    now = utcnow()
    asset = Asset(
        asset_number=number, serial_number=serial_number, asset_type=asset_type, model_id=model_id,
        branch_id=branch.id, status=initial_status.value, criticality=criticality, request_id=request_id,
        received_date=fields.pop("received_date", None) or date.today(),
        tag_applied_at=now if tag_applied else None, oper_state=OperState.UNKNOWN.value,
        install_checklist={}, last_metrics={}, created_at=now, updated_at=now, **fields,
    )
    if initial_status == S.ACTIVE:
        asset.install_date = asset.install_date or date.today()
        asset.go_live_verified_at = now
        asset.monitored = asset_type in NETWORK_TYPES
    db.add(asset)
    db.flush()
    add_history(db, asset, actor, "REGISTERED", f"Registered at {branch.code} {branch.name}", None, asset.status)
    auditlog.record(db, actor, "asset.register", "asset", number, serial=serial_number, type=asset_type,
                    branch=branch.code, status=asset.status)
    return asset


def default_criticality(asset_type: str) -> str:
    if asset_type in (AssetType.RTR, AssetType.FWL):
        return Criticality.CRITICAL.value
    if asset_type in (AssetType.SRV, AssetType.SWT, AssetType.ATM, AssetType.STO):
        return Criticality.HIGH.value
    if asset_type == AssetType.UPS:
        return Criticality.MEDIUM.value
    return Criticality.LOW.value


def update_asset(db: Session, actor: User, asset: Asset, changes: dict[str, Any]) -> Asset:
    if not can(actor, "asset.edit"):
        raise PermissionDenied("You may not edit asset records")
    if asset.status == S.DISPOSED:
        raise ServiceError("Disposed assets are read-only")
    unknown = set(changes) - EDITABLE_FIELDS
    if unknown:
        raise ServiceError(f"Fields cannot be edited directly: {', '.join(sorted(unknown))}")
    if "serial_number" in changes and changes["serial_number"] != asset.serial_number:
        _check_duplicate_serial(db, changes["serial_number"], asset.id)
    if "criticality" in changes and changes["criticality"] not in Criticality._value2member_map_:
        raise ServiceError("Unknown criticality")
    if changes.get("location_id"):
        loc = db.get(Location, changes["location_id"])
        if loc is None or loc.branch_id != asset.branch_id:
            raise ServiceError("Location does not belong to the asset's branch — use a move request")
    if changes.get("model_id"):
        model = db.get(AssetModel, changes["model_id"])
        if model is None or model.asset_type != asset.asset_type:
            raise ServiceError("Model does not match the asset type")
    if changes.get("contract_id") and db.get(Contract, changes["contract_id"]) is None:
        raise ServiceError("Unknown contract")
    diff: dict[str, Any] = {}
    for key, value in changes.items():
        old = getattr(asset, key)
        if old != value:
            diff[key] = {"from": old, "to": value}
            setattr(asset, key, value)
    if diff:
        add_history(db, asset, actor, "UPDATED", ", ".join(sorted(diff)))
        auditlog.record(db, actor, "asset.update", "asset", asset.asset_number, changes=diff)
    return asset


def install_asset(db: Session, actor: User, asset: Asset, *, location_id: int, ip_address: str | None,
                  hostname: str | None = None, mac_address: str | None = None, rack_u: str | None = None,
                  checklist: dict[str, bool] | None = None) -> Asset:
    """Install & configure (slide 19, step 6). Go-live follows once discovery confirms the device."""
    if not can(actor, "asset.install") or not (
        acts_for_branch(actor, Role.REGIONAL_IT, asset.branch) or acts_for_branch(actor, Role.REGIONAL_LEAD, asset.branch)
        or actor.has_role(Role.IT_ASSET_MANAGER)
    ):
        raise PermissionDenied("Only regional IT for this branch can install equipment")
    if asset.status != S.IN_STOCK:
        raise ServiceError("Only equipment that is in stock at the branch can be installed")
    loc = db.get(Location, location_id) if location_id else None
    if loc is None or loc.branch_id != asset.branch_id:
        raise ServiceError("Choose a location at the asset's branch")
    checklist = checklist or {}
    if asset.asset_type in NETWORK_TYPES:
        missing = [label for key, label in INSTALL_CHECKLIST.items() if not checklist.get(key)]
        if missing:
            raise ServiceError("Install checklist incomplete: " + "; ".join(missing))
        if not ip_address:
            raise ServiceError("Management IP address is required for network-managed devices")
    asset.location_id = loc.id
    asset.ip_address = ip_address or asset.ip_address
    asset.hostname = hostname or asset.hostname
    asset.mac_address = (mac_address or asset.mac_address or None)
    asset.rack_u = rack_u or asset.rack_u
    asset.install_checklist = {k: bool(checklist.get(k)) for k in INSTALL_CHECKLIST}
    asset.install_date = date.today()
    asset.go_live_verified_at = None
    asset.monitored = asset.asset_type in NETWORK_TYPES
    add_history(db, asset, actor, "INSTALLED", f"Installed at {loc.label}; awaiting discovery verification")
    auditlog.record(db, actor, "asset.install", "asset", asset.asset_number, location=loc.label,
                    ip=asset.ip_address, checklist=asset.install_checklist)
    if asset.asset_type not in NETWORK_TYPES:
        # Not network-visible: go live on installation.
        verify_go_live(db, actor, asset, method="manual (not network-managed)")
    return asset


def verify_go_live(db: Session, actor: User | None, asset: Asset, method: str = "discovery") -> Asset:
    """Verify & go live (slide 19, step 7): discovery confirms device → 'Installed – active'."""
    if actor is not None and not (can(actor, "asset.verify") or can(actor, "asset.install")):
        raise PermissionDenied("Only NOC / ITAM can verify go-live")
    if asset.status != S.IN_STOCK or not asset.install_date:
        raise ServiceError("Asset must be installed before go-live verification")
    asset.go_live_verified_at = utcnow()
    asset.monitored = asset.asset_type in NETWORK_TYPES
    if asset.oper_state == OperState.UNKNOWN.value:
        asset.oper_state = OperState.UP.value
        asset.oper_state_since = utcnow()
    set_status(db, asset, S.ACTIVE, actor, "GO_LIVE", f"Go-live verified ({method})")
    return asset


def accept_custody(db: Session, actor: User, asset: Asset) -> Asset:
    """Branch manager accepts custody in the system (slide 19, step 8)."""
    if not acts_for_branch(actor, Role.BRANCH_MANAGER, asset.branch):
        raise PermissionDenied("Only the branch manager of this branch can accept custody")
    if asset.status not in (S.ACTIVE, S.FAULTY, S.IN_STOCK):
        raise ServiceError("Custody can only be accepted for assets at the branch")
    asset.custodian_id = actor.id
    asset.custody_accepted_by_id = actor.id
    asset.custody_accepted_at = utcnow()
    add_history(db, asset, actor, "CUSTODY_ACCEPTED", f"Custody accepted by {actor.full_name}")
    auditlog.record(db, actor, "asset.custody_accept", "asset", asset.asset_number)
    return asset


def mark_tag_applied(db: Session, actor: User, asset: Asset) -> Asset:
    if not (can(actor, "asset.install") or can(actor, "asset.register")):
        raise PermissionDenied("Not permitted")
    asset.tag_applied_at = utcnow()
    add_history(db, asset, actor, "TAG_APPLIED", "Tamper-evident QR tag applied / verified")
    auditlog.record(db, actor, "asset.tag", "asset", asset.asset_number)
    return asset
