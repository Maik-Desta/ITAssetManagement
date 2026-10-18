"""Standard branch blueprint and approved equipment catalogue (slides 3, 9, 26, 40, 68).

Branches may only hold equipment from the approved catalogue, in the quantities of the standard blueprint.
Requests outside the blueprint need a Design Authority approval; devices outside the catalogue that appear
on a branch network (e.g. a branch-bought modem) are unapproved devices.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam.enums import (
    BRANCH_BLUEPRINT,
    FORBIDDEN_DEVICE_TYPES,
    OPEN_CHANGE_STATUSES,
    AssetStatus,
    AssetType,
    ChangeType,
    ExceptionStatus,
    ExceptionType,
    RequestStatus,
)
from itam.models import Asset, AssetModel, Branch, ChangeRequest, ControlException, EquipmentRequest

# Assets that count against a branch's blueprint (still at, or on their way to, the branch).
HELD_STATUSES = [s.value for s in (AssetStatus.IN_STOCK, AssetStatus.IN_TRANSIT, AssetStatus.ACTIVE,
                                   AssetStatus.FAULTY, AssetStatus.UNDER_REPAIR, AssetStatus.MISSING)]
OPEN_REQUEST_STATUSES = [s.value for s in (RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED,
                                           RequestStatus.ORDERED)]


def approved_models(db: Session, asset_type: str | None = None) -> list[AssetModel]:
    q = select(AssetModel).where(AssetModel.is_standard.is_(True))
    if asset_type:
        q = q.where(AssetModel.asset_type == asset_type)
    return list(db.execute(q.order_by(AssetModel.asset_type, AssetModel.name)).scalars())


def blueprint_for(branch: Branch) -> dict[AssetType, int] | None:
    """The head office / data centre is designed separately; every other branch follows the standard blueprint."""
    return None if branch.is_head_office else BRANCH_BLUEPRINT


def held_count(db: Session, branch: Branch, asset_type: str, *, excluding_due_for_refresh: bool = False) -> int:
    q = select(func.count(Asset.id)).where(
        Asset.branch_id == branch.id, Asset.asset_type == asset_type, Asset.status.in_(HELD_STATUSES))
    if excluding_due_for_refresh:
        # Units being retired, or past end of life, are replaced like for like within the blueprint.
        retiring = select(ChangeRequest.asset_id).where(
            ChangeRequest.change_type.in_([ChangeType.RETIRE.value, ChangeType.DISPOSE.value]),
            ChangeRequest.status.in_([s.value for s in OPEN_CHANGE_STATUSES]))
        past_eol = select(AssetModel.id).where(AssetModel.eol_date.is_not(None), AssetModel.eol_date < date.today())
        q = q.where(Asset.id.not_in(retiring), (Asset.model_id.is_(None)) | Asset.model_id.not_in(past_eol))
    return db.execute(q).scalar_one()


def on_order_count(db: Session, branch: Branch, asset_type: str, exclude_request_id: int | None = None) -> int:
    """Units requested for the branch that have not yet been received into stock."""
    q = select(EquipmentRequest).where(EquipmentRequest.branch_id == branch.id,
                                       EquipmentRequest.asset_type == asset_type,
                                       EquipmentRequest.status.in_(OPEN_REQUEST_STATUSES))
    if exclude_request_id:
        q = q.where(EquipmentRequest.id != exclude_request_id)
    return sum(r.quantity - r.received_quantity for r in db.execute(q).scalars())


def exceeds_blueprint(db: Session, branch: Branch, asset_type: str, quantity: int,
                      exclude_request_id: int | None = None) -> bool:
    """Would ``quantity`` more units take the branch above its blueprint? Like-for-like replacements stay within it."""
    blueprint = blueprint_for(branch)
    if blueprint is None:
        return False
    allowed = blueprint.get(AssetType(asset_type), 0)
    held = held_count(db, branch, asset_type, excluding_due_for_refresh=True)
    return held + on_order_count(db, branch, asset_type, exclude_request_id) + quantity > allowed


def is_forbidden_device(device: dict) -> bool:
    """Device classes the Bank never allows on a branch network, whatever the vendor."""
    kind = (device.get("type") or "").strip().upper().replace(" ", "_").replace("-", "_")
    return kind in FORBIDDEN_DEVICE_TYPES


def branch_compliance(db: Session, branches: list[Branch]) -> list[dict]:
    """Blueprint compliance per branch: required vs held per type, non-catalogue kit and unapproved devices."""
    ids = [b.id for b in branches]
    if not ids:
        return []
    held: dict[tuple[int, str], int] = {}
    for branch_id, asset_type, n in db.execute(
        select(Asset.branch_id, Asset.asset_type, func.count(Asset.id))
        .where(Asset.branch_id.in_(ids), Asset.status.in_(HELD_STATUSES))
        .group_by(Asset.branch_id, Asset.asset_type)
    ):
        held[(branch_id, asset_type)] = n
    non_catalogue: dict[int, int] = dict(db.execute(
        select(Asset.branch_id, func.count(Asset.id))
        .outerjoin(AssetModel, Asset.model_id == AssetModel.id)
        .where(Asset.branch_id.in_(ids), Asset.status.in_(HELD_STATUSES),
               (AssetModel.id.is_(None)) | (AssetModel.is_standard.is_(False)))
        .group_by(Asset.branch_id)
    ).all())
    unapproved: dict[int, int] = dict(db.execute(
        select(ControlException.branch_id, func.count(ControlException.id))
        .where(ControlException.branch_id.in_(ids), ControlException.status == ExceptionStatus.OPEN.value,
               ControlException.exception_type == ExceptionType.UNAPPROVED_DEVICE.value)
        .group_by(ControlException.branch_id)
    ).all())

    rows = []
    for b in branches:
        blueprint = blueprint_for(b)
        if blueprint is None:
            continue
        lines, short, excess = [], 0, 0
        for asset_type, required in blueprint.items():
            have = held.get((b.id, asset_type.value), 0)
            short += max(0, required - have)
            excess += max(0, have - required)
            lines.append({"type": asset_type.value, "required": required, "held": have})
        extra_types = sorted({t for (bid, t) in held if bid == b.id} - {t.value for t in blueprint})
        for t in extra_types:
            excess += held[(b.id, t)]
            lines.append({"type": t, "required": 0, "held": held[(b.id, t)]})
        rows.append({
            "branch": b, "lines": lines, "short": short, "excess": excess,
            "non_catalogue": non_catalogue.get(b.id, 0), "unapproved": unapproved.get(b.id, 0),
            "compliant": excess == 0 and non_catalogue.get(b.id, 0) == 0 and unapproved.get(b.id, 0) == 0,
            "started": any(line["held"] for line in lines),
        })
    return rows
