"""Physical audits, attestation, data-quality scoring and Internal Audit control tests (slide 22)."""

from __future__ import annotations

import math
from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import (
    INSTALLED_STATUSES,
    NETWORK_TYPES,
    AssetStatus,
    AuditItemResult,
    AuditMethod,
    AuditStatus,
    ChangeStatus,
    ChangeType,
    ExceptionSource,
    ExceptionStatus,
    ExceptionType,
    NotificationChannel,
)
from itam.models import (
    Asset,
    Attestation,
    AuditItem,
    Branch,
    ChangeRequest,
    ControlException,
    Location,
    PhysicalAudit,
    User,
    utcnow,
)
from itam.notifications import notify_roles
from itam.numbering import extract_asset_number
from itam.rbac import Role, acts_for_branch, can
from itam.services import PermissionDenied, ServiceError
from itam.services.discovery import raise_exception

# Assets expected to be physically present at the branch during an audit.
PHYSICALLY_PRESENT = (AssetStatus.IN_STOCK, AssetStatus.ACTIVE, AssetStatus.FAULTY, AssetStatus.RETIRED)


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------


def last_completed_audit(db: Session, branch: Branch) -> PhysicalAudit | None:
    return db.execute(select(PhysicalAudit).where(
        PhysicalAudit.branch_id == branch.id, PhysicalAudit.status == AuditStatus.COMPLETED.value
    ).order_by(PhysicalAudit.completed_at.desc())).scalars().first()


def schedule_audit(db: Session, actor: User, branch: Branch, scheduled_for: date,
                   method: AuditMethod = AuditMethod.MOBILE_SCAN, auditor: User | None = None) -> PhysicalAudit:
    if not can(actor, "audit.schedule") and not actor.has_role(Role.INTERNAL_AUDIT):
        raise PermissionDenied("Only the ITAM Office or Internal Audit can schedule audits")
    audit = PhysicalAudit(branch_id=branch.id, method=method.value, status=AuditStatus.SCHEDULED.value,
                          scheduled_for=scheduled_for, auditor_id=auditor.id if auditor else None)
    db.add(audit)
    db.flush()
    auditlog.record(db, actor, "audit.schedule", "audit", audit.id, branch=branch.code, method=method.value,
                    date=scheduled_for)
    return audit


def schedule_quarterly_cycle(db: Session, actor: User, start: date | None = None) -> list[PhysicalAudit]:
    """Cyclical physical audit: 25% of branches per quarter, least-recently audited first (all covered yearly)."""
    start = start or date.today()
    branches = db.execute(select(Branch).order_by(Branch.code)).scalars().all()
    if not branches:
        return []
    already = {a.branch_id for a in db.execute(select(PhysicalAudit).where(
        PhysicalAudit.status.in_([AuditStatus.SCHEDULED.value, AuditStatus.IN_PROGRESS.value]))).scalars()}

    def last_done(b: Branch) -> datetime:
        a = last_completed_audit(db, b)
        return a.completed_at if a and a.completed_at else datetime.min

    pool = sorted((b for b in branches if b.id not in already), key=lambda b: (last_done(b), b.code))
    quota = math.ceil(len(branches) * 0.25)
    created = []
    for i, branch in enumerate(pool[:quota]):
        # Spread over the 13 weeks of the quarter.
        when = start + timedelta(days=(i * 91) // max(quota, 1))
        created.append(schedule_audit(db, actor, branch, when, AuditMethod.MOBILE_SCAN))
    return created


# ---------------------------------------------------------------------------
# Conducting an audit (mobile scan)
# ---------------------------------------------------------------------------


def _check_auditor(actor: User, audit: PhysicalAudit) -> None:
    if not can(actor, "audit.conduct"):
        raise PermissionDenied("You may not conduct audits")
    if not (actor.has_role(Role.IT_ASSET_MANAGER, Role.INTERNAL_AUDIT)
            or acts_for_branch(actor, Role.REGIONAL_IT, audit.branch)
            or acts_for_branch(actor, Role.REGIONAL_LEAD, audit.branch)):
        raise PermissionDenied("This branch is outside your region")


def start_audit(db: Session, actor: User, audit: PhysicalAudit) -> PhysicalAudit:
    _check_auditor(actor, audit)
    if audit.status != AuditStatus.SCHEDULED.value:
        raise ServiceError("Audit already started")
    expected = db.execute(select(Asset).where(
        Asset.branch_id == audit.branch_id, Asset.status.in_([s.value for s in PHYSICALLY_PRESENT])
    ).order_by(Asset.asset_number)).scalars().all()
    for asset in expected:
        audit.items.append(AuditItem(asset_id=asset.id))
    audit.status = AuditStatus.IN_PROGRESS.value
    audit.started_at = utcnow()
    audit.auditor_id = actor.id
    audit.expected_count = len(expected)
    db.flush()
    auditlog.record(db, actor, "audit.start", "audit", audit.id, branch=audit.branch.code, expected=len(expected))
    return audit


def scan(db: Session, actor: User, audit: PhysicalAudit, scanned: str, location_id: int | None = None,
         note: str | None = None) -> AuditItem:
    """Record one tag scan. Idempotent for repeated scans of the same tag."""
    _check_auditor(actor, audit)
    if audit.status != AuditStatus.IN_PROGRESS.value:
        raise ServiceError("Audit is not in progress")
    number = extract_asset_number(scanned)
    if not number:
        raise ServiceError("Nothing scanned")
    now = utcnow()
    asset = db.execute(select(Asset).where(Asset.asset_number == number)).scalar_one_or_none()
    item = None
    if asset is not None:
        item = db.execute(select(AuditItem).where(AuditItem.audit_id == audit.id,
                                                  AuditItem.asset_id == asset.id)).scalar_one_or_none()
    if item is None:
        existing = db.execute(select(AuditItem).where(AuditItem.audit_id == audit.id,
                                                      AuditItem.scanned_value == number)).scalars().first()
        if existing:
            return existing
        # Not expected here: unknown tag, or an asset registered elsewhere.
        item = AuditItem(audit_id=audit.id, asset_id=asset.id if asset else None, scanned_value=number,
                         scanned_at=now, result=AuditItemResult.UNEXPECTED.value,
                         note=note or (f"Registered at {asset.branch.code} as {asset.status}" if asset else "Unknown tag"))
        audit.items.append(item)
        db.flush()
        return item
    item.scanned_value = number
    item.scanned_at = now
    item.note = note or item.note
    if location_id and asset.location_id and location_id != asset.location_id:
        loc = db.get(Location, location_id)
        item.result = AuditItemResult.WRONG_LOCATION.value
        item.note = f"Found at {loc.label if loc else location_id}; registered at {asset.location.label}"
    else:
        item.result = AuditItemResult.FOUND.value
    if asset.tag_applied_at is None:
        asset.tag_applied_at = now
    db.flush()
    return item


def complete_audit(db: Session, actor: User, audit: PhysicalAudit, notes: str | None = None) -> PhysicalAudit:
    _check_auditor(actor, audit)
    if audit.status != AuditStatus.IN_PROGRESS.value:
        raise ServiceError("Audit is not in progress")
    branch = audit.branch
    for item in audit.items:
        if item.result is None:
            item.result = AuditItemResult.MISSING.value
    counts = {r: sum(1 for i in audit.items if i.result == r.value) for r in AuditItemResult}
    audit.found_count = counts[AuditItemResult.FOUND]
    audit.missing_count = counts[AuditItemResult.MISSING]
    audit.unexpected_count = counts[AuditItemResult.UNEXPECTED]
    audit.wrong_location_count = counts[AuditItemResult.WRONG_LOCATION]
    # Register accuracy: physical audit matches system record.
    denominator = audit.expected_count + audit.unexpected_count
    audit.accuracy = round(100.0 * audit.found_count / denominator, 2) if denominator else 100.0
    audit.status = AuditStatus.COMPLETED.value
    audit.completed_at = utcnow()
    audit.notes = notes

    for item in audit.items:
        if item.result == AuditItemResult.MISSING.value:
            raise_exception(db, exception_type=ExceptionType.MISSING_DEVICE, source=ExceptionSource.PHYSICAL_AUDIT,
                            dedup_key=f"AUDIT_MISSING:{item.asset_id}", asset=item.asset, branch=branch,
                            summary=f"Physical audit #{audit.id}: {item.asset.asset_number} not found at {branch.code}",
                            observed={"audit_id": audit.id})
        elif item.result == AuditItemResult.UNEXPECTED.value:
            raise_exception(db, exception_type=ExceptionType.UNEXPECTED_ITEM, source=ExceptionSource.PHYSICAL_AUDIT,
                            dedup_key=f"AUDIT_UNEXPECTED:{branch.id}:{item.scanned_value}", asset=item.asset,
                            branch=branch,
                            summary=f"Physical audit #{audit.id}: unexpected tag {item.scanned_value} at {branch.code}",
                            observed={"audit_id": audit.id, "note": item.note})
        elif item.result == AuditItemResult.WRONG_LOCATION.value:
            raise_exception(db, exception_type=ExceptionType.LOCATION_MISMATCH, source=ExceptionSource.PHYSICAL_AUDIT,
                            dedup_key=f"AUDIT_LOCATION:{item.asset_id}", asset=item.asset, branch=branch,
                            summary=f"Physical audit #{audit.id}: {item.asset.asset_number} at wrong location",
                            observed={"audit_id": audit.id, "note": item.note})
    auditlog.record(db, actor, "audit.complete", "audit", audit.id, branch=branch.code, accuracy=audit.accuracy,
                    found=audit.found_count, missing=audit.missing_count, unexpected=audit.unexpected_count)
    if audit.missing_count or audit.unexpected_count:
        notify_roles(db, [Role.IT_ASSET_MANAGER, Role.BRANCH_MANAGER],
                     f"Audit exceptions at {branch.code}: {audit.missing_count} missing, {audit.unexpected_count} unexpected",
                     f"Physical audit #{audit.id} accuracy {audit.accuracy}%.", [NotificationChannel.EMAIL], branch=branch)
    return audit


def attest(db: Session, actor: User, branch: Branch, statement: str, audit: PhysicalAudit | None = None) -> Attestation:
    """Branch manager attests custody of all assets at the branch."""
    if not acts_for_branch(actor, Role.BRANCH_MANAGER, branch):
        raise PermissionDenied("Only the branch manager can attest custody for this branch")
    if not statement or not statement.strip():
        raise ServiceError("Attestation statement is required")
    count = db.execute(select(func.count(Asset.id)).where(
        Asset.branch_id == branch.id, Asset.status.in_([s.value for s in PHYSICALLY_PRESENT])
    )).scalar_one()
    att = Attestation(branch_id=branch.id, user_id=actor.id, audit_id=audit.id if audit else None,
                      attested_at=utcnow(), asset_count=count, statement=statement.strip())
    db.add(att)
    db.flush()
    auditlog.record(db, actor, "branch.attest", "branch", branch.code, assets=count, audit=audit.id if audit else None)
    return att


# ---------------------------------------------------------------------------
# Data quality (monthly score per branch)
# ---------------------------------------------------------------------------


def asset_completeness(asset: Asset) -> tuple[int, int, list[str]]:
    """(filled, required, missing_field_names) for the mandatory fields of the data-quality standard."""
    checks: list[tuple[str, bool]] = [
        ("serial", bool(asset.serial_number)),
        ("model", asset.model_id is not None),
        ("tag", asset.tag_applied_at is not None),
        ("warranty", asset.effective_warranty_end is not None),
        ("finance ref", bool(asset.finance_asset_ref)),
    ]
    if asset.status in [s.value for s in INSTALLED_STATUSES]:
        checks += [
            ("location", asset.location_id is not None),
            ("custodian", asset.custody_accepted_at is not None),
            ("install date", asset.install_date is not None),
        ]
        if asset.asset_type in NETWORK_TYPES:
            checks.append(("IP address", bool(asset.ip_address)))
    missing = [name for name, ok in checks if not ok]
    return len(checks) - len(missing), len(checks), missing


def branch_data_quality(db: Session, branch: Branch) -> dict:
    assets = db.execute(select(Asset).where(Asset.branch_id == branch.id,
                                            Asset.status != AssetStatus.DISPOSED.value)).scalars().all()
    filled = required = 0
    for asset in assets:
        f, r, _ = asset_completeness(asset)
        filled += f
        required += r
    completeness = round(100.0 * filled / required, 1) if required else None
    last = last_completed_audit(db, branch)
    accuracy = last.accuracy if last else None
    if completeness is None:
        score = None
    elif accuracy is None:
        score = completeness
    else:
        score = round(0.6 * completeness + 0.4 * accuracy, 1)
    return {"branch": branch, "assets": len(assets), "completeness": completeness, "accuracy": accuracy,
            "score": score, "last_audit": last}


def league_table(db: Session, branches: list[Branch]) -> list[dict]:
    rows = [branch_data_quality(db, b) for b in branches]
    return sorted(rows, key=lambda r: (r["score"] is None, -(r["score"] or 0), r["branch"].code))


# ---------------------------------------------------------------------------
# Internal Audit control tests (3rd line of defence)
# ---------------------------------------------------------------------------


def control_tests(db: Session) -> list[dict]:
    from itam.auditlog import verify_chain
    from itam.services.changes import evidence_required

    results: list[dict] = []

    def add(name: str, description: str, failures: list[str]):
        results.append({"name": name, "description": description, "passed": not failures,
                        "failures": failures[:50], "count": len(failures)})

    completed = db.execute(select(ChangeRequest).where(ChangeRequest.status.in_(
        [ChangeStatus.APPROVED.value, ChangeStatus.IN_PROGRESS.value, ChangeStatus.COMPLETED.value]))).scalars().all()
    add("Approvals complete", "Every executed change carries all approvals required by the matrix",
        [c.reference for c in completed if any(a.decision != "APPROVED" for a in c.approvals) or not c.approvals])
    add("Maker-checker", "No requester approved their own change; no person approved twice",
        [c.reference for c in completed
         if any(a.approver_id == c.requester_id for a in c.approvals)
         or len({a.approver_id for a in c.approvals}) != len(c.approvals)])
    disposals = [c for c in completed if c.change_type == ChangeType.DISPOSE.value and c.status == ChangeStatus.COMPLETED.value]
    add("Disposal evidence", "Disposals have wipe and disposal certificates on file",
        [c.reference for c in disposals if any(not getattr(c, f) for f in evidence_required(c))])
    cutoff = utcnow() - timedelta(days=30)
    add("Finance write-off", "Disposals confirmed in the fixed-asset register within 30 days",
        [c.reference for c in disposals if not c.finance_confirmed_at and c.completed_at and c.completed_at < cutoff])
    missing = db.execute(select(Asset).where(Asset.status == AssetStatus.MISSING.value)).scalars().all()
    add("Unexplained removals", "Missing assets without an approved change (target 0)", [a.asset_number for a in missing])
    untagged = db.execute(select(Asset.asset_number).where(Asset.tag_applied_at.is_(None),
                                                           Asset.status != AssetStatus.DISPOSED.value)).scalars().all()
    add("Tagging", "Every asset carries a valid tag", list(untagged))
    no_custody = db.execute(select(Asset.asset_number).where(
        Asset.status.in_([s.value for s in INSTALLED_STATUSES]), Asset.custody_accepted_at.is_(None))).scalars().all()
    add("Custody", "Installed assets have custody accepted by the branch manager", list(no_custody))
    aged = db.execute(select(ControlException).where(ControlException.status == ExceptionStatus.OPEN.value,
                                                     ControlException.created_at < cutoff)).scalars().all()
    add("Exception ageing", "No exception open for more than 30 days", [e.ticket_ref for e in aged])
    conflicts = []
    sod_pairs = [(Role.PROCUREMENT, Role.FINANCE), (Role.IT_ASSET_MANAGER, Role.FINANCE),
                 (Role.CIO, Role.CFO), (Role.INTERNAL_AUDIT, Role.IT_ASSET_MANAGER)]
    for u in db.execute(select(User).where(User.is_active.is_(True))).scalars():
        for a, b in sod_pairs:
            if u.has_role(a) and u.has_role(b):
                conflicts.append(f"{u.username}: {a.value} + {b.value}")
    add("Segregation of duties", "No user holds conflicting roles", conflicts)
    ok, checked, bad = verify_chain(db)
    add("Audit trail integrity", f"Hash chain verified over {checked} entries", [] if ok else [f"Broken at entry {bad}"])
    return results
