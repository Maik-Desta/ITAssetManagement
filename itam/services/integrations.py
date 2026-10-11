"""Integrations: Finance fixed-asset register reconciliation and HR leaver feed (slide 14)."""

from __future__ import annotations

import csv
import io
from decimal import Decimal, InvalidOperation

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import AssetStatus, ExceptionSource, ExceptionStatus, ExceptionType, NotificationChannel
from itam.models import Asset, ControlException, FinanceReconciliation, User, utcnow
from itam.notifications import notify_roles
from itam.rbac import Role, can
from itam.services import PermissionDenied, ServiceError
from itam.services.discovery import auto_resolve_exception, raise_exception

FINANCE_COLUMNS = {"finance_asset_ref", "asset_number", "serial_number", "description", "cost", "branch_code", "status"}


def _decimal(value: str | None) -> Decimal | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return Decimal(str(value).replace(",", "").strip())
    except InvalidOperation:
        return None


def reconcile_finance(db: Session, actor: User, csv_text: str, source_name: str = "upload.csv") -> FinanceReconciliation:
    """Reconcile the IT register with the Finance fixed-asset register (annual, slide 22).

    CSV columns: finance_asset_ref (required), asset_number, serial_number, description, cost, branch_code,
    status (ACTIVE / WRITTEN_OFF).
    """
    if not can(actor, "finance.reconcile"):
        raise PermissionDenied("Only Finance or the ITAM Office can run the reconciliation")
    reader = csv.DictReader(io.StringIO(csv_text.lstrip("﻿")))
    headers = {h.strip().lower() for h in (reader.fieldnames or [])}
    if "finance_asset_ref" not in headers:
        raise ServiceError("CSV must contain a finance_asset_ref column")
    rows = [{(k or "").strip().lower(): (v or "").strip() for k, v in row.items()} for row in reader]

    run = FinanceReconciliation(run_by_id=actor.id, source_name=source_name[:160], finance_records=len(rows), run_at=utcnow(),
                               matched=0, mismatched=0, finance_only=0, it_only=0)
    db.add(run)
    db.flush()
    assets = db.execute(select(Asset)).scalars().all()
    by_ref = {a.finance_asset_ref: a for a in assets if a.finance_asset_ref}
    by_number = {a.asset_number: a for a in assets}
    by_serial = {a.serial_number.lower(): a for a in assets if a.status != AssetStatus.DISPOSED.value}
    matched_ids: set[int] = set()
    active_keys: set[str] = set()

    for row in rows:
        ref = row.get("finance_asset_ref")
        if not ref:
            continue
        asset = by_ref.get(ref) or by_number.get(row.get("asset_number", "").upper()) \
            or by_serial.get(row.get("serial_number", "").lower())
        written_off = row.get("status", "").upper() in {"WRITTEN_OFF", "DISPOSED"}
        if asset is None:
            if written_off:
                continue
            key = f"FIN_ONLY:{ref}"
            active_keys.add(key)
            run.finance_only += 1
            raise_exception(db, exception_type=ExceptionType.FINANCE_NOT_IN_IT, source=ExceptionSource.FINANCE_RECON,
                            dedup_key=key, summary=f"Fixed asset {ref} ({row.get('description') or 'n/a'}) not in IT register",
                            observed={**row, "run": run.id})
            continue
        matched_ids.add(asset.id)
        if not asset.finance_asset_ref:
            asset.finance_asset_ref = ref
            auditlog.record(db, actor, "asset.finance_link", "asset", asset.asset_number, finance_ref=ref)
        problems = []
        if row.get("branch_code") and row["branch_code"] != asset.branch.code and asset.status != AssetStatus.IN_TRANSIT.value:
            problems.append(f"branch {row['branch_code']} vs IT {asset.branch.code}")
        cost = _decimal(row.get("cost"))
        if cost is not None and asset.purchase_cost is not None:
            it_cost = Decimal(str(asset.purchase_cost))
            if abs(cost - it_cost) > max(Decimal("1"), it_cost * Decimal("0.01")):
                problems.append(f"cost {cost} vs IT {it_cost}")
        if asset.status == AssetStatus.DISPOSED.value and not written_off:
            problems.append("disposed in IT but still active in the fixed-asset register")
        if written_off and asset.status not in (AssetStatus.DISPOSED.value, AssetStatus.MISSING.value):
            problems.append(f"written off in Finance but '{asset.status}' in IT")
        key = f"FIN_MISMATCH:{asset.id}"
        if problems:
            active_keys.add(key)
            run.mismatched += 1
            raise_exception(db, exception_type=ExceptionType.FINANCE_MISMATCH, source=ExceptionSource.FINANCE_RECON,
                            dedup_key=key, asset=asset, summary=f"{asset.asset_number} / {ref}: " + "; ".join(problems),
                            observed={**row, "run": run.id})
        else:
            run.matched += 1

    for asset in assets:
        if asset.id in matched_ids or asset.status in (AssetStatus.DISPOSED.value,) or not asset.purchase_cost:
            continue
        key = f"IT_ONLY:{asset.id}"
        active_keys.add(key)
        run.it_only += 1
        raise_exception(db, exception_type=ExceptionType.IT_NOT_IN_FINANCE, source=ExceptionSource.FINANCE_RECON,
                        dedup_key=key, asset=asset,
                        summary=f"{asset.asset_number} (cost {asset.purchase_cost}) not in fixed-asset register",
                        observed={"run": run.id})

    # Exceptions from earlier runs that no longer reproduce are cleared.
    for exc in db.execute(select(ControlException).where(
        ControlException.source == ExceptionSource.FINANCE_RECON.value,
        ControlException.status == ExceptionStatus.OPEN.value,
    )).scalars().all():
        if exc.dedup_key not in active_keys:
            auto_resolve_exception(db, exc.dedup_key, f"Cleared by reconciliation run #{run.id}")

    auditlog.record(db, actor, "finance.reconcile", "reconciliation", run.id, source=source_name,
                    records=run.finance_records, matched=run.matched, mismatched=run.mismatched,
                    finance_only=run.finance_only, it_only=run.it_only)
    return run


def finance_register_csv(db: Session) -> str:
    """Export the IT view in the reconciliation format (for Finance)."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["finance_asset_ref", "asset_number", "serial_number", "description", "cost", "branch_code", "status"])
    for a in db.execute(select(Asset).order_by(Asset.asset_number)).scalars():
        writer.writerow([a.finance_asset_ref or "", a.asset_number, a.serial_number,
                         a.model.display if a.model else a.asset_type, a.purchase_cost or "", a.branch.code,
                         "WRITTEN_OFF" if a.status == AssetStatus.DISPOSED.value else "ACTIVE"])
    return out.getvalue()


def process_hr_leavers(db: Session, actor: User | None, identifiers: list[str]) -> dict[str, int]:
    """HR leaver feed: deactivate accounts and raise exceptions for assets in the leaver's custody."""
    if actor is not None and not actor.has_role(Role.ADMIN):
        raise PermissionDenied("Only administrators can process the HR feed")
    wanted = {i.strip().lower() for i in identifiers if i and i.strip()}
    deactivated = exceptions = 0
    for user in db.execute(select(User).where(User.is_active.is_(True))).scalars().all():
        if user.username.lower() not in wanted and (user.email or "").lower() not in wanted:
            continue
        user.is_active = False
        user.left_at = utcnow()
        deactivated += 1
        auditlog.record(db, actor, "user.leaver", "user", user.username)
        held = db.execute(select(Asset).where(Asset.custodian_id == user.id,
                                              Asset.status != AssetStatus.DISPOSED.value)).scalars().all()
        for asset in held:
            raise_exception(db, exception_type=ExceptionType.CUSTODIAN_LEFT, source=ExceptionSource.HR_FEED,
                            dedup_key=f"CUSTODIAN:{asset.id}:{user.id}", asset=asset,
                            summary=f"Custodian {user.full_name} has left; reassign custody of {asset.asset_number}")
            exceptions += 1
        if held:
            notify_roles(db, [Role.IT_ASSET_MANAGER], f"Custodian left: {user.full_name}",
                         f"{len(held)} asset(s) need a new custodian.", [NotificationChannel.EMAIL])
    return {"deactivated": deactivated, "exceptions": exceptions}
