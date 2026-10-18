"""Auto-discovery reconciliation: discovered vs registered (slide 22, daily) and missing detection (slide 18/20)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.config import settings
from itam.enums import (
    INSTALLED_STATUSES,
    NETWORK_TYPES,
    AlertCategory,
    AlertSource,
    AssetStatus,
    ExceptionSource,
    ExceptionStatus,
    ExceptionType,
    NotificationChannel,
    Severity,
)
from itam.models import Asset, Branch, Collector, ControlException, DiscoveryRun, User, utcnow
from itam.notifications import notify_roles
from itam.rbac import Role, can
from itam.services import NotFound, PermissionDenied, ServiceError
from itam.services.assets import add_history, set_status, verify_go_live
from itam.services.catalogue import is_forbidden_device
from itam.services.changes import authorised_change_for
from itam.services.monitoring import (
    auto_resolve,
    collector_healthy_for,
    open_alert,
    parse_ts,
    raise_alert,
)


def _norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    digits = "".join(ch for ch in mac.lower() if ch in "0123456789abcdef")
    if len(digits) != 12:
        return mac.lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


# ---------------------------------------------------------------------------
# Exceptions register
# ---------------------------------------------------------------------------


def open_exception(db: Session, dedup_key: str) -> ControlException | None:
    return db.execute(select(ControlException).where(
        ControlException.dedup_key == dedup_key, ControlException.status == ExceptionStatus.OPEN.value
    )).scalars().first()


def is_allowlisted(db: Session, dedup_key: str) -> bool:
    for exc in db.execute(select(ControlException).where(
        ControlException.dedup_key == dedup_key, ControlException.status == ExceptionStatus.RESOLVED.value
    )).scalars():
        if (exc.observed or {}).get("allowlisted"):
            return True
    return False


def raise_exception(db: Session, *, exception_type: ExceptionType, source: ExceptionSource, dedup_key: str,
                    summary: str, branch: Branch | None = None, asset: Asset | None = None,
                    observed: dict[str, Any] | None = None) -> tuple[ControlException, bool]:
    """Create an exception unless an identical one is already open. Returns (exception, created)."""
    existing = open_exception(db, dedup_key)
    if existing:
        if observed:
            existing.observed = {**(existing.observed or {}), **observed, "last_observed_at": utcnow().isoformat()}
        return existing, False
    exc = ControlException(exception_type=exception_type.value, source=source.value, dedup_key=dedup_key,
                           summary=summary[:255], branch_id=branch.id if branch else (asset.branch_id if asset else None),
                           asset_id=asset.id if asset else None, observed=observed or {},
                           status=ExceptionStatus.OPEN.value, created_at=utcnow())
    db.add(exc)
    db.flush()
    exc.ticket_ref = f"EXC-{exc.id:06d}"
    auditlog.record(db, None, "exception.raise", "exception", exc.ticket_ref, type=exception_type.value,
                    source=source.value, summary=summary)
    return exc, True


def resolve_exception(db: Session, actor: User, exc: ControlException, resolution: str,
                      allowlist: bool = False, linked_asset: Asset | None = None) -> ControlException:
    if not can(actor, "exception.resolve"):
        raise PermissionDenied("You may not resolve exceptions")
    if exc.status != ExceptionStatus.OPEN.value:
        raise ServiceError("Exception already resolved")
    if not resolution or not resolution.strip():
        raise ServiceError("Resolution notes are required")
    if allowlist and exc.exception_type != ExceptionType.ROGUE_DEVICE.value:
        raise ServiceError("Only rogue-device exceptions can be allow-listed")
    if allowlist and not actor.has_role(Role.CISO, Role.IT_ASSET_MANAGER):
        raise PermissionDenied("Allow-listing a non-asset device requires CISO or IT Asset Manager")
    exc.status = ExceptionStatus.RESOLVED.value
    exc.resolution = resolution.strip()
    exc.resolved_at = utcnow()
    exc.resolved_by_id = actor.id
    observed = dict(exc.observed or {})
    if allowlist:
        observed["allowlisted"] = True
    if linked_asset is not None:
        observed["linked_asset"] = linked_asset.asset_number
        exc.asset_id = linked_asset.id
    exc.observed = observed
    if exc.exception_type == ExceptionType.ROGUE_DEVICE.value:
        auto_resolve(db, f"ROGUE:{exc.dedup_key}", f"Exception {exc.ticket_ref} resolved: {resolution}")
    auditlog.record(db, actor, "exception.resolve", "exception", exc.ticket_ref, resolution=resolution,
                    allowlist=allowlist, linked_asset=linked_asset.asset_number if linked_asset else None)
    return exc


def auto_resolve_exception(db: Session, dedup_key: str, resolution: str) -> None:
    exc = open_exception(db, dedup_key)
    if exc:
        exc.status = ExceptionStatus.RESOLVED.value
        exc.resolution = resolution
        exc.resolved_at = utcnow()
        auditlog.record(db, None, "exception.auto_resolve", "exception", exc.ticket_ref, resolution=resolution)


# ---------------------------------------------------------------------------
# Discovery ingestion
# ---------------------------------------------------------------------------


def expected_on_network(db: Session, branch: Branch) -> list[Asset]:
    """Registered devices that discovery should see at the branch."""
    assets = db.execute(select(Asset).where(
        Asset.branch_id == branch.id,
        Asset.asset_type.in_([t.value for t in NETWORK_TYPES]),
        Asset.status.in_([s.value for s in INSTALLED_STATUSES] + [AssetStatus.MISSING.value]),
    )).scalars().all()
    pending = db.execute(select(Asset).where(
        Asset.branch_id == branch.id, Asset.status == AssetStatus.IN_STOCK.value, Asset.install_date.is_not(None),
        Asset.asset_type.in_([t.value for t in NETWORK_TYPES]),
    )).scalars().all()
    return list(assets) + list(pending)


def ingest_discovery(db: Session, collector: Collector | None, branch_code: str, devices: list[dict[str, Any]],
                     run_at: Any = None) -> DiscoveryRun:
    """Reconcile one discovery scan of a branch management network against the register."""
    branch = db.execute(select(Branch).where(Branch.code == branch_code)).scalar_one_or_none()
    if branch is None:
        raise NotFound(f"Unknown branch {branch_code}")
    seen_at = parse_ts(run_at)
    run = DiscoveryRun(collector_id=collector.id if collector else None, branch_id=branch.id, run_at=seen_at,
                       devices_seen=len(devices), matched=0, rogue=0, not_seen=0, mismatched=0)
    expected = expected_on_network(db, branch)
    by_serial = {a.serial_number.lower(): a for a in expected if a.serial_number}
    by_mac = {_norm_mac(a.mac_address): a for a in expected if a.mac_address}
    by_ip = {a.ip_address: a for a in expected if a.ip_address}
    seen_ids: set[int] = set()

    for dev in devices:
        serial = (dev.get("serial") or "").strip()
        mac = _norm_mac(dev.get("mac"))
        ip = (dev.get("ip") or "").strip() or None
        asset = by_serial.get(serial.lower()) if serial else None

        if asset is None and serial:
            # Registered elsewhere? (moved without approval)
            elsewhere = db.execute(select(Asset).where(Asset.serial_number == serial,
                                                       Asset.status != AssetStatus.DISPOSED.value)).scalars().first()
            if elsewhere is not None and elsewhere.branch_id != branch.id:
                elsewhere.last_seen_at = seen_at
                if authorised_change_for(db, elsewhere) is None:
                    raise_exception(
                        db, exception_type=ExceptionType.LOCATION_MISMATCH, source=ExceptionSource.DISCOVERY,
                        dedup_key=f"LOCATION:{elsewhere.id}:{branch.id}", branch=branch, asset=elsewhere,
                        summary=f"{elsewhere.asset_number} registered at {elsewhere.branch.code} but discovered at {branch.code}",
                        observed={"ip": ip, "mac": mac, "serial": serial, "discovered_branch": branch.code},
                    )
                run.mismatched += 1
                continue

        if asset is None:
            candidate = (by_mac.get(mac) if mac else None) or (by_ip.get(ip) if ip else None)
            if candidate is not None and serial and candidate.serial_number.lower() != serial.lower():
                # Same MAC / IP answering with a different serial: device swapped.
                run.mismatched += 1
                key = f"SWAP:{candidate.id}:{serial.lower()}"
                raise_exception(
                    db, exception_type=ExceptionType.IDENTITY_MISMATCH, source=ExceptionSource.DISCOVERY,
                    dedup_key=key, branch=branch, asset=candidate,
                    summary=f"{candidate.asset_number}: serial changed {candidate.serial_number} → {serial}",
                    observed={"ip": ip, "mac": mac, "serial": serial, "hostname": dev.get("hostname")},
                )
                raise_alert(db, dedup_key=f"SWAP:{candidate.id}", severity=Severity.P2,
                            category=AlertCategory.DEVICE_SWAPPED, asset=candidate, source=AlertSource.DISCOVERY,
                            title=f"Device swapped: {candidate.asset_number} at {branch.code} now reports serial {serial}",
                            occurred_at=seen_at)
                continue
            asset = candidate

        if asset is None:
            ident = (serial or mac or ip or "unknown").lower()
            observed = {"ip": ip, "mac": mac, "serial": serial, "hostname": dev.get("hostname"),
                        "vendor": dev.get("vendor"), "model": dev.get("model"), "type": dev.get("type")}
            label = dev.get("hostname") or ip or mac
            if is_forbidden_device(dev):
                # Branch-bought modem / hotspot: outside the approved catalogue, never allow-listed (slides 3, 10).
                run.rogue += 1
                key = f"UNAPPROVED:{branch.id}:{ident}"
                exc, _ = raise_exception(
                    db, exception_type=ExceptionType.UNAPPROVED_DEVICE, source=ExceptionSource.DISCOVERY,
                    dedup_key=key, branch=branch, observed=observed,
                    summary=f"Unapproved {dev.get('type', 'device').lower()} at {branch.code}: {label}",
                )
                raise_alert(db, dedup_key=key, severity=Severity.P2, category=AlertCategory.UNAPPROVED_DEVICE,
                            branch=branch, source=AlertSource.DISCOVERY, occurred_at=seen_at,
                            title=f"Unapproved {dev.get('type', 'device').lower()} on the network at {branch.code}: {label}",
                            detail=f"Exception {exc.ticket_ref}. Not in the approved catalogue or branch blueprint; "
                                   f"cannot be patched or secured. Network access control: quarantine and remove.")
                continue
            key = f"ROGUE:{branch.id}:{ident}"
            if is_allowlisted(db, key):
                continue
            run.rogue += 1
            exc, _ = raise_exception(
                db, exception_type=ExceptionType.ROGUE_DEVICE, source=ExceptionSource.DISCOVERY, dedup_key=key,
                branch=branch, summary=f"Unregistered device at {branch.code}: {dev.get('hostname') or ip or mac}",
                observed={"ip": ip, "mac": mac, "serial": serial, "hostname": dev.get("hostname"),
                          "vendor": dev.get("vendor"), "model": dev.get("model"), "type": dev.get("type")},
            )
            raise_alert(db, dedup_key=f"ROGUE:{key}", severity=Severity.P2, category=AlertCategory.ROGUE_DEVICE,
                        branch=branch, source=AlertSource.DISCOVERY, occurred_at=seen_at,
                        title=f"Rogue device at {branch.code}: {dev.get('hostname') or ip or mac}",
                        detail=f"Exception {exc.ticket_ref}. Network access control should quarantine unknown devices.")
            continue

        # Matched a registered asset.
        run.matched += 1
        seen_ids.add(asset.id)
        asset.last_seen_at = max(asset.last_seen_at or seen_at, seen_at)
        if mac and asset.mac_address and _norm_mac(asset.mac_address) != mac and serial:
            raise_exception(db, exception_type=ExceptionType.IDENTITY_MISMATCH, source=ExceptionSource.DISCOVERY,
                            dedup_key=f"MAC:{asset.id}:{mac}", asset=asset,
                            summary=f"{asset.asset_number}: MAC changed {asset.mac_address} → {mac}",
                            observed={"mac": mac, "ip": ip})
        if not asset.mac_address and mac:
            asset.mac_address = mac
        auto_resolve(db, f"NOTSEEN:{asset.id}", "Device seen again by discovery", seen_at)
        if asset.status == AssetStatus.MISSING.value:
            set_status(db, asset, AssetStatus.ACTIVE, None, "REDISCOVERED",
                       "Seen again by discovery; missing exception remains open for investigation")
        elif asset.status == AssetStatus.IN_STOCK.value and asset.install_date and not asset.go_live_verified_at:
            verify_go_live(db, None, asset, method="auto-discovery")

    # Expected devices not seen in this scan → possible unapproved removal (slide 20: alert within 15 min).
    branch_down = open_alert(db, f"BRANCH_OFFLINE:{branch.id}") is not None
    threshold = seen_at - timedelta(minutes=settings.removal_alert_minutes)
    for asset in expected:
        if (asset.id in seen_ids or asset.status == AssetStatus.MISSING.value or not asset.monitored
                or not asset.go_live_verified_at):
            continue
        run.not_seen += 1
        if branch_down or (asset.last_seen_at and asset.last_seen_at > threshold):
            continue
        if authorised_change_for(db, asset):
            continue
        raise_alert(db, dedup_key=f"NOTSEEN:{asset.id}", severity=Severity.P2,
                    category=AlertCategory.DEVICE_NOT_DISCOVERED, asset=asset, source=AlertSource.DISCOVERY,
                    title=f"Possible unapproved removal: {asset.asset_number} ({asset.hostname or asset.asset_type}) "
                          f"not discovered at {branch.code}",
                    detail="Device lost from discovery with no approved change. NOC, Security and Branch Manager notified.",
                    occurred_at=asset.last_seen_at or seen_at)

    db.add(run)
    if collector:
        collector.last_heartbeat_at = utcnow()
    auditlog.record(db, None, "discovery.run", "branch", branch.code, seen=run.devices_seen, matched=run.matched,
                    rogue=run.rogue, not_seen=run.not_seen, mismatched=run.mismatched,
                    collector=collector.name if collector else None)
    return run


def detect_missing(db: Session, now: datetime | None = None) -> int:
    """Installed devices not seen for > 72 h without an approved change become 'Missing' (slide 18)."""
    now = now or utcnow()
    cutoff = now - timedelta(hours=settings.missing_after_hours)
    candidates = db.execute(select(Asset).where(
        Asset.status.in_([s.value for s in INSTALLED_STATUSES]), Asset.monitored.is_(True),
        Asset.last_seen_at.is_not(None), Asset.last_seen_at < cutoff,
    )).scalars().all()
    flagged = 0
    for asset in candidates:
        if authorised_change_for(db, asset):
            continue
        if not collector_healthy_for(db, asset.branch, now):
            continue  # cannot distinguish a removal from a monitoring outage
        if open_alert(db, f"BRANCH_OFFLINE:{asset.branch_id}"):
            continue
        set_status(db, asset, AssetStatus.MISSING, None, "MISSING",
                   f"Not seen by discovery for > {settings.missing_after_hours} h; no approved change")
        raise_exception(db, exception_type=ExceptionType.MISSING_DEVICE, source=ExceptionSource.DISCOVERY,
                        dedup_key=f"MISSING:{asset.id}", asset=asset,
                        summary=f"{asset.asset_number} missing at {asset.branch.code} (last seen {asset.last_seen_at:%Y-%m-%d %H:%M})",
                        observed={"last_seen_at": asset.last_seen_at.isoformat()})
        raise_alert(db, dedup_key=f"MISSING:{asset.id}", severity=Severity.P2, category=AlertCategory.DEVICE_NOT_DISCOVERED,
                    asset=asset, source=AlertSource.SCHEDULER,
                    title=f"Asset missing: {asset.asset_number} at {asset.branch.code}",
                    detail="Not seen for more than 72 hours and no approved change.", occurred_at=asset.last_seen_at)
        add_history(db, asset, None, "EXCEPTION", "Missing-device exception raised")
        flagged += 1
    return flagged


def weekly_exception_report(db: Session, now: datetime | None = None) -> int:
    """Open exceptions with ageing, sent to regional managers (slide 22, weekly)."""
    now = now or utcnow()
    open_excs = db.execute(select(ControlException).where(ControlException.status == ExceptionStatus.OPEN.value)).scalars().all()
    by_region: dict[int | None, list[ControlException]] = {}
    for exc in open_excs:
        region_id = exc.branch.region_id if exc.branch else None
        by_region.setdefault(region_id, []).append(exc)
    sent = 0
    for items in by_region.values():
        lines = [f"{e.ticket_ref} {e.exception_type} {e.branch.code if e.branch else '-'} "
                 f"age {(now - e.created_at).days} d: {e.summary}" for e in sorted(items, key=lambda e: e.created_at)]
        aged = sum(1 for e in items if (now - e.created_at).days > 30)
        subject = f"Weekly ITAM exception report: {len(items)} open ({aged} older than 30 days)"
        branch = items[0].branch if items[0].branch else None
        notify_roles(db, [Role.REGIONAL_LEAD], subject, "\n".join(lines), [NotificationChannel.EMAIL], branch=branch)
        sent += 1
    notify_roles(db, [Role.IT_ASSET_MANAGER], f"Weekly ITAM exception report: {len(open_excs)} open exceptions",
                 "See the Exceptions page for detail and ageing.", [NotificationChannel.EMAIL])
    return sent
