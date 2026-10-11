"""Discovery reconciliation, missing detection, physical audits, Finance reconciliation, HR feed (slide 22)."""

from datetime import timedelta

import pytest

from itam.enums import AlertCategory, AlertStatus, AssetStatus, ChangeType, ExceptionType
from itam.models import Alert, ControlException, utcnow
from itam.services import PermissionDenied
from itam.services import audits as audit_svc
from itam.services import changes as chg
from itam.services import discovery as disc
from itam.services import integrations as integ


def _excs(db, t):
    return db.query(ControlException).filter(ControlException.exception_type == t.value,
                                             ControlException.status == "OPEN").all()


def _devices(assets):
    return [{"serial": a.serial_number, "mac": a.mac_address, "ip": a.ip_address} for a in assets]


def test_rogue_device_and_allowlist(db, world):
    a = world.active_asset(world.b1, "RTR")
    rogue = {"ip": "10.0.12.200", "mac": "de:ad:be:ef:00:01", "hostname": "rpi"}
    run = disc.ingest_discovery(db, world.collector, "0012", _devices([a]) + [rogue])
    assert run.matched == 1 and run.rogue == 1
    [exc] = _excs(db, ExceptionType.ROGUE_DEVICE)
    assert db.query(Alert).filter(Alert.category == AlertCategory.ROGUE_DEVICE.value).count() == 1
    # repeated scans do not duplicate
    disc.ingest_discovery(db, world.collector, "0012", _devices([a]) + [rogue])
    assert len(_excs(db, ExceptionType.ROGUE_DEVICE)) == 1
    with pytest.raises(PermissionDenied):
        disc.resolve_exception(db, world.u("lead"), exc, "printer", allowlist=True)
    disc.resolve_exception(db, world.u("ciso"), exc, "Branch label printer", allowlist=True)
    disc.ingest_discovery(db, world.collector, "0012", _devices([a]) + [rogue])
    assert not _excs(db, ExceptionType.ROGUE_DEVICE)


def test_device_swap_detected(db, world):
    a = world.active_asset(world.b1, "SWT")
    disc.ingest_discovery(db, world.collector, "0012", [{"serial": "OTHER-SERIAL", "mac": a.mac_address, "ip": a.ip_address}])
    assert _excs(db, ExceptionType.IDENTITY_MISMATCH)
    assert db.query(Alert).filter(Alert.category == AlertCategory.DEVICE_SWAPPED.value).count() == 1


def test_device_found_at_wrong_branch(db, world):
    a = world.active_asset(world.b1, "EUD")
    disc.ingest_discovery(db, world.collector, "0013", [{"serial": a.serial_number, "ip": "10.0.13.50"}])
    [exc] = _excs(db, ExceptionType.LOCATION_MISMATCH)
    assert exc.asset_id == a.id


def test_unapproved_removal_alert_unless_change_approved(db, world):
    a = world.active_asset(world.b1, "SWT")
    b = world.active_asset(world.b1, "SWT")
    a.last_seen_at = b.last_seen_at = utcnow() - timedelta(minutes=30)
    # b has an approved repair change → authorised to disappear
    c = chg.create_change(db, world.u("eng"), b, ChangeType.SEND_REPAIR, "PSU")
    chg.decide(db, world.u("lead"), c, True)
    chg.decide(db, world.u("itam"), c, True)
    disc.ingest_discovery(db, world.collector, "0012", [])
    alerts = db.query(Alert).filter(Alert.category == AlertCategory.DEVICE_NOT_DISCOVERED.value).all()
    assert [al.asset_id for al in alerts] == [a.id]
    # NOC, CISO and branch manager are told
    from itam.models import Notification

    recipients = {n.recipient_user_id for n in db.query(Notification).filter(Notification.alert_id == alerts[0].id)}
    assert {world.u("noc").id, world.u("ciso").id, world.u("bm1").id} <= recipients
    # reappears → alert resolves
    disc.ingest_discovery(db, world.collector, "0012", _devices([a]))
    assert alerts[0].status == AlertStatus.RESOLVED.value


def test_missing_after_72_hours(db, world):
    a = world.active_asset(world.b1, "SWT")
    a.last_seen_at = utcnow() - timedelta(hours=73)
    assert disc.detect_missing(db) == 1
    assert a.status == AssetStatus.MISSING.value
    assert _excs(db, ExceptionType.MISSING_DEVICE)
    # rediscovered → back to active, exception stays open for investigation
    disc.ingest_discovery(db, world.collector, "0012", _devices([a]))
    assert a.status == AssetStatus.ACTIVE.value
    assert _excs(db, ExceptionType.MISSING_DEVICE)


def test_missing_not_raised_when_collector_silent(db, world):
    a = world.active_asset(world.b1, "SWT")
    a.last_seen_at = utcnow() - timedelta(hours=80)
    world.collector.last_heartbeat_at = utcnow() - timedelta(hours=2)
    assert disc.detect_missing(db) == 0
    assert a.status == AssetStatus.ACTIVE.value


def test_physical_audit_accuracy_and_exceptions(db, world):
    assets = [world.active_asset(world.b1, "EUD") for _ in range(4)]
    stranger = world.active_asset(world.b2, "EUD")
    audit = audit_svc.schedule_audit(db, world.u("itam"), world.b1, utcnow().date())
    with pytest.raises(PermissionDenied):
        audit_svc.start_audit(db, world.u("eng_msa"), audit)
    audit_svc.start_audit(db, world.u("eng"), audit)
    assert audit.expected_count == 4
    for a in assets[:3]:
        audit_svc.scan(db, world.u("eng"), audit, f"https://x/scan/{a.asset_number}")
    audit_svc.scan(db, world.u("eng"), audit, assets[0].asset_number)  # duplicate scan is idempotent
    audit_svc.scan(db, world.u("eng"), audit, stranger.asset_number)
    audit_svc.complete_audit(db, world.u("eng"), audit)
    assert (audit.found_count, audit.missing_count, audit.unexpected_count) == (3, 1, 1)
    assert audit.accuracy == 60.0  # 3 matched of 5 records checked
    assert _excs(db, ExceptionType.MISSING_DEVICE)[0].asset_id == assets[3].id
    assert _excs(db, ExceptionType.UNEXPECTED_ITEM)


def test_quarterly_cycle_covers_quarter_of_branches(db, world):
    created = audit_svc.schedule_quarterly_cycle(db, world.u("itam"))
    assert len(created) == 1  # ceil(4 branches * 25%)
    second = audit_svc.schedule_quarterly_cycle(db, world.u("itam"))
    assert {a.branch_id for a in created}.isdisjoint({a.branch_id for a in second})


def test_finance_reconciliation(db, world):
    a = world.active_asset(world.b1, "RTR", finance_asset_ref="FA-1", purchase_cost=4800)
    b = world.active_asset(world.b1, "SWT", purchase_cost=2500)  # no FA ref, matched by serial
    world.active_asset(world.b1, "SRV", purchase_cost=9000)  # IT only
    csv_text = ("finance_asset_ref,asset_number,serial_number,description,cost,branch_code,status\n"
                f"FA-1,,,{a.serial_number},4800,0012,ACTIVE\n"
                f"FA-2,,{b.serial_number},switch,9999,0012,ACTIVE\n"
                "FA-3,,,ghost laptop,1200,0012,ACTIVE\n")
    run = integ.reconcile_finance(db, world.u("finance"), csv_text, "fa.csv")
    assert (run.matched, run.mismatched, run.finance_only, run.it_only) == (1, 1, 1, 1)
    assert b.finance_asset_ref == "FA-2"
    # fix the cost and re-run: the mismatch clears automatically
    fixed = csv_text.replace("9999", "2500")
    run2 = integ.reconcile_finance(db, world.u("finance"), fixed, "fa2.csv")
    assert run2.mismatched == 0
    assert not _excs(db, ExceptionType.FINANCE_MISMATCH)


def test_hr_leaver_feed(db, world):
    a = world.active_asset(world.b1, "EUD")
    from itam.services.assets import accept_custody

    accept_custody(db, world.u("bm1"), a)
    result = integ.process_hr_leavers(db, world.u("admin"), ["bm1@bank.test"])
    assert result == {"deactivated": 1, "exceptions": 1}
    assert not world.u("bm1").is_active


def test_control_tests_pass_on_clean_data(db, world):
    results = {t["name"]: t for t in audit_svc.control_tests(db)}
    assert results["Audit trail integrity"]["passed"]
    assert results["Maker-checker"]["passed"]
