"""Proposal v5: approved catalogue & blueprint, RFID, staging & logistics, removal detection, operating model."""

from __future__ import annotations

from datetime import timedelta

import pytest

from itam.config import settings
from itam.enums import (
    AlertCategory,
    AlertStatus,
    AssetStatus,
    ChangeType,
    ExceptionType,
    ReadOutcome,
    ShipmentStatus,
)
from itam.models import Alert, AssetModel, ControlException, RfidRead, utcnow
from itam.numbering import decode_epc, encode_epc
from itam.services import PermissionDenied, ServiceError
from itam.services import assets as asset_svc
from itam.services import catalogue as cat_svc
from itam.services import changes as change_svc
from itam.services import discovery as disc_svc
from itam.services import logistics as log_svc
from itam.services import monitoring as mon_svc
from itam.services import requests as req_svc
from itam.services import rfid as rfid_svc
from itam.services import security as sec_svc
from tests.conftest import COLLECTOR_KEY

CHECKLIST = {"hardened": True, "snmpv3": True, "syslog": True, "ntp": True}


def _alerts(db, category):
    return db.query(Alert).filter(Alert.category == category.value).all()


def _exceptions(db, exc_type):
    return db.query(ControlException).filter(ControlException.exception_type == exc_type.value).all()


def _ordered_request(db, world, asset_type="RTR", quantity=1, branch=None):
    branch = branch or world.b1
    req = req_svc.create_request(db, world.u("eng"), branch=branch, asset_type=asset_type, quantity=quantity,
                                 justification="Refresh", model_id=world.models[asset_type].id)
    req_svc.approve(db, world.u("head") if req.outside_blueprint else world.u("itam"), req, "it")
    req_svc.approve(db, world.u("finance"), req, "budget")
    req_svc.record_po(db, world.u("procurement"), req, f"PO-{req.id}", "Dimension Data")
    return req


def _read_points(db, world):
    itam = world.u("itam")
    comms = world.loc["0012"][0]
    return {
        "reg": rfid_svc.create_read_point(db, itam, code="HQ-REG", name="Registration bench", kind="REGISTRATION",
                                          branch=world.hq),
        "dispatch": rfid_svc.create_read_point(db, itam, code="HQ-DISPATCH", name="Dispatch dock", kind="DISPATCH",
                                               branch=world.hq, camera_ref="CAM-HQ-DOCK"),
        "cage": rfid_svc.create_read_point(db, itam, code="HQ-CAGE", name="Secure cage", kind="CAGE", branch=world.hq),
        "receipt": rfid_svc.create_read_point(db, itam, code="NRB-HH-1", name="Handheld NRB 1", kind="BRANCH_RECEIPT",
                                              branch=world.b1),
        "install": rfid_svc.create_read_point(db, itam, code="NRB-HH-2", name="Handheld NRB 2", kind="INSTALL",
                                              branch=world.b1),
        "cabinet": rfid_svc.create_read_point(db, itam, code="0012-CAB", name="Comms cabinet", kind="CABINET",
                                              branch=world.b1, location_id=comms.id, camera_ref="CAM-0012-COMMS"),
        "exit": rfid_svc.create_read_point(db, itam, code="0012-EXIT", name="Staff exit", kind="EXIT_PORTAL",
                                           branch=world.b1, camera_ref="CAM-0012-EXIT"),
        "sweep": rfid_svc.create_read_point(db, itam, code="NRB-HH-3", name="Handheld NRB 3", kind="AUDIT_SWEEP",
                                            branch=world.b1),
    }


# --- RFID tag encoding --------------------------------------------------------------------------


def test_epc_encodes_the_asset_number_and_rejects_foreign_or_corrupt_tags():
    epc = encode_epc("KE-NRB-0012-RTR-00041")
    assert len(epc) == 24 and decode_epc(epc) == "KE-NRB-0012-RTR-00041"
    assert decode_epc(epc[:-1] + ("0" if epc[-1] != "0" else "1")) is None  # checksum
    assert decode_epc("E28011606000020A1B2C3D4E") is None  # someone else's tag
    assert decode_epc("not-a-tag") is None


def test_registration_encodes_rfid_and_handheld_reads_resolve(db, world):
    a = world.active_asset(world.b1)
    assert a.rfid_epc == encode_epc(a.asset_number) and a.rfid_verified_at  # baseline onboarding: verified on site
    assert asset_svc.find_by_number(db, a.rfid_epc) is a
    req = _ordered_request(db, world, "EUD")
    [new] = req_svc.receive(db, world.u("itam"), req, ["SN-NEW-1"])
    assert new.rfid_epc and new.rfid_verified_at is None  # verify read still to come
    with pytest.raises(ServiceError, match="does not match"):
        asset_svc.verify_rfid(db, world.u("itam"), new, a.rfid_epc)
    asset_svc.verify_rfid(db, world.u("itam"), new, new.rfid_epc)
    assert new.rfid_verified_at


# --- Approved catalogue and standard branch blueprint ----------------------------------------------


def test_requests_must_use_the_approved_catalogue(db, world):
    with pytest.raises(ServiceError, match="approved catalogue"):
        req_svc.create_request(db, world.u("eng"), branch=world.b1, asset_type="RTR", quantity=1, justification="x")
    legacy = AssetModel(vendor_id=world.models["RTR"].vendor_id, name="ISR 2901", asset_type="RTR", is_standard=False)
    db.add(legacy)
    db.flush()
    with pytest.raises(ServiceError, match="approved catalogue"):
        req_svc.create_request(db, world.u("eng"), branch=world.b1, asset_type="RTR", quantity=1, justification="x",
                               model_id=legacy.id)


def test_request_above_blueprint_needs_design_authority(db, world):
    req = req_svc.create_request(db, world.u("eng"), branch=world.b1, asset_type="FWL", quantity=1,
                                 justification="Firewall", model_id=world.models["FWL"].id)
    assert not req.outside_blueprint  # blueprint allows one firewall
    extra = req_svc.create_request(db, world.u("eng"), branch=world.b1, asset_type="FWL", quantity=1,
                                   justification="Second firewall", model_id=world.models["FWL"].id)
    assert extra.outside_blueprint  # the first request is already on order
    with pytest.raises(PermissionDenied, match="Design Authority"):
        req_svc.approve(db, world.u("itam"), extra, "it")
    req_svc.approve(db, world.u("head"), extra, "it")
    assert extra.it_approver_id == world.u("head").id


def test_branch_bought_modem_is_an_unapproved_device_and_cannot_be_allowlisted(db, world):
    a = world.active_asset(world.b1)
    disc_svc.ingest_discovery(db, world.collector, "0012", [
        {"serial": a.serial_number, "mac": a.mac_address, "ip": a.ip_address},
        {"ip": "10.0.12.250", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "huawei-4g", "type": "Modem", "vendor": "Huawei"},
    ])
    [exc] = _exceptions(db, ExceptionType.UNAPPROVED_DEVICE)
    assert "modem" in exc.summary.lower()
    [alert] = _alerts(db, AlertCategory.UNAPPROVED_DEVICE)
    assert alert.severity == "P2" and "quarantine" in alert.detail
    with pytest.raises(ServiceError, match="Only rogue-device"):
        disc_svc.resolve_exception(db, world.u("ciso"), exc, "known", allowlist=True)
    rows = {r["branch"].code: r for r in cat_svc.branch_compliance(db, [world.b1])}
    assert rows["0012"]["unapproved"] == 1 and not rows["0012"]["compliant"]


# --- Goods-in against the shipping notice ----------------------------------------------------------


def test_goods_in_variance_against_shipping_notice(db, world):
    req = _ordered_request(db, world, "EUD", quantity=3)
    req_svc.record_shipping_notice(db, world.u("procurement"), req, "ASN-77", ["A1", "A2", "A3"])
    created = req_svc.receive(db, world.u("itam"), req, ["A1", "A2", "ZZ9"])
    assert [a.serial_number for a in created] == ["A1", "A2"]  # ZZ9 is not on the notice: held, not registered
    [exc] = _exceptions(db, ExceptionType.GOODS_RECEIPT_VARIANCE)
    assert exc.observed["not_on_notice"] == ["ZZ9"] and exc.observed["short"] == ["A3"]
    assert req.received_quantity == 2 and req.status == "ORDERED"


# --- Staging, shipment, dispatch and branch receipt ---------------------------------------------------


def _staged_router(db, world, rps):
    req = _ordered_request(db, world, "RTR")
    [rtr] = req_svc.receive(db, world.u("itam"), req, ["RTR-NEW-1"])
    return rtr


def test_order_to_branch_flow_with_rfid_reads(db, world):
    itam, bm1 = world.u("itam"), world.u("bm1")
    rps = _read_points(db, world)
    rtr = _staged_router(db, world, rps)
    with pytest.raises(ServiceError, match="RFID tag not encoded"):
        log_svc.create_shipment(db, itam, to_branch=world.b1, assets=[rtr], seal_number="SEAL-1")
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "HQ-REG", "epc": rtr.rfid_epc}])
    assert rtr.rfid_verified_at
    with pytest.raises(ServiceError, match="burn-in"):
        log_svc.create_shipment(db, itam, to_branch=world.b1, assets=[rtr], seal_number="SEAL-1")
    with pytest.raises(ServiceError, match="Burn-in"):
        asset_svc.record_staging(db, itam, rtr, config_backup_ref="CFG-1", burn_in_hours=8, checklist=CHECKLIST)
    asset_svc.record_staging(db, itam, rtr, config_backup_ref="CFG-1", burn_in_hours=36, checklist=CHECKLIST)
    with pytest.raises(ServiceError, match="not new equipment ordered"):
        log_svc.create_shipment(db, itam, to_branch=world.b2, assets=[rtr], seal_number="SEAL-1")
    ship = log_svc.create_shipment(db, itam, to_branch=world.b1, assets=[rtr], seal_number="SEAL-1",
                                   eta=utcnow() + timedelta(hours=6))
    # Exit-portal read dispatches the shipment automatically.
    out = rfid_svc.ingest_reads(db, world.collector, [{"read_point": "HQ-DISPATCH", "epc": rtr.rfid_epc, "event": "LEFT"}])
    assert out[ReadOutcome.UPDATED.value] == 1
    assert ship.status == ShipmentStatus.IN_TRANSIT.value and rtr.status == AssetStatus.IN_TRANSIT.value
    # Handheld read at the branch, then seal check and sign-off.
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "NRB-HH-1", "epc": rtr.rfid_epc, "branch_code": "0012"}])
    log_svc.receive_shipment(db, bm1, ship, scanned=[], seal_intact=True, seal_number="SEAL-1")
    assert ship.status == ShipmentStatus.DELIVERED.value
    assert rtr.branch_id == world.b1.id and rtr.status == AssetStatus.IN_STOCK.value
    assert log_svc.accept_custody(db, bm1, ship) == 1 and rtr.custodian_id == bm1.id
    # Rack read records the location (logged, never silent).
    comms = world.loc["0012"][0]
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "NRB-HH-2", "epc": rtr.rfid_epc, "branch_code": "0012",
                                                 "location_id": comms.id, "rack_u": "U7"}])
    assert rtr.location_id == comms.id and rtr.rack_u == "U7"
    assert any(h.event == "RFID_LOCATION" for h in rtr.history)
    assert db.query(RfidRead).filter(RfidRead.asset_id == rtr.id).count() == 4


def test_receipt_variance_missing_item_and_broken_seal(db, world):
    itam = world.u("itam")
    req = _ordered_request(db, world, "EUD", quantity=2)
    a1, a2 = req_svc.receive(db, itam, req, ["E1", "E2"])
    for a in (a1, a2):
        asset_svc.verify_rfid(db, itam, a, a.rfid_epc)
    ship = log_svc.create_shipment(db, itam, to_branch=world.b1, assets=[a1, a2], seal_number="S-9")
    log_svc.dispatch(db, itam, ship)
    log_svc.receive_shipment(db, world.u("bm1"), ship, scanned=[a1.rfid_epc], seal_intact=False)
    assert ship.status == ShipmentStatus.VARIANCE.value
    assert a1.status == AssetStatus.IN_STOCK.value and a2.status == AssetStatus.IN_TRANSIT.value
    [exc] = _exceptions(db, ExceptionType.SHIPMENT_VARIANCE)
    assert exc.observed["missing"] == [a2.asset_number] and exc.observed["seal_intact"] is False
    assert _alerts(db, AlertCategory.SHIPMENT_VARIANCE)


def test_transfer_between_branches_ships_under_the_approved_change(db, world):
    eud = world.active_asset(world.hq, "EUD")
    eud.status = AssetStatus.IN_STOCK.value
    with pytest.raises(ServiceError, match="no approved transfer"):
        log_svc.create_shipment(db, world.u("itam"), to_branch=world.b2, assets=[eud], seal_number="S")
    t = change_svc.create_change(db, world.u("eng"), eud, ChangeType.TRANSFER_BRANCH, "Relocation", to_branch=world.b2)
    change_svc.decide(db, world.u("bm_hq"), t, True, "ok")
    change_svc.decide(db, world.u("itam2"), t, True, "ok")
    ship = log_svc.create_shipment(db, world.u("itam"), to_branch=world.b2, assets=[eud], seal_number="S")
    log_svc.dispatch(db, world.u("itam"), ship)
    assert t.status == "IN_PROGRESS" and t.evidence_ref == f"Manifest {ship.reference}"
    log_svc.receive_shipment(db, world.u("bm2"), ship, scanned=[eud.asset_number], seal_intact=True)
    assert t.status == "COMPLETED" and eud.branch_id == world.b2.id


def test_dispatch_portal_without_manifest_is_an_unexplained_exit(db, world):
    _read_points(db, world)
    req = _ordered_request(db, world, "EUD")
    [eud] = req_svc.receive(db, world.u("itam"), req, ["E-X"])
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "HQ-DISPATCH", "epc": eud.rfid_epc, "event": "LEFT"}])
    [alert] = _alerts(db, AlertCategory.UNEXPLAINED_EXIT)
    assert alert.severity == "P1" and eud.suspected_removal_at
    assert alert.clips and alert.clips[0].camera_ref == "CAM-HQ-DOCK"
    assert _exceptions(db, ExceptionType.RFID_MISMATCH)


def test_overdue_delivery_alerts_itam_and_security(db, world):
    itam = world.u("itam")
    req = _ordered_request(db, world, "EUD")
    [eud] = req_svc.receive(db, itam, req, ["E-OD"])
    asset_svc.verify_rfid(db, itam, eud, eud.rfid_epc)
    ship = log_svc.create_shipment(db, itam, to_branch=world.b1, assets=[eud], seal_number="S",
                                   eta=utcnow() - timedelta(hours=3))
    log_svc.dispatch(db, itam, ship)
    assert log_svc.overdue_shipments(db) == 1 and log_svc.overdue_shipments(db) == 0
    [alert] = _alerts(db, AlertCategory.SHIPMENT_OVERDUE)
    log_svc.receive_shipment(db, world.u("bm1"), ship, scanned=[eud.asset_number], seal_intact=True)
    assert alert.status == AlertStatus.RESOLVED.value


# --- Removal detection and physical security -------------------------------------------------------


def test_exit_portal_without_ticket_raises_p1_with_clip_and_5_minute_escalation(db, world):
    _read_points(db, world)
    srv = world.active_asset(world.b1, "SRV")
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0012-EXIT", "epc": srv.rfid_epc, "event": "LEFT"}])
    [alert] = [a for a in _alerts(db, AlertCategory.SUSPECTED_REMOVAL) if a.status == "OPEN"]
    assert alert.severity == "P1" and srv.suspected_removal_at
    assert alert.clips[0].camera_ref == "CAM-0012-EXIT" and alert.clips[0].status == "NOT_CONFIGURED"
    clip = alert.clips[0]
    assert (clip.end_at - clip.start_at) == timedelta(seconds=90)
    mon_svc.escalate_overdue(db, alert.detected_at + timedelta(minutes=6))
    assert alert.escalation_level == 1  # P1 response target is 15 min, but security alarms escalate every 5
    sec_svc.archive_clip(db, clip.id, sha256="ab" * 32, url="https://vms/clip/1")
    assert clip.status == "ARCHIVED"
    mon_svc.resolve(db, world.u("ciso"), alert, "Engineer took it for repair; ticket raised late")
    assert srv.suspected_removal_at is None


def test_exit_portal_with_approved_change_is_logged_only(db, world):
    _read_points(db, world)
    ups = world.active_asset(world.b1, "UPS")
    c = change_svc.create_change(db, world.u("eng"), ups, ChangeType.SEND_REPAIR, "Battery")
    change_svc.decide(db, world.u("lead"), c, True, "ok")
    change_svc.decide(db, world.u("itam"), c, True, "ok")
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0012-EXIT", "epc": ups.rfid_epc}])
    alerts = _alerts(db, AlertCategory.SUSPECTED_REMOVAL)
    assert len(alerts) == 1 and alerts[0].status == "RESOLVED" and alerts[0].severity == "P4"
    assert alerts[0].clips  # evidence clip kept
    assert ups.suspected_removal_at is None


def test_cabinet_reader_alarms_after_missed_cycles_and_clears_when_seen(db, world):
    _read_points(db, world)
    rtr = world.active_asset(world.b1, "RTR")
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0012-CAB", "epc": rtr.rfid_epc, "event": "NOT_SEEN",
                                                 "cycles_missed": 1}])
    assert not _alerts(db, AlertCategory.CABINET_TAG_MISSING)
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0012-CAB", "epc": rtr.rfid_epc, "event": "NOT_SEEN",
                                                 "cycles_missed": settings.cabinet_missed_cycles}])
    [alert] = _alerts(db, AlertCategory.CABINET_TAG_MISSING)
    assert alert.severity == "P1" and "discovery" in alert.detail
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0012-CAB", "epc": rtr.rfid_epc, "event": "SEEN"}])
    assert alert.status == AlertStatus.RESOLVED.value


def test_door_and_motion_correlation_with_badges_and_hours(db, world, monkeypatch):
    monkeypatch.setattr(settings, "business_hours", "00-24")  # everything is business hours
    now = utcnow()
    sec_svc.ingest_events(db, world.collector, [
        {"branch_code": "0012", "kind": "BADGE", "door": "comms", "badge_id": "B-17", "authorised": True,
         "occurred_at": now - timedelta(seconds=30)},
        {"branch_code": "0012", "kind": "DOOR_OPEN", "door": "comms", "occurred_at": now},
        {"branch_code": "0012", "kind": "MOTION", "occurred_at": now},
    ])
    assert not _alerts(db, AlertCategory.CABINET_DOOR) and not _alerts(db, AlertCategory.INTRUSION)
    out = sec_svc.ingest_events(db, world.collector, [{"branch_code": "0013", "kind": "DOOR_OPEN", "door": "comms"}])
    assert out["alarms"] == 1 and _alerts(db, AlertCategory.CABINET_DOOR)[0].severity == "P1"
    monkeypatch.setattr(settings, "business_hours", "00-00")  # always after hours
    sec_svc.ingest_events(db, world.collector, [{"branch_code": "0012", "kind": "MOTION"}])
    assert _alerts(db, AlertCategory.INTRUSION)[0].severity == "P2"


def test_silent_fixed_reader_is_treated_as_tampered(db, world):
    rps = _read_points(db, world)
    rps["cabinet"].last_heartbeat_at = utcnow() - timedelta(minutes=settings.reader_stale_minutes + 5)
    assert sec_svc.check_readers(db) == 1
    [alert] = _alerts(db, AlertCategory.SECURITY_DEVICE_TAMPER)
    rfid_svc.heartbeat(db, world.collector, ["0012-CAB"])
    assert alert.status == AlertStatus.RESOLVED.value


def test_audit_sweep_reads_feed_the_physical_audit(db, world):
    from itam.services import audits as audit_svc

    _read_points(db, world)
    a = world.active_asset(world.b1, "SWT")
    audit = audit_svc.schedule_audit(db, world.u("itam"), world.b1, utcnow().date())
    audit_svc.start_audit(db, world.u("eng"), audit)
    rfid_svc.ingest_reads(db, world.collector, [{"read_point": "NRB-HH-3", "epc": a.rfid_epc, "branch_code": "0012",
                                                 "operator": "eng"}])
    item = next(i for i in audit.items if i.asset_id == a.id)
    assert item.result == "FOUND"


def test_unknown_tags_are_recorded_and_collector_region_is_enforced(db, world):
    _read_points(db, world)
    out = rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0012-EXIT", "epc": "E28011606000020A1B2C3D4E"}])
    assert out[ReadOutcome.UNKNOWN_TAG.value] == 1
    rfid_svc.create_read_point(db, world.u("itam"), code="0040-EXIT", name="Exit", kind="EXIT_PORTAL", branch=world.b3)
    with pytest.raises(PermissionDenied):
        rfid_svc.ingest_reads(db, world.collector, [{"read_point": "0040-EXIT", "epc": "00"}])


# --- API, schema upgrade, operating model ---------------------------------------------------------------


def test_rfid_and_security_api(client, world, db):
    _read_points(db, world)
    srv = world.active_asset(world.b1, "SRV")
    db.commit()
    headers = {"X-API-Key": COLLECTOR_KEY}
    r = client.post("/api/v1/rfid/reads", headers=headers,
                    json=[{"read_point": "0012-EXIT", "epc": srv.rfid_epc, "event": "LEFT"}])
    assert r.status_code == 200 and r.json()["EXCEPTION"] == 1
    r = client.post("/api/v1/security/events", headers=headers, json=[{"branch_code": "0012", "kind": "DEVICE_TAMPER",
                                                                        "device_ref": "CAM-0012-EXIT"}])
    assert r.status_code == 200 and r.json()["alarms"] == 1
    assert client.post("/api/v1/rfid/reads", json=[]).status_code == 401


def test_schema_upgrade_adds_new_columns_to_an_existing_database(tmp_path):
    from sqlalchemy import create_engine, inspect

    from itam.db import add_missing_columns

    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE branches (id INTEGER PRIMARY KEY, code VARCHAR(4), name VARCHAR(120), "
                             "region_id INTEGER, is_head_office BOOLEAN, rollout_stage VARCHAR(20), rollout_checklist JSON)")
    added = add_missing_columns(engine)
    assert "branches.security_tier" in added
    assert "security_tier" in {c["name"] for c in inspect(engine).get_columns("branches")}
    assert add_missing_columns(engine) == []


def test_operating_model_shows_who_operates_each_stage(client, world):
    from tests.conftest import login

    login(client, "cio")
    page = client.get("/rollout")
    assert page.status_code == 200 and "Sister co." in page.text and "Live &amp; protected" in page.text
