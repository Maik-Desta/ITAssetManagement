"""Asset numbering, lifecycle, new-equipment workflow (slides 16, 18, 19)."""

import pytest

from itam.enums import AssetStatus
from itam.numbering import extract_asset_number, format_asset_number, is_valid_asset_number, parse_asset_number
from itam.services import PermissionDenied, ServiceError
from itam.services import assets as asset_svc
from itam.services import discovery as disc_svc
from itam.services import requests as req_svc


def test_asset_number_format_and_parsing():
    number = format_asset_number("KE", "NRB", "0012", "RTR", 41)
    assert number == "KE-NRB-0012-RTR-00041"
    assert parse_asset_number(number) == {"cc": "KE", "rrr": "NRB", "bbbb": "0012", "ttt": "RTR", "nnnnn": "00041"}
    assert is_valid_asset_number(number)
    assert not is_valid_asset_number("KE-NRB-12-RTR-41")
    assert extract_asset_number("https://itam.bank/scan/KE-NRB-0012-RTR-00041") == number


def test_sequence_per_prefix_and_number_never_changes(db, world):
    itam = world.u("itam")
    a1 = asset_svc.register_asset(db, itam, branch=world.b1, asset_type="RTR", serial_number="A1")
    a2 = asset_svc.register_asset(db, itam, branch=world.b1, asset_type="RTR", serial_number="A2")
    s1 = asset_svc.register_asset(db, itam, branch=world.b1, asset_type="SWT", serial_number="S1")
    assert a1.asset_number == "KE-NRB-0012-RTR-00001"
    assert a2.asset_number == "KE-NRB-0012-RTR-00002"
    assert s1.asset_number == "KE-NRB-0012-SWT-00001"
    assert a1.status == AssetStatus.IN_STOCK.value


def test_duplicate_serial_rejected(db, world):
    asset_svc.register_asset(db, world.u("itam"), branch=world.b1, asset_type="RTR", serial_number="DUP")
    with pytest.raises(ServiceError, match="already registered"):
        asset_svc.register_asset(db, world.u("itam"), branch=world.b2, asset_type="RTR", serial_number="DUP")


def test_only_itam_office_registers(db, world):
    with pytest.raises(PermissionDenied):
        asset_svc.register_asset(db, world.u("eng"), branch=world.b1, asset_type="RTR", serial_number="X")


def test_invalid_lifecycle_transition_rejected(db, world):
    a = asset_svc.register_asset(db, world.u("itam"), branch=world.b1, asset_type="EUD", serial_number="E1")
    with pytest.raises(ServiceError, match="not allowed"):
        asset_svc.set_status(db, a, AssetStatus.DISPOSED, world.u("itam"), "TEST")


def test_install_requires_checklist_then_discovery_confirms_go_live(db, world):
    a = asset_svc.register_asset(db, world.u("itam"), branch=world.b1, asset_type="SWT", serial_number="SW-NEW")
    comms = world.loc["0012"][0]
    with pytest.raises(ServiceError, match="checklist incomplete"):
        asset_svc.install_asset(db, world.u("eng"), a, location_id=comms.id, ip_address="10.0.12.9",
                                checklist={"hardened": True, "snmpv3": True})
    full = {"hardened": True, "snmpv3": True, "syslog": True, "ntp": True}
    with pytest.raises(PermissionDenied):  # engineer from another region
        asset_svc.install_asset(db, world.u("eng_msa"), a, location_id=comms.id, ip_address="10.0.12.9", checklist=full)
    asset_svc.install_asset(db, world.u("eng"), a, location_id=comms.id, ip_address="10.0.12.9",
                            mac_address="aa:bb:cc:dd:ee:01", checklist=full)
    assert a.status == AssetStatus.IN_STOCK.value and a.install_date and not a.go_live_verified_at

    disc_svc.ingest_discovery(db, world.collector, "0012", [{"serial": "SW-NEW", "ip": "10.0.12.9"}])
    assert a.status == AssetStatus.ACTIVE.value
    assert a.go_live_verified_at is not None


def test_custody_only_by_own_branch_manager(db, world):
    a = world.active_asset(world.b1)
    with pytest.raises(PermissionDenied):
        asset_svc.accept_custody(db, world.u("bm2"), a)
    asset_svc.accept_custody(db, world.u("bm1"), a)
    assert a.custodian_id == world.u("bm1").id and a.custody_accepted_at


def test_equipment_request_end_to_end(db, world):
    bm1, itam, fin = world.u("bm1"), world.u("itam"), world.u("finance")
    req = req_svc.create_request(db, bm1, branch=world.b1, asset_type="EUD", quantity=2, justification="New tellers",
                                 model_id=world.models["EUD"].id, estimated_cost=2000)
    with pytest.raises(PermissionDenied):
        req_svc.approve(db, bm1, req, "it")  # maker-checker
    with pytest.raises(ServiceError):
        req_svc.record_po(db, world.u("procurement"), req, "PO-1", "Dell")  # not yet approved
    req_svc.approve(db, itam, req, "it")
    assert req.status == "PENDING_APPROVAL"
    req_svc.approve(db, fin, req, "budget")
    assert req.status == "APPROVED"
    req_svc.record_po(db, world.u("procurement"), req, "PO-1", "Dell")
    with pytest.raises(ServiceError, match="outstanding"):
        req_svc.receive(db, itam, req, ["S1", "S2", "S3"])
    assets = req_svc.receive(db, itam, req, ["S1", "S2"])
    assert req.status == "RECEIVED"
    # Received into the central store, numbered for the destination branch.
    assert all(a.branch_id == world.hq.id for a in assets)
    assert assets[0].asset_number == "KE-NRB-0012-EUD-00001"
    assert all(a.tag_applied_at and float(a.purchase_cost) == 1000.0 for a in assets)
