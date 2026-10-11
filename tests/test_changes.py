"""Maker-checker approval matrix for moves, transfers, repairs, retirement and disposal (slide 20)."""

import pytest

from itam.enums import AssetStatus, ChangeStatus, ChangeType
from itam.rbac import Role
from itam.services import PermissionDenied, ServiceError
from itam.services import changes as chg
from itam.services.assets import register_asset


def test_approval_matrix(db, world):
    router = world.active_asset(world.b1, "RTR")
    eud = world.active_asset(world.b1, "EUD")
    assert chg.approval_matrix(ChangeType.MOVE_WITHIN_BRANCH, eud) == [Role.REGIONAL_LEAD]
    assert chg.approval_matrix(ChangeType.TRANSFER_BRANCH, eud) == [Role.BRANCH_MANAGER, Role.IT_ASSET_MANAGER]
    assert chg.approval_matrix(ChangeType.SEND_REPAIR, eud) == [Role.REGIONAL_LEAD, Role.IT_ASSET_MANAGER]
    assert chg.approval_matrix(ChangeType.RETIRE, router) == [Role.HEAD_INFRA, Role.CISO]
    assert chg.approval_matrix(ChangeType.RETIRE, eud) == [Role.REGIONAL_LEAD, Role.IT_ASSET_MANAGER]
    assert chg.approval_matrix(ChangeType.DISPOSE, eud) == [Role.CIO, Role.CFO]


def test_maker_checker_rules(db, world):
    eud = world.active_asset(world.b1, "EUD")
    c = chg.create_change(db, world.u("eng"), eud, ChangeType.TRANSFER_BRANCH, "relocation", to_branch=world.b2)
    # requester cannot approve
    ok, why = chg.can_approve(world.u("eng"), c)
    assert not ok and "requester" in why
    # wrong branch's manager cannot give approver-1
    with pytest.raises(PermissionDenied):
        chg.decide(db, world.u("bm2"), c, True)
    # ITAM cannot jump the queue (step 1 is the sending branch manager)
    with pytest.raises(PermissionDenied):
        chg.decide(db, world.u("itam"), c, True)
    chg.decide(db, world.u("bm1"), c, True, "ok")
    assert c.status == ChangeStatus.PENDING_APPROVAL.value
    chg.decide(db, world.u("itam"), c, True, "ok")
    assert c.status == ChangeStatus.APPROVED.value


def test_same_person_cannot_approve_twice(db, world):
    dual = world.u("itam")
    dual.roles = ["IT_ASSET_MANAGER", "REGIONAL_LEAD"]
    eud = world.active_asset(world.b1, "EUD")
    c = chg.create_change(db, world.u("eng"), eud, ChangeType.SEND_REPAIR, "broken screen")
    chg.decide(db, dual, c, True)
    ok, why = chg.can_approve(dual, c)
    assert not ok and "both approvals" in why


def test_rejection_requires_reason(db, world):
    eud = world.active_asset(world.b1, "EUD")
    c = chg.create_change(db, world.u("eng"), eud, ChangeType.MOVE_WITHIN_BRANCH, "desk move",
                          to_location=world.loc["0012"][1])
    with pytest.raises(ServiceError):
        chg.decide(db, world.u("lead"), c, False, "")
    chg.decide(db, world.u("lead"), c, False, "not needed")
    assert c.status == ChangeStatus.REJECTED.value


def test_transfer_flow_keeps_asset_number(db, world):
    eud = world.active_asset(world.b1, "EUD")
    number = eud.asset_number
    c = chg.create_change(db, world.u("eng"), eud, ChangeType.TRANSFER_BRANCH, "relocation", to_branch=world.b2)
    chg.decide(db, world.u("bm1"), c, True)
    chg.decide(db, world.u("itam"), c, True)
    with pytest.raises(ServiceError, match="does not match"):
        chg.execute(db, world.u("eng"), c, "KE-NRB-0012-EUD-99999", evidence_ref="TN-1")
    with pytest.raises(ServiceError, match="Evidence required"):
        chg.execute(db, world.u("eng"), c, number)
    chg.execute(db, world.u("eng"), c, number, evidence_ref="TN-1")
    assert eud.status == AssetStatus.IN_TRANSIT.value and c.status == ChangeStatus.IN_PROGRESS.value
    with pytest.raises(PermissionDenied):
        chg.confirm_delivery(db, world.u("bm3"), c)
    chg.confirm_delivery(db, world.u("bm2"), c, world.loc["0013"][1])
    assert eud.branch_id == world.b2.id and eud.status == AssetStatus.IN_STOCK.value
    assert eud.asset_number == number  # never changes when the asset moves
    assert eud.custody_accepted_at is None  # new custodian must sign
    assert c.status == ChangeStatus.COMPLETED.value


def test_disposal_requires_certificates_and_finance(db, world):
    srv = world.active_asset(world.b1, "SRV")
    retire = chg.create_change(db, world.u("eng"), srv, ChangeType.RETIRE, "EOL")
    chg.decide(db, world.u("head"), retire, True)
    chg.decide(db, world.u("ciso"), retire, True)
    chg.execute(db, world.u("eng"), retire, srv.asset_number, ticket_ref="CHG1", evidence_ref="WIPE-PLAN-1")
    assert srv.status == AssetStatus.RETIRED.value and not srv.monitored

    dispose = chg.create_change(db, world.u("itam"), srv, ChangeType.DISPOSE, "WEEE")
    chg.decide(db, world.u("cio"), dispose, True)
    chg.decide(db, world.u("cfo"), dispose, True)
    with pytest.raises(ServiceError, match="data-wipe certificate"):
        chg.execute(db, world.u("eng"), dispose, srv.asset_number, disposal_certificate_ref="D-1")
    chg.execute(db, world.u("eng"), dispose, srv.asset_number, disposal_certificate_ref="D-1",
                wipe_certificate_ref="W-1")
    assert srv.status == AssetStatus.DISPOSED.value
    with pytest.raises(PermissionDenied):
        chg.finance_confirm(db, world.u("itam"), dispose)
    chg.finance_confirm(db, world.u("finance"), dispose)
    assert dispose.finance_confirmed_at


def test_only_one_open_change_and_state_guards(db, world):
    eud = world.active_asset(world.b1, "EUD")
    chg.create_change(db, world.u("eng"), eud, ChangeType.SEND_REPAIR, "fan")
    with pytest.raises(ServiceError, match="already has an open change"):
        chg.create_change(db, world.u("eng"), eud, ChangeType.RETIRE, "x")
    fresh = register_asset(db, world.u("itam"), branch=world.b1, asset_type="EUD", serial_number="FRESH")
    with pytest.raises(ServiceError, match="not possible"):
        chg.create_change(db, world.u("itam"), fresh, ChangeType.DISPOSE, "x")
