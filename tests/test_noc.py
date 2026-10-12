"""NOC: L1 → L2 → L3 → CEO escalation, CEO alert on branch outage, notification methods, grouping and response metrics."""

from datetime import timedelta

from itam.enums import OperState
from itam.models import Notification, User, utcnow
from itam.rbac import Role
from itam.security import hash_password
from itam.services import monitoring as mon
from itam.services.noc import noc_overview
from tests.conftest import PASSWORD, login


def _add_ceo(db):
    ceo = User(username="ceo", full_name="CEO", email="ceo@bank.test", phone="+254700000001",
               password_hash=hash_password(PASSWORD), roles=[Role.EXECUTIVE.value], is_active=True)
    db.add(ceo)
    db.flush()
    return ceo


def test_branch_offline_alerts_ceo_immediately(db, world):
    ceo = _add_ceo(db)
    r = world.active_asset(world.b1, "RTR")
    alert = mon.apply_state(db, r, OperState.DOWN, utcnow())
    assert [e.level for e in alert.escalations] == [0, 3]  # L1 and CEO, nothing in between yet
    ceo_msgs = {n.channel for n in db.query(Notification).filter(Notification.recipient_user_id == ceo.id)}
    assert ceo_msgs == {"VOICE", "SMS", "EMAIL", "SYSTEM"}
    steps = {s["code"]: s["state"] for s in mon.escalation_path(alert)}
    assert steps == {"L1": "done", "L2": "due", "L3": "due", "CEO": "done"}


def test_escalation_ceiling_by_severity(db, world):
    _add_ceo(db)
    srv = world.active_asset(world.b1, "SRV")  # P2 server down
    alert = mon.apply_state(db, srv, OperState.DOWN, utcnow())
    mon.escalate_overdue(db, alert.detected_at + timedelta(hours=10))
    assert alert.escalation_level == 2  # P2 stops at L3, never reaches the CEO
    assert [e.level for e in alert.escalations] == [0, 1, 2]
    assert mon.escalation_path(alert)[3]["state"] == "na"


def test_core_device_p1_escalates_to_ceo_once(db, world):
    ceo = _add_ceo(db)
    fw = world.active_asset(world.b1, "FWL")
    world.active_asset(world.b1, "RTR")
    alert = mon.apply_state(db, fw, OperState.DOWN, utcnow())
    mon.escalate_overdue(db, alert.detected_at + timedelta(minutes=50))
    assert [e.level for e in alert.escalations] == [0, 1, 2, 3]
    assert {n.recipient_user_id for n in db.query(Notification).filter(Notification.alert_id == alert.id)} >= {ceo.id}
    before = db.query(Notification).count()
    mon.escalate_overdue(db, alert.detected_at + timedelta(minutes=90))
    assert db.query(Notification).count() == before  # no repeat notifications


def test_acknowledgement_stops_escalation(db, world):
    sw = world.active_asset(world.b1, "SWT")
    alert = mon.apply_state(db, sw, OperState.DOWN, utcnow())
    mon.acknowledge(db, world.u("noc"), alert)
    assert [s["state"] for s in mon.escalation_path(alert)][1:3] == ["stopped", "stopped"]


def test_noc_overview_groups_and_metrics(db, world):
    r = world.active_asset(world.b1, "RTR")
    world.active_asset(world.b1, "SWT")
    srv = world.active_asset(world.b3, "SRV")
    mon.apply_state(db, r, OperState.DOWN, utcnow())
    a2 = mon.apply_state(db, srv, OperState.DOWN, utcnow() - timedelta(minutes=10))
    mon.acknowledge(db, world.u("noc"), a2)
    mon.resolve(db, world.u("noc"), a2, "PSU replaced")
    db.flush()
    n = noc_overview(db, world.u("noc"))
    assert [g["branch"].code for g in n["incidents"]] == ["0012"]
    assert n["offline"][0]["branch"].code == "0012"
    assert n["impact_counts"]["P1"] == 1
    assert n["overall"]["alerts"] == 2 and n["overall"]["mttr"] is not None
    assert n["asset_counts"]["down"] == 2  # the server is still down even though its alert was closed


def test_noc_page_and_notifications(client, db, world):
    _add_ceo(db)
    r = world.active_asset(world.b1, "RTR")
    mon.apply_state(db, r, OperState.DOWN, utcnow())
    db.commit()
    login(client, "noc")
    html = client.get("/noc").text
    for text in ("Branch offline", "CEO alerted", "Escalation path", "grouped by branch", "Affected assets",
                 "Mean resolution time"):
        assert text in html
    assert client.get("/noc?show=history").status_code == 200
    client.cookies.clear()
    login(client, "ceo")
    assert 'class="bell-n"' in client.get("/dashboard").text
    assert "is completely offline" in client.get("/notifications").text
    assert 'class="bell-n"' not in client.get("/dashboard").text  # marked read
