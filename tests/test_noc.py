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


def test_response_sla_states(db, world):
    from itam.services.noc import response_sla

    sw = world.active_asset(world.b1, "SWT")  # P2 → 30-minute target
    alert = mon.apply_state(db, sw, OperState.DOWN, utcnow())
    t0 = alert.detected_at
    assert response_sla(alert, t0 + timedelta(minutes=5))["state"] == "on_track"
    assert response_sla(alert, t0 + timedelta(minutes=25))["state"] == "at_risk"
    assert response_sla(alert, t0 + timedelta(minutes=40))["state"] == "breached"
    alert.acknowledged_at = t0 + timedelta(minutes=10)
    assert response_sla(alert, t0 + timedelta(hours=2))["state"] == "met"


def test_cases_by_escalation_level(db, world):
    _add_ceo(db)
    r = world.active_asset(world.b1, "RTR")
    mon.apply_state(db, r, OperState.DOWN, utcnow())  # branch offline → CEO immediately
    srv = world.active_asset(world.b3, "SRV")
    a2 = mon.apply_state(db, srv, OperState.DOWN, utcnow() - timedelta(minutes=40))
    a2.detected_at = utcnow() - timedelta(minutes=40)
    mon.escalate_overdue(db)  # P2 unacknowledged for 40 min → L2
    n = noc_overview(db, world.u("noc"))
    levels = {lvl["code"]: lvl for lvl in n["by_level"]}
    assert levels["CEO"]["count"] == 1 and levels["CEO"]["critical_unacked"] == 1
    assert levels["L2"]["count"] == 1 and levels["L2"]["breached"] == 1
    assert levels["L1"]["count"] == 0 and levels["L3"]["count"] == 0
    assert n["sla_counts"]["breached"] == 1


def test_noc_page_flashes_critical(client, db, world):
    r = world.active_asset(world.b1, "RTR")
    mon.apply_state(db, r, OperState.DOWN, utcnow())
    db.commit()
    login(client, "noc")
    html = client.get("/noc").text
    assert "Open cases by escalation level" in html
    assert html.count("flash-critical") >= 3  # banner, tiles, incident card
    assert "On track" in html


def test_branch_offline_voice_announcement_in_english_and_french(client, db, world):
    _add_ceo(db)
    world.b1.latitude, world.b1.longitude = 4.05, 9.77  # Douala, so the branch is drawn on the map
    r = world.active_asset(world.b1, "RTR")
    alert = mon.apply_state(db, r, OperState.DOWN, utcnow())
    db.commit()
    g = noc_overview(db, world.u("noc"))["offline"][0]
    en, fr = g["announce"]["en"], g["announce"]["fr"]
    code = " ".join(world.b1.code)
    assert f"Branch number {code}" in en and f"L'agence numéro {code}" in fr
    assert "router" in en and "routeur" in fr
    assert "CEO level" in en and "Direction générale" in fr  # escalation status
    assert "Notified:" in en and "Personnes notifiées" in fr and "CEO" in en
    assert "not yet been acknowledged" in en and "pas encore été prise en charge" in fr
    assert g["announce"]["key"] == alert.ticket_ref

    login(client, "noc")
    html = client.get("/noc").text
    assert "data-say-en=" in html and "data-say-fr=" in html and "data-voice-toggle" in html
    assert 'class="cmr-map"' in html and 'class="cmr-dot p1' in html  # live map, P1 branch flashing
    assert "Executive View" in html
