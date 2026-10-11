"""Monitoring, alert severity, event correlation and escalation (slide 21)."""

from datetime import timedelta

from itam.enums import AlertCategory, AlertStatus, AssetStatus, OperState
from itam.models import Alert, Notification, utcnow
from itam.services import monitoring as mon


def _open(db, category=None):
    q = db.query(Alert).filter(Alert.status != AlertStatus.RESOLVED.value)
    if category:
        q = q.filter(Alert.category == category.value)
    return q.all()


def test_single_router_down_is_branch_offline_p1(db, world):
    r = world.active_asset(world.b1, "RTR")
    t = utcnow() - timedelta(minutes=2)
    alert = mon.apply_state(db, r, OperState.DOWN, t, world.collector)
    assert alert.severity == "P1" and alert.category == AlertCategory.BRANCH_OFFLINE.value
    assert r.status == AssetStatus.FAULTY.value
    assert alert.ticket_ref.startswith("INC-")
    # P1: SMS + voice + e-mail + chat to NOC and regional IT
    channels = {n.channel for n in db.query(Notification).filter(Notification.alert_id == alert.id)}
    assert {"SMS", "VOICE", "EMAIL", "CHAT"} <= channels
    # MTTD is measured from the failure, not from ingestion
    assert (alert.detected_at - alert.occurred_at) >= timedelta(minutes=1)

    mon.apply_state(db, r, OperState.UP, utcnow(), world.collector)
    assert alert.status == AlertStatus.RESOLVED.value
    assert r.status == AssetStatus.ACTIVE.value


def test_redundancy_then_branch_offline(db, world):
    r1 = world.active_asset(world.b1, "RTR")
    r2 = world.active_asset(world.b1, "RTR")
    a1 = mon.apply_state(db, r1, OperState.DOWN, utcnow(), world.collector)
    assert a1.severity == "P2" and a1.category == AlertCategory.REDUNDANCY_LOST.value
    a2 = mon.apply_state(db, r2, OperState.DOWN, utcnow(), world.collector)
    assert a2.category == AlertCategory.BRANCH_OFFLINE.value and a2.severity == "P1"
    assert a1.status == AlertStatus.RESOLVED.value  # superseded


def test_event_correlation_suppresses_children_while_branch_offline(db, world):
    r = world.active_asset(world.b1, "RTR")
    sw = world.active_asset(world.b1, "SWT")
    mon.apply_state(db, r, OperState.DOWN, utcnow(), world.collector)
    assert mon.apply_state(db, sw, OperState.DOWN, utcnow(), world.collector) is None
    assert sw.oper_state == OperState.UNKNOWN.value and sw.status == AssetStatus.ACTIVE.value
    # Branch back; the switch is genuinely down → now it alerts.
    mon.apply_state(db, r, OperState.UP, utcnow(), world.collector)
    alert = mon.apply_state(db, sw, OperState.DOWN, utcnow(), world.collector)
    assert alert is not None and alert.category == AlertCategory.DEVICE_DOWN.value


def test_server_down_is_p2_and_degraded_is_p3(db, world):
    srv = world.active_asset(world.b1, "SRV")
    assert mon.apply_state(db, srv, OperState.DOWN, utcnow()).severity == "P2"
    sw = world.active_asset(world.b1, "SWT", criticality="LOW")
    assert mon.apply_state(db, sw, OperState.DEGRADED, utcnow()).severity == "P3"


def test_stale_buffered_sample_ignored(db, world):
    r = world.active_asset(world.b1, "RTR")
    mon.apply_state(db, r, OperState.DOWN, utcnow(), world.collector)
    mon.apply_state(db, r, OperState.UP, utcnow() - timedelta(minutes=10), world.collector)
    assert r.oper_state == OperState.DOWN.value


def test_escalation_chain(db, world):
    r = world.active_asset(world.b1, "RTR")
    alert = mon.apply_state(db, r, OperState.DOWN, utcnow())
    base = alert.detected_at
    assert mon.escalate_overdue(db, base + timedelta(minutes=10)) == 0
    mon.escalate_overdue(db, base + timedelta(minutes=16))
    assert alert.escalation_level == 1  # regional lead
    mon.escalate_overdue(db, base + timedelta(minutes=31))
    assert alert.escalation_level == 2  # Head of Infrastructure
    mon.escalate_overdue(db, base + timedelta(minutes=200))
    assert alert.escalation_level == 3  # CIO
    cio_msgs = db.query(Notification).filter(Notification.recipient_user_id == world.u("cio").id).count()
    assert cio_msgs > 0
    # acknowledged alerts stop escalating
    r2 = world.active_asset(world.b2, "RTR")
    a2 = mon.apply_state(db, r2, OperState.DOWN, utcnow())
    mon.acknowledge(db, world.u("noc"), a2)
    mon.escalate_overdue(db, a2.detected_at + timedelta(hours=5))
    assert a2.escalation_level == 0


def test_unapproved_config_change_alerts(db, world):
    r = world.active_asset(world.b1, "RTR")
    result = mon.ingest_events(db, world.collector, [{"asset_number": r.asset_number, "kind": "CONFIG_CHANGE",
                                                      "message": "running-config changed"}])
    assert result["unapproved_config_changes"] == 1
    assert _open(db, AlertCategory.CONFIG_CHANGE)


def test_environment_alarm(db, world):
    ups = world.active_asset(world.b1, "UPS")
    mon.ingest_poll_results(db, world.collector, [{"asset_number": ups.asset_number, "metrics": {"on_battery": True}}])
    assert _open(db, AlertCategory.ENVIRONMENT)
    mon.ingest_poll_results(db, world.collector, [{"asset_number": ups.asset_number, "metrics": {"on_battery": False}}])
    assert not _open(db, AlertCategory.ENVIRONMENT)


def test_user_reported_incident_vs_proactive(db, world):
    r = world.active_asset(world.b1, "RTR")
    user_alert = mon.report_user_incident(db, world.u("noc"), world.b2, "Customers cannot transact")
    assert user_alert.source == "USER_REPORT"
    detected = mon.apply_state(db, r, OperState.DOWN, utcnow())
    same = mon.report_user_incident(db, world.u("noc"), world.b1, "ATMs offline")
    assert same.id == detected.id  # monitoring got there first


def test_warranty_alerts_raised_once(db, world):
    from datetime import date

    a = world.active_asset(world.b1, "EUD", warranty_end=date.today() + timedelta(days=30))
    assert mon.warranty_and_eol_alerts(db) == 1
    alert = db.query(Alert).filter(Alert.asset_id == a.id).one()
    mon.resolve(db, world.u("noc"), alert, "Renewal ordered")
    assert mon.warranty_and_eol_alerts(db) == 0
