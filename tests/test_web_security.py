"""HTTP layer: authentication, MFA, CSRF, RBAC scoping, collector API, audit-log immutability."""

import pytest
from sqlalchemy import text

from itam import auditlog
from itam.models import Alert, AuditLogEntry, User
from itam.security import totp_now
from tests.conftest import COLLECTOR_KEY, PASSWORD, csrf_from, login


def test_login_required_and_success(client, world):
    r = client.get("/assets", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert login(client, "itam").status_code == 303
    assert "Asset register" in client.get("/assets").text


def test_bad_password_and_lockout(client, world):
    for _ in range(5):
        assert login(client, "noc", "wrong").status_code == 401
    assert login(client, "noc", PASSWORD).status_code == 429


def test_csrf_enforced(client, world):
    login(client, "itam")
    r = client.post("/assets/new", data={"branch_id": world.b1.id, "asset_type": "RTR", "serial_number": "X"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "expired" in client.get(r.headers["location"]).text
    assert not client.get("/api/v1/assets").json()


def test_register_asset_through_ui(client, world, db):
    login(client, "itam")
    token = csrf_from(client.get("/assets/new").text)
    r = client.post("/assets/new", data={"csrf_token": token, "branch_id": world.b1.id, "asset_type": "RTR",
                                         "serial_number": "UI-1", "initial_status": "IN_STOCK", "tag_applied": "1"})
    assert r.status_code == 200 and "KE-NRB-0012-RTR-00001" in r.text


def test_service_error_is_flashed(client, world):
    login(client, "itam")
    token = csrf_from(client.get("/assets/new").text)
    data = {"csrf_token": token, "branch_id": world.b1.id, "asset_type": "RTR", "serial_number": "DUP-UI"}
    client.post("/assets/new", data=data)
    r = client.post("/assets/new", data=data, headers={"referer": "http://testserver/assets/new"})
    assert "already registered" in r.text


def test_branch_manager_scope(client, world, db):
    other = world.active_asset(world.b2, "EUD")
    own = world.active_asset(world.b1, "EUD")
    db.commit()
    login(client, "bm1")
    assert client.get(f"/assets/{own.id}").status_code == 200
    assert client.get(f"/assets/{other.id}").status_code == 404
    numbers = [a["asset_number"] for a in client.get("/api/v1/assets").json()]
    assert numbers == [own.asset_number]


def test_permission_denied_page(client, world):
    login(client, "bm1")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/controls").status_code == 403


def test_mfa_enrolment_and_required_login(client, world, db, settings):
    settings.mfa_required_roles = "CIO"
    try:
        r = login(client, "cio")
        assert r.headers["location"] == "/login/mfa"
        page = client.get("/login/mfa").text
        secret = page.split('<p class="mono">')[1].split("</p>")[0].strip()
        r = client.post("/login/mfa", data={"code": "000000", "csrf_token": csrf_from(page)}, follow_redirects=False)
        assert r.headers["location"] == "/login/mfa"
        page = client.get("/login/mfa").text
        r = client.post("/login/mfa", data={"code": totp_now(secret), "csrf_token": csrf_from(page)},
                        follow_redirects=False)
        assert r.headers["location"] == "/dashboard"
        db.expire_all()
        assert db.get(User, world.u("cio").id).mfa_secret == secret
    finally:
        settings.mfa_required_roles = ""


def test_collector_api(client, world, db):
    r = world.active_asset(world.b1, "RTR")
    db.commit()
    assert client.post("/api/v1/collector/heartbeat").status_code == 401
    assert client.post("/api/v1/collector/heartbeat", headers={"X-API-Key": "nope"}).status_code == 401
    h = {"X-API-Key": COLLECTOR_KEY}
    res = client.post("/api/v1/collector/poll", headers=h,
                      json=[{"asset_number": r.asset_number, "state": "DOWN", "message": "ICMP timeout"}])
    assert res.status_code == 200 and res.json()["alerts"] == 1
    db.expire_all()
    assert db.query(Alert).filter(Alert.category == "BRANCH_OFFLINE").count() == 1
    res = client.post("/api/v1/collector/discovery", headers=h, json={"branch_code": "0012", "devices": [
        {"serial": r.serial_number, "ip": r.ip_address}, {"ip": "10.9.9.9", "mac": "aa:aa:aa:aa:aa:aa"}]})
    assert res.json()["rogue"] == 1
    # a collector cannot report for another region
    res = client.post("/api/v1/collector/discovery", headers=h, json={"branch_code": "0040", "devices": []})
    assert res.status_code == 403


def test_full_change_through_ui(client, world, db):
    eud = world.active_asset(world.b1, "EUD")
    db.commit()
    login(client, "eng")
    page = client.get(f"/changes/new?asset_id={eud.id}").text
    r = client.post("/changes/new", data={"csrf_token": csrf_from(page), "asset_id": eud.id,
                                          "change_type": "SEND_REPAIR", "reason": "Fan noise"})
    assert "submitted for approval" in r.text
    change_url = str(r.url.path)
    client.post("/logout", data={"csrf_token": csrf_from(r.text)})
    login(client, "lead")
    page = client.get(change_url).text
    r = client.post(f"{change_url}/decide", data={"csrf_token": csrf_from(page), "decision": "approve"})
    assert "Decision recorded" in r.text
    client.post("/logout", data={"csrf_token": csrf_from(r.text)})
    login(client, "itam")
    page = client.get(change_url).text
    r = client.post(f"{change_url}/decide", data={"csrf_token": csrf_from(page), "decision": "approve"})
    assert "Execute" in r.text


def test_audit_log_append_only_and_tamper_evident(db, world):
    auditlog.record(db, world.u("admin"), "test.event", "thing", 1, value="a")
    db.commit()
    ok, count, _ = auditlog.verify_chain(db)
    assert ok and count >= 1
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("UPDATE audit_log SET actor = 'mallory'"))
    db.rollback()
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("DELETE FROM audit_log"))
    db.rollback()
    # Even with triggers removed, tampering is detected by the hash chain.
    db.execute(text("DROP TRIGGER audit_log_no_update"))
    last = db.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).first()
    db.execute(text("UPDATE audit_log SET actor = 'mallory' WHERE id = :i"), {"i": last.id})
    db.expire_all()
    ok, _, bad = auditlog.verify_chain(db)
    assert not ok and bad == last.id


def test_security_headers_and_health(client):
    r = client.get("/healthz")
    assert r.json()["status"] == "ok"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
