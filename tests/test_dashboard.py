"""Dashboard asset breakdown: totals per region/branch and consistency with the asset-list filters."""

from datetime import timedelta

from itam.enums import OperState
from itam.models import utcnow
from itam.services import dashboard as dash
from itam.services import monitoring as mon
from itam.services.assets import register_asset
from tests.conftest import login


def _world_with_states(db, world):
    r1 = world.active_asset(world.b1, "RTR")
    world.active_asset(world.b1, "RTR")
    srv = world.active_asset(world.b1, "SRV")
    world.active_asset(world.b1, "EUD").monitored = False
    sw = world.active_asset(world.b3, "SWT")
    mon.apply_state(db, srv, OperState.DOWN, utcnow() - timedelta(minutes=1))  # down + faulty
    mon.apply_state(db, sw, OperState.DEGRADED, utcnow())  # issue, still installed
    register_asset(db, world.u("itam"), branch=world.b2, asset_type="EUD", serial_number="STOCK-1")  # in stock
    db.flush()
    return r1


def test_classify_asset_buckets():
    assert dash.classify_asset("ACTIVE", "UP", True) == {"total", "installed", "live"}
    assert dash.classify_asset("FAULTY", "DOWN", True) == {"total", "installed", "issues", "down"}
    assert dash.classify_asset("ACTIVE", "DEGRADED", True) == {"total", "installed", "issues"}
    assert dash.classify_asset("ACTIVE", "UNKNOWN", False) == {"total", "installed", "live", "not_monitored"}
    assert dash.classify_asset("IN_STOCK", "UNKNOWN", False) == {"total"}
    assert dash.classify_asset("MISSING", "UP", True) == {"total", "issues"}
    assert dash.classify_asset("DISPOSED", "UP", False) == set()


def test_breakdown_per_branch_and_region(db, world):
    _world_with_states(db, world)
    bd = dash.asset_breakdown(db, [world.hq, world.b1, world.b2, world.b3])
    by_code = {row["branch"].code: row["counts"] for row in bd["branches"]}
    assert by_code["0012"] == {"total": 4, "installed": 4, "live": 3, "issues": 1, "down": 1, "not_monitored": 1}
    assert by_code["0013"] == {"total": 1, "installed": 0, "live": 0, "issues": 0, "down": 0, "not_monitored": 0}
    regions = {r["region"].code: r for r in bd["regions"]}
    assert regions["NRB"]["branches"] == 3 and regions["NRB"]["counts"]["total"] == 5
    assert regions["MSA"]["counts"]["issues"] == 1
    assert bd["totals"]["counts"]["total"] == 6
    assert bd["totals"]["monitored"] == 1  # only 0012 has monitored routers


def test_dashboard_numbers_match_asset_list_links(client, db, world):
    _world_with_states(db, world)
    db.commit()
    login(client, "itam")
    html = client.get("/dashboard").text
    assert "Total branches" in html and "Assets by region" in html and "Assets by branch" in html
    expected = dash.asset_breakdown(db, [world.hq, world.b1, world.b2, world.b3])["totals"]["counts"]
    for key, _label, flag, _help in dash.BREAKDOWN_COLUMNS:
        if not flag:
            continue
        page = client.get(f"/assets?flag={flag}").text
        assert f"{expected[key]:,} matching records" in page, key


def test_deployment_stage():
    assert dash.deployment_stage("IN_STOCK", True) == "store"
    assert dash.deployment_stage("IN_STOCK", False) == "not_installed"
    assert dash.deployment_stage("IN_TRANSIT", False) == "transit"
    assert dash.deployment_stage("FAULTY", False) == "installed"
    assert dash.deployment_stage("RETIRED", False) == "out"
    assert dash.deployment_stage("DISPOSED", False) is None


def test_inventory_store_and_not_installed(client, db, world):
    _world_with_states(db, world)
    register_asset(db, world.u("itam"), branch=world.hq, asset_type="RTR", serial_number="HQ-STOCK", purchase_cost=4800)
    db.commit()
    inv = dash.asset_inventory(db, [world.hq, world.b1, world.b2, world.b3])
    assert inv["stage_totals"] == {"installed": 5, "not_installed": 1, "store": 1, "transit": 0, "out": 0}
    assert inv["total"] == 7 and inv["store_value"] == 4800
    assert [n["branch"].code for n in inv["not_installed"]] == ["0013"]
    assert {t["type"]: t["total"] for t in inv["types"]}["RTR"] == 3
    login(client, "cio")
    html = client.get("/dashboard").text
    for text in ("Key messages for the CEO", "Deployment pipeline", "Assets by type", "Asset type by region",
                 "Purchased, not yet assigned to a branch", "Delivered to branches, not yet installed"):
        assert text in html
    assert "1 matching records" in client.get("/assets?flag=store").text
    assert "1 matching records" in client.get("/assets?flag=not_installed").text
