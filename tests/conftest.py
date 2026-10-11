from __future__ import annotations

import re
from datetime import date, timedelta

import pytest

from itam.config import reload_settings
from itam.db import create_schema, init_engine, new_session
from itam.models import AssetModel, Branch, Collector, Location, Region, User, Vendor, utcnow
from itam.rbac import Role
from itam.security import hash_api_key, hash_password

PASSWORD = "Test-Password-123"
COLLECTOR_KEY = "itamc_test_key_nrb"


@pytest.fixture()
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("ITAM_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("ITAM_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ITAM_SCHEDULER_ENABLED", "false")
    cfg = reload_settings()
    init_engine(cfg.database_url)
    create_schema()
    return cfg


@pytest.fixture()
def db(settings):
    session = new_session()
    yield session
    session.rollback()
    session.close()


class World:
    """A small estate: two regions, HQ + three branches, one user per role, a collector."""

    def __init__(self, db):
        self.db = db
        self.nrb = Region(code="NRB", name="Nairobi", country_code="KE")
        self.msa = Region(code="MSA", name="Coast", country_code="KE")
        db.add_all([self.nrb, self.msa])
        db.flush()
        self.hq = Branch(code="0001", name="HQ", region_id=self.nrb.id, is_head_office=True, rollout_stage="LIVE",
                         rollout_checklist={})
        self.b1 = Branch(code="0012", name="Westlands", region_id=self.nrb.id, rollout_stage="NOT_STARTED",
                         rollout_checklist={})
        self.b2 = Branch(code="0013", name="Karen", region_id=self.nrb.id, rollout_stage="NOT_STARTED",
                         rollout_checklist={})
        self.b3 = Branch(code="0040", name="Nyali", region_id=self.msa.id, rollout_stage="NOT_STARTED",
                         rollout_checklist={})
        db.add_all([self.hq, self.b1, self.b2, self.b3])
        db.flush()
        self.loc = {}
        for b in (self.hq, self.b1, self.b2, self.b3):
            comms = Location(branch_id=b.id, building=b.name, room="Comms room", rack="R1")
            hall = Location(branch_id=b.id, building=b.name, room="Banking hall")
            db.add_all([comms, hall])
            db.flush()
            self.loc[b.code] = (comms, hall)
        self.users: dict[str, User] = {}
        for name, roles, region, branch in [
            ("admin", [Role.ADMIN], None, None), ("itam", [Role.IT_ASSET_MANAGER], None, None),
            ("itam2", [Role.IT_ASSET_MANAGER], None, None), ("cio", [Role.CIO], None, None),
            ("cfo", [Role.CFO], None, None), ("head", [Role.HEAD_INFRA], None, None), ("ciso", [Role.CISO], None, None),
            ("noc", [Role.NOC], None, None), ("finance", [Role.FINANCE], None, None),
            ("procurement", [Role.PROCUREMENT], None, None), ("audit", [Role.INTERNAL_AUDIT], None, None),
            ("lead", [Role.REGIONAL_LEAD], self.nrb, None), ("lead_msa", [Role.REGIONAL_LEAD], self.msa, None),
            ("eng", [Role.REGIONAL_IT], self.nrb, None), ("eng_msa", [Role.REGIONAL_IT], self.msa, None),
            ("bm_hq", [Role.BRANCH_MANAGER], None, self.hq), ("bm1", [Role.BRANCH_MANAGER], None, self.b1),
            ("bm2", [Role.BRANCH_MANAGER], None, self.b2), ("bm3", [Role.BRANCH_MANAGER], None, self.b3),
        ]:
            u = User(username=name, full_name=name.upper(), email=f"{name}@bank.test", phone="+254700000000",
                     password_hash=hash_password(PASSWORD), roles=[r.value for r in roles],
                     region_id=region.id if region else None, branch_id=branch.id if branch else None, is_active=True)
            db.add(u)
            db.flush()
            self.users[name] = u
            if branch is not None:
                branch.manager_id = u.id
        vendor = Vendor(name="Cisco")
        db.add(vendor)
        db.flush()
        self.models = {}
        for t, name in [("RTR", "ISR 4331"), ("SWT", "C9200"), ("SRV", "R650"), ("FWL", "FG100F"), ("EUD", "EliteDesk"),
                        ("UPS", "SRT3000")]:
            m = AssetModel(vendor_id=vendor.id, name=name, asset_type=t, is_standard=True,
                           eol_date=date.today() + timedelta(days=1000), eos_date=date.today() + timedelta(days=2000))
            db.add(m)
            db.flush()
            self.models[t] = m
        self.collector = Collector(name="collector-nrb", region_id=self.nrb.id, api_key_hash=hash_api_key(COLLECTOR_KEY),
                                   api_key_prefix=COLLECTOR_KEY[:12], last_heartbeat_at=utcnow())
        db.add(self.collector)
        db.flush()

    def u(self, name: str) -> User:
        return self.users[name]

    def active_asset(self, branch: Branch, asset_type: str = "RTR", serial: str | None = None, ip: str | None = None,
                     **kw):
        from itam.enums import AssetStatus
        from itam.services.assets import register_asset

        self._n = getattr(self, "_n", 0) + 1
        n = self._n
        serial = serial or f"SN-{branch.code}-{asset_type}-{n}"
        a = register_asset(self.db, self.u("itam"), branch=branch, asset_type=asset_type, serial_number=serial,
                           model_id=self.models.get(asset_type).id if asset_type in self.models else None,
                           initial_status=AssetStatus.ACTIVE, location_id=self.loc[branch.code][0].id,
                           ip_address=ip or f"10.0.{int(branch.code)}.{n}", hostname=f"{branch.code}-{asset_type}{n}",
                           mac_address=f"00:11:22:33:{int(branch.code) % 99:02d}:{n % 99:02d}", **kw)
        a.oper_state = "UP"
        a.last_seen_at = utcnow()
        self.db.flush()
        return a


@pytest.fixture()
def world(db):
    w = World(db)
    db.commit()
    return w


@pytest.fixture()
def app(settings):
    from itam.main import create_app

    return create_app(settings, start_scheduler=False)


@pytest.fixture()
def client(app):
    from fastapi.testclient import TestClient

    return TestClient(app)


def csrf_from(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, username: str, password: str = PASSWORD):
    page = client.get("/login")
    return client.post("/login", data={"username": username, "password": password, "csrf_token": csrf_from(page.text),
                                       "next": "/dashboard"}, follow_redirects=False)
