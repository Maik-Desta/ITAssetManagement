"""Demo dataset lifecycle: load into an empty DB, replace an outdated demo, never touch real data."""

from sqlalchemy import func, select

from itam import main
from itam.models import Branch, JobRun, Region, User


def _fake_seed(db, small=False):
    from itam.seed import DEMO_DATA_VERSION, DEMO_MARKER

    db.add(Region(code="LIT", name="Littoral (Douala)", country_code="CM"))
    db.merge(JobRun(name=DEMO_MARKER, last_result=DEMO_DATA_VERSION))
    db.flush()
    return {"branches": 0, "assets": 0, "users": 0}


def test_real_data_is_never_replaced(db, world, monkeypatch):
    monkeypatch.setattr("itam.seed.seed", _fake_seed)
    assert main.demo_data_status() == "foreign"
    assert main.prepare_demo_data() == "foreign"
    db.expire_all()
    assert db.execute(select(func.count(User.id))).scalar() == len(world.users)


def test_empty_database_gets_demo_data(db, monkeypatch):
    monkeypatch.setattr("itam.seed.seed", _fake_seed)
    assert main.demo_data_status() == "empty"
    assert main.prepare_demo_data() == "loaded"
    assert main.demo_data_status() == "current"
    assert main.prepare_demo_data() == "current"  # restarts do nothing


def test_legacy_kenya_demo_is_replaced(db, monkeypatch):
    monkeypatch.setattr("itam.seed.seed", _fake_seed)
    nrb = Region(code="NRB", name="Nairobi (Capital)", country_code="KE")
    db.add(nrb)
    db.flush()
    db.add(Branch(code="0001", name="Head Office & Central Store", region_id=nrb.id, is_head_office=True,
                  rollout_stage="LIVE", rollout_checklist={}))
    db.commit()
    assert main.demo_data_status() == "outdated"
    assert main.prepare_demo_data() == "replaced"
    db.close()
    from itam.db import new_session

    fresh = new_session()
    assert [r.code for r in fresh.execute(select(Region)).scalars()] == ["LIT"]
    fresh.close()


def test_older_tagged_demo_is_replaced(db, monkeypatch):
    from itam.seed import DEMO_MARKER

    monkeypatch.setattr("itam.seed.seed", _fake_seed)
    db.add(Region(code="XXX", name="Old demo", country_code="CM"))
    db.add(JobRun(name=DEMO_MARKER, last_result="some-older-version"))
    db.commit()
    assert main.demo_data_status() == "outdated"
    assert main.prepare_demo_data() == "replaced"
