"""Demo data: ~100 branches across 5 regions, rollout waves, users for every role, and live-looking state.

Run with ``python -m itam.cli seed``. Deterministic (fixed random seed).
"""

from __future__ import annotations

import os
import random
import zlib
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.config import settings
from itam.enums import (
    RESPONSE_MINUTES,
    AlertCategory,
    AlertSource,
    AlertStatus,
    AssetStatus,
    ChangeType,
    OperState,
    RolloutStage,
    ROLLOUT_CHECKLIST,
    ROLLOUT_ORDER,
    Severity,
)
from itam.models import (
    Alert,
    AssetModel,
    Branch,
    Collector,
    Contract,
    JobRun,
    Location,
    Milestone,
    Region,
    User,
    Vendor,
    utcnow,
)
from itam.rbac import Role
from itam.security import hash_api_key, hash_password
from itam.services import assets as asset_svc
from itam.services import audits as audit_svc
from itam.services import changes as change_svc
from itam.services import discovery as disc_svc
from itam.services import monitoring as mon_svc
from itam.services import requests as req_svc

DEMO_PASSWORD = os.environ.get("ITAM_DEMO_PASSWORD") or "ChangeMe!2026"
# Bump when the demo dataset changes; a demo database tagged with an older version is replaced on start-up.
DEMO_DATA_VERSION = "cameroon-250-v1"
DEMO_MARKER = "demo_dataset"

# Cameroon: the 10 regions. (code, name, regional capital lat, lon, rollout wave, spread in degrees)
REGIONS = [
    ("LIT", "Littoral (Douala)", 4.0511, 9.7679, "WAVE1", 0.45),
    ("CEN", "Centre (Yaoundé)", 3.8480, 11.5021, "WAVE1", 0.55),
    ("OUE", "Ouest (Bafoussam)", 5.4781, 10.4176, "WAVE2", 0.35),
    ("SOW", "Sud-Ouest (Buea)", 4.1527, 9.2410, "WAVE2", 0.40),
    ("NOW", "Nord-Ouest (Bamenda)", 5.9631, 10.1591, "WAVE2", 0.40),
    ("SUD", "Sud (Ebolowa)", 2.9000, 11.1500, "WAVE2", 0.70),
    ("NOR", "Nord (Garoua)", 9.3014, 13.3977, "WAVE3", 0.80),
    ("EXN", "Extrême-Nord (Maroua)", 10.5956, 14.3247, "WAVE3", 0.60),
    ("ADA", "Adamaoua (Ngaoundéré)", 7.3277, 13.5847, "WAVE3", 0.80),
    ("EST", "Est (Bertoua)", 4.5785, 13.6846, "WAVE3", 1.00),
]
# 249 branches + head office = 250 sites, weighted by economic activity.
BRANCH_COUNTS = {"LIT": 60, "CEN": 55, "OUE": 25, "SOW": 20, "NOW": 18, "SUD": 14, "NOR": 15, "EXN": 15,
                 "ADA": 15, "EST": 12}
# Neighbourhoods of the two largest cities first (clustered near the city centre), then towns across the region.
CITY = {"LIT": "Douala", "CEN": "Yaoundé"}
TOWNS = {
    "LIT": ["Akwa", "Bonanjo", "Bonapriso", "Bonamoussadi", "Deido", "Bali", "Bonabéri", "Makepe", "Logpom", "Kotto",
            "Ndokoti", "Bépanda", "Ndogbong", "PK8", "PK14", "Bassa", "Yassa", "Japoma", "Logbaba",
            "Cité des Palmiers", "New Bell", "Mboppi", "Akwa Nord", "Denver", "Ange Raphaël", "Youpwé", "Nyalla",
            "Village", "Bonadibong", "Bessengué", "Koumassi", "Ndogpassi", "Kotto Bloc", "Beedi", "Maképé Missoké",
            "Grand Hangar", "Rond-point Deido", "Bonaloka", "Ndog-Bong", "Bonamikano", "Nkongsamba", "Edéa", "Loum",
            "Mbanga", "Manjo", "Penja", "Dibombari", "Yabassi", "Dizangué", "Mouanko", "Njombé", "Melong",
            "Nkongsamba Centre", "Edéa Centre", "Pouma", "Ngambé", "Massock", "Bonaléa", "Souza", "Ekité"],
    "CEN": ["Centre-ville", "Bastos", "Hippodrome", "Mvan", "Nlongkak", "Mvog-Mbi", "Mokolo", "Melen", "Biyem-Assi",
            "Essos", "Emana", "Etoudi", "Ekounou", "Omnisport", "Nsimeyong", "Mendong", "Odza", "Mimboman",
            "Nkolbisson", "Elig-Edzoa", "Tsinga", "Ngoa-Ekellé", "Mvog-Ada", "Olézoa", "Damas", "Efoulan",
            "Messassi", "Nkoabang", "Simbock", "Ahala", "Mvolyé", "Ngousso", "Nkomo", "Obili", "Briqueterie",
            "Mbalmayo", "Obala", "Bafia", "Eséka", "Akonolinga", "Monatélé", "Nanga-Eboko", "Ntui", "Mfou", "Soa",
            "Saa", "Ayos", "Makak", "Ngoumou", "Okola", "Mbandjock", "Évodoula", "Ombessa", "Yoko", "Esse"],
    "OUE": ["Bafoussam Centre", "Bafoussam Marché A", "Bafoussam Tamdja", "Dschang", "Mbouda", "Foumban", "Bafang",
            "Bangangté", "Foumbot", "Bandjoun", "Baham", "Bazou", "Kékem", "Penka-Michel", "Batié", "Bangou",
            "Koutaba", "Malantouen", "Galim", "Santchou", "Fokoué", "Bana", "Bamendjou", "Bafoussam Kouogouo",
            "Dschang Foto"],
    "SOW": ["Buea", "Buea Molyko", "Limbe", "Limbe Down Beach", "Kumba", "Kumba Fiango", "Tiko", "Mutengene",
            "Muyuka", "Mamfe", "Idenau", "Ekondo-Titi", "Mundemba", "Bangem", "Tombel", "Fontem", "Nguti", "Konye",
            "Mbonge", "Tiko Likomba"],
    "NOW": ["Bamenda Commercial Avenue", "Bamenda Nkwen", "Bamenda Up Station", "Bamenda Mile 4", "Kumbo", "Ndop",
            "Wum", "Nkambé", "Bali Nyonga", "Bafut", "Fundong", "Mbengwi", "Batibo", "Jakiri", "Santa",
            "Bamenda Food Market", "Bambui", "Bamenda Hospital Roundabout"],
    "SUD": ["Ebolowa", "Ebolowa Marché", "Kribi", "Kribi Port", "Sangmélima", "Sangmélima Centre", "Ambam",
            "Kyé-Ossi", "Lolodorf", "Campo", "Djoum", "Mvangan", "Zoétélé", "Akom II"],
    "NOR": ["Garoua Centre", "Garoua Marché", "Garoua Roumdé Adjia", "Garoua Yelwa", "Garoua Poumpoumré", "Guider",
            "Figuil", "Pitoa", "Lagdo", "Poli", "Tcholliré", "Touboro", "Rey Bouba", "Mayo-Oulo", "Bibémi"],
    "EXN": ["Maroua Domayo", "Maroua Djarengol", "Maroua Marché", "Mokolo", "Kousséri", "Mora", "Yagoua", "Kaélé",
            "Mindif", "Maga", "Makary", "Waza", "Doukoula", "Bogo", "Guidiguis"],
    "ADA": ["Ngaoundéré Centre", "Ngaoundéré Gare", "Ngaoundéré Marché", "Ngaoundéré Dang", "Meiganga", "Tibati",
            "Banyo", "Tignère", "Ngaoundal", "Mbé", "Dir", "Martap", "Belel", "Mbakaou", "Djohong"],
    "EST": ["Bertoua Centre", "Bertoua Marché", "Bertoua Tigaza", "Batouri", "Abong-Mbang", "Yokadouma",
            "Garoua-Boulaï", "Bélabo", "Doumé", "Lomié", "Kenzou", "Moloundou"],
}
# Demo prices are set in USD and converted to the configured currency (FCFA ≈ 600 per USD).
FX = {"XAF": 600, "XOF": 600, "USD": 1, "EUR": 0.92}.get(settings.currency, 1)
UNIT_COST_USD = {"RTR": 4800, "SWT": 2500, "FWL": 9500, "SRV": 18000, "UPS": 1200, "ATM": 32000, "EUD": 1200,
                 "ENV": 900, "STO": 15000, "WAP": 600}

MODELS = [
    # vendor, model, type, eol offset days, eos offset days
    ("Cisco", "ISR 4331", "RTR", 900, 1800),
    ("Cisco", "ISR 2901", "RTR", -900, 60),  # legacy, end of support soon
    ("Cisco", "Catalyst 9200-24P", "SWT", 1200, 2400),
    ("Cisco", "Catalyst 2960-X", "SWT", -600, 400),
    ("Fortinet", "FortiGate 100F", "FWL", 1300, 2500),
    ("Dell", "PowerEdge R650", "SRV", 1000, 2200),
    ("APC", "Smart-UPS SRT 3000", "UPS", 1500, 2600),
    ("NCR", "SelfServ 84", "ATM", 1400, 2800),
    ("HP", "EliteDesk 800 G6", "EUD", 700, 1500),
    ("APC", "NetBotz 250", "ENV", 1500, 2500),
]

BRANCH_KIT = [("RTR", 2), ("SWT", 2), ("FWL", 1), ("SRV", 1), ("UPS", 1), ("ATM", 2), ("EUD", 6), ("ENV", 1)]


def _user(db: Session, username: str, full_name: str, roles: list[Role], region: Region | None = None,
          branch: Branch | None = None) -> User:
    u = User(username=username, full_name=full_name, email=f"{username}@bank.local",
             phone=f"+2376{zlib.crc32(username.encode()) % 10**8:08d}", password_hash=hash_password(DEMO_PASSWORD),
             roles=[r.value for r in roles], region_id=region.id if region else None,
             branch_id=branch.id if branch else None, is_active=True)
    db.add(u)
    db.flush()
    return u


def demo_collector_key(region_code: str) -> str:
    return f"itamc_demo_{region_code.lower()}_collector_key"


def seed(db: Session, small: bool = False) -> dict:
    if db.execute(select(Region)).first():
        raise RuntimeError("Database already contains data; seed only an empty database")
    rnd = random.Random(42)
    now = utcnow()
    today = date.today()
    cc = settings.country_code

    regions = {}
    for code, name, *_ in REGIONS:
        regions[code] = Region(code=code, name=name, country_code=cc)
        db.add(regions[code])
    db.flush()

    # Head office + central store
    hq = Branch(code="0001", name="Head Office & Central Store (Bonanjo)", region_id=regions["LIT"].id, city="Douala",
                latitude=4.0429, longitude=9.6915, is_head_office=True, wave="PILOT",
                rollout_stage=RolloutStage.LIVE.value, rollout_checklist={}, went_live_at=now - timedelta(days=150))
    db.add(hq)
    db.flush()
    for building, floor, room, rack in [("HQ Tower", "B1", "Data centre", "DC-A1"), ("HQ Tower", "B1", "Data centre", "DC-A2"),
                                        ("HQ Tower", "G", "Central store", None), ("HQ Tower", "3", "NOC", None)]:
        db.add(Location(branch_id=hq.id, building=building, floor=floor, room=room, rack=rack))

    branches: list[Branch] = [hq]
    number = 2
    for code, _name, lat, lon, wave, spread in REGIONS:
        count = BRANCH_COUNTS[code] if not small else 3
        towns = TOWNS[code]
        city_parts = 40 if code == "LIT" else 35 if code == "CEN" else 0
        for i in range(count):
            town = towns[i % len(towns)] + ("" if i < len(towns) else f" {i // len(towns) + 1}")
            in_city = i < city_parts
            name = f"{CITY[code]} {town}" if in_city else town
            jitter = 0.07 if in_city else spread
            b = Branch(code=f"{number:04d}", name=f"{name} Branch", region_id=regions[code].id,
                       city=CITY[code] if in_city else town, latitude=round(lat + rnd.uniform(-jitter, jitter), 4),
                       longitude=round(lon + rnd.uniform(-jitter, jitter), 4), wave=wave,
                       rollout_stage=RolloutStage.NOT_STARTED.value, rollout_checklist={})
            if code == "LIT" and i < 5:
                b.wave = "PILOT"
            db.add(b)
            branches.append(b)
            number += 1
    db.flush()
    for b in branches[1:]:
        db.add(Location(branch_id=b.id, floor="G", room="Comms room", rack="R1"))
        db.add(Location(branch_id=b.id, floor="G", room="Banking hall"))
        db.add(Location(branch_id=b.id, floor="1", room="Back office"))
    db.flush()

    # Rollout progress: pilot + wave 1 live, wave 2 in progress, wave 3 not started.
    for b in branches[1:]:
        if b.wave in ("PILOT", "WAVE1"):
            b.rollout_stage = RolloutStage.LIVE.value
            b.went_live_at = now - timedelta(days=rnd.randint(20, 120))
        elif b.wave == "WAVE2":
            idx = branches.index(b)
            stage = [RolloutStage.LIVE] * 6 + [RolloutStage.SIGN_OFF, RolloutStage.VERIFY, RolloutStage.ON_SITE,
                                               RolloutStage.PREPARE]
            b.rollout_stage = stage[idx % len(stage)].value
            if b.rollout_stage == RolloutStage.LIVE.value:
                b.went_live_at = now - timedelta(days=rnd.randint(2, 18))
        if b.rollout_stage != RolloutStage.NOT_STARTED.value:
            done = {}
            for st in ROLLOUT_ORDER[1:ROLLOUT_ORDER.index(RolloutStage(b.rollout_stage))]:
                for item in ROLLOUT_CHECKLIST.get(st, []):
                    done[item] = True
            b.rollout_checklist = done
        b.planned_go_live = (b.went_live_at.date() + timedelta(days=rnd.choice([0, 0, 0, 2])) if b.went_live_at
                             else today + timedelta(days={"WAVE2": 20, "WAVE3": 90}.get(b.wave, 30) + rnd.randint(-10, 10)))

    # People
    admin = _user(db, "admin", "Platform Administrator", [Role.ADMIN])
    _user(db, "ceo", "Chief Executive Officer", [Role.EXECUTIVE])
    cio = _user(db, "cio", "Chief Information Officer", [Role.CIO])
    cfo = _user(db, "cfo", "Chief Financial Officer", [Role.CFO])
    head = _user(db, "head.infra", "Head of Infrastructure", [Role.HEAD_INFRA])
    _user(db, "ciso", "Chief Information Security Officer", [Role.CISO])
    itam = _user(db, "itam", "IT Asset Manager", [Role.IT_ASSET_MANAGER])
    users_by_role_noc = _user(db, "noc", "NOC Analyst", [Role.NOC])
    _user(db, "noc2", "NOC Analyst (night)", [Role.NOC])
    procurement = _user(db, "procurement", "Procurement Officer", [Role.PROCUREMENT])
    finance = _user(db, "finance", "Fixed-Asset Accountant", [Role.FINANCE])
    _user(db, "audit", "Internal Auditor", [Role.INTERNAL_AUDIT])
    leads, engineers = {}, {}
    for code, *_ in REGIONS:
        leads[code] = _user(db, f"lead.{code.lower()}", f"Regional IT Lead {code}", [Role.REGIONAL_LEAD], regions[code])
        engineers[code] = _user(db, f"eng.{code.lower()}", f"Regional IT Engineer {code}", [Role.REGIONAL_IT], regions[code])
    managers = {}
    for b in branches:
        m = _user(db, f"bm{b.code}", f"Branch Manager {b.name}", [Role.BRANCH_MANAGER], branch=b)
        b.manager_id = m.id
        managers[b.id] = m
    db.flush()

    # Catalogue & contracts
    vendors = {}
    models: dict[str, list[AssetModel]] = {}
    for vname, mname, mtype, eol, eos in MODELS:
        if vname not in vendors:
            vendors[vname] = Vendor(name=vname, support_portal=f"https://support.{vname.lower()}.com")
            db.add(vendors[vname])
            db.flush()
        m = AssetModel(vendor_id=vendors[vname].id, name=mname, asset_type=mtype, is_standard=eol > 0,
                       eol_date=today + timedelta(days=eol), eos_date=today + timedelta(days=eos))
        db.add(m)
        models.setdefault(mtype, []).append(m)
    contracts = []
    for i, (supplier, years) in enumerate([("Dimension Data", 3), ("CFAO Technologies", 3), ("Orange Business Cameroun", 2),
                                            ("NCR Afrique Centrale", 5), ("Dell Technologies", 3)]):
        start = today - timedelta(days=rnd.randint(200, 1000))
        c = Contract(reference=f"CON-{2023 + i % 3}-{i + 1:03d}", supplier=supplier, po_number=f"PO-{48000 + i}",
                     contract_type="WARRANTY", start_date=start, warranty_end=start + timedelta(days=365 * years),
                     support_end=start + timedelta(days=365 * years), cost=rnd.randint(2, 40) * 100000 * FX)
        db.add(c)
        contracts.append(c)
    db.flush()

    # Collectors (one per region) with deterministic demo keys.
    collectors = {}
    for code, *_ in REGIONS:
        key = demo_collector_key(code)
        collectors[code] = Collector(name=f"collector-{code.lower()}", region_id=regions[code].id,
                                     api_key_hash=hash_api_key(key), api_key_prefix=key[:12], last_heartbeat_at=now)
        db.add(collectors[code])
    db.flush()

    # Assets for branches that have reached on-site / later stages.
    onsite_or_later = {RolloutStage.ON_SITE.value, RolloutStage.VERIFY.value, RolloutStage.SIGN_OFF.value,
                       RolloutStage.LIVE.value}
    created = 0
    region_code = {r.id: r.code for r in regions.values()}
    for b in branches:
        if b.rollout_stage not in onsite_or_later:
            continue
        locs = db.execute(select(Location).where(Location.branch_id == b.id).order_by(Location.id)).scalars().all()
        comms, hall, office = locs[0], locs[1 % len(locs)], locs[-1]
        subnet = f"10.{20 + list(regions).index(region_code[b.region_id])}.{int(b.code) % 250}"
        host_no = 1
        kit = BRANCH_KIT if not b.is_head_office else [("RTR", 2), ("SWT", 4), ("FWL", 2), ("SRV", 6), ("UPS", 2)]
        for atype, qty in kit:
            for n in range(qty):
                options = models.get(atype)
                model = options[0] if len(options) == 1 or rnd.random() > 0.15 else options[1]
                installed_days = rnd.randint(30, 365 * 8)
                # Installed from Day +1 (verify) onwards; at "on site" the kit is delivered but not yet installed.
                live = b.rollout_stage in (RolloutStage.VERIFY.value, RolloutStage.SIGN_OFF.value, RolloutStage.LIVE.value)
                loc = hall if atype == "ATM" else office if atype == "EUD" else comms
                fields = dict(
                    location_id=loc.id, rack_u=f"U{2 * n + 1}" if loc is comms else None,
                    hostname=f"{b.code}-{atype.lower()}{n + 1:02d}" if atype != "EUD" else f"WS-{b.code}-{n + 1:02d}",
                    ip_address=f"{subnet}.{host_no}" if atype != "EUD" else None,
                    mac_address=":".join(f"{rnd.randint(0, 255):02x}" for _ in range(6)),
                    contract_id=rnd.choice(contracts).id if rnd.random() > 0.08 else None,
                    purchase_cost=float(UNIT_COST_USD[atype] * FX * rnd.choice([0.9, 1.0, 1.0, 1.1])),
                    finance_asset_ref=f"FA-{100000 + created}" if rnd.random() > 0.06 else None,
                    install_date=today - timedelta(days=installed_days) if live or b.is_head_office else None,
                    received_date=(today - timedelta(days=installed_days + 14) if live or b.is_head_office
                                   else today - timedelta(days=rnd.randint(2, 40))),
                    pci_scope=atype in ("ATM", "FWL", "SRV", "RTR"),
                    holds_customer_data=atype in ("SRV", "ATM", "STO"),
                )
                host_no += 1
                asset = asset_svc.register_asset(
                    db, itam, branch=b, asset_type=atype, serial_number=f"{atype[:2]}{b.code}{n:02d}{rnd.randint(10000, 99999)}",
                    model_id=model.id, initial_status=AssetStatus.ACTIVE if live or b.is_head_office else AssetStatus.IN_STOCK,
                    tag_applied=rnd.random() > 0.02, **fields)
                if live or b.is_head_office:
                    asset.oper_state = OperState.UP.value
                    asset.oper_state_since = now - timedelta(days=rnd.randint(1, 20))
                    asset.last_seen_at = now - timedelta(minutes=rnd.randint(1, 10))
                    if rnd.random() > 0.05:
                        asset.custodian_id = managers[b.id].id
                        asset.custody_accepted_by_id = managers[b.id].id
                        asset.custody_accepted_at = b.went_live_at
                created += 1
    db.flush()

    # Purchased stock held in the central store, not yet assigned to a branch (received over recent months).
    store_loc = db.execute(select(Location).where(Location.branch_id == hq.id,
                                                  Location.room == "Central store")).scalar_one().id
    for atype, qty, cost in (("RTR", 6, 4800.0), ("SWT", 8, 2500.0), ("FWL", 3, 9500.0), ("SRV", 2, 18000.0),
                             ("UPS", 5, 1200.0), ("EUD", 18, 1200.0), ("ATM", 2, 32000.0)):
        for _ in range(qty):
            asset_svc.register_asset(db, itam, branch=hq, asset_type=atype,
                                     serial_number=f"ST{atype}{rnd.randint(100000, 999999)}",
                                     model_id=models[atype][0].id, contract_id=contracts[0].id, purchase_cost=cost * FX,
                                     finance_asset_ref=f"FA-{200000 + rnd.randint(0, 9999)}", location_id=store_loc,
                                     received_date=today - timedelta(days=rnd.choice([3, 10, 21, 45, 75, 120, 200])))

    live_branches = [b for b in branches if b.rollout_stage == RolloutStage.LIVE.value and not b.is_head_office]

    # Historical outages for MTTD / MTTR trends (resolved).
    for i in range(46):
        b = rnd.choice(live_branches)
        occurred = now - timedelta(days=rnd.uniform(1, 55), minutes=rnd.randint(0, 600))
        detect = rnd.choice([1, 1, 2, 2, 2, 3, 3, 4, 6])
        user_reported = rnd.random() < 0.06
        a = Alert(dedup_key=f"HIST:{i}", severity=rnd.choice([Severity.P1.value, Severity.P2.value, Severity.P2.value]),
                  category=rnd.choice([AlertCategory.BRANCH_OFFLINE.value, AlertCategory.DEVICE_DOWN.value,
                                       AlertCategory.REDUNDANCY_LOST.value]),
                  source=AlertSource.USER_REPORT.value if user_reported else AlertSource.MONITORING.value,
                  title=f"Historical outage at {b.code} {b.name}", branch_id=b.id, status=AlertStatus.RESOLVED.value,
                  occurred_at=occurred, detected_at=occurred + timedelta(minutes=detect),
                  acknowledged_at=occurred + timedelta(minutes=detect + rnd.randint(2, 12)),
                  resolved_at=occurred + timedelta(minutes=rnd.randint(25, 300)), resolution="Link restored by carrier",
                  escalation_level=0)
        db.add(a)
    db.flush()
    for a in db.execute(select(Alert).where(Alert.dedup_key.like("HIST:%"))).scalars():
        a.ticket_ref = f"INC-{a.id:06d}"

    # Completed physical audits (last quarter) with realistic accuracy.
    for b in live_branches[:22]:
        audit = audit_svc.schedule_audit(db, itam, b, today - timedelta(days=rnd.randint(10, 80)))
        audit_svc.start_audit(db, engineers[region_code[b.region_id]], audit)
        for item in audit.items:
            if rnd.random() > 0.015:
                audit_svc.scan(db, engineers[region_code[b.region_id]], audit, item.asset.asset_number)
        audit_svc.complete_audit(db, engineers[region_code[b.region_id]], audit, "Quarterly cyclical audit")
        audit.completed_at = now - timedelta(days=rnd.randint(5, 80))
        audit_svc.attest(db, managers[b.id], b, "I confirm custody of all IT assets recorded at my branch.", audit)
    audit_svc.schedule_quarterly_cycle(db, itam, today + timedelta(days=3))

    # Live state: one branch offline, one degraded (backup link down), a faulty server, an env alarm.
    lit_live = [b for b in live_branches if b.region_id == regions["LIT"].id]
    offline_branch, degraded_branch = lit_live[7], lit_live[11]
    mon = collectors["LIT"]
    routers = [a for a in offline_branch.assets if a.asset_type == "RTR"]
    for r in routers:
        mon_svc.apply_state(db, r, OperState.DOWN, now - timedelta(minutes=9), mon, "ICMP timeout; BGP down")
    r2 = [a for a in degraded_branch.assets if a.asset_type == "RTR"][1]
    mon_svc.apply_state(db, r2, OperState.DOWN, now - timedelta(minutes=34), mon, "LTE backup link down")
    srv_branch = rnd.choice([b for b in live_branches if b.region_id == regions["CEN"].id] or live_branches)
    srv = [a for a in srv_branch.assets if a.asset_type == "SRV"][0]
    mon_svc.apply_state(db, srv, OperState.DOWN, now - timedelta(minutes=52), collectors["CEN"], "WinRM unreachable")
    env = [a for a in lit_live[3].assets if a.asset_type == "ENV"][0]
    mon_svc.ingest_poll_results(db, mon, [{"asset_number": env.asset_number, "metrics": {"temperature_c": 38.5},
                                           "occurred_at": (now - timedelta(minutes=12)).isoformat()}])

    # A core firewall down for over an hour with nobody responding: escalates all the way to the CEO.
    fw_branch = [b for b in live_branches if b.region_id == regions["OUE"].id][2]
    fw = [a for a in fw_branch.assets if a.asset_type == "FWL"][0]
    mon_svc.apply_state(db, fw, OperState.DOWN, now - timedelta(minutes=78), collectors["OUE"], "HA heartbeat lost")

    # Collectors poll every minute: live alerts were detected 1-2 minutes after the failure.
    for a in db.execute(select(Alert).where(Alert.status == AlertStatus.OPEN.value)).scalars():
        a.detected_at = min(a.occurred_at + timedelta(minutes=rnd.choice([1, 2])), now)
        for e in a.escalations:
            e.at = a.detected_at
    # The NOC picked up the environment alarm quickly, so it did not escalate.
    env_alert = db.execute(select(Alert).where(Alert.category == "ENVIRONMENT")).scalars().first()
    if env_alert:
        mon_svc.acknowledge(db, users_by_role_noc, env_alert)
        env_alert.acknowledged_at = env_alert.detected_at + timedelta(minutes=4)
    # Run the escalation timer as the scheduler would have, timestamping each step when it fell due.
    mon_svc.escalate_overdue(db, now)
    for a in db.execute(select(Alert).where(Alert.status == AlertStatus.OPEN.value)).scalars():
        target = timedelta(minutes=RESPONSE_MINUTES[Severity(a.severity)])
        for e in a.escalations:
            if e.reason.startswith("Not acknowledged"):
                e.at = a.detected_at + target * e.level
                e.reason = f"Not acknowledged within {int((target * e.level).total_seconds() // 60)} min"

    # Missing assets: not seen for 4 days, no approved change.
    for b in (lit_live[2], lit_live[15]):
        victim = [a for a in b.assets if a.asset_type == "SWT"][1]
        victim.last_seen_at = now - timedelta(days=4)
    disc_svc.detect_missing(db, now)

    # Rogue devices found by discovery.
    for b, host in ((lit_live[4], "unknown-ap"), (lit_live[9], "android-hotspot"), (live_branches[-1], "rpi-4b")):
        expected = disc_svc.expected_on_network(db, b)
        devices = [{"serial": a.serial_number, "mac": a.mac_address, "ip": a.ip_address} for a in expected
                   if a.status != AssetStatus.MISSING.value]
        devices.append({"ip": f"10.99.{int(b.code)}.200", "mac": ":".join(f"{rnd.randint(0, 255):02x}" for _ in range(6)),
                        "hostname": host, "vendor": "Unknown"})
        coll = collectors[region_code[b.region_id]]
        disc_svc.ingest_discovery(db, coll, b.code, devices, now.isoformat())

    # Workflows in various states.
    some = live_branches[20]
    eng = engineers[region_code[some.region_id]]
    ups = [a for a in some.assets if a.asset_type == "UPS"][0]
    change_svc.create_change(db, eng, ups, ChangeType.SEND_REPAIR, "Battery fails self-test", ticket_ref="CHG-T-1001")
    legacy = next((a for b in live_branches for a in b.assets if a.model and a.model.name == "ISR 2901"), None)
    if legacy:
        c = change_svc.create_change(db, engineers[region_code[legacy.branch.region_id]], legacy, ChangeType.RETIRE,
                                     "End of support — replaced by ISR 4331", ticket_ref="CHG-T-1002")
        change_svc.decide(db, head, c, True, "Replacement in place")
    eud = [a for a in live_branches[5].assets if a.asset_type == "EUD"][0]
    t = change_svc.create_change(db, engineers["LIT"], eud, ChangeType.TRANSFER_BRANCH, "Staff relocation",
                                 to_branch=live_branches[6])
    change_svc.decide(db, managers[live_branches[5].id], t, True, "OK")
    change_svc.decide(db, itam, t, True, "OK")
    change_svc.execute(db, engineers["LIT"], t, eud.asset_number, evidence_ref="TN-2026-0311")  # now in transit
    # A completed disposal awaiting Finance confirmation.
    old = [a for a in live_branches[8].assets if a.asset_type == "EUD"][1]
    rc = change_svc.create_change(db, engineers["LIT"], old, ChangeType.RETIRE, "Beyond economic repair",
                                  ticket_ref="CHG-T-1003")
    change_svc.decide(db, leads["LIT"], rc, True, "Agreed")
    change_svc.decide(db, itam, rc, True, "Agreed")
    change_svc.execute(db, engineers["LIT"], rc, old.asset_number, ticket_ref="CHG-T-1003")
    dc = change_svc.create_change(db, itam, old, ChangeType.DISPOSE, "WEEE disposal batch Q3")
    change_svc.decide(db, cio, dc, True, "Approved")
    change_svc.decide(db, cfo, dc, True, "Approved")
    change_svc.execute(db, engineers["LIT"], dc, old.asset_number, wipe_certificate_ref="WIPE-2026-0042",
                       disposal_certificate_ref="WEEE-2026-0107")

    req_svc.create_request(db, managers[live_branches[12].id], branch=live_branches[12], asset_type="EUD",
                                quantity=3, justification="New tellers joining", model_id=models["EUD"][0].id,
                                estimated_cost=3600 * FX)
    r2 = req_svc.create_request(db, engineers["CEN"], branch=[b for b in branches if b.region_id == regions["CEN"].id][0],
                                asset_type="RTR", quantity=1, justification="Replace ISR 2901 (end of support)",
                                model_id=models["RTR"][0].id, estimated_cost=4800 * FX)
    req_svc.approve(db, itam, r2, "it")
    req_svc.approve(db, finance, r2, "budget")
    req_svc.record_po(db, procurement, r2, "PO-2026-0457", "Dimension Data")

    # Programme milestones (decision gates G1-G5) and budget.
    start = today - timedelta(days=200)
    for code, name, phase, month, actual_delta, planned_budget, actual_budget in [
        ("G1", "Business case approved", "Phase 0 – Mobilise & baseline", 1, 0, 50000, 48000),
        ("G2", "Vendor selected", "Phase 1 – Design & select", 3, 6, 120000, 126000),
        ("G3", "Pilot exit", "Phase 2 – Build & pilot", 5, 0, 450000, 470000),
        ("G4", "Rollout done", "Phase 3 – Rollout waves 1-3", 10, None, 900000, None),
        ("G5", "BAU handover", "Phase 4 – Stabilise & handover", 12, None, 150000, None),
    ]:
        planned = start + timedelta(days=30 * month)
        db.add(Milestone(code=code, name=name, phase=phase, planned_date=planned,
                         actual_date=planned + timedelta(days=actual_delta) if actual_delta is not None else None,
                         budget_planned=planned_budget * FX,
                         budget_actual=actual_budget * FX if actual_budget is not None else None))

    db.merge(JobRun(name=DEMO_MARKER, last_run_at=now, last_result=DEMO_DATA_VERSION))
    auditlog.record(db, admin, "system.seed", "system", None, branches=len(branches), assets=created,
                    dataset=DEMO_DATA_VERSION)
    return {"branches": len(branches), "assets": created, "users": len(db.execute(select(User)).scalars().all())}
