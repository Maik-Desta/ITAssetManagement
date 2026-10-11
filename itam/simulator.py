"""Demo collector simulator: posts heartbeats, poll results and discovery scans to a running ITAM instance.

Uses the deterministic demo collector keys created by ``itam.cli seed``. Not for production use — real
collectors (SNMPv3/ICMP/syslog pollers) post the same payloads to ``/api/v1/collector/*``.

    python -m itam.simulator --url http://127.0.0.1:8000 --cycles 10 --interval 30
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import select

from itam.config import settings
from itam.db import init_engine, session_scope
from itam.enums import NETWORK_TYPES, AssetStatus
from itam.models import Asset, Collector
from itam.seed import demo_collector_key


def _post(base: str, path: str, key: str, payload) -> dict:
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-API-Key": key})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - operator-supplied URL
        return json.loads(resp.read())


def snapshot() -> dict[str, dict[str, list[dict]]]:
    """{region_code: {branch_code: [device dicts]}} for monitored, installed network devices."""
    out: dict[str, dict[str, list[dict]]] = {}
    with session_scope() as db:
        rows = db.execute(select(Asset).where(
            Asset.monitored.is_(True), Asset.asset_type.in_([t.value for t in NETWORK_TYPES]),
            Asset.status.in_([AssetStatus.ACTIVE.value, AssetStatus.FAULTY.value]))).scalars().all()
        for a in rows:
            out.setdefault(a.branch.region.code, {}).setdefault(a.branch.code, []).append(
                {"asset_number": a.asset_number, "serial": a.serial_number, "mac": a.mac_address, "ip": a.ip_address,
                 "hostname": a.hostname, "type": a.asset_type})
        names = {c.region.code: c.name for c in db.execute(select(Collector)).scalars() if c.region}
    return {r: v for r, v in out.items() if r in names}


def run(base: str, cycles: int, interval: int, fault_rate: float) -> None:
    rnd = random.Random()
    estate = snapshot()
    for cycle in range(cycles):
        now = datetime.now(timezone.utc).isoformat()
        for region, branches in estate.items():
            key = demo_collector_key(region)
            _post(base, "/api/v1/collector/heartbeat", key, {})
            results = []
            for devices in branches.values():
                for d in devices:
                    state = "DOWN" if rnd.random() < fault_rate else "UP"
                    metrics = {"cpu_pct": rnd.randint(3, 70)}
                    if d["type"] == "ENV":
                        metrics["temperature_c"] = round(rnd.uniform(21, 36), 1)
                    results.append({"asset_number": d["asset_number"], "state": state, "occurred_at": now,
                                    "metrics": metrics})
            r = _post(base, "/api/v1/collector/poll", key, results)
            print(f"cycle {cycle + 1} {region}: poll {r}")
            if cycle % 3 == 0:  # discovery less often than polling
                for code, devices in branches.items():
                    seen = [{k: d[k] for k in ("serial", "mac", "ip", "hostname")} for d in devices]
                    _post(base, "/api/v1/collector/discovery", key, {"branch_code": code, "run_at": now, "devices": seen})
        if cycle + 1 < cycles:
            time.sleep(interval)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--cycles", type=int, default=5)
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--fault-rate", type=float, default=0.002)
    args = p.parse_args()
    init_engine(settings.database_url)
    run(args.url, args.cycles, args.interval, args.fault_rate)


if __name__ == "__main__":
    main()
