"""Scheduled jobs (audit scheduler / monitoring engine housekeeping)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from itam.db import session_scope
from itam.models import JobRun, utcnow
from itam.notifications import deliver_queued
from itam.services.discovery import detect_missing, weekly_exception_report
from itam.services.logistics import overdue_shipments
from itam.services.monitoring import check_collectors, escalate_overdue, warranty_and_eol_alerts
from itam.services.security import check_readers

log = logging.getLogger(__name__)


@dataclass
class Job:
    name: str
    interval: timedelta
    func: Callable[[Session], object]
    description: str


JOBS: list[Job] = [
    Job("escalate_alerts", timedelta(minutes=1), lambda db: escalate_overdue(db),
        "Escalate unacknowledged alerts (engineer → regional lead → Head of Infra → CIO); security alarms every 5 min"),
    Job("deliver_notifications", timedelta(minutes=1), lambda db: deliver_queued(db),
        "Send queued e-mail / SMS / chat notifications"),
    Job("check_collectors", timedelta(minutes=5), lambda db: check_collectors(db),
        "Alert when a regional collector stops reporting"),
    Job("check_readers", timedelta(minutes=5), lambda db: check_readers(db),
        "Alert when a fixed RFID reader stops reporting (offline or tampered)"),
    Job("overdue_shipments", timedelta(minutes=15), lambda db: overdue_shipments(db),
        "Alert the ITAM Office and Security when a delivery is past its ETA"),
    Job("detect_missing", timedelta(minutes=15), lambda db: detect_missing(db),
        "Mark devices not seen for > 72 h without approved change as Missing"),
    Job("warranty_eol", timedelta(days=1), lambda db: warranty_and_eol_alerts(db),
        "Raise P4 alerts for warranty expiry / end of support within 90 days"),
    Job("weekly_exception_report", timedelta(days=7), lambda db: weekly_exception_report(db),
        "Send open exceptions with ageing to regional managers"),
]


def run_job(job: Job) -> str:
    with session_scope() as db:
        result = job.func(db)
        run = db.get(JobRun, job.name) or JobRun(name=job.name)
        run.last_run_at = utcnow()
        run.last_result = str(result)
        db.merge(run)
    return str(result)


def due_jobs(now: datetime | None = None) -> list[Job]:
    now = now or utcnow()
    with session_scope() as db:
        last = {r.name: r.last_run_at for r in db.query(JobRun).all()}
    return [j for j in JOBS if not last.get(j.name) or now - last[j.name] >= j.interval]


def run_due_jobs() -> dict[str, str]:
    results = {}
    for job in due_jobs():
        try:
            results[job.name] = run_job(job)
        except Exception:  # noqa: BLE001 - one failing job must not stop the others
            log.exception("Job %s failed", job.name)
            results[job.name] = "error"
    return results


async def scheduler_loop(interval_seconds: int) -> None:
    while True:
        await asyncio.to_thread(run_due_jobs)
        await asyncio.sleep(interval_seconds)
