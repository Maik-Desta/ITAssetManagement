"""Rollout tracking: the repeatable 'branch day' playbook and wave progress (slides 30-31)."""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam import auditlog
from itam.enums import ROLLOUT_CHECKLIST, ROLLOUT_ORDER, RolloutStage
from itam.models import Attestation, Branch, User, utcnow
from itam.rbac import Role, acts_for_branch, can
from itam.services import PermissionDenied, ServiceError

WAVES = ["PILOT", "WAVE1", "WAVE2", "WAVE3"]
WAVE_LABELS = {"PILOT": "Pilot (HQ + 5 branches)", "WAVE1": "Wave 1 – Capital", "WAVE2": "Wave 2 – Regions A/B",
               "WAVE3": "Wave 3 – Remaining regions"}


def _check(actor: User, branch: Branch) -> None:
    if not can(actor, "rollout.manage"):
        raise PermissionDenied("You may not manage the rollout")
    if not (actor.has_role(Role.IT_ASSET_MANAGER) or acts_for_branch(actor, Role.REGIONAL_LEAD, branch)
            or acts_for_branch(actor, Role.REGIONAL_IT, branch)):
        raise PermissionDenied("Branch outside your region")


def toggle_item(db: Session, actor: User, branch: Branch, item: str, done: bool) -> Branch:
    _check(actor, branch)
    stage = RolloutStage(branch.rollout_stage)
    if stage not in ROLLOUT_CHECKLIST or item not in ROLLOUT_CHECKLIST[stage]:
        raise ServiceError("Checklist item does not belong to the current stage")
    checklist = dict(branch.rollout_checklist or {})
    checklist[item] = bool(done)
    branch.rollout_checklist = checklist
    auditlog.record(db, actor, "rollout.check", "branch", branch.code, stage=stage.value, item=item, done=done)
    return branch


def advance(db: Session, actor: User, branch: Branch) -> Branch:
    _check(actor, branch)
    stage = RolloutStage(branch.rollout_stage)
    if stage == RolloutStage.LIVE:
        raise ServiceError("Branch is already live")
    pending = [i for i in ROLLOUT_CHECKLIST.get(stage, []) if not (branch.rollout_checklist or {}).get(i)]
    if pending:
        raise ServiceError("Complete the checklist first: " + "; ".join(pending))
    nxt = ROLLOUT_ORDER[ROLLOUT_ORDER.index(stage) + 1]
    if nxt == RolloutStage.LIVE:
        attested = db.execute(select(Attestation).where(Attestation.branch_id == branch.id)).scalars().first()
        if attested is None:
            raise ServiceError("Branch manager must attest custody before the branch goes live")
        branch.went_live_at = utcnow()
    branch.rollout_stage = nxt.value
    auditlog.record(db, actor, "rollout.advance", "branch", branch.code, stage=nxt.value)
    return branch


def wave_summary(db: Session) -> list[dict]:
    branches = db.execute(select(Branch)).scalars().all()
    stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for b in branches:
        stats[b.wave or "UNASSIGNED"][b.rollout_stage] += 1
        stats[b.wave or "UNASSIGNED"]["total"] += 1
    rows = []
    for wave in WAVES + (["UNASSIGNED"] if "UNASSIGNED" in stats else []):
        s = stats.get(wave, {})
        total = s.get("total", 0)
        live = s.get(RolloutStage.LIVE.value, 0)
        rows.append({"wave": wave, "label": WAVE_LABELS.get(wave, "Unassigned"), "total": total, "live": live,
                     "in_progress": total - live - s.get(RolloutStage.NOT_STARTED.value, 0),
                     "pct": round(100 * live / total) if total else 0,
                     "stages": {st.value: s.get(st.value, 0) for st in ROLLOUT_ORDER}})
    return rows
