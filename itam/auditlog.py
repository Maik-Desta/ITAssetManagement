"""Immutable, hash-chained audit log.

Every state-changing action writes one entry. Each entry's hash covers its content and the
previous entry's hash, so any tampering breaks the chain (verified by ``verify_chain``).
Database triggers additionally reject UPDATE and DELETE on the table.
"""

from __future__ import annotations

import hashlib
import json
import logging
import logging.handlers
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from itam.config import settings
from itam.models import AuditLogEntry, User, utcnow

GENESIS = "0" * 64
_siem_logger: logging.Logger | None = None


def _siem() -> logging.Logger | None:
    """Syslog forwarder to the SIEM / SOC, if configured (ITAM_SIEM_SYSLOG=host:port)."""
    global _siem_logger
    if not settings.siem_syslog:
        return None
    if _siem_logger is None:
        host, _, port = settings.siem_syslog.partition(":")
        logger = logging.getLogger("itam.siem")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(logging.handlers.SysLogHandler(address=(host, int(port or 514))))
        _siem_logger = logger
    return _siem_logger


def _digest(prev_hash: str, at: str, actor: str, action: str, entity_type: str,
            entity_id: str | None, details: dict) -> str:
    payload = json.dumps(
        {"prev": prev_hash, "at": at, "actor": actor, "action": action, "type": entity_type,
         "id": entity_id, "details": details},
        sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def record(db: Session, actor: User | str | None, action: str, entity_type: str,
           entity_id: Any = None, **details: Any) -> AuditLogEntry:
    """Append an entry to the audit log (in the caller's transaction)."""
    actor_name = actor.username if isinstance(actor, User) else (actor or "system")
    details = json.loads(json.dumps(details, default=str))
    if db.get_bind().dialect.name == "postgresql":
        # Serialise writers so concurrent transactions cannot fork the hash chain.
        db.execute(text("SELECT pg_advisory_xact_lock(19770)"))
    last = db.execute(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(1)).scalar_one_or_none()
    prev_hash = last.hash if last else GENESIS
    at = utcnow()
    eid = str(entity_id) if entity_id is not None else None
    entry = AuditLogEntry(
        at=at, actor=actor_name, action=action, entity_type=entity_type, entity_id=eid,
        details=details, prev_hash=prev_hash,
        hash=_digest(prev_hash, at.isoformat(), actor_name, action, entity_type, eid, details),
    )
    db.add(entry)
    db.flush()
    siem = _siem()
    if siem:
        siem.info("ITAM audit actor=%s action=%s %s=%s %s", actor_name, action, entity_type, eid,
                  json.dumps(details, default=str))
    return entry


def verify_chain(db: Session) -> tuple[bool, int, int | None]:
    """Recompute the chain. Returns (ok, entries_checked, first_bad_id)."""
    prev = GENESIS
    count = 0
    for entry in db.execute(select(AuditLogEntry).order_by(AuditLogEntry.id)).scalars():
        count += 1
        expected = _digest(prev, entry.at.isoformat(), entry.actor, entry.action, entry.entity_type,
                           entry.entity_id, entry.details)
        if entry.prev_hash != prev or entry.hash != expected:
            return False, count, entry.id
        prev = entry.hash
    return True, count, None


def install_immutability_guards(engine: Engine) -> None:
    """Create triggers that make the audit log append-only."""
    dialect = engine.dialect.name
    with engine.begin() as conn:
        if dialect == "sqlite":
            for op in ("UPDATE", "DELETE"):
                conn.execute(text(
                    f"CREATE TRIGGER IF NOT EXISTS audit_log_no_{op.lower()} BEFORE {op} ON audit_log "
                    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
                ))
        elif dialect == "postgresql":
            conn.execute(text(
                "CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$ "
                "BEGIN RAISE EXCEPTION 'audit_log is append-only'; END; $$ LANGUAGE plpgsql;"
            ))
            conn.execute(text("DROP TRIGGER IF EXISTS audit_log_no_modify ON audit_log"))
            conn.execute(text(
                "CREATE TRIGGER audit_log_no_modify BEFORE UPDATE OR DELETE ON audit_log "
                "FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();"
            ))
