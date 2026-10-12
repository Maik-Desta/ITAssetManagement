"""Core data model (slide 16) plus workflow, monitoring, audit and governance entities."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from itam.db import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (stored consistently across SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


# ---------------------------------------------------------------------------
# Organisation
# ---------------------------------------------------------------------------


class Region(Base):
    __tablename__ = "regions"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(3), unique=True)  # RRR
    name: Mapped[str] = mapped_column(String(100))
    country_code: Mapped[str] = mapped_column(String(2))  # CC

    branches: Mapped[list[Branch]] = relationship(back_populates="region", order_by="Branch.code")


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(4), unique=True)  # BBBB
    name: Mapped[str] = mapped_column(String(120))
    region_id: Mapped[int] = mapped_column(ForeignKey("regions.id"))
    city: Mapped[str | None] = mapped_column(String(80))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    is_head_office: Mapped[bool] = mapped_column(Boolean, default=False)
    manager_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", use_alter=True))

    # Rollout (slides 30-31)
    wave: Mapped[str | None] = mapped_column(String(20))  # PILOT, WAVE1, WAVE2, WAVE3
    rollout_stage: Mapped[str] = mapped_column(String(20), default="NOT_STARTED")
    rollout_checklist: Mapped[dict] = mapped_column(JSON, default=dict)
    planned_go_live: Mapped[date | None] = mapped_column(Date)
    went_live_at: Mapped[datetime | None] = mapped_column(DateTime)

    region: Mapped[Region] = relationship(back_populates="branches")
    manager: Mapped[User | None] = relationship(foreign_keys=[manager_id])
    locations: Mapped[list[Location]] = relationship(back_populates="branch", order_by="Location.id")
    assets: Mapped[list[Asset]] = relationship(back_populates="branch", foreign_keys="Asset.branch_id")


class Location(Base):
    __tablename__ = "locations"

    id: Mapped[int] = mapped_column(primary_key=True)
    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"))
    building: Mapped[str | None] = mapped_column(String(80))
    floor: Mapped[str | None] = mapped_column(String(20))
    room: Mapped[str | None] = mapped_column(String(80))
    rack: Mapped[str | None] = mapped_column(String(40))

    branch: Mapped[Branch] = relationship(back_populates="locations")

    @property
    def label(self) -> str:
        parts = [p for p in (self.building, f"Floor {self.floor}" if self.floor else None, self.room,
                             f"Rack {self.rack}" if self.rack else None) if p]
        return " / ".join(parts) or f"Location #{self.id}"


# ---------------------------------------------------------------------------
# People
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(60), unique=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str | None] = mapped_column(String(160))
    phone: Mapped[str | None] = mapped_column(String(40))
    password_hash: Mapped[str] = mapped_column(String(255))
    roles: Mapped[list] = mapped_column(JSON, default=list)
    # Scope: regional staff are limited to a region, branch managers to a branch.
    region_id: Mapped[int | None] = mapped_column(ForeignKey("regions.id"))
    branch_id: Mapped[int | None] = mapped_column(ForeignKey("branches.id", use_alter=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    left_at: Mapped[datetime | None] = mapped_column(DateTime)  # HR leaver feed

    region: Mapped[Region | None] = relationship(foreign_keys=[region_id])
    branch: Mapped[Branch | None] = relationship(foreign_keys=[branch_id])

    def has_role(self, *roles: str) -> bool:
        return any(r in (self.roles or []) for r in roles)


# ---------------------------------------------------------------------------
# Catalogue, contracts
# ---------------------------------------------------------------------------


class Vendor(Base):
    __tablename__ = "vendors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    support_portal: Mapped[str | None] = mapped_column(String(255))
    support_phone: Mapped[str | None] = mapped_column(String(40))

    models: Mapped[list[AssetModel]] = relationship(back_populates="vendor")


class AssetModel(Base):
    __tablename__ = "asset_models"

    id: Mapped[int] = mapped_column(primary_key=True)
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id"))
    name: Mapped[str] = mapped_column(String(120))
    asset_type: Mapped[str] = mapped_column(String(3))
    is_standard: Mapped[bool] = mapped_column(Boolean, default=True)  # approved standard model
    eol_date: Mapped[date | None] = mapped_column(Date)  # end of life (sale)
    eos_date: Mapped[date | None] = mapped_column(Date)  # end of support

    vendor: Mapped[Vendor] = relationship(back_populates="models")

    @property
    def display(self) -> str:
        return f"{self.vendor.name} {self.name}"


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(60), unique=True)
    supplier: Mapped[str] = mapped_column(String(120))
    po_number: Mapped[str | None] = mapped_column(String(60))
    contract_type: Mapped[str] = mapped_column(String(30), default="WARRANTY")  # WARRANTY / SUPPORT / LEASE
    cost: Mapped[float | None] = mapped_column(Numeric(14, 2))
    start_date: Mapped[date | None] = mapped_column(Date)
    warranty_end: Mapped[date | None] = mapped_column(Date)
    support_end: Mapped[date | None] = mapped_column(Date)


# ---------------------------------------------------------------------------
# Asset (configuration item)
# ---------------------------------------------------------------------------


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    serial_number: Mapped[str] = mapped_column(String(80), index=True)
    asset_type: Mapped[str] = mapped_column(String(3), index=True)
    model_id: Mapped[int | None] = mapped_column(ForeignKey("asset_models.id"))
    hostname: Mapped[str | None] = mapped_column(String(120))
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True, default="IN_STOCK")
    criticality: Mapped[str] = mapped_column(String(10), default="MEDIUM")
    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), index=True)
    location_id: Mapped[int | None] = mapped_column(ForeignKey("locations.id"))
    rack_u: Mapped[str | None] = mapped_column(String(10))  # U-position
    custodian_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    contract_id: Mapped[int | None] = mapped_column(ForeignKey("contracts.id"))
    request_id: Mapped[int | None] = mapped_column(ForeignKey("equipment_requests.id"))

    purchase_cost: Mapped[float | None] = mapped_column(Numeric(14, 2))
    warranty_end: Mapped[date | None] = mapped_column(Date)  # overrides contract warranty if set
    finance_asset_ref: Mapped[str | None] = mapped_column(String(60), index=True)  # fixed-asset register no.
    pci_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    holds_customer_data: Mapped[bool] = mapped_column(Boolean, default=False)

    received_date: Mapped[date | None] = mapped_column(Date)
    tag_applied_at: Mapped[datetime | None] = mapped_column(DateTime)
    install_date: Mapped[date | None] = mapped_column(Date)
    install_checklist: Mapped[dict] = mapped_column(JSON, default=dict)  # SNMPv3, syslog, NTP, hardened
    go_live_verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    custody_accepted_at: Mapped[datetime | None] = mapped_column(DateTime)
    custody_accepted_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    # Monitoring
    monitored: Mapped[bool] = mapped_column(Boolean, default=False)
    oper_state: Mapped[str] = mapped_column(String(10), default="UNKNOWN")
    oper_state_since: Mapped[datetime | None] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)  # last seen by discovery/polling
    last_metrics: Mapped[dict] = mapped_column(JSON, default=dict)

    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    branch: Mapped[Branch] = relationship(back_populates="assets", foreign_keys=[branch_id])
    location: Mapped[Location | None] = relationship()
    model: Mapped[AssetModel | None] = relationship()
    custodian: Mapped[User | None] = relationship(foreign_keys=[custodian_id])
    custody_accepted_by: Mapped[User | None] = relationship(foreign_keys=[custody_accepted_by_id])
    contract: Mapped[Contract | None] = relationship()
    history: Mapped[list[AssetHistory]] = relationship(back_populates="asset",
                                                       order_by="AssetHistory.id.desc()")

    @property
    def effective_warranty_end(self) -> date | None:
        if self.warranty_end:
            return self.warranty_end
        return self.contract.warranty_end if self.contract else None

    @property
    def eol_date(self) -> date | None:
        return self.model.eol_date if self.model else None

    @property
    def eos_date(self) -> date | None:
        return self.model.eos_date if self.model else None


class AssetHistory(Base):
    """Per-asset timeline (status changes, moves, custody). Complements the global audit log."""

    __tablename__ = "asset_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    event: Mapped[str] = mapped_column(String(40))
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str | None] = mapped_column(String(20))
    detail: Mapped[str | None] = mapped_column(Text)

    asset: Mapped[Asset] = relationship(back_populates="history")
    actor: Mapped[User | None] = relationship()


class NumberSequence(Base):
    """Next NNNNN per CC-RRR-BBBB-TTT prefix."""

    __tablename__ = "number_sequences"

    prefix: Mapped[str] = mapped_column(String(24), primary_key=True)
    next_value: Mapped[int] = mapped_column(Integer, default=1)


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------


class EquipmentRequest(Base):
    """New equipment: request & approve → procure → receive & tag (slide 19, steps 1-4)."""

    __tablename__ = "equipment_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(20), unique=True)
    requester_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"))
    asset_type: Mapped[str] = mapped_column(String(3))
    model_id: Mapped[int | None] = mapped_column(ForeignKey("asset_models.id"))
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    justification: Mapped[str] = mapped_column(Text)
    estimated_cost: Mapped[float | None] = mapped_column(Numeric(14, 2))
    status: Mapped[str] = mapped_column(String(20), default="PENDING_APPROVAL")
    it_approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    it_approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    budget_approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    budget_approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    rejected_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    po_number: Mapped[str | None] = mapped_column(String(60))
    supplier: Mapped[str | None] = mapped_column(String(120))
    contract_id: Mapped[int | None] = mapped_column(ForeignKey("contracts.id"))
    received_quantity: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    it_approver: Mapped[User | None] = relationship(foreign_keys=[it_approver_id])
    budget_approver: Mapped[User | None] = relationship(foreign_keys=[budget_approver_id])
    branch: Mapped[Branch] = relationship()
    model: Mapped[AssetModel | None] = relationship()
    contract: Mapped[Contract | None] = relationship()


class ChangeRequest(Base):
    """Move / transfer / repair / retire / dispose with maker-checker approval (slide 20)."""

    __tablename__ = "change_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(20), unique=True)
    change_type: Mapped[str] = mapped_column(String(30))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    requester_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="PENDING_APPROVAL", index=True)
    from_branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"))
    from_location_id: Mapped[int | None] = mapped_column(ForeignKey("locations.id"))
    to_branch_id: Mapped[int | None] = mapped_column(ForeignKey("branches.id"))
    to_location_id: Mapped[int | None] = mapped_column(ForeignKey("locations.id"))
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime)
    ticket_ref: Mapped[str | None] = mapped_column(String(60))
    # Evidence (slide 20, "Evidence" column)
    evidence_ref: Mapped[str | None] = mapped_column(String(120))  # transfer note / RMA / wipe plan
    wipe_certificate_ref: Mapped[str | None] = mapped_column(String(120))
    disposal_certificate_ref: Mapped[str | None] = mapped_column(String(120))
    executed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    finance_confirmed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    finance_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    asset: Mapped[Asset] = relationship()
    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    executed_by: Mapped[User | None] = relationship(foreign_keys=[executed_by_id])
    completed_by: Mapped[User | None] = relationship(foreign_keys=[completed_by_id])
    from_branch: Mapped[Branch] = relationship(foreign_keys=[from_branch_id])
    to_branch: Mapped[Branch | None] = relationship(foreign_keys=[to_branch_id])
    from_location: Mapped[Location | None] = relationship(foreign_keys=[from_location_id])
    to_location: Mapped[Location | None] = relationship(foreign_keys=[to_location_id])
    approvals: Mapped[list[ChangeApproval]] = relationship(back_populates="change",
                                                           order_by="ChangeApproval.step")


class ChangeApproval(Base):
    __tablename__ = "change_approvals"
    __table_args__ = (UniqueConstraint("change_id", "step"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    change_id: Mapped[int] = mapped_column(ForeignKey("change_requests.id"))
    step: Mapped[int] = mapped_column(Integer)
    required_role: Mapped[str] = mapped_column(String(30))
    approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[str | None] = mapped_column(String(10))  # APPROVED / REJECTED
    comment: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)

    change: Mapped[ChangeRequest] = relationship(back_populates="approvals")
    approver: Mapped[User | None] = relationship()


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------


class Collector(Base):
    """Regional collector polling ~25-50 branches (slide 15)."""

    __tablename__ = "collectors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    region_id: Mapped[int | None] = mapped_column(ForeignKey("regions.id"))
    api_key_hash: Mapped[str] = mapped_column(String(128))
    api_key_prefix: Mapped[str] = mapped_column(String(12))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    region: Mapped[Region | None] = relationship()


class MonitoringEvent(Base):
    """Raw event: time, severity, metric, ticket reference (slide 16)."""

    __tablename__ = "monitoring_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), index=True)
    branch_id: Mapped[int | None] = mapped_column(ForeignKey("branches.id"), index=True)
    collector_id: Mapped[int | None] = mapped_column(ForeignKey("collectors.id"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    kind: Mapped[str] = mapped_column(String(30))  # STATE, METRIC, SYSLOG, TRAP, CONFIG_CHANGE
    metric: Mapped[str | None] = mapped_column(String(60))
    value: Mapped[str | None] = mapped_column(String(120))
    severity: Mapped[str | None] = mapped_column(String(2))
    message: Mapped[str | None] = mapped_column(Text)
    ticket_ref: Mapped[str | None] = mapped_column(String(60))

    asset: Mapped[Asset | None] = relationship()


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(120), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), index=True)
    branch_id: Mapped[int | None] = mapped_column(ForeignKey("branches.id"), index=True)
    severity: Mapped[str] = mapped_column(String(2), index=True)
    category: Mapped[str] = mapped_column(String(30))
    source: Mapped[str] = mapped_column(String(20), default="MONITORING")
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(15), default="OPEN", index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime)  # when the failure happened
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)  # when the alert was raised
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime)
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    resolution: Mapped[str | None] = mapped_column(Text)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)
    last_escalated_at: Mapped[datetime | None] = mapped_column(DateTime)
    ticket_ref: Mapped[str | None] = mapped_column(String(60))
    change_id: Mapped[int | None] = mapped_column(ForeignKey("change_requests.id"))  # authorising change

    asset: Mapped[Asset | None] = relationship()
    branch: Mapped[Branch | None] = relationship()
    acknowledged_by: Mapped[User | None] = relationship(foreign_keys=[acknowledged_by_id])
    resolved_by: Mapped[User | None] = relationship(foreign_keys=[resolved_by_id])
    escalations: Mapped[list[AlertEscalation]] = relationship(back_populates="alert", order_by="AlertEscalation.id")

    @property
    def impact(self) -> str:
        from itam.enums import IMPACT_LABELS, Severity

        return IMPACT_LABELS[Severity(self.severity)]

    @property
    def response_due_at(self) -> datetime:
        from itam.enums import RESPONSE_MINUTES, Severity

        return self.detected_at + timedelta(minutes=RESPONSE_MINUTES[Severity(self.severity)])


class AlertEscalation(Base):
    """One step on an alert's escalation path: who was told, how, and why (L1, L2, L3, CEO)."""

    __tablename__ = "alert_escalations"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    level: Mapped[int] = mapped_column(Integer)  # 0=L1, 1=L2, 2=L3, 3=CEO
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reason: Mapped[str] = mapped_column(String(160))
    recipients: Mapped[list] = mapped_column(JSON, default=list)  # full names
    channels: Mapped[list] = mapped_column(JSON, default=list)
    notifications_sent: Mapped[int] = mapped_column(Integer, default=0)

    alert: Mapped[Alert] = relationship(back_populates="escalations")


# ---------------------------------------------------------------------------
# Discovery & exceptions
# ---------------------------------------------------------------------------


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    collector_id: Mapped[int | None] = mapped_column(ForeignKey("collectors.id"))
    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), index=True)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    devices_seen: Mapped[int] = mapped_column(Integer, default=0)
    matched: Mapped[int] = mapped_column(Integer, default=0)
    rogue: Mapped[int] = mapped_column(Integer, default=0)
    not_seen: Mapped[int] = mapped_column(Integer, default=0)
    mismatched: Mapped[int] = mapped_column(Integer, default=0)

    branch: Mapped[Branch] = relationship()


class ControlException(Base):
    """Exception register shared by discovery, physical audit, finance reconciliation and HR feeds."""

    __tablename__ = "control_exceptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    exception_type: Mapped[str] = mapped_column(String(30), index=True)
    source: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(10), default="OPEN", index=True)
    dedup_key: Mapped[str] = mapped_column(String(160), index=True)
    branch_id: Mapped[int | None] = mapped_column(ForeignKey("branches.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    observed: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    resolution: Mapped[str | None] = mapped_column(Text)
    ticket_ref: Mapped[str | None] = mapped_column(String(60))

    branch: Mapped[Branch | None] = relationship()
    asset: Mapped[Asset | None] = relationship()
    resolved_by: Mapped[User | None] = relationship()


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------


class PhysicalAudit(Base):
    """Audit record: date, method, result, auditor, exceptions (slide 16)."""

    __tablename__ = "physical_audits"

    id: Mapped[int] = mapped_column(primary_key=True)
    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), index=True)
    method: Mapped[str] = mapped_column(String(20), default="MOBILE_SCAN")
    status: Mapped[str] = mapped_column(String(15), default="SCHEDULED")
    scheduled_for: Mapped[date] = mapped_column(Date)
    auditor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    expected_count: Mapped[int] = mapped_column(Integer, default=0)
    found_count: Mapped[int] = mapped_column(Integer, default=0)
    missing_count: Mapped[int] = mapped_column(Integer, default=0)
    unexpected_count: Mapped[int] = mapped_column(Integer, default=0)
    wrong_location_count: Mapped[int] = mapped_column(Integer, default=0)
    accuracy: Mapped[float | None] = mapped_column(Float)  # % of expected records that matched
    notes: Mapped[str | None] = mapped_column(Text)

    branch: Mapped[Branch] = relationship()
    auditor: Mapped[User | None] = relationship()
    items: Mapped[list[AuditItem]] = relationship(back_populates="audit", order_by="AuditItem.id")


class AuditItem(Base):
    __tablename__ = "audit_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("physical_audits.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    scanned_value: Mapped[str | None] = mapped_column(String(80))
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime)
    result: Mapped[str | None] = mapped_column(String(20))
    note: Mapped[str | None] = mapped_column(Text)

    audit: Mapped[PhysicalAudit] = relationship(back_populates="items")
    asset: Mapped[Asset | None] = relationship()


class Attestation(Base):
    """Branch manager attests custody of the branch's assets."""

    __tablename__ = "attestations"

    id: Mapped[int] = mapped_column(primary_key=True)
    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    audit_id: Mapped[int | None] = mapped_column(ForeignKey("physical_audits.id"))
    attested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    asset_count: Mapped[int] = mapped_column(Integer)
    statement: Mapped[str] = mapped_column(Text)

    branch: Mapped[Branch] = relationship()
    user: Mapped[User] = relationship()


class FinanceReconciliation(Base):
    __tablename__ = "finance_reconciliations"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    run_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    source_name: Mapped[str] = mapped_column(String(160))
    finance_records: Mapped[int] = mapped_column(Integer, default=0)
    matched: Mapped[int] = mapped_column(Integer, default=0)
    mismatched: Mapped[int] = mapped_column(Integer, default=0)
    finance_only: Mapped[int] = mapped_column(Integer, default=0)
    it_only: Mapped[int] = mapped_column(Integer, default=0)

    run_by: Mapped[User] = relationship()


# ---------------------------------------------------------------------------
# Programme governance (roadmap & decision gates, slide 30)
# ---------------------------------------------------------------------------


class Milestone(Base):
    __tablename__ = "milestones"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(10), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    phase: Mapped[str] = mapped_column(String(80))
    planned_date: Mapped[date] = mapped_column(Date)
    actual_date: Mapped[date | None] = mapped_column(Date)
    budget_planned: Mapped[float | None] = mapped_column(Numeric(14, 2))
    budget_actual: Mapped[float | None] = mapped_column(Numeric(14, 2))
    notes: Mapped[str | None] = mapped_column(Text)


# ---------------------------------------------------------------------------
# Notifications, audit log, jobs
# ---------------------------------------------------------------------------


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    channel: Mapped[str] = mapped_column(String(10))
    recipient: Mapped[str] = mapped_column(String(160))
    recipient_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    subject: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(15), default="QUEUED")
    error: Mapped[str | None] = mapped_column(Text)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)


class AuditLogEntry(Base):
    """Append-only, hash-chained audit trail. UPDATE/DELETE are blocked by database triggers."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(60), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[str | None] = mapped_column(String(40))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class JobRun(Base):
    __tablename__ = "job_runs"

    name: Mapped[str] = mapped_column(String(60), primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_result: Mapped[str | None] = mapped_column(Text)
