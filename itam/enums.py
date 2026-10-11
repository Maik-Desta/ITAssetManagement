"""Controlled vocabularies used across the platform."""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class AssetStatus(StrEnum):
    """Lifecycle status — every asset has exactly one at every moment (slide 18)."""

    IN_STOCK = "IN_STOCK"
    IN_TRANSIT = "IN_TRANSIT"
    ACTIVE = "ACTIVE"
    FAULTY = "FAULTY"
    UNDER_REPAIR = "UNDER_REPAIR"
    MISSING = "MISSING"
    RETIRED = "RETIRED"
    DISPOSED = "DISPOSED"


STATUS_LABELS = {
    AssetStatus.IN_STOCK: "In stock",
    AssetStatus.IN_TRANSIT: "In transit",
    AssetStatus.ACTIVE: "Installed – active",
    AssetStatus.FAULTY: "Installed – faulty",
    AssetStatus.UNDER_REPAIR: "Under repair",
    AssetStatus.MISSING: "Missing",
    AssetStatus.RETIRED: "Retired",
    AssetStatus.DISPOSED: "Disposed",
}

INSTALLED_STATUSES = (AssetStatus.ACTIVE, AssetStatus.FAULTY)


class AssetType(StrEnum):
    """TTT component of the asset number."""

    RTR = "RTR"  # router
    SWT = "SWT"  # switch
    SRV = "SRV"  # server
    FWL = "FWL"  # firewall
    UPS = "UPS"  # UPS / power
    ATM = "ATM"  # ATM
    STO = "STO"  # storage
    WAP = "WAP"  # wireless access point
    EUD = "EUD"  # end-user device
    ENV = "ENV"  # environmental sensor


TYPE_LABELS = {
    AssetType.RTR: "Router",
    AssetType.SWT: "Switch",
    AssetType.SRV: "Server",
    AssetType.FWL: "Firewall",
    AssetType.UPS: "UPS / power",
    AssetType.ATM: "ATM",
    AssetType.STO: "Storage",
    AssetType.WAP: "Wireless AP",
    AssetType.EUD: "End-user device",
    AssetType.ENV: "Environment sensor",
}

# Network-managed device types that must have an IP address and be monitored.
NETWORK_TYPES = {AssetType.RTR, AssetType.SWT, AssetType.SRV, AssetType.FWL, AssetType.UPS,
                 AssetType.STO, AssetType.WAP, AssetType.ATM, AssetType.ENV}
# "Critical device" for retirement approvals (slide 20: router, server, firewall).
CRITICAL_RETIRE_TYPES = {AssetType.RTR, AssetType.SRV, AssetType.FWL}
# Types that may hold customer data and therefore need a certified data wipe before disposal.
DATA_BEARING_TYPES = {AssetType.SRV, AssetType.STO, AssetType.EUD, AssetType.ATM}


class Criticality(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OperState(StrEnum):
    UP = "UP"
    DOWN = "DOWN"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


class Severity(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


SEVERITY_LABELS = {
    Severity.P1: "Critical",
    Severity.P2: "High",
    Severity.P3: "Medium",
    Severity.P4: "Low",
}

# Response targets (minutes) — slide 21.
RESPONSE_MINUTES = {Severity.P1: 15, Severity.P2: 30, Severity.P3: 240, Severity.P4: 24 * 60}


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class AlertCategory(StrEnum):
    BRANCH_OFFLINE = "BRANCH_OFFLINE"
    DEVICE_DOWN = "DEVICE_DOWN"
    REDUNDANCY_LOST = "REDUNDANCY_LOST"
    DEGRADED = "DEGRADED"
    ENVIRONMENT = "ENVIRONMENT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    DEVICE_NOT_DISCOVERED = "DEVICE_NOT_DISCOVERED"
    DEVICE_SWAPPED = "DEVICE_SWAPPED"
    ROGUE_DEVICE = "ROGUE_DEVICE"
    WARRANTY_EXPIRY = "WARRANTY_EXPIRY"
    END_OF_LIFE = "END_OF_LIFE"
    COLLECTOR_OFFLINE = "COLLECTOR_OFFLINE"


# Categories that represent a service outage (used for MTTD/MTTR and proactive detection rate).
OUTAGE_CATEGORIES = {AlertCategory.BRANCH_OFFLINE, AlertCategory.DEVICE_DOWN, AlertCategory.REDUNDANCY_LOST}


class AlertSource(StrEnum):
    MONITORING = "MONITORING"
    DISCOVERY = "DISCOVERY"
    SCHEDULER = "SCHEDULER"
    USER_REPORT = "USER_REPORT"


class ChangeType(StrEnum):
    MOVE_WITHIN_BRANCH = "MOVE_WITHIN_BRANCH"
    TRANSFER_BRANCH = "TRANSFER_BRANCH"
    SEND_REPAIR = "SEND_REPAIR"
    RETIRE = "RETIRE"
    DISPOSE = "DISPOSE"


CHANGE_LABELS = {
    ChangeType.MOVE_WITHIN_BRANCH: "Move within branch",
    ChangeType.TRANSFER_BRANCH: "Transfer between branches",
    ChangeType.SEND_REPAIR: "Send for repair",
    ChangeType.RETIRE: "Retire",
    ChangeType.DISPOSE: "Dispose / write-off",
}


class ChangeStatus(StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


OPEN_CHANGE_STATUSES = (ChangeStatus.PENDING_APPROVAL, ChangeStatus.APPROVED, ChangeStatus.IN_PROGRESS)
# Changes that authorise a device to disappear from discovery.
AUTHORISED_CHANGE_STATUSES = (ChangeStatus.APPROVED, ChangeStatus.IN_PROGRESS)


class RequestStatus(StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    ORDERED = "ORDERED"
    RECEIVED = "RECEIVED"
    REJECTED = "REJECTED"


class ExceptionType(StrEnum):
    ROGUE_DEVICE = "ROGUE_DEVICE"  # discovered, not registered
    MISSING_DEVICE = "MISSING_DEVICE"  # registered, not discovered / not found
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"  # serial / MAC changed (device swapped)
    LOCATION_MISMATCH = "LOCATION_MISMATCH"  # found at a different branch / location
    UNEXPECTED_ITEM = "UNEXPECTED_ITEM"  # physical audit found an unexpected tag
    FINANCE_NOT_IN_IT = "FINANCE_NOT_IN_IT"
    IT_NOT_IN_FINANCE = "IT_NOT_IN_FINANCE"
    FINANCE_MISMATCH = "FINANCE_MISMATCH"
    CUSTODIAN_LEFT = "CUSTODIAN_LEFT"


class ExceptionSource(StrEnum):
    DISCOVERY = "DISCOVERY"
    PHYSICAL_AUDIT = "PHYSICAL_AUDIT"
    FINANCE_RECON = "FINANCE_RECON"
    HR_FEED = "HR_FEED"


class ExceptionStatus(StrEnum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class AuditStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class AuditMethod(StrEnum):
    MOBILE_SCAN = "MOBILE_SCAN"  # quarterly cyclical audit
    FULL_VERIFICATION = "FULL_VERIFICATION"  # annual full verification


class AuditItemResult(StrEnum):
    FOUND = "FOUND"
    MISSING = "MISSING"
    UNEXPECTED = "UNEXPECTED"
    WRONG_LOCATION = "WRONG_LOCATION"


class RolloutStage(StrEnum):
    """Branch-day playbook stages (slide 31)."""

    NOT_STARTED = "NOT_STARTED"
    PREPARE = "PREPARE"  # T-10 days
    ON_SITE = "ON_SITE"  # Day 0
    VERIFY = "VERIFY"  # Day +1
    SIGN_OFF = "SIGN_OFF"  # Day +2
    LIVE = "LIVE"


ROLLOUT_CHECKLIST: dict[RolloutStage, list[str]] = {
    RolloutStage.PREPARE: [
        "Pull existing records for the branch",
        "Confirm WAN, management VLAN and firewall rules",
        "Book access with branch manager",
        "Pre-print QR tags",
    ],
    RolloutStage.ON_SITE: [
        "Physical count of every device",
        "Apply / verify tags; photo of racks",
        "Enable SNMPv3, syslog, NTP",
        "Record location, rack and custodian",
    ],
    RolloutStage.VERIFY: [
        "Discovery confirms all devices",
        "Monitoring and alerts tested (pull-cable test)",
        "Exceptions resolved or logged",
    ],
    RolloutStage.SIGN_OFF: [
        "Branch manager attests custody",
        "Lessons learned captured in playbook",
    ],
}

ROLLOUT_ORDER = [RolloutStage.NOT_STARTED, RolloutStage.PREPARE, RolloutStage.ON_SITE,
                 RolloutStage.VERIFY, RolloutStage.SIGN_OFF, RolloutStage.LIVE]


class NotificationChannel(StrEnum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    VOICE = "VOICE"
    CHAT = "CHAT"


class NotificationStatus(StrEnum):
    QUEUED = "QUEUED"
    SENT = "SENT"
    FAILED = "FAILED"
    OUTBOX_ONLY = "OUTBOX_ONLY"
