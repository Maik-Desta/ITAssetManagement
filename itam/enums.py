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
    UNAPPROVED_DEVICE = "UNAPPROVED_DEVICE"  # branch-bought / non-catalogue device (e.g. a modem)
    # Physical security (slides 31-33)
    SUSPECTED_REMOVAL = "SUSPECTED_REMOVAL"  # tagged asset left through an exit portal without a ticket
    CABINET_TAG_MISSING = "CABINET_TAG_MISSING"  # cabinet reader no longer sees a tag
    CABINET_DOOR = "CABINET_DOOR"  # door opened without an authorised badge or after hours
    INTRUSION = "INTRUSION"  # motion after hours
    SECURITY_DEVICE_TAMPER = "SECURITY_DEVICE_TAMPER"  # RFID reader or camera offline, blocked or moved
    # Logistics (slides 27-28)
    SHIPMENT_VARIANCE = "SHIPMENT_VARIANCE"
    SHIPMENT_OVERDUE = "SHIPMENT_OVERDUE"
    UNEXPLAINED_EXIT = "UNEXPLAINED_EXIT"  # asset read at the staging exit without being on a manifest


# Categories that represent a service outage (used for MTTD/MTTR and proactive detection rate).
OUTAGE_CATEGORIES = {AlertCategory.BRANCH_OFFLINE, AlertCategory.DEVICE_DOWN, AlertCategory.REDUNDANCY_LOST}
# Physical-security alarms: unacknowledged alarms escalate every 5 minutes (slide 31), not per response target.
SECURITY_CATEGORIES = {AlertCategory.SUSPECTED_REMOVAL, AlertCategory.CABINET_TAG_MISSING, AlertCategory.CABINET_DOOR,
                       AlertCategory.INTRUSION, AlertCategory.SECURITY_DEVICE_TAMPER, AlertCategory.UNEXPLAINED_EXIT}
SECURITY_ESCALATION_MINUTES = 5


class AlertSource(StrEnum):
    MONITORING = "MONITORING"
    DISCOVERY = "DISCOVERY"
    SCHEDULER = "SCHEDULER"
    USER_REPORT = "USER_REPORT"
    RFID = "RFID"
    SECURITY = "SECURITY"  # access control, door contacts, motion sensors, cameras


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
    UNAPPROVED_DEVICE = "UNAPPROVED_DEVICE"  # device not in the approved catalogue (e.g. branch-bought modem)
    GOODS_RECEIPT_VARIANCE = "GOODS_RECEIPT_VARIANCE"  # short / wrong delivery against PO and shipping notice
    SHIPMENT_VARIANCE = "SHIPMENT_VARIANCE"  # branch receipt does not match the manifest, or seal broken
    RFID_MISMATCH = "RFID_MISMATCH"  # a tag read that does not match the expected state


class ExceptionSource(StrEnum):
    DISCOVERY = "DISCOVERY"
    PHYSICAL_AUDIT = "PHYSICAL_AUDIT"
    FINANCE_RECON = "FINANCE_RECON"
    HR_FEED = "HR_FEED"
    RFID = "RFID"
    LOGISTICS = "LOGISTICS"


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
        "Pre-encode RFID + QR labels",
    ],
    RolloutStage.ON_SITE: [
        "Physical count of every device",
        "Apply / verify RFID + QR labels; handheld sweep",
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
        "Branch status 'Live' on dashboard",
        "Lessons learned captured in playbook",
    ],
}

ROLLOUT_ORDER = [RolloutStage.NOT_STARTED, RolloutStage.PREPARE, RolloutStage.ON_SITE,
                 RolloutStage.VERIFY, RolloutStage.SIGN_OFF, RolloutStage.LIVE]


class NotificationChannel(StrEnum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    VOICE = "VOICE"  # automated phone call
    CHAT = "CHAT"  # Teams / chat
    SYSTEM = "SYSTEM"  # in-app notification


CHANNEL_LABELS = {
    NotificationChannel.VOICE: "Call",
    NotificationChannel.SMS: "SMS",
    NotificationChannel.EMAIL: "Email",
    NotificationChannel.CHAT: "Teams",
    NotificationChannel.SYSTEM: "In-app",
}

# Service impact shown to the business, derived from alert severity.
IMPACT_LABELS = {Severity.P1: "Critical", Severity.P2: "Major", Severity.P3: "Medium", Severity.P4: "Minor"}


class NotificationStatus(StrEnum):
    QUEUED = "QUEUED"
    SENT = "SENT"
    FAILED = "FAILED"
    OUTBOX_ONLY = "OUTBOX_ONLY"
    UNREAD = "UNREAD"  # in-app
    READ = "READ"  # in-app


# ---------------------------------------------------------------------------
# Standard branch blueprint and approved catalogue (slides 3, 9, 26, 40, 68)
# ---------------------------------------------------------------------------


class BranchTier(StrEnum):
    """Security tier (slide 33). Tier A also gets an exit portal, a cabinet reader and integrated cameras."""

    A = "A"  # data centre, staging, critical branches
    B = "B"  # other branches


TIER_LABELS = {BranchTier.A: "Tier A — critical", BranchTier.B: "Tier B — standard"}

# Standard kit per branch. Anything else needs a Design Authority exception.
BRANCH_BLUEPRINT: dict[AssetType, int] = {
    AssetType.RTR: 2,  # primary + backup WAN
    AssetType.SWT: 2,
    AssetType.FWL: 1,
    AssetType.SRV: 1,
    AssetType.UPS: 1,
    AssetType.ATM: 2,
    AssetType.EUD: 6,
    AssetType.ENV: 1,  # comms-room environmental sensor
}
# Discovered device types that are never allowed on the branch network (bought locally, cannot be patched).
FORBIDDEN_DEVICE_TYPES = {"MODEM", "HOTSPOT", "MIFI", "CONSUMER_ROUTER", "PERSONAL_AP"}


# ---------------------------------------------------------------------------
# RFID (slides 20, 29, 54)
# ---------------------------------------------------------------------------


class ReadPointKind(StrEnum):
    DOCK_IN = "DOCK_IN"  # goods-in dock portal (staging)
    REGISTRATION = "REGISTRATION"  # printer-encoder + verify read
    CAGE = "CAGE"  # secure store fixed shelf reader
    DISPATCH = "DISPATCH"  # dispatch dock exit portal (staging)
    BRANCH_RECEIPT = "BRANCH_RECEIPT"  # handheld at branch delivery
    INSTALL = "INSTALL"  # handheld read at the rack position
    CABINET = "CABINET"  # fixed comms-cabinet reader (critical branches)
    EXIT_PORTAL = "EXIT_PORTAL"  # staff / service exit portal (DC and critical branches)
    AUDIT_SWEEP = "AUDIT_SWEEP"  # handheld quarterly / annual sweep


READ_POINT_LABELS = {
    ReadPointKind.DOCK_IN: "Goods-in dock (staging)",
    ReadPointKind.REGISTRATION: "Registration bench",
    ReadPointKind.CAGE: "Secure store / cage",
    ReadPointKind.DISPATCH: "Dispatch dock",
    ReadPointKind.BRANCH_RECEIPT: "Branch receipt (handheld)",
    ReadPointKind.INSTALL: "Install / rack (handheld)",
    ReadPointKind.CABINET: "Comms cabinet",
    ReadPointKind.EXIT_PORTAL: "Exit portal",
    ReadPointKind.AUDIT_SWEEP: "Audit sweep (handheld)",
}


class ReadEvent(StrEnum):
    """What the RFID middleware reports after filtering and de-duplicating raw reads."""

    SEEN = "SEEN"
    ARRIVED = "ARRIVED"
    LEFT = "LEFT"
    NOT_SEEN = "NOT_SEEN"


class ReadOutcome(StrEnum):
    UPDATED = "UPDATED"  # the record was updated (always logged)
    CONFIRMED = "CONFIRMED"  # the read matched the expected state
    EXCEPTION = "EXCEPTION"  # mismatch with the expected state: exception and/or alarm raised
    UNKNOWN_TAG = "UNKNOWN_TAG"


# ---------------------------------------------------------------------------
# Staging and logistics (slides 27-28, 48)
# ---------------------------------------------------------------------------


class ShipmentStatus(StrEnum):
    PACKED = "PACKED"
    IN_TRANSIT = "IN_TRANSIT"
    DELIVERED = "DELIVERED"
    VARIANCE = "VARIANCE"  # delivered with missing / unexpected items or a broken seal
    CANCELLED = "CANCELLED"


class ShipmentItemResult(StrEnum):
    PENDING = "PENDING"
    MATCHED = "MATCHED"
    MISSING = "MISSING"


# Burn-in before dispatch (slide 27: golden config, firmware, SNMPv3, NTP; 24-48 h burn-in).
MIN_BURN_IN_HOURS = 24


# ---------------------------------------------------------------------------
# Physical security (slides 31-33)
# ---------------------------------------------------------------------------


class SecurityEventKind(StrEnum):
    BADGE = "BADGE"  # access-control badge event at a door
    DOOR_OPEN = "DOOR_OPEN"  # cabinet / comms-room door contact
    MOTION = "MOTION"
    DEVICE_TAMPER = "DEVICE_TAMPER"  # reader or camera offline, view blocked or moved


class ClipStatus(StrEnum):
    REQUESTED = "REQUESTED"  # bookmark sent to the VMS
    ARCHIVED = "ARCHIVED"  # clip received, hashed and kept as evidence
    NOT_CONFIGURED = "NOT_CONFIGURED"  # no VMS integration: request recorded only


# ---------------------------------------------------------------------------
# Operating model (slides 5, 43, 48-51): who operates each automated order-lifecycle stage
# ---------------------------------------------------------------------------


class OperatingModel(StrEnum):
    IN_HOUSE = "IN_HOUSE"
    SISTER_COMPANY = "SISTER_COMPANY"
    OUTSOURCED = "OUTSOURCED"


OPERATING_MODEL_LABELS = {
    OperatingModel.IN_HOUSE: "Option 1 — own and manage inside the bank",
    OperatingModel.SISTER_COMPANY: "Option 2 — sister company (recommended)",
    OperatingModel.OUTSOURCED: "Option 3 — completely outsource",
}

ORDER_STAGES = ["Order approval", "Order info sharing", "Arrival at centre", "Registration & tagging", "Shipment",
                "Received", "Installation", "Live & protected"]

STAGE_OPERATORS: dict[OperatingModel, list[str]] = {
    OperatingModel.IN_HOUSE: ["Bank", "Bank ITAM Office", "Bank ITAM Office", "Bank ITAM Office", "Bank + courier",
                              "Bank branch manager", "Bank regional IT", "Bank NOC + SOC"],
    OperatingModel.SISTER_COMPANY: ["Bank", "Sister co.", "Sister co.", "Sister co.", "Sister co.",
                                    "Bank branch manager", "Sister co.", "Sister co. NOC + Bank SOC"],
    OperatingModel.OUTSOURCED: ["Bank", "Provider", "Provider", "Provider", "Provider", "Bank branch manager",
                                "Provider", "Provider NOC + Bank SOC"],
}
