"""Runtime configuration, read from environment variables (prefix ``ITAM_``)."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"ITAM_{name}", default)


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value else default


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _database_url() -> str:
    """ITAM_DATABASE_URL, else a platform-provided DATABASE_URL (e.g. Render), normalised for psycopg 3."""
    url = _env("DATABASE_URL") or os.environ.get("DATABASE_URL") or "sqlite:///./itam.db"
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


@dataclass
class Settings:
    database_url: str = field(default_factory=_database_url)
    secret_key: str = field(default_factory=lambda: _env("SECRET_KEY") or secrets.token_hex(32))
    # Country code used as the CC part of the asset number standard.
    country_code: str = field(default_factory=lambda: _env("COUNTRY_CODE", "CM"))
    bank_name: str = field(default_factory=lambda: _env("BANK_NAME", "The Bank"))
    currency: str = field(default_factory=lambda: _env("CURRENCY", "XAF"))

    # Monitoring / discovery thresholds (slides 18, 20, 21).
    missing_after_hours: int = field(default_factory=lambda: _env_int("MISSING_AFTER_HOURS", 72))
    removal_alert_minutes: int = field(default_factory=lambda: _env_int("REMOVAL_ALERT_MINUTES", 15))
    # A collector that has not reported for this long is considered offline, and its
    # branches are excluded from missing-device detection (it buffers data while the WAN is down).
    collector_stale_minutes: int = field(default_factory=lambda: _env_int("COLLECTOR_STALE_MINUTES", 30))
    warranty_warning_days: int = field(default_factory=lambda: _env_int("WARRANTY_WARNING_DAYS", 90))

    # Operating model (slides 5, 43): IN_HOUSE, SISTER_COMPANY (recommended) or OUTSOURCED, and the operator's name.
    operating_model: str = field(default_factory=lambda: (_env("OPERATING_MODEL") or "SISTER_COMPANY").upper())
    operator_name: str = field(default_factory=lambda: _env("OPERATOR_NAME", "Group IT Services"))

    # RFID and physical security (slides 20, 29, 31-33).
    # A cabinet tag missed this many consecutive read cycles (with no change ticket) raises an alarm.
    cabinet_missed_cycles: int = field(default_factory=lambda: _env_int("CABINET_MISSED_CYCLES", 2))
    # A fixed reader silent this long is treated as tampered / offline.
    reader_stale_minutes: int = field(default_factory=lambda: _env_int("READER_STALE_MINUTES", 15))
    # An authorised badge this many seconds before an exit read or door event explains it.
    badge_window_seconds: int = field(default_factory=lambda: _env_int("BADGE_WINDOW_SECONDS", 120))
    # An approved change scheduled within this many hours counts as "inside an approved change window".
    change_window_hours: int = field(default_factory=lambda: _env_int("CHANGE_WINDOW_HOURS", 4))
    # Branch business hours (local time, 24 h clock); door and motion events outside them are "after hours".
    business_hours: str = field(default_factory=lambda: _env("BUSINESS_HOURS", "07-19"))
    # Branch local time = UTC + this offset (timestamps are stored in UTC). Cameroon: +1.
    utc_offset_hours: int = field(default_factory=lambda: _env_int("UTC_OFFSET_HOURS", 1))
    # Video management system: JSON POST {action, camera, start, end, alert} for bookmarks, clips and PTZ.
    vms_url: str | None = field(default_factory=lambda: _env("VMS_URL"))

    # Session / security.
    session_max_age: int = field(default_factory=lambda: _env_int("SESSION_MAX_AGE", 8 * 3600))
    secure_cookies: bool = field(default_factory=lambda: _env_bool("SECURE_COOKIES", False))
    # Comma-separated roles that must use MFA (TOTP) to sign in.
    mfa_required_roles: str = field(default_factory=lambda: _env("MFA_REQUIRED_ROLES", ""))

    # Demo mode: load demo data on first start when the database is empty.
    demo_seed: bool = field(default_factory=lambda: _env_bool("DEMO_SEED", False))

    # Background scheduler.
    scheduler_enabled: bool = field(default_factory=lambda: _env_bool("SCHEDULER_ENABLED", True))
    scheduler_interval_seconds: int = field(default_factory=lambda: _env_int("SCHEDULER_INTERVAL", 60))

    # Notification channels. When not configured, messages are kept in the outbox only.
    smtp_host: str | None = field(default_factory=lambda: _env("SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", 25))
    smtp_from: str = field(default_factory=lambda: _env("SMTP_FROM", "itam@bank.local"))
    sms_gateway_url: str | None = field(default_factory=lambda: _env("SMS_GATEWAY_URL"))
    chat_webhook_url: str | None = field(default_factory=lambda: _env("CHAT_WEBHOOK_URL"))
    # SIEM forwarding of audit-log entries and alerts via syslog (host:port).
    siem_syslog: str | None = field(default_factory=lambda: _env("SIEM_SYSLOG"))

    @property
    def mfa_roles(self) -> set[str]:
        return {r.strip() for r in self.mfa_required_roles.split(",") if r.strip()}

    def is_after_hours(self, utc_hour: int) -> bool:
        hour = (utc_hour + self.utc_offset_hours) % 24
        start, _, end = self.business_hours.partition("-")
        try:
            return not int(start) <= hour < int(end)
        except ValueError:
            return not 7 <= hour < 19


settings = Settings()


def reload_settings() -> Settings:
    """Re-read the environment in place, so modules holding a reference see the new values (tests)."""
    settings.__dict__.update(Settings().__dict__)
    return settings
