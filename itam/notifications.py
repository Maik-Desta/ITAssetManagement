"""Notification outbox and channel adapters (e-mail, SMS, voice, chat).

Messages are always written to the outbox table first (auditable). A scheduled job delivers queued
messages through whichever channels are configured; unconfigured channels stay OUTBOX_ONLY.
"""

from __future__ import annotations

import json
import logging
import smtplib
import urllib.request
from collections.abc import Iterable
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from itam.config import settings
from itam.enums import NotificationChannel, NotificationStatus
from itam.models import Branch, Notification, User, utcnow
from itam.rbac import BRANCH_SCOPED, REGION_SCOPED, Role

log = logging.getLogger(__name__)


def users_with_role(db: Session, role: Role, branch: Branch | None = None) -> list[User]:
    """Active users holding ``role``; scoped roles are filtered to the branch / region concerned."""
    users = [u for u in db.execute(select(User).where(User.is_active.is_(True))).scalars() if u.has_role(role)]
    if branch is None:
        return users
    if role in BRANCH_SCOPED:
        return [u for u in users if u.branch_id == branch.id or branch.manager_id == u.id]
    if role in REGION_SCOPED:
        return [u for u in users if u.region_id in (None, branch.region_id)]
    return users


def _channel_configured(channel: NotificationChannel) -> bool:
    if channel == NotificationChannel.EMAIL:
        return bool(settings.smtp_host)
    if channel in (NotificationChannel.SMS, NotificationChannel.VOICE):
        return bool(settings.sms_gateway_url)
    if channel == NotificationChannel.CHAT:
        return bool(settings.chat_webhook_url)
    return False


def notify(db: Session, recipients: Iterable[User], subject: str, body: str,
           channels: Iterable[NotificationChannel], alert_id: int | None = None) -> list[Notification]:
    created: list[Notification] = []
    seen: set[tuple[int, str]] = set()
    for user in recipients:
        for channel in channels:
            if (user.id, channel) in seen:
                continue
            seen.add((user.id, channel))
            address = user.email if channel == NotificationChannel.EMAIL else user.phone
            if channel == NotificationChannel.CHAT:
                address = f"@{user.username}"
            if not address:
                continue
            status = NotificationStatus.QUEUED if _channel_configured(channel) else NotificationStatus.OUTBOX_ONLY
            n = Notification(channel=channel.value, recipient=address, recipient_user_id=user.id,
                             subject=subject[:255], body=body, status=status.value, alert_id=alert_id)
            db.add(n)
            created.append(n)
    db.flush()
    return created


def notify_roles(db: Session, roles: Iterable[Role], subject: str, body: str,
                 channels: Iterable[NotificationChannel], branch: Branch | None = None,
                 alert_id: int | None = None) -> list[Notification]:
    users: dict[int, User] = {}
    for role in roles:
        for u in users_with_role(db, role, branch):
            users[u.id] = u
    return notify(db, users.values(), subject, body, list(channels), alert_id)


def _send(n: Notification) -> None:
    channel = NotificationChannel(n.channel)
    if channel == NotificationChannel.EMAIL:
        msg = EmailMessage()
        msg["From"] = settings.smtp_from
        msg["To"] = n.recipient
        msg["Subject"] = n.subject
        msg.set_content(n.body)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.send_message(msg)
        return
    url = settings.chat_webhook_url if channel == NotificationChannel.CHAT else settings.sms_gateway_url
    payload = {"to": n.recipient, "subject": n.subject, "text": n.body, "type": channel.value.lower()}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10):  # noqa: S310 - URL is operator configuration
        pass


def deliver_queued(db: Session, limit: int = 200) -> int:
    sent = 0
    queued = db.execute(select(Notification).where(Notification.status == NotificationStatus.QUEUED.value)
                        .order_by(Notification.id).limit(limit)).scalars().all()
    for n in queued:
        try:
            _send(n)
            n.status = NotificationStatus.SENT.value
            n.sent_at = utcnow()
            sent += 1
        except Exception as exc:  # noqa: BLE001 - record any delivery failure
            log.warning("Notification %s failed: %s", n.id, exc)
            n.status = NotificationStatus.FAILED.value
            n.error = str(exc)[:500]
    return sent
