"""Shared web plumbing: DB session, authentication, CSRF, flash messages, template rendering."""

from __future__ import annotations

import time
from datetime import date, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from itam import enums
from itam.config import settings
from itam.db import get_db
from itam.models import User
from itam.rbac import ROLE_LABELS, can
from itam.security import new_csrf_token
from itam.services import PermissionDenied

DB = Annotated[Session, Depends(get_db, scope="function")]

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class LoginRequired(Exception):
    def __init__(self, next_url: str = "/"):
        self.next_url = next_url


class CSRFError(Exception):
    pass


# --- template helpers -------------------------------------------------------


def _fmt_dt(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return value.strftime(fmt) if value else "—"


def _fmt_date(value: date | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "—"


def _ago(value: datetime | None) -> str:
    if not value:
        return "never"
    from itam.models import utcnow

    secs = int((utcnow() - value).total_seconds())
    if secs < 0:
        return "just now"
    if secs < 90:
        return f"{secs}s ago"
    if secs < 5400:
        return f"{secs // 60} min ago"
    if secs < 172800:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


def _duration(minutes: float | None) -> str:
    if minutes is None:
        return "—"
    if minutes < 60:
        return f"{minutes:.0f} min"
    return f"{minutes / 60:.1f} h"


TEMPLATES.env.filters.update(dt=_fmt_dt, d=_fmt_date, ago=_ago, duration=_duration)
TEMPLATES.env.globals.update(
    can=can, enums=enums, STATUS_LABELS={k.value: v for k, v in enums.STATUS_LABELS.items()},
    TYPE_LABELS={k.value: v for k, v in enums.TYPE_LABELS.items()},
    CHANGE_LABELS={k.value: v for k, v in enums.CHANGE_LABELS.items()},
    SEVERITY_LABELS={k.value: v for k, v in enums.SEVERITY_LABELS.items()},
    ROLE_LABELS={k.value: v for k, v in ROLE_LABELS.items()},
    settings=settings,
)


# --- session / auth -----------------------------------------------------------


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = new_csrf_token()
        request.session["csrf"] = token
    return token


async def csrf_protect(request: Request) -> None:
    """Router-level dependency: every state-changing web request must carry the session's CSRF token."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    expected = request.session.get("csrf")
    supplied = request.headers.get("x-csrf-token")
    if not supplied:
        form = await request.form()
        supplied = form.get("csrf_token")
    if not expected or not supplied or supplied != expected:
        raise CSRFError()


def flash(request: Request, message: str, category: str = "success") -> None:
    request.session.setdefault("flash", []).append([category, message])


def current_user(request: Request, db: DB) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    if time.time() - request.session.get("auth_at", 0) > settings.session_max_age:
        request.session.clear()
        return None
    user = db.get(User, uid)
    if user is None or not user.is_active:
        request.session.clear()
        return None
    return user


def require_user(request: Request, db: DB) -> User:
    user = current_user(request, db)
    if user is None:
        next_url = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise LoginRequired(next_url)
    return user


CurrentUser = Annotated[User, Depends(require_user)]


def require(user: User, permission: str) -> None:
    if not can(user, permission):
        raise PermissionDenied("You do not have permission for this page or action")


def render(request: Request, template: str, user: User | None = None, status_code: int = 200, **ctx: Any):
    messages = request.session.pop("flash", [])
    return TEMPLATES.TemplateResponse(
        request, template,
        {"user": user, "csrf_token": csrf_token(request), "messages": messages, "path": request.url.path, **ctx},
        status_code=status_code,
    )


def redirect(url: str, message: str | None = None, request: Request | None = None,
             category: str = "success") -> RedirectResponse:
    if message and request is not None:
        flash(request, message, category)
    return RedirectResponse(url, status_code=303)


def login_redirect(next_url: str) -> RedirectResponse:
    return RedirectResponse(f"/login?next={quote(next_url)}", status_code=303)


def safe_next(url: str | None) -> str:
    if not url or not url.startswith("/") or url.startswith("//"):
        return "/dashboard"
    return url


def opt_int(value: Any) -> int | None:
    if value in (None, "", "None"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def opt_float(value: Any) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        return float(str(value).replace(",", ""))
    except ValueError:
        return None


def opt_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def opt_str(value: Any) -> str | None:
    value = (value or "").strip() if isinstance(value, str) else value
    return value or None


def get_or_404(db: Session, model: type, ident: Any, label: str = "Record"):
    obj = db.get(model, ident) if ident is not None else None
    if obj is None:
        from itam.services import NotFound

        raise NotFound(f"{label} not found")
    return obj


# --- chart helpers (server-rendered SVG) ------------------------------------------------------------


def nice_max(value: float | None, ticks: int = 4) -> float:
    """Round an axis maximum up to a clean number divisible into ``ticks`` steps."""
    import math

    if not value or value <= 0:
        return float(ticks)
    raw = value / ticks
    magnitude = 10 ** math.floor(math.log10(raw))
    for step in (1, 2, 2.5, 5, 10):
        if raw <= step * magnitude:
            return step * magnitude * ticks
    return 10 * magnitude * ticks


def bar_path(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    """Column with a rounded data-end (top) and a square baseline."""
    if h <= 0:
        return ""
    r = min(r, w / 2, h)
    return (f"M{x:.1f},{y + h:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
            f"H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h:.1f} Z")


def fmt_tick(v: float) -> str:
    if v >= 1000:
        return f"{v / 1000:g}K"
    return f"{v:g}"


def hbar_path(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    """Horizontal bar segment with a rounded data-end (right) and square start."""
    if w <= 0:
        return ""
    r = min(r, h / 2, w)
    return (f"M{x:.1f},{y:.1f} H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} "
            f"V{y + h - r:.1f} Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z")


def compact(value: float | None) -> str:
    if value is None:
        return "—"
    for div, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(value) >= div:
            return f"{value / div:.1f}{suffix}"
    return f"{value:,.0f}"


def pct(num: float, den: float) -> int:
    return round(100 * num / den) if den else 0


TEMPLATES.env.globals.update(nice_max=nice_max, bar_path=bar_path, fmt_tick=fmt_tick, hbar_path=hbar_path,
                             compact=compact, pct=pct)
