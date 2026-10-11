"""Sign-in (password + optional TOTP MFA), sign-out and account settings."""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select

from itam import auditlog
from itam.config import settings
from itam.models import User
from itam.security import hash_password, new_totp_secret, totp_uri, verify_password, verify_totp
from itam.web.deps import DB, CurrentUser, csrf_protect, current_user, redirect, render, safe_next

router = APIRouter(dependencies=[Depends(csrf_protect)])

MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60
_failures: dict[str, list[float]] = defaultdict(list)


def _locked(username: str) -> bool:
    now = time.time()
    _failures[username] = [t for t in _failures[username] if now - t < LOCKOUT_SECONDS]
    return len(_failures[username]) >= MAX_FAILURES


def _needs_mfa(user: User) -> bool:
    return bool(user.mfa_secret) or any(r in settings.mfa_roles for r in user.roles or [])


def _complete_login(request: Request, user: User) -> None:
    request.session.clear()
    request.session["uid"] = user.id
    request.session["auth_at"] = time.time()


@router.get("/login")
def login_form(request: Request, db: DB, next: str | None = None):
    if current_user(request, db):
        return redirect(safe_next(next))
    return render(request, "login.html", next=safe_next(next))


@router.post("/login")
def login(request: Request, db: DB, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    username = username.strip().lower()
    if _locked(username):
        auditlog.record(db, username, "auth.locked", "user", username)
        return render(request, "login.html", next=next, error="Too many failed attempts. Try again in 15 minutes.",
                      status_code=429)
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(password, user.password_hash):
        _failures[username].append(time.time())
        auditlog.record(db, username, "auth.failed", "user", username)
        return render(request, "login.html", next=next, error="Invalid username or password.", status_code=401)
    _failures.pop(username, None)
    if _needs_mfa(user):
        request.session.clear()
        request.session["mfa_uid"] = user.id
        request.session["mfa_at"] = time.time()
        request.session["next"] = safe_next(next)
        return redirect("/login/mfa")
    _complete_login(request, user)
    auditlog.record(db, user, "auth.login", "user", user.username)
    return redirect(safe_next(next))


@router.get("/login/mfa")
def mfa_form(request: Request, db: DB):
    uid = request.session.get("mfa_uid")
    user = db.get(User, uid) if uid else None
    if user is None:
        return redirect("/login")
    enrol_secret = None
    if not user.mfa_secret:
        enrol_secret = request.session.get("mfa_enrol") or new_totp_secret()
        request.session["mfa_enrol"] = enrol_secret
    return render(request, "mfa.html", enrol_secret=enrol_secret,
                  enrol_uri=totp_uri(enrol_secret, user.username) if enrol_secret else None)


@router.post("/login/mfa")
def mfa_verify(request: Request, db: DB, code: str = Form(...)):
    uid = request.session.get("mfa_uid")
    user = db.get(User, uid) if uid else None
    if user is None or time.time() - request.session.get("mfa_at", 0) > 300:
        request.session.clear()
        return redirect("/login", "Sign-in expired, please start again.", request, "error")
    secret = user.mfa_secret or request.session.get("mfa_enrol")
    if _locked(user.username) or not secret or not verify_totp(secret, code):
        _failures[user.username].append(time.time())
        auditlog.record(db, user, "auth.mfa_failed", "user", user.username)
        return redirect("/login/mfa", "Invalid authentication code.", request, "error")
    if not user.mfa_secret:
        user.mfa_secret = secret
        auditlog.record(db, user, "auth.mfa_enrolled", "user", user.username)
    next_url = request.session.get("next", "/dashboard")
    _complete_login(request, user)
    auditlog.record(db, user, "auth.login", "user", user.username, mfa=True)
    return redirect(next_url)


@router.post("/logout")
def logout(request: Request, db: DB):
    user = current_user(request, db)
    if user:
        auditlog.record(db, user, "auth.logout", "user", user.username)
    request.session.clear()
    return redirect("/login")


@router.get("/account")
def account(request: Request, user: CurrentUser):
    enrol_secret = None
    if not user.mfa_secret:
        enrol_secret = request.session.get("mfa_enrol") or new_totp_secret()
        request.session["mfa_enrol"] = enrol_secret
    return render(request, "account.html", user, enrol_secret=enrol_secret,
                  enrol_uri=totp_uri(enrol_secret, user.username) if enrol_secret else None)


@router.post("/account/password")
def change_password(request: Request, db: DB, user: CurrentUser, current: str = Form(...), new: str = Form(...),
                    confirm: str = Form(...)):
    if not verify_password(current, user.password_hash):
        return redirect("/account", "Current password is incorrect.", request, "error")
    if new != confirm:
        return redirect("/account", "New passwords do not match.", request, "error")
    if len(new) < 12 or new.lower() == new or not any(c.isdigit() for c in new):
        return redirect("/account", "Use at least 12 characters with upper and lower case and a digit.", request, "error")
    user.password_hash = hash_password(new)
    auditlog.record(db, user, "auth.password_change", "user", user.username)
    return redirect("/account", "Password changed.", request)


@router.post("/account/mfa")
def enrol_mfa(request: Request, db: DB, user: CurrentUser, code: str = Form(...)):
    secret = request.session.get("mfa_enrol")
    if user.mfa_secret or not secret:
        return redirect("/account")
    if not verify_totp(secret, code):
        return redirect("/account", "Invalid code — check your authenticator app's clock.", request, "error")
    user.mfa_secret = secret
    request.session.pop("mfa_enrol", None)
    auditlog.record(db, user, "auth.mfa_enrolled", "user", user.username)
    return redirect("/account", "Multi-factor authentication enabled.", request)
