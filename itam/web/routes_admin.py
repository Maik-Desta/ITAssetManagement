"""Administration: users & roles, collectors, reference data, notification outbox, scheduled jobs."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select

from itam import auditlog
from itam.enums import AssetType
from itam.models import (
    AssetModel,
    Branch,
    Collector,
    Contract,
    JobRun,
    Location,
    Notification,
    Region,
    User,
    Vendor,
)
from itam.rbac import Role
from itam.security import hash_password, new_api_key
from itam.services import ServiceError
from itam.services.jobs import JOBS, run_job
from itam.web.deps import (
    DB,
    CurrentUser,
    csrf_protect,
    get_or_404,
    opt_date,
    opt_float,
    opt_int,
    opt_str,
    redirect,
    render,
    require,
)

router = APIRouter(prefix="/admin", dependencies=[Depends(csrf_protect)])


# --- Users ------------------------------------------------------------------------------


@router.get("/users")
def users(request: Request, db: DB, user: CurrentUser, q: str = ""):
    require(user, "admin.users")
    query = select(User).order_by(User.username)
    if q:
        query = query.where(User.username.ilike(f"%{q}%") | User.full_name.ilike(f"%{q}%"))
    rows = db.execute(query.limit(300)).scalars().all()
    return render(request, "admin_users.html", user, rows=rows, q=q, roles=list(Role),
                  regions=db.execute(select(Region).order_by(Region.code)).scalars().all(),
                  branches=db.execute(select(Branch).order_by(Branch.code)).scalars().all())


async def _user_fields(request: Request) -> dict:
    f = await request.form()
    roles = [r for r in f.getlist("roles") if r in Role._value2member_map_]
    if not roles:
        raise ServiceError("Assign at least one role")
    return {"full_name": (f.get("full_name") or "").strip(), "email": opt_str(f.get("email")),
            "phone": opt_str(f.get("phone")), "roles": roles, "region_id": opt_int(f.get("region_id")),
            "branch_id": opt_int(f.get("branch_id")), "username": (f.get("username") or "").strip().lower()}


@router.post("/users")
async def user_create(request: Request, db: DB, user: CurrentUser):
    require(user, "admin.users")
    data = await _user_fields(request)
    if not data["username"] or not data["full_name"]:
        raise ServiceError("Username and full name are required")
    if db.execute(select(User).where(User.username == data["username"])).first():
        raise ServiceError("Username already exists", 409)
    temp = secrets.token_urlsafe(10) + "A1"
    new = User(**data, password_hash=hash_password(temp), is_active=True)
    db.add(new)
    db.flush()
    if Role.BRANCH_MANAGER.value in data["roles"] and data["branch_id"]:
        branch = db.get(Branch, data["branch_id"])
        branch.manager_id = new.id
    auditlog.record(db, user, "user.create", "user", new.username, roles=new.roles, region=new.region_id,
                    branch=new.branch_id)
    return redirect("/admin/users", f"User {new.username} created. Temporary password (share securely): {temp}", request)


@router.post("/users/{uid}")
async def user_update(request: Request, db: DB, user: CurrentUser, uid: int):
    require(user, "admin.users")
    target = get_or_404(db, User, uid, "User")
    data = await _user_fields(request)
    data.pop("username")
    if target.id == user.id and Role.ADMIN.value not in data["roles"]:
        raise ServiceError("You cannot remove your own administrator role")
    before = {k: getattr(target, k) for k in data}
    for k, v in data.items():
        setattr(target, k, v)
    if Role.BRANCH_MANAGER.value in data["roles"] and data["branch_id"]:
        db.get(Branch, data["branch_id"]).manager_id = target.id
    auditlog.record(db, user, "user.update", "user", target.username, before=before, after=data)
    return redirect("/admin/users", f"User {target.username} updated.", request)


@router.post("/users/{uid}/action")
def user_action(request: Request, db: DB, user: CurrentUser, uid: int, action: str = Form(...)):
    require(user, "admin.users")
    target = get_or_404(db, User, uid, "User")
    msg = ""
    if action == "deactivate":
        if target.id == user.id:
            raise ServiceError("You cannot deactivate yourself")
        target.is_active = False
        msg = "deactivated"
    elif action == "activate":
        target.is_active = True
        msg = "re-activated"
    elif action == "reset_mfa":
        target.mfa_secret = None
        msg = "MFA reset — the user enrols again at next sign-in"
    elif action == "reset_password":
        temp = secrets.token_urlsafe(10) + "A1"
        target.password_hash = hash_password(temp)
        msg = f"password reset. Temporary password (share securely): {temp}"
    else:
        raise ServiceError("Unknown action")
    auditlog.record(db, user, f"user.{action}", "user", target.username)
    return redirect("/admin/users", f"{target.username}: {msg}.", request)


# --- Collectors ------------------------------------------------------------------------------


@router.get("/collectors")
def collectors(request: Request, db: DB, user: CurrentUser):
    require(user, "admin.collectors")
    rows = db.execute(select(Collector).order_by(Collector.name)).scalars().all()
    regions = db.execute(select(Region).order_by(Region.code)).scalars().all()
    return render(request, "admin_collectors.html", user, rows=rows, regions=regions,
                  new_key=request.session.pop("new_collector_key", None))


@router.post("/collectors")
def collector_create(request: Request, db: DB, user: CurrentUser, name: str = Form(...), region_id: str = Form("")):
    require(user, "admin.collectors")
    if db.execute(select(Collector).where(Collector.name == name.strip())).first():
        raise ServiceError("Collector name already exists", 409)
    key, prefix, digest = new_api_key()
    c = Collector(name=name.strip(), region_id=opt_int(region_id), api_key_hash=digest, api_key_prefix=prefix)
    db.add(c)
    db.flush()
    auditlog.record(db, user, "collector.create", "collector", c.name)
    request.session["new_collector_key"] = [c.name, key]
    return redirect("/admin/collectors")


@router.post("/collectors/{cid}/rotate")
def collector_rotate(request: Request, db: DB, user: CurrentUser, cid: int):
    require(user, "admin.collectors")
    c = get_or_404(db, Collector, cid, "Collector")
    key, prefix, digest = new_api_key()
    c.api_key_hash, c.api_key_prefix = digest, prefix
    auditlog.record(db, user, "collector.rotate_key", "collector", c.name)
    request.session["new_collector_key"] = [c.name, key]
    return redirect("/admin/collectors")


@router.post("/collectors/{cid}/toggle")
def collector_toggle(request: Request, db: DB, user: CurrentUser, cid: int):
    require(user, "admin.collectors")
    c = get_or_404(db, Collector, cid, "Collector")
    c.is_active = not c.is_active
    auditlog.record(db, user, "collector.toggle", "collector", c.name, active=c.is_active)
    return redirect("/admin/collectors", f"Collector {c.name} {'enabled' if c.is_active else 'disabled'}.", request)


# --- RFID read points (slides 20, 29) ---------------------------------------------------------------


@router.get("/read-points")
def read_points(request: Request, db: DB, user: CurrentUser):
    from itam.enums import READ_POINT_LABELS, ReadPointKind
    from itam.models import ReadPoint

    require(user, "readpoints.manage")
    rows = db.execute(select(ReadPoint).order_by(ReadPoint.branch_id, ReadPoint.code)).scalars().all()
    branches = db.execute(select(Branch).order_by(Branch.code)).scalars().all()
    return render(request, "admin_read_points.html", user, rows=rows, branches=branches, kinds=list(ReadPointKind),
                  kind_labels={k.value: v for k, v in READ_POINT_LABELS.items()})


@router.post("/read-points")
def read_point_create(request: Request, db: DB, user: CurrentUser, code: str = Form(...), name: str = Form(...),
                      kind: str = Form(...), branch_id: int = Form(...), camera_ref: str = Form("")):
    from itam.services import rfid as rfid_svc

    branch = get_or_404(db, Branch, branch_id, "Branch")
    rp = rfid_svc.create_read_point(db, user, code=code, name=name, kind=kind, branch=branch, camera_ref=camera_ref)
    return redirect("/admin/read-points", f"Read point {rp.code} registered.", request)


@router.post("/read-points/{rid}/toggle")
def read_point_toggle(request: Request, db: DB, user: CurrentUser, rid: int):
    from itam.models import ReadPoint

    require(user, "readpoints.manage")
    rp = get_or_404(db, ReadPoint, rid, "Read point")
    rp.is_active = not rp.is_active
    auditlog.record(db, user, "readpoint.toggle", "read_point", rp.code, active=rp.is_active)
    return redirect("/admin/read-points", f"{rp.code} {'enabled' if rp.is_active else 'disabled'}.", request)


# --- Reference data ------------------------------------------------------------------------------


@router.get("/reference")
def reference(request: Request, db: DB, user: CurrentUser):
    require(user, "reference.manage")
    return render(request, "admin_reference.html", user,
                  regions=db.execute(select(Region).order_by(Region.code)).scalars().all(),
                  branches=db.execute(select(Branch).order_by(Branch.code)).scalars().all(),
                  vendors=db.execute(select(Vendor).order_by(Vendor.name)).scalars().all(),
                  models=db.execute(select(AssetModel).order_by(AssetModel.asset_type, AssetModel.name)).scalars().all(),
                  contracts=db.execute(select(Contract).order_by(Contract.reference)).scalars().all(),
                  types=list(AssetType))


@router.post("/reference/{kind}")
async def reference_create(request: Request, db: DB, user: CurrentUser, kind: str):
    require(user, "reference.manage")
    f = await request.form()
    if kind == "region":
        code = (f.get("code") or "").strip().upper()
        if len(code) != 3 or not code.isalpha():
            raise ServiceError("Region code must be 3 letters (RRR)")
        country = (f.get("country_code") or "").strip().upper()
        if len(country) != 2 or not country.isalpha():
            raise ServiceError("Country code must be 2 letters (CC)")
        obj = Region(code=code, name=(f.get("name") or code).strip(), country_code=country)
    elif kind == "branch":
        code = (f.get("code") or "").strip()
        if len(code) != 4 or not code.isdigit():
            raise ServiceError("Branch code must be 4 digits (BBBB)")
        if db.execute(select(Branch).where(Branch.code == code)).first():
            raise ServiceError("Branch code already exists", 409)
        obj = Branch(code=code, name=(f.get("name") or "").strip(), region_id=int(f.get("region_id")),
                     city=opt_str(f.get("city")), latitude=opt_float(f.get("latitude")),
                     longitude=opt_float(f.get("longitude")), wave=opt_str(f.get("wave")),
                     rollout_stage="NOT_STARTED", rollout_checklist={}, planned_go_live=opt_date(f.get("planned_go_live")))
    elif kind == "location":
        obj = Location(branch_id=int(f.get("branch_id")), building=opt_str(f.get("building")),
                       floor=opt_str(f.get("floor")), room=opt_str(f.get("room")), rack=opt_str(f.get("rack")))
    elif kind == "vendor":
        obj = Vendor(name=(f.get("name") or "").strip(), support_portal=opt_str(f.get("support_portal")),
                     support_phone=opt_str(f.get("support_phone")))
    elif kind == "model":
        if f.get("asset_type") not in AssetType._value2member_map_:
            raise ServiceError("Unknown asset type")
        obj = AssetModel(vendor_id=int(f.get("vendor_id")), name=(f.get("name") or "").strip(),
                         asset_type=f.get("asset_type"), is_standard=f.get("is_standard") == "1",
                         eol_date=opt_date(f.get("eol_date")), eos_date=opt_date(f.get("eos_date")))
    elif kind == "contract":
        obj = Contract(reference=(f.get("reference") or "").strip(), supplier=(f.get("supplier") or "").strip(),
                       po_number=opt_str(f.get("po_number")), contract_type=f.get("contract_type") or "WARRANTY",
                       cost=opt_float(f.get("cost")), start_date=opt_date(f.get("start_date")),
                       warranty_end=opt_date(f.get("warranty_end")), support_end=opt_date(f.get("support_end")))
    else:
        raise ServiceError("Unknown reference type")
    db.add(obj)
    db.flush()
    auditlog.record(db, user, f"reference.create_{kind}", kind, obj.id)
    return redirect("/admin/reference", f"{kind.title()} created.", request)


@router.post("/reference/model/{mid}")
def model_update(request: Request, db: DB, user: CurrentUser, mid: int, eol_date: str = Form(""),
                 eos_date: str = Form(""), is_standard: str = Form("0")):
    require(user, "reference.manage")
    m = get_or_404(db, AssetModel, mid, "Model")
    m.eol_date, m.eos_date, m.is_standard = opt_date(eol_date), opt_date(eos_date), is_standard == "1"
    auditlog.record(db, user, "reference.update_model", "model", m.id, eol=m.eol_date, eos=m.eos_date,
                    standard=m.is_standard)
    return redirect("/admin/reference#models", f"Model {m.display} updated.", request)


# --- Notifications & jobs ----------------------------------------------------------------------------


@router.get("/notifications")
def notifications(request: Request, db: DB, user: CurrentUser):
    require(user, "notifications.view")
    rows = db.execute(select(Notification).order_by(Notification.id.desc()).limit(300)).scalars().all()
    return render(request, "admin_notifications.html", user, rows=rows)


@router.get("/jobs")
def jobs(request: Request, db: DB, user: CurrentUser):
    require(user, "admin.users")
    runs = {r.name: r for r in db.execute(select(JobRun)).scalars()}
    return render(request, "admin_jobs.html", user, jobs=JOBS, runs=runs)


@router.post("/jobs/{name}")
def job_run(request: Request, db: DB, user: CurrentUser, name: str):
    require(user, "admin.users")
    job = next((j for j in JOBS if j.name == name), None)
    if job is None:
        raise ServiceError("Unknown job")
    result = run_job(job)
    auditlog.record(db, user, "job.run", "job", name, result=result)
    return redirect("/admin/jobs", f"{name}: {result}", request)
