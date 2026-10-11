"""Role-based access control and data scoping (governance model and RACI, slides 25-26)."""

from __future__ import annotations

from sqlalchemy import Select

from itam.enums import StrEnum
from itam.models import Asset, Branch, User


class Role(StrEnum):
    ADMIN = "ADMIN"  # platform administrator
    EXECUTIVE = "EXECUTIVE"  # CEO / Steering Committee (read-only)
    CIO = "CIO"
    CFO = "CFO"
    HEAD_INFRA = "HEAD_INFRA"  # Head of Infrastructure
    CISO = "CISO"
    IT_ASSET_MANAGER = "IT_ASSET_MANAGER"
    REGIONAL_LEAD = "REGIONAL_LEAD"  # regional IT lead / coordinator
    REGIONAL_IT = "REGIONAL_IT"  # regional IT engineer
    BRANCH_MANAGER = "BRANCH_MANAGER"  # asset custodian
    NOC = "NOC"
    PROCUREMENT = "PROCUREMENT"
    FINANCE = "FINANCE"
    INTERNAL_AUDIT = "INTERNAL_AUDIT"


ROLE_LABELS = {
    Role.ADMIN: "Platform administrator",
    Role.EXECUTIVE: "Executive (CEO / Steering Committee)",
    Role.CIO: "CIO",
    Role.CFO: "CFO",
    Role.HEAD_INFRA: "Head of Infrastructure",
    Role.CISO: "CISO",
    Role.IT_ASSET_MANAGER: "IT Asset Manager",
    Role.REGIONAL_LEAD: "Regional IT lead",
    Role.REGIONAL_IT: "Regional IT engineer",
    Role.BRANCH_MANAGER: "Branch manager (custodian)",
    Role.NOC: "NOC analyst",
    Role.PROCUREMENT: "Procurement",
    Role.FINANCE: "Finance",
    Role.INTERNAL_AUDIT: "Internal Audit",
}

R = Role
PERMISSIONS: dict[str, set[Role]] = {
    # Asset register
    "asset.register": {R.IT_ASSET_MANAGER, R.ADMIN},
    "asset.edit": {R.IT_ASSET_MANAGER, R.ADMIN},
    "asset.install": {R.REGIONAL_IT, R.REGIONAL_LEAD, R.IT_ASSET_MANAGER},
    "asset.verify": {R.NOC, R.IT_ASSET_MANAGER},
    "asset.custody": {R.BRANCH_MANAGER},
    "asset.receive_delivery": {R.BRANCH_MANAGER, R.REGIONAL_IT, R.REGIONAL_LEAD, R.IT_ASSET_MANAGER},
    "asset.export": {R.IT_ASSET_MANAGER, R.CIO, R.CISO, R.INTERNAL_AUDIT, R.FINANCE, R.ADMIN, R.HEAD_INFRA},
    # Equipment requests (slide 19)
    "request.create": {R.BRANCH_MANAGER, R.REGIONAL_IT, R.REGIONAL_LEAD, R.IT_ASSET_MANAGER, R.HEAD_INFRA},
    "request.approve_it": {R.IT_ASSET_MANAGER, R.HEAD_INFRA, R.CIO},
    "request.approve_budget": {R.FINANCE, R.CFO},
    "request.procure": {R.PROCUREMENT},
    "request.receive": {R.IT_ASSET_MANAGER},
    # Changes (slide 20). Approval rights come from the approval matrix, not from here.
    "change.create": {R.REGIONAL_IT, R.REGIONAL_LEAD, R.BRANCH_MANAGER, R.IT_ASSET_MANAGER, R.HEAD_INFRA},
    "change.execute": {R.REGIONAL_IT, R.REGIONAL_LEAD, R.IT_ASSET_MANAGER},
    "change.close": {R.IT_ASSET_MANAGER},
    "change.finance_confirm": {R.FINANCE},
    # Monitoring (slide 21)
    "alert.respond": {R.NOC, R.REGIONAL_IT, R.REGIONAL_LEAD, R.HEAD_INFRA},
    "incident.report": {R.NOC},
    # Exceptions & audits (slide 22)
    "exception.resolve": {R.IT_ASSET_MANAGER, R.REGIONAL_LEAD, R.CISO},
    "audit.schedule": {R.IT_ASSET_MANAGER},
    "audit.conduct": {R.REGIONAL_IT, R.REGIONAL_LEAD, R.IT_ASSET_MANAGER, R.INTERNAL_AUDIT},
    "audit.attest": {R.BRANCH_MANAGER},
    "finance.reconcile": {R.FINANCE, R.IT_ASSET_MANAGER},
    "auditlog.view": {R.INTERNAL_AUDIT, R.CISO, R.CIO, R.IT_ASSET_MANAGER, R.ADMIN},
    "controls.view": {R.INTERNAL_AUDIT, R.CISO, R.CIO, R.IT_ASSET_MANAGER, R.ADMIN},
    # Programme / rollout (slides 30-31)
    "rollout.manage": {R.IT_ASSET_MANAGER, R.REGIONAL_LEAD, R.REGIONAL_IT},
    "programme.manage": {R.IT_ASSET_MANAGER, R.CIO, R.ADMIN},
    # Reference data & administration
    "reference.manage": {R.IT_ASSET_MANAGER, R.ADMIN},
    "admin.users": {R.ADMIN},
    "admin.collectors": {R.ADMIN},
    "notifications.view": {R.ADMIN, R.NOC, R.IT_ASSET_MANAGER},
}

# Roles whose view of the estate is limited to their own region / branch.
REGION_SCOPED = {R.REGIONAL_IT, R.REGIONAL_LEAD}
BRANCH_SCOPED = {R.BRANCH_MANAGER}


def can(user: User | None, permission: str) -> bool:
    if user is None:
        return False
    allowed = PERMISSIONS.get(permission, set())
    return any(Role(r) in allowed for r in (user.roles or []) if r in Role._value2member_map_)


def has_global_scope(user: User) -> bool:
    """Users holding any non-scoped role see the whole estate."""
    roles = {Role(r) for r in user.roles or [] if r in Role._value2member_map_}
    return bool(roles - REGION_SCOPED - BRANCH_SCOPED)


def scope_assets(user: User, query: Select) -> Select:
    """Restrict an Asset query to what the user may see (regional views)."""
    if has_global_scope(user):
        return query
    if user.has_role(*REGION_SCOPED) and user.region_id:
        return query.where(Asset.branch.has(Branch.region_id == user.region_id))
    if user.has_role(*BRANCH_SCOPED) and user.branch_id:
        return query.where(Asset.branch_id == user.branch_id)
    return query.where(Asset.id == -1)


def scope_branches(user: User, query: Select) -> Select:
    if has_global_scope(user):
        return query
    if user.has_role(*REGION_SCOPED) and user.region_id:
        return query.where(Branch.region_id == user.region_id)
    if user.has_role(*BRANCH_SCOPED) and user.branch_id:
        return query.where(Branch.id == user.branch_id)
    return query.where(Branch.id == -1)


def can_see_branch(user: User, branch: Branch) -> bool:
    if has_global_scope(user):
        return True
    if user.has_role(*REGION_SCOPED) and user.region_id == branch.region_id:
        return True
    if user.has_role(*BRANCH_SCOPED) and user.branch_id == branch.id:
        return True
    return False


def acts_for_branch(user: User, role: Role, branch: Branch) -> bool:
    """Does ``user`` hold ``role`` with authority over ``branch``?"""
    if not user.has_role(role):
        return False
    if role in BRANCH_SCOPED:
        return user.branch_id == branch.id or branch.manager_id == user.id
    if role in REGION_SCOPED:
        return user.region_id is None or user.region_id == branch.region_id
    return True
