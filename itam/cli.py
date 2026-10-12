"""Command-line administration: ``python -m itam.cli <command>``."""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select

from itam import auditlog
from itam.config import settings
from itam.db import create_schema, init_engine, session_scope
from itam.models import Collector, Region, User
from itam.rbac import Role
from itam.security import hash_password, new_api_key


def cmd_init_db(_args) -> None:
    create_schema()
    print("Schema created.")


def cmd_seed(args) -> None:
    from itam.seed import DEMO_PASSWORD, seed

    create_schema()
    with session_scope() as db:
        result = seed(db, small=args.small)
    print(f"Seeded {result['branches']} branches, {result['assets']} assets, {result['users']} users.")
    print(f"Demo users (password '{DEMO_PASSWORD}'): admin, ceo, cio, cfo, head.infra, ciso, itam, noc, "
          "procurement, finance, audit, lead.lit, eng.lit, bm0002 ...")


def cmd_create_admin(args) -> None:
    create_schema()
    password = args.password or getpass.getpass("Password: ")
    if len(password) < 12:
        sys.exit("Password must be at least 12 characters")
    with session_scope() as db:
        if db.execute(select(User).where(User.username == args.username)).first():
            sys.exit("User already exists")
        user = User(username=args.username, full_name=args.name or args.username, email=args.email,
                    password_hash=hash_password(password), roles=[Role.ADMIN.value], is_active=True)
        db.add(user)
        db.flush()
        auditlog.record(db, "cli", "user.create", "user", user.username, roles=user.roles)
    print(f"Administrator {args.username} created.")


def cmd_create_collector(args) -> None:
    with session_scope() as db:
        region = None
        if args.region:
            region = db.execute(select(Region).where(Region.code == args.region.upper())).scalar_one_or_none()
            if region is None:
                sys.exit(f"Unknown region {args.region}")
        key, prefix, digest = new_api_key()
        db.add(Collector(name=args.name, region_id=region.id if region else None, api_key_hash=digest,
                         api_key_prefix=prefix))
        auditlog.record(db, "cli", "collector.create", "collector", args.name)
    print(f"Collector {args.name} created. API key (shown once): {key}")


def cmd_run_jobs(args) -> None:
    from itam.services.jobs import JOBS, run_due_jobs, run_job

    if args.all:
        for job in JOBS:
            print(job.name, "→", run_job(job))
    else:
        for name, result in run_due_jobs().items():
            print(name, "→", result)


def cmd_verify_audit_log(_args) -> None:
    with session_scope() as db:
        ok, count, bad = auditlog.verify_chain(db)
    print(f"Audit log {'INTACT' if ok else 'TAMPERED'}: {count} entries checked" + ("" if ok else f", first bad id {bad}"))
    sys.exit(0 if ok else 1)


def cmd_serve(args) -> None:
    import uvicorn

    uvicorn.run("itam.main:create_app", factory=True, host=args.host, port=args.port, proxy_headers=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="itam", description="IT Asset Management platform")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db", help="Create database schema").set_defaults(func=cmd_init_db)
    p = sub.add_parser("seed", help="Load demo data into an empty database")
    p.add_argument("--small", action="store_true", help="Small dataset (3 branches per region)")
    p.set_defaults(func=cmd_seed)
    p = sub.add_parser("create-admin", help="Create a platform administrator")
    p.add_argument("username")
    p.add_argument("--name")
    p.add_argument("--email")
    p.add_argument("--password")
    p.set_defaults(func=cmd_create_admin)
    p = sub.add_parser("create-collector", help="Register a regional collector and print its API key")
    p.add_argument("name")
    p.add_argument("--region", help="Region code (RRR)")
    p.set_defaults(func=cmd_create_collector)
    p = sub.add_parser("run-jobs", help="Run scheduled jobs that are due")
    p.add_argument("--all", action="store_true", help="Run every job now")
    p.set_defaults(func=cmd_run_jobs)
    sub.add_parser("verify-audit-log", help="Verify the audit-log hash chain").set_defaults(func=cmd_verify_audit_log)
    p = sub.add_parser("serve", help="Run the web application")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    init_engine(settings.database_url)
    args.func(args)


if __name__ == "__main__":
    main()
