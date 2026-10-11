"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from itam import __version__
from itam.api.routes import ApiAuthError
from itam.api.routes import router as api_router
from itam.config import Settings, settings as default_settings
from itam.db import create_schema, init_engine
from itam.services import ServiceError
from itam.web import routes_admin, routes_assets, routes_assurance, routes_auth, routes_main, routes_workflow
from itam.web.deps import CSRFError, LoginRequired, current_user, flash, login_redirect, render

log = logging.getLogger("itam")


def _is_api(request: Request) -> bool:
    return request.url.path.startswith("/api/")


def _back(request: Request) -> str:
    ref = request.headers.get("referer") or "/dashboard"
    # Only redirect within this site.
    base = str(request.base_url)
    if ref.startswith(base):
        ref = "/" + ref[len(base):]
    return ref if ref.startswith("/") and not ref.startswith("//") else "/dashboard"


def _seed_if_empty() -> None:
    from sqlalchemy import select

    from itam.db import session_scope
    from itam.models import Region
    from itam.seed import seed

    with session_scope() as db:
        if db.execute(select(Region.id)).first() is None:
            result = seed(db)
            log.warning("Demo data loaded: %s", result)


def create_app(cfg: Settings | None = None, start_scheduler: bool | None = None) -> FastAPI:
    cfg = cfg or default_settings
    init_engine(cfg.database_url)
    create_schema()
    if cfg.demo_seed:
        _seed_if_empty()

    run_scheduler = cfg.scheduler_enabled if start_scheduler is None else start_scheduler

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = None
        if run_scheduler:
            from itam.services.jobs import scheduler_loop

            task = asyncio.create_task(scheduler_loop(cfg.scheduler_interval_seconds))
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Bank IT Asset & Infrastructure Management", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    app.add_middleware(SessionMiddleware, secret_key=cfg.secret_key, session_cookie="itam_session",
                       max_age=cfg.session_max_age, same_site="lax", https_only=cfg.secure_cookies)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                "frame-ancestors 'none'; form-action 'self'",
            )
        return response

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "web" / "static")), name="static")
    for module in (routes_auth, routes_main, routes_assets, routes_workflow, routes_assurance, routes_admin):
        app.include_router(module.router)
    app.include_router(api_router)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return login_redirect(exc.next_url)

    @app.exception_handler(ApiAuthError)
    async def _api_auth(_request: Request, _exc: ApiAuthError):
        return JSONResponse({"detail": "Authentication required"}, status_code=401)

    @app.exception_handler(CSRFError)
    async def _csrf(request: Request, _exc: CSRFError):
        if _is_api(request):
            return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)
        flash(request, "Your session form token expired. Please try again.", "error")
        return RedirectResponse(_back(request), status_code=303)

    @app.exception_handler(ServiceError)
    async def _service_error(request: Request, exc: ServiceError):
        if _is_api(request):
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)
        if request.method == "GET":
            from itam.db import new_session

            db = new_session()
            try:
                user = current_user(request, db)
                return render(request, "error.html", user, status_code=exc.status_code, message=exc.message)
            finally:
                db.close()
        flash(request, exc.message, "error")
        return RedirectResponse(_back(request), status_code=303)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        if _is_api(request):
            return JSONResponse({"detail": exc.errors()}, status_code=422)
        fields = ", ".join(str(e.get("loc", ["?"])[-1]) for e in exc.errors())
        flash(request, f"Please complete the required fields: {fields}", "error")
        return RedirectResponse(_back(request), status_code=303)

    return app

