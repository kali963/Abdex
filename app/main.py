"""AbdEX application factory."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import BASE_DIR, settings
from app.core.context import RequestContext, reset_ctx, set_ctx
from app.core.errors import AppError, ValidationFailed
from app.core.i18n import LOCALES, translate
from app.core.security import token
from app.db import uuid7


class JsonFormatter(logging.Formatter):
    """NFR-OBS-01: structured JSON logs carrying the request id."""

    def format(self, record: logging.LogRecord) -> str:
        from app.core.context import get_ctx

        return json.dumps({"ts": self.formatTime(record), "level": record.levelname, "logger": record.name,
                           "msg": record.getMessage(), "request_id": get_ctx().request_id}, ensure_ascii=False)


def _setup_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


_REQUEST_ID_RE = re.compile(r"[^A-Za-z0-9._-]")

CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; "
       "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; "
       "object-src 'none'; manifest-src 'self'; worker-src 'self'")


def create_app() -> FastAPI:
    _setup_logging()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        from app.bootstrap import ensure_initialized

        ensure_initialized()
        task = None
        if settings.run_background_worker:
            from app.worker import run_forever

            task = asyncio.create_task(run_forever())
        yield
        if task:
            task.cancel()

    app = FastAPI(title="AbdEX API", version="1.0.0", lifespan=lifespan,
                  docs_url="/api/docs" if not settings.is_production else None, redoc_url=None,
                  openapi_url="/api/v1/openapi.json")

    @app.middleware("http")
    async def context_middleware(request: Request, call_next):
        from app.bootstrap import ensure_initialized
        from app.web.deps import DEVICE_COOKIE, LANG_COOKIE, SESSION_COOKIE

        await asyncio.to_thread(ensure_initialized)

        rid = _REQUEST_ID_RE.sub("", request.headers.get("x-request-id", ""))[:40] or uuid7().hex
        ip = request.client.host if request.client else ""
        if settings.trust_proxy:
            fwd = request.headers.get("x-forwarded-for", "")
            ip = (fwd.split(",")[0].strip() if fwd else "") or ip
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > (settings.max_upload_mb + 2) * 1024 * 1024:
            return JSONResponse(status_code=413, content={"error": {
                "code": "payload_too_large", "message": translate("error.file_too_large", limit=settings.max_upload_mb),
                "fields": {}, "request_id": rid}})
        device = request.cookies.get(DEVICE_COOKIE) or ""
        new_device = ""
        if not device:
            device = new_device = token(16)
        lang = request.cookies.get(LANG_COOKIE) or settings.default_locale
        ctx = RequestContext(request_id=rid, ip=ip, user_agent=request.headers.get("user-agent", "")[:300],
                             device_id=device, locale=lang if lang in LOCALES else "ru",
                             timezone=settings.default_timezone)
        tok = set_ctx(ctx)
        pre_csrf = request.cookies.get("abdex_pre_csrf") or ""
        new_pre = ""
        if not pre_csrf:
            pre_csrf = new_pre = token(24)
        request.state.pre_csrf = pre_csrf
        started = time.monotonic()
        try:
            response = await call_next(request)
        finally:
            reset_ctx(tok)
            from app.modules.integrations.base import flush_journal

            await asyncio.to_thread(flush_journal)
        response.headers["X-Request-ID"] = rid
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(self), camera=(self), microphone=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = CSP + "; upgrade-insecure-requests"
        if not request.url.path.startswith("/static/") and (
                SESSION_COOKIE in request.cookies or request.url.path.startswith(("/files", "/admin", "/api/"))):
            response.headers["Cache-Control"] = "no-store"  # personal pages never land in shared caches
        if new_device:
            response.set_cookie(DEVICE_COOKIE, new_device, max_age=3600 * 24 * 365 * 2, httponly=True,
                                samesite="lax", secure=settings.secure_cookies)
        if new_pre:
            response.set_cookie("abdex_pre_csrf", new_pre, httponly=True, samesite="lax", secure=settings.secure_cookies)
        logging.getLogger("abdex.http").info("%s %s %s %dms", request.method, request.url.path,
                                             response.status_code, int((time.monotonic() - started) * 1000))
        return response

    _install_error_handlers(app)

    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")

    from app.web import (
        routes_account,
        routes_admin,
        routes_api,
        routes_carrier,
        routes_client,
        routes_deals,
        routes_misc,
        routes_public,
    )

    for module in (routes_public, routes_account, routes_client, routes_carrier, routes_deals, routes_misc,
                   routes_admin, routes_api):
        app.include_router(module.router)
    app.include_router(routes_api.html, include_in_schema=False)
    from app.web import routes_hooks

    app.include_router(routes_hooks.router, include_in_schema=False)
    return app


def _install_error_handlers(app: FastAPI) -> None:
    from app.web.deps import LoginRequired, MfaRequired, render, safe_next, set_flash

    def _is_api(request: Request) -> bool:
        return request.url.path.startswith("/api/") or "application/json" in request.headers.get("accept", "")

    def _error_json(request: Request, code: str, message: str, status: int, fields: dict | None = None):
        from app.core.context import get_ctx

        return JSONResponse(status_code=status, content={"error": {
            "code": code, "message": message,
            "fields": {k: translate(v) for k, v in (fields or {}).items()},
            "request_id": get_ctx().request_id or request.headers.get("x-request-id", "")}})

    @app.exception_handler(LoginRequired)
    async def _login(request: Request, exc: LoginRequired):
        if _is_api(request):
            return _error_json(request, "unauthorized", translate("error.unauthorized"), 401)
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(MfaRequired)
    async def _mfa(request: Request, exc: MfaRequired):
        return RedirectResponse("/login/2fa", status_code=303)

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        message = translate(exc.message_key, **exc.params)
        if _is_api(request):
            return _error_json(request, exc.code, message, exc.status_code, exc.fields)
        if request.method == "POST" and exc.status_code not in (403, 404):
            back = safe_next(request.headers.get("referer", "").split(request.base_url.netloc, 1)[-1], "/dashboard")
            resp = RedirectResponse(back, status_code=303)
            if isinstance(exc, ValidationFailed) and exc.fields:
                first = next(iter(exc.fields.values()))
                set_flash(resp, "error", first, **exc.params)
            else:
                set_flash(resp, "error", exc.message_key, **exc.params)
            return resp
        return render(request, "error.html", {"code": exc.status_code, "message": message},
                      status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        fields = {".".join(str(p) for p in e.get("loc", [])[1:]): "error.invalid_value" for e in exc.errors()}
        if _is_api(request):
            return _error_json(request, "validation_failed", translate("error.validation_failed"), 422, fields)
        return render(request, "error.html", {"code": 422, "message": translate("error.validation_failed")},
                      status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        code = "not_found" if exc.status_code == 404 else "http_error"
        if _is_api(request):
            return _error_json(request, code, translate(f"error.{code}"), exc.status_code)
        return render(request, "error.html", {"code": exc.status_code, "message": translate(f"error.{code}")},
                      status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        # SEC-APP-08: no stack traces, versions, paths or SQL in responses
        logging.getLogger("abdex").exception("unhandled error")
        if _is_api(request):
            return _error_json(request, "internal_error", translate("error.internal"), 500)
        return render(request, "error.html", {"code": 500, "message": translate("error.internal")}, status_code=500)


app = create_app()
