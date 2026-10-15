"""Unified error format (NFR-API-03, SEC-APP-08)."""
from __future__ import annotations


class AppError(Exception):
    """Business error with an application code. Never carries stack traces outward."""

    status_code = 400

    def __init__(self, code: str, message_key: str | None = None, *, fields: dict | None = None,
                 status_code: int | None = None, **params):
        super().__init__(code)
        self.code = code
        self.message_key = message_key or f"error.{code}"
        self.fields = fields or {}
        self.params = params
        if status_code:
            self.status_code = status_code


class NotFound(AppError):
    status_code = 404

    def __init__(self, code: str = "not_found", **kw):
        super().__init__(code, **kw)


class Forbidden(AppError):
    status_code = 403

    def __init__(self, code: str = "forbidden", **kw):
        super().__init__(code, **kw)


class Conflict(AppError):
    """Invalid status transitions and concurrency conflicts are 409 (section 6)."""

    status_code = 409


class ValidationFailed(AppError):
    status_code = 422

    def __init__(self, fields: dict, code: str = "validation_failed", **kw):
        super().__init__(code, fields=fields, **kw)


class RateLimited(AppError):
    status_code = 429

    def __init__(self, code: str = "rate_limited", **kw):
        super().__init__(code, **kw)
