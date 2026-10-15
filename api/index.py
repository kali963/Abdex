"""Vercel entrypoint: the whole site is one ASGI function (see vercel.json)."""
from app.main import app  # noqa: F401
