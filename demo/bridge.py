"""
Browser bridge for the TriageDesk live demo.

The demo page runs CPython compiled to WebAssembly (Pyodide), so there is no
server. This module lets the *real* backend run unchanged anyway:

  1. It registers a tiny stand-in for the `fastapi` package that only records
     routes (FastAPI itself needs a web server, which a browser tab can't host).
  2. It imports web/app.py exactly as it is in the repo, so every route handler,
     the engine, SQLite, enrichment, scoring, correlation and the SLA engine are
     the same code that runs locally with uvicorn.
  3. The dashboard's fetch('/api/...') calls are routed to `dispatch()`, which
     matches the recorded route, converts query parameters to the handler's
     annotated types and returns the handler's JSON — just like FastAPI would.
"""

from __future__ import annotations

import inspect
import json
import re
import sys
import types
import typing
from urllib.parse import parse_qs, urlsplit


# -- minimal fastapi stand-in -------------------------------------------------

class HTTPException(Exception):
    def __init__(self, status_code: int = 500, detail: str | None = None) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _BodyParam:
    """Marker used as a default value for request-body parameters."""

    def __init__(self, default=...) -> None:
        self.default = default


def Body(default=..., **_kw):  # noqa: N802 - mirrors fastapi.Body
    return _BodyParam(default)


class FastAPI:
    def __init__(self, *args, **kwargs) -> None:
        self.routes: list[tuple[str, re.Pattern, typing.Callable]] = []
        self.startup: list[typing.Callable] = []

    def on_event(self, event: str):
        def deco(fn):
            if event == "startup":
                self.startup.append(fn)
            return fn
        return deco

    def _route(self, method: str, path: str):
        pattern = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", path) + "$")

        def deco(fn):
            self.routes.append((method, pattern, fn))
            return fn
        return deco

    def get(self, path: str, **_kw):
        return self._route("GET", path)

    def post(self, path: str, **_kw):
        return self._route("POST", path)


class FileResponse:  # only used by the "/" route, which the demo never calls
    def __init__(self, *args, **kwargs) -> None:
        pass


JSONResponse = FileResponse


def _install_fastapi_shim() -> None:
    if "fastapi" in sys.modules:
        return
    fastapi = types.ModuleType("fastapi")
    fastapi.Body, fastapi.FastAPI, fastapi.HTTPException = Body, FastAPI, HTTPException
    responses = types.ModuleType("fastapi.responses")
    responses.FileResponse, responses.JSONResponse = FileResponse, JSONResponse
    fastapi.responses = responses
    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.responses"] = responses


# -- dispatch -----------------------------------------------------------------

_app = None


def start() -> dict:
    """Import the real backend and run its startup hook (seeds 60 alerts)."""
    global _app
    _install_fastapi_shim()
    from web import app as backend  # the unchanged repo file
    _app = backend.app
    for fn in _app.startup:
        fn()
    m = backend.metrics()
    return {"routes": len(_app.routes), "alerts": m["total_alerts"],
            "incidents": m["total_incidents"], "python": sys.version.split()[0]}


def _coerce(hint, value: str):
    args = [a for a in typing.get_args(hint) if a is not type(None)]
    base = args[0] if args else hint
    if base is int:
        return int(value)
    if base is float:
        return float(value)
    if base is bool:
        return value.lower() in ("1", "true", "yes", "on")
    return value


def dispatch(method: str, url: str, body_json: str | None = None) -> str:
    """Handle one API call from the dashboard; returns a JSON string."""
    parts = urlsplit(url)
    query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
    for m, pattern, fn in _app.routes:
        if m != method.upper():
            continue
        match = pattern.match(parts.path)
        if not match:
            continue
        hints = typing.get_type_hints(fn)
        kwargs = {}
        for name, param in inspect.signature(fn).parameters.items():
            if isinstance(param.default, _BodyParam):
                kwargs[name] = json.loads(body_json) if body_json else {}
            elif name in match.groupdict():
                kwargs[name] = match.group(name)
            elif name in query:
                kwargs[name] = _coerce(hints.get(name, str), query[name])
        try:
            result = fn(**kwargs)
            return json.dumps({"status": 200, "body": result}, default=str)
        except HTTPException as exc:
            return json.dumps({"status": exc.status_code, "body": {"detail": exc.detail}})
    return json.dumps({"status": 404, "body": {"detail": "no route for " + method + " " + parts.path}})
