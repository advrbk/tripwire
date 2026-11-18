"""Dashboard and JSON API.

Package names, file paths and snippets come from untrusted archives. The
API returns them as JSON strings, the page only ever writes them with
``textContent``, and a strict Content-Security-Policy blocks inline script, so
a release that ships ``<script>`` in a filename cannot run code in the page.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from .. import __version__
from ..analyzers import ANALYZER_NAMES
from ..db import Database

STATIC = resources.files("tripwire.web").joinpath("static")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def create_app(db_path: Path | str) -> FastAPI:
    db = Database(db_path)
    app = FastAPI(title="Tripwire", version=__version__, docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")

    @app.middleware("http")
    async def security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(STATIC.joinpath("index.html").read_text(encoding="utf-8"))

    @app.get("/static/{name}")
    def static(name: str) -> Response:
        types = {"app.js": "text/javascript", "style.css": "text/css"}
        if name not in types:
            raise HTTPException(404)
        return Response(STATIC.joinpath(name).read_text(encoding="utf-8"), media_type=types[name])

    @app.get("/api/releases")
    def releases(
        ecosystem: Literal["pypi", "npm"] | None = None,
        min_score: int = Query(0, ge=0, le=100),
        flagged: bool | None = None,
        level: Literal["none", "low", "medium", "high", "critical"] | None = None,
        analyzer: str | None = None,
        q: str | None = Query(None, max_length=100),
        status: Literal["scanned", "skipped", "error"] | None = None,
        source: str | None = Query(None, max_length=20),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict:
        if analyzer is not None and analyzer not in (*ANALYZER_NAMES, "archive"):
            raise HTTPException(422, f"unknown analyzer; use one of {', '.join(ANALYZER_NAMES)}")
        rows, total = db.list_releases(ecosystem=ecosystem, min_score=min_score, flagged=flagged, level=level,
                                       analyzer=analyzer, q=q, status=status, source=source, limit=limit,
                                       offset=offset)
        return {"total": total, "limit": limit, "offset": offset, "items": rows}

    @app.get("/api/releases/{rid}")
    def release(rid: int) -> dict:
        row = db.get_release(rid)
        if row is None:
            raise HTTPException(404, "no such release")
        return row

    @app.get("/api/stats")
    def stats() -> dict:
        return {**db.stats(), "analyzers": list(ANALYZER_NAMES)}

    @app.get("/healthz")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    app.state.db = db
    return app
