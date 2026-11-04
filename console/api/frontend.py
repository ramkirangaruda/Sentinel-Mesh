"""/api/* in the exact shapes console/frontend-kit/src/types.ts declares.

The frontend kit was written against a slightly different API than the one
the console already served:

    kit expects                          console's original endpoint
    GET /api/events     -> SmEvent[]     GET /events    -> {events, count, server_ts}
    GET /api/incidents  -> Incident[]    GET /incidents -> {incidents: [{..., chain: [...]}]}
      with stages: {inbox: "hit"|...}
    POST /api/scan/email, /api/scan/file (console proxies to the ML service)

Rather than break the original endpoints (the Streamlit UI and the tests use
them), this router adapts. Status/energy/experiment/controls are already in
the kit's shape and are mounted under /api by main.py directly (see v4.py).
"""
import os
from typing import Any, Optional

import requests
from fastapi import APIRouter, HTTPException, Query, Request

from . import config, correlation, db, validation

router = APIRouter()
_conn = None
_store = None   # main.store_event: validate + normalize + store, shared with POST /events

_http = requests.Session()

STAGE_OF_STEP = {"Inbox": "inbox", "Endpoint": "endpoint", "Field network": "field", "Physical": "physical"}
EVENT_KEYS = ("id", "ts", "layer", "type", "severity", "score", "node", "technique",
              "summary", "reasons", "details")


def bind(conn, store) -> None:
    global _conn, _store
    _conn, _store = conn, store


def _contract_event(e: dict) -> dict:
    return {k: e.get(k) for k in EVENT_KEYS}


@router.get("/events")
def events(since: Optional[int] = Query(None), limit: int = Query(200, ge=1, le=10_000)):
    # the kit always sends since (0 on first poll); 0 means "the latest page"
    evs = db.get_events(_conn, since=since or None, limit=limit)
    return [_contract_event(e) for e in evs]


@router.get("/incidents")
def incidents(window_ms: Optional[int] = Query(None, ge=1000)):
    out = []
    for inc in correlation.build_incidents(db.get_events(_conn, limit=1000), window_ms=window_ms):
        out.append({
            "id": inc["id"],
            "title": inc["title"],
            "severity": inc["severity"],
            "started_ts": inc["started_ts"],
            "last_ts": inc["last_ts"],
            "layers": inc["layers"],
            "stages": {STAGE_OF_STEP[c["step"]]: ("hit" if c["lit"] else "clear") for c in inc["chain"]},
            "event_ids": inc["event_ids"],
            "techniques": inc["techniques"],
            # optional extras, declared in types.ts: the "why this severity" line
            "base_severity": inc["base_severity"],
            "escalated_by": inc["escalated_by"],
            "coordinated": inc["coordinated"],
        })
    return out


# -- scan: the console calls the ML service, stores what comes back ----------

def _ml(path: str, **kw) -> Any:
    try:
        r = _http.post(f"{config.ML_URL}{path}", timeout=60, **kw)
    except requests.RequestException as exc:
        raise HTTPException(503, f"ML service unreachable at {config.ML_URL}: {exc.__class__.__name__}")
    if r.status_code != 200:
        raise HTTPException(502, f"ML service returned {r.status_code}: {r.text[:300]}")
    return r.json()


def _store_all(body: Any) -> list[dict]:
    events = body if isinstance(body, list) else [body]
    stored = []
    for e in events:
        event, errors = _store(e)
        if errors:
            raise HTTPException(502, {"detail": "ML service returned an Event that fails "
                                                "contracts/event.schema.json", "errors": errors})
        stored.append(_contract_event(event))
    return stored


@router.post("/scan/email")
async def scan_email(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON: {\"text\": \"...\"}")
    text = body.get("text") if isinstance(body, dict) else None
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(400, "text must be a non-empty string")
    return _store_all(_ml("/score/email", json={"text": text}))


def _too_large(limit: int) -> HTTPException:
    return HTTPException(413, f"upload is larger than the {limit // (1024 * 1024)} MB limit "
                              f"(SENTINEL_MAX_UPLOAD_BYTES={limit})")


async def _read_capped(request: Request, limit: int) -> None:
    """Read the body, refusing it with 413 as soon as it passes `limit` bytes.

    Content-Length is checked first so an honest client is refused before
    anything is read; the streamed count catches chunked bodies and lying
    headers. Starlette's request.form() would otherwise spool any size to
    disk, and the upload is then read into memory and re-sent to ML. The
    multipart framing counts toward the limit (a few hundred bytes).
    """
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise _too_large(limit)
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise _too_large(limit)
        chunks.append(chunk)
    # request.form() re-reads from the cached body (Starlette's stream()
    # replays _body when it is set), so the parse below sees exactly this.
    request._body = b"".join(chunks)


@router.post("/scan/file")
async def scan_file(request: Request):
    """Benign files only -- the safety rule. Malicious demo samples are feature
    rows sent straight to the ML service, never uploaded files."""
    await _read_capped(request, config.MAX_UPLOAD_BYTES)
    form = await request.form()
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(400, "multipart body must include a 'file' field")
    data = await upload.read()
    name = upload.filename or "upload.bin"
    endpoint = "/score/eml" if name.lower().endswith(".eml") else "/score/file"
    return _store_all(_ml(endpoint, files={"file": (os.path.basename(name), data)}))
