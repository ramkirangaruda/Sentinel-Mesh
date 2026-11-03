"""SentinelMesh console API (contracts/CONTRACT.md): FastAPI on :8000.

Contract endpoints:
    POST /events          an Event -> 201
    GET  /events?since=   events since an epoch-ms timestamp
    GET  /incidents       correlated incidents (rules, see correlation.py)

Console-local (not contract surface -- see contracts/CHANGELOG.md):
    GET  /health
    GET/POST /recording, POST /recording/{start,stop,label}
    GET/POST /traces
    DELETE /events, POST /reset
    v4 (api/v4.py): GET /status, GET/POST /energy, GET /experiment, GET /control,
        POST /mode, POST /attack, POST /experiment/{run,stop,result}
    channels (api/channels.py): GET /channels, POST /channels/{id}/toggle,
        POST /classify {channel, text} -- the pluggable "Detection Channels"
        registry (channels/*/manifest.json). Only SMS Guard is a real, trained
        classifier; WhatsApp/Telegram/Voice are labeled dummy channels and
        /classify refuses them. Independent of MailGuard/FileGuard, which
        keep using /api/scan/{email,file} below, unmodified.
    /api/* (api/frontend.py + v4.py): the same, in frontend-kit/src/types.ts shapes,
        plus POST /api/scan/{email,file}. Built React app served at / if present.

Run:
    uvicorn api.main:app --port 8000        # from console/
"""
import json
import os
import re
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import attack, channels, config, correlation, db, energy, frontend, v4, validation

app = FastAPI(title="SentinelMesh console", version="2.0")

_conn = db.connect()

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def same_origin_only(request: Request, call_next):
    """Refuse requests a browser was tricked into sending.

    Every handler parses its body with request.json() whatever the
    Content-Type, so without this any web page the operator has open could
    POST a text/plain body to 127.0.0.1:8000 -- no CORS preflight -- and turn
    the defence off, start an attack, inject events into the incident view,
    toggle channels or wipe the database. Browsers always send Origin on such
    a request; the bridge, the Streamlit UI (server side) and curl send none.
    The Host check stops DNS rebinding, where Origin and Host would agree.
    """
    host = request.headers.get("host", "")
    hostname = (urlsplit(f"//{host}").hostname or "") if host else ""
    if hostname not in config.ALLOWED_HOSTS:
        return JSONResponse(status_code=421, content={"detail": f"host not allowed: {host!r}"})
    origin = request.headers.get("origin")
    if request.method in _UNSAFE_METHODS and origin is not None:
        if urlsplit(origin).netloc.lower() != host.lower():
            return JSONResponse(status_code=403, content={"detail": "cross-origin request refused"})
    return await call_next(request)

# nodes whose events prove the gateway relayed them (field/tamper EVTs only
# ever come off the gateway's serial port)
_GATEWAY_LAYERS = {"field", "tamper"}


def store_event(payload: Any) -> tuple[dict, list[str]]:
    """Validate, normalize and store one event. Shared by POST /events and the
    /api/scan proxy, so every path into the database gets the same checks.

    Board timestamps are uptime millis() (no wall clock on an ESP32), so a ts
    below 1e12 is replaced with arrival time and kept as details.device_ts.
    Without this, a real hardware event would land in 1970 and never correlate
    with the mail/file events of the same attack (CONTRACT.md, "Timestamps").
    """
    event, errors = validation.validate_event(payload)
    if errors:
        return {}, errors
    ts, device_ts = energy.normalize_ts(event["ts"])
    if device_ts is not None:
        event["ts"] = ts
        event["details"] = {**event["details"], "device_ts": device_ts}
    stored = db.insert_event(_conn, event)
    if stored:
        if event.get("node"):
            db.touch_node(_conn, event["node"], event["ts"])
        if event["layer"] in _GATEWAY_LAYERS:
            db.touch_node(_conn, "gateway", event["ts"])
    event["_stored"] = stored
    return event, []


v4.bind(_conn)
frontend.bind(_conn, store_event)
app.include_router(v4.router)                      # /status, /energy, ... (root)
app.include_router(v4.router, prefix="/api")       # same handlers for the React app
app.include_router(frontend.router, prefix="/api") # /api/events, /api/incidents, /api/scan/*
app.include_router(channels.router)                 # /channels, /classify (root)
app.include_router(channels.router, prefix="/api") # same handlers for the React app

TRACE_LABELS = ["normal", "weak_link", "replay", "flood", "impersonation"]
_SAFE_SESSION = re.compile(r"[^A-Za-z0-9_-]+")


def _session_filename(session: str) -> str:
    """Session names become file names, so they are sanitized, not trusted."""
    safe = _SAFE_SESSION.sub("_", session).strip("_")
    return safe or "session"


@app.get("/health")
def health():
    rec = db.get_recording(_conn)
    n = _conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    return {
        "status": "ok",
        "events": n,
        "recording": rec["active"],
        "session": rec["session"],
        "db": config.DB_PATH,
        "trace_dir": config.TRACE_DIR,
    }


# -- contract endpoints ----------------------------------------------------

@app.post("/events", status_code=201)
async def post_event(request: Request):
    """Validate against contracts/event.schema.json, then store."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON")

    event, errors = store_event(payload)
    if errors:
        return JSONResponse(
            status_code=422,
            content={"detail": "event does not match contracts/event.schema.json", "errors": errors},
        )
    stored = event.pop("_stored")
    return {"id": event["id"], "stored": stored, "duplicate": not stored, "ts": event["ts"]}


@app.get("/events")
def get_events(since: Optional[int] = Query(None, description="epoch ms, exclusive"),
               limit: int = Query(1000, ge=1, le=10000)):
    events = db.get_events(_conn, since=since, limit=limit)
    for e in events:
        e["technique_name"] = attack.technique_name(e.get("technique"))
    return {"events": events, "count": len(events), "server_ts": int(time.time() * 1000)}


@app.get("/incidents")
def get_incidents(window_ms: Optional[int] = Query(None, ge=1000),
                  limit: int = Query(1000, ge=1, le=10000)):
    events = db.get_events(_conn, limit=limit)
    incidents = correlation.build_incidents(events, window_ms=window_ms)
    return {
        "incidents": incidents,
        "count": len(incidents),
        "window_ms": window_ms or config.INCIDENT_WINDOW_MS,
        "rules": "see console/api/correlation.py -- rules only, no ML",
    }


@app.delete("/events")
def delete_events():
    """Reset the demo database between rehearsals."""
    n = db.clear_events(_conn)
    return {"deleted": n}


@app.post("/reset")
@app.post("/api/reset")
def reset_demo():
    """Clean slate before presenting: events, energy samples and markers, node
    liveness, and the controls back to off.

    Kept: finished experiment rows and recorded trace files. Both are evidence
    recorded before the pitch, and the runbook has the operator reset right
    before presenting -- wiping them there would destroy the measured table.
    A run still in progress is dropped: its samples are gone, so it could only
    finish with a wrong number. (DELETE /experiment clears the table on purpose.)
    """
    n = db.clear_events(_conn)
    for table in ("energy_samples", "energy_markers", "node_seen"):
        _conn.execute(f"DELETE FROM {table}")
    _conn.execute("DELETE FROM experiment WHERE status = 'running'")
    _conn.commit()
    db.set_mode(_conn, "none")
    db.set_attack(_conn, "none")
    return {"ok": True, "events_deleted": n}


# -- trace recording -------------------------------------------------------

@app.get("/recording")
def get_recording():
    return db.get_recording(_conn)


@app.post("/recording/start")
async def start_recording(request: Request):
    body = await _json_body(request)
    label = body.get("label", "normal")
    if label not in TRACE_LABELS:
        raise HTTPException(400, f"label must be one of {TRACE_LABELS}")
    session = body.get("session") or time.strftime("session_%Y%m%d_%H%M%S")
    rec = db.start_recording(_conn, _session_filename(session), label)
    os.makedirs(config.TRACE_DIR, exist_ok=True)
    return rec


@app.post("/recording/stop")
def stop_recording():
    return db.stop_recording(_conn)


@app.post("/recording/label")
async def set_label(request: Request):
    body = await _json_body(request)
    label = body.get("label")
    if label not in TRACE_LABELS:
        raise HTTPException(400, f"label must be one of {TRACE_LABELS}")
    return db.set_label(_conn, label)


@app.get("/traces")
def list_traces():
    """Recorded sessions on disk -- what gets handed to the ML stream."""
    out = []
    if os.path.isdir(config.TRACE_DIR):
        for name in sorted(os.listdir(config.TRACE_DIR)):
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(config.TRACE_DIR, name)
            labels: dict[str, int] = {}
            rows = 0
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rows += 1
                    try:
                        label = json.loads(line).get("label", "?")
                    except json.JSONDecodeError:
                        label = "<unparseable>"
                    labels[label] = labels.get(label, 0) + 1
            out.append({"session": name[:-6], "file": path, "rows": rows, "labels": labels})
    return {"trace_dir": config.TRACE_DIR, "sessions": out}


@app.post("/traces", status_code=202)
async def post_trace(request: Request):
    """One Trace row from the serial bridge.

    Dropped unless a recording session is active -- the gateway emits TRC lines
    continuously, and only the ones an operator deliberately labelled belong in
    the training set. Rows that fail contracts/trace.schema.json are counted and
    dropped rather than written: a malformed row would become silent zeros in
    the ML stream's features.
    """
    body = await _json_body(request)
    # Any TRC line proves the gateway is alive and says how well it hears
    # field-1, whether or not we are recording -- /status wants both.
    now = energy.now_ms()
    db.touch_node(_conn, "gateway", now)
    if isinstance(body.get("rssi_mean"), (int, float)):
        db.touch_node(_conn, "field-1", now, rssi=body["rssi_mean"],
                      battery_pct=body.get("battery_pct") if isinstance(body.get("battery_pct"), (int, float)) else None)

    rec = db.get_recording(_conn)
    if not rec["active"]:
        return {"stored": False, "reason": "not recording"}

    row, errors = validation.validate_trace(body)
    if errors:
        db.count_trace_row(_conn, stored=False)
        return JSONResponse(
            status_code=422,
            content={"stored": False, "detail": "trace does not match contracts/trace.schema.json",
                     "errors": errors},
        )

    # The console owns ground truth: the operator chose the label in the UI, so
    # it is stamped here. A disagreeing gateway label is kept for debugging.
    gw_label = row.get("label")
    row["label"] = rec["label"]
    row["session"] = rec["session"]
    mismatched = bool(gw_label and gw_label != rec["label"])
    if mismatched:
        row["gw_label"] = gw_label

    os.makedirs(config.TRACE_DIR, exist_ok=True)
    path = os.path.join(config.TRACE_DIR, f"{rec['session']}.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    db.count_trace_row(_conn, stored=True, mismatched=mismatched)
    return {"stored": True, "session": rec["session"], "label": rec["label"],
            "file": path, "gw_label_mismatch": mismatched}


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


# The built React frontend (console/web/dist), if present, at /. Registered
# last so every API route above wins; the app then calls /api/* on the same
# origin and needs no dev proxy for the demo.
#
# React Router gives the app a second real path (/dashboard, on top of the
# landing page at /). StaticFiles(html=True) alone only auto-serves
# index.html for "/" and directory-like paths -- a direct load or refresh on
# /dashboard has no matching file and 404s. The catch-all below serves any
# real file that exists (JS/CSS under /assets, favicon, etc.) and falls back
# to index.html for everything else, which is what lets client-side routing
# work on a hard refresh or a shared /dashboard link.
if os.path.isdir(config.WEB_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(config.WEB_DIST, "assets")), name="web-assets")

    _WEB_ROOT = os.path.realpath(config.WEB_DIST)

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        # An unknown API path is a real 404, not the app's HTML with a 200 --
        # otherwise a typo'd fetch fails later as a confusing JSON parse error.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(404, "Not Found")
        # Resolve and confine to web/dist. `full_path` arrives URL-decoded, so
        # "..%2F..%2Fapi%2Fmain.py" becomes "../../api/main.py"; joining it
        # unchecked served any file the process could read (source, console.db,
        # recorded traces).
        candidate = os.path.realpath(os.path.join(_WEB_ROOT, full_path))
        try:
            inside = os.path.commonpath([candidate, _WEB_ROOT]) == _WEB_ROOT
        except ValueError:  # different drive on Windows, e.g. "/D:/x"
            inside = False
        if full_path and inside and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(_WEB_ROOT, "index.html"))
