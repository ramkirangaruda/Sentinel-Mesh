# Console stream notes (Claude 2)

Written for: the Claude session that owns `console/` and `contracts/`, to
re-orient at the start of a session. Claude Code loads this file only when
working in `console/`; the team-wide rules are in the root `CLAUDE.md` — read
that first. Other streams keep their own notes in their own folders.

**Pull `master` and read the newest `contracts/CHANGELOG.md` entry first** —
other sessions write there too.

## Scope

Owns `console/` and `contracts/`. Reads `ml/` and `firmware/` to check
integration; never edits them — problems there go to the human. Any contract
change gets a `CHANGELOG.md` entry and an announcement to all three streams.

## Deliverables — status (166 tests; the 7 SPA-route tests skip until web/dist is built)

v3:
1. `api/` — FastAPI :8000, SQLite, `POST/GET /events`, `GET /incidents`, every
   event validated against `contracts/event.schema.json`.
2. `bridge/serial_bridge.py` — EVT/TRC/NRG in; LABEL/DEFENSE/MODE out.
   `--port` / `--replay` / `--stdin`. **One bridge per board.**
3. `api/correlation.py` — rules R1–R5, one test each.
4. `ui/app.py` (Streamlit) — the **fallback** UI; still the only one with trace
   recording.
5. `tools/mock_events.py`, `tools/mock_serial.py`.
6. `demo/RUNBOOK.md`.

v4 (`docs/v4_energy_split.md`, Claude 2 section — all nine items done):
- **React console `web/`** (Vite + Recharts), stood up from `frontend-kit/`.
  `npm run build` → the API serves it at **http://127.0.0.1:8000/**.
  `web/src/types.ts` + `api.ts` must stay identical to the kit's copies.
  Two routes: `/` (landing page) and `/dashboard` (the tabbed operator
  console; `?tab=incidents` etc. picks the tab) — `App.tsx` is a
  `react-router-dom` shell,
  `pages/LandingPage.tsx` + `pages/Dashboard.tsx` hold the real content.
  Direct navigation/refresh on `/dashboard` needs the server-side catch-all
  in `api/main.py` (`StaticFiles(html=True)` alone only auto-serves
  `index.html` for `/`) — don't remove that route without re-testing a
  hard refresh on `/dashboard`.
  Visual design follows the design language of nodenza.com (palette, Aspekta
  type, floating pill header, glass slabs, tile field, 3D flip cards): shared
  system in `styles.css`, page styles in `landing.css` / `dashboard.css`
  (dashboard scoped under `.console`), shared parts in `components/`. Only the
  design language is borrowed; copy, logo and imagery are ours, and the slabs
  and tile field are drawn in CSS. Aspekta is OFL (`assets/fonts/`). Recharts
  can't read CSS `var()`, so `charts.tsx` mirrors the palette as hex.
  The page before this one was ported from a separately-contributed
  `Front-End/` folder (since removed): its fixture numbers were never real
  and three factual errors were fixed while porting (wrong crypto version,
  fabricated hardware-support claims, fabricated customer testimonials) — see
  that port commit before reintroducing any of that copy.
- `api/v4.py`, `energy.py`, `status.py`, `experiment.py`: `/status`, `/energy`,
  `/experiment` (+ run/stop/result), `/mode`, `/attack`, `/control`, `/reset`.
  All also under `/api/*`; `api/frontend.py` adapts `/api/events` +
  `/api/incidents` to the kit's shapes and proxies `/api/scan/*` to ML.
- `tools/mock_rig.py` — SIMULATED rig reacting live to the controls; output
  tagged `source: sim` → SIMULATED banners everywhere.
- Contract: `DEFENSE` / `MODE` / `NRG` serial lines, `energy.schema.json`,
  optional `budget_j`/`budget_max_j` on `gate_decision`.

**EnergyGate lives on field-1, not the gateway** (moved 2026-09-18; see
`contracts/CHANGELOG.md`). The gateway relays `DEFENSE` to field-1 and relays
its decisions back as `gate_decision` with `"node": "field-1"`; the genuine
sender that must still get through is the gateway itself, so the mocks show
`sender: "gateway"` SPENDs. The monitor board now prints `NRG` lines.

**Waiting on other streams:** real boards + INA219 rig and the ESP-NOW
transport (every board's mesh send/receive is still a stub); the measured
experiment table and legit-client numbers (firmware posts them to
`POST /experiment/result`); real trace recordings for FieldGuard and EnergyGate.

## Console-specific facts (do not re-derive)

- **Trace hand-off verified end to end:** traces recorded through the console
  (label switched per attack) train `ml/`'s EnergyGate unmodified — 180 rows,
  3 sessions, all 5 labels. EnergyGate maps `normal`/`weak_link` → real, the
  rest → not real, and reads the v4 optional fields `frag_complete_pct`,
  `dup_pct`, `battery_pct`, which the stand-ins now emit too.
- `gate_decision` must not correlate (R1). Measured: otherwise mail + file +
  gate decisions = a fake "coordinated attack", and the decision stream holds
  the window open forever. `energy_alert`/`budget_exhausted` do correlate.
- `GET /events` without `since` returns the **newest** `limit`.
- `POST /reset` keeps finished experiment rows (evidence recorded before the
  pitch); drops only a run in progress.
- `/status` returns `null` (UI shows —) and `link: "offline"` without data.
  Projected days = measured draw vs an **assumed** 9.25 Wh cell
  (`SENTINEL_BATTERY_WH`), always labelled an estimate.
- The monitor board's benchmark CSV rows reach the bridge as unrecognised
  lines (counted, harmless). Ask Claude 3 to prefix them `LOG `.
- Streamlit serves HTML before running the script — `tests/test_ui_smoke.py`
  uses `AppTest`. For the React app, look at it: headless Edge
  (`msedge --headless=new --screenshot=out.png --virtual-time-budget=8000 URL`).
- Recharts: SVG attributes don't reliably take CSS `var()` — `web/src/charts.tsx`
  uses hex mirrors of the CSS tokens. Marker labels are thinned (newest-first,
  ≤2, ≥⅓ chart apart) or they smear.
- Scripted Python edits via heredoc can turn `"\n"` into a real newline → syntax
  error. Use the Edit tool for escapes; parse-check after scripted edits.
- **The API refuses cross-origin writes and unknown Host headers**
  (`same_origin_only` in `api/main.py`): POST/PUT/PATCH/DELETE carrying a
  foreign `Origin` get 403, any Host not in `SENTINEL_ALLOWED_HOSTS` (default
  `127.0.0.1,localhost,::1`) gets 421. The bridge and Streamlit send no Origin,
  the Vite proxy keeps Origin and Host equal. Serving beyond 127.0.0.1 means
  adding that host to the env var. Tests add `testserver` in `tests/conftest.py`.
- A stale uvicorn from an earlier session can hold :8000 and serve old code —
  check `netstat -ano | grep :8000` and the process's command line first.

## Environment

`console/.venv` — Python 3.12 (FastAPI, Streamlit, pyserial, jsonschema,
python-multipart). `console/web` — Node 22, Vite 8, React 19, Recharts 3,
TypeScript 7. See `README.md` and `demo/RUNBOOK.md`.
