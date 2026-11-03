# SentinelMesh integration contract v1 + v2-energy delta + v4 serial/control (owner: Console/Claude 2. Announce any change to all three.)

## Ports / transport
- Console API: http://127.0.0.1:8000
- ML scoring service: http://127.0.0.1:8001
  (Use `127.0.0.1`, not `localhost`: on the team's Windows laptop `localhost`
  tries IPv6 first and stalls ~2 s per request. Same port, same service.)
- Gateway ESP32 -> console: USB serial, 115200 baud, one message per line

## Event: every layer emits exactly this JSON
{ "id": "uuid4", "ts": <epoch ms>, "layer": "mail|file|field|tamper", "type": "<see table>",
  "severity": "info|low|medium|high|critical", "score": <0..1 or null>,
  "node": "field-1|gateway|attacker|null", "technique": "<ATT&CK id or null>",
  "summary": "<one line for the timeline>", "reasons": ["<top 3 reasons>"], "details": {} }

| layer  | type                                             | technique  | severity |
|--------|--------------------------------------------------|------------|----------|
| mail   | email_malicious / email_suspicious / email_clean | T1566.001 / T1566.001 / null | high / medium / info |
| file   | file_malicious / file_clean                      | T1204.002 / null | high / info |
| field  | replay_rejected                                  | T1692.002  | medium   |
| field  | handshake_rejected                               | T0830      | high     |
| field  | attack_detected (details.kind: replay_campaign, handshake_flood, impersonation) | by kind | high |
| field  | link_degraded                                    | null       | low      |
| field  | rekey (details.level: 512/768/1024, details.reason) | null    | info     |
| field  | gate_decision (details: action=spend\|challenge\|drop, sender; `score`=prob. sender is real) | null | info(spend)/low(challenge)/medium(drop) |
| field  | energy_alert (details: draw_mw, baseline_mw)     | null       | low..critical, scales with draw multiple |
| field  | budget_exhausted                                 | null       | high |
| tamper | case_opened / moved / voltage_anomaly            | null       | critical |

## HTTP
- POST :8000/events (Event) -> 201 | GET :8000/events?since=<ms> | GET :8000/incidents
- POST :8001/score/email {"text": "..."} -> Event
- POST :8001/score/file (multipart file) or {"features": {<54 PE features>}} -> Event
- GET  :8001/health

**v4 console-local endpoints** (only the console and its frontend read these, so
their JSON shapes live in `console/frontend-kit/src/types.ts`, not here):
`GET /status`, `GET /energy?since=`, `GET /experiment`, `POST /mode {mode}`,
`POST /attack {profile}`, `POST /experiment/run {condition, profile}`, plus
`POST /energy` (sample ingest from the bridge). Also served under `/api/*` in the
exact shapes `types.ts` declares. The cross-team part of v4 is the serial lines
below.

**Timestamps from boards.** ESP32s have no wall clock, so board-originated
`ts` values are uptime `millis()`. The console replaces any `ts` below 10^12
(i.e. not an epoch-ms value) with the time it arrived, and keeps the original
as `details.device_ts` (events) / `device_ts` (samples). Boards do not need to
sync time -- which is as well, since `firmware/`'s `new_event()` takes the ts as
`uint32_t`, and epoch ms (~1.8e12) does not fit in 32 bits.

## Serial lines
- gateway -> console: `EVT <Event JSON>` | `TRC <Trace JSON>` | `LOG <text>` (ignored)
- console -> gateway: `LABEL <normal|weak_link|replay|flood|impersonation>` (tags the TRC lines that follow)

v4 additions. Console -> board lines are sent to **every** bridged port; each board
acts on its own commands and ignores the rest (both current boards already do).
- monitor -> console: `NRG <EnergySample JSON>` -- one INA219 reading per line,
  shape in `contracts/energy.schema.json`:
  `{"ts": <ms>, "power_mw": 512.0, "volts": 3.86, "amps": 0.133, "battery_pct": 78.4}`
  (`ts` and `battery_pct` optional).
- console -> gateway: `DEFENSE <none|ratelimit|cookie|gate>` -- which admission
  defence runs in front of the handshake. (Not `MODE`: the attacker board already
  uses `MODE` for attack modes.) **EnergyGate runs on field-1**, the battery-powered
  node whose battery the INA219 measures (brief v4 sections 1-4) -- not on the
  USB-powered gateway. field-1 has no serial link during a run, so the gateway
  relays `DEFENSE` to it over the mesh, and relays field-1's decisions back to the
  console as `gate_decision` / `budget_exhausted` events with `"node": "field-1"`.
- console -> attacker: the attacker's existing `MODE <...>` commands.
  `POST /attack {profile}` maps `none`->`MODE OFF`, `loud`->`MODE FLOOD`,
  `slow_drip`->`MODE SLOW_DRIP` (new), `replay`->`MODE REPLAY`,
  `impersonate`->`MODE IMPERSONATE`, `weak_link`->`MODE WEAK_LINK`.

## Trace JSON (one row per detection window, used to train the field model)
{ "ts": 0, "node": "gateway", "label": "normal", "window_ms": 5000, "hs_per_s": 0, "hs_fail": 0,
  "replay_rej": 0, "auth_fail": 0, "stale": 0, "frag_timeout": 0, "rssi_mean": -55.2,
  "rssi_var": 3.1, "loss_pct": 0.0, "jitter_ms": 2.4 }

v4 adds three optional fields to the same row — EnergyGate's free signals,
not required so pre-v4 producers keep validating: `battery_pct` (0-100),
`frag_complete_pct` (0-100, % of this sender's fragment sets that arrived
complete), `dup_pct` (0-100, duplicate-packet rate).