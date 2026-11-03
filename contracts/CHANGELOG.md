# Contract changelog

Owner: Console / Claude 2. **Every entry here must be announced to all three
streams.** Entries are newest first.

---

## 2026-11-03 — CONTRACT.md host: `127.0.0.1`, not `localhost` (doc fix, no shape change)

**All streams: nothing to change in code.** `CONTRACT.md`'s "Ports / transport"
said `http://localhost:8000` / `:8001`, contradicting the repo-wide rule in
`CLAUDE.md` and `console/README.md` (`localhost` stalls ~2 s per request on the
team's Windows laptop). The ports and services are unchanged; only the host
spelling in the contract now matches the rule. No schema, event, trace, energy
or serial-line shape changed. Found during the contracts/firmware review
(`docs/review-contracts-firmware.md`), which lists the other contract gaps
without changing them.

---

## 2026-09-19 — MailGuard: clean / suspicious / malicious, and no reasons

**Console (Claude 2), ML (Claude 1), firmware (Claude 3): read this.** One new
event type; firmware is unaffected (boards never emit `mail` events).

**What changed.**
- New event type **`email_suspicious`** on layer `mail`: severity `medium`,
  technique `T1566.001`. Added to `event.schema.json` (type enum and the mail
  layer rule), the `types.ts` union (`web/` and `frontend-kit/`, kept identical)
  and the CONTRACT.md table.
- MailGuard now buckets its score into three bands: `< 0.40` -> `email_clean`
  (info), `0.40 .. < 0.75` -> `email_suspicious` (medium), `>= 0.75` ->
  `email_malicious` (high). The model is unchanged; the old single cut
  (~0.51, tuned for <=2% false alarms) is no longer what the service alerts on.
- MailGuard events carry **no `reasons`** (`[]`); they report a score and a
  verdict only. FileGuard still emits its SHAP reasons.

**Correlation.** `email_suspicious` is severity `medium`, so R1 does not
exclude it: like any non-info alert it can open or join an incident and count as
a `mail` layer hit for R4/R5. `email_clean` (info) still never does.

---

## 2026-09-18 — EnergyGate moves from the gateway to field-1

**Firmware (Claude 3) and ML (Claude 1): read this.** No serial line format,
event type or schema changes -- this is about *which board* runs EnergyGate,
and one feature-order fix.

**Why.** Brief v4 puts EnergyGate on the battery-powered node being drained:
"flatten a *field node's* battery" (section 1), "the node has to decide who is
worth spending energy on" ("What changed"), "the node holds an energy budget",
"the node replies with an 8-byte value" (section 4), and the INA219 sits on
"the field node's battery line" (sections 3, 10). `docs/v4_energy_split.md`
had put it on the gateway, and the firmware followed that. But the gateway is
USB-powered (`docs/hardware_setup.md`), so the flood drained a board with no
battery while the INA219 measured a battery nobody was attacking -- demo beats
3-4 ("the battery line tilts down ... EnergyGate on, draw falls back to idle")
could not happen on real hardware.

**What changed.**
- field-1 now answers inbound `HELLO`s and runs the whole admission path:
  `energygate_score()`, the joule token bucket, the cookie, and the
  spend/challenge/drop policy (now `lib/sentinel_proto/gate_policy.h`,
  host-tested, including the `none|ratelimit|cookie|gate` modes the five-row
  experiment needs). Its `battery_pct` feature is now its own real ADC
  reading; on the gateway it was never set and silently defaulted to 100%.
- The gateway relays the console's `DEFENSE <x>` to field-1 (new mesh message
  `CONTROL`), and turns field-1's `GATE_REPORT` messages into the
  `gate_decision` / `budget_exhausted` events the console already expects --
  now with `"node": "field-1"`. The gateway keeps the signed-handshake check,
  the replay window, trace windows and lockout (beat 5 is still the gateway's).
- The attacker's `FLOOD` / `SLOW_DRIP` target field-1; the gateway still
  overhears them for its trace windows and FieldGuard.
- The monitor board now also prints ~1 Hz `NRG` lines -- it previously printed
  only per-operation CSV, so the console's battery chart had no real data.

**Feature-order fix (ML <-> firmware).** The firmware stand-in read
`f[] = hs_per_s, hs_fail, frag_complete_pct, loss_pct, dup_pct, rssi_mean,
rssi_var, battery_pct`, but `ml/sentinel_ml/energygate.py`'s `FEATURE_ORDER`
(what the real model is trained on) is `hs_per_s, hs_fail, rssi_mean,
rssi_var, loss_pct, dup_pct, frag_complete_pct, battery_pct`. Dropping the real
model in would have scored signal strength as fragment completion. The
firmware now uses the ML order, and `energygate.cpp` compiles the real model
automatically when `ml/export/energygate.h` is copied to
`firmware/lib/sentinel_proto/include/sentinel_proto/energygate_model.h` --
verified by compiling an exported model against the firmware library.

**Known caveat.** EnergyGate's training windows are recorded at the gateway;
it now runs at field-1, whose view of RSSI differs from the gateway's. The
feature definitions match; the vantage point does not. Record field-1-side
windows when the transport exists if the scores look off.

---

## 2026-09-18 — v4 endpoints, control serial lines, NRG line, board timestamps

Closes the "still open" item below: the six endpoints the frontend kit assumed
are implemented (console-local, shapes in `console/frontend-kit/src/types.ts`),
and the cross-team pieces are fixed here. **Firmware (Claude 3) should read
points 1-4; ML (Claude 1) is unaffected.**

1. **`DEFENSE <none|ratelimit|cookie|gate>`**, console -> gateway. Not `MODE`,
   as `docs/v4_energy_split.md` suggested: the attacker board *already* uses
   `MODE REPLAY|FLOOD|IMPERSONATE|WEAK_LINK|OFF` for attack modes, and one word
   meaning two things is a demo-day bug waiting to happen.
2. **Attack control reuses the attacker's existing `MODE` commands.**
   `POST /attack {profile}` sends `none`->`MODE OFF`, `loud`->`MODE FLOOD`,
   `slow_drip`->`MODE SLOW_DRIP` (**new command** -- already on Claude 3's v4
   list), `replay`/`impersonate`/`weak_link`->`MODE REPLAY|IMPERSONATE|WEAK_LINK`.
   No gateway relay: the bridge sends every control line to every bridged port,
   one bridge per board, and each board ignores what it does not handle. Both
   boards already do (verified: attacker logs `LOG unknown command`, gateway
   ignores non-LABEL lines). On start-up the bridge pushes current state once,
   so a rebooted board resyncs.
3. **`NRG <json>`**, monitor -> console: one INA219 reading per line, schema in
   the new `energy.schema.json`. Required `power_mw`, `volts`, `amps`; optional
   `ts`, `battery_pct`, `node` (default field-1). Continuous telemetry, never an
   Event.
4. **Board timestamps.** `firmware/`'s `new_event()` takes `uint32_t
   ts_epoch_ms` and falls back to `millis()` -- but epoch ms (~1.8e12) does not
   fit in 32 bits, so real hardware events will always carry uptime. Left alone
   they land in 1970 and never correlate with the mail/file events of the same
   attack, which breaks the "one incident" beat. The console now replaces any
   `ts` below 1e12 with arrival time and keeps the original as
   `details.device_ts`. **No firmware change needed**; worth fixing the
   signature's comment so nobody tries to pass wall-clock time through it.
5. `gate_decision.details` may carry **optional** `budget_j` / `budget_max_j`.
   The bucket lives on the gateway and `GET /status` needs a source for
   `budget_j`; this is additive, nothing required changed.

Console-side changes the other streams should know about, not contract:
- Correlation rule R1 now also excludes `gate_decision`. Leaving R1-R5
  untouched (as the split doc suggested) was measurably wrong: an email + a file
  + routine gate decisions was reported as a critical "coordinated attack", and a
  steady stream of decisions held the window open so a tamper 40 min later
  merged into the same incident. `energy_alert`/`budget_exhausted` still
  correlate -- a drain is a real attack on the field network.
- `GET /events` without `since` now returns the newest `limit` events (it
  returned the oldest, which would have frozen the timeline under v4 volume).

---

## 2026-09-18 — v2 energy delta, corrected against `sentinelmesh_frontend_kit.zip`

The entry directly below this one (same day) invented `energy_sample` and a
`details.prob_real`/`budget_j`/`cost_est_mj` shape for `gate_decision` before
checking whether anything already assumed a shape. A frontend kit
(`console/frontend-kit/`, copied in alongside this entry) turned up with
`src/types.ts` stating it "mirrors contracts/CONTRACT.md (v1.1)" and fixture
`events.json` showing real examples — so that shape wins over the guess:

- **`energy_sample` does not exist.** Continuous power/battery samples are
  **not events** — they are served by `GET /energy` (console-local, returns
  `{samples: [{ts, power_mw, battery_pct, volts, amps}], markers: [{ts,
  label}]}`, polled ~1s). Only two new *discrete* event types exist:
  `energy_alert` (details: `draw_mw`, `baseline_mw` — both required) and
  `budget_exhausted` (no required details).
- **`gate_decision`'s `details` is just `{action, sender}`.** `action` is
  `spend|challenge|drop` (required); `sender` is a free-text id (optional,
  seen in the fixture but not load-bearing). The probability the sender is
  real goes in the Event's existing top-level `score` field, per the fixture
  (`evt-0005`: `score: 0.21` alongside `details.action: "challenge"`) — it is
  **not** duplicated into `details.prob_real`. There is no `budget_j` or
  `cost_est_mj` in the event at all; live budget state is `Status.budget_j`/
  `budget_max_j` on `GET /status`, a separate resource.
- `event.schema.json` / `trace.schema.json` / `CONTRACT.md` corrected to
  match. The Trace-row additions from the entry below (`battery_pct`,
  `frag_complete_pct`, `dup_pct`) are unaffected — the kit doesn't touch
  Trace, that hand-off is internal to console/ml/firmware, not the frontend.
- Re-verified: 46/46 console tests still pass; the corrected shapes validate
  against the fixture's actual `gate_decision`/`energy_alert` examples.

**Still open**, now more precisely: `GET /status`, `GET /energy`,
`GET /experiment`, `POST /mode`, `POST /attack`, `POST /experiment/run` —
the kit assumes all six but none is specified here yet. First v4 task for
Claude 2 (`docs/v4_energy_split.md`), coordinating the `mode`/`attack`
serial mapping with Claude 3.

---

## 2026-09-18 — v2 energy delta (additive, frozen ahead of the three streams starting v4 work) — SUPERSEDED, see entry above

Brief v4 adds EnergyGate (a gatekeeper in front of the PQC handshake) and a
measured energy budget. Two new `field`-layer event types and three new
optional Trace fields, so all three streams can start in parallel against a
frozen shape instead of serializing on a contract discussion:

- **`gate_decision`** — one per admission decision. `details.action` is
  `spend|challenge|drop`, plus `prob_real` (0-1) and `budget_j` (token-bucket
  balance after the decision) are required; `cost_est_mj` is optional.
  Emitted by firmware (Claude 3) each time EnergyGate/the cookie challenge
  runs; the console (me) renders it as the per-decision feed the brief's demo
  beat 4 needs.
- **`energy_sample`** — periodic telemetry, independent of any one decision.
  `details.mj_hour` and `details.source` (`field-1|monitor`) are required,
  `details.battery_pct` optional. This is what feeds the battery-over-time
  chart (brief section 6's closing slide).
- **Trace row**: three new *optional* fields — `battery_pct`,
  `frag_complete_pct`, `dup_pct` — EnergyGate's free signals (ML stream,
  Claude 1, uses these to train it). Not added to `required`: existing
  producers (mocks, any already-recorded sessions) keep validating without
  them, per the same reasoning as `additionalProperties: true` above.

No existing event type, severity mapping, or required field changed. No
serial line format changed — `gate_decision`/`energy_sample` events travel
as ordinary `EVT <json>` lines, same as everything else.

**Still open, not decided by this entry** (each stream's own call, not a
contract question): the token-bucket refill rate and starting balance, the
exact EnergyGate feature set/model format, and how `cost_est_mj` gets
estimated before a handshake it hasn't run yet. Raise here if any of those
turn out to need a shared shape.

---

## 2026-09-18 — schemas added (additive, no semantic change)

Added, alongside the unchanged `CONTRACT.md` v1:

- `event.schema.json` — JSON Schema (draft 2020-12) for the Event shape. The
  console validates every `POST /events` body against it.
- `trace.schema.json` — JSON Schema for the Trace row. The console validates
  every `TRC` line before appending it to a trace file.

**Nothing in `CONTRACT.md` changed.** These files only write down what the prose
already said, so an invalid event fails loudly at the console rather than
quietly at demo time. Two points where the prose was silent and the schema had
to choose — flagged here because they are the parts you might trip over:

1. **Required vs optional fields.** Required: `id`, `ts`, `layer`, `type`,
   `severity`, `summary`. Optional with defaults: `score` (null), `node` (null),
   `technique` (null), `reasons` (`[]`), `details` (`{}`). This keeps
   hand-written firmware JSON from being rejected over an omitted `reasons`.
2. **Conditional `details`.** `attack_detected` must carry `details.kind`
   (`replay_campaign` | `handshake_flood` | `impersonation`) and `rekey` must
   carry `details.level` (512/768/1024) and `details.reason`, exactly as the
   event table says. Both are enforced.

`additionalProperties` is **false** on Event (a typo'd field is a bug worth
catching) and **true** on Trace (so the console can stamp `session` provenance
without breaking producers).

### Console-local HTTP, not part of the cross-team contract

The console serves these beyond the three contract endpoints. No other stream
calls them, so they are not contract surface and can change without an
announcement:

```
GET  /health
GET  /recording                  current trace-recording session + label
POST /recording/start            {"session": "...", "label": "normal"}
POST /recording/stop
POST /recording/label            {"label": "replay"}
GET  /traces                     recorded sessions and row counts
POST /traces                     one Trace row, appended if recording is active
DELETE /events                   clear the demo database
```

The serial bridge is the only client of `POST /traces`; it polls `GET /recording`
and sends `LABEL <x>` down the wire when `label_version` changes.

---

## 2026-09-17 — v1

Initial contract: ports, Event schema and event table, HTTP endpoints, serial
line formats, Trace schema. Frozen so all three streams could start at once.
