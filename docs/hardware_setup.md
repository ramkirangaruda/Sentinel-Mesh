# Hardware setup -- paper rig (2026-10-08 addendum, read this first)

For the research paper the sensor is an **INA219** (high-side, no ground lift, 0.1 mA
resolution), build `env:monitor_ina219`. The ADS1115 + hand-made shunt below stays as a
rehearsal rig (`env:monitor`). Energy pass for crypto: flash `env:benchmark_energy` to the
board under test (raises GPIO4 around every op, repeats x20, no LEDs/buzzer) and power it
ONLY through the INA219, no USB. Full step list: paper/setup.md and the shared
"SentinelMesh Hardware Build Instructions" doc.

```
charger 5V -> INA219 Vin+ ;  INA219 Vin- -> board-under-test VIN(5V)
charger GND -> board-under-test GND  AND  Monitor GND  AND  INA219 GND
INA219 VCC -> Monitor 3V3, SDA -> GPIO21, SCL -> GPIO22
board-under-test GPIO4 --1k--> Monitor GPIO4 (marker)
```

---

# Hardware setup — energy rig (v4)

**Updated 2026-09-19, night before/of demo, from what's actually wired and
running on real hardware right now** — supersedes the original plan below in
every place they disagree. Kept the original plan's reasoning where it's
still true; corrected everything that changed once we actually had parts in
hand (no battery, ADS1115 instead of INA219, no USB hub, only 2 data-capable
cables). If you're picking up Monitor work, read this whole file before
touching firmware — several things here look like they should be "obviously"
different and aren't; the reasons are load-bearing.

## The four boards and what's actually true about each

| Board | Role | Powered by (actual, tonight) | Laptop connection |
|---|---|---|---|
| **Field node** | Runs the mesh/crypto handshake, the thing being measured | **No battery available.** Powered via a jumper wire from Gateway's own 5V/GND header pins, routed through the shunt (see wiring below) | None — no USB cable at all. It has no serial link to any laptop; it only talks over ESP-NOW to Gateway. |
| **Gateway** | Central hub: ESP-NOW handshake initiator with field node, detects attacks, reports to console | USB, from the main laptop | **Permanent** — this is the one board that must stay wired the whole demo, since it's the only source of live "ATTACK!" detection events on the dashboard |
| **Attacker** | Floods/replays/impersonates over ESP-NOW at field node; Gateway is what detects it | USB (any spare charging cable — it only needs power, not data, to actually attack) | **None most of the time.** Only gets a data cable plugged in briefly to push a `MODE` command (see "Demo cable plan" below); the attack itself runs over radio with zero laptop involvement |
| **Monitor** | Reads real current/voltage off a shunt resistor, reports energy telemetry | USB | **Permanent** — this is what drives the dashboard's live energy graph |

Why field node has no battery: we don't have a LiPo pack for this rig. The
fix in use tonight is powering it entirely off Gateway's own USB-supplied 5V
rail via jumper wires — Gateway is going to be plugged in anyway, so this
costs nothing extra. **Do not also plug field node into its own USB cable
while this jumper is connected** — two live 5V sources on the same board
risks backfeed, and more importantly it gives current a path around the
shunt, silently invalidating every reading Monitor reports.

## Sensor: ADS1115, not INA219

The original plan (below) assumed an INA219. **We don't have one — we have an
ADS1115** (a general-purpose 16-bit ADC, no built-in current-sense amp), so
`firmware/src/monitor/main.cpp` was rewritten around it. If you're writing or
reading Monitor firmware, everything is in terms of the ADS1115's two
channels:

- **A0−A1 (differential, `GAIN_SIXTEEN`, ±256mV full scale)** — reads the
  voltage drop across the shunt resistor. Current = that voltage ÷
  `board::SHUNT_RESISTANCE_OHMS`.
- **A2 (single-ended, `GAIN_ONE`, ±4.096V full scale)** — meant to read bus/
  battery voltage through a divider. **Currently tied to GND** (see wiring),
  since there's no real battery/divider circuit built — a real "volts"
  reading isn't available yet, and 0V is more honest than the ADC railing at
  its ±4.096V limit (which is exactly what happened before it was grounded —
  showed a constant, meaningless 8.188V).

Unlike the INA219, the ADS1115 has no built-in shunt amplifier and its inputs
can't exceed its own 3.3V supply — so **the shunt sits low-side**, in the
return/GND leg, not the traditional high-side placement:

```
gateway 5V  ──────────────────────────────────────────> field node 5V/VIN
gateway GND ──[shunt, ~2.5Ω = four 10Ω resistors in parallel]──> field node GND
                    |                              |
                   A0 (Monitor)                   A1 (Monitor)
Monitor GND ────────┘ (shares the same ground rail as gateway GND / shunt A0 side —
                        required, or the differential reading is meaningless)
Monitor A2 ─────────> tied directly to GND (no real battery divider built yet)
```

Both A0 and A1 sit within millivolts of true ground regardless of the supply
voltage, which is what makes this safe for a 3.3V-powered ADS1115.

Getting A0/A1 backwards just flips the sign of the current reading — the
firmware already detects and logs this rather than silently reporting
garbage: `LOG monitor: negative power -- are the shunt's A0/A1 leads
swapped?`. If you see that line, just swap A0 and A1.

The shunt resistor pack, the breadboard, and jumper wires are the same ones
from earlier bring-up — already assembled, ~2.5Ω (`board::
SHUNT_RESISTANCE_OHMS`).

## Firmware bugs found and fixed tonight (know these before debugging further)

1. **`PIN_ENERGY_MARKER` (GPIO4) floating → serial flood.** `monitor/main.cpp`
   originally set this pin to plain `INPUT`. Since nothing currently drives
   it (the field-node/benchmark marker signal isn't wired up in this ad-hoc
   rig), it floated and picked up electrical noise as a constant stream of
   spurious edges — each one firing `report_interval()` and flooding the
   115200-baud serial line with corrupted/truncated JSON. **Fixed**: changed
   to `INPUT_PULLDOWN` so it reads a stable LOW at rest. Already reflashed
   and confirmed clean.

2. **`EVT `/`TRC ` prefixes silently dropped on gateway.** `firmware/lib/
   sentinel_proto/src/{event,trace}.cpp`'s `to_evt_line()`/`to_trc_line()`
   pre-populated a `String` with `"EVT "`/`"TRC "` and then called
   `serializeJson(doc, out)` on the same string — but that call **overwrites**
   the destination instead of appending to it, silently throwing away the
   prefix. Every board using this shared library (`gateway`, `field_node`,
   `attacker`, `benchmark`) has/had this bug — it just never surfaced before
   tonight because this is the first time gateway's serial output has
   actually been fed through the console's bridge parser instead of eyeballed
   on a raw monitor. **Fixed** in both files: serialize into a fresh string
   first, then prepend the tag. **As of the last message in this session,
   gateway needed a re-flash to pick up this fix and it hadn't been
   reconfirmed yet — check whether that happened before trusting gateway's
   EVT/TRC lines.** field_node, attacker, and benchmark also need a reflash
   to pick up this fix if their EVT/TRC output matters for anything you're
   doing.

## Console integration (already built, no firmware changes needed for this part)

The console (`console/` — FastAPI + SQLite + React/Vite dashboard) already
has a `bridge/serial_bridge.py` script built for exactly this: run one
instance per board, it reads `EVT`/`TRC`/`NRG`/`LOG` lines off that board's
serial port and POSTs them to the console API. Monitor's `NRG {...}` JSON
line format is already fully compatible with the console's `/energy`
endpoint (checked against `console/api/energy.py` — no firmware changes were
needed there). Run it as:

```
cd console
.venv\Scripts\python -m bridge.serial_bridge --port COMx -v
```

It also polls the console's `/control` endpoint and pushes `LABEL`/
`DEFENSE`/`MODE` lines down to whatever board it's bridging — including
**pushing the current state once immediately on startup**, which is why the
cable-swap trick below works (set the dashboard's attack mode before you even
plug attacker in; the moment its bridge starts, it catches up within about a
second).

## Demo cable plan (real constraint: only 2 data-capable USB cables, 1 USB
port on the main laptop, no hub)

Field node needs no cable (power-only, via the jumper above). That leaves
three boards wanting connections with only two real cables:

- **Cable 1 → Gateway → main laptop, permanent.** Drives the dashboard's live
  detection feed and physical LED.
- **Cable 2 → Monitor → main laptop (or a second laptop, bridging over the
  network to the main laptop's IP with `--console http://<ip>:8000`),
  permanent.** Drives the live energy graph — arguably the more important
  visual for v4's "the battery, not the message, is the attack surface"
  pitch.
- **Attacker**: powered via any spare cable (data or charge-only, doesn't
  matter — it just needs power). To trigger an attack: click the dashboard's
  attack button (e.g. "Loud flood") first, then briefly swap cable 2 from
  Monitor into attacker, start its bridge, wait ~1s for it to auto-push the
  pending `MODE`, then unplug and put cable 2 back into Monitor. Attacker
  keeps attacking autonomously over ESP-NOW after the cable's gone — no
  laptop connection needed for the attack itself, only to deliver the
  command. Repeat with "None" selected to stop it.

If a COM port ever throws `PermissionError: Access is denied` mid-swap
(happened twice tonight), the fix that worked both times: unplug the USB
cable, wait a couple seconds, replug, retry. Usually a stuck PlatformIO
monitor/upload session still holding the port, not a real hardware fault.

## What's still open (pick up here)

- **Field node has not yet been tested running on the gateway-jumper power
  source** — it's only ever run on its own USB so far. First time powering it
  this way, verify it boots and completes the ESP-NOW handshake with Gateway
  before trusting anything downstream.
- **Monitor has not yet measured real current.** With no load actually drawn
  through the shunt in a live circuit, `amps` has read a flat `0.0000` all
  night. Once field node is powered through the shunt and doing real work
  (joining the mesh, running the handshake), this should become the first
  real non-zero reading — that's the actual proof the rig works.
- **Gateway's EVT/TRC reflash (bug #2 above) needs reconfirming** — verify
  with a raw `pio device monitor --port COMx --baud 115200` that lines now
  read `TRC {"ts":...}` / `EVT {"ts":...}` with the prefix intact before
  trusting the bridge/dashboard output.

---

## Original plan (superseded above where they disagree, kept for context)

Written 2026-09-18, before parts were in hand. The INA219 assumption, the
3-board framing, and the battery-powered field node did not survive contact
with actual hardware — see the corrected sections above. Kept here because
the underlying reasoning (why Monitor is a separate board, why the sensor
goes low-side of what it measures, the step-by-step bring-up philosophy) is
still valid even where the specific parts changed.

### Why four boards, not three

The original `platformio.ini` only defined three environments —
`field_node`, `gateway`, `attacker`. v4 added a fourth board, **Monitor**,
whose only job is reading the energy sensor so the measurement never
disturbs the node being measured (brief v4 §3's own reasoning: if the field
node read its own current sensor, the act of reading would cost energy and
contaminate the number).

### Bring-up philosophy

Don't skip a verification step when bringing up new hardware — isolate one
new variable at a time so a failure doesn't leave four things to debug at
once. That principle is why tonight's actual bring-up went: fix the marker
pin flood first (isolated, verified via raw serial), then diagnose the EVT/
TRC prefix bug separately (isolated, verified via raw serial before touching
the bridge again), rather than changing everything at once and guessing which
change fixed what.

### Safety notes (still apply, cell or no cell)

- Double-check polarity before connecting any current sensor — reversed
  polarity on a shunt-based sensor is a common way to get either nonsense
  readings or a damaged board.
- If a real battery does get added later: never let its leads touch each
  other or anything else while connected — that's a direct short. Use a
  protected cell, or add an inline fuse/protection module if only a bare cell
  is available.
