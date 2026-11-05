# SentinelMesh research paper: handoff for the 3-day push (written 2026-10-15, 16:00 IST)

**For the Claude session that picks this up (and the human driving it).** Drop this whole file into the new
session as its first message, then say which person you are. It replaces `paper/CONTEXT_HANDOFF.md` (older; its
history section is still accurate). Everything here is in the repo on branch `paper/phase6-handshake`; run
`git pull` first. Pushed HEAD at the time of writing: see `git log -1`.

---

## 0. First five minutes (Claude: do this before anything else)

1. Read `/CLAUDE.md` in the repo root (project rules, "which stream are you"). **The stream for this work is
   Claude 3 (firmware) plus the `paper/` folder.** Confirm that with the human, as `CLAUDE.md` demands. Edit
   only `firmware/` and `paper/`; contract or `ml/` changes go through the console/ML streams (tell the human).
2. Read `paper/decisions.md` (decisions 1-17: why things are the way they are) and
   `paper/data/E_phase6/README.md` (every bench run with its caveats).
3. Ask the human the questions in section 10 that are still open. Do not guess them.
4. Check what you can actually reach. If you are a cloud session linked to the person's laptop through a device
   bridge, you can read and write files in their connected folder, but you **cannot open COM ports, flash boards
   or run `pio` on their machine**. Every flash, wire and reset is a human step. If you run locally on their laptop
   you can run the tools yourself. Do not assume which; check.

## 1. What this is

Hackathon project **SentinelMesh** (team "One Last Run": Navika Kapoor, Chaitanya Patil, Adithya Binoj Nair,
Ramkiran "Ram") won 1st at Code Cortex 3.0 (Security track). It is an ESP32 mesh with a post-quantum handshake
and **EnergyGate**, a learned gatekeeper in front of that handshake. The team is turning it into a research
paper.

**Thesis: post-quantum cryptography protects the message but not the battery.** A forged or abusive HELLO forces
an ML-KEM/ML-DSA verification on a battery-powered node (an energy-exhaustion denial of service). EnergyGate
scores each inbound HELLO at its first fragment and a joule token bucket decides SPEND / CHALLENGE / DROP before
any public-key work.

Claims the paper makes:
- **C1** measured PQC handshake energy on real hardware, radio included.
- **C2** victim-to-attacker energy ratio per defence and attack, including slow-drip.
- **C3** a budget-bounded learned gate.
- **C4** the artifact (open code and data).

Plan: 14 phases, experiments E0-E9. Done: E0 (PQC bring-up), E1 (primitive timings, radio off), Phase 6 (real
ESP-NOW transport + real handshake firmware, bench-tested without the energy rig). **Next: the energy rig.**

## 2. Rules for the paper (non-negotiable; also in `CLAUDE.md`)

- **Honest numbers only.** Report group-split/held-out next to flattering numbers; detection at a fixed low false
  alarm rate; quote measured values. Anything simulated is labelled **SIMULATED**.
- SIMULATED right now: `battery_pct` is fixed at 100 (`SENTINEL_NO_BATTERY`), and the EnergyGate model was
  **trained on simulated traces only**. It must be retrained on recorded traces before a claim about the learned
  gate is made. The 0.0005 J "challenge cost" in gate policy v2 is a **placeholder** until measured on the rig.
- Never download, store or run live malware. Never call the handshake "formally secure"; it is an unverified
  protocol.
- Report in the paper: ML-DSA-87 does not fit the ESP32; the classical baseline caveat; signing time as median
  **and tail** (it varied 38-287 ms with Wi-Fi on); the control channel (GATE_REPORT / CONTROL / CHALLENGE) is
  unauthenticated; demo keys are not key management; an attacker that echoes the cookie (`ECHO on`) defeats the
  cookie (the budget bounds it); report per-attempt handshake success, not just "it connected".
- Use `127.0.0.1`, never `localhost`. Never edit a raw log; a bad run stays, marked `excluded=y` in
  `paper/runlog.csv`.

## 3. Architecture in one screen

- **Handshake** (`firmware/lib/sentinel_pqc`): signed ML-KEM, gateway = initiator, field-1 = responder.
  HELLO = cookie(8) | nonce_i(16) | kem_pk | sig_I; RESPONSE = nonce_i echo | nonce_r | kem_ct | sig_R;
  CONFIRM = nonce_r | tag(32). Cookie is outside the signed transcript. SHAKE256 KDF, AES-256-GCM sessions.
  Level 3 (ML-KEM-768 + ML-DSA-65) is default; level 1 via `SENTINEL_PQC_LEVEL=1`. At level 3 a HELLO is 20 ESP-NOW
  frames and a RESPONSE 19 (235 B payload each; broadcast, no retransmission, so about 39 frames must all arrive).
- **EnergyGate runs on field-1 (F), not the gateway.** F decides at HELLO fragment 0. 8 features in
  `ml/sentinel_ml/energygate.py` `FEATURE_ORDER`: `hs_per_s, hs_fail, rssi_mean, rssi_var, loss_pct, dup_pct,
  frag_complete_pct, battery_pct`. Rolling 5 s window. Single crypto slot (`busy_drop` if busy).
- **Gate policy v2 is the default** (decision 17): a returned cookie admits whatever the score (rule 2); a low
  score gets a charged CHALLENGE (0.0005 J placeholder) instead of a DROP (rule 5). v1 (drop low scores) is the
  ablation: `-DSENTINEL_GATE_V1`, env `field_node_bench_gatev1`. Under flood v1 dropped the real gateway too.
- **Replay guard** (decision 15): ring of 8 verified epochs per sender, exact-epoch match.
- **Gateway (G)** relays console lines `DEFENSE <none|ratelimit|cookie|gate>` to F as CONTROL and relays F's
  gate decisions back. **Attacker (A)** modes: OFF, REPLAY, FLOOD, INSIDER, IMPERSONATE, WEAK_LINK, SLOW_DRIP;
  serial commands `MODE <name>`, `RATE <hz>`, `ECHO on|off`, `STATS` (line ends in `\n`). A forgets its mode on
  power cycle.
- **Monitor (M)** reads the INA219 over I2C and a GPIO4 marker wire from the board under test, and prints
  `NRG {...}` lines (per second) and `monitor,op_N,us,mJ,peak_mA` rows (per marked operation).
- Board timestamps are uptime, not wall clock (console replaces `ts` < 1e12).

## 4. Hardware: the four boards and what is in hand

All ESP32-WROOM-32 devkits (micro-USB, CP2102). MACs let you identify them:

| Label | Role | MAC | Notes |
|---|---|---|---|
| **F** | field node (EnergyGate, the victim) | A4:F0:0F:77:A2:70 | flashed `field_node_bench` |
| **G** | gateway | 5C:01:3B:BE:A0:10 | flashed `gateway` |
| **A** | attacker | 8C:94:DF:58:DA:1C | flashed plain `attacker` (starts OFF) |
| **M** | monitor for the energy rig | 30:76:F5:05:3E:A0 | flashed `monitor_ina219`; INA219 wired and found on I2C |

**COM port numbers change when a cable moves.** They were G=COM6/F=COM7 earlier, then F=COM6, G=COM9 (later
COM8), M=COM7, A=COM10. Never trust a remembered number: run `python paper\tools\identify_ports.py`, which
resets every port and names the board from its boot line and MAC.

Parts Ram has: multimeter, 2x INA219 (headers to be soldered by Ram on 2026-10-15; **status unconfirmed**; one
board was already wired to M by jumper and read correctly), a **Ve-Pro 5 V 2 A barrel-plug adaptor** (label says
centre-positive; **no-load voltage not yet measured**), jumper wires, breadboard, resistors (below). Not bought
yet: a DC barrel-jack-to-screw-terminal adapter (or cut the cable), a battery for E4 (without one `battery_pct`
stays SIMULATED).

**Resistor inventory** (read from photos by Claude, **medium confidence, verify with the multimeter before use**):
39 ohm x3, 1 kohm x1 (blue, 5-band, 1%), 10 ohm, 56 ohm x3, 47 ohm x3, 22 ohm x2+, 100 kohm, 270 kohm. All
small ¼ W parts. **The 22 ohm and 10 ohm planned in the old docs must not be put across 5 V**: 5 V / 22 ohm =
1.1 W and 5 V / 10 ohm = 2.5 W, far above a ¼ W rating (they would overheat). Use the safe networks in section 7.

## 5. What has been done and measured

Code (all pushed): native tests `bash firmware/tools/run_native_tests.sh` -> 305 passed; PQC host tests
`bash firmware/tools/run_pqc_tests.sh`. Tools: `paper/tools/run_flood_test.py` (one-command bench run),
`paper/tools/identify_ports.py`. Monitor firmware now also prints `LOG cal ...` lines (raw per-second averages) for
calibration. That edit was **not build-verified in the sandbox**, but Ram's own build and flash worked.

Bench results (all on **USB power, radio on, NOT energy measurements**, one run per condition; the gate model is
SIMULATED-trained; raw logs in `paper/data/E_phase6/` and `.../runs/`):

| Run | Result |
|---|---|
| plain handshakes, boards adjacent | 9 of 9 OK; total 329-545 ms (median 439); sign 38-250 ms (median 78) |
| gate **v1** + FLOOD (earlier run) | 589 forged dropped, **legit 0 of 10** (the gate dropped the real gateway) |
| gate **v2** + FLOOD, adjacent, scripted | **9 of 9 legit OK**; 4 inside the flood each `tries=2 challenged=1` (394-527 ms); about 600 forged challenged, about 2 admitted at onset, 0 dropped |
| gate v2 + FLOOD, boards far apart (RSSI -61 dBm) | 4 of 7 attempts, but that run's no-attack baseline was 4 of 9: a link-quality confound |
| defence **none** + FLOOD, adjacent, scripted | 9 of 9 legit OK; **F verified about 560 forged HELLOs** (`hs_fail` +562, spend +584). At 5/s the flood costs the battery, not connectivity |
| gate v2 + INSIDER, adjacent, scripted | 9 of 9 legit OK; about 5 of 566 insider HELLOs admitted in the first 1.5 s (score 0.96 before the 5 s window saw the flood), then all challenged; the cookie stops a non-echoing insider; ECHO attacker NOT tested |
| INA219 open input | zero offset about -0.30 mA (shunt -0.03 mV), steady to ±0.01 mA; about 989 samples/s |

**Conflict to resolve, do not cite:** an earlier adjacent `none` + FLOOD run showed legit 0 of 7 with
`busy_drop` +269 (`bench_gateway_2026-10-14_flood_defence_none_partial.log`, a partial gateway-only scrollback).
The scripted rerun did not reproduce it (9 of 9, `busy_drop` +27). If denial of service by connectivity is to be
claimed, test a higher rate (`RATE 20`, or more) and capture F's own serial log.

Unexplained: some earlier intermittent handshake timeouts (likely lost broadcast frames on a weak link, not proven);
G free heap dips after floods (93.2k -> 81.8k in one run); watch before long slow-drip runs.

## 6. Open problems and risks (be honest about these in the paper)

1. **Energy rig, USB power and serial.** `benchmark_energy` and `field_node_energy` must run with the board powered
   **only** through the INA219 (no USB 5 V), otherwise current bypasses the sensor. But the board prints its logs
   over USB serial. Unresolved: you need USB **data without 5 V**. The usual fix is a USB cable with the red (5 V)
   wire cut or taped, or a separate USB-serial adapter on TX/RX. Decide this on day 1; measure with a multimeter that
   no current flows through the USB 5 V line. Without it, F's counters are unavailable during energy runs; use the
   gate decisions G relays (`gate_decision` events in G's log) instead.
2. Gate model is SIMULATED-trained; `battery_pct` fixed at 100; challenge cost is a placeholder: all need real data.
3. Insider onset window: the learned score reacts to the 5 s window, not the first frame, so a few insider HELLOs
   get through at the start. An ECHO-capable insider is untested.
4. One run per condition so far. The E5 grid needs repeats (at least 5) and confidence intervals.
5. The earlier "none: 0 of 7" conflict (section 5).
6. Repo state: branch `paper/phase6-handshake` is ahead of `master`; a teammate branch
   `origin/v4-esp-now-and-handshake` (HMAC-PSK) is not merged and will conflict in the three `main.cpp` files.

## 7. The three-day plan (suggested order; adjust to what the human has time for)

### Day 1: build and calibrate the rig (human hands needed)

Safety first:
- **Measure the adaptor's no-load voltage** (multimeter, DC V, 20 V range, red on the centre tip, black on the outer
  sleeve). Proceed only if it reads about 4.8-5.3 V and the tip is positive. If it reads 6 V or more, do not use that
  adaptor.
- Never connect two 5 V sources to F (adaptor and USB 5 V) at once: it backfeeds and bypasses the shunt.
- Get 5 V from the barrel plug to wires with a screw-terminal barrel-jack adapter (or by cutting the cable).

Rig wiring (`docs/hardware_setup.md`, top section):
```
adaptor 5V  -> INA219 Vin+ ;  INA219 Vin- -> board-under-test VIN (5V)
adaptor GND -> board-under-test GND  AND  M GND  AND  INA219 GND
INA219 VCC -> M 3V3, SDA -> M GPIO21, SCL -> M GPIO22        (already done and verified once)
board-under-test GPIO4 --1 kohm--> M GPIO4                    (marker wire)
```
M's pins (USB up, left column top to bottom): 3V3, GND, D15, D2, D4, RX2, TX2, D5, D18, D19, **D21**, RX0, TX0,
**D22**, D23. D21 and D22 are not adjacent (RX0/TX0 sit between them; do not use those).

Calibration (fill the table in `paper/setup.md`; use the multimeter in **voltage** mode and resistance mode, not as
an ammeter): for each load, power it from the adaptor through the INA219, measure V across the load and R of the
load (power off), compute I = V/R, and compare with the `current_ma` in M's `LOG cal` line, minus the zero offset
(about -0.30 mA measured open).
- open input: zero offset (done: -0.30 mA).
- 1 kohm (5 mA): second offset check only.
- **Test 1, about 30 mA:** three 56 ohm in series (168 ohm). Total heat 0.15 W, about 0.05 W per resistor.
- **Test 2, about 106 mA:** three identical strings in parallel, each string 56 + 47 + 39 ohm in series (about 47 ohm
  total). Each string about 35 mA, every resistor under 0.07 W. Check each string's resistance with the meter first.
- Record multimeter value, sensor value and error % in `paper/setup.md` (replace the old 22/10 ohm rows).

Then bring up the real rig: flash F with `field_node_energy` (marker on GPIO4), power it only through the INA219,
confirm M prints `NRG` lines and per-operation rows when F runs.

### Day 2: measure (C1 and C2)

- **E2:** flash `benchmark_energy` on the board under test and capture M's per-operation `mJ` rows next to the
  benchmark's serial CSV (see risk 1); build tables for ML-KEM keygen/encaps/decaps, ML-DSA sign/verify, AES-GCM per
  KB, handshake at both levels, idle baseline.
- **Handshake energy on the real mesh:** `field_node_energy` with G; energy per accepted handshake, per challenge,
  per dropped HELLO. This replaces the 0.0005 J placeholder. Put it in `gate_policy` config and rerun.
- **E5 grid:** extend `paper/tools/run_flood_test.py` to loop defence {none, ratelimit, cookie, gate (v2), gate (v1)}
  x attack {FLOOD, INSIDER, SLOW_DRIP, ECHO-INSIDER} with at least 5 repeats, logging M's NRG output as well. Report
  victim joules per attacker joule and legit success per attempt with confidence intervals. Add a `RATE` sweep
  (5, 20, 50 per second) to find where connectivity starts to fail.

### Day 3: analysis and writing

- Analysis scripts in `paper/analysis/` that rebuild every table and figure from raw data (see `e1_summary.py`).
- Retrain EnergyGate on recorded traces (the ML stream owns `ml/`; copy `console/data/traces/*.jsonl` into
  `ml/data/traces/` and tell the ML stream); report held-out/group-split results next to random-split.
- Write: method (handshake, threat model, gate, rig, calibration) and results sections; limitations list from
  sections 2 and 6.
- Update `paper/runlog.csv`, `paper/setup.md` (versions: `pio --version`, platform, core), `paper/decisions.md`
  (new decisions), and this handoff file.

## 8. Command cheat-sheet (Windows PowerShell, repo at `C:\Users\ramki\Sentinel-mesh`)

Activate the venv, then run firmware commands from `firmware\`:
```
.venv\Scripts\Activate.ps1
cd firmware
pio run -e <env> -t upload --upload-port COMx           # flash
pio device monitor --baud 115200 --port COMx -f log2file   # logs land in firmware\logs\
pio device list                                          # ports (no MACs)
```
Envs: `field_node`, `gateway`, `attacker`, `*_l1`, `field_node_bench`, `field_node_bench_gatev1`,
`field_node_energy(_l1)`, `monitor`, `monitor_ina219`, `benchmark_energy`, `attacker_flood|insider|slowdrip`,
`native`.

From the repo root:
```
git pull
python paper\tools\identify_ports.py                       # which COM port is which board (close monitors first)
python paper\tools\run_flood_test.py --g COMg --f COMf --a COMa --defence gate --attack FLOOD
```
`run_flood_test.py` logs G, F and A and sends the control lines itself (baseline 60 s, `DEFENSE`, settle 30 s, attack
120 s, recovery 60 s; about 5 min). Logs go to `paper\data\E_phase6\runs\`. A must be on the plain `attacker`
firmware. All three boards stay on the laptop.

## 9. Gotchas that already cost time

- `pio device monitor` needs an interactive terminal (no piping, `Tee-Object` fails). To type a line into a board use
  `--echo --eol LF`. `MODE`/`DEFENSE` are typed into the board's monitor, not PowerShell (the script does this for you).
- Only one program can hold a COM port: close old monitors before flashing or running the scripts.
- The Stop hook sometimes complains about unpushed commits; the repo fetch refspec was fixed, so verify with
  `git ls-remote origin paper/phase6-handshake` against `git rev-parse HEAD`.
- `git pull` refused once because the run logs existed untracked locally and in the repo. Fix used: move the local
  `runs` folder aside (`runs_local_backup`), then pull. That backup folder can be deleted once compared.
- Do not leave `__pycache__` folders in `paper/tools/` (untracked files trip the Stop hook).
- INA219 open input prints "negative power -- are the shunt's A0/A1 leads swapped?" and suppresses `NRG` lines. The
  message wording is left over from the ADS1115 version; with nothing connected it is harmless. Read `LOG cal` lines.
- "Bus already started in Master Mode" at boot (Wire begun twice) is harmless.

## 10. Open questions for the human (ask, do not guess)

1. Are both INA219 boards soldered, with no bridges between neighbouring pins (multimeter continuity check)?
2. The adaptor's no-load voltage and polarity (steps in section 7, day 1).
3. How will 5 V reach the board under test: screw-terminal barrel-jack adapter, or cut cable?
4. Current multimeter readings of the resistors that will be used (56, 47, 39 ohm groups and the 1 kohm).
5. Which COM port is which board right now (`identify_ports.py`).
6. Is a battery wanted for E4 (real drain), or is energy per attack in joules enough with `battery_pct` labelled
   SIMULATED?
7. Do they want a USB data-only cable for F during energy runs, or the TX/RX adapter route (risk 1)?

## 11. Working with the person (Ram was doing this alone and is worn out)

- He is a capable CSE student but new to hardware. Give **exact numbered steps**, say which board (F/G/A/M) each
  step is for, say which terminal to type in, and what success looks like.
- Keep each step small and one at a time; he has said several times that long instruction lists were too tedious.
  Automate with scripts wherever possible (as `run_flood_test.py` and `identify_ports.py` do).
- Never ask him to do something dangerous on a guess. Power safety (section 7) beats speed.
- When a photo or log is attached, read it yourself and say how confident you are. Do not claim certainty you do not
  have (resistor colour codes from photos are unreliable; the multimeter is the final word).
- Save raw logs under `paper/data/`, add a note to `paper/data/E_phase6/README.md` (or a new experiment folder),
  commit, push, and say plainly in your reply what the result is and its caveats.

## Update: PRs merged into master (2026-10-15)
PRs #9, #10 (hardware fixes only), #11 are integrated into master; see `paper/decisions.md`. First thing: `git pull`, then `pio run` for every env (not verified in the cloud), check the LCD shows text (address 0x27, else 0x3F in `board_config.h`).

## Update: 2026-10-24 (Chaitanya)
Work continued on branch `paper/e5-grid-tooling`: tooling, Day 0 bench check, rig safety checks and the INA219
calibration are done. Read `paper/CONTEXT_2026-10-24.md` for what changed and `paper/WORK_SPLIT.md` for who does what next.
