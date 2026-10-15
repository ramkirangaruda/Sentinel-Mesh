# SentinelMesh research paper: handoff context (written 2026-10-12, late evening)

> **Superseded by `paper/HANDOFF_3DAY.md` (2026-10-15). Read that one first.**

Drop this file into the new project's context. It replaces the old conversation.

## 1. Who and what

- User: Ramkiran (Ram), BTech CSE, VIT Vellore. Team "One Last Run": Navika Kapoor, Chaitanya Patil, Adithya Binoj Nair, Ramkiran.
- They won 1st at Code Cortex 3.0 (Security track) with **SentinelMesh**, an ESP32 post-quantum mesh with **EnergyGate**, an energy gatekeeper. They are now turning it into a research paper.
- Division of labour: **Claude does all code, analysis and writing. Ram does the physical hardware work** (flashing, wiring, power, pasting logs back).
- Repo: `~/Sentinel-mesh` on Ram's Windows laptop (GitHub `ramkirangaruda/Sentinel-Mesh`; the old URL redirects). Working branch: **`paper/phase6-handshake`**, last pushed commit `cc2111f`. Ram's shell is PowerShell with a Python venv; PlatformIO commands must be run from the `firmware/` folder.
- Ram's firmware stream in the repo's CLAUDE.md is "Claude 3 (firmware)": edit only `firmware/` (plus `paper/`). Contract changes go through the console stream (Claude 2). Read `/CLAUDE.md` at the repo root first; it holds the working rules.

## 2. The research claim

PQC protects the message but not the battery. Forged or abusive HELLOs force costly ML-KEM/ML-DSA work, which is an energy-exhaustion DoS. Claims:
- **C1** measured PQC handshake energy, including radio.
- **C2** victim/attacker energy ratio, including slow-drip attacks.
- **C3** a budget-bounded learned gate.
- **C4** the artifact (open code and data).

Plan: 14 phases, experiments E0-E9. **Phase 6 (real ESP-NOW transport + real PQC handshake firmware) is the active one.** E1 (primitive timings, radio off) is done. The energy rig is not built yet.

## 3. Rules for the paper (non-negotiable)

- Honest numbers only: report held-out/group-split next to flattering results; detection at a fixed low false-alarm rate; quote measured numbers, not the brief's.
- Anything simulated is labelled **SIMULATED**: `battery_pct` (fixed at 100 via `SENTINEL_NO_BATTERY`) and the EnergyGate model's training data (trained on simulated traces; must be retrained on recorded traces).
- Never run live malware. Do not call the handshake formally secure; it is an unverified protocol.
- Report: ML-DSA-87 does not fit the ESP32; the classical-baseline caveat; signing-time variance as median and tail; demo keys are not key management; control channel (GATE_REPORT/CONTROL/CHALLENGE) is unauthenticated (lab limitation).
- Use `127.0.0.1`, never `localhost`.

## 4. What exists (Phase 6, all committed and pushed)

**Handshake library** `firmware/lib/sentinel_pqc/` (namespace `sentinel::pqc`), host-tested at both levels via `firmware/tools/run_pqc_tests.sh` (happy path, forged signature, wrong key, tampered fields, wrong identity, tampered RESPONSE/CONFIRM, single-use CONFIRM, fragmentation round trip).
- Signed ML-KEM, 3 messages. Gateway = initiator, field-1 = responder.
  - HELLO = cookie(8) | nonce_i(16) | kem_pk | sig_I
  - RESPONSE = nonce_i echo(16) | nonce_r(16) | kem_ct | sig_R
  - CONFIRM = nonce_r(16) | tag(32)
  - The cookie is outside the signed transcript. Transcript hashes and keys use SHAKE256 (PQClean fips202) with length-prefixed fields; sessions use AES-256-GCM (mbedtls), header as AAD, nonce = sender||epoch||seq.
- Levels fixed at compile time: `SENTINEL_PQC_LEVEL` 1 = ML-KEM-512 + ML-DSA-44; 3 (default) = ML-KEM-768 + ML-DSA-65.
- Sizes: L1 HELLO 3244 B (14 frames), RESPONSE 3220 B (14); L3 HELLO 4517 B (20), RESPONSE 4429 B (19); CONFIRM 48 B. ESP-NOW v1 = 235 B payload per 250 B frame.

**Firmware** (`firmware/src/`): `common/` (aead, mesh_transport with RX queue + RSSI sniffer, msg_io, crypto_task, phase_probe, demo keys), `field_node/main.cpp` (responder + EnergyGate), `gateway/main.cpp` (initiator state machine, console lines), `attacker/main.cpp` (modes OFF/REPLAY/FLOOD/INSIDER/IMPERSONATE/WEAK_LINK/SLOW_DRIP; commands `MODE <name>`, `RATE <hz>`, `ECHO on|off`, `STATS`). `lib/sentinel_proto/` has `link_window.*` (rolling 5 s feature window) and `MsgType::CHALLENGE = 0x09`. Native tests: 298 pass.

**PlatformIO envs** (run from `firmware/`): `field_node`, `gateway`, `attacker`, `*_l1`, `field_node_bench` (measurement build, no battery, bench logs; this is what F runs now), `field_node_energy` / `_l1` (adds GPIO4 energy markers).

**Key design points** (full table: `paper/decisions.md`, section "Phase 6: what was actually built", items 1-15):
- EnergyGate runs on **field-1**, decides at HELLO fragment 0 before reassembly or public-key work: SPEND / CHALLENGE / DROP. 8 features in `FEATURE_ORDER`: hs_per_s, hs_fail, rssi_mean, rssi_var, loss_pct, dup_pct, frag_complete_pct, battery_pct. Joule token bucket + cookie.
- Single crypto slot (`busy_drop` if busy). Crypto task stack 90112 B at L3 / 49152 B at L1, core 0.
- Threat model: FLOOD (forged HELLOs claiming the gateway id, random signature), INSIDER (validly signed with the enrolled attacker key, forces a full handshake), SLOW_DRIP (INSIDER about 1/min), REPLAY, IMPERSONATE, WEAK_LINK. Senders with no enrolled key are dropped free by an allow-list. The cookie only stops blind spoofers; the attacker's `ECHO on` defeats it (shared broadcast medium).
- Replay guard (decision 15): ring of 8 verified epochs per sender, exact-epoch match, replay only if seq <= recorded. Limitation: a captured signed HELLO whose epoch aged out can be replayed once, costing one full handshake.
- Board timestamps are uptime; the console replaces `ts` < 1e12 with arrival time.

## 5. Bench results so far (honest status)

Boards, labelled by Ram: **F** (field node), **G** (gateway), **A** (attacker), **M** (Monitor, for the later rig). Radio on, USB power, boards adjacent, no energy rig.

- First run (`paper/data/E_phase6/bench_gateway_F_G_2026-10-12.log`): 10 handshakes, 0 failures, session established in 360-530 ms. Gateway-side: keygen about 9 ms, verify about 27 ms, decaps about 12 ms, **sign 52-174 ms (high variance)**. Crypto stack free minimum 9960 of 90112 B. RSSI sniffer works (`rssi_missing=0`, about -33 dBm). DATA stats decode works. Artefact: pre-fix double handshakes.
- Second run (`bench_gateway_after_reboot_2026-10-12.log`): every handshake timed out after the gateway was reflashed. Cause: F's old replay guard compared epochs numerically and rejected the rebooted gateway's lower random epoch. **Fixed in `cc2111f`; not yet re-tested on hardware.** This log is a bug record, not a result.
- Not a measurement: nothing above includes energy. No attacker test has run yet.

## 6. Where we stopped, and what to do next

**Ram unplugged everything for the night.** Next session:
1. `cd firmware`, `git pull` (branch `paper/phase6-handshake`).
2. Reflash F: `pio run -e field_node_bench -t upload --upload-port COMx` (F's port). G is already on the fixed gateway build (9ccc095) and needs no reflash.
3. `pio device monitor --baud 115200` on G; confirm `LOG hs ok ...` lines again; Ram pastes about a minute of log.
4. Attacker test: flash A (`pio run -e attacker -t upload --upload-port COMx`), type `MODE FLOOD` (wait for `LOG mode set to MODE FLOOD`), unplug A and power it from a charger, watch G for about a minute, paste. `MODE OFF` stops it. Then `MODE INSIDER`.
5. Save each log under `paper/data/E_phase6/` with a README note; add decisions to `paper/decisions.md`.

Still to observe on hardware: flood effect with defence `none`, ECHO behaviour, RSSI under load, signing time with Wi-Fi on, stack need on the responder path, heap headroom (after boot: free 93540, largest block 55284).

## 7. Remaining plan

- **Ram's action item:** order the energy-rig parts (2x INA219, 5 V 2 A charger + USB-A screw-terminal breakout, multimeter, cables, jumpers, 1 kΩ resistors, calibration resistors) and tell Claude when they arrive. Then Part B of the Hardware Build Instructions doc.
- Claude: `benchmark_energy` (E2), analysis scripts in `paper/analysis/`, calibration table, automation for the E5 grid (defence x attack modes), retrain EnergyGate on recorded traces (copy `console/data/traces/*.jsonl` to `ml/data/traces/`; ML stream owns `ml/`), E3-E9, paper writing (method section and E1 results can be written now).
- Other possible items: authenticate the control channel (currently a recorded limitation); merge conflicts later with the teammate branch `origin/v4-esp-now-and-handshake` (HMAC-PSK; not merged; will conflict on the three `main.cpp` files); update the outdated Execution Guide doc (Phase 4) and `SentinelMesh_Project_Context.md`.

## 8. Practical notes for the next Claude session

- Ram is a capable student but new to hardware work; give exact, numbered, PowerShell-ready steps and say which board (F/G/A) each step is for.
- The repo's Stop hook falsely reports "unpushed commits and no remote branch" for this branch. Verify with `git ls-remote origin paper/phase6-handshake` against `git rev-parse HEAD`; if equal, ignore. `git push -u origin paper/phase6-handshake` would set the upstream and likely silence it.
- Host syntax-check stubs for the Arduino code live only in the old session's scratchpad and are gone; rebuild if needed. Ram's own `pio run` builds succeeded for all three firmware targets on the first try.
- Attachments from the old session are not in the repo except the two logs above.

---
# UPDATE 2026-10-15 (01:40 IST) — supersedes sections 5, 6 and the commit hash above

Branch `paper/phase6-handshake`, pushed HEAD 4dbc640 or later. Read `paper/decisions.md` (decisions 15-17) and `paper/data/E_phase6/README.md` (every run, with caveats) first.

## What changed since the note above
- Replay guard fixed (exact-epoch ring of 8, decision 15) and verified on hardware: re-handshake every 30 s works.
- Attacker boot-mode envs (`attacker_flood/insider/slowdrip`, decision 16). Now mostly unneeded: use the script below.
- **Gate policy v2** is the default (decision 17): returned cookie admits whatever the score; low scores get a charged CHALLENGE (0.0005 J, PLACEHOLDER) instead of DROP. v1 is the ablation (`-DSENTINEL_GATE_V1`, env `field_node_bench_gatev1`). v1 under flood dropped the real gateway too (0 of 10).
- **`paper/tools/run_flood_test.py`**: one command runs baseline -> `DEFENSE <x>` -> attack -> recovery with G, F, A all on the laptop (no typing, no moving boards). Usage: `python paper\tools\run_flood_test.py --g COM6 --f COM7 --a COM8 --defence gate --attack FLOOD` (close monitors first; A flashed with plain `attacker`). Logs go to `paper/data/E_phase6/runs/`. Claude can read them straight from Ram's folder through the device bridge (device_bash, folder mount) after he says "done"; no pasting needed. Claude CANNOT open COM ports or flash boards itself.

## Bench results (all USB power, radio on, NOT energy; gate model SIMULATED-trained; one run per condition)
- gate v2 + FLOOD, adjacent: 9/9 legit handshakes ok, 4 inside the flood each `tries=2 challenged=1` (394-527 ms); ~600 forged HELLOs challenged, ~2 admitted at onset, 0 dropped.
- none + FLOOD, adjacent: 9/9 legit ok; F verified ~560 forged HELLOs (hs_fail +562). Flood at 5/s costs battery, not connectivity. The earlier "none: 0 of 7" is NOT reproduced; do not cite it. If DoS-by-connectivity is wanted, test a higher `RATE` with F's log captured.
- gate v2 + INSIDER: 9/9 legit ok; ~5 of 566 insider HELLOs admitted in the first 1.5 s (score 0.96 before the 5 s window saw the flood), then all challenged; cookie stops a non-echoing insider; ECHO attacker NOT tested.
- sign time with Wi-Fi on: 38-287 ms (report median and tail).
- Unexplained: earlier intermittent timeouts (weak link at -61 dBm explained that run; not chased).

## Hardware status
Ram has: multimeter, 2x INA219 (headers NOT yet soldered; he solders them the morning of 2026-10-15), Ve-Pro 5 V 2 A regulated-looking barrel adaptor (label: centre positive, still to verify with the multimeter; do not connect a board until the no-load voltage reads 4.8-5.3 V), jumper wires, breadboard, 1 kohm and 22 / 10 ohm resistors. Still needed: a way to get 5 V from the barrel plug to F's VIN (DC barrel jack to screw-terminal adapter, or cut the cable). Boards: F (A4:F0:0F:77:A2:70, COM7 in the last runs), G (5C:01:3B:BE:A0:10, COM6), A (8C:94:DF:58:DA:1C, COM8), M (monitor, for the rig).

## Next steps, in order
1. Ram: solder INA219 headers, continuity check, multimeter check of the adaptor, barrel-to-wire solution.
2. INA219 on the bench with M (`pio run -e monitor_ina219`), calibration vs multimeter (open, 22 ohm, 10 ohm; table in `paper/setup.md`).
3. Wire F through the INA219 (flash `field_node_energy`), `benchmark_energy` (E2), handshake energy (C1).
4. E5 grid with `run_flood_test.py` (defence x attack), now with energy; add `RATE` sweep and an ECHO attacker run.
5. Retrain EnergyGate on recorded traces (ML stream owns `ml/`; copy traces), measure the real challenge cost to replace 0.0005 J, then paper writing (method + Phase 6 results can start now).
