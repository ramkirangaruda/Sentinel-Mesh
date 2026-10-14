# Phase 6 bench logs

`bench_gateway_F_G_2026-10-12.log`: first run of the real handshake. Gateway (board G, `env:gateway`,
ML-KEM-768 + ML-DSA-65) and field node (board F, `env:field_node_bench`), no energy rig, boards ~adjacent.
Raw serial capture, ~2 min. Not a measurement: radio on, USB power, no marker.

What it shows: 10 handshakes, 0 failures, 0 challenges, 0 drops; session established in 360-530 ms;
gateway-side timings (keygen ~9 ms, verify ~27 ms, decaps ~12 ms, sign 52-174 ms, high variance);
crypto-task stack free minimum 9960 B of 90112; RSSI sniffer works (rssi_missing=0).

Known artefact: this run was recorded BEFORE a gateway fix. Every scheduled handshake was
immediately followed by a second one (the state machine read the stale next-start time before
consuming the result). Fixed in the commit after this file was added; do not count these as 2x
the intended rate.

`bench_gateway_after_reboot_2026-10-12.log`: gateway reflashed (9ccc095 build) while field node F kept
running its previous image state. Every handshake times out (`reason=timeout`, backoff 1 s to 15 s).
Cause: F's replay guard compared epochs numerically; the rebooted gateway drew a random epoch lower than
the one F had recorded, so F dropped every HELLO as a replay before the gate. Fixed by an exact-epoch
ring (decision 15). A failure that was a bug, kept here as a record, not a result.

## 2026-10-14 reruns (field node on the exact-epoch replay guard, commit cc2111f build)

`bench_gateway_F_G_2026-10-14_9_handshakes_ok.log`: G (laptop USB, monitor), F (separate power). About 4.6 min.
9 handshakes started, 9 ok, 0 failed; 1 initial + 8 scheduled re-handshakes at the 30 s period, each with a
`rekey` event. No attacker, no energy rig, radio on, USB power: NOT a measurement.
Gateway-side phase times over the 9: total 329-545 ms (median 439), keygen about 9 ms, verify about 27 ms,
decaps about 11.8 ms, sign 38-250 ms (median 78 ms; high variance, report median AND tail).
crypto-task stack free minimum 9960 B of 90112; rx_overflow=0; rssi_missing=0; RSSI about -20 dBm (boards adjacent).
A separate run with F monitored on its own serial port (not saved: pasted in chat) showed F completing 3 of 3
handshakes (epochs 48605-48607), hs_fail=0, replay_pre=0, ignored_frags=0, rx_overflow=0.

`bench_gateway_2026-10-14_second_handshake_timeout.log`: UNEXPLAINED. Same builds, G rebooted. First handshake
ok (377 ms), the second (at the 30 s period) and the retry timed out while F's gate said "spend" (F admitted the
HELLO) and F's counters showed no failure. Not reproduced in the two runs above. Possible causes not yet
excluded: lost RESPONSE frames at G, a power/reset condition on F. Watch for it in later runs (`hs fail
reason=timeout` after a successful first handshake) and do not claim 100% handshake success from these logs.

`bench_gateway_2026-10-14_after_flood_attacker_rebooted.log` (first ~25 s only; the leading `_pct":0}` lines are
serial-buffer leftovers from the previous session). First flood attempt, defence none. A was set to `MODE FLOOD`
over USB for about 5-6 min, then unplugged and moved to a charger. A does NOT remember its mode across a power
cycle, so the flood STOPPED at that moment: the field-1 counters in this log are frozen (spend=896,
busy_drop=690, hs_fail=735, hs_ok=24 for the whole window) and G's first handshake succeeded in 486 ms.
The counters are cumulative since F's boot and include the pre-flood handshakes, so they are NOT a clean
flood measurement. What they do show: with defence none, F admitted about 900 forged HELLOs into the
crypto slot and refused about 690 more because the slot was busy, i.e. roughly the 5/s default rate for the
few minutes A was attached. Lesson: for a charger-powered attacker use `env:attacker_flood` (boots flooding).

`bench_gateway_2026-10-14_flood_defence_none_partial.log`: first real FLOOD run, defence `none`, attacker =
`env:attacker_flood` (5 attempts/s default) on a charger, F power-cycled before the run (clean counters), G on USB.
PARTIAL: this is the terminal scrollback (419 lines), not the monitor's log file, so the baseline and the flood
start are missing. Visible window: gateway uptime 129-260 s; flood present until about 206 s (last forged-gateway
HELLO event 205.3 s), A unplugged about then.
What it shows (defence none, boards adjacent, radio on, NOT an energy measurement):
- Legit handshakes during about 77 s of flood: 7 attempts, 7 timeouts, 0 ok (gw stats ok stuck at 4, failed 2 -> 9;
  backoff 1 s -> 15 s). First success 211.7 s, about 6 s after the flood stopped; the next at 242 s (30 s period).
- field-1 counters over the same window: spend +91 (admitted forged HELLOs, each a failed verify), busy_drop +269
  (crypto slot busy), hs_fail +45. About 360 attempts in 77 s, i.e. about the 5/s the attacker sends; roughly 75% hit
  busy_drop, 25% were admitted into reassembly + verification.
- The (SIMULATED-trained) EnergyGate score was 0.002-0.35 for the forged HELLOs and 0.958 for the real gateway's.
  With defence none the score is only logged, not acted on. Not a result until the model is retrained on recorded traces.
- G heap fell from 93.2 kB to 86.5 kB during the flood (overheard-HELLO tracking); stack_free_min unchanged.
Redo with the monitor's log file for a complete baseline / flood / recovery record.
