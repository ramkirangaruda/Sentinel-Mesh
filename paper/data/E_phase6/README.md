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

`bench_gateway_2026-10-14_flood_defence_gate_full.log`: FLOOD (attacker_flood, 5/s) with `DEFENSE gate`, complete
monitor log (log2file). F power-cycled before; G uptime in seconds below. Radio on, boards adjacent, USB power,
NOT an energy measurement. EnergyGate model trained on SIMULATED traces (not retrained on recorded data).
Timeline: baseline 0-72 s (6 of 6 handshakes ok); `DEFENSE gate` relayed about 72 s; forged HELLOs from 142 s to
about 269 s (about 127 s); recovery after.
- field-1 counters across the flood: drop 0 -> 589 (about 4.6/s, i.e. essentially every forged HELLO), spend 6 -> 9
  (3 admitted at flood onset, before the gate's rate features rose), busy_drop +3, hs_fail +1. Nothing admitted for
  the rest of the flood. Compare defence none (partial run): about 25% of forged HELLOs admitted, 75% busy_drop.
- BUT legitimate handshakes during the flood: 10 attempts (epochs 54761-54770), 10 timeouts, 0 ok, backoff to 15 s.
  The gate dropped the real gateway's HELLOs too: the forged and the real HELLOs claim the same sender id and the
  window features cannot tell them apart. challenge=0 throughout (the gate never issued a cookie challenge).
  So: victim's crypto load protected, availability for the legit peer NOT protected. Same 0-for-N legit outcome as
  defence none. Report both numbers.
- Recovery: first legit handshake ok at about 287 s, about 17 s after the flood ended (one 15 s backoff).
- G's detector (rules, not ML here) classified windows as impersonation / handshake_flood (26 attack_detected
  events); the gateway window showed hs_per_s about 5, auth_fail about 25 per 5 s, RSSI about -62 dBm for the
  forged frames vs about -41 dBm for the real field node.
- Another handshake timeout after the flood ended (epoch 54772, then 54773 ok). Same signature as the earlier
  unexplained timeout: field-1 counted a `spend` (it received the first HELLO fragment), no hs_fail, G timed out.
  Leading hypothesis, NOT verified: ESP-NOW broadcast has no retransmission, a handshake needs about 39 frames to all
  arrive, so a single lost frame fails the attempt (G's backoff retry then succeeds within seconds). Roughly 3 such
  timeouts in about 35 clean-condition attempts so far (about 8%): count and report per-attempt success, and capture
  F's own serial log at the same time to confirm.
- G free heap trend: 93.2 kB at start, 86.5 kB during the flood, 81.8 kB at the end. Watch it (possible slow leak or
  fragmentation in the overheard-HELLO tracking) before any long slow-drip run.

`bench_gateway_2026-10-14_cookie_mode_no_attack.log` (G monitor; first ~230 lines are serial-buffer junk): FIRST
hardware run of the cookie/CHALLENGE path, no attacker. `DEFENSE none` for the first 45 s, `DEFENSE cookie` from
about 47 s (G uptime). Radio on, boards adjacent, NOT an energy measurement.
- The cookie path works end to end: 4 handshakes in cookie mode succeeded with `tries=2 challenged=1`
  (epochs 13697, 13698, 13699, 13701), total 413-583 ms (about 50-100 ms more than an unchallenged one).
  field-1 reported challenge=5, spend 8 by the end.
- One cookie-mode attempt timed out even after the challenge (epoch 13700, tries=2, at about 160 s), and one
  `none`-mode attempt timed out (epoch 13695 at about 33 s). Totals for the run: started 8, ok 6, failed 2.
- Evidence for the lost-frame hypothesis (still NOT proven): G's window right after the 13695 timeout shows
  `frag_timeout=1` (G expired a partly received RESPONSE set, i.e. some but not all of the 19 frames arrived),
  and the 13700 failure coincides with a window where G's mean RSSI dropped to -58.6 dBm with variance 71.8
  (a link dip). Both the earlier unexplained timeouts and this one happened at or after the first
  re-handshake. Count attempts and failures per run and report the per-attempt success rate.

`bench_gateway_2026-10-15_flood_defence_gate_v2_weak_link.log`: FLOOD with `DEFENSE gate`, policy v2 (challenge
instead of drop), F on `field_node_bench` v2, attacker_flood 5/s. Times noted by the operator (wall clock):
G monitor 00:22:13, `DEFENSE gate` 00:23:40, A on 00:24:25, A off 00:26:25, Ctrl+C 00:27:25. In G uptime the
log shows `DEFENSE gate` at 75 s, forged HELLOs 132-255 s. NOT an energy measurement. Model still trained on
SIMULATED traces.
CONFOUND, read first: the boards were further apart than in the earlier runs. G's RSSI for field-1 was about -61 dBm
(-60 to -63 before the flood) versus about -42 dBm before, so the link was weak even with no attacker.
Baseline (0-132 s, no attack): 9 attempts, 4 ok, 5 timeouts (44% per attempt) with `none` then `gate`.
- During the flood (132-255 s) with policy v2: 7 legitimate attempts (epochs 663-669), 4 ok, 3 timeouts; every
  timeout was followed by a successful retry about 1 s later (664->665, 666->667, 668->669), so a session was
  restored within about 4 s each time. v1 (earlier run, strong link, RSSI -35 to -44): 0 of 10.
  Per-attempt success during the flood (4/7) is NOT lower than this run's own no-attack baseline (4/9), so the
  v2 result is "legit connectivity is no longer blocked by the gate", not "better than no attack". Repeat with
  the boards adjacent (RSSI about -40) for the clean comparison.
- field-1 counters: challenge 0 -> 558 (about 4.5/s, one per forged HELLO), drop 0, busy_drop 0; spend rose only
  with legitimate handshakes (19 at the end; 9 ok, 3 hs_fail on F). Essentially no forged HELLO was admitted. The
  price: a challenge frame TX per forged HELLO (about 558 in 123 s); energy cost to be measured on the rig.
- G's `frag_timeout` counter rose to about 8 per 5 s window during the flood (186 over the flood vs 0 before): G
  tracks overheard HELLO fragment sets and these partial forged sets expire. So that counter is flood-driven here;
  it does not by itself show lost RESPONSE frames (revises the reading of the earlier cookie-mode log).
- G free heap 93.5 kB at start, 86.5 kB at the end (same pattern as before: it dips during/after a flood).
