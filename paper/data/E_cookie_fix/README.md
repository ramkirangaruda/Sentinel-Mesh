# E_cookie_fix: rerun against the bound cookie (2026-10-30/31, INA219 rig)
F = `field_node_energy` on the rig, adaptor 5 V through the INA219, no data cable (G relays its counters). G = `gateway`,
A = `attacker`, M = `monitor_ina219`. All at 7afdea4: Ramkiran's cookie bound to (sender, epoch, seq, window), plus the
gateway keeping its (epoch, seq) on a retry and the attacker's `ECHO same`. G and A sit next to F (5-10 cm).
Commands: `paper/tools/session_cookie_rerun.sh`. Numbers: `python paper/analysis/cookie_fix_summary.py`.

Each grid run: 60 s baseline, 30 s settle, 120 s attack, 60 s recovery. Power is NRG `power_mw` (never `amps`), calibrated,
against the run's own baseline. Rates are per second over the attack window. Placeholder budget: B = 20 J, r = 0.05 J/s,
c_h = 0.02 J. Attack = FORGE at 5/s. Mean ± 95 % CI (Student t).

| Defence | Attack | n | Extra F power | Spend/s | Challenge/s | Echoes per run (A) | Real gateway ok / attempts |
|---|---|---|---|---|---|---|---|
| cookie | none | 3 | 0.0 ± 1.1 mW | 0.03 | 0.04 | 0 | 13/14 |
| gate v2 | none | 3 | -0.4 ± 4.2 mW | 0.04 | 0 | 0 | 12/14 |
| cookie | old echo (fresh seq) | 5 | -1.2 ± 2.3 mW | 0.05 | 13.6 | ~1,600 | 6/47 |
| gate v2 | old echo (fresh seq) | 5 | -1.2 ± 3.5 mW | 0.07 | 14.4 | ~1,600 | 4/51 |
| cookie | same-seq echo | 5 | **+7.0 ± 3.2 mW** | **3.78** | 5.03 | ~560 | 5/47 |
| gate v2 | same-seq echo | 5 | **+7.1 ± 5.6 mW** | **3.76** | 5.02 | ~560 | 8/48 |

**900 s same-seq echo under gate v2 (n = 3), split at the first relayed drop:**

| Rep | Bucket empty at | Spend/s before → after | Drop/s after | Extra power before → after | Gateway before; after |
|---|---|---|---|---|---|
| 1 | +633 s | 3.94 → 2.41 | 2.48 | +10.5 → +5.9 mW | 2/42; 0/15 |
| 2 | +412 s | 4.79 → 2.42 | 2.54 | +12.2 → +4.4 mW | 1/27; 3/31 |
| 3 | +415 s | 4.77 → 2.42 | 2.54 | +14.0 → +6.2 mW | 4/28; 3/29 |
| mean | | 4.50 → 2.42 | 2.52 | **+12.2 ± 4.3 → +5.5 ± 2.4 mW** | 7/97; 6/75 |

## What this shows
- **The gateway fix works.** With no attack the real gateway gets in 25/28 times under the bound cookie. Ramkiran's firmware
  alone would have locked it out.
- **The old attack is stopped.** A fresh-seq echo no longer gets in: spends are about the gateway's own, and power is
  within noise, against +15.1/+16.0 mW on the reusable cookie (2026-10-27). Its echoes each draw a new challenge, hence
  about 14 challenges/s.
- **The fix does not close the attack; it makes it dearer.** An attacker echoing under the challenged (epoch, seq) is still
  admitted, at 3.77/s against about 4.5/s before, but needs about 560 echoes per 120 s instead of about 30. Forced work is
  still real, and cookie and gate v2 do not differ.
- **The budget now has a measured power figure.** Once empty, admissions hold at 2.42/s (bound r/c_h = 2.5/s), and extra power
  falls from +12.2 to **+5.5 ± 2.4 mW measured**, replacing the 8.6 mW ESTIMATED in `E_budget`. Reps start from a full bucket.
- **Availability is the bad news.** The real gateway succeeds 25/28 (89 %) with no attack and only 8-17 % under every attack
  here, including the one the cookie stops, and emptying the bucket does not change it. So the defences protect energy, not
  availability. Failures log as timeouts; the cause is not established. The reference runs below should separate the echo
  from the flood itself.

## Limits
- Power is noisy at this size: idle moves 578-592 mW across the session, baseline-to-recovery drift reaches ±5.7 mW in a run,
  and same-seq runs range +0.8 to +11.3 mW. The 120 s figure (+7) is below the 900 s pre-empty figure (+12.2) at similar
  spend rates, so quote the 900 s runs where possible. n = 3 for those; the 15-min control below measures the drift.
- Comparison with +15-16 mW is across days and firmware, not paired. Admit costs here work out to about 2.3-2.7 mJ against
  3.45 mJ then; this is unexplained.
- F's counters arrive by relay, so window edges can be a few seconds stale. Bucket-empty times come from the first relayed drop.
- A's echo counter is cumulative and some STATS lines were lost or garbled, so echoes per run are from the runs with readings.
- G's RSSI during an attack is mostly the attacker's frames, so it says nothing about the F-G link then.
- Wi-Fi was due off at 01:30, +664 s into budget rep 1 and about 30 s after that bucket emptied. Power and RSSI show no separate
  step there (-22 dBm either side), and reps 2-3 agree. Whether it went off then was not logged.

## Excluded runs
`20261030_225133` and `20261030_225531` (smoke): G and A were too far from F (RSSI about -58), so the gateway failed with no
attack. Moved, then `20261030_230155` and `20261030_230553` passed. Marked excluded in `paper/runlog.csv`.

## Still to come
Controls from `session_cookie_rerun.sh controls`, started 2026-10-31 02:43, not yet analysed or in the tables above: no defence
(with and without attack), FORGE without echo, 15 min with no attack, and 15 min under cookie.
