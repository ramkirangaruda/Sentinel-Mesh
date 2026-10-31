# E_cookie_fix: rerun against the bound cookie (2026-10-30/31, INA219 rig, 53 runs)
F = `field_node_energy` on the rig, adaptor 5 V through the INA219, no data cable (G relays its counters). G = `gateway`,
A = `attacker`, M = `monitor_ina219`. All at 7afdea4: Ramkiran's cookie bound to (sender, epoch, seq, window), plus the
gateway keeping its (epoch, seq) on a retry and the attacker's `ECHO same`. G and A sit next to F (5-10 cm).
Commands: `paper/tools/session_cookie_rerun.sh`. Numbers: `python paper/analysis/cookie_fix_summary.py` (per run: `summary.csv`).

Each short run: 60 s baseline, 30 s settle, 120 s attack, 60 s recovery; long runs have a 900 s window. Power is NRG
`power_mw` (never `amps`), calibrated, against the run's own baseline. Rates are per second over the window. Placeholder
budget: B = 20 J, r = 0.05 J/s, c_h = 0.02 J. Attack = FORGE at 5/s. Mean ± 95 % CI (Student t).

| Defence | Attack | Window | n | Extra F power | Spend/s | Challenge/s | Real gateway ok / attempts |
|---|---|---|---|---|---|---|---|
| none | none | 120 s | 3 | +0.2 ± 0.3 mW | 0.03 | 0 | 14/14 |
| cookie | none | 120 s | 3 | 0.0 ± 1.1 mW | 0.03 | 0.04 | 13/14 |
| gate v2 | none | 120 s | 3 | -0.4 ± 4.2 mW | 0.04 | 0 | 12/14 |
| gate v2 | none | 900 s | 3 | +0.2 ± 0.4 mW | 0.03 | 0 | 89/90 |
| none | FORGE, no echo | 120 s | 5 | **+14.7 ± 0.9 mW** | 4.97 | 0 | 17/35 |
| cookie | FORGE, no echo | 120 s | 3 | -0.7 ± 0.3 mW | 0.05 | 5.05 | 11/19 |
| gate v2 | FORGE, no echo | 120 s | 3 | -0.6 ± 0.8 mW | 0.07 | 5.02 | 11/26 |
| cookie | old echo (fresh seq) | 120 s | 5 | -1.2 ± 2.3 mW | 0.05 | 13.6 | 6/47 |
| gate v2 | old echo (fresh seq) | 120 s | 5 | -1.2 ± 3.5 mW | 0.07 | 14.4 | 4/51 |
| cookie | same-seq echo | 120 s | 5 | +7.0 ± 3.2 mW | 3.78 | 5.03 | 5/47 |
| gate v2 | same-seq echo | 120 s | 5 | +7.1 ± 5.6 mW | 3.76 | 5.02 | 8/48 |
| cookie | same-seq echo | 900 s | 3 | **+13.0 ± 1.0 mW** | 4.71 | 5.07 | 41/198 |
| gate v2 | same-seq echo | 900 s | 3 | see below | 3.51 | 3.89 | 13/172 |

**900 s same-seq echo under gate v2, split at the first relayed drop:**

| Rep | Bucket empty at | Spend/s before → after | Drop/s after | Extra power before → after | Gateway before; after |
|---|---|---|---|---|---|
| 1 | +633 s | 3.94 → 2.41 | 2.48 | +10.5 → +5.9 mW | 2/42; 0/15 |
| 2 | +412 s | 4.79 → 2.42 | 2.54 | +12.2 → +4.4 mW | 1/27; 3/31 |
| 3 | +415 s | 4.77 → 2.42 | 2.54 | +14.0 → +6.2 mW | 4/28; 3/29 |
| mean | | 4.50 → 2.42 | 2.52 | **+12.2 ± 4.3 → +5.5 ± 2.4 mW** | 7/97; 6/75 |

Extra power per 150 s (first five bins of the attack), which shows the step under gate and none under cookie:

| Run | 5-155 s | 155-305 s | 305-455 s | 455-605 s | 605-755 s |
|---|---|---|---|---|---|
| gate rep 1 | 10.7 | 11.6 | 9.9 | 9.8 | 7.1 |
| gate rep 2 | 12.0 | 12.3 | 10.1 | 4.3 | 4.4 |
| gate rep 3 | 13.4 | 14.9 | 11.5 | 6.1 | 6.0 |
| cookie rep 1 | 13.4 | 13.0 | 13.1 | 12.8 | 12.0 |
| cookie rep 2 | 13.5 | 13.0 | 11.7 | 14.2 | 14.4 |
| cookie rep 3 | 11.6 | 12.4 | 13.3 | 13.3 | 13.6 |

**Real gateway against attacker load** (95 % Wilson interval; handshakes treated as independent, which is approximate):

| Attack | A's frames/s | Ok / attempts | Rate |
|---|---|---|---|
| none (all defences) | 0 | 128/132 | 97 % (92-99) |
| FORGE, no echo, cookie or gate (F verifies nothing) | 100 | 22/45 | 49 % (35-63) |
| FORGE, no defence (F verifies about 5/s) | 100 | 17/35 | 49 % (33-64) |
| same-seq echo, 120 s | 192 | 13/95 | 14 % (8-22) |
| same-seq echo, 900 s, gate | 181 | 13/172 | 8 % (4-13) |
| same-seq echo, 900 s, cookie | not logged | 41/198 | 21 % (16-27) |
| old echo | 294 | 10/98 | 10 % (6-18) |

## What this shows
- **The gateway fix works.** With no attack the real gateway gets in 128/132 times. Ramkiran's firmware alone would have
  locked it out under cookie.
- **The cookie stops a non-echoing or fresh-seq attacker.** Both read within about 1 mW of idle, against +14.7 mW with no defence.
- **It barely slows a same-seq attacker.** On 900 s runs, cookie still leaves +13.0 mW against +14.7 mW undefended, about
  12 % less. The attacker's price is one echo per HELLO, about 4.6 echoes/s and roughly double the frames, instead of about
  30 echoes per run on the reusable cookie. So: dearer for the attacker, not closed, and little saved for the victim.
- **The budget is what limits this attacker, and now that is measured.** Under gate v2 extra power steps down from +12.2 to
  **+5.5 ± 2.4 mW** when the bucket empties, with admissions at 2.42/s (bound r/c_h = 2.5/s). Cookie has no budget and stays
  flat at +13.0 mW. This replaces the 8.6 mW ESTIMATED in `E_budget`. The gap would persist for as long as the attack lasts,
  while the first few minutes show no benefit at all.
- **The cap binds only because c_h is a placeholder.** A forced verify really costs about 3 mJ (14.7 mW / 4.97 per s) against
  c_h = 20 mJ. With an honest c_h = 3 mJ and r = 50 mW the cap would be 16.7 admits/s, and a 5/s attacker would never empty
  the bucket. r has to be set from the battery life wanted. Decision for the paper.
- **Availability falls with radio load, not with F's crypto.** Success is 49 % at 100 frames/s whether F verifies every forged
  HELLO or none, and about 10-20 % with echoes. Failures are nearly all timeouts; 14 are `bad_binding`, all under same-seq.
  A handshake needs all 39 frames, so frame loss is the likely mechanism. It is consistent with the data but was not tested
  directly: nothing here measures loss per frame. Neither cookie nor gate protects availability in these runs.
- **It recovers at once.** In every 900 s run the gateway connected again within the last 50 s of recovery, even with gate's
  bucket nearly empty.

## Limits
- **Early runs are noisier, cause unknown.** From about 23:10 to 01:15, idle moved 580-592 mW and baseline-to-recovery drift
  reached ±5.7 mW; after that idle held 577-581 mW, and the 900 s no-attack control read +0.2 ± 0.4 mW with drift under 1 mW.
  The 120 s same-seq runs (+0.8 to +11.3 mW, 3.77 spends/s) fall in that stretch, so **use the 900 s figures** and treat +7 as weak.
- Gate's and cookie's 900 s runs were about 3.5 hours apart, not interleaved. Spend rates differ (4.5 and 4.7/s), and so does
  gateway success (8 % and 21 %); that second gap may be the conditions rather than the defence, so do not claim it.
- +15-16 mW on the reusable cookie and +19.0 mW no-defence (2026-10-2x) are other days and firmware, so compare only loosely. This
  session's no-defence figure is +14.7 mW.
- n = 3 on long runs. F's counters arrive by relay, so window edges can be a few seconds stale. Bucket-empty times come from
  the first relayed drop; rep 1's drop rate only settled about 70 s later.
- A's counters are cumulative and many STATS lines were lost or garbled, so frames and echoes come from runs with readings on
  both sides; there are none for long cookie. G's RSSI during an attack is mostly A's frames, so it says nothing about the F-G link.
- Wi-Fi was due off at 01:30, +664 s into gate rep 1 and about 30 s after that bucket emptied. Power and RSSI show no separate
  step (-22 dBm either side), and reps 2-3 agree. Whether it went off then was not logged.

## Excluded runs
`20261030_225133` and `20261030_225531` (smoke): G and A were too far from F (RSSI about -58), so the gateway failed with no
attack. Moved, then `20261030_230155` and `20261030_230553` passed. Marked excluded in `paper/runlog.csv`.
