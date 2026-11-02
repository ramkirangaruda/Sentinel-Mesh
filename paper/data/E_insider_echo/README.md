# E_insider_echo: an insider that echoes the cookie (2026-11-01/02, INA219 rig, 23 runs)
Every earlier INSIDER+ECHO run was excluded because `cookie_echoes` stayed 0: the attacker signed a new HELLO at 5/s, so its
crypto task was busy when a CHALLENGE arrived. Here A resends one signed HELLO (389d74f), and its echoes fire.

F = `field_node_energy` on the rig, adaptor 5 V through the INA219, no data cable (G relays its counters). G = `gateway`,
A = `attacker`, M = `monitor_ina219`. F and G at 7afdea4, A at 389d74f. G and A sit next to F. Started once:
`paper/tools/overnight_2026-11-01.sh`; its log is `overnight.log`. Numbers: `python paper/analysis/cookie_fix_summary.py
paper/data/E_insider_echo` (per run: `summary.csv`). Two 120 s smokes are excluded from every table.

Each run: 60 s baseline, 30 s settle, attack, 60 s recovery. Power is NRG `power_mw` (never `amps`), calibrated, against the
run's own baseline. Placeholder budget: B = 20 J, r = 0.05 J/s, c_h = 0.02 J. All attacks at 5/s, n = 3, interleaved by defence.
Mean ± 95 % CI (Student t).

| Defence | Attack | Window | Extra F power | Spend/s | Challenge/s | Drop/s | Echoes/run | Real gateway ok / attempts |
|---|---|---|---|---|---|---|---|---|
| none | INSIDER, cached HELLO | 600 s | **+73.2 ± 4.1 mW** | 2.38 | 0 | 0 | 5 | 17/125 |
| cookie | INSIDER + same-seq echo | 600 s | **+58.5 ± 13.7 mW** | 2.03 | 4.79 | 0 | 2632 | 4/115 |
| gate v2 | INSIDER + same-seq echo | 600 s | **+69.0 ± 9.4 mW** | 2.26 | 4.93 | 0 | 2810 | 12/116 |
| cookie | INSIDER, no echo | 120 s | +2.8 ± 1.0 mW | 0.04 | 4.78 | 0 | 2 | 11/20 |
| gate v2 | INSIDER, no echo | 120 s | +2.4 ± 1.5 mW | 0.08 | 4.73 | 0 | 0 | 10/22 |
| cookie | FORGE + same-seq echo | 900 s | **+19.7 ± 0.9 mW** | 4.54 | 5.00 | 0 | 4385 | 23/185 |
| gate v2 | FORGE + same-seq echo | 900 s | +13.9 ± 2.8 mW (split below) | 3.51 | 3.83 | 1.25 | 3318 | 31/189 |

**900 s FORGE echo under gate v2, split at the first relayed drop:**

| Rep | Bucket empty at | Spend/s before → after | Drop/s after | Extra power before → after | Gateway before; after |
|---|---|---|---|---|---|
| 1 | +461 s | 4.53 → 2.42 | 2.46 | +19.1 → +10.9 mW | 5/34; 6/32 |
| 2 | +438 s | 4.64 → 2.42 | 2.52 | +18.0 → +8.1 mW | 6/29; 4/31 |
| 3 | +466 s | 4.50 → 2.42 | 2.48 | +17.8 → +9.3 mW | 4/30; 6/33 |

## What this shows
1. **Neither defence stops an insider that echoes.** Gate v2 is +69.0 ± 9.4 mW against +73.2 ± 4.1 mW undefended; the intervals
   overlap. Cookie's +58.5 ± 13.7 also overlaps, and its spend rate is lower for a reason we have not explained (n = 3).
2. **The joule budget never comes into play.** No drops in any of the 3 gate runs, and the lowest `budget_j` reported was 19.26 of
   20 J. The crypto slot limits admits to about 2.26/s, which charges 45 mW against a 50 mW refill. The cap r/c_h = 2.5/s lies above
   what the attacker can reach.
3. **The budget undercharges this attack.** Extra power per admit is about 30 mJ (69.0 / 2.26), against c_h = 20 mJ. On the FORGE
   echo it overcharges, about 4 mJ per admit. Per-admit figures are power divided by rate, so they include radio and timeouts, and
   they are not the 14.9 mJ per completed handshake from E2.
4. **Without an echo the insider is stopped** by either defence (+2.8 and +2.4 mW), with no difference between them.
5. **Paired over 900 s on the FORGE echo,** the budget's gain is real but only after it empties: about +9 mW against cookie's
   +19.7 mW. Before that, gate and cookie match (+17.8 to +19.1 mW). This removes the earlier caveat that the two ran 3.5 h apart.
6. **Real gateway:** 9 % (33/356, 95 % CI 7-13 %) under the echoing insider, 14 % (54/374, 11-18 %) under the FORGE echo, 50 % (21/42,
   36-64 %) under the plain insider. Echoes hurt it about as much under gate as under cookie.

## Caveats
- **Absolute mW did not repeat between sessions.** Cookie on the FORGE echo was +13.0 ± 1.0 mW on 10-31 and is +19.7 ± 0.9 mW here,
  with the same F firmware and about the same spend rate. Gate's power before and after emptying also rose (+12.2 → about +18.3 and
  +5.5 → about +9.3 mW). Idle moved from about 579 to 572 mW and RSSI from about -19 to -16, so placement may have changed when the
  boards were reconnected; the cause is not established. Compare within this set, and do not mix these figures with `E_cookie_fix`.
- The undefended INSIDER here (+73.2 mW, cached HELLO, 600 s) is not the same condition as the paper's +91.2 mW (fresh signature,
  120 s, earlier session).
- n = 3 per cell. Some cookie runs climb during the attack (46 → 64 mW in rep 1), which is why its interval is wide.
- ESTIMATED, not run: charging the measured 30 mJ with r = 0.05 J/s would cap admits at about 1.6/s (about 50 mW) and empty the
  bucket in about 1,000 s under this insider. It would also empty sooner under a forger, and that charge has no firmware test.
