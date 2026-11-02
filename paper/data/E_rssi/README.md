# E_rssi: does echo power follow A's signal? (2026-11-02 evening, INA219 rig, 9 runs)
`E_repeat` found extra power rising with RSSI on the cookie echo (r = 0.89, 14 runs), with RSSI not controlled. Here only A moved, by
hand, between runs: F and G stayed put. Cookie, FORGE, same-seq echo, 300 s. F and G at 7afdea4, A at 389d74f, nothing reflashed.
G=COM7, A=COM10, M=COM6. Commands: `paper/tools/session_rssi_test.sh`, log in `session.log`. Numbers:
`python paper/analysis/cookie_fix_summary.py paper/data/E_rssi` (`summary.csv`), `python paper/analysis/voltage_vs_power.py`
(`voltage_all_sessions.csv`).

**Answer: moving A did not make power follow signal.** Over this range the correlation is weak and the opposite sign. The swing inside
this session came largely from F's supply voltage moving during runs. That does **not** explain the gap between sessions, which
stays unexplained.

| Order | Time | A at | RSSI at G | Bus idle | Bus shift, idle to attack | Extra power | Extra current | At fixed 4.85 V | Spend/s | Gateway |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 19:12 | close (files say `mid`) | -24 | 4.899 V | -0.008 V | +7.8 mW | +1.83 mA | +8.9 mW | 4.39 | 3/21 |
| 2 | 19:22 | 40 cm | -53 | 4.828 V | +0.026 V | +20.7 mW | +3.74 mA | +18.2 mW | 4.56 | 9/16 |
| 3 | 19:34 | close | -37 | 4.877 V | -0.011 V | +11.4 mW | +2.74 mA | +13.3 mW | 4.69 | 8/20 |
| 4 | 20:51 | 40 cm | -52 | 4.746 V | -0.012 V | +13.4 mW | +3.23 mA | +15.6 mW | 4.31 | 7/19 |
| 5 | 21:01 | close | -44 | 4.768 V | +0.068 V | +24.8 mW | +3.57 mA | +17.3 mW | 4.58 | 0/19 |
| 6 | 21:21 | 20 cm | -44 | 4.872 V | -0.004 V | +9.9 mW | +2.18 mA | +10.6 mW | 3.41 | 0/18 |
| 7 | 21:31 | 40 cm | -49 | 4.880 V | -0.095 V | -0.2 mW | +2.37 mA | +11.5 mW | 4.21 | 9/16 |
| 8 | 21:42 | 20 cm | -39 | 4.767 V | +0.005 V | +9.4 mW | +1.85 mA | +9.0 mW | 3.99 | 2/22 |
| 9 | 21:50 | 20 cm | -43 | 4.777 V | +0.005 V | +9.0 mW | +1.83 mA | +8.9 mW | 4.10 | 8/19 |

**By spot (n = 3 each, mean ± 95 % CI):**

| A at | RSSI at G | Extra power | At fixed 4.85 V | Spend/s | Gateway ok / attempts |
|---|---|---|---|---|---|
| close | -35 | +14.7 ± 22.3 mW | +13.2 ± 10.4 mW | 4.55 | 11/60, 18 % (95 % CI 11-30 %) |
| 20 cm | -42 | +9.4 ± 1.2 mW | +9.5 ± 2.4 mW | 3.83 | 10/59, 17 % (9-28 %) |
| 40 cm | -51 | +11.3 ± 26.4 mW | +15.1 ± 8.4 mW | 4.36 | 25/51, 49 % (36-62 %) |

**Cookie echo by session (mean ± SD):**

| Session | Window | n | RSSI | Bus shift | Extra power | At fixed 4.85 V |
|---|---|---|---|---|---|---|
| 10-31 | 900 s | 3 | -19 | -0.010 V | +13.0 ± 0.4 mW | +14.0 ± 1.0 mW |
| 11-01/02 | 900 s | 3 | -16 | -0.004 V | +19.7 ± 0.4 mW | +20.5 ± 0.7 mW |
| 11-02 day | 900 s | 3 | -25 | -0.010 V | +9.7 ± 1.3 mW | +10.9 ± 1.5 mW |
| 11-02 evening | 300 s | 9 | -43 | -0.003 V | +11.8 ± 7.3 mW | +12.6 ± 3.7 mW |

## What this shows
1. **Signal did not drive power.** Inside this test, RSSI against extra power is r = -0.25, and -0.60 at fixed voltage (n = 9). The 40 cm
   spot, with the weakest signal, is not lower than the close spot. So the earlier r = 0.89 does not hold as a rule when A is moved.
   Over the three 900 s sessions it is r = 0.93 on 9 runs, but that is three clusters, so it is close to three points.
2. **F draws a nearly fixed current, so its power follows the supply.** Idle current stayed at 117.4-120.0 mA while the bus ranged over
   4.746-4.929 V (r = +0.17), and idle power tracked the bus (r = +0.91). This accounts for idle moving between sessions.
3. **A voltage shift during a run shows up as extra power.** Bus shift against extra power is r = +0.90 here. Run 7 reads -0.2 mW only
   because the bus fell 0.095 V, though its current rose by 2.37 mA. Using current at a fixed voltage halves the spread between
   runs, from 7.3 to 3.7 mW (SD). Runs 2, 5 and 7 carry most of that.
4. **Voltage does not explain the gap between sessions.** The three 900 s sessions had almost no shift, and at fixed voltage they still
   read +14.0, +20.5 and +10.9 mW. Extra current differs too (2.9, 4.2, 2.2 mA), at about the same spend rate. **The cause remains
   unknown.** Note the top figure was at RSSI -16, a signal this test never reached (strongest -24), so very strong signal is not ruled out.
5. **The real gateway did better with A far away:** 49 % at 40 cm against 18 % and 17 % nearer (intervals do not overlap). F still spent
   at 4.36/s with A at 40 cm, so the attack still reaches F at that distance.

## Caveats
- **Position names.** Run 1 is tagged `mid`, but Chaitanya reports it was at the same distance as the `near` runs, so `rssimid` and
  `rssinear` are one spot, called "close" here. The last 4 runs were re-planned for three spots with 3 runs each, adding 20 cm.
- **Order is not balanced.** The re-plan put all of the 20 cm runs late. Their lower power and spend rate may be partly a time effect.
  Spend/s against fixed-voltage power is r = +0.56 here.
- **Placement is by hand and not exact.** The close spot read -24, -37 and -44 dBm, so orientation or nearby boards matter as well as
  distance. Only "close" and the 20 and 40 cm spots are distinct; 20 cm and 40 cm were by eye.
- **RSSI is what G reports, A to G.** A to F was not measured, and F's power depends on that link.
- **Why the bus moves is not known.** It fell from about 4.90 V to about 4.75 V at times this evening, with steps during runs and nobody
  touching the rig as far as we know. It came back between runs. Bus voltage readings carry the 1.4-3.1 % error in `paper/setup.md`, but
  a shift of the size seen here is well above run-to-run noise.
- "At fixed 4.85 V" is extra current times 4.85 V: a comparison figure we derived, not what F drew. n = 3 per spot.
- All 9 runs are kept, including run 7. Its -0.2 mW is a real reading of power and should not be read as "the attack costs nothing".
