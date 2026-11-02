# E_repeat: do the absolute numbers repeat? (2026-11-02, INA219 rig, 12 runs, 4 excluded)
Cookie on the FORGE echo gave +13.0 mW on 10-31 and +19.7 mW on 11-02 with the same F and G firmware, and Chaitanya reports the
boards were not moved. This repeats that cell and the no-defence FORGE reference, in one session. Nothing was reflashed: F and G at
7afdea4, A at 389d74f. A's change touches only the INSIDER path, not FORGE. G=COM7, A=COM10, M=COM6. Commands:
`paper/tools/session_repeat_2026-11-02.sh`, log in `session.log`. Numbers: `python paper/analysis/cookie_fix_summary.py paper/data/E_repeat`.

| Defence | Attack | Window | n | Extra F power | Spend/s | Real gateway ok / attempts |
|---|---|---|---|---|---|---|
| none | FORGE, no echo | 120 s | 5 | **+14.1 ± 2.2 mW** | 4.87 | 19/33 |
| cookie | FORGE + same-seq echo | 900 s | 3 | **+9.7 ± 3.1 mW** | 4.57 | 56/182 |

**Across sessions (same firmware on F and G, mean ± 95 % CI, RSSI as reported by G during the attack):**

| Cell | 10-31 | 11-02 night | 11-02 day |
|---|---|---|---|
| none, FORGE, 120 s | +14.7 ± 0.9 (RSSI -18) | not run | +14.1 ± 2.2 (RSSI -24) |
| cookie, FORGE echo, 900 s | +13.0 ± 1.0 (RSSI -19) | +19.7 ± 0.9 (RSSI -16) | +9.7 ± 3.1 (RSSI -25) |
| Real gateway under that echo | 21 % (41/198) | 12 % (23/185) | 31 % (56/182) |

## What this shows
1. **No-defence FORGE repeats.** +14.1 ± 2.2 against +14.7 ± 0.9 mW, about 2.9 mJ per verify, despite an RSSI difference of 6 dB.
2. **Cookie on the FORGE echo does not repeat.** It spans +9.7 to +19.7 mW at about the same spend rate, so no single figure is
   safe to quote. Any value compared with it must come from the same session.
3. **Power rises with RSSI on the echo.** r = 0.89 over all 14 cookie echo runs in the three sessions, against r = 0.23 over 10
   no-defence runs. The gateway does worse as RSSI rises. This is an observed correlation with RSSI not controlled, and most of it
   comes from differences between sessions, so it is not a shown cause. We have no measured mechanism. **Update:** a controlled test
   moving only A did not support this (r = -0.25, n = 9): see `paper/data/E_rssi/README.md`.
4. RSSI moved without the boards being moved (it also drifted from -31 to -19 during 10-30/31). What moved it is not known.

## Excluded runs
- `20261102_163706` (rep 1, first start): the adaptor was off, bus 0.065 V. Stopped by hand after about 75 s.
- F lost power from about 16:52 to about 17:07, cause unknown; Chaitanya did not switch it off. It returned by itself at bus 4.93 V.
  `165311` and `165804` have no power data, and `170258` got power back only in recovery. All three are excluded and were
  redone at 18:14.
- `164817` lost power after its attack window, so its attack figure stands and its drift is not reported.
- `170752` started 40 s after power returned, with baseline 580.5 mW (others 580.1 and 581.2), so it is kept. Bus voltage after the
  outage held at about 4.9 V, slightly above the 4.85-4.88 V before.
- The 5 no-defence runs are therefore 2 before the outage and 3 after it. Bus voltage shows no outage in the last 6 runs.
